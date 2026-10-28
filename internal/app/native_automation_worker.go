package app

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"zhiyu.local/zhiyu-go/internal/execution/bankv2"
	funds "zhiyu.local/zhiyu-go/internal/funds/domain"
	policy "zhiyu.local/zhiyu-go/internal/policy/domain"
)

const nativeStandingPermitProtocol = "native-standing-submission-permit-v1"
const nativeStandingJointPermitProtocol = "native-standing-submission-permit-v2"

type nativeStandingSubmissionProof struct {
	Protocol           string                    `json:"protocol"`
	Scope              policy.TemplateOwnerScope `json:"scope"`
	OperationID        funds.ID                  `json:"operation_id"`
	PermitID           string                    `json:"permit_id"`
	BankRequestHash    string                    `json:"bank_request_hash"`
	EffectHash         string                    `json:"effect_hash"`
	SignatureHash      string                    `json:"signature_hash"`
	PlanHash           string                    `json:"plan_hash"`
	Grant              NativeStandingGrant       `json:"grant"`
	GrantStateSequence uint64                    `json:"grant_state_sequence"`
	OccurrenceKey      string                    `json:"occurrence_key"`
	FundsVersion       uint64                    `json:"funds_version"`
	SourceVersion      uint64                    `json:"source_version"`
	WriterGeneration   uint64                    `json:"writer_generation"`
	ControlVersion     uint64                    `json:"control_version"`
	DecisionAt         time.Time                 `json:"decision_at"`
	PrefixReceipts     []nativePrefixReceipt     `json:"prefix_receipts,omitempty"`
}

func standingAllocationExpectedRequest(plan nativeStandingAllocationPlan, namespace, planHash string) bankv2.Request {
	c := plan.Candidate
	ref := standingAllocationReference(plan)
	amount := c.Use.Amount
	goal := standingAllocationGoal(plan)
	businessKey := plan.Occurrence.Key
	if plan.Joint != nil {
		businessKey = fmt.Sprintf("%s:%d", businessKey, plan.JointChild)
	}
	return bankv2.Request{Protocol: bankv2.Protocol, Namespace: namespace, Key: plan.ID.String(), OperationID: plan.ID.String(), UserID: plan.Scope.UserID.String(), PermitID: plan.PermitID.String(), ReferenceHash: planHash, RequestedAt: plan.CreatedAt, ExpiresAt: plan.ExpiresAt, Effect: bankv2.Effect{Kind: bankv2.Allocate, BusinessKey: businessKey, Amount: amount, CashUses: []bankv2.CashUse{{AccountID: c.Use.AccountID.String(), Amount: amount}}, OriginUses: []bankv2.OriginUse{{OriginID: c.Use.OriginID.String(), AccountID: c.Use.AccountID.String(), Amount: amount, Bucket: "AVAILABLE"}}, ReturnUses: []bankv2.ReturnUse{}, DestinationGoalID: goal.String(), LatestArrivalAt: plan.ExpiresAt}, Authorities: []bankv2.Authority{{Role: "EXECUTE", SourceID: plan.Grant.ID.String(), Version: int64(plan.Grant.Version), GoalID: goal.String(), PolicyID: ref.PolicyID.String(), PolicyVersion: int64(ref.Version)}}}
}

func standingNativeStoredPermit(ctx context.Context, q queryRow, p Principal, operation funds.ID, request bankv2.Request, signature string) error {
	var raw []byte
	var rawHash, rh, eh, sh, permit string
	if err := q.QueryRow(ctx, `SELECT original,original_hash,bank_request_hash,effect_hash,signature_hash,permit_id::text FROM native_submission_permits WHERE environment_id=$1 AND user_id=$2 AND operation_id=$3`, p.EnvironmentID.String(), p.UserID.String(), operation.String()).Scan(&raw, &rawHash, &rh, &eh, &sh, &permit); err != nil {
		return reject("EVIDENCE_INVALID", err)
	}
	var proof nativeStandingSubmissionProof
	want, e := request.Digest()
	effect, e2 := request.Effect.Digest()
	if e != nil || e2 != nil || Hash(raw) != rawHash || auditJSON(raw, &proof) != nil || (proof.Protocol != nativeStandingPermitProtocol && proof.Protocol != nativeStandingJointPermitProtocol) || proof.Scope != nativeAutomationScope(p) || proof.OperationID != operation || proof.PermitID != permit || permit != request.PermitID || rh != want || eh != effect || sh != Hash([]byte(signature)) || proof.BankRequestHash != rh || proof.EffectHash != eh || proof.SignatureHash != sh || proof.DecisionAt.Before(request.RequestedAt) || !proof.DecisionAt.Before(request.ExpiresAt) {
		return reject("EVIDENCE_INVALID", nil)
	}
	plan, hash, e := loadStandingAllocationPlan(ctx, q, p, operation)
	if e != nil {
		return e
	}
	expected := standingAllocationExpectedRequest(plan, request.Namespace, hash)
	expectedHash, e := expected.Digest()
	a, _ := encode(proof.Grant)
	b, _ := encode(plan.Grant)
	if e != nil || expectedHash != want || proof.PlanHash != hash || proof.OccurrenceKey != plan.Occurrence.Key || string(a) != string(b) || proof.GrantStateSequence < plan.GrantStateSequence || proof.WriterGeneration != plan.Dependencies.WriterGeneration || proof.ControlVersion != plan.Dependencies.ControlVersion || proof.Grant.Terms.Validate() != nil {
		return reject("EVIDENCE_INVALID", nil)
	}
	if plan.Joint != nil {
		return verifyStandingJointWitness(ctx, q, p, plan, proof)
	}
	if proof.Protocol != nativeStandingPermitProtocol || len(proof.PrefixReceipts) != 0 || proof.FundsVersion != plan.Dependencies.FundsVersion+1 || proof.SourceVersion != plan.Dependencies.SourceEvidenceVersion {
		return reject("EVIDENCE_INVALID", nil)
	}
	// This verifies the immutable original witness, never today's signing key,
	// grant status, USER session, policy state or permission expiry.
	return nil
}

func (s *Service) standingNativePermit(ctx context.Context, c Claim) (nativePermitted, error) {
	var out nativePermitted
	if c.Principal.Kind != "SYSTEM" || c.Principal.SessionID != (funds.ID{}) {
		return out, reject("FORBIDDEN", nil)
	}
	tx, err := s.begin(ctx)
	if err != nil {
		return out, err
	}
	defer rollback(ctx, tx)
	if err = s.lockNativeClaim(ctx, tx, c); err != nil {
		return out, err
	}
	p := c.Principal
	var raw []byte
	var rh, eh, mode, grantID string
	var grantVersion, reservedFV uint64
	var signature, observed *string
	err = tx.QueryRow(ctx, `SELECT status,bank_request,bank_request_hash,effect_hash,mode,grant_id::text,grant_version,reserved_funds_version,permit_signature,bank_observed_status FROM native_operations WHERE environment_id=$1 AND user_id=$2 AND id=$3 AND command_kind=$4`, p.EnvironmentID.String(), p.UserID.String(), c.OperationID.String(), nativeStandingAllocateKind).Scan(&out.State, &raw, &rh, &eh, &mode, &grantID, &grantVersion, &reservedFV, &signature, &observed)
	if err != nil {
		return out, err
	}
	if auditJSON(raw, &out.Request) != nil {
		return out, reject("EVIDENCE_INVALID", nil)
	}
	want, e := out.Request.Digest()
	effect, e2 := out.Request.Effect.Digest()
	if e != nil || e2 != nil || want != rh || effect != eh || out.Request.Namespace != s.Namespace || out.Request.UserID != p.UserID.String() || out.Request.OperationID != c.OperationID.String() || mode != "STANDING" {
		return out, reject("EVIDENCE_INVALID", nil)
	}
	if out.State == "SETTLED" || out.State == "REJECTED" || out.State == "CANCELLED" {
		out.Cancelled = true
		return out, nil
	}
	if signature != nil {
		if err = standingNativeStoredPermit(ctx, tx, p, c.OperationID, out.Request, *signature); err != nil {
			return out, err
		}
		out.Signature = *signature
		return out, tx.Commit(ctx)
	}
	if out.State != "QUEUED" || observed != nil && (*observed == "ACCEPTED" || *observed == "SETTLED") {
		return out, reject("OPERATION_UNKNOWN", nil)
	}
	plan, hash, err := loadStandingAllocationPlan(ctx, tx, p, c.OperationID)
	if err != nil {
		return out, err
	}
	expected := standingAllocationExpectedRequest(plan, s.Namespace, hash)
	expectedHash, e := expected.Digest()
	if e != nil || expectedHash != want || plan.Grant.ID.String() != grantID || plan.Grant.Version != grantVersion || reservedFV != plan.Dependencies.FundsVersion+1 {
		return out, reject("EVIDENCE_INVALID", e)
	}
	decisionAt := s.now()
	grant, err := loadNativeStandingGrant(ctx, tx, p, plan.Grant.ID)
	if err != nil {
		return out, err
	}
	permissionErr := s.validateStandingAllocationPermit(ctx, tx, p, plan, grant, reservedFV, decisionAt)
	if permissionErr != nil {
		switch Code(permissionErr) {
		case "NATIVE_GRANT_NOT_ACTIVE", "NATIVE_GRANT_POLICY_CHANGED", "SOURCE_CHANGED", "AUTHORIZATION_EXPIRED", "NATIVE_STANDING_CAP_EXCEEDED", "BILL_INTAKE_PENDING":
			if err = s.standingNativeCancelUnsigned(ctx, tx, c, plan, Code(permissionErr)); err != nil {
				return out, err
			}
			out.Cancelled = true
			return out, tx.Commit(ctx)
		default:
			return out, permissionErr
		}
	}
	out.Signature, err = bankv2.SignPermit(out.Request, s.PermitSecret)
	if err != nil {
		return out, err
	}
	d := plan.Dependencies
	proof := nativeStandingSubmissionProof{Protocol: nativeStandingPermitProtocol, Scope: nativeAutomationScope(p), OperationID: c.OperationID, PermitID: out.Request.PermitID, BankRequestHash: rh, EffectHash: eh, SignatureHash: Hash([]byte(out.Signature)), PlanHash: hash, Grant: grant.Grant, GrantStateSequence: grant.StateSequence, OccurrenceKey: plan.Occurrence.Key, FundsVersion: reservedFV, SourceVersion: d.SourceEvidenceVersion, WriterGeneration: d.WriterGeneration, ControlVersion: d.ControlVersion, DecisionAt: decisionAt}
	if plan.Joint != nil {
		proof.Protocol = nativeStandingJointPermitProtocol
		proof.PrefixReceipts, err = standingJointPrefix(ctx, tx, p, plan)
		if err != nil {
			return out, err
		}
		proof.FundsVersion += uint64(len(proof.PrefixReceipts))
		proof.SourceVersion += uint64(len(proof.PrefixReceipts))
	}
	proofRaw, err := encode(proof)
	if err != nil {
		return out, err
	}
	_, err = tx.Exec(ctx, `INSERT INTO native_submission_permits(environment_id,user_id,operation_id,permit_id,bank_request_hash,effect_hash,signature_hash,original,original_hash,decision_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`, p.EnvironmentID.String(), p.UserID.String(), c.OperationID.String(), out.Request.PermitID, rh, eh, proof.SignatureHash, proofRaw, Hash(proofRaw), decisionAt)
	if err != nil {
		return out, err
	}
	_, err = tx.Exec(ctx, `UPDATE native_operations SET status='SUBMITTING',permit_signature=$4,version=version+1,updated_at=$5 WHERE environment_id=$1 AND user_id=$2 AND id=$3`, p.EnvironmentID.String(), p.UserID.String(), c.OperationID.String(), out.Signature, decisionAt)
	if err != nil {
		return out, err
	}
	out.State = "SUBMITTING"
	return out, tx.Commit(ctx)
}

func (s *Service) validateStandingAllocationPermit(ctx context.Context, tx pgx.Tx, p Principal, plan nativeStandingAllocationPlan, grant NativeStandingGrantView, reservedFV uint64, now time.Time) error {
	if err := ensureNativeBillsReady(ctx, tx, p); err != nil {
		return err
	}
	if !now.Before(plan.ExpiresAt) || now.Before(plan.CreatedAt) {
		return reject("AUTHORIZATION_EXPIRED", nil)
	}
	a, _ := encode(plan.Grant)
	b, _ := encode(grant.Grant)
	if string(a) != string(b) {
		return reject("EVIDENCE_INVALID", nil)
	}
	if grant.State != "ACTIVE" || now.Before(grant.Grant.Terms.EffectiveFrom) || !now.Before(grant.Grant.Terms.ExpiresAt) {
		return reject("NATIVE_GRANT_NOT_ACTIVE", nil)
	}
	versions := make([]funds.ID, len(grant.Grant.Terms.Policies))
	for i, r := range grant.Grant.Terms.Policies {
		versions[i] = r.VersionID
	}
	refs, _, _, err := nativeGrantReferences(ctx, tx, s, p, versions)
	if err != nil {
		return err
	}
	r1, _ := encode(refs)
	r2, _ := encode(grant.Grant.Terms.Policies)
	if string(r1) != string(r2) {
		return reject("NATIVE_GRANT_POLICY_CHANGED", nil)
	}
	var fv, sv, wg, cv, goalVersion uint64
	err = tx.QueryRow(ctx, `SELECT u.funds_version,u.source_version,e.writer_generation,e.control_version FROM users u JOIN environments e ON(e.id=u.environment_id) WHERE u.environment_id=$1 AND u.id=$2`, p.EnvironmentID.String(), p.UserID.String()).Scan(&fv, &sv, &wg, &cv)
	if err != nil {
		return err
	}
	d := plan.Dependencies
	prefix := uint64(0)
	if plan.Joint != nil {
		receipts, e := standingJointPrefix(ctx, tx, p, plan)
		if e != nil {
			return e
		}
		prefix = uint64(len(receipts))
	}
	if reservedFV != d.FundsVersion+1 || fv != reservedFV+prefix || sv != d.SourceEvidenceVersion+prefix || wg != d.WriterGeneration || cv != d.ControlVersion {
		return reject("SOURCE_CHANGED", nil)
	}
	err = tx.QueryRow(ctx, `SELECT version FROM goals WHERE environment_id=$1 AND user_id=$2 AND id=$3`, p.EnvironmentID.String(), p.UserID.String(), standingAllocationGoal(plan).String()).Scan(&goalVersion)
	if err != nil {
		return err
	}
	if goalVersion != plan.Candidate.GoalVersion {
		return reject("SOURCE_CHANGED", nil)
	}
	if plan.Joint != nil {
		if err = validateStandingJointGoalVersions(ctx, tx, p, plan); err != nil {
			return err
		}
	}
	usage, err := nativeStandingUsage(ctx, tx, p, grant.Grant, now, &plan.Occurrence.ID)
	if err != nil {
		return err
	}
	if err = policy.AuthorizeNativeStanding(grant.Grant.Terms, grant.State, plan.Candidate.Authority, usage, now); err != nil {
		return reject(err.Error(), err)
	}
	ledger, err := s.Store.LoadNativeLedger(ctx, tx, p.EnvironmentID, p.UserID, now)
	if err != nil {
		return err
	}
	matched, holds := false, 0
	for _, r := range ledger.Income.Snapshot().Reservations {
		if r.ActionID == plan.ID {
			if r.Operation != funds.AllocateGoal || r.State != funds.Reserved || r.DestinationAccountID != nil || len(r.Uses) != 1 || r.Uses[0] != plan.Candidate.Use {
				return reject("EVIDENCE_INVALID", nil)
			}
			matched = true
		}
	}
	for _, h := range ledger.Holds {
		if h.OperationID == plan.ID {
			if h.ResourceKind != "CASH" || h.ResourceID != plan.Candidate.Use.AccountID.String() || h.Amount != plan.Candidate.Use.Amount || h.State != funds.Reserved {
				return reject("EVIDENCE_INVALID", nil)
			}
			holds++
		}
	}
	if !matched || holds != 1 {
		return reject("EVIDENCE_INVALID", nil)
	}
	var budget bool
	err = tx.QueryRow(ctx, `SELECT b.state='RESERVED' AND b.amount_cents=$4 AND b.grant_id=$5::uuid AND b.grant_version=$6 AND x.economic_amount_cents=$8 FROM native_grant_budget_claims b JOIN native_occurrence_operations x ON(x.environment_id=b.environment_id AND x.user_id=b.user_id AND x.occurrence_id=b.occurrence_id) WHERE b.environment_id=$1 AND b.user_id=$2 AND b.occurrence_id=$3 AND x.operation_id=$7`, p.EnvironmentID.String(), p.UserID.String(), plan.Occurrence.ID.String(), plan.Candidate.Authority.Amount.Cents(), grant.Grant.ID.String(), grant.Grant.Version, plan.ID.String(), plan.Candidate.Use.Amount.Cents()).Scan(&budget)
	if err != nil {
		return err
	}
	if !budget {
		return reject("EVIDENCE_INVALID", nil)
	}
	return nil
}

func finalizeNativeStandingBudget(ctx context.Context, tx pgx.Tx, p Principal, occurrence funds.ID, spent funds.Money, now time.Time) error {
	tag, err := tx.Exec(ctx, `UPDATE native_grant_budget_claims SET state='FINAL',spent_cents=$4,closed_at=$5 WHERE environment_id=$1 AND user_id=$2 AND occurrence_id=$3 AND state='RESERVED'`, p.EnvironmentID.String(), p.UserID.String(), occurrence.String(), spent.Cents(), now)
	return assertOne(tag, err)
}

func (s *Service) standingNativeCancelUnsigned(ctx context.Context, tx pgx.Tx, c Claim, plan nativeStandingAllocationPlan, reason string) error {
	if plan.Joint != nil {
		return s.cancelStandingJointSuffix(ctx, tx, c, plan, reason, false)
	}
	p := c.Principal
	ledger, err := s.Store.LoadNativeLedger(ctx, tx, p.EnvironmentID, p.UserID, s.now())
	if err != nil {
		return err
	}
	ledger.Income, err = ledger.Income.Release(c.OperationID, s.now(), true)
	if err != nil {
		return err
	}
	for i := range ledger.Holds {
		if ledger.Holds[i].OperationID == c.OperationID {
			ledger.Holds[i].State = funds.Released
		}
	}
	tag, err := tx.Exec(ctx, `UPDATE native_operations SET status='CANCELLED',processing_health=$4,version=version+1,updated_at=$5 WHERE environment_id=$1 AND user_id=$2 AND id=$3 AND permit_signature IS NULL AND status='QUEUED'`, p.EnvironmentID.String(), p.UserID.String(), c.OperationID.String(), reason, s.now())
	if err = assertOne(tag, err); err != nil {
		return err
	}
	if err = s.Store.PersistNativeLedger(ctx, tx, p.EnvironmentID, p.UserID, ledger); err != nil {
		return err
	}
	if err = finalizeNativeStandingBudget(ctx, tx, p, plan.Occurrence.ID, funds.Money{}, s.now()); err != nil {
		return err
	}
	if err = s.recordNativeCancellation(ctx, tx, p, c.OperationID, reason); err != nil {
		return err
	}
	if _, err = tx.Exec(ctx, `UPDATE users SET funds_version=funds_version+1 WHERE environment_id=$1 AND id=$2`, p.EnvironmentID.String(), p.UserID.String()); err != nil {
		return err
	}
	if _, _, err = s.refreshTemplateProtectionAfterNativeEffect(ctx, tx, p, plan.Grant.Terms.Timezone); err != nil {
		return err
	}
	return finishNativeJob(ctx, tx, c)
}

func (s *Service) standingNativeProtection(ctx context.Context, tx pgx.Tx, p Principal, id funds.ID) error {
	plan, _, err := loadStandingAllocationPlan(ctx, tx, p, id)
	if err != nil {
		return err
	}
	_, _, err = s.refreshTemplateProtectionAfterNativeEffect(ctx, tx, p, plan.Grant.Terms.Timezone)
	return err
}
