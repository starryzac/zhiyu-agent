package app

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"zhiyu.local/zhiyu-go/internal/execution/bankv2"
	funds "zhiyu.local/zhiyu-go/internal/funds/domain"
	planning "zhiyu.local/zhiyu-go/internal/planning/domain"
)

func (s *Service) ClaimNativeJob(ctx context.Context, owner string, lease time.Duration) (*Claim, error) {
	if owner == "" || len(owner) > 128 || lease < time.Millisecond || lease > time.Minute {
		return nil, reject("INVALID_WORKER_CONFIGURATION", nil)
	}
	tx, err := s.begin(ctx)
	if err != nil {
		return nil, err
	}
	defer rollback(ctx, tx)
	if _, err = s.environment(ctx, tx, true); err != nil {
		return nil, err
	}
	var e, u, j, o string
	var generation uint64
	err = tx.QueryRow(ctx, `WITH picked AS (
 SELECT j.environment_id,j.user_id,j.id FROM native_jobs j JOIN environments e ON e.id=j.environment_id
 JOIN native_operations o ON(o.environment_id=j.environment_id AND o.user_id=j.user_id AND o.id=j.operation_id)
 LEFT JOIN native_operations prior ON(prior.environment_id=o.environment_id AND prior.user_id=o.user_id AND prior.id=o.previous_operation_id)
 WHERE e.namespace=$1 AND NOT j.paused AND j.attempts<j.max_attempts AND j.state IN ('READY','RUNNING')
 AND j.next_attempt_at<=clock_timestamp() AND (j.lease_until IS NULL OR j.lease_until<=clock_timestamp())
 AND (o.previous_operation_id IS NULL OR prior.status IN ('SETTLED','REJECTED','CANCELLED'))
 ORDER BY j.next_attempt_at,o.child_number,j.id FOR UPDATE OF j SKIP LOCKED LIMIT 1)
 UPDATE native_jobs j SET state='RUNNING',claim_generation=j.claim_generation+1,lease_owner=$2,
 lease_until=clock_timestamp()+$3::bigint*interval '1 millisecond',attempts=j.attempts+1
 FROM picked p WHERE j.environment_id=p.environment_id AND j.user_id=p.user_id AND j.id=p.id
 RETURNING j.environment_id::text,j.user_id::text,j.id::text,j.operation_id::text,j.claim_generation`, s.Namespace, owner, lease.Milliseconds()).Scan(&e, &u, &j, &o, &generation)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	env, err := funds.ParseID(e)
	if err != nil {
		return nil, err
	}
	user, err := funds.ParseID(u)
	if err != nil {
		return nil, err
	}
	job, err := funds.ParseID(j)
	if err != nil {
		return nil, err
	}
	op, err := funds.ParseID(o)
	if err != nil {
		return nil, err
	}
	if err = tx.Commit(ctx); err != nil {
		return nil, err
	}
	return &Claim{Principal: Principal{EnvironmentID: env, UserID: user, Kind: "SYSTEM"}, JobID: job, OperationID: op, Generation: generation, Owner: owner}, nil
}

func nativeCurrentClaim(ctx context.Context, tx pgx.Tx, c Claim) error {
	var valid bool
	err := tx.QueryRow(ctx, `SELECT claim_generation=$4 AND lease_owner=$5 AND lease_until>clock_timestamp() AND state='RUNNING' AND NOT paused AND operation_id=$6 FROM native_jobs WHERE environment_id=$1 AND user_id=$2 AND id=$3 FOR UPDATE`, c.Principal.EnvironmentID.String(), c.Principal.UserID.String(), c.JobID.String(), c.Generation, c.Owner, c.OperationID.String()).Scan(&valid)
	if err != nil {
		return err
	}
	if !valid {
		return ErrClaimLost
	}
	return nil
}

func (s *Service) lockNativeClaim(ctx context.Context, tx pgx.Tx, c Claim) error {
	env, err := s.environment(ctx, tx, true)
	if err != nil {
		return err
	}
	if err = sameUser(c.Principal, env.ID); err != nil {
		return err
	}
	if _, _, err = lockUser(ctx, tx, c.Principal); err != nil {
		return err
	}
	var id string
	if err = tx.QueryRow(ctx, `SELECT id::text FROM native_operations WHERE environment_id=$1 AND user_id=$2 AND id=$3 FOR UPDATE`, env.ID.String(), c.Principal.UserID.String(), c.OperationID.String()).Scan(&id); err != nil {
		return err
	}
	return nativeCurrentClaim(ctx, tx, c)
}

type nativePermitted struct {
	Request          bankv2.Request
	Signature, State string
	Cancelled        bool
}

type nativeSubmissionProof struct {
	Protocol        string                    `json:"protocol"`
	OperationID     funds.ID                  `json:"operation_id"`
	PermitID        string                    `json:"permit_id"`
	BankRequestHash string                    `json:"bank_request_hash"`
	EffectHash      string                    `json:"effect_hash"`
	SignatureHash   string                    `json:"signature_hash"`
	Approval        nativeJointApproval       `json:"approval"`
	DecisionAt      time.Time                 `json:"decision_at"`
	Witness         *nativeJointPermitWitness `json:"witness,omitempty"`
}

type nativePrefixReceipt struct {
	OperationID string `json:"operation_id"`
	ReceiptID   string `json:"receipt_id"`
	ReceiptHash string `json:"receipt_hash"`
}

type nativeJointPermitWitness struct {
	Algorithm            string                       `json:"algorithm"`
	FundsVersion         uint64                       `json:"funds_version"`
	SourceVersion        uint64                       `json:"source_version"`
	WriterGeneration     uint64                       `json:"writer_generation"`
	ControlVersion       uint64                       `json:"control_version"`
	ReservedFundsVersion uint64                       `json:"reserved_funds_version"`
	PrefixSettled        int                          `json:"prefix_settled"`
	SourceHash           string                       `json:"source_hash"`
	InventoryHash        string                       `json:"inventory_hash"`
	PolicyReferences     []NativeJointPolicyReference `json:"policy_references"`
	PolicyViews          []TemplatePolicyView         `json:"policy_views"`
	ForecastInput        planning.ForecastInput       `json:"forecast_input"`
	PrefixReceipts       []nativePrefixReceipt        `json:"prefix_receipts"`
}

func (s *Service) nativePermit(ctx context.Context, c Claim) (nativePermitted, error) {
	var out nativePermitted
	var commandKind string
	if err := s.Pool.QueryRow(ctx, `SELECT command_kind FROM native_operations WHERE environment_id=$1 AND user_id=$2 AND id=$3`, c.Principal.EnvironmentID.String(), c.Principal.UserID.String(), c.OperationID.String()).Scan(&commandKind); err != nil {
		return out, err
	}
	if commandKind == "BRIDGE_TRANSFER" || commandKind == "BRIDGE_ALLOCATE" {
		return s.bridgePermit(ctx, c)
	}
	if nativeStandingBridgeKind(commandKind) {
		return s.standingBridgePermit(ctx, c)
	}
	if commandKind == string(bankv2.MoveGoal) {
		return s.goalTransferPermit(ctx, c)
	}
	if commandKind == string(bankv2.Payment) {
		return s.paymentPermit(ctx, c)
	}
	if commandKind == nativeStandingAllocateKind {
		return s.standingNativePermit(ctx, c)
	}
	if nativeAssetKind(bankv2.Kind(commandKind)) {
		return s.assetPermit(ctx, c)
	}
	if commandKind != "JOINT_ALLOCATE" {
		return out, reject("UNSUPPORTED_OPERATION", nil)
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
	var hash, effectHash, group string
	var signature *string
	var reservedFV uint64
	var child int
	var confirmation string
	err = tx.QueryRow(ctx, `SELECT status,bank_request,bank_request_hash,effect_hash,group_id::text,child_number,confirmation_id::text,reserved_funds_version,permit_signature FROM native_operations WHERE environment_id=$1 AND user_id=$2 AND id=$3`, p.EnvironmentID.String(), p.UserID.String(), c.OperationID.String()).Scan(&out.State, &raw, &hash, &effectHash, &group, &child, &confirmation, &reservedFV, &signature)
	if err != nil {
		return out, err
	}
	if err = decode(raw, &out.Request); err != nil {
		return out, reject("EVIDENCE_INVALID", err)
	}
	requestHash, e := out.Request.Digest()
	effect, e2 := out.Request.Effect.Digest()
	if e != nil || e2 != nil || requestHash != hash || effect != effectHash || out.Request.Namespace != s.Namespace || out.Request.UserID != p.UserID.String() || out.Request.OperationID != c.OperationID.String() {
		return out, reject("EVIDENCE_INVALID", nil)
	}
	if out.State == "SETTLED" || out.State == "REJECTED" || out.State == "CANCELLED" {
		out.Cancelled = true
		return out, nil
	}
	// Signed originals recover after expiry, policy changes or session revocation.
	if signature != nil {
		if err = nativeStoredPermit(ctx, tx, p, c.OperationID, out.Request, *signature); err != nil {
			return out, err
		}
		out.Signature = *signature
		return out, tx.Commit(ctx)
	}
	if out.State != "QUEUED" {
		return out, reject("EVIDENCE_INVALID", nil)
	}
	groupID, err := funds.ParseID(group)
	if err != nil {
		return out, err
	}
	plan, err := loadNativeJointPlan(ctx, tx, p, groupID)
	if err != nil {
		return out, err
	}
	var approvalRaw []byte
	var approvalHash string
	if err = tx.QueryRow(ctx, `SELECT original,original_hash FROM native_confirmations WHERE environment_id=$1 AND user_id=$2 AND id=$3`, p.EnvironmentID.String(), p.UserID.String(), confirmation).Scan(&approvalRaw, &approvalHash); err != nil {
		return out, err
	}
	var approval nativeJointApproval
	if Hash(approvalRaw) != approvalHash || decode(approvalRaw, &approval) != nil {
		return out, reject("EVIDENCE_INVALID", nil)
	}
	decisionAt := s.now()
	witness := nativeJointPermitWitness{}
	permissionErr := s.validateNativeJointPermit(ctx, tx, p, plan, approval, out.Request, child, reservedFV, decisionAt, &witness)
	if permissionErr != nil {
		if Code(permissionErr) == "INTERNAL_ERROR" {
			return out, permissionErr
		}
		if err = s.cancelNativeUnsigned(ctx, tx, c, Code(permissionErr)); err != nil {
			return out, err
		}
		out.Cancelled = true
		return out, tx.Commit(ctx)
	}
	out.Signature, err = bankv2.SignPermit(out.Request, s.PermitSecret)
	if err != nil {
		return out, err
	}
	proof := nativeSubmissionProof{Protocol: "native-submission-permit-v2", OperationID: c.OperationID, PermitID: out.Request.PermitID, BankRequestHash: hash, EffectHash: effectHash, SignatureHash: Hash([]byte(out.Signature)), Approval: approval, DecisionAt: decisionAt, Witness: &witness}
	proofRaw, err := encode(proof)
	if err != nil {
		return out, err
	}
	_, err = tx.Exec(ctx, `INSERT INTO native_submission_permits(environment_id,user_id,operation_id,permit_id,bank_request_hash,effect_hash,signature_hash,original,original_hash,decision_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`, p.EnvironmentID.String(), p.UserID.String(), c.OperationID.String(), out.Request.PermitID, hash, effectHash, proof.SignatureHash, proofRaw, Hash(proofRaw), decisionAt)
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

// Recovery checks the actual immutable T2 original. Rotating today's signing
// key must not prevent querying and booking a bank fact under yesterday's key.
// The stored request and signature are never replaced or signed again.
func nativeStoredPermit(ctx context.Context, q queryRow, p Principal, operation funds.ID, request bankv2.Request, signature string) error {
	return nativeStoredPermitRead(ctx, q, p, operation, request, signature, nil)
}

// NativeActivityOriginal alone obtains this concrete transaction from its
// RepeatableRead ReadOnly Pool.BeginTx. Other callers retain both full reads.
func nativeActivityStoredPermit(ctx context.Context, tx *pgxpool.Tx, p Principal, operation funds.ID, request bankv2.Request, signature string) error {
	return nativeStoredPermitRead(ctx, tx, p, operation, request, signature, tx)
}

func nativeStoredPermitRead(ctx context.Context, q queryRow, p Principal, operation funds.ID, request bankv2.Request, signature string, activityTx *pgxpool.Tx) error {
	var raw []byte
	var rawHash, requestHash, effectHash, signatureHash, permitID string
	err := q.QueryRow(ctx, `SELECT original,original_hash,bank_request_hash,effect_hash,signature_hash,permit_id::text FROM native_submission_permits WHERE environment_id=$1 AND user_id=$2 AND operation_id=$3`, p.EnvironmentID.String(), p.UserID.String(), operation.String()).Scan(&raw, &rawHash, &requestHash, &effectHash, &signatureHash, &permitID)
	if err != nil {
		return reject("EVIDENCE_INVALID", err)
	}
	want, err := request.Digest()
	if err != nil {
		return reject("EVIDENCE_INVALID", err)
	}
	effect, err := request.Effect.Digest()
	if err != nil {
		return reject("EVIDENCE_INVALID", err)
	}
	var proof nativeSubmissionProof
	var protocol struct {
		Protocol string `json:"protocol"`
	}
	if decode(raw, &protocol) == nil && protocol.Protocol == "native-bridge-submission-permit-v1" {
		return bridgeStoredPermit(ctx, q, p, operation, request, signature)
	}
	if protocol.Protocol == "native-goal-transfer-submission-permit-v1" {
		return goalTransferStoredPermit(ctx, q, p, operation, request, signature)
	}
	if protocol.Protocol == nativePaymentPermitProtocol || protocol.Protocol == nativeStandingPaymentPermitProtocol {
		return paymentStoredPermit(ctx, q, p, operation, request, signature)
	}
	if protocol.Protocol == nativeStandingPermitProtocol || protocol.Protocol == "native-standing-submission-permit-v2" {
		return standingNativeStoredPermit(ctx, q, p, operation, request, signature)
	}
	if protocol.Protocol == nativeStandingBridgePermitProtocol {
		return standingBridgeStoredPermit(ctx, q, p, operation, request, signature)
	}
	if protocol.Protocol == nativeAssetPermitProtocol || protocol.Protocol == nativeStandingAssetProtocol+"/permit" || protocol.Protocol == nativeStandingAssetPermitV2Protocol {
		if fact := captureNativeActivityPermitRaw(q, activityTx, p, operation, request.Effect.Kind, raw); fact != nil {
			return assetStoredPermitWithActivityRaw(ctx, q, p, operation, request, signature, fact)
		}
		return assetStoredPermit(ctx, q, p, operation, request, signature)
	}
	if Hash(raw) != rawHash || decode(raw, &proof) != nil || (proof.Protocol != "native-submission-permit-v1" && proof.Protocol != "native-submission-permit-v2") || proof.OperationID != operation || proof.PermitID != permitID || permitID != request.PermitID || requestHash != want || effectHash != effect || signatureHash != Hash([]byte(signature)) || proof.BankRequestHash != requestHash || proof.EffectHash != effectHash || proof.SignatureHash != signatureHash || proof.DecisionAt.Before(request.RequestedAt) || !proof.DecisionAt.Before(request.ExpiresAt) {
		return reject("EVIDENCE_INVALID", nil)
	}
	if proof.Protocol == "native-submission-permit-v2" && (proof.Witness == nil || proof.Witness.Algorithm != "frozen-joint-exact-owned-prefix-v1" || proof.Witness.SourceHash != proof.Witness.ForecastInput.Facts.SourceHash || proof.Witness.FundsVersion != proof.Witness.ReservedFundsVersion+uint64(proof.Witness.PrefixSettled) || len(proof.Witness.PrefixReceipts) != proof.Witness.PrefixSettled) {
		return reject("EVIDENCE_INVALID", nil)
	}
	return nil
}

func (s *Service) validateNativeJointPermit(ctx context.Context, tx pgx.Tx, p Principal, plan NativeJointPlan, approval nativeJointApproval, request bankv2.Request, child int, reservedFV uint64, now time.Time, witness *nativeJointPermitWitness) error {
	reviewHash, err := NativeJointReviewHash(plan)
	if err != nil {
		return err
	}
	if approval.Protocol != "native-joint-user-confirmation-v1" || approval.PrincipalKind != "USER" || approval.EnvironmentID != p.EnvironmentID || approval.UserID != p.UserID || approval.PlanID != plan.ID || approval.ReviewedBundleHash != reviewHash || request.ReferenceHash != reviewHash || !approval.ExpiresAt.Equal(plan.ExpiresAt) || !now.Before(plan.ExpiresAt) || now.Before(approval.ConfirmedAt) {
		return reject("AUTHORIZATION_EXPIRED", nil)
	}
	if child < 1 || child > len(plan.Result.Children) || len(approval.ChildEffectHashes) != len(plan.Result.Children) {
		return reject("EVIDENCE_INVALID", nil)
	}
	effectHash, _ := request.Effect.Digest()
	if approval.ChildEffectHashes[child-1] != effectHash {
		return reject("EVIDENCE_INVALID", nil)
	}
	human := p
	human.Kind = "USER"
	human.SessionID = approval.SessionID
	if err = s.human(ctx, tx, human); err != nil {
		return err
	}
	var fv, sv, wg, cv uint64
	if err = tx.QueryRow(ctx, `SELECT u.funds_version,u.source_version,e.writer_generation,e.control_version FROM users u JOIN environments e ON e.id=u.environment_id WHERE u.environment_id=$1 AND u.id=$2`, p.EnvironmentID.String(), p.UserID.String()).Scan(&fv, &sv, &wg, &cv); err != nil {
		return err
	}
	var prior, settled int
	if err = tx.QueryRow(ctx, `SELECT count(*),count(*) FILTER(WHERE status='SETTLED' AND receipt_id IS NOT NULL) FROM native_operations WHERE environment_id=$1 AND user_id=$2 AND group_id=$3 AND child_number<$4`, p.EnvironmentID.String(), p.UserID.String(), plan.ID.String(), child).Scan(&prior, &settled); err != nil {
		return err
	}
	if prior != child-1 || settled != prior {
		return reject("PREVIOUS_OPERATION_UNSETTLED", nil)
	}
	if fv != reservedFV+uint64(settled) || sv != plan.Dependencies.SourceEvidenceVersion+uint64(settled) || wg != plan.Dependencies.WriterGeneration || cv != plan.Dependencies.ControlVersion {
		return reject("SOURCE_CHANGED", nil)
	}
	snapshot, err := s.loadTemplateSnapshot(ctx, tx, p, now, plan.Input.ProtectionForecast.Timezone)
	if err != nil {
		return err
	}
	_, refs, err := nativeJointGoals(snapshot)
	if err != nil {
		return err
	}
	if len(refs) != len(plan.PolicyReferences) {
		return reject("SOURCE_CHANGED", nil)
	}
	for i, ref := range refs {
		want := plan.PolicyReferences[i]
		var own uint64
		if err = tx.QueryRow(ctx, `SELECT count(*) FROM native_operations WHERE environment_id=$1 AND user_id=$2 AND group_id=$3 AND child_number<$4 AND status='SETTLED' AND subject_goal_ids @> ARRAY[$5::uuid]`, p.EnvironmentID.String(), p.UserID.String(), plan.ID.String(), child, ref.GoalID.String()).Scan(&own); err != nil {
			return err
		}
		want.GoalVersion += own
		if ref != want {
			return reject("SOURCE_CHANGED", nil)
		}
	}
	*witness = nativeJointPermitWitness{Algorithm: "frozen-joint-exact-owned-prefix-v1", FundsVersion: fv, SourceVersion: sv, WriterGeneration: wg, ControlVersion: cv, ReservedFundsVersion: reservedFV, PrefixSettled: settled, SourceHash: snapshot.Facts.SourceHash, InventoryHash: Hash(snapshot.InventoryRaw), PolicyReferences: refs, PolicyViews: snapshot.Views, ForecastInput: snapshot.forecastInput(365), PrefixReceipts: []nativePrefixReceipt{}}
	rows, err := tx.Query(ctx, `SELECT o.id::text,r.id::text,r.original_hash::text FROM native_operations o JOIN native_receipts r ON(r.environment_id=o.environment_id AND r.user_id=o.user_id AND r.id=o.receipt_id AND r.operation_id=o.id) WHERE o.environment_id=$1 AND o.user_id=$2 AND o.group_id=$3 AND o.child_number<$4 ORDER BY o.child_number`, p.EnvironmentID.String(), p.UserID.String(), plan.ID.String(), child)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var receipt nativePrefixReceipt
		if err = rows.Scan(&receipt.OperationID, &receipt.ReceiptID, &receipt.ReceiptHash); err != nil {
			return err
		}
		witness.PrefixReceipts = append(witness.PrefixReceipts, receipt)
	}
	if err = rows.Err(); err != nil {
		return err
	}
	if len(witness.PrefixReceipts) != settled {
		return reject("EVIDENCE_INVALID", nil)
	}
	return nil
}

func (s *Service) cancelNativeUnsigned(ctx context.Context, tx pgx.Tx, c Claim, reason string) error {
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
	if _, err = tx.Exec(ctx, `UPDATE native_operations SET status='CANCELLED',processing_health=$4,version=version+1,updated_at=$5 WHERE environment_id=$1 AND user_id=$2 AND id=$3 AND permit_signature IS NULL`, p.EnvironmentID.String(), p.UserID.String(), c.OperationID.String(), reason, s.now()); err != nil {
		return err
	}
	if err = s.Store.PersistNativeLedger(ctx, tx, p.EnvironmentID, p.UserID, ledger); err != nil {
		return err
	}
	if err = s.recordNativeCancellation(ctx, tx, p, c.OperationID, reason); err != nil {
		return err
	}
	if _, err = tx.Exec(ctx, `UPDATE users SET funds_version=funds_version+1 WHERE environment_id=$1 AND id=$2`, p.EnvironmentID.String(), p.UserID.String()); err != nil {
		return err
	}
	if err = s.refreshNativeOperationProtection(ctx, tx, p, c.OperationID); err != nil {
		return err
	}
	_, err = tx.Exec(ctx, `UPDATE native_jobs SET state='FINISHED',lease_owner=NULL,lease_until=NULL,last_error=$4 WHERE environment_id=$1 AND user_id=$2 AND id=$3`, p.EnvironmentID.String(), p.UserID.String(), c.JobID.String(), reason)
	return err
}

func (s *Service) ProcessNativeClaim(ctx context.Context, c Claim) error {
	permit, err := s.nativePermit(ctx, c)
	if err != nil {
		if errors.Is(err, ErrClaimLost) {
			return err
		}
		return s.nativeFailure(ctx, c, err)
	}
	if permit.Cancelled {
		return nil
	}
	if s.Failpoint != nil {
		if err = s.Failpoint("native_after_permit_commit"); err != nil {
			return err
		}
	}
	if s.NativeBank == nil {
		return s.nativeFailure(ctx, c, reject("BANK_UNAVAILABLE", nil))
	}
	result, err := s.NativeBank.Lookup(ctx, s.Namespace, permit.Request.UserID, permit.Request.Key)
	if err == nil {
		err = bankv2.VerifyResult(permit.Request, result)
	}
	if err == nil && result.Status == bankv2.NotFound {
		if _, recovering := ctx.Value(recoveryIntentKey{}).(recoveryIntent); recovering {
			return s.nativeFailure(ctx, c, reject("OPERATION_UNKNOWN", nil))
		}
		if permit.State == "PENDING_SETTLEMENT" || permit.State == "RECONCILING" {
			return s.nativeFailure(ctx, c, reject("OPERATION_UNKNOWN", nil))
		}
		result, err = s.NativeBank.Submit(ctx, permit.Request, permit.Signature)
	}
	if err == nil && result.Status == bankv2.Accepted && result.AvailableAt != nil && !s.now().Before(*result.AvailableAt) {
		result, err = s.NativeBank.Settle(ctx, s.Namespace, permit.Request.UserID, permit.Request.Key)
	}
	if err != nil {
		return s.nativeFailure(ctx, c, reject("BANK_UNAVAILABLE", err))
	}
	if err = bankv2.VerifyResult(permit.Request, result); err != nil {
		return s.nativeFailure(ctx, c, reject("EVIDENCE_INVALID", err))
	}
	if s.Failpoint != nil {
		if err = s.Failpoint("native_after_bank_commit"); err != nil {
			return err
		}
	}
	return s.nativeObservation(ctx, c, permit.Request, result)
}

func (s *Service) refreshNativeOperationProtection(ctx context.Context, tx pgx.Tx, p Principal, id funds.ID) error {
	var kind string
	if err := tx.QueryRow(ctx, `SELECT command_kind FROM native_operations WHERE environment_id=$1 AND user_id=$2 AND id=$3`, p.EnvironmentID.String(), p.UserID.String(), id.String()).Scan(&kind); err != nil {
		return err
	}
	if kind == string(bankv2.MoveGoal) {
		return s.goalTransferProtection(ctx, tx, p, id)
	}
	if kind == string(bankv2.Payment) {
		return s.paymentProtection(ctx, tx, p, id)
	}
	if kind == nativeStandingAllocateKind {
		return s.standingNativeProtection(ctx, tx, p, id)
	}
	if nativeStandingBridgeKind(kind) {
		return s.standingBridgeProtection(ctx, tx, p, id)
	}
	if nativeAssetKind(bankv2.Kind(kind)) {
		zone, err := assetOperationTimezone(ctx, tx, p, id)
		if err != nil {
			return err
		}
		_, _, err = s.refreshTemplateProtectionAfterNativeEffect(ctx, tx, p, zone)
		return err
	}
	var planText string
	if err := tx.QueryRow(ctx, `SELECT plan_id::text FROM native_operations WHERE environment_id=$1 AND user_id=$2 AND id=$3`, p.EnvironmentID.String(), p.UserID.String(), id.String()).Scan(&planText); err != nil {
		return err
	}
	planID, err := funds.ParseID(planText)
	if err != nil {
		return err
	}
	plan, err := loadNativeJointPlan(ctx, tx, p, planID)
	if err != nil {
		return err
	}
	_, _, err = s.refreshTemplateProtectionAfterNativeEffect(ctx, tx, p, plan.Input.ProtectionForecast.Timezone)
	return err
}

func (s *Service) NativeWorkerStep(ctx context.Context, owner string, lease time.Duration) (bool, error) {
	c, err := s.ClaimNativeJob(ctx, owner, lease)
	if err != nil || c == nil {
		return false, err
	}
	return true, s.ProcessNativeClaim(ctx, *c)
}

func (s *Service) nativeFailure(ctx context.Context, c Claim, cause error) error {
	tx, err := s.begin(ctx)
	if err != nil {
		return err
	}
	defer rollback(ctx, tx)
	if err = s.lockNativeClaim(ctx, tx, c); err != nil {
		return err
	}
	p := c.Principal
	var attempts, maxAttempts int
	if err = tx.QueryRow(ctx, `SELECT attempts,max_attempts FROM native_jobs WHERE environment_id=$1 AND user_id=$2 AND id=$3`, p.EnvironmentID.String(), p.UserID.String(), c.JobID.String()).Scan(&attempts, &maxAttempts); err != nil {
		return err
	}
	state, health := "READY", "RETRYING"
	paused := attempts >= maxAttempts
	if paused {
		state = "EXHAUSTED"
		health = "PAUSED"
	}
	_, err = tx.Exec(ctx, `UPDATE native_operations SET status=CASE WHEN status='SUBMITTING' THEN 'UNKNOWN' ELSE status END,processing_health=$4,version=version+1,updated_at=$5 WHERE environment_id=$1 AND user_id=$2 AND id=$3 AND status NOT IN ('SETTLED','REJECTED','CANCELLED')`, p.EnvironmentID.String(), p.UserID.String(), c.OperationID.String(), health, s.now())
	if err != nil {
		return err
	}
	_, err = tx.Exec(ctx, `UPDATE native_jobs SET state=$4,paused=$5,lease_owner=NULL,lease_until=NULL,last_error=$6,next_attempt_at=clock_timestamp()+$7::bigint*interval '1 millisecond' WHERE environment_id=$1 AND user_id=$2 AND id=$3`, p.EnvironmentID.String(), p.UserID.String(), c.JobID.String(), state, paused, Code(cause), 100*(1<<min(attempts, 8)))
	if err != nil {
		return err
	}
	if err = tx.Commit(ctx); err != nil {
		return err
	}
	return cause
}
