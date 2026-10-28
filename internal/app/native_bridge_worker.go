package app

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5"
	"zhiyu.local/zhiyu-go/internal/adapters/postgres"
	"zhiyu.local/zhiyu-go/internal/execution/bankv2"
	funds "zhiyu.local/zhiyu-go/internal/funds/domain"
)

const nativeBridgePermitProtocol = "native-bridge-submission-permit-v1"

type nativeBridgeSubmissionProof struct {
	Protocol        string                   `json:"protocol"`
	EnvironmentID   funds.ID                 `json:"environment_id"`
	UserID          funds.ID                 `json:"user_id"`
	OperationID     funds.ID                 `json:"operation_id"`
	PermitID        string                   `json:"permit_id"`
	BankRequestHash string                   `json:"bank_request_hash"`
	EffectHash      string                   `json:"effect_hash"`
	SignatureHash   string                   `json:"signature_hash"`
	StepNumber      int                      `json:"step_number"`
	Approval        nativeBridgeApproval     `json:"approval"`
	DecisionAt      time.Time                `json:"decision_at"`
	Witness         nativeJointPermitWitness `json:"witness"`
}
type nativeBridgeBatch struct {
	Preview                                    NativeBridgePreview
	Plan                                       NativeJointPlan
	Approval                                   nativeBridgeApproval
	ReservedFV, SourceVersion, Writer, Control uint64
	Key                                        string
	Command                                    []byte
}

func (s *Service) bridgeBatch(ctx context.Context, tx pgx.Tx, p Principal, group funds.ID) (nativeBridgeBatch, error) {
	var out nativeBridgeBatch
	var raw []byte
	var hash string
	err := tx.QueryRow(ctx, `SELECT original,original_hash,reserved_funds_version,source_version,writer_generation,control_version,idempotency_key,request FROM native_group_batches WHERE environment_id=$1 AND user_id=$2 AND id=$3`, p.EnvironmentID.String(), p.UserID.String(), group.String()).Scan(&raw, &hash, &out.ReservedFV, &out.SourceVersion, &out.Writer, &out.Control, &out.Key, &out.Command)
	if err != nil {
		return out, err
	}
	if Hash(raw) != hash || decode(raw, &out.Approval) != nil || out.Approval.Protocol != NativeBridgeProtocol+"/USER" || out.Approval.PrincipalKind != "USER" || out.Approval.EnvironmentID != p.EnvironmentID || out.Approval.UserID != p.UserID || out.Approval.GroupID != group {
		return out, reject("EVIDENCE_INVALID", nil)
	}
	out.Preview, err = loadNativeBridgePreview(ctx, tx, p, group)
	if err != nil {
		return out, err
	}
	out.Plan, err = loadNativeJointPlan(ctx, tx, p, out.Preview.PlanID)
	if err != nil {
		return out, err
	}
	if out.Approval.PlanID != out.Plan.ID || out.Approval.ReviewedHash != out.Preview.ReviewHash || !out.Approval.ExpiresAt.Equal(out.Preview.ExpiresAt) || len(out.Approval.StepEffectHashes) != len(out.Preview.Steps) {
		return out, reject("EVIDENCE_INVALID", nil)
	}
	for i, step := range out.Preview.Steps {
		if out.Approval.StepEffectHashes[i] != step.EffectHash {
			return out, reject("EVIDENCE_INVALID", nil)
		}
	}
	return out, nil
}

func bridgeStoredPermit(ctx context.Context, q queryRow, p Principal, operation funds.ID, request bankv2.Request, signature string) error {
	var raw []byte
	var rawHash, rh, eh, sh, permit string
	if err := q.QueryRow(ctx, `SELECT original,original_hash,bank_request_hash,effect_hash,signature_hash,permit_id::text FROM native_submission_permits WHERE environment_id=$1 AND user_id=$2 AND operation_id=$3`, p.EnvironmentID.String(), p.UserID.String(), operation.String()).Scan(&raw, &rawHash, &rh, &eh, &sh, &permit); err != nil {
		return reject("EVIDENCE_INVALID", err)
	}
	var proof nativeBridgeSubmissionProof
	want, err := request.Digest()
	effect, e2 := request.Effect.Digest()
	if err != nil || e2 != nil || Hash(raw) != rawHash || decode(raw, &proof) != nil || proof.Protocol != nativeBridgePermitProtocol || proof.EnvironmentID != p.EnvironmentID || proof.UserID != p.UserID || proof.OperationID != operation || proof.PermitID != permit || permit != request.PermitID || rh != want || eh != effect || sh != Hash([]byte(signature)) || proof.BankRequestHash != rh || proof.EffectHash != eh || proof.SignatureHash != sh || proof.DecisionAt.Before(request.RequestedAt) || !proof.DecisionAt.Before(request.ExpiresAt) || proof.StepNumber < 1 || proof.StepNumber > len(proof.Approval.StepEffectHashes) || proof.Approval.StepEffectHashes[proof.StepNumber-1] != eh || proof.Witness.Algorithm != "frozen-bridge-arrival-prefix-v1" || proof.Witness.PrefixSettled != proof.StepNumber-1 || proof.Witness.FundsVersion != proof.Witness.ReservedFundsVersion+uint64(proof.Witness.PrefixSettled) || len(proof.Witness.PrefixReceipts) != proof.Witness.PrefixSettled || proof.Witness.SourceHash != proof.Witness.ForecastInput.Facts.SourceHash {
		return reject("EVIDENCE_INVALID", nil)
	}
	return nil
}

func (s *Service) bridgePermit(ctx context.Context, c Claim) (nativePermitted, error) {
	var out nativePermitted
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
	var rh, eh, group, kind string
	var signature *string
	var number int
	if err = tx.QueryRow(ctx, `SELECT status,bank_request,bank_request_hash,effect_hash,group_id::text,child_number,command_kind,permit_signature FROM native_operations WHERE environment_id=$1 AND user_id=$2 AND id=$3`, p.EnvironmentID.String(), p.UserID.String(), c.OperationID.String()).Scan(&out.State, &raw, &rh, &eh, &group, &number, &kind, &signature); err != nil {
		return out, err
	}
	if kind != "BRIDGE_TRANSFER" && kind != "BRIDGE_ALLOCATE" {
		return out, reject("UNSUPPORTED_OPERATION", nil)
	}
	if decode(raw, &out.Request) != nil {
		return out, reject("EVIDENCE_INVALID", nil)
	}
	want, e := out.Request.Digest()
	effect, e2 := out.Request.Effect.Digest()
	if e != nil || e2 != nil || want != rh || effect != eh || out.Request.Namespace != s.Namespace || out.Request.UserID != p.UserID.String() || out.Request.OperationID != c.OperationID.String() {
		return out, reject("EVIDENCE_INVALID", nil)
	}
	if out.State == "SETTLED" || out.State == "CANCELLED" || out.State == "REJECTED" {
		out.Cancelled = true
		return out, nil
	}
	if signature != nil {
		if err = bridgeStoredPermit(ctx, tx, p, c.OperationID, out.Request, *signature); err != nil {
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
	batch, err := s.bridgeBatch(ctx, tx, p, groupID)
	if err != nil {
		return out, err
	}
	now := s.now()
	witness := nativeJointPermitWitness{}
	permissionErr := s.bridgeValidatePermit(ctx, tx, p, batch, out.Request, number, now, &witness)
	if permissionErr != nil {
		if Code(permissionErr) == "INTERNAL_ERROR" || Code(permissionErr) == "PREVIOUS_OPERATION_UNSETTLED" {
			return out, permissionErr
		}
		ledger, e := s.Store.LoadNativeLedger(ctx, tx, p.EnvironmentID, p.UserID, now)
		if e != nil {
			return out, e
		}
		if err = s.bridgeCancelSuffix(ctx, tx, c, &ledger, Code(permissionErr)); err != nil {
			return out, err
		}
		if err = s.Store.PersistNativeLedger(ctx, tx, p.EnvironmentID, p.UserID, ledger); err != nil {
			return out, err
		}
		if _, err = tx.Exec(ctx, `UPDATE users SET funds_version=funds_version+1 WHERE environment_id=$1 AND id=$2`, p.EnvironmentID.String(), p.UserID.String()); err != nil {
			return out, err
		}
		if _, _, err = s.refreshTemplateProtectionAfterNativeEffect(ctx, tx, p, batch.Plan.Input.ProtectionForecast.Timezone); err != nil {
			return out, err
		}
		if err = finishNativeJob(ctx, tx, c); err != nil {
			return out, err
		}
		out.Cancelled = true
		return out, tx.Commit(ctx)
	}
	out.Signature, err = bankv2.SignPermit(out.Request, s.PermitSecret)
	if err != nil {
		return out, err
	}
	proof := nativeBridgeSubmissionProof{nativeBridgePermitProtocol, p.EnvironmentID, p.UserID, c.OperationID, out.Request.PermitID, rh, eh, Hash([]byte(out.Signature)), number, batch.Approval, now, witness}
	proofRaw, err := encode(proof)
	if err != nil {
		return out, err
	}
	_, err = tx.Exec(ctx, `INSERT INTO native_submission_permits(environment_id,user_id,operation_id,permit_id,bank_request_hash,effect_hash,signature_hash,original,original_hash,decision_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`, p.EnvironmentID.String(), p.UserID.String(), c.OperationID.String(), out.Request.PermitID, rh, eh, proof.SignatureHash, proofRaw, Hash(proofRaw), now)
	if err != nil {
		return out, err
	}
	_, err = tx.Exec(ctx, `UPDATE native_operations SET status='SUBMITTING',permit_signature=$4,version=version+1,updated_at=$5 WHERE environment_id=$1 AND user_id=$2 AND id=$3`, p.EnvironmentID.String(), p.UserID.String(), c.OperationID.String(), out.Signature, now)
	if err != nil {
		return out, err
	}
	out.State = "SUBMITTING"
	return out, tx.Commit(ctx)
}

func (s *Service) bridgeValidatePermit(ctx context.Context, tx pgx.Tx, p Principal, batch nativeBridgeBatch, request bankv2.Request, number int, now time.Time, witness *nativeJointPermitWitness) error {
	if number < 1 || number > len(batch.Preview.Steps) || !now.Before(batch.Preview.ExpiresAt) || now.Before(batch.Approval.ConfirmedAt) {
		return reject("AUTHORIZATION_EXPIRED", nil)
	}
	step := batch.Preview.Steps[number-1]
	rh, err := request.Digest()
	if err != nil || rh != step.RequestHash || step.OperationID.String() != request.OperationID {
		return reject("EVIDENCE_INVALID", err)
	}
	human := p
	human.Kind = "USER"
	human.SessionID = batch.Approval.SessionID
	if err = s.human(ctx, tx, human); err != nil {
		return err
	}
	var fv, sv, wg, cv uint64
	if err = tx.QueryRow(ctx, `SELECT u.funds_version,u.source_version,e.writer_generation,e.control_version FROM users u JOIN environments e ON e.id=u.environment_id WHERE u.environment_id=$1 AND u.id=$2`, p.EnvironmentID.String(), p.UserID.String()).Scan(&fv, &sv, &wg, &cv); err != nil {
		return err
	}
	if fv != batch.ReservedFV+uint64(number-1) || sv != batch.SourceVersion+uint64(number-1) || wg != batch.Writer || cv != batch.Control {
		return reject("SOURCE_CHANGED", nil)
	}
	prefix := []nativePrefixReceipt{}
	allocations := map[funds.ID]uint64{}
	for i := 0; i < number-1; i++ {
		prior := batch.Preview.Steps[i]
		var state, id, hash string
		var raw []byte
		if err = tx.QueryRow(ctx, `SELECT o.status,r.id::text,r.original_hash::text,r.original FROM native_operations o JOIN native_receipts r ON(r.environment_id=o.environment_id AND r.user_id=o.user_id AND r.operation_id=o.id AND r.id=o.receipt_id) WHERE o.environment_id=$1 AND o.user_id=$2 AND o.id=$3`, p.EnvironmentID.String(), p.UserID.String(), prior.OperationID.String()).Scan(&state, &id, &hash, &raw); err != nil {
			return reject("PREVIOUS_OPERATION_UNSETTLED", err)
		}
		var receipt NativeReceipt
		if state != "SETTLED" || Hash(raw) != hash || decode(raw, &receipt) != nil || receipt.OperationID != prior.OperationID || receipt.GroupID != batch.Preview.ID || receipt.BankResult.Status != bankv2.Settled || bankv2.VerifyResult(prior.Request, receipt.BankResult) != nil {
			return reject("EVIDENCE_INVALID", nil)
		}
		prefix = append(prefix, nativePrefixReceipt{prior.OperationID.String(), id, hash})
		if prior.Request.Effect.Kind == bankv2.Allocate {
			allocations[prior.GoalID]++
		}
	}
	snapshot, err := s.loadTemplateSnapshot(ctx, tx, p, now, batch.Plan.Input.ProtectionForecast.Timezone)
	if err != nil {
		return err
	}
	_, refs, err := nativeJointGoals(snapshot)
	if err != nil {
		return err
	}
	if len(refs) != len(batch.Plan.PolicyReferences) {
		return reject("SOURCE_CHANGED", nil)
	}
	for i, ref := range refs {
		expected := batch.Plan.PolicyReferences[i]
		expected.GoalVersion += allocations[ref.GoalID]
		if ref != expected {
			return reject("SOURCE_CHANGED", nil)
		}
	}
	ledger, err := s.Store.LoadLedger(ctx, tx, p.EnvironmentID, p.UserID, now)
	if err != nil {
		return err
	}
	matched := false
	for _, r := range ledger.Snapshot().Reservations {
		if r.ActionID != step.OperationID {
			continue
		}
		uses := map[funds.ID]funds.IncomeUse{}
		for _, use := range r.Uses {
			uses[use.FragmentID] = use
		}
		if r.State != funds.Reserved || r.Operation != step.Resources.IncomeOperation || len(uses) != len(step.Resources.IncomeUses) || (r.DestinationAccountID == nil) != (step.Resources.DestinationAccountID == nil) || r.DestinationAccountID != nil && *r.DestinationAccountID != *step.Resources.DestinationAccountID {
			return reject("EVIDENCE_INVALID", nil)
		}
		for _, use := range step.Resources.IncomeUses {
			if uses[use.FragmentID] != use {
				return reject("EVIDENCE_INVALID", nil)
			}
		}
		matched = true
	}
	if !matched {
		return reject("EVIDENCE_INVALID", nil)
	}
	*witness = nativeJointPermitWitness{Algorithm: "frozen-bridge-arrival-prefix-v1", FundsVersion: fv, SourceVersion: sv, WriterGeneration: wg, ControlVersion: cv, ReservedFundsVersion: batch.ReservedFV, PrefixSettled: number - 1, SourceHash: snapshot.Facts.SourceHash, InventoryHash: Hash(snapshot.InventoryRaw), PolicyReferences: refs, PolicyViews: snapshot.Views, ForecastInput: snapshot.forecastInput(365), PrefixReceipts: prefix}
	return nil
}

// bridgeCancelSuffix leaves every already-signed operation and its resources
// intact. Call it while holding the common user/claim lock, before one complete
// PersistNativeLedger. It also handles a rejected current step already released
// by the shared observation path.
func (s *Service) bridgeCancelSuffix(ctx context.Context, tx pgx.Tx, c Claim, ledger *postgres.NativeLedger, reason string) error {
	p := c.Principal
	var group string
	if err := tx.QueryRow(ctx, `SELECT group_id::text FROM native_operations WHERE environment_id=$1 AND user_id=$2 AND id=$3 AND command_kind IN ('BRIDGE_TRANSFER','BRIDGE_ALLOCATE')`, p.EnvironmentID.String(), p.UserID.String(), c.OperationID.String()).Scan(&group); err != nil {
		return err
	}
	rows, err := tx.Query(ctx, `SELECT id::text FROM native_operations WHERE environment_id=$1 AND user_id=$2 AND group_id=$3 AND permit_signature IS NULL AND status NOT IN ('SETTLED','REJECTED','CANCELLED') ORDER BY child_number`, p.EnvironmentID.String(), p.UserID.String(), group)
	if err != nil {
		return err
	}
	ids := []funds.ID{}
	for rows.Next() {
		var id string
		if err = rows.Scan(&id); err != nil {
			rows.Close()
			return err
		}
		parsed, e := funds.ParseID(id)
		if e != nil {
			rows.Close()
			return e
		}
		ids = append(ids, parsed)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return err
	}
	for _, id := range ids {
		ledger.Income, err = ledger.Income.Release(id, s.now(), true)
		if err != nil {
			return err
		}
		for i := range ledger.Holds {
			if ledger.Holds[i].OperationID == id {
				ledger.Holds[i].State = funds.Released
			}
		}
		if _, err = tx.Exec(ctx, `UPDATE native_operations SET status='CANCELLED',processing_health=$4,version=version+1,updated_at=$5 WHERE environment_id=$1 AND user_id=$2 AND id=$3 AND permit_signature IS NULL`, p.EnvironmentID.String(), p.UserID.String(), id.String(), reason, s.now()); err != nil {
			return err
		}
		if err = s.recordNativeCancellation(ctx, tx, p, id, reason); err != nil {
			return err
		}
		if _, err = tx.Exec(ctx, `UPDATE native_jobs SET state='FINISHED',lease_owner=NULL,lease_until=NULL,last_error=$4 WHERE environment_id=$1 AND user_id=$2 AND operation_id=$3`, p.EnvironmentID.String(), p.UserID.String(), id.String(), reason); err != nil {
			return err
		}
	}
	return nil
}
