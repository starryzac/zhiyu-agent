package app

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5"
	"zhiyu.local/zhiyu-go/internal/execution/bankv2"
	funds "zhiyu.local/zhiyu-go/internal/funds/domain"
	planning "zhiyu.local/zhiyu-go/internal/planning/domain"
	policy "zhiyu.local/zhiyu-go/internal/policy/domain"
)

const nativeGoalTransferPermitProtocol = "native-goal-transfer-submission-permit-v1"

type nativeGoalTransferWitness struct {
	Protocol             string                           `json:"protocol"`
	FundsVersion         uint64                           `json:"funds_version"`
	ReservedFundsVersion uint64                           `json:"reserved_funds_version"`
	SourceVersion        uint64                           `json:"source_version"`
	WriterGeneration     uint64                           `json:"writer_generation"`
	ControlVersion       uint64                           `json:"control_version"`
	SourceHash           string                           `json:"source_hash"`
	InventoryHash        string                           `json:"inventory_hash"`
	PairedInput          planning.PairedGoalTransferInput `json:"paired_input"`
	ForecastInput        planning.ForecastInput           `json:"forecast_input"`
	ForecastBefore       planning.ForecastResult          `json:"forecast_before"`
	ForecastAfter        planning.ForecastResult          `json:"forecast_after"`
}
type nativeGoalTransferSubmissionProof struct {
	Protocol        string                     `json:"protocol"`
	OperationID     funds.ID                   `json:"operation_id"`
	PreviewID       funds.ID                   `json:"preview_id"`
	PermitID        string                     `json:"permit_id"`
	BankRequestHash string                     `json:"bank_request_hash"`
	EffectHash      string                     `json:"effect_hash"`
	SignatureHash   string                     `json:"signature_hash"`
	Approval        nativeGoalTransferApproval `json:"approval"`
	Witness         nativeGoalTransferWitness  `json:"witness"`
	DecisionAt      time.Time                  `json:"decision_at"`
}

func goalTransferApprovals(ctx context.Context, q queryRow, p Principal, preview NativeGoalTransferPreview, request bankv2.Request) (nativeGoalTransferApproval, error) {
	var execute nativeGoalTransferApproval
	if request.Effect.Kind != bankv2.MoveGoal || len(request.Authorities) != 3 {
		return execute, reject("EVIDENCE_INVALID", nil)
	}
	var canonical []byte
	for i, role := range []string{"EXECUTE", "RELEASE_SOURCE", "RECEIVE_TARGET"} {
		authority := request.Authorities[i]
		bankRole := []string{"EXECUTE", "GOAL_RELEASE", "GOAL_RECEIVE"}[i]
		if authority.Role != bankRole {
			return execute, reject("EVIDENCE_INVALID", nil)
		}
		var raw []byte
		var rawHash, session, storedRole, policyID, effectHash string
		var version uint64
		var at, expires time.Time
		err := q.QueryRow(ctx, `SELECT original,original_hash::text,session_id::text,role,policy_id::text,policy_version,effect_hash::text,created_at,expires_at FROM native_confirmations WHERE environment_id=$1 AND user_id=$2 AND id=$3 AND preview_id=$4`, p.EnvironmentID.String(), p.UserID.String(), authority.SourceID, preview.ID.String()).Scan(&raw, &rawHash, &session, &storedRole, &policyID, &version, &effectHash, &at, &expires)
		var approval nativeGoalTransferApproval
		if err != nil || Hash(raw) != rawHash || auditJSON(raw, &approval) != nil || approval.Protocol != NativeGoalTransferProtocol+"/USER" || approval.PrincipalKind != "USER" || approval.Role != role || storedRole != role || approval.ID.String() != authority.SourceID || approval.Scope != preview.Scope || approval.PreviewID != preview.ID || approval.SessionID.String() != session || approval.Command.PreviewID != preview.ID || approval.Command.ReviewedHash != preview.ReviewedHash || validateGoalTransferCommand(approval.Command) != nil || approval.BankEffectHash != preview.EffectHash || effectHash != preview.EffectHash || policyID != authority.PolicyID || version != uint64(authority.PolicyVersion) || !approval.ConfirmedAt.Equal(at) || !approval.ExpiresAt.Equal(expires) || !expires.Equal(preview.ExpiresAt) {
			return execute, reject("EVIDENCE_INVALID", err)
		}
		commandRaw, _ := encode(approval.Command)
		if Hash(commandRaw) != approval.CommandHash {
			return execute, reject("EVIDENCE_INVALID", nil)
		}
		if approval.Release.ID == approval.Receive.ID || approval.Release.ID == (funds.ID{}) || approval.Receive.ID == (funds.ID{}) || approval.ExecuteID == (funds.ID{}) || approval.ExecuteID == approval.Release.ID || approval.ExecuteID == approval.Receive.ID {
			return execute, reject("EVIDENCE_INVALID", nil)
		}
		if i == 0 {
			execute = approval
			canonical, _ = encode(struct {
				Session, Execute funds.ID
				Release, Receive planning.PairedGoalConsent
				Command          NativeGoalTransferCommand
				At, Expires      time.Time
			}{approval.SessionID, approval.ExecuteID, approval.Release, approval.Receive, approval.Command, approval.ConfirmedAt, approval.ExpiresAt})
		} else {
			other, _ := encode(struct {
				Session, Execute funds.ID
				Release, Receive planning.PairedGoalConsent
				Command          NativeGoalTransferCommand
				At, Expires      time.Time
			}{approval.SessionID, approval.ExecuteID, approval.Release, approval.Receive, approval.Command, approval.ConfirmedAt, approval.ExpiresAt})
			if string(other) != string(canonical) {
				return execute, reject("EVIDENCE_INVALID", nil)
			}
		}
		if i == 0 && approval.ID != approval.ExecuteID || i == 1 && approval.ID != approval.Release.ID || i == 2 && approval.ID != approval.Receive.ID {
			return execute, reject("EVIDENCE_INVALID", nil)
		}
	}
	if request.Authorities[0].PolicyID != preview.PairedInput.Policy.PolicyID.String() || request.Authorities[0].PolicyVersion != int64(preview.PairedInput.Policy.Version) || request.Authorities[1].PolicyID != preview.PairedInput.Source.PolicyID.String() || request.Authorities[1].PolicyVersion != int64(preview.PairedInput.Source.GoalVersion.Version) || request.Authorities[2].PolicyID != preview.PairedInput.Target.PolicyID.String() || request.Authorities[2].PolicyVersion != int64(preview.PairedInput.Target.GoalVersion.Version) || execute.ConfirmedAt.After(request.RequestedAt) {
		return execute, reject("EVIDENCE_INVALID", nil)
	}
	return execute, nil
}

func goalTransferValidateWitness(preview NativeGoalTransferPreview, approval nativeGoalTransferApproval, witness nativeGoalTransferWitness, at time.Time) error {
	d := preview.Dependencies
	if witness.Protocol != "current-paired-goal-protection-v1" || witness.FundsVersion != witness.ReservedFundsVersion || witness.ReservedFundsVersion != d.FundsVersion+1 || witness.SourceVersion != d.SourceEvidenceVersion || witness.WriterGeneration != d.WriterGeneration || witness.ControlVersion != d.ControlVersion || witness.InventoryHash != preview.InventoryHash || witness.SourceHash != witness.ForecastInput.Facts.SourceHash || witness.ForecastInput.Scope != preview.Scope || !witness.PairedInput.Now.Equal(at) || !witness.ForecastInput.AsOf.Equal(at) || witness.PairedInput.DependencyHash != preview.PairedInput.DependencyHash || !at.Before(preview.ExpiresAt) || at.Before(approval.ConfirmedAt) {
		return reject("EVIDENCE_INVALID", nil)
	}
	paired, err := planning.CheckPairedGoalTransfer(witness.PairedInput, approval.Release, approval.Receive)
	a, _ := encode(paired)
	b, _ := encode(preview.PairedEffect)
	if err != nil || string(a) != string(b) {
		return reject("EVIDENCE_INVALID", err)
	}
	before, err := planning.Forecast365(witness.ForecastInput)
	if err != nil {
		return reject("EVIDENCE_INVALID", err)
	}
	afterInput, err := goalTransferCounterfactual(witness.ForecastInput, paired.SourceGoalID, paired.TargetGoalID, paired.Amount)
	if err != nil {
		return err
	}
	after, err := planning.Forecast365(afterInput)
	if err != nil || !after.MaximumDeficit.IsZero() {
		return reject("EVIDENCE_INVALID", err)
	}
	decoded, err := witness.PairedInput.Policy.Compiled.Decode()
	if err != nil {
		return reject("EVIDENCE_INVALID", err)
	}
	config, ok := decoded.(*policy.CrossGoalReallocationConfig)
	if !ok {
		return reject("EVIDENCE_INVALID", nil)
	}
	refs, err := goalTransferProtectedReferences(witness.ForecastInput, afterInput, config.MustNotReducePolicyIDs)
	if err != nil {
		return reject("EVIDENCE_INVALID", err)
	}
	a, _ = encode(refs)
	b, _ = encode(witness.PairedInput.ProtectedReferences)
	if string(a) != string(b) {
		return reject("EVIDENCE_INVALID", nil)
	}
	a, _ = encode(before)
	b, _ = encode(witness.ForecastBefore)
	if string(a) != string(b) {
		return reject("EVIDENCE_INVALID", nil)
	}
	a, _ = encode(after)
	b, _ = encode(witness.ForecastAfter)
	if string(a) != string(b) {
		return reject("EVIDENCE_INVALID", nil)
	}
	return nil
}

func goalTransferStoredPermit(ctx context.Context, q queryRow, p Principal, operation funds.ID, request bankv2.Request, signature string) error {
	var raw []byte
	var rawHash, rh, eh, sh, permit string
	err := q.QueryRow(ctx, `SELECT original,original_hash::text,bank_request_hash::text,effect_hash::text,signature_hash::text,permit_id::text FROM native_submission_permits WHERE environment_id=$1 AND user_id=$2 AND operation_id=$3`, p.EnvironmentID.String(), p.UserID.String(), operation.String()).Scan(&raw, &rawHash, &rh, &eh, &sh, &permit)
	var proof nativeGoalTransferSubmissionProof
	want, e := request.Digest()
	effect, e2 := request.Effect.Digest()
	if err != nil || e != nil || e2 != nil || Hash(raw) != rawHash || auditJSON(raw, &proof) != nil || proof.Protocol != nativeGoalTransferPermitProtocol || proof.OperationID != operation || proof.PermitID != permit || permit != request.PermitID || request.OperationID != operation.String() || request.UserID != p.UserID.String() || request.Effect.Kind != bankv2.MoveGoal || rh != want || eh != effect || sh != Hash([]byte(signature)) || proof.BankRequestHash != rh || proof.EffectHash != eh || proof.SignatureHash != sh || proof.DecisionAt.Before(request.RequestedAt) || !proof.DecisionAt.Before(request.ExpiresAt) {
		return reject("EVIDENCE_INVALID", err)
	}
	preview, err := loadGoalTransferPreview(ctx, q, p, proof.PreviewID)
	if err != nil {
		return err
	}
	if preview.EffectHash != eh || preview.ReviewedHash != request.ReferenceHash {
		return reject("EVIDENCE_INVALID", nil)
	}
	approval, err := goalTransferApprovals(ctx, q, p, preview, request)
	if err != nil {
		return err
	}
	a, _ := encode(approval)
	b, _ := encode(proof.Approval)
	if string(a) != string(b) {
		return reject("EVIDENCE_INVALID", nil)
	}
	return goalTransferValidateWitness(preview, approval, proof.Witness, proof.DecisionAt)
}

func (s *Service) goalTransferProtection(ctx context.Context, tx pgx.Tx, p Principal, operation funds.ID) error {
	var raw string
	if err := tx.QueryRow(ctx, `SELECT preview_id::text FROM native_operations WHERE environment_id=$1 AND user_id=$2 AND id=$3 AND command_kind='TRANSFER_GOAL'`, p.EnvironmentID.String(), p.UserID.String(), operation.String()).Scan(&raw); err != nil {
		return err
	}
	id, err := funds.ParseID(raw)
	if err != nil {
		return err
	}
	preview, err := loadGoalTransferPreview(ctx, tx, p, id)
	if err != nil {
		return err
	}
	_, _, err = s.refreshTemplateProtectionAfterNativeEffect(ctx, tx, p, preview.Timezone)
	return err
}

func (s *Service) goalTransferPermit(ctx context.Context, c Claim) (nativePermitted, error) {
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
	var rh, eh, previewText, kind string
	var signature *string
	var reservedFV uint64
	if err = tx.QueryRow(ctx, `SELECT status,bank_request,bank_request_hash::text,effect_hash::text,preview_id::text,command_kind,permit_signature,reserved_funds_version FROM native_operations WHERE environment_id=$1 AND user_id=$2 AND id=$3`, p.EnvironmentID.String(), p.UserID.String(), c.OperationID.String()).Scan(&out.State, &raw, &rh, &eh, &previewText, &kind, &signature, &reservedFV); err != nil {
		return out, err
	}
	if kind != "TRANSFER_GOAL" || auditJSON(raw, &out.Request) != nil {
		return out, reject("EVIDENCE_INVALID", nil)
	}
	want, e := out.Request.Digest()
	effect, e2 := out.Request.Effect.Digest()
	if e != nil || e2 != nil || rh != want || eh != effect || out.Request.Namespace != s.Namespace || out.Request.UserID != p.UserID.String() || out.Request.OperationID != c.OperationID.String() {
		return out, reject("EVIDENCE_INVALID", nil)
	}
	if out.State == "SETTLED" || out.State == "REJECTED" || out.State == "CANCELLED" {
		out.Cancelled = true
		return out, nil
	}
	if signature != nil {
		if err = goalTransferStoredPermit(ctx, tx, p, c.OperationID, out.Request, *signature); err != nil {
			return out, err
		}
		out.Signature = *signature
		return out, tx.Commit(ctx)
	}
	if out.State != "QUEUED" {
		return out, reject("EVIDENCE_INVALID", nil)
	}
	previewID, err := funds.ParseID(previewText)
	if err != nil {
		return out, err
	}
	preview, err := loadGoalTransferPreview(ctx, tx, p, previewID)
	if err != nil {
		return out, err
	}
	approval, err := goalTransferApprovals(ctx, tx, p, preview, out.Request)
	if err != nil {
		return out, err
	}
	now := s.now()
	witness := nativeGoalTransferWitness{}
	permissionErr := func() error {
		if !now.Before(preview.ExpiresAt) || now.Before(approval.ConfirmedAt) {
			return reject("AUTHORIZATION_EXPIRED", nil)
		}
		human := p
		human.Kind, human.SessionID = "USER", approval.SessionID
		if e := s.human(ctx, tx, human); e != nil {
			return e
		}
		var fv, sv, wg, cv uint64
		if e := tx.QueryRow(ctx, `SELECT u.funds_version,u.source_version,e.writer_generation,e.control_version FROM users u JOIN environments e ON e.id=u.environment_id WHERE u.environment_id=$1 AND u.id=$2`, p.EnvironmentID.String(), p.UserID.String()).Scan(&fv, &sv, &wg, &cv); e != nil {
			return e
		}
		d := preview.Dependencies
		if fv != reservedFV || reservedFV != d.FundsVersion+1 || sv != d.SourceEvidenceVersion || wg != d.WriterGeneration || cv != d.ControlVersion {
			return reject("SOURCE_CHANGED", nil)
		}
		snapshot, e := s.loadTemplateSnapshot(ctx, tx, p, now, preview.Timezone)
		if e != nil {
			return e
		}
		if snapshot.Native == nil || Hash(snapshot.InventoryRaw) != preview.InventoryHash {
			return reject("SOURCE_CHANGED", nil)
		}
		// This temporary reader view removes ONLY this unsigned operation's
		// own pins. No release is persisted and no UNKNOWN is freed.
		without, e := releaseGoalTransferResources(*snapshot.Native, c.OperationID, preview.BankEffect, preview.LotUses, true)
		if e != nil {
			return e
		}
		snapshot.Native = &without
		usage, e := goalTransferUsage(ctx, tx, p, s.Namespace, preview.PairedEffect.PolicyID)
		if e != nil {
			return e
		}
		usage, e = usage.Sub(preview.PairedEffect.Amount)
		if e != nil {
			return reject("EVIDENCE_INVALID", e)
		}
		current, e := deriveGoalTransferPreview(snapshot, preview.Request, preview.ID, approval.SessionID, usage)
		if e != nil {
			return e
		}
		a, _ := encode(current.LotUses)
		b, _ := encode(preview.LotUses)
		if string(a) != string(b) {
			return reject("SOURCE_CHANGED", nil)
		}
		// The reviewed dependency hash identifies the frozen command; current
		// locked versions and current complete protection are separately proven.
		current.PairedInput.DependencyHash = preview.PairedInput.DependencyHash
		paired, e := planning.CheckPairedGoalTransfer(current.PairedInput, approval.Release, approval.Receive)
		a, _ = encode(paired)
		b, _ = encode(preview.PairedEffect)
		if e != nil || string(a) != string(b) {
			return reject("GOAL_TRANSFER_NOT_AUTHORIZED", e)
		}
		witness = nativeGoalTransferWitness{Protocol: "current-paired-goal-protection-v1", FundsVersion: fv, ReservedFundsVersion: reservedFV, SourceVersion: sv, WriterGeneration: wg, ControlVersion: cv, SourceHash: snapshot.Facts.SourceHash, InventoryHash: Hash(snapshot.InventoryRaw), PairedInput: current.PairedInput, ForecastInput: snapshot.forecastInput(365), ForecastBefore: current.ForecastBefore, ForecastAfter: current.ForecastAfter}
		return goalTransferValidateWitness(preview, approval, witness, now)
	}()
	if permissionErr != nil {
		allowed := map[string]bool{"AUTHORIZATION_EXPIRED": true, "SOURCE_CHANGED": true, "FORBIDDEN": true, "SESSION_EXPIRED": true, "SESSION_REVOKED": true, "GOAL_TRANSFER_NOT_AUTHORIZED": true, "GOAL_TRANSFER_PROTECTION_DEFICIT": true, "GOAL_TRANSFER_PROTECTED_REFERENCE_REDUCED": true, "GOAL_CASH_UNAVAILABLE": true}
		if !allowed[Code(permissionErr)] {
			return out, permissionErr
		}
		ledger, e := s.Store.LoadNativeLedger(ctx, tx, p.EnvironmentID, p.UserID, now)
		if e != nil {
			return out, e
		}
		ledger, e = releaseGoalTransferResources(ledger, c.OperationID, preview.BankEffect, preview.LotUses, true)
		if e != nil {
			return out, e
		}
		if _, e = tx.Exec(ctx, `UPDATE native_operations SET status='CANCELLED',processing_health=$4,version=version+1,updated_at=$5 WHERE environment_id=$1 AND user_id=$2 AND id=$3 AND permit_signature IS NULL`, p.EnvironmentID.String(), p.UserID.String(), c.OperationID.String(), Code(permissionErr), now); e != nil {
			return out, e
		}
		if e = s.Store.PersistNativeLedger(ctx, tx, p.EnvironmentID, p.UserID, ledger); e != nil {
			return out, e
		}
		if e = s.recordNativeCancellation(ctx, tx, p, c.OperationID, Code(permissionErr)); e != nil {
			return out, e
		}
		if _, e = tx.Exec(ctx, `UPDATE users SET funds_version=funds_version+1 WHERE environment_id=$1 AND id=$2`, p.EnvironmentID.String(), p.UserID.String()); e != nil {
			return out, e
		}
		if e = s.goalTransferProtection(ctx, tx, p, c.OperationID); e != nil {
			return out, e
		}
		if e = finishNativeJob(ctx, tx, c); e != nil {
			return out, e
		}
		out.Cancelled = true
		return out, tx.Commit(ctx)
	}
	out.Signature, err = bankv2.SignPermit(out.Request, s.PermitSecret)
	if err != nil {
		return out, err
	}
	proof := nativeGoalTransferSubmissionProof{Protocol: nativeGoalTransferPermitProtocol, OperationID: c.OperationID, PreviewID: preview.ID, PermitID: out.Request.PermitID, BankRequestHash: rh, EffectHash: eh, SignatureHash: Hash([]byte(out.Signature)), Approval: approval, Witness: witness, DecisionAt: now}
	proofRaw, err := encode(proof)
	if err != nil {
		return out, err
	}
	if _, err = tx.Exec(ctx, `INSERT INTO native_submission_permits(environment_id,user_id,operation_id,permit_id,bank_request_hash,effect_hash,signature_hash,original,original_hash,decision_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`, p.EnvironmentID.String(), p.UserID.String(), c.OperationID.String(), out.Request.PermitID, rh, eh, proof.SignatureHash, proofRaw, Hash(proofRaw), now); err != nil {
		return out, err
	}
	if _, err = tx.Exec(ctx, `UPDATE native_operations SET status='SUBMITTING',permit_signature=$4,version=version+1,updated_at=$5 WHERE environment_id=$1 AND user_id=$2 AND id=$3`, p.EnvironmentID.String(), p.UserID.String(), c.OperationID.String(), out.Signature, now); err != nil {
		return out, err
	}
	out.State = "SUBMITTING"
	return out, tx.Commit(ctx)
}
