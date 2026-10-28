package app

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5"
	"zhiyu.local/zhiyu-go/internal/execution/bankv2"
	funds "zhiyu.local/zhiyu-go/internal/funds/domain"
	planning "zhiyu.local/zhiyu-go/internal/planning/domain"
)

const nativePaymentPermitProtocol = "native-payment-submission-permit-v1"

type nativePaymentSubmissionProof struct {
	Protocol             string                `json:"protocol"`
	OperationID          funds.ID              `json:"operation_id"`
	PreviewID            funds.ID              `json:"preview_id"`
	PermitID             string                `json:"permit_id"`
	BankRequestHash      string                `json:"bank_request_hash"`
	EffectHash           string                `json:"effect_hash"`
	SignatureHash        string                `json:"signature_hash"`
	Approval             nativePaymentApproval `json:"approval"`
	Current              NativePaymentPreview  `json:"current"`
	ReservedFundsVersion uint64                `json:"reserved_funds_version"`
	BankCapturedAt       time.Time             `json:"bank_captured_at"`
	DecisionAt           time.Time             `json:"decision_at"`
}

func paymentApproval(ctx context.Context, q queryRow, p Principal, preview NativePaymentPreview, request bankv2.Request) (nativePaymentApproval, error) {
	var out nativePaymentApproval
	if request.Effect.Kind != bankv2.Payment || len(request.Authorities) != 1 || request.Authorities[0].Role != "EXECUTE" || request.Authorities[0].PolicyID != preview.Policy.Version.PolicyID.String() || request.Authorities[0].PolicyVersion != int64(preview.Policy.Version.Version) {
		return out, reject("EVIDENCE_INVALID", nil)
	}
	var raw []byte
	var digest, session, role, policyID, effect string
	var version uint64
	var at, expires time.Time
	e := q.QueryRow(ctx, `SELECT original,original_hash::text,session_id::text,role,policy_id::text,policy_version,effect_hash::text,created_at,expires_at FROM native_confirmations WHERE environment_id=$1 AND user_id=$2 AND id=$3 AND preview_id=$4`, p.EnvironmentID.String(), p.UserID.String(), request.Authorities[0].SourceID, preview.ID.String()).Scan(&raw, &digest, &session, &role, &policyID, &version, &effect, &at, &expires)
	if e != nil || Hash(raw) != digest || auditJSON(raw, &out) != nil || out.Protocol != "native-payment-USER-v1" || out.PrincipalKind != "USER" || out.Scope != preview.Scope || out.ID.String() != request.Authorities[0].SourceID || out.SessionID.String() != session || role != "EXECUTE" || policyID != request.Authorities[0].PolicyID || version != uint64(request.Authorities[0].PolicyVersion) || out.Command.PreviewID != preview.ID || out.Command.ReviewedHash != preview.ReviewedHash || out.EffectHash != preview.EffectHash || effect != preview.EffectHash || !at.Equal(out.ConfirmedAt) || !expires.Equal(out.ExpiresAt) || !expires.Equal(preview.ExpiresAt) || request.RequestedAt.Before(at) {
		return out, reject("EVIDENCE_INVALID", e)
	}
	command, _ := encode(out.Command)
	if Hash(command) != out.CommandHash {
		return out, reject("EVIDENCE_INVALID", nil)
	}
	var source []byte
	var sourceHash, debt string
	if e = q.QueryRow(ctx, `SELECT original,original_hash::text,obligation_id FROM native_payment_sources WHERE environment_id=$1 AND user_id=$2 AND operation_id=$3`, p.EnvironmentID.String(), p.UserID.String(), request.OperationID).Scan(&source, &sourceHash, &debt); e != nil {
		return out, reject("EVIDENCE_INVALID", e)
	}
	var liability bankv2.LiabilityState
	if Hash(source) != sourceHash || auditJSON(source, &liability) != nil || liability != preview.Liability || debt != preview.Debt.ID {
		return out, reject("EVIDENCE_INVALID", nil)
	}
	return out, nil
}

func validatePaymentProof(preview NativePaymentPreview, proof nativePaymentSubmissionProof, request bankv2.Request) error {
	d, c := preview.Dependencies, proof.Current
	if proof.Protocol != nativePaymentPermitProtocol || proof.PreviewID != preview.ID || proof.OperationID.String() != request.OperationID || proof.PermitID != request.PermitID || request.ReferenceHash != preview.ReviewedHash || proof.ReservedFundsVersion != d.FundsVersion+1 || c.Dependencies.FundsVersion != proof.ReservedFundsVersion || c.Dependencies.SourceEvidenceVersion != d.SourceEvidenceVersion || c.Dependencies.WriterGeneration != d.WriterGeneration || c.Dependencies.ControlVersion != d.ControlVersion || c.InventoryHash != preview.InventoryHash || c.ID != preview.ID || c.Scope != preview.Scope || c.Request != preview.Request || c.Liability != preview.Liability || c.Policy.Version.VersionID != preview.Policy.Version.VersionID || c.EffectHash != preview.EffectHash || !c.CreatedAt.Equal(proof.DecisionAt) || !c.ExpiresAt.Equal(preview.ExpiresAt) || proof.DecisionAt.Before(proof.Approval.ConfirmedAt) || !proof.DecisionAt.Before(preview.ExpiresAt) || proof.BankCapturedAt.After(proof.DecisionAt.Add(time.Second)) || proof.DecisionAt.Sub(proof.BankCapturedAt) > 30*time.Second {
		return reject("EVIDENCE_INVALID", nil)
	}
	if e := replayNativePaymentPreview(c); e != nil {
		return e
	}
	a, _ := encode(c.BankEffect)
	b, _ := encode(request.Effect)
	if !templateSameBytes(a, b) {
		return reject("EVIDENCE_INVALID", nil)
	}
	return nil
}

func paymentStoredPermit(ctx context.Context, q queryRow, p Principal, operation funds.ID, request bankv2.Request, signature string) error {
	var raw []byte
	var hash, rh, eh, sh, permit string
	e := q.QueryRow(ctx, `SELECT original,original_hash::text,bank_request_hash::text,effect_hash::text,signature_hash::text,permit_id::text FROM native_submission_permits WHERE environment_id=$1 AND user_id=$2 AND operation_id=$3`, p.EnvironmentID.String(), p.UserID.String(), operation.String()).Scan(&raw, &hash, &rh, &eh, &sh, &permit)
	var protocol struct {
		Protocol string `json:"protocol"`
	}
	if e == nil && decode(raw, &protocol) == nil && protocol.Protocol == nativeStandingPaymentPermitProtocol {
		return standingPaymentStoredPermit(ctx, q, p, operation, request, signature)
	}
	var proof nativePaymentSubmissionProof
	want, e1 := request.Digest()
	effect, e2 := request.Effect.Digest()
	if e != nil || e1 != nil || e2 != nil || Hash(raw) != hash || auditJSON(raw, &proof) != nil || rh != want || eh != effect || sh != Hash([]byte(signature)) || permit != request.PermitID || proof.BankRequestHash != rh || proof.EffectHash != eh || proof.SignatureHash != sh || proof.OperationID != operation || request.UserID != p.UserID.String() {
		return reject("EVIDENCE_INVALID", e)
	}
	preview, e := loadNativePaymentPreview(ctx, q, p, proof.PreviewID)
	if e != nil {
		return e
	}
	approval, e := paymentApproval(ctx, q, p, preview, request)
	if e != nil {
		return e
	}
	a, _ := encode(approval)
	b, _ := encode(proof.Approval)
	if !templateSameBytes(a, b) {
		return reject("EVIDENCE_INVALID", nil)
	}
	return validatePaymentProof(preview, proof, request)
}

func (s *Service) paymentProtection(ctx context.Context, tx pgx.Tx, p Principal, operation funds.ID) error {
	var text string
	if e := tx.QueryRow(ctx, `SELECT preview_id::text FROM native_operations WHERE environment_id=$1 AND user_id=$2 AND id=$3 AND command_kind='PAY_RECURRING'`, p.EnvironmentID.String(), p.UserID.String(), operation.String()).Scan(&text); e != nil {
		return e
	}
	id, e := funds.ParseID(text)
	if e != nil {
		return e
	}
	preview, e := loadNativePaymentExecutionPreview(ctx, tx, p, operation, id)
	if e != nil {
		return e
	}
	_, _, e = s.refreshTemplateProtectionAfterNativeEffect(ctx, tx, p, preview.Timezone)
	return e
}

func (s *Service) paymentCancelUnsigned(ctx context.Context, tx pgx.Tx, c Claim, reason string) error {
	p := c.Principal
	ledger, e := s.Store.LoadNativeLedger(ctx, tx, p.EnvironmentID, p.UserID, s.now())
	if e != nil {
		return e
	}
	if e = releaseNativeAssetResources(&ledger, c.OperationID); e != nil {
		return e
	}
	tag, e := tx.Exec(ctx, `UPDATE native_operations SET status='CANCELLED',processing_health=$4,version=version+1,updated_at=$5 WHERE environment_id=$1 AND user_id=$2 AND id=$3 AND status='QUEUED' AND permit_signature IS NULL`, p.EnvironmentID.String(), p.UserID.String(), c.OperationID.String(), reason, s.now())
	if e = assertOne(tag, e); e != nil {
		return e
	}
	if e = s.Store.PersistNativeLedger(ctx, tx, p.EnvironmentID, p.UserID, ledger); e != nil {
		return e
	}
	if e = finalizeStandingPaymentBudget(ctx, tx, p, c.OperationID, funds.Money{}, s.now()); e != nil {
		return e
	}
	cause, e := s.nativeTerminalCancellationCause(ctx, tx, p, c.OperationID, reason)
	if e != nil {
		return e
	}
	if e = s.recordFundsTerminalDecision(ctx, tx, p, "NATIVE", c.OperationID, "CANCELLED", cause); e != nil {
		return e
	}
	if _, e = tx.Exec(ctx, `UPDATE users SET funds_version=funds_version+1 WHERE environment_id=$1 AND id=$2`, p.EnvironmentID.String(), p.UserID.String()); e != nil {
		return e
	}
	if e = s.paymentProtection(ctx, tx, p, c.OperationID); e != nil {
		return e
	}
	return finishNativeJob(ctx, tx, c)
}

func (s *Service) paymentPermit(ctx context.Context, c Claim) (nativePermitted, error) {
	var out nativePermitted
	var mode string
	if e := s.Pool.QueryRow(ctx, `SELECT mode FROM native_operations WHERE environment_id=$1 AND user_id=$2 AND id=$3`, c.Principal.EnvironmentID.String(), c.Principal.UserID.String(), c.OperationID.String()).Scan(&mode); e != nil {
		return out, e
	}
	if mode == "STANDING" {
		return s.standingPaymentPermit(ctx, c)
	}
	if mode != "ONCE" {
		return out, reject("EVIDENCE_INVALID", nil)
	}
	var unsigned bool
	var previewText string
	e := s.Pool.QueryRow(ctx, `SELECT permit_signature IS NULL,preview_id::text FROM native_operations WHERE environment_id=$1 AND user_id=$2 AND id=$3 AND command_kind='PAY_RECURRING'`, c.Principal.EnvironmentID.String(), c.Principal.UserID.String(), c.OperationID.String()).Scan(&unsigned, &previewText)
	if e != nil {
		return out, e
	}
	previewID, e := funds.ParseID(previewText)
	if e != nil {
		return out, e
	}
	preview, e := loadNativePaymentPreview(ctx, s.Pool, c.Principal, previewID)
	if e != nil {
		return out, e
	}
	var bank bankv2.LiabilityState
	var captured time.Time
	// Already-signed originals deliberately skip current liability/session/rule I/O.
	if unsigned {
		bank, captured, e = s.paymentBankLiability(ctx, c.Principal, preview.Debt.ID)
		if e != nil {
			return out, e
		}
	}
	tx, e := s.begin(ctx)
	if e != nil {
		return out, e
	}
	defer rollback(ctx, tx)
	if e = s.lockNativeClaim(ctx, tx, c); e != nil {
		return out, e
	}
	p := c.Principal
	var raw []byte
	var rh, eh string
	var signature *string
	var reserved uint64
	e = tx.QueryRow(ctx, `SELECT status,bank_request,bank_request_hash::text,effect_hash::text,permit_signature,reserved_funds_version FROM native_operations WHERE environment_id=$1 AND user_id=$2 AND id=$3`, p.EnvironmentID.String(), p.UserID.String(), c.OperationID.String()).Scan(&out.State, &raw, &rh, &eh, &signature, &reserved)
	if e != nil {
		return out, e
	}
	if auditJSON(raw, &out.Request) != nil {
		return out, reject("EVIDENCE_INVALID", nil)
	}
	want, e1 := out.Request.Digest()
	effect, e2 := out.Request.Effect.Digest()
	if e1 != nil || e2 != nil || want != rh || effect != eh || out.Request.Namespace != s.Namespace || out.Request.OperationID != c.OperationID.String() || out.Request.UserID != p.UserID.String() {
		return out, reject("EVIDENCE_INVALID", nil)
	}
	if out.State == "SETTLED" || out.State == "REJECTED" || out.State == "CANCELLED" {
		out.Cancelled = true
		return out, nil
	}
	if signature != nil {
		if e = paymentStoredPermit(ctx, tx, p, c.OperationID, out.Request, *signature); e != nil {
			return out, e
		}
		out.Signature = *signature
		return out, tx.Commit(ctx)
	}
	if out.State != "QUEUED" {
		return out, reject("EVIDENCE_INVALID", nil)
	}
	approval, e := paymentApproval(ctx, tx, p, preview, out.Request)
	if e != nil {
		return out, e
	}
	now := s.now()
	current := preview
	permissionErr := func() error {
		if !now.Before(preview.ExpiresAt) || now.Before(approval.ConfirmedAt) {
			return reject("AUTHORIZATION_EXPIRED", nil)
		}
		human := p
		human.Kind, human.SessionID = "USER", approval.SessionID
		if e := s.human(ctx, tx, human); e != nil {
			return e
		}
		snapshot, e := s.loadTemplateSnapshot(ctx, tx, p, now, preview.Timezone)
		if e != nil {
			return e
		}
		d := preview.Dependencies
		if snapshot.Native == nil || snapshot.FundsVersion != reserved || reserved != d.FundsVersion+1 || snapshot.SourceVersion != d.SourceEvidenceVersion || snapshot.WriterGeneration != d.WriterGeneration || snapshot.ControlVersion != d.ControlVersion || bank != preview.Liability {
			return reject("SOURCE_CHANGED", nil)
		}
		if e = checkNativePaymentHolds(*snapshot.Native, c.OperationID, preview); e != nil {
			return e
		}
		if e = releaseNativeAssetResources(snapshot.Native, c.OperationID); e != nil {
			return e
		}
		snapshot.Held, e = snapshot.Held.Sub(preview.Resources.Amount)
		if e != nil {
			return reject("EVIDENCE_INVALID", e)
		}
		for _, use := range preview.Resources.IncomeUses {
			found := false
			for i := range snapshot.Facts.Income {
				fact := &snapshot.Facts.Income[i]
				if fact.ID == use.OriginID {
					fact.Available, e = fact.Available.Add(use.Amount)
					if e != nil {
						return e
					}
					found = true
				}
			}
			if !found {
				return reject("EVIDENCE_INVALID", nil)
			}
		}
		resources, e := currentNativePayment(snapshot, preview, bank)
		if e != nil {
			return e
		}
		a, _ := encode(resources)
		b, _ := encode(preview.Resources)
		if !templateSameBytes(a, b) {
			return reject("SOURCE_CHANGED", nil)
		}
		current.CreatedAt = now
		current.Dependencies.FundsVersion = snapshot.FundsVersion
		current.SourceHash = snapshot.Facts.SourceHash
		current.InventoryHash = Hash(snapshot.InventoryRaw)
		current.InventoryOriginal = snapshot.InventoryRaw
		current.Ledger = captureNativeAssetLedger(*snapshot.Native)
		current.ForecastInput = snapshot.forecastInput(365)
		for _, v := range snapshot.Views {
			if v.Version.VersionID == preview.Request.PolicyVersionID {
				current.Policy = v
			}
		}
		for _, d := range snapshot.Retained {
			if d.ID == preview.Debt.ID {
				current.Debt = d
			}
		}
		current.BillProof, e = nativePaymentCurrentBillProof(snapshot, preview, bank)
		if e != nil {
			return e
		}
		current.AdoptionProof, e = nativePaymentCurrentAdoptionProof(snapshot, preview, bank)
		if e != nil {
			return e
		}
		current.ForecastBefore, e = planning.Forecast365(current.ForecastInput)
		if e != nil {
			return e
		}
		after, e := nativePaymentPreviewAfter(current.ForecastInput, current, resources.Amount)
		if e != nil {
			return e
		}
		current.ForecastAfter, e = planning.Forecast365(after)
		if e != nil {
			return e
		}
		current.ReviewedHash, e = NativePaymentReviewHash(current)
		if e != nil {
			return e
		}
		return replayNativePaymentPreview(current)
	}()
	if permissionErr != nil {
		if Code(permissionErr) == "INTERNAL_ERROR" || Code(permissionErr) == "EVIDENCE_INVALID" {
			return out, permissionErr
		}
		if e = s.paymentCancelUnsigned(ctx, tx, c, Code(permissionErr)); e != nil {
			return out, e
		}
		out.Cancelled = true
		return out, tx.Commit(ctx)
	}
	out.Signature, e = bankv2.SignPermit(out.Request, s.PermitSecret)
	if e != nil {
		return out, e
	}
	proof := nativePaymentSubmissionProof{Protocol: nativePaymentPermitProtocol, OperationID: c.OperationID, PreviewID: preview.ID, PermitID: out.Request.PermitID, BankRequestHash: rh, EffectHash: eh, SignatureHash: Hash([]byte(out.Signature)), Approval: approval, Current: current, ReservedFundsVersion: reserved, BankCapturedAt: captured, DecisionAt: now}
	if e = validatePaymentProof(preview, proof, out.Request); e != nil {
		return out, e
	}
	proofRaw, e := encode(proof)
	if e != nil {
		return out, e
	}
	_, e = tx.Exec(ctx, `INSERT INTO native_submission_permits(environment_id,user_id,operation_id,permit_id,bank_request_hash,effect_hash,signature_hash,original,original_hash,decision_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`, p.EnvironmentID.String(), p.UserID.String(), c.OperationID.String(), out.Request.PermitID, rh, eh, proof.SignatureHash, proofRaw, Hash(proofRaw), now)
	if e != nil {
		return out, e
	}
	_, e = tx.Exec(ctx, `UPDATE native_operations SET status='SUBMITTING',permit_signature=$4,version=version+1,updated_at=$5 WHERE environment_id=$1 AND user_id=$2 AND id=$3`, p.EnvironmentID.String(), p.UserID.String(), c.OperationID.String(), out.Signature, now)
	if e != nil {
		return out, e
	}
	out.State = "SUBMITTING"
	return out, tx.Commit(ctx)
}
