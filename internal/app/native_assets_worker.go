package app

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5"
	"zhiyu.local/zhiyu-go/internal/execution/bankv2"
	funds "zhiyu.local/zhiyu-go/internal/funds/domain"
)

const nativeAssetPermitProtocol = "native-asset-submission-permit-v1"

type nativeAssetWitness struct {
	Protocol                                                                            string `json:"protocol"`
	FundsVersion, ReservedFundsVersion, SourceVersion, WriterGeneration, ControlVersion uint64
	Current                                                                             NativeAssetPreview `json:"current"`
}
type nativeAssetSubmissionProof struct {
	Protocol                                             string `json:"protocol"`
	OperationID, PreviewID                               funds.ID
	PermitID, BankRequestHash, EffectHash, SignatureHash string
	Approval                                             nativeAssetApproval `json:"approval"`
	Witness                                              nativeAssetWitness  `json:"witness"`
	DecisionAt                                           time.Time           `json:"decision_at"`
}

func assetApproval(ctx context.Context, q queryRow, p Principal, preview NativeAssetPreview, request bankv2.Request) (nativeAssetApproval, error) {
	var approval nativeAssetApproval
	if len(request.Authorities) < 1 {
		return approval, reject("EVIDENCE_INVALID", nil)
	}
	var raw []byte
	var storedHash, session, role, policyID, effectHash string
	var version uint64
	var at, expires time.Time
	authority := request.Authorities[0]
	e := q.QueryRow(ctx, `SELECT original,original_hash::text,session_id::text,role,policy_id::text,policy_version,effect_hash::text,created_at,expires_at FROM native_confirmations WHERE environment_id=$1 AND user_id=$2 AND id=$3 AND preview_id=$4`, p.EnvironmentID.String(), p.UserID.String(), authority.SourceID, preview.ID.String()).Scan(&raw, &storedHash, &session, &role, &policyID, &version, &effectHash, &at, &expires)
	if e != nil || Hash(raw) != storedHash || decode(raw, &approval) != nil || approval.Protocol != NativeAssetProtocol+"/USER" || approval.PrincipalKind != "USER" || approval.ID.String() != authority.SourceID || approval.Scope != preview.Scope || approval.PreviewID != preview.ID || approval.SessionID.String() != session || role != "EXECUTE" || policyID != preview.Policy.Version.PolicyID.String() || version != preview.Policy.Version.Version || effectHash != preview.EffectHash || approval.EffectHash != preview.EffectHash || approval.PolicyVersionID != preview.Policy.Version.VersionID || approval.ConfigurationHash != preview.Policy.Version.Compiled.Hash || approval.Command.PreviewID != preview.ID || approval.Command.ReviewedHash != preview.ReviewedHash || !approval.ConfirmedAt.Equal(at) || !approval.ExpiresAt.Equal(expires) || !expires.Equal(preview.ExpiresAt) || at.Before(preview.CreatedAt) || at.After(request.RequestedAt) {
		return approval, reject("EVIDENCE_INVALID", e)
	}
	command, _ := encode(approval.Command)
	cost := !preview.BankEffect.Fee.IsZero() || !preview.BankEffect.Loss.IsZero()
	if Hash(command) != approval.CommandHash || approval.Command.CostReviewed != cost {
		return approval, reject("EVIDENCE_INVALID", nil)
	}
	expected, e := assetRequestAuthorities(preview, approval.ID)
	if e != nil {
		return approval, e
	}
	a, _ := encode(expected)
	b, _ := encode(request.Authorities)
	if string(a) != string(b) || request.Effect.Kind != preview.Kind || request.ReferenceHash != preview.ReviewedHash || !request.ExpiresAt.Equal(preview.ExpiresAt) {
		return approval, reject("EVIDENCE_INVALID", nil)
	}
	eh, e := request.Effect.Digest()
	if e != nil || eh != preview.EffectHash {
		return approval, reject("EVIDENCE_INVALID", e)
	}
	if cost {
		c := request.CostConsent
		if c == nil || c.ConfirmationID != approval.ID.String() || c.ReviewedEffectHash != preview.EffectHash || c.PrincipalKind != "USER" || !c.ConfirmedAt.Equal(at) || !c.ExpiresAt.Equal(expires) {
			return approval, reject("EVIDENCE_INVALID", nil)
		}
	} else if request.CostConsent != nil {
		return approval, reject("EVIDENCE_INVALID", nil)
	}
	return approval, nil
}
func assetValidateWitness(preview NativeAssetPreview, approval nativeAssetApproval, w nativeAssetWitness, at time.Time) error {
	d := preview.Dependencies
	if w.Protocol != "current-asset-protection-v1" || w.FundsVersion != w.ReservedFundsVersion || w.ReservedFundsVersion != d.FundsVersion+1 || w.SourceVersion != d.SourceEvidenceVersion || w.WriterGeneration != d.WriterGeneration || w.ControlVersion != d.ControlVersion || w.Current.Dependencies.FundsVersion != w.FundsVersion || w.Current.Dependencies.SourceEvidenceVersion != w.SourceVersion || w.Current.Dependencies.WriterGeneration != w.WriterGeneration || w.Current.Dependencies.ControlVersion != w.ControlVersion || w.Current.ID != preview.ID || w.Current.Scope != preview.Scope || w.Current.SessionID != approval.SessionID || !w.Current.CreatedAt.Equal(at) || !at.Before(preview.ExpiresAt) || at.Before(approval.ConfirmedAt) {
		return reject("EVIDENCE_INVALID", nil)
	}
	if e := replayNativeAssetPreview(w.Current); e != nil {
		return e
	}
	return assetEquivalentEconomic(w.Current, preview)
}

func assetStoredPermit(ctx context.Context, q queryRow, p Principal, operation funds.ID, request bankv2.Request, signature string) error {
	return assetStoredPermitWithActivityRaw(ctx, q, p, operation, request, signature, nil)
}

func assetStoredPermitWithActivityRaw(ctx context.Context, q queryRow, p Principal, operation funds.ID, request bankv2.Request, signature string, fact *nativeActivityPermitRaw) error {
	mode, modeErr := assetExecutionMode(ctx, q, p, operation)
	if modeErr != nil {
		return modeErr
	}
	if mode == "STANDING" {
		return assetStandingStoredPermit(ctx, q, p, operation, request, signature)
	}
	stored, e := loadNativeAssetStoredPermitRow(ctx, q, p, operation, request.Effect.Kind, fact)
	raw, storedHash, rh, eh, sh, permit := stored.original, stored.originalHash, stored.requestHash, stored.effectHash, stored.signatureHash, stored.permitID
	var proof nativeAssetSubmissionProof
	want, we := request.Digest()
	effect, ee := request.Effect.Digest()
	if e != nil || we != nil || ee != nil || Hash(raw) != storedHash || decode(raw, &proof) != nil || proof.Protocol != nativeAssetPermitProtocol || !nativeAssetKind(request.Effect.Kind) || proof.OperationID != operation || request.OperationID != operation.String() || request.UserID != p.UserID.String() || permit != request.PermitID || proof.PermitID != permit || rh != want || proof.BankRequestHash != rh || eh != effect || proof.EffectHash != eh || sh != Hash([]byte(signature)) || proof.SignatureHash != sh || proof.DecisionAt.Before(request.RequestedAt) || !proof.DecisionAt.Before(request.ExpiresAt) {
		return reject("EVIDENCE_INVALID", e)
	}
	preview, e := loadNativeAssetPreview(ctx, q, p, proof.PreviewID, request.Effect.Kind)
	if e != nil {
		return e
	}
	approval, e := assetApproval(ctx, q, p, preview, request)
	if e != nil {
		return e
	}
	a, _ := encode(approval)
	b, _ := encode(proof.Approval)
	if string(a) != string(b) {
		return reject("EVIDENCE_INVALID", nil)
	}
	return assetValidateWitness(preview, approval, proof.Witness, proof.DecisionAt)
}
func assetOperationTimezone(ctx context.Context, q queryRow, p Principal, operation funds.ID) (string, error) {
	var text, kind string
	if e := q.QueryRow(ctx, `SELECT preview_id::text,command_kind FROM native_operations WHERE environment_id=$1 AND user_id=$2 AND id=$3`, p.EnvironmentID.String(), p.UserID.String(), operation.String()).Scan(&text, &kind); e != nil {
		return "", e
	}
	id, e := funds.ParseID(text)
	if e != nil {
		return "", e
	}
	preview, e := loadAssetExecutionPreview(ctx, q, p, operation, id, bankv2.Kind(kind))
	return preview.Timezone, e
}
func (s *Service) assetProtection(ctx context.Context, tx pgx.Tx, p Principal, operation funds.ID) error {
	tz, e := assetOperationTimezone(ctx, tx, p, operation)
	if e != nil {
		return e
	}
	_, _, e = s.refreshTemplateProtectionAfterNativeEffect(ctx, tx, p, tz)
	return e
}

// The current independent-bank read occurs before any application fund lock.
// Once a signature exists, recovery uses only its immutable original request;
// revocation or a later catalog/quote never replaces the original bank key.
func (s *Service) assetPermit(ctx context.Context, c Claim) (nativePermitted, error) {
	mode, modeErr := assetExecutionMode(ctx, s.Pool, c.Principal, c.OperationID)
	if modeErr != nil {
		return nativePermitted{}, modeErr
	}
	if mode == "STANDING" {
		return s.assetStandingPermit(ctx, c)
	}
	var out nativePermitted
	p := c.Principal
	var initialRaw []byte
	var initialSignature *string
	var initialKind string
	if e := s.Pool.QueryRow(ctx, `SELECT bank_request,permit_signature,command_kind FROM native_operations WHERE environment_id=$1 AND user_id=$2 AND id=$3`, p.EnvironmentID.String(), p.UserID.String(), c.OperationID.String()).Scan(&initialRaw, &initialSignature, &initialKind); e != nil {
		return out, e
	}
	var initial bankv2.Request
	if decode(initialRaw, &initial) != nil || !nativeAssetKind(bankv2.Kind(initialKind)) || initial.Effect.Kind != bankv2.Kind(initialKind) {
		return out, reject("EVIDENCE_INVALID", nil)
	}
	var state bankv2.CurrentState
	var latestQuote *bankv2.Quote
	if initialSignature == nil {
		reader, ok := s.NativeBank.(nativeAssetBankReader)
		if !ok {
			return out, reject("BANK_UNAVAILABLE", nil)
		}
		var e error
		state, e = reader.CurrentState(ctx, s.Namespace, p.UserID.String())
		if e != nil {
			return out, reject("BANK_UNAVAILABLE", nil)
		}
		if initial.Effect.Kind != bankv2.Purchase {
			q, qe := reader.Quote(ctx, s.Namespace, p.UserID.String(), initial.Effect.PositionID, initial.Effect.Kind)
			if qe != nil {
				return out, reject("ASSET_QUOTE_UNAVAILABLE", nil)
			}
			latestQuote = &q
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
	var raw []byte
	var rh, eh, previewText, kind string
	var signature *string
	var reservedFV uint64
	e = tx.QueryRow(ctx, `SELECT status,bank_request,bank_request_hash::text,effect_hash::text,preview_id::text,command_kind,permit_signature,reserved_funds_version FROM native_operations WHERE environment_id=$1 AND user_id=$2 AND id=$3`, p.EnvironmentID.String(), p.UserID.String(), c.OperationID.String()).Scan(&out.State, &raw, &rh, &eh, &previewText, &kind, &signature, &reservedFV)
	if e != nil {
		return out, e
	}
	if decode(raw, &out.Request) != nil || !nativeAssetKind(bankv2.Kind(kind)) || out.Request.Effect.Kind != bankv2.Kind(kind) {
		return out, reject("EVIDENCE_INVALID", nil)
	}
	want, we := out.Request.Digest()
	effect, ee := out.Request.Effect.Digest()
	if we != nil || ee != nil || want != rh || effect != eh || out.Request.Namespace != s.Namespace || out.Request.UserID != p.UserID.String() || out.Request.OperationID != c.OperationID.String() {
		return out, reject("EVIDENCE_INVALID", nil)
	}
	if out.State == "SETTLED" || out.State == "REJECTED" || out.State == "CANCELLED" {
		out.Cancelled = true
		return out, nil
	}
	if signature != nil {
		if e = assetStoredPermit(ctx, tx, p, c.OperationID, out.Request, *signature); e != nil {
			return out, e
		}
		out.Signature = *signature
		return out, tx.Commit(ctx)
	}
	if out.State != "QUEUED" {
		return out, reject("EVIDENCE_INVALID", nil)
	}
	previewID, e := funds.ParseID(previewText)
	if e != nil {
		return out, e
	}
	preview, e := loadNativeAssetPreview(ctx, tx, p, previewID, out.Request.Effect.Kind)
	if e != nil {
		return out, e
	}
	approval, e := assetApproval(ctx, tx, p, preview, out.Request)
	if e != nil {
		return out, e
	}
	now := s.now()
	var witness nativeAssetWitness
	permissionErr := func() error {
		if now.Before(approval.ConfirmedAt) || !now.Before(preview.ExpiresAt) {
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
		if latestQuote != nil {
			frozen := preview.Quote
			if frozen == nil || latestQuote.Validate() != nil || latestQuote.Namespace != out.Request.Namespace || latestQuote.UserID != out.Request.UserID || latestQuote.PositionID != frozen.PositionID || latestQuote.PositionOpeningHash != frozen.PositionOpeningHash || latestQuote.Kind != frozen.Kind || latestQuote.Principal != frozen.Principal || latestQuote.Net != frozen.Net || latestQuote.Fee != frozen.Fee || latestQuote.Loss != frozen.Loss || latestQuote.Product.TermsHash != frozen.Product.TermsHash || latestQuote.Product.AvailabilityHash != frozen.Product.AvailabilityHash {
				return reject("SOURCE_CHANGED", nil)
			}
		}
		snapshot, e := s.loadTemplateSnapshot(ctx, tx, p, now, preview.Timezone)
		if e != nil {
			return e
		}
		if snapshot.Native == nil || Hash(snapshot.InventoryRaw) != preview.InventoryHash {
			return reject("SOURCE_CHANGED", nil)
		}
		if e = checkNativeAssetResources(*snapshot.Native, c.OperationID, preview); e != nil {
			return e
		}
		snapshot, e = assetSnapshotWithoutReservation(snapshot, c.OperationID)
		if e != nil {
			return e
		}
		pending, e := assetPendingPurchases(ctx, tx, p, s.Namespace)
		if e != nil {
			return e
		}
		filtered := pending[:0]
		for _, request := range pending {
			if request.OperationID != c.OperationID.String() {
				filtered = append(filtered, request)
			}
		}
		current, e := deriveNativeAssetPreview(snapshot, preview.Request, preview.ID, approval.SessionID, state, preview.Quote, filtered, preview.ExpiresAt)
		if e != nil {
			return e
		}
		if e = assetEquivalentEconomic(current, preview); e != nil {
			return e
		}
		witness = nativeAssetWitness{Protocol: "current-asset-protection-v1", FundsVersion: fv, ReservedFundsVersion: reservedFV, SourceVersion: sv, WriterGeneration: wg, ControlVersion: cv, Current: current}
		return assetValidateWitness(preview, approval, witness, now)
	}()
	if permissionErr != nil {
		allowed := map[string]bool{"AUTHORIZATION_EXPIRED": true, "SOURCE_CHANGED": true, "FORBIDDEN": true, "SESSION_EXPIRED": true, "SESSION_REVOKED": true, "ASSET_POLICY_NOT_ACTIVE": true, "ASSET_PRODUCT_UNAVAILABLE": true, "ASSET_POSITION_UNAVAILABLE": true, "ASSET_NO_SAFE_PURCHASE": true, "ASSET_PROTECTION_DEFICIT": true, "ASSET_POLICY_REJECTED": true, "ASSET_CLOSE_NOT_AUTHORIZED": true, "ASSET_RECOVERY_NOT_TRIGGERED": true, "ASSET_COST_NOT_AUTHORIZED": true, "ASSET_BELOW_MINIMUM": true, "ASSET_BANK_STATE_CHANGED": true}
		if !allowed[Code(permissionErr)] {
			return out, permissionErr
		}
		ledger, e := s.Store.LoadNativeLedger(ctx, tx, p.EnvironmentID, p.UserID, now)
		if e != nil {
			return out, e
		}
		if e = releaseNativeAssetResources(&ledger, c.OperationID); e != nil {
			return out, e
		}
		if _, e = tx.Exec(ctx, `UPDATE native_operations SET status='CANCELLED',processing_health=$4,version=version+1,updated_at=$5 WHERE environment_id=$1 AND user_id=$2 AND id=$3 AND permit_signature IS NULL`, p.EnvironmentID.String(), p.UserID.String(), c.OperationID.String(), Code(permissionErr), now); e != nil {
			return out, e
		}
		if e = s.Store.PersistNativeLedger(ctx, tx, p.EnvironmentID, p.UserID, ledger); e != nil {
			return out, e
		}
		cause, e := s.nativeTerminalCancellationCause(ctx, tx, p, c.OperationID, Code(permissionErr))
		if e != nil {
			return out, e
		}
		if e = s.recordFundsTerminalDecision(ctx, tx, p, "NATIVE", c.OperationID, "CANCELLED", cause); e != nil {
			return out, e
		}
		if _, e = tx.Exec(ctx, `UPDATE users SET funds_version=funds_version+1 WHERE environment_id=$1 AND id=$2`, p.EnvironmentID.String(), p.UserID.String()); e != nil {
			return out, e
		}
		if e = s.assetProtection(ctx, tx, p, c.OperationID); e != nil {
			return out, e
		}
		if e = finishNativeJob(ctx, tx, c); e != nil {
			return out, e
		}
		out.Cancelled = true
		return out, tx.Commit(ctx)
	}
	out.Signature, e = bankv2.SignPermit(out.Request, s.PermitSecret)
	if e != nil {
		return out, e
	}
	proof := nativeAssetSubmissionProof{Protocol: nativeAssetPermitProtocol, OperationID: c.OperationID, PreviewID: preview.ID, PermitID: out.Request.PermitID, BankRequestHash: rh, EffectHash: eh, SignatureHash: Hash([]byte(out.Signature)), Approval: approval, Witness: witness, DecisionAt: now}
	proofRaw, e := encode(proof)
	if e != nil {
		return out, e
	}
	if len(proofRaw) > 1<<20 {
		return out, reject("ASSET_CAPACITY", nil)
	}
	if _, e = tx.Exec(ctx, `INSERT INTO native_submission_permits(environment_id,user_id,operation_id,permit_id,bank_request_hash,effect_hash,signature_hash,original,original_hash,decision_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`, p.EnvironmentID.String(), p.UserID.String(), c.OperationID.String(), out.Request.PermitID, rh, eh, proof.SignatureHash, proofRaw, Hash(proofRaw), now); e != nil {
		return out, e
	}
	if _, e = tx.Exec(ctx, `UPDATE native_operations SET status='SUBMITTING',permit_signature=$4,version=version+1,updated_at=$5 WHERE environment_id=$1 AND user_id=$2 AND id=$3`, p.EnvironmentID.String(), p.UserID.String(), c.OperationID.String(), out.Signature, now); e != nil {
		return out, e
	}
	out.State = "SUBMITTING"
	return out, tx.Commit(ctx)
}
