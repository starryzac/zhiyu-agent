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

type nativeStandingAssetProof struct {
	Protocol           string              `json:"protocol"`
	OperationID        funds.ID            `json:"operation_id"`
	PermitID           string              `json:"permit_id"`
	PlanHash           string              `json:"plan_hash"`
	RequestHash        string              `json:"request_hash"`
	EffectHash         string              `json:"effect_hash"`
	SignatureHash      string              `json:"signature_hash"`
	Grant              NativeStandingGrant `json:"grant"`
	GrantStateSequence uint64              `json:"grant_state_sequence"`
	Current            NativeAssetPreview  `json:"current"`
	DecisionAt         time.Time           `json:"decision_at"`
}

func assetExecutionMode(ctx context.Context, q queryRow, p Principal, operation funds.ID) (string, error) {
	var mode string
	err := q.QueryRow(ctx, `SELECT mode FROM native_operations WHERE environment_id=$1 AND user_id=$2 AND id=$3 AND command_kind='PURCHASE_ASSET'`, p.EnvironmentID.String(), p.UserID.String(), operation.String()).Scan(&mode)
	if err == pgx.ErrNoRows {
		return "ONCE", nil
	} // Other asset kinds retain their original ONCE protocol.
	if err != nil {
		return "", err
	}
	if mode != "ONCE" && mode != "STANDING" {
		return "", reject("EVIDENCE_INVALID", nil)
	}
	return mode, nil
}

func loadAssetExecutionPreview(ctx context.Context, q queryRow, p Principal, operation, preview funds.ID, kind bankv2.Kind) (NativeAssetPreview, error) {
	mode, err := assetExecutionMode(ctx, q, p, operation)
	if err != nil {
		return NativeAssetPreview{}, err
	}
	if mode == "STANDING" {
		plan, _, err := loadStandingAssetPlan(ctx, q, p, operation)
		if err != nil {
			return NativeAssetPreview{}, err
		}
		if preview != plan.Preview.ID || kind != bankv2.Purchase {
			return NativeAssetPreview{}, reject("EVIDENCE_INVALID", nil)
		}
		return plan.Preview, nil
	}
	return loadNativeAssetPreview(ctx, q, p, preview, kind)
}

func (s *Service) assetStandingFinalizeBudget(ctx context.Context, tx pgx.Tx, p Principal, operation funds.ID, spent funds.Money) error {
	mode, err := assetExecutionMode(ctx, tx, p, operation)
	if err != nil || mode != "STANDING" {
		return err
	}
	plan, _, err := loadStandingAssetPlan(ctx, tx, p, operation)
	if err != nil {
		return err
	}
	return finalizeNativeStandingBudget(ctx, tx, p, plan.Occurrence.ID, spent, s.now())
}

func standingAssetReplayCurrent(plan nativeStandingAssetPlan, current NativeAssetPreview) error {
	if current.SessionID != (funds.ID{}) || current.ID != plan.ID || current.Kind != bankv2.Purchase || current.Quote != nil || current.Dependencies.GrantVersion != plan.Grant.Version || current.CreatedAt.Before(plan.Preview.CreatedAt) || !current.CreatedAt.Before(plan.Preview.ExpiresAt) {
		return reject("EVIDENCE_INVALID", nil)
	}
	ledger, err := current.Ledger.DomainLedger()
	if err != nil {
		return reject("EVIDENCE_INVALID", err)
	}
	d := current.Dependencies
	snapshot := templateSnapshot{Facts: current.ForecastInput.Facts, Versions: current.ForecastInput.Versions, Views: current.Policies, Retained: current.ForecastInput.RetainedObligations, Held: current.ForecastInput.HeldCash, UnassignedGoalCash: current.ForecastInput.UnassignedGoalCash, InventoryRaw: current.InventoryOriginal, FundsVersion: d.FundsVersion, SourceVersion: d.SourceEvidenceVersion, WriterGeneration: d.WriterGeneration, ControlVersion: d.ControlVersion, AsOf: current.CreatedAt, Timezone: current.Timezone, Native: &ledger}
	snapshot.ExternalLiabilities = current.ForecastInput.ExternalLiabilities
	expected, err := deriveNativeAssetPreviewWithSource(snapshot, plan.Preview.Request, plan.ID, funds.ID{}, current.BankState, nil, current.PendingPurchases, &plan.Source, plan.Preview.ExpiresAt)
	if err != nil {
		return reject("EVIDENCE_INVALID", err)
	}
	expected.Dependencies.GrantVersion = plan.Grant.Version
	expected.ReviewedHash, err = NativeAssetReviewHash(expected)
	if err != nil {
		return err
	}
	a, _ := encode(expected)
	b, _ := encode(current)
	if string(a) != string(b) {
		return reject("EVIDENCE_INVALID", fmt.Errorf("standing asset current capture replay differs"))
	}
	return assetEquivalentEconomic(current, plan.Preview)
}

func assetStandingStoredPermit(ctx context.Context, q queryRow, p Principal, operation funds.ID, request bankv2.Request, signature string) error {
	var raw []byte
	var stored, rh, eh, sh, permit string
	err := q.QueryRow(ctx, `SELECT original,original_hash,bank_request_hash,effect_hash,signature_hash,permit_id::text FROM native_submission_permits WHERE environment_id=$1 AND user_id=$2 AND operation_id=$3`, p.EnvironmentID.String(), p.UserID.String(), operation.String()).Scan(&raw, &stored, &rh, &eh, &sh, &permit)
	if err != nil {
		return err
	}
	if len(raw) == 0 || len(raw) > nativeStandingAssetPermitStoredLimit {
		return reject("ASSET_CAPACITY", nil)
	}
	var declared struct {
		Protocol string `json:"protocol"`
	}
	if decode(raw, &declared) == nil && declared.Protocol == nativeStandingAssetPermitV2Protocol {
		return assetStandingStoredPermitV2(ctx, q, p, operation, request, signature, raw, stored, rh, eh, sh, permit)
	}
	var proof nativeStandingAssetProof
	want, e := request.Digest()
	effect, e2 := request.Effect.Digest()
	if e != nil || e2 != nil || Hash(raw) != stored || auditJSON(raw, &proof) != nil || proof.Protocol != nativeStandingAssetProtocol+"/permit" || proof.OperationID != operation || request.OperationID != operation.String() || request.UserID != p.UserID.String() || proof.PermitID != permit || permit != request.PermitID || want != rh || effect != eh || sh != Hash([]byte(signature)) || proof.RequestHash != rh || proof.EffectHash != eh || proof.SignatureHash != sh || !proof.DecisionAt.Equal(proof.Current.CreatedAt) || proof.DecisionAt.Before(request.RequestedAt) || !proof.DecisionAt.Before(request.ExpiresAt) {
		return reject("EVIDENCE_INVALID", nil)
	}
	plan, hash, err := loadStandingAssetPlan(ctx, q, p, operation)
	if err != nil {
		return err
	}
	expected := standingAssetRequest(plan, request.Namespace, hash)
	expectedHash, err := expected.Digest()
	a, _ := encode(plan.Grant)
	b, _ := encode(proof.Grant)
	d, current := plan.Preview.Dependencies, proof.Current.Dependencies
	if err != nil || expectedHash != want || hash != proof.PlanHash || string(a) != string(b) || proof.GrantStateSequence < plan.GrantStateSequence || current.FundsVersion != d.FundsVersion+1 || current.SourceEvidenceVersion != d.SourceEvidenceVersion || current.WriterGeneration != d.WriterGeneration || current.ControlVersion != d.ControlVersion {
		return reject("EVIDENCE_INVALID", nil)
	}
	return standingAssetReplayCurrent(plan, proof.Current)
}

func (s *Service) assetStandingCancel(ctx context.Context, tx pgx.Tx, c Claim, plan nativeStandingAssetPlan, reason string) error {
	p := c.Principal
	ledger, err := s.Store.LoadNativeLedger(ctx, tx, p.EnvironmentID, p.UserID, s.now())
	if err != nil {
		return err
	}
	if err = releaseNativeAssetResources(&ledger, c.OperationID); err != nil {
		return err
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
	cause, err := s.nativeTerminalCancellationCause(ctx, tx, p, c.OperationID, reason)
	if err != nil {
		return err
	}
	if err = s.recordFundsTerminalDecision(ctx, tx, p, "NATIVE", c.OperationID, "CANCELLED", cause); err != nil {
		return err
	}
	if _, err = tx.Exec(ctx, `UPDATE users SET funds_version=funds_version+1 WHERE environment_id=$1 AND id=$2`, p.EnvironmentID.String(), p.UserID.String()); err != nil {
		return err
	}
	if err = s.assetProtection(ctx, tx, p, c.OperationID); err != nil {
		return err
	}
	return finishNativeJob(ctx, tx, c)
}

func (s *Service) assetStandingPermit(ctx context.Context, c Claim) (nativePermitted, error) {
	var out nativePermitted
	p := c.Principal
	if p.Kind != "SYSTEM" || p.SessionID != (funds.ID{}) {
		return out, reject("FORBIDDEN", nil)
	}
	// Once signed, recovery has no current-bank/catalog dependency.
	var unsigned bool
	if err := s.Pool.QueryRow(ctx, `SELECT permit_signature IS NULL AND status='QUEUED' FROM native_operations WHERE environment_id=$1 AND user_id=$2 AND id=$3 AND mode='STANDING'`, p.EnvironmentID.String(), p.UserID.String(), c.OperationID.String()).Scan(&unsigned); err != nil {
		return out, err
	}
	var bankState bankv2.CurrentState
	if unsigned {
		reader, ok := s.NativeBank.(nativeAssetBankReader)
		if !ok {
			return out, reject("BANK_UNAVAILABLE", nil)
		}
		var err error
		bankState, err = reader.CurrentState(ctx, s.Namespace, p.UserID.String())
		if err != nil {
			return out, reject("BANK_UNAVAILABLE", nil)
		}
	}
	tx, err := s.begin(ctx)
	if err != nil {
		return out, err
	}
	defer rollback(ctx, tx)
	if err = s.lockNativeClaim(ctx, tx, c); err != nil {
		return out, err
	}
	var raw []byte
	var rh, eh, mode, grantID string
	var grantVersion, reservedFV uint64
	var signature *string
	err = tx.QueryRow(ctx, `SELECT status,bank_request,bank_request_hash,effect_hash,mode,grant_id::text,grant_version,reserved_funds_version,permit_signature FROM native_operations WHERE environment_id=$1 AND user_id=$2 AND id=$3 AND command_kind='PURCHASE_ASSET'`, p.EnvironmentID.String(), p.UserID.String(), c.OperationID.String()).Scan(&out.State, &raw, &rh, &eh, &mode, &grantID, &grantVersion, &reservedFV, &signature)
	if err != nil {
		return out, err
	}
	if auditJSON(raw, &out.Request) != nil {
		return out, reject("EVIDENCE_INVALID", nil)
	}
	h, e := out.Request.Digest()
	effect, e2 := out.Request.Effect.Digest()
	if e != nil || e2 != nil || h != rh || effect != eh || mode != "STANDING" || out.Request.Namespace != s.Namespace || out.Request.UserID != p.UserID.String() || out.Request.OperationID != c.OperationID.String() || out.Request.Effect.Kind != bankv2.Purchase {
		return out, reject("EVIDENCE_INVALID", nil)
	}
	if out.State == "SETTLED" || out.State == "REJECTED" || out.State == "CANCELLED" {
		out.Cancelled = true
		return out, nil
	}
	if signature != nil {
		if err = assetStandingStoredPermit(ctx, tx, p, c.OperationID, out.Request, *signature); err != nil {
			return out, err
		}
		out.Signature = *signature
		return out, tx.Commit(ctx)
	}
	if out.State != "QUEUED" {
		return out, reject("OPERATION_UNKNOWN", nil)
	}
	plan, hash, err := loadStandingAssetPlan(ctx, tx, p, c.OperationID)
	if err != nil {
		return out, err
	}
	expected := standingAssetRequest(plan, s.Namespace, hash)
	expectedHash, err := expected.Digest()
	if err != nil || expectedHash != rh || grantID != plan.Grant.ID.String() || grantVersion != plan.Grant.Version || reservedFV != plan.Preview.Dependencies.FundsVersion+1 {
		return out, reject("EVIDENCE_INVALID", err)
	}
	now := s.now()
	var current NativeAssetPreview
	var grant NativeStandingGrantView
	permissionErr := func() error {
		if now.Before(plan.Preview.CreatedAt) || !now.Before(plan.Preview.ExpiresAt) {
			return reject("AUTHORIZATION_EXPIRED", nil)
		}
		var err error
		grant, err = loadNativeStandingGrant(ctx, tx, p, plan.Grant.ID)
		if err != nil {
			return err
		}
		a, _ := encode(grant.Grant)
		b, _ := encode(plan.Grant)
		if string(a) != string(b) {
			return reject("EVIDENCE_INVALID", nil)
		}
		if grant.State != "ACTIVE" {
			return reject("NATIVE_GRANT_NOT_ACTIVE", nil)
		}
		if err = nativeStandingCurrentReferences(ctx, tx, s, p, grant.Grant); err != nil {
			return err
		}
		var fv, sv, wg, cv uint64
		if err = tx.QueryRow(ctx, `SELECT u.funds_version,u.source_version,e.writer_generation,e.control_version FROM users u JOIN environments e ON(e.id=u.environment_id) WHERE u.environment_id=$1 AND u.id=$2`, p.EnvironmentID.String(), p.UserID.String()).Scan(&fv, &sv, &wg, &cv); err != nil {
			return err
		}
		d := plan.Preview.Dependencies
		if fv != reservedFV || sv != d.SourceEvidenceVersion || wg != d.WriterGeneration || cv != d.ControlVersion {
			return reject("SOURCE_CHANGED", nil)
		}
		usage, err := nativeStandingUsage(ctx, tx, p, grant.Grant, now, &plan.Occurrence.ID)
		if err != nil {
			return err
		}
		if err = policy.AuthorizeNativeStanding(grant.Grant.Terms, grant.State, plan.Authority, usage, now); err != nil {
			return reject(err.Error(), err)
		}
		snapshot, err := s.loadTemplateSnapshot(ctx, tx, p, now, plan.Grant.Terms.Timezone)
		if err != nil {
			return err
		}
		if snapshot.Native == nil {
			return reject("EVIDENCE_INVALID", nil)
		}
		if err = checkNativeAssetResources(*snapshot.Native, c.OperationID, plan.Preview); err != nil {
			return err
		}
		snapshot, err = assetSnapshotWithoutReservation(snapshot, c.OperationID)
		if err != nil {
			return err
		}
		pending, err := assetPendingPurchases(ctx, tx, p, s.Namespace)
		if err != nil {
			return err
		}
		filtered := pending[:0]
		for _, request := range pending {
			if request.OperationID != c.OperationID.String() {
				filtered = append(filtered, request)
			}
		}
		current, err = deriveNativeAssetPreviewWithSource(snapshot, plan.Preview.Request, plan.ID, funds.ID{}, bankState, nil, filtered, &plan.Source, plan.Preview.ExpiresAt)
		if err != nil {
			return err
		}
		current.Dependencies.GrantVersion = plan.Grant.Version
		current.ReviewedHash, err = NativeAssetReviewHash(current)
		if err != nil {
			return err
		}
		return standingAssetReplayCurrent(plan, current)
	}()
	if permissionErr != nil {
		switch Code(permissionErr) {
		case "AUTHORIZATION_EXPIRED", "SOURCE_CHANGED", "NATIVE_GRANT_NOT_ACTIVE", "NATIVE_GRANT_POLICY_CHANGED", "NATIVE_STANDING_CAP_EXCEEDED", "ASSET_POLICY_NOT_ACTIVE", "ASSET_PRODUCT_UNAVAILABLE", "ASSET_NO_SAFE_PURCHASE", "ASSET_PROTECTION_DEFICIT", "ASSET_POLICY_REJECTED", "ASSET_BELOW_MINIMUM", "ASSET_BANK_STATE_CHANGED":
			if err = s.assetStandingCancel(ctx, tx, c, plan, Code(permissionErr)); err != nil {
				return out, err
			}
			out.Cancelled = true
			return out, tx.Commit(ctx)
		default:
			return out, fmt.Errorf("standing asset current permission: %w", permissionErr)
		}
	}
	out.Signature, err = bankv2.SignPermit(out.Request, s.PermitSecret)
	if err != nil {
		return out, err
	}
	proof := nativeStandingAssetProof{Protocol: nativeStandingAssetProtocol + "/permit", OperationID: c.OperationID, PermitID: out.Request.PermitID, PlanHash: hash, RequestHash: rh, EffectHash: eh, SignatureHash: Hash([]byte(out.Signature)), Grant: grant.Grant, GrantStateSequence: grant.StateSequence, Current: current, DecisionAt: now}
	proofRaw, err := encode(proof)
	if err != nil {
		return out, err
	}
	storedProofRaw, err := encodeNativeStandingAssetProofV2(plan, proof, proofRaw)
	if err != nil {
		return out, err
	}
	_, err = tx.Exec(ctx, `INSERT INTO native_submission_permits(environment_id,user_id,operation_id,permit_id,bank_request_hash,effect_hash,signature_hash,original,original_hash,decision_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`, p.EnvironmentID.String(), p.UserID.String(), c.OperationID.String(), out.Request.PermitID, rh, eh, proof.SignatureHash, storedProofRaw, Hash(storedProofRaw), now)
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
