package app

import (
	"bytes"
	"context"
	"encoding/json"
	"time"

	"zhiyu.local/zhiyu-go/internal/execution/bankv2"
	funds "zhiyu.local/zhiyu-go/internal/funds/domain"
	planning "zhiyu.local/zhiyu-go/internal/planning/domain"
)

const nativeStandingAssetPermitV2Protocol = "native-standing-asset-v2/permit"
const nativeStandingAssetPermitStoredLimit = 1 << 20

// V2 alone permits this expanded identity. It does not enlarge the V1 raw limit.
const nativeStandingAssetPermitV2ExpandedLimit = 2 << 20

// Every frozen Current field is retained except the selected Policy and the
// two forecast results. Those three fields are derived by the pinned pure core.
type nativeStandingAssetCurrentInputsV2 struct {
	NativeActionPreviewHeader
	Protocol          string                   `json:"protocol"`
	Timezone          string                   `json:"timezone"`
	Request           NativeAssetRequest       `json:"request"`
	Policies          []TemplatePolicyView     `json:"policies"`
	Ledger            NativeAssetLedgerCapture `json:"ledger"`
	InventoryOriginal json.RawMessage          `json:"inventory_original"`
	BankState         bankv2.CurrentState      `json:"bank_state"`
	Quote             *bankv2.Quote            `json:"quote,omitempty"`
	Position          *bankv2.PositionOpening  `json:"position,omitempty"`
	CashResources     NativeCashResources      `json:"cash_resources"`
	GoalUses          []NativeGoalTransferUse  `json:"goal_uses"`
	PendingPurchases  []bankv2.Request         `json:"pending_purchases"`
	BankEffect        bankv2.Effect            `json:"bank_effect"`
	ForecastInput     planning.ForecastInput   `json:"forecast_input"`
	RecoveryTrigger   string                   `json:"recovery_trigger,omitempty"`
	ReviewedHash      string                   `json:"reviewed_hash"`
}

type nativeStandingAssetProofV2 struct {
	Protocol           string                             `json:"protocol"`
	OperationID        funds.ID                           `json:"operation_id"`
	PermitID           string                             `json:"permit_id"`
	PlanHash           string                             `json:"plan_hash"`
	RequestHash        string                             `json:"request_hash"`
	EffectHash         string                             `json:"effect_hash"`
	SignatureHash      string                             `json:"signature_hash"`
	Grant              NativeStandingGrant                `json:"grant"`
	GrantStateSequence uint64                             `json:"grant_state_sequence"`
	CurrentInputs      nativeStandingAssetCurrentInputsV2 `json:"current_inputs"`
	FullCurrentBytes   int                                `json:"full_current_bytes"`
	FullCurrentSHA256  string                             `json:"full_current_sha256"`
	FullProofBytes     int                                `json:"full_proof_bytes"`
	FullProofSHA256    string                             `json:"full_proof_sha256"`
	DecisionAt         time.Time                          `json:"decision_at"`
}

func freezeStandingAssetCurrentV2(p NativeAssetPreview) nativeStandingAssetCurrentInputsV2 {
	return nativeStandingAssetCurrentInputsV2{NativeActionPreviewHeader: p.NativeActionPreviewHeader, Protocol: p.Protocol, Timezone: p.Timezone, Request: p.Request, Policies: p.Policies, Ledger: p.Ledger, InventoryOriginal: p.InventoryOriginal, BankState: p.BankState, Quote: p.Quote, Position: p.Position, CashResources: p.CashResources, GoalUses: p.GoalUses, PendingPurchases: p.PendingPurchases, BankEffect: p.BankEffect, ForecastInput: p.ForecastInput, RecoveryTrigger: p.RecoveryTrigger, ReviewedHash: p.ReviewedHash}
}

func rehydrateNativeStandingAssetProofV2(p nativeStandingAssetProofV2, plan nativeStandingAssetPlan) (nativeStandingAssetProof, error) {
	var zero nativeStandingAssetProof
	if p.Protocol != nativeStandingAssetPermitV2Protocol {
		return zero, reject("EVIDENCE_INVALID", nil)
	}
	if p.FullCurrentBytes < 1 || p.FullCurrentBytes > nativeStandingAssetPermitV2ExpandedLimit || p.FullProofBytes < 1 || p.FullProofBytes > nativeStandingAssetPermitV2ExpandedLimit {
		return zero, reject("ASSET_CAPACITY", nil)
	}
	planRaw, err := encode(plan)
	if err != nil || Hash(planRaw) != p.PlanHash || p.OperationID != plan.ID || !nativeActionHash(p.FullCurrentSHA256) || !nativeActionHash(p.FullProofSHA256) {
		return zero, reject("EVIDENCE_INVALID", nil)
	}
	grantRaw, err := encode(p.Grant)
	if err != nil {
		return zero, err
	}
	planGrantRaw, err := encode(plan.Grant)
	if err != nil {
		return zero, err
	}
	if !bytes.Equal(grantRaw, planGrantRaw) || p.GrantStateSequence < plan.GrantStateSequence {
		return zero, reject("EVIDENCE_INVALID", nil)
	}
	in := p.CurrentInputs
	if in.SessionID != (funds.ID{}) || in.ID != plan.ID || in.Kind != bankv2.Purchase || in.Quote != nil || in.Dependencies.GrantVersion != plan.Grant.Version || in.CreatedAt.Before(plan.Preview.CreatedAt) || !in.CreatedAt.Before(plan.Preview.ExpiresAt) || !p.DecisionAt.Equal(in.CreatedAt) {
		return zero, reject("EVIDENCE_INVALID", nil)
	}
	dependency := in.Dependencies
	prior := plan.Preview.Dependencies
	if in.Scope != plan.Scope || dependency.FundsVersion != prior.FundsVersion+1 || dependency.SourceEvidenceVersion != prior.SourceEvidenceVersion || dependency.WriterGeneration != prior.WriterGeneration || dependency.ControlVersion != prior.ControlVersion {
		return zero, reject("EVIDENCE_INVALID", nil)
	}
	request := standingAssetRequest(plan, in.Ledger.Namespace, p.PlanHash)
	requestHash, requestErr := request.Digest()
	effectHash, effectErr := request.Effect.Digest()
	if requestErr != nil || effectErr != nil || p.PermitID != request.PermitID || p.RequestHash != requestHash || p.EffectHash != effectHash || !nativeActionHash(p.SignatureHash) || p.DecisionAt.Before(request.RequestedAt) || !p.DecisionAt.Before(request.ExpiresAt) {
		return zero, reject("EVIDENCE_INVALID", nil)
	}
	ledger, err := in.Ledger.DomainLedger()
	if err != nil {
		return zero, reject("EVIDENCE_INVALID", err)
	}
	d := in.Dependencies
	snapshot := templateSnapshot{Facts: in.ForecastInput.Facts, Versions: in.ForecastInput.Versions, Views: in.Policies, Retained: in.ForecastInput.RetainedObligations, Held: in.ForecastInput.HeldCash, UnassignedGoalCash: in.ForecastInput.UnassignedGoalCash, InventoryRaw: in.InventoryOriginal, FundsVersion: d.FundsVersion, SourceVersion: d.SourceEvidenceVersion, WriterGeneration: d.WriterGeneration, ControlVersion: d.ControlVersion, AsOf: in.CreatedAt, Timezone: in.Timezone, Native: &ledger}
	snapshot.ExternalLiabilities = in.ForecastInput.ExternalLiabilities
	current, err := deriveNativeAssetPreviewWithSource(snapshot, plan.Preview.Request, plan.ID, funds.ID{}, in.BankState, nil, in.PendingPurchases, &plan.Source, plan.Preview.ExpiresAt)
	if err != nil {
		return zero, reject("EVIDENCE_INVALID", err)
	}
	current.Dependencies.GrantVersion = plan.Grant.Version
	current.ReviewedHash, err = NativeAssetReviewHash(current)
	if err != nil {
		return zero, err
	}
	// This compares every retained field, including values not directly consumed
	// by derive. A new hash cannot make contradictory frozen fields acceptable.
	a, err := encode(freezeStandingAssetCurrentV2(current))
	if err != nil {
		return zero, err
	}
	b, err := encode(in)
	if err != nil || !bytes.Equal(a, b) {
		return zero, reject("EVIDENCE_INVALID", nil)
	}
	currentRaw, err := encode(current)
	if err != nil {
		return zero, err
	}
	if len(currentRaw) > nativeStandingAssetPermitV2ExpandedLimit {
		return zero, reject("ASSET_CAPACITY", nil)
	}
	if len(currentRaw) != p.FullCurrentBytes || Hash(currentRaw) != p.FullCurrentSHA256 {
		return zero, reject("EVIDENCE_INVALID", nil)
	}
	if err = assetEquivalentEconomic(current, plan.Preview); err != nil {
		return zero, err
	}
	// This V1-shaped object is only the reconstructed identity of a V2 record.
	// It is never accepted as a successful oversized V1 stored original.
	full := nativeStandingAssetProof{Protocol: nativeStandingAssetProtocol + "/permit", OperationID: p.OperationID, PermitID: p.PermitID, PlanHash: p.PlanHash, RequestHash: p.RequestHash, EffectHash: p.EffectHash, SignatureHash: p.SignatureHash, Grant: p.Grant, GrantStateSequence: p.GrantStateSequence, Current: current, DecisionAt: p.DecisionAt}
	fullRaw, err := encode(full)
	if err != nil {
		return zero, err
	}
	if len(fullRaw) > nativeStandingAssetPermitV2ExpandedLimit {
		return zero, reject("ASSET_CAPACITY", nil)
	}
	if len(fullRaw) != p.FullProofBytes || Hash(fullRaw) != p.FullProofSHA256 {
		return zero, reject("EVIDENCE_INVALID", nil)
	}
	return full, nil
}

func encodeNativeStandingAssetProofV2(plan nativeStandingAssetPlan, full nativeStandingAssetProof, originalFullRaw []byte) ([]byte, error) {
	if full.Protocol != nativeStandingAssetProtocol+"/permit" {
		return nil, reject("EVIDENCE_INVALID", nil)
	}
	if len(originalFullRaw) < 1 || len(originalFullRaw) > nativeStandingAssetPermitV2ExpandedLimit {
		return nil, reject("ASSET_CAPACITY", nil)
	}
	currentRaw, err := encode(full.Current)
	if err != nil {
		return nil, err
	}
	if len(currentRaw) > nativeStandingAssetPermitV2ExpandedLimit {
		return nil, reject("ASSET_CAPACITY", nil)
	}
	p := nativeStandingAssetProofV2{Protocol: nativeStandingAssetPermitV2Protocol, OperationID: full.OperationID, PermitID: full.PermitID, PlanHash: full.PlanHash, RequestHash: full.RequestHash, EffectHash: full.EffectHash, SignatureHash: full.SignatureHash, Grant: full.Grant, GrantStateSequence: full.GrantStateSequence, CurrentInputs: freezeStandingAssetCurrentV2(full.Current), FullCurrentBytes: len(currentRaw), FullCurrentSHA256: Hash(currentRaw), FullProofBytes: len(originalFullRaw), FullProofSHA256: Hash(originalFullRaw), DecisionAt: full.DecisionAt}
	raw, err := encode(p)
	if err != nil {
		return nil, err
	}
	if len(raw) > nativeStandingAssetPermitStoredLimit {
		return nil, reject("ASSET_CAPACITY", nil)
	}
	roundTrip, err := rehydrateNativeStandingAssetProofV2(p, plan)
	if err != nil {
		return nil, err
	}
	again, err := encode(roundTrip)
	if err != nil || !bytes.Equal(again, originalFullRaw) {
		return nil, reject("EVIDENCE_INVALID", err)
	}
	return raw, nil
}

func decodeNativeStandingAssetProofV2(raw []byte, plan nativeStandingAssetPlan) (nativeStandingAssetProof, error) {
	var p nativeStandingAssetProofV2
	if len(raw) < 1 || len(raw) > nativeStandingAssetPermitStoredLimit {
		return nativeStandingAssetProof{}, reject("ASSET_CAPACITY", nil)
	}
	if auditJSON(raw, &p) != nil || p.Protocol != nativeStandingAssetPermitV2Protocol {
		return nativeStandingAssetProof{}, reject("EVIDENCE_INVALID", nil)
	}
	return rehydrateNativeStandingAssetProofV2(p, plan)
}

// SELECT and immutable stored-byte hash are shared with the original entry.
// No current-bank read, clock substitution, re-signing or external call occurs.
func assetStandingStoredPermitV2(ctx context.Context, q queryRow, p Principal, operation funds.ID, request bankv2.Request, signature string, raw []byte, stored, rh, eh, sh, permit string) error {
	if len(raw) < 1 || len(raw) > nativeStandingAssetPermitStoredLimit {
		return reject("ASSET_CAPACITY", nil)
	}
	if Hash(raw) != stored {
		return reject("EVIDENCE_INVALID", nil)
	}
	plan, hash, err := loadStandingAssetPlan(ctx, q, p, operation)
	if err != nil {
		return err
	}
	proof, err := decodeNativeStandingAssetProofV2(raw, plan)
	if err != nil {
		return err
	}
	want, e := request.Digest()
	effect, e2 := request.Effect.Digest()
	if e != nil || e2 != nil || proof.OperationID != operation || request.OperationID != operation.String() || request.UserID != p.UserID.String() || proof.PermitID != permit || permit != request.PermitID || want != rh || effect != eh || sh != Hash([]byte(signature)) || proof.RequestHash != rh || proof.EffectHash != eh || proof.SignatureHash != sh || !proof.DecisionAt.Equal(proof.Current.CreatedAt) || proof.DecisionAt.Before(request.RequestedAt) || !proof.DecisionAt.Before(request.ExpiresAt) {
		return reject("EVIDENCE_INVALID", nil)
	}
	expected := standingAssetRequest(plan, request.Namespace, hash)
	expectedHash, err := expected.Digest()
	a, _ := encode(plan.Grant)
	b, _ := encode(proof.Grant)
	d, current := plan.Preview.Dependencies, proof.Current.Dependencies
	if err != nil || expectedHash != want || hash != proof.PlanHash || !bytes.Equal(a, b) || proof.GrantStateSequence < plan.GrantStateSequence || current.FundsVersion != d.FundsVersion+1 || current.SourceEvidenceVersion != d.SourceEvidenceVersion || current.WriterGeneration != d.WriterGeneration || current.ControlVersion != d.ControlVersion {
		return reject("EVIDENCE_INVALID", nil)
	}
	return standingAssetReplayCurrent(plan, proof.Current)
}
