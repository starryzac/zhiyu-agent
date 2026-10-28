// Private v2 candidate: independent audit wire and pure frozen-input replay.
// Mirrored from the private app v2 protocol; no app package, DB, bank or clock I/O.
package executionaudit

import (
	"bytes"
	"encoding/json"
	"time"

	"zhiyu.local/zhiyu-go/internal/execution/bankv2"
	funds "zhiyu.local/zhiyu-go/internal/funds/domain"
	planning "zhiyu.local/zhiyu-go/internal/planning/domain"
	policy "zhiyu.local/zhiyu-go/internal/policy/domain"
)

const nativeStandingAssetLogicalProtocolBaseV3 = "native-standing-asset-v1"

const nativeStandingAssetPermitV2ProtocolV3 = "native-standing-asset-v2/permit"
const nativeStandingAssetPermitStoredLimitV3 = 1 << 20

// V2 alone permits this expanded identity. It does not enlarge the V1 raw limit.
const nativeStandingAssetPermitV2ExpandedLimitV3 = 2 << 20

// Every frozen Current field is retained except the selected Policy and the
// two forecast results. Those three fields are derived by the pinned pure core.
type wireNativeStandingAssetCurrentInputsV2 struct {
	wireNativeActionPreviewHeader
	Protocol          string                       `json:"protocol"`
	Timezone          string                       `json:"timezone"`
	Request           wireNativeAssetRequest       `json:"request"`
	Policies          []wireTemplatePolicyView     `json:"policies"`
	Ledger            wireNativeAssetLedgerCapture `json:"ledger"`
	InventoryOriginal json.RawMessage              `json:"inventory_original"`
	BankState         bankv2.CurrentState          `json:"bank_state"`
	Quote             *bankv2.Quote                `json:"quote,omitempty"`
	Position          *bankv2.PositionOpening      `json:"position,omitempty"`
	CashResources     wireNativeCashResources      `json:"cash_resources"`
	GoalUses          []wireNativeGoalTransferUse  `json:"goal_uses"`
	PendingPurchases  []bankv2.Request             `json:"pending_purchases"`
	BankEffect        bankv2.Effect                `json:"bank_effect"`
	ForecastInput     planning.ForecastInput       `json:"forecast_input"`
	RecoveryTrigger   string                       `json:"recovery_trigger,omitempty"`
	ReviewedHash      string                       `json:"reviewed_hash"`
}

type wirenativeStandingAssetProofV2 struct {
	Protocol           string                                 `json:"protocol"`
	OperationID        funds.ID                               `json:"operation_id"`
	PermitID           string                                 `json:"permit_id"`
	PlanHash           string                                 `json:"plan_hash"`
	RequestHash        string                                 `json:"request_hash"`
	EffectHash         string                                 `json:"effect_hash"`
	SignatureHash      string                                 `json:"signature_hash"`
	Grant              wireNativeStandingGrant                `json:"grant"`
	GrantStateSequence uint64                                 `json:"grant_state_sequence"`
	CurrentInputs      wireNativeStandingAssetCurrentInputsV2 `json:"current_inputs"`
	FullCurrentBytes   int                                    `json:"full_current_bytes"`
	FullCurrentSHA256  string                                 `json:"full_current_sha256"`
	FullProofBytes     int                                    `json:"full_proof_bytes"`
	FullProofSHA256    string                                 `json:"full_proof_sha256"`
	DecisionAt         time.Time                              `json:"decision_at"`
}

func freezeStandingAssetCurrentV2V3(p wireNativeAssetPreview) wireNativeStandingAssetCurrentInputsV2 {
	return wireNativeStandingAssetCurrentInputsV2{wireNativeActionPreviewHeader: p.wireNativeActionPreviewHeader, Protocol: p.Protocol, Timezone: p.Timezone, Request: p.Request, Policies: p.Policies, Ledger: p.Ledger, InventoryOriginal: p.InventoryOriginal, BankState: p.BankState, Quote: p.Quote, Position: p.Position, CashResources: p.CashResources, GoalUses: p.GoalUses, PendingPurchases: p.PendingPurchases, BankEffect: p.BankEffect, ForecastInput: p.ForecastInput, RecoveryTrigger: p.RecoveryTrigger, ReviewedHash: p.ReviewedHash}
}

func rehydrateStandingAssetProofV2V3(p wirenativeStandingAssetProofV2, plan wirenativeStandingAssetPlan) (wirenativeStandingAssetProof, error) {
	var zero wirenativeStandingAssetProof
	if p.Protocol != nativeStandingAssetPermitV2ProtocolV3 {
		return zero, nativeMirrorRejectV3("EVIDENCE_INVALID", nil)
	}
	if p.FullCurrentBytes < 1 || p.FullCurrentBytes > nativeStandingAssetPermitV2ExpandedLimitV3 || p.FullProofBytes < 1 || p.FullProofBytes > nativeStandingAssetPermitV2ExpandedLimitV3 {
		return zero, nativeMirrorRejectV3("ASSET_CAPACITY", nil)
	}
	planRaw, err := nativeMirrorEncodeV3(plan)
	if err != nil || nakedHash(planRaw) != p.PlanHash || p.OperationID != plan.ID || !mirrornativeActionHashV3(p.FullCurrentSHA256) || !mirrornativeActionHashV3(p.FullProofSHA256) {
		return zero, nativeMirrorRejectV3("EVIDENCE_INVALID", nil)
	}
	grantRaw, err := nativeMirrorEncodeV3(p.Grant)
	if err != nil {
		return zero, err
	}
	planGrantRaw, err := nativeMirrorEncodeV3(plan.Grant)
	if err != nil {
		return zero, err
	}
	if !bytes.Equal(grantRaw, planGrantRaw) || p.GrantStateSequence < plan.GrantStateSequence {
		return zero, nativeMirrorRejectV3("EVIDENCE_INVALID", nil)
	}
	in := p.CurrentInputs
	if in.SessionID != (funds.ID{}) || in.ID != plan.ID || in.Kind != bankv2.Purchase || in.Quote != nil || in.Dependencies.GrantVersion != plan.Grant.Version || in.CreatedAt.Before(plan.Preview.CreatedAt) || !in.CreatedAt.Before(plan.Preview.ExpiresAt) || !p.DecisionAt.Equal(in.CreatedAt) {
		return zero, nativeMirrorRejectV3("EVIDENCE_INVALID", nil)
	}
	dependency := in.Dependencies
	prior := plan.Preview.Dependencies
	if in.Scope != plan.Scope || dependency.FundsVersion != prior.FundsVersion+1 || dependency.SourceEvidenceVersion != prior.SourceEvidenceVersion || dependency.WriterGeneration != prior.WriterGeneration || dependency.ControlVersion != prior.ControlVersion {
		return zero, nativeMirrorRejectV3("EVIDENCE_INVALID", nil)
	}
	request := mirrorstandingAssetRequestV3(plan, in.Ledger.Namespace, p.PlanHash)
	requestHash, requestErr := request.Digest()
	effectHash, effectErr := request.Effect.Digest()
	if requestErr != nil || effectErr != nil || p.PermitID != request.PermitID || p.RequestHash != requestHash || p.EffectHash != effectHash || !mirrornativeActionHashV3(p.SignatureHash) || p.DecisionAt.Before(request.RequestedAt) || !p.DecisionAt.Before(request.ExpiresAt) {
		return zero, nativeMirrorRejectV3("EVIDENCE_INVALID", nil)
	}
	ledger, err := in.Ledger.DomainLedger()
	if err != nil {
		return zero, nativeMirrorRejectV3("EVIDENCE_INVALID", err)
	}
	d := in.Dependencies
	snapshot := mirrortemplateSnapshotV3{Facts: in.ForecastInput.Facts, Versions: in.ForecastInput.Versions, Views: in.Policies, Retained: in.ForecastInput.RetainedObligations, Held: in.ForecastInput.HeldCash, UnassignedGoalCash: in.ForecastInput.UnassignedGoalCash, InventoryRaw: in.InventoryOriginal, FundsVersion: d.FundsVersion, SourceVersion: d.SourceEvidenceVersion, WriterGeneration: d.WriterGeneration, ControlVersion: d.ControlVersion, AsOf: in.CreatedAt, Timezone: in.Timezone, Native: &ledger}
	snapshot.ExternalLiabilities = in.ForecastInput.ExternalLiabilities
	current, err := mirrorderiveNativeAssetPreviewWithSourceV3(snapshot, plan.Preview.Request, plan.ID, funds.ID{}, in.BankState, nil, in.PendingPurchases, &plan.Source, plan.Preview.ExpiresAt)
	if err != nil {
		return zero, nativeMirrorRejectV3("EVIDENCE_INVALID", err)
	}
	current.Dependencies.GrantVersion = plan.Grant.Version
	current.ReviewedHash, err = mirrorNativeAssetReviewHashV3(current)
	if err != nil {
		return zero, err
	}
	// This compares every retained field, including values not directly consumed
	// by derive. A new hash cannot make contradictory frozen fields acceptable.
	a, err := nativeMirrorEncodeV3(freezeStandingAssetCurrentV2V3(current))
	if err != nil {
		return zero, err
	}
	b, err := nativeMirrorEncodeV3(in)
	if err != nil || !bytes.Equal(a, b) {
		return zero, nativeMirrorRejectV3("EVIDENCE_INVALID", nil)
	}
	currentRaw, err := nativeMirrorEncodeV3(current)
	if err != nil {
		return zero, err
	}
	if len(currentRaw) > nativeStandingAssetPermitV2ExpandedLimitV3 {
		return zero, nativeMirrorRejectV3("ASSET_CAPACITY", nil)
	}
	if len(currentRaw) != p.FullCurrentBytes || nakedHash(currentRaw) != p.FullCurrentSHA256 {
		return zero, nativeMirrorRejectV3("EVIDENCE_INVALID", nil)
	}
	if err = mirrorassetEquivalentEconomicV3(current, plan.Preview); err != nil {
		return zero, err
	}
	// This V1-shaped object is only the reconstructed identity of a V2 record.
	// It is never accepted as a successful oversized V1 stored original.
	full := wirenativeStandingAssetProof{Protocol: nativeStandingAssetLogicalProtocolBaseV3 + "/permit", OperationID: p.OperationID, PermitID: p.PermitID, PlanHash: p.PlanHash, RequestHash: p.RequestHash, EffectHash: p.EffectHash, SignatureHash: p.SignatureHash, Grant: p.Grant, GrantStateSequence: p.GrantStateSequence, Current: current, DecisionAt: p.DecisionAt}
	fullRaw, err := nativeMirrorEncodeV3(full)
	if err != nil {
		return zero, err
	}
	if len(fullRaw) > nativeStandingAssetPermitV2ExpandedLimitV3 {
		return zero, nativeMirrorRejectV3("ASSET_CAPACITY", nil)
	}
	if len(fullRaw) != p.FullProofBytes || nakedHash(fullRaw) != p.FullProofSHA256 {
		return zero, nativeMirrorRejectV3("EVIDENCE_INVALID", nil)
	}
	return full, nil
}

func decodeStandingAssetProofV2V3(raw []byte, plan wirenativeStandingAssetPlan) (wirenativeStandingAssetProof, error) {
	var p wirenativeStandingAssetProofV2
	if len(raw) < 1 || len(raw) > nativeStandingAssetPermitStoredLimitV3 {
		return wirenativeStandingAssetProof{}, nativeMirrorRejectV3("ASSET_CAPACITY", nil)
	}
	if nativeCompactOriginalV3(raw, &p) != nil || p.Protocol != nativeStandingAssetPermitV2ProtocolV3 {
		return wirenativeStandingAssetProof{}, nativeMirrorRejectV3("EVIDENCE_INVALID", nil)
	}
	return rehydrateStandingAssetProofV2V3(p, plan)
}

// The row is still bound to its stored bytes/hash by permitHeaderV3. The V2
// logical identity does not replace any existing grant/bank/economic closure.
func (g *nativeGraphV3) checkStandingAssetPermitV2V3(row *ledgerRow, request bankv2.Request, id string, op *ledgerRow) error {
	plan := g.standingPlans[id]
	if plan.asset == nil {
		return businessInvalid("native standing asset v2 T2 original plan")
	}
	f := plan.asset
	p, err := decodeStandingAssetProofV2V3(nativeRawV3(row, "original"), *f)
	if err != nil {
		return nativeMirrorCheckV3("standing asset v2 T2 input", err)
	}
	if err = g.permitHeaderV3(row, request, p.OperationID, p.PermitID, p.RequestHash, p.EffectHash, p.SignatureHash, p.DecisionAt); err != nil {
		return err
	}
	if op.text("mode") != "STANDING" || p.PlanHash != plan.hash || !exactJSON(p.Grant, f.Grant) || p.GrantStateSequence < f.GrantStateSequence {
		return businessInvalid("native standing asset v2 original grant T2")
	}
	if err = g.grantActiveAtV3(p.Grant.ID.String(), p.GrantStateSequence, p.DecisionAt); err != nil {
		return err
	}
	if err = mirrorstandingAssetReplayCurrentV3(*f, p.Current); err != nil {
		return nativeMirrorCheckV3("standing asset v2 T2 current", err)
	}
	expected := mirrorstandingAssetRequestV3(*f, g.manifest.Scope.Namespace, plan.hash)
	if !exactJSON(expected, request) || policy.AuthorizeNativeStanding(p.Grant.Terms, "ACTIVE", f.Authority, f.Usage, p.DecisionAt) != nil {
		return businessInvalid("native standing asset v2 exact T2 request/source/budget")
	}
	ledger, err := g.frozenLedgerV3(p.Current.Ledger, p.DecisionAt, mustBusinessID(id))
	if err != nil {
		return err
	}
	return g.frozenForecastEconomyV3(p.Current.ForecastInput, p.Current.ForecastBefore, ledger, p.Current.Dependencies, mustBusinessID(id))
}
