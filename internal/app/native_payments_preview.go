package app

import (
	"context"
	"math/big"
	"time"

	"github.com/jackc/pgx/v5"
	"zhiyu.local/zhiyu-go/internal/execution/bankv2"
	funds "zhiyu.local/zhiyu-go/internal/funds/domain"
	planning "zhiyu.local/zhiyu-go/internal/planning/domain"
	policy "zhiyu.local/zhiyu-go/internal/policy/domain"
)

type NativePaymentRequest struct {
	PolicyVersionID funds.ID    `json:"policy_version_id"`
	ObligationID    string      `json:"obligation_id"`
	SourceAccountID funds.ID    `json:"source_account_id"`
	Amount          funds.Money `json:"amount_cents"`
	Timezone        string      `json:"timezone"`
}
type NativePaymentPreview struct {
	NativeActionPreviewHeader
	Protocol          string                      `json:"protocol"`
	Timezone          string                      `json:"timezone"`
	Request           NativePaymentRequest        `json:"request"`
	Policy            TemplatePolicyView          `json:"policy"`
	Debt              planning.ForecastObligation `json:"debt"`
	Liability         bankv2.LiabilityState       `json:"liability"`
	BillProof         *NativeBillProof            `json:"bill_proof,omitempty"`
	AdoptionProof     *NativePaymentAdoptionProof `json:"adoption_proof,omitempty"`
	BankEffect        bankv2.Effect               `json:"bank_effect"`
	Resources         NativeCashResources         `json:"resources"`
	Ledger            NativeAssetLedgerCapture    `json:"ledger"`
	InventoryOriginal []byte                      `json:"inventory_original"`
	ForecastInput     planning.ForecastInput      `json:"forecast_input"`
	ForecastBefore    planning.ForecastResult     `json:"forecast_before"`
	ForecastAfter     planning.ForecastResult     `json:"forecast_after"`
	ReviewedHash      string                      `json:"reviewed_hash"`
}
type nativePaymentBankReader interface {
	Liabilities(context.Context, string, string) (bankv2.LiabilitySnapshot, error)
}

func nativePaymentEffect(id funds.ID, resources NativeCashResources, liability bankv2.LiabilityReference, expires time.Time) bankv2.Effect {
	return bankv2.Effect{Kind: bankv2.Payment, BusinessKey: id.String(), Amount: resources.Amount, CashUses: append([]bankv2.CashUse{}, resources.CashUses...), OriginUses: nativeCashOriginUses(resources), ReturnUses: append([]bankv2.ReturnUse{}, resources.ReturnUses...), Liability: &liability, LatestArrivalAt: expires}
}

func NativePaymentReviewHash(preview NativePaymentPreview) (string, error) {
	preview.ReviewedHash = ""
	raw, e := encode(preview)
	return Hash(raw), e
}
func nativePaymentMargins(before, after planning.ForecastResult) error {
	if len(before.Points) != len(after.Points) || len(before.Points) == 0 || after.MaximumDeficit.Cents() > before.MaximumDeficit.Cents() {
		return reject("PAYMENT_PROTECTION_REDUCED", nil)
	}
	for i, left := range before.Points {
		right := after.Points[i]
		a, ok := new(big.Int).SetString(left.MarginCents, 10)
		b, ok2 := new(big.Int).SetString(right.MarginCents, 10)
		if !ok || !ok2 || left.Date != right.Date || left.Phase != right.Phase || b.Cmp(a) < 0 {
			return reject("PAYMENT_PROTECTION_REDUCED", nil)
		}
	}
	return nil
}
func replayNativePaymentPreview(preview NativePaymentPreview) error {
	if preview.Protocol != "native-payment-preview-v1" || preview.Kind != bankv2.Payment || preview.BankAuthority || preview.Policy.GoalID != nil || preview.Policy.Version.Scope != preview.Scope || preview.Policy.Version.VersionID != preview.Request.PolicyVersionID || preview.SourceHash != preview.ForecastInput.Facts.SourceHash || preview.InventoryHash != preview.ForecastInput.InventoryHash || preview.ForecastInput.Scope != preview.Scope || !preview.ForecastInput.AsOf.Equal(preview.CreatedAt) || preview.ForecastInput.Timezone != preview.Timezone || preview.Request.Timezone != preview.Timezone {
		return reject("EVIDENCE_INVALID", nil)
	}
	amount, e := nativePaymentPreviewAmount(preview, preview.CreatedAt)
	if e != nil || amount != preview.Resources.Amount || len(preview.Resources.CashUses) != 1 || preview.Resources.CashUses[0].AccountID != preview.Request.SourceAccountID.String() || preview.Resources.CashUses[0].Amount != amount {
		return reject("EVIDENCE_INVALID", e)
	}
	ledger, e := preview.Ledger.DomainLedger()
	if e != nil || ledger.Income.Snapshot().UserID != preview.Scope.UserID || !ledger.Income.Snapshot().AsOf.Equal(preview.CreatedAt) || Hash(preview.InventoryOriginal) != preview.InventoryHash {
		return reject("EVIDENCE_INVALID", e)
	}
	selected, e := selectNativeUnownedCash(ledger, []funds.ID{preview.Request.SourceAccountID}, amount)
	a, _ := encode(selected)
	b, _ := encode(preview.Resources)
	if e != nil || !templateSameBytes(a, b) {
		return reject("EVIDENCE_INVALID", e)
	}
	decoded, e := preview.Policy.Version.Compiled.Decode()
	if e != nil {
		return reject("EVIDENCE_INVALID", e)
	}
	if config, ok := decoded.(*policy.PeriodicTransferConfig); ok && config.SourceAccountID != preview.Request.SourceAccountID {
		return reject("EVIDENCE_INVALID", nil)
	}
	want := nativePaymentEffect(preview.ID, preview.Resources, preview.Liability.Original, preview.ExpiresAt)
	left, e := encode(want)
	right, e2 := encode(preview.BankEffect)
	effect, e3 := want.Digest()
	if e != nil || e2 != nil || e3 != nil || !templateSameBytes(left, right) || effect != preview.EffectHash {
		return reject("EVIDENCE_INVALID", nil)
	}
	before, e := planning.Forecast365(preview.ForecastInput)
	if e != nil {
		return reject("EVIDENCE_INVALID", e)
	}
	afterInput, e := nativePaymentPreviewAfter(preview.ForecastInput, preview, amount)
	if e != nil {
		return reject("EVIDENCE_INVALID", e)
	}
	after, e := planning.Forecast365(afterInput)
	if e != nil {
		return reject("EVIDENCE_INVALID", e)
	}
	left, _ = encode(before)
	right, _ = encode(preview.ForecastBefore)
	if !templateSameBytes(left, right) {
		return reject("EVIDENCE_INVALID", nil)
	}
	left, _ = encode(after)
	right, _ = encode(preview.ForecastAfter)
	if !templateSameBytes(left, right) {
		return reject("EVIDENCE_INVALID", nil)
	}
	if e = nativePaymentMargins(before, after); e != nil {
		return e
	}
	hash, e := NativePaymentReviewHash(preview)
	if e != nil || hash != preview.ReviewedHash {
		return reject("EVIDENCE_INVALID", e)
	}
	return nil
}

// PreviewNativePayment reads the independent final liability before opening its
// local RR snapshot. The persisted original contains an effect, not a fabricated
// USER confirmation or bank request.
func (s *Service) PreviewNativePayment(ctx context.Context, p Principal, in NativePaymentRequest) (NativePaymentPreview, error) {
	var out NativePaymentPreview
	if e := s.auditHuman(ctx, p); e != nil {
		return out, e
	}
	if in.PolicyVersionID == (funds.ID{}) || in.SourceAccountID == (funds.ID{}) || len(in.ObligationID) < 1 || len(in.ObligationID) > 128 {
		return out, reject("PAYMENT_REQUEST_INVALID", nil)
	}
	reader, ok := s.NativeBank.(nativePaymentBankReader)
	if !ok {
		return out, reject("BANK_UNAVAILABLE", nil)
	}
	bank, e := reader.Liabilities(ctx, s.Namespace, p.UserID.String())
	if e != nil {
		return out, reject("BANK_UNAVAILABLE", e)
	}
	now := s.now()
	if bank.Validate() != nil || bank.Namespace != s.Namespace || bank.UserID != p.UserID.String() || bank.CapturedAt.After(now.Add(time.Second)) || now.Sub(bank.CapturedAt) > 30*time.Second {
		return out, reject("BANK_SNAPSHOT_STALE", nil)
	}
	tx, e := s.Pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	if e != nil {
		return out, e
	}
	defer rollback(ctx, tx)
	if e = s.human(ctx, tx, p); e != nil {
		return out, e
	}
	zone, e := templateScopedTimezone(ctx, tx, p, in.Timezone)
	if e != nil {
		return out, e
	}
	in.Timezone = zone
	snapshot, e := s.loadTemplateSnapshot(ctx, tx, p, now, zone)
	if e != nil {
		return out, e
	}
	id, e := newID()
	if e != nil {
		return out, e
	}
	expires := now.Add(2 * time.Minute)
	location, _ := policy.TemplateLocation(zone)
	local := now.In(location)
	midnight := time.Date(local.Year(), local.Month(), local.Day()+1, 0, 0, 0, 0, location)
	if midnight.Before(expires) {
		expires = midnight.UTC()
	}
	out, e = buildNativePaymentPreview(snapshot, in, bank, now, expires, id)
	if e != nil {
		return out, e
	}
	out.SessionID = p.SessionID
	out.ReviewedHash, e = NativePaymentReviewHash(out)
	if e != nil {
		return out, e
	}
	raw, e := encode(out)
	if e != nil {
		return out, e
	}
	if e = tx.Commit(ctx); e != nil {
		return out, e
	}
	if e = s.saveNativeActionPreview(ctx, s.Pool, p, out.NativeActionPreviewHeader, raw); e != nil {
		return out, e
	}
	return out, nil
}
func loadNativePaymentPreview(ctx context.Context, q queryRow, p Principal, id funds.ID) (NativePaymentPreview, error) {
	var out NativePaymentPreview
	_, raw, e := loadNativeActionPreview(ctx, q, p, bankv2.Payment, id)
	if e != nil {
		return out, e
	}
	if auditJSON(raw, &out) != nil {
		return out, reject("EVIDENCE_INVALID", nil)
	}
	if e = replayNativePaymentPreview(out); e != nil {
		return out, e
	}
	return out, nil
}
func (s *Service) NativePaymentPreview(ctx context.Context, p Principal, id funds.ID) (NativePaymentPreview, error) {
	if e := s.auditHuman(ctx, p); e != nil {
		return NativePaymentPreview{}, e
	}
	return loadNativePaymentPreview(ctx, s.Pool, p, id)
}

// Builds deterministic economics from a caller-owned snapshot. It authenticates
// nobody, persists nothing and creates no consent. SYSTEM standing callers keep
// SessionID zero and prove a separate original USER grant.
func buildNativePaymentPreview(snapshot templateSnapshot, in NativePaymentRequest, bank bankv2.LiabilitySnapshot, now, expires time.Time, id funds.ID) (NativePaymentPreview, error) {
	var out NativePaymentPreview
	var view *TemplatePolicyView
	for i := range snapshot.Views {
		if snapshot.Views[i].Version.VersionID == in.PolicyVersionID {
			if view != nil {
				return out, reject("EVIDENCE_INVALID", nil)
			}
			view = &snapshot.Views[i]
		}
	}
	if view == nil {
		return out, reject("PAYMENT_RULE_INVALID", nil)
	}
	var debt *planning.ForecastObligation
	for i := range snapshot.Retained {
		if snapshot.Retained[i].ID == in.ObligationID {
			if debt != nil {
				return out, reject("EVIDENCE_INVALID", nil)
			}
			debt = &snapshot.Retained[i]
		}
	}
	if debt == nil {
		return out, reject("PAYMENT_DEBT_NOT_ADOPTED", nil)
	}
	var liability *bankv2.LiabilityState
	for i := range bank.Liabilities {
		if bank.Liabilities[i].Original.ID == in.ObligationID {
			liability = &bank.Liabilities[i]
		}
	}
	if liability == nil {
		return out, reject("PAYMENT_BANK_ORIGINAL_REQUIRED", nil)
	}
	if snapshot.Native == nil {
		return out, reject("NATIVE_STORAGE_REQUIRED", nil)
	}
	// An unresolved original payment owns this liability. Its independently
	// paid counter may already have advanced after a lost response; recover the
	// original before attempting to interpret a replacement amount.
	for _, hold := range snapshot.Native.Holds {
		if hold.ResourceKind == "LIABILITY" && hold.ResourceID == debt.ID && hold.State == funds.Reserved {
			return out, reject("PAYMENT_OPERATION_PENDING", nil)
		}
	}
	base := NativePaymentPreview{Policy: *view, Debt: *debt, Liability: *liability, Request: in, Timezone: in.Timezone}
	if liability.Original.Kind == "BILL" {
		proof, e := nativeBillProofForDebt(snapshot, *debt)
		if e != nil {
			return out, e
		}
		base.BillProof = &proof
	} else if liability.Original.Kind == "OCCURRENCE" {
		proof, e := nativePaymentAdoptionProofForDebt(snapshot, *debt)
		if e != nil {
			return out, e
		}
		base.AdoptionProof = &proof
	}
	amount, e := nativePaymentPreviewAmount(base, now)
	if e != nil {
		return out, e
	}
	resources, e := selectNativeUnownedCash(*snapshot.Native, []funds.ID{in.SourceAccountID}, amount)
	if e != nil || resources.Amount != amount {
		return out, reject("FUNDS_UNAVAILABLE", e)
	}
	beforeInput := snapshot.forecastInput(365)
	before, e := planning.Forecast365(beforeInput)
	if e != nil {
		return out, e
	}
	afterInput, e := nativePaymentPreviewAfter(beforeInput, base, amount)
	if e != nil {
		return out, e
	}
	after, e := planning.Forecast365(afterInput)
	if e != nil {
		return out, e
	}
	if e = nativePaymentMargins(before, after); e != nil {
		return out, e
	}
	effect := nativePaymentEffect(id, resources, liability.Original, expires)
	effectHash, e := effect.Digest()
	if e != nil {
		return out, reject("PAYMENT_EFFECT_INVALID", e)
	}
	deps := planning.DependencyVector{FundsVersion: snapshot.FundsVersion, PolicyVersion: view.Version.Version, ProductTermsVersion: 1, ProductAvailabilityVersion: 1, SourceEvidenceVersion: snapshot.SourceVersion, WriterGeneration: snapshot.WriterGeneration, ControlVersion: snapshot.ControlVersion}
	out = NativePaymentPreview{NativeActionPreviewHeader: NativeActionPreviewHeader{ID: id, Scope: snapshot.Facts.Scope, Kind: bankv2.Payment, EffectHash: effectHash, Dependencies: deps, SourceHash: snapshot.Facts.SourceHash, InventoryHash: Hash(snapshot.InventoryRaw), CreatedAt: now, ExpiresAt: expires}, Protocol: "native-payment-preview-v1", Timezone: in.Timezone, Request: in, Policy: *view, Debt: *debt, Liability: *liability, BankEffect: effect, Resources: resources, ForecastInput: beforeInput, ForecastBefore: before, ForecastAfter: after}
	out.Ledger, out.InventoryOriginal = captureNativeAssetLedger(*snapshot.Native), snapshot.InventoryRaw
	out.BillProof = base.BillProof
	out.AdoptionProof = base.AdoptionProof
	out.ReviewedHash, e = NativePaymentReviewHash(out)
	if e != nil {
		return out, e
	}
	if e = replayNativePaymentPreview(out); e != nil {
		return out, e
	}
	return out, nil
}
