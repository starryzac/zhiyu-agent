package app

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"strconv"
	"time"

	"github.com/jackc/pgx/v5"
	"zhiyu.local/zhiyu-go/internal/adapters/postgres"
	"zhiyu.local/zhiyu-go/internal/execution/bankv2"
	funds "zhiyu.local/zhiyu-go/internal/funds/domain"
	planning "zhiyu.local/zhiyu-go/internal/planning/domain"
	policy "zhiyu.local/zhiyu-go/internal/policy/domain"
)

const NativeAssetProtocol = "native-asset-action-v1"

type NativeAssetRequest struct {
	Kind            bankv2.Kind `json:"kind"`
	PolicyVersionID funds.ID    `json:"policy_version_id"`
	ProductID       string      `json:"product_id,omitempty"`
	PositionID      string      `json:"position_id,omitempty"`
	// Amount is a USER upper bound. The server computes the actual amount.
	Amount   funds.Money `json:"amount_cents"`
	Timezone string      `json:"timezone"`
}
type NativeAssetCommand struct {
	PreviewID    funds.ID `json:"preview_id"`
	ReviewedHash string   `json:"reviewed_hash"`
	CostReviewed bool     `json:"cost_reviewed"`
}
type NativeAssetPreview struct {
	NativeActionPreviewHeader
	Protocol          string                   `json:"protocol"`
	Timezone          string                   `json:"timezone"`
	Request           NativeAssetRequest       `json:"request"`
	Policy            TemplatePolicyView       `json:"policy"`
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
	ForecastBefore    planning.ForecastResult  `json:"forecast_before"`
	ForecastAfter     planning.ForecastResult  `json:"forecast_after"`
	RecoveryTrigger   string                   `json:"recovery_trigger,omitempty"`
	ReviewedHash      string                   `json:"reviewed_hash"`
}
type nativeAssetBankReader interface {
	CurrentState(context.Context, string, string) (bankv2.CurrentState, error)
	Quote(context.Context, string, string, string, bankv2.Kind) (bankv2.Quote, error)
}

func nativeAssetKind(kind bankv2.Kind) bool {
	return kind == bankv2.Purchase || kind == bankv2.Redeem || kind == bankv2.Mature
}
func NativeAssetReviewHash(preview NativeAssetPreview) (string, error) {
	_, hash, err := nativeAssetReviewBody(preview)
	return hash, err
}
func nativeAssetObjectID(namespace, kind, id string) funds.ID {
	h := sha256.Sum256([]byte("native-asset-object-v1\x00" + namespace + "\x00" + kind + "\x00" + id))
	var out funds.ID
	copy(out[:], h[:16])
	out[6] = (out[6] & 15) | 80
	out[8] = (out[8] & 63) | 128
	return out
}
func nativeAssetClass(terms bankv2.ProductTerms) string {
	if terms.AssetClass != "FIXED_DEPOSIT" {
		return terms.AssetClass
	}
	switch terms.TermDays {
	case 7:
		return "FIXED_DEPOSIT_7D"
	case 30:
		return "FIXED_DEPOSIT_30D"
	case 90:
		return "FIXED_DEPOSIT_90D"
	}
	return "LOW_RISK_TERM"
}
func nativeAssetSameGoal(a *funds.ID, b string) bool {
	return a == nil && b == "" || a != nil && a.String() == b
}

func nativeAssetState(n postgres.NativeLedger, state bankv2.CurrentState, scope policy.TemplateOwnerScope) error {
	if state.Protocol != bankv2.Protocol || state.Namespace != n.Namespace || state.UserID != scope.UserID.String() || state.CapturedAt.IsZero() || len(state.Products) > 100 || len(state.Positions) > 10000 || len(state.Accounts) != len(n.Accounts) {
		return reject("ASSET_BANK_STATE_INVALID", nil)
	}
	accounts := map[string]postgres.NativeAccount{}
	for _, a := range n.Accounts {
		accounts[a.ID.String()] = a
	}
	for _, a := range state.Accounts {
		local, ok := accounts[a.ID]
		if !ok || local.Balance != a.Balance {
			return reject("ASSET_BANK_STATE_CHANGED", nil)
		}
		delete(accounts, a.ID)
	}
	positions := map[string]postgres.NativePosition{}
	for _, p := range n.Positions {
		positions[p.ID] = p
	}
	if len(positions) != len(state.Positions) {
		return reject("ASSET_BANK_STATE_CHANGED", nil)
	}
	for _, p := range state.Positions {
		local, ok := positions[p.Opening.PositionID]
		h, e := p.Opening.Digest()
		if !ok || e != nil || h != p.OpeningHash || h != local.OriginalHash || local.Closed != p.Closed || p.Opening.Namespace != n.Namespace || p.Opening.UserID != scope.UserID.String() {
			return reject("ASSET_BANK_STATE_CHANGED", e)
		}
		delete(positions, p.Opening.PositionID)
	}
	products := map[string]bool{}
	for _, p := range state.Products {
		if products[p.Terms.ProductID] || p.Validate() != nil {
			return reject("ASSET_BANK_STATE_INVALID", nil)
		}
		products[p.Terms.ProductID] = true
	}
	goals := map[string]postgres.NativeGoalBalance{}
	for _, g := range n.Goals {
		goals[g.GoalID.String()] = g
	}
	for _, g := range state.Goals {
		local, ok := goals[g.ID]
		if !ok || local.AccountID.String() != g.AccountID || local.Cash != g.Cash || local.Principal != g.Principal || local.Loss != g.Loss {
			return reject("ASSET_BANK_STATE_CHANGED", nil)
		}
		delete(goals, g.ID)
	}
	for _, g := range goals {
		if !g.Cash.IsZero() || !g.Principal.IsZero() || !g.Loss.IsZero() {
			return reject("ASSET_BANK_STATE_CHANGED", nil)
		}
	}
	return nil
}

func assetPendingPurchases(ctx context.Context, tx pgx.Tx, p Principal, namespace string) ([]bankv2.Request, error) {
	rows, e := tx.Query(ctx, `SELECT bank_request,bank_request_hash::text FROM native_operations WHERE environment_id=$1 AND user_id=$2 AND command_kind='PURCHASE_ASSET' AND status NOT IN ('SETTLED','REJECTED','CANCELLED') ORDER BY id LIMIT 10001`, p.EnvironmentID.String(), p.UserID.String())
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	out := []bankv2.Request{}
	for rows.Next() {
		if len(out) >= 10000 {
			return nil, reject("ASSET_CAPACITY", nil)
		}
		var raw []byte
		var hash string
		if e = rows.Scan(&raw, &hash); e != nil {
			return nil, e
		}
		var r bankv2.Request
		if decode(raw, &r) != nil {
			return nil, reject("EVIDENCE_INVALID", nil)
		}
		h, he := r.Digest()
		if he != nil || h != hash || r.Namespace != namespace || r.UserID != p.UserID.String() || r.Effect.Kind != bankv2.Purchase {
			return nil, reject("EVIDENCE_INVALID", he)
		}
		out = append(out, r)
	}
	return out, rows.Err()
}
func nativeAssetManaged(n postgres.NativeLedger, pending []bankv2.Request, goal *funds.ID) (funds.Money, error) {
	var total funds.Money
	for _, p := range n.Positions {
		if p.Closed || !nativeAssetSameGoal(goal, func() string {
			if p.GoalID == nil {
				return ""
			}
			return p.GoalID.String()
		}()) {
			continue
		}
		var e error
		total, e = total.Add(p.Principal)
		if e != nil {
			return funds.Money{}, e
		}
	}
	for _, p := range pending {
		if !nativeAssetSameGoal(goal, p.Effect.SourceGoalID) {
			continue
		}
		var e error
		total, e = total.Add(p.Effect.Amount)
		if e != nil {
			return funds.Money{}, e
		}
	}
	return total, nil
}
func nativeAssetExpiry(now time.Time, tz string, version policy.TemplateVersion, quote *bankv2.Quote, product *bankv2.ProductSnapshot) (time.Time, error) {
	end := now.Add(2 * time.Minute)
	zone, e := policy.TemplateLocation(tz)
	if e != nil {
		return end, e
	}
	local := now.In(zone)
	midnight := time.Date(local.Year(), local.Month(), local.Day()+1, 0, 0, 0, 0, zone).UTC()
	if midnight.Before(end) {
		end = midnight
	}
	_, validUntil, e := policy.TemplateValidity(version.Compiled, version.ConfirmedAt, tz)
	if e != nil {
		return end, e
	}
	if validUntil != nil && validUntil.Before(end) {
		end = *validUntil
	}
	if quote != nil && quote.ExpiresAt.Before(end) {
		end = quote.ExpiresAt
	}
	if product != nil && product.Availability.EffectiveUntil.Before(end) {
		end = product.Availability.EffectiveUntil
	}
	if !end.After(now) {
		return end, reject("AUTHORIZATION_EXPIRED", nil)
	}
	return end, nil
}

// A purchase is checked conservatively without crediting its planned return.
// Existing principal is not cash, and an unsubmitted candidate cannot supply a
// trusted principal-return fact. Closing adds only the independently quoted net.
func nativeAssetCounterfactual(in planning.ForecastInput, effect bankv2.Effect) (planning.ForecastInput, error) {
	var after planning.ForecastInput
	raw, e := encode(in)
	if e != nil || decode(raw, &after) != nil {
		return after, reject("EVIDENCE_INVALID", e)
	}
	for _, use := range effect.CashUses {
		found := false
		for i := range after.Facts.Accounts {
			a := &after.Facts.Accounts[i]
			if a.ID.String() != use.AccountID {
				continue
			}
			a.Balance, e = a.Balance.Sub(use.Amount)
			if e != nil {
				return after, e
			}
			found = true
		}
		if !found {
			return after, nativeResourceConflict()
		}
	}
	if effect.Kind == bankv2.Purchase {
		after.Facts.CurrentCash, e = after.Facts.CurrentCash.Sub(effect.Amount)
	} else {
		after.Facts.CurrentCash, e = after.Facts.CurrentCash.Add(effect.Net)
		found := false
		for i := range after.Facts.Accounts {
			a := &after.Facts.Accounts[i]
			if a.ID.String() == effect.ReturnAccountID {
				a.Balance, e = a.Balance.Add(effect.Net)
				found = true
			}
		}
		if !found {
			return after, nativeResourceConflict()
		}
	}
	if e != nil {
		return after, e
	}
	if effect.SourceGoalID != "" {
		found := false
		for i := range after.Facts.Goals {
			g := &after.Facts.Goals[i]
			if g.ID.String() != effect.SourceGoalID {
				continue
			}
			found = true
			if effect.Kind == bankv2.Purchase {
				g.CashOwned, e = g.CashOwned.Sub(effect.Amount)
			} else {
				principal, pe := g.Owned.Sub(g.CashOwned)
				if pe != nil || principal.Cents() < effect.Amount.Cents() {
					return after, nativeResourceConflict()
				}
				_, e = principal.Sub(effect.Amount)
				if e == nil {
					g.CashOwned, e = g.CashOwned.Add(effect.Net)
				}
				if e == nil {
					cost, _ := effect.Fee.Add(effect.Loss)
					g.Owned, e = g.Owned.Sub(cost)
				}
			}
			if e != nil {
				return after, e
			}
		}
		if !found {
			return after, nativeResourceConflict()
		}
	}
	return after, nil
}

func deriveNativeAssetPreview(snapshot templateSnapshot, in NativeAssetRequest, id, session funds.ID, state bankv2.CurrentState, quote *bankv2.Quote, pending []bankv2.Request, expiryCap ...time.Time) (NativeAssetPreview, error) {
	return deriveNativeAssetPreviewWithSource(snapshot, in, id, session, state, quote, pending, nil, expiryCap...)
}

func deriveNativeAssetPreviewWithSource(snapshot templateSnapshot, in NativeAssetRequest, id, session funds.ID, state bankv2.CurrentState, quote *bankv2.Quote, pending []bankv2.Request, source *nativeStandingAssetSource, expiryCap ...time.Time) (NativeAssetPreview, error) {
	return deriveNativeAssetPreviewWithSourceForecast(planning.Forecast365, snapshot, in, id, session, state, quote, pending, source, expiryCap...)
}

func deriveNativeAssetPreviewWithSourceForecast(forecast nativeAssetForecast, snapshot templateSnapshot, in NativeAssetRequest, id, session funds.ID, state bankv2.CurrentState, quote *bankv2.Quote, pending []bankv2.Request, source *nativeStandingAssetSource, expiryCap ...time.Time) (NativeAssetPreview, error) {
	return deriveNativeAssetPreviewWithReplayBody(forecast, nil, snapshot, in, id, session, state, quote, pending, source, expiryCap...)
}

func deriveNativeAssetPreviewWithReplayBody(forecast nativeAssetForecast, capture *nativeAssetReviewCapture, snapshot templateSnapshot, in NativeAssetRequest, id, session funds.ID, state bankv2.CurrentState, quote *bankv2.Quote, pending []bankv2.Request, source *nativeStandingAssetSource, expiryCap ...time.Time) (NativeAssetPreview, error) {
	var out NativeAssetPreview
	if snapshot.Native == nil || !nativeAssetKind(in.Kind) || in.PolicyVersionID == (funds.ID{}) {
		return out, reject("INVALID_NATIVE_ASSET", nil)
	}
	if e := nativeAssetState(*snapshot.Native, state, snapshot.Facts.Scope); e != nil {
		return out, e
	}
	if source != nil {
		if in.Kind != bankv2.Purchase || session != (funds.ID{}) {
			return out, reject("INVALID_NATIVE_ASSET", nil)
		}
		if e := source.validate(*snapshot.Native, snapshot.AsOf); e != nil {
			return out, e
		}
	}
	var view TemplatePolicyView
	for _, v := range snapshot.Views {
		if v.Version.VersionID == in.PolicyVersionID {
			view = v
		}
	}
	if active, e := view.Version.EffectiveState(snapshot.AsOf, snapshot.Timezone); e != nil || active != "ACTIVE" {
		return out, reject("ASSET_POLICY_NOT_ACTIVE", e)
	}
	decoded, e := view.Version.Compiled.Decode()
	if e != nil {
		return out, reject("ASSET_POLICY_REQUIRED", e)
	}
	forecastInput := snapshot.forecastInput(365)
	before, e := forecast(forecastInput)
	if e != nil {
		return out, reject("ASSET_PROTECTION_INCOMPLETE", e)
	}
	effect := bankv2.Effect{Kind: in.Kind, BusinessKey: "asset:" + id.String(), CashUses: []bankv2.CashUse{}, OriginUses: []bankv2.OriginUse{}, ReturnUses: []bankv2.ReturnUse{}}
	var cash NativeCashResources
	goalUses := []NativeGoalTransferUse{}
	var original *bankv2.PositionOpening
	trigger := ""
	var purchaseUseLimit time.Time
	if in.Kind == bankv2.Purchase {
		config, ok := decoded.(*policy.AssetAuthorizationConfig)
		if !ok || in.ProductID == "" || in.PositionID != "" || in.Amount.IsZero() || quote != nil {
			return out, reject("ASSET_POLICY_REQUIRED", nil)
		}
		var product *bankv2.ProductSnapshot
		for _, p := range state.Products {
			if p.Terms.ProductID == in.ProductID {
				copy := p
				product = &copy
			}
		}
		if product == nil || product.Availability.Status != "AVAILABLE" || snapshot.AsOf.Before(product.Availability.EffectiveFrom) || !snapshot.AsOf.Before(product.Availability.EffectiveUntil) {
			return out, reject("ASSET_PRODUCT_UNAVAILABLE", nil)
		}
		facts := snapshot.Facts
		facts.Goals = append([]policy.TemplateGoalFact(nil), facts.Goals...)
		facts.CurrentSafe, facts.CurrentSafeVerified = before.CurrentSafe, true
		facts.Products = []policy.TemplateAssetProductFact{}
		facts.ManagedAmount, e = nativeAssetManaged(*snapshot.Native, pending, config.GoalID)
		if e != nil {
			return out, e
		}
		zone, _ := policy.TemplateLocation(snapshot.Timezone)
		useDate := snapshot.AsOf.In(zone).AddDate(0, 0, 365).Format("2006-01-02")
		if config.GoalID != nil {
			found := false
			for i := range facts.Goals {
				g := &facts.Goals[i]
				if g.ID != *config.GoalID {
					continue
				}
				found = true
				g.ScopeAvailable = g.CashOwned
				for _, h := range snapshot.Native.Holds {
					if h.ResourceKind == "GOAL" && h.ResourceID == g.ID.String() && h.State == funds.Reserved {
						g.ScopeAvailable, e = g.ScopeAvailable.Sub(h.Amount)
						if e != nil {
							return out, nativeResourceConflict()
						}
					}
				}
				if g.GoalVersion == nil {
					return out, reject("ASSET_GOAL_POLICY_REQUIRED", nil)
				}
				c, ce := g.GoalVersion.Compiled.Decode()
				if ce != nil {
					return out, ce
				}
				long, ok := c.(*policy.LongTermGoalConfig)
				if !ok {
					return out, reject("ASSET_GOAL_POLICY_REQUIRED", nil)
				}
				if long.Deadline < useDate {
					useDate = long.Deadline
				}
			}
			if !found {
				return out, reject("ASSET_GOAL_POLICY_REQUIRED", nil)
			}
		}
		facts.AssetUseDate = useDate
		useDay, _ := policy.TemplateDate(useDate)
		purchaseUseLimit = time.Date(useDay.Year(), useDay.Month(), useDay.Day(), 0, 0, 0, 0, zone)
		for _, p := range state.Products {
			kind, accrual := "PLANNED_REDEMPTION", "UNTIL_REDEMPTION_REQUEST"
			if p.Terms.AssetClass == "FIXED_DEPOSIT" {
				kind, accrual = "FIXED_MATURITY", "UNTIL_MATURITY"
			}
			facts.Products = append(facts.Products, policy.TemplateAssetProductFact{ID: nativeAssetObjectID(state.Namespace, "product", p.Terms.ProductID), AssetClass: nativeAssetClass(p.Terms), Minimum: p.Terms.MinimumPurchase, LockDays: p.Terms.LockDays, RedemptionDelayDays: p.Terms.RedemptionDelayDays, AutoPurchaseAllowed: p.Availability.Status == "AVAILABLE", AutoRedeemAllowed: p.Terms.RedemptionFeeBPS == 0 && p.Terms.EarlyLossBPS == 0, Current: !snapshot.AsOf.Before(p.Availability.EffectiveFrom) && snapshot.AsOf.Before(p.Availability.EffectiveUntil), TermsVerified: true, TermsHash: p.TermsHash, ReturnKind: kind, TermDays: p.Terms.TermDays, TermsSettlementDelayDays: p.Terms.RedemptionDelayDays, Accrual: accrual})
		}
		pure, pe := policy.PreviewTemplate(view.Version, facts, snapshot.AsOf, snapshot.Timezone)
		if pe != nil {
			return out, reject("ASSET_POLICY_REJECTED", pe)
		}
		var budget funds.Money
		for _, candidate := range pure.Candidates {
			if candidate.SubjectID == nativeAssetObjectID(state.Namespace, "product", in.ProductID) && candidate.Kind == "ASSET_PURCHASE_CONSTRAINT" {
				budget = candidate.AmountCap
			}
		}
		budget = nativeResourceMinimum(budget, in.Amount)
		if source != nil {
			var available funds.Money
			if config.GoalID == nil {
				selected, e := selectStandingAssetCash(*snapshot.Native, *source, budget)
				if e != nil {
					return out, e
				}
				available = selected.Amount
			} else {
				available, e = standingAssetGoalAmount(*snapshot.Native, *source, *config.GoalID)
				if e != nil {
					return out, e
				}
			}
			budget = nativeResourceMinimum(budget, available)
		}
		if config.GoalID == nil {
			for _, point := range before.Points {
				margin, me := strconv.ParseInt(point.MarginCents, 10, 64)
				if me != nil || margin < 0 {
					return out, reject("ASSET_NO_SAFE_PURCHASE", me)
				}
				bound, _ := funds.NewMoney(margin)
				budget = nativeResourceMinimum(budget, bound)
			}
		}
		if budget.IsZero() {
			return out, reject("ASSET_NO_SAFE_PURCHASE", nil)
		}
		if config.GoalID == nil {
			if source == nil {
				cash, e = selectNativeUnownedCash(*snapshot.Native, nil, budget)
			} else {
				cash, e = selectStandingAssetCash(*snapshot.Native, *source, budget)
			}
			if e != nil {
				return out, e
			}
			effect.Amount = cash.Amount
			effect.CashUses = cash.CashUses
			effect.OriginUses = nativeCashOriginUses(cash)
			effect.ReturnUses = append([]bankv2.ReturnUse{}, cash.ReturnUses...)
		} else {
			effect.Amount = budget
			effect.SourceGoalID = config.GoalID.String()
			for _, g := range facts.Goals {
				if g.ID == *config.GoalID {
					effect.CashUses = []bankv2.CashUse{{AccountID: g.AccountID.String(), Amount: budget}}
					if source == nil {
						goalUses, e = goalTransferLotUses(*snapshot.Native, g.ID, g.AccountID, budget)
					} else {
						goalUses, e = goalTransferLotUsesMatching(*snapshot.Native, g.ID, g.AccountID, budget, source.lot)
					}
					if e != nil {
						return out, e
					}
					for _, u := range goalUses {
						if u.SourceKind == "INCOME" {
							effect.OriginUses = append(effect.OriginUses, bankv2.OriginUse{OriginID: u.SourceID, AccountID: g.AccountID.String(), Amount: u.Amount, Bucket: "ASSIGNED_GOAL"})
						} else {
							effect.ReturnUses = append(effect.ReturnUses, bankv2.ReturnUse{OperationKey: u.SourceID, PositionID: u.PositionID, AccountID: g.AccountID.String(), Amount: u.Amount})
						}
					}
				}
			}
		}
		if effect.Amount.Cents() < product.Terms.MinimumPurchase.Cents() || len(effect.CashUses) == 0 {
			return out, reject("ASSET_BELOW_MINIMUM", nil)
		}
		effect.Product = product
		effect.PositionID = "position:" + id.String()
		effect.ReturnAccountID = effect.CashUses[0].AccountID
		if product.Terms.AssetClass == "FIXED_DEPOSIT" {
			effect.PrincipalAvailableBy = snapshot.AsOf.UTC().AddDate(0, 0, product.Terms.TermDays+product.Terms.RedemptionDelayDays)
		} else {
			date, _ := policy.TemplateDate(useDate)
			limit := time.Date(date.Year(), date.Month(), date.Day(), 0, 0, 0, 0, zone)
			effect.PrincipalAvailableBy = limit
			effect.PlannedRedeemAt = limit.AddDate(0, 0, -product.Terms.RedemptionDelayDays)
		}
	} else {
		if in.ProductID != "" || in.PositionID == "" || quote == nil || quote.Validate() != nil || quote.Namespace != state.Namespace || quote.UserID != state.UserID || quote.Kind != in.Kind || quote.PositionID != in.PositionID || snapshot.AsOf.Before(quote.RequestedAt) || !snapshot.AsOf.Before(quote.ExpiresAt) {
			return out, reject("ASSET_QUOTE_INVALID", nil)
		}
		var local *postgres.NativePosition
		for _, p := range snapshot.Native.Positions {
			if p.ID == in.PositionID {
				copy := p
				local = &copy
			}
		}
		if local == nil || local.Closed || local.ClosingOperationID != nil || local.OriginalHash != quote.PositionOpeningHash || decode(local.Original, &original) != nil || original == nil {
			return out, reject("ASSET_POSITION_UNAVAILABLE", nil)
		}
		h, he := original.Digest()
		if he != nil || h != quote.PositionOpeningHash || original.Principal != quote.Principal || original.TermsHash != quote.Product.TermsHash || original.ReturnAccountID != local.ReturnAccountID.String() {
			return out, reject("ASSET_QUOTE_INVALID", he)
		}
		net, fee, loss, available, qe := bankv2.RedemptionQuote(original.Principal, original.Terms, original.PurchasedAt, quote.RequestedAt, in.Kind == bankv2.Mature)
		if qe != nil || net != quote.Net || fee != quote.Fee || loss != quote.Loss || !available.Equal(quote.AvailableAt) {
			return out, reject("ASSET_QUOTE_INVALID", qe)
		}
		if !in.Amount.IsZero() && in.Amount.Cents() < original.Principal.Cents() {
			return out, reject("ASSET_FULL_POSITION_REQUIRED", nil)
		}
		switch config := decoded.(type) {
		case *policy.AssetAuthorizationConfig:
			if view.Version.PolicyID.String() != original.SourceAuthority.PolicyID || !nativeAssetSameGoal(config.GoalID, original.GoalID) || config.SingleActionCap.Cents() < original.Principal.Cents() || config.MaxRedemptionDelayDays < original.Terms.RedemptionDelayDays {
				return out, reject("ASSET_CLOSE_NOT_AUTHORIZED", nil)
			}
			allowed := false
			for _, class := range config.AllowedAssetClasses {
				if class == nativeAssetClass(original.Terms) {
					allowed = true
				}
			}
			if !allowed || (!fee.IsZero() || !loss.IsZero()) && !config.AllowEarlyWithdrawalWithPenalty {
				return out, reject("ASSET_COST_NOT_AUTHORIZED", nil)
			}
		case *policy.RecoveryConfig:
			if config.AssetPolicyID.String() != original.SourceAuthority.PolicyID || !nativeAssetSameGoal(config.GoalID, original.GoalID) || config.SingleActionCap.Cents() < original.Principal.Cents() || config.MaxRedemptionDelayDays < original.Terms.RedemptionDelayDays || !fee.IsZero() || !loss.IsZero() {
				return out, reject("ASSET_CLOSE_NOT_AUTHORIZED", nil)
			}
			if !before.MaximumDeficit.IsZero() {
				trigger = "LIQUIDITY_SHORTFALL"
			}
			for _, v := range snapshot.Views {
				if v.Version.PolicyID == config.AssetPolicyID {
					if v.EffectiveState == "REVOKED" {
						trigger = "AUTHORIZATION_REVOKED"
					}
					if v.EffectiveState == "EXPIRED" {
						trigger = "POLICY_EXPIRED"
					}
				}
			}
			allowed := false
			for _, value := range config.Triggers {
				if value == trigger {
					allowed = true
				}
			}
			if !allowed {
				return out, reject("ASSET_RECOVERY_NOT_TRIGGERED", nil)
			}
		default:
			return out, reject("ASSET_POLICY_REQUIRED", nil)
		}
		effect.Amount, effect.Product, effect.PositionID, effect.PositionOpeningHash = original.Principal, &quote.Product, original.PositionID, local.OriginalHash
		effect.ReturnAccountID, effect.DestinationAccountID = original.ReturnAccountID, original.ReturnAccountID
		effect.SourceGoalID = original.GoalID
		effect.Net, effect.Fee, effect.Loss, effect.QuoteID = quote.Net, quote.Fee, quote.Loss, quote.ID
	}
	expires, e := nativeAssetExpiry(snapshot.AsOf, snapshot.Timezone, view.Version, quote, func() *bankv2.ProductSnapshot {
		if in.Kind == bankv2.Purchase {
			return effect.Product
		}
		return nil
	}())
	if e != nil {
		return out, e
	}
	if len(expiryCap) > 1 {
		return out, reject("INVALID_NATIVE_ASSET", nil)
	}
	if len(expiryCap) == 1 && expiryCap[0].Before(expires) {
		expires = expiryCap[0]
	}
	if !expires.After(snapshot.AsOf) {
		return out, reject("AUTHORIZATION_EXPIRED", nil)
	}
	effect.LatestArrivalAt = expires
	if in.Kind == bankv2.Purchase && effect.Product.Terms.AssetClass == "FIXED_DEPOSIT" {
		// Acceptance can occur at any instant strictly before the pinned expiry.
		// The promise therefore includes that whole interval, not preview time.
		effect.PrincipalAvailableBy = expires.UTC().AddDate(0, 0, effect.Product.Terms.TermDays+effect.Product.Terms.RedemptionDelayDays)
	}
	if in.Kind == bankv2.Purchase {
		if effect.PrincipalAvailableBy.After(purchaseUseLimit) || effect.Product.Terms.AssetClass != "FIXED_DEPOSIT" && effect.PlannedRedeemAt.Before(expires.UTC().AddDate(0, 0, effect.Product.Terms.LockDays)) {
			return out, reject("ASSET_EXIT_AFTER_USE", nil)
		}
	}
	if quote != nil {
		effect.LatestArrivalAt = expires.UTC().AddDate(0, 0, quote.Product.Terms.RedemptionDelayDays)
		if quote.AvailableAt.After(effect.LatestArrivalAt) {
			effect.LatestArrivalAt = quote.AvailableAt
		}
	}
	effectHash, e := effect.Digest()
	if e != nil {
		return out, reject("INVALID_NATIVE_ASSET", e)
	}
	afterInput, e := nativeAssetCounterfactual(forecastInput, effect)
	if e != nil {
		return out, e
	}
	after, e := forecast(afterInput)
	if e != nil {
		return out, reject("ASSET_PROTECTION_INCOMPLETE", e)
	}
	if in.Kind == bankv2.Purchase && !after.MaximumDeficit.IsZero() || in.Kind != bankv2.Purchase && after.MaximumDeficit.Cents() > before.MaximumDeficit.Cents() {
		return out, reject("ASSET_PROTECTION_DEFICIT", nil)
	}
	for _, point := range after.Points {
		if _, e = strconv.ParseInt(point.MarginCents, 10, 64); e != nil {
			return out, e
		}
	}
	deps := planning.DependencyVector{FundsVersion: snapshot.FundsVersion, PolicyVersion: view.Version.Version, ProductTermsVersion: uint64(effect.Product.Terms.Version), ProductAvailabilityVersion: uint64(effect.Product.Availability.Version), SourceEvidenceVersion: snapshot.SourceVersion, WriterGeneration: snapshot.WriterGeneration, ControlVersion: snapshot.ControlVersion}
	in.Timezone = snapshot.Timezone
	out = NativeAssetPreview{NativeActionPreviewHeader: NativeActionPreviewHeader{ID: id, Scope: snapshot.Facts.Scope, SessionID: session, Kind: in.Kind, EffectHash: effectHash, Dependencies: deps, SourceHash: snapshot.Facts.SourceHash, InventoryHash: Hash(snapshot.InventoryRaw), CreatedAt: snapshot.AsOf, ExpiresAt: expires}, Protocol: NativeAssetProtocol, Timezone: snapshot.Timezone, Request: in, Policy: view, Policies: snapshot.Views, Ledger: captureNativeAssetLedger(*snapshot.Native), InventoryOriginal: append([]byte(nil), snapshot.InventoryRaw...), BankState: state, Quote: quote, Position: original, CashResources: cash, GoalUses: goalUses, PendingPurchases: pending, BankEffect: effect, ForecastInput: forecastInput, ForecastBefore: before, ForecastAfter: after, RecoveryTrigger: trigger}
	return finishNativeAssetReview(out, capture)
}

func (s *Service) PreviewNativeAsset(ctx context.Context, p Principal, in NativeAssetRequest) (NativeAssetPreview, error) {
	var out NativeAssetPreview
	if e := s.auditHuman(ctx, p); e != nil {
		return out, e
	}
	reader, ok := s.NativeBank.(nativeAssetBankReader)
	if !ok {
		return out, reject("BANK_UNAVAILABLE", nil)
	}
	// Independent bank I/O never holds the application user/environment locks.
	state, e := reader.CurrentState(ctx, s.Namespace, p.UserID.String())
	if e != nil {
		return out, reject("BANK_UNAVAILABLE", nil)
	}
	var quote *bankv2.Quote
	if in.Kind == bankv2.Redeem || in.Kind == bankv2.Mature {
		q, qe := reader.Quote(ctx, s.Namespace, p.UserID.String(), in.PositionID, in.Kind)
		if qe != nil {
			return out, reject("ASSET_QUOTE_UNAVAILABLE", nil)
		}
		quote = &q
	}
	tx, e := s.Pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	if e != nil {
		return out, e
	}
	defer rollback(ctx, tx)
	tz, e := templateScopedTimezone(ctx, tx, p, in.Timezone)
	if e != nil {
		return out, e
	}
	snapshot, e := s.loadTemplateSnapshot(ctx, tx, p, s.now(), tz)
	if e != nil {
		return out, e
	}
	pending, e := assetPendingPurchases(ctx, tx, p, s.Namespace)
	if e != nil {
		return out, e
	}
	id, e := newID()
	if e != nil {
		return out, e
	}
	out, e = deriveNativeAssetPreview(snapshot, in, id, p.SessionID, state, quote, pending)
	if e != nil {
		return out, e
	}
	if e = tx.Commit(ctx); e != nil {
		return out, e
	}
	raw, e := encode(out)
	if e != nil {
		return out, e
	}
	e = s.saveNativeActionPreview(ctx, s.Pool, p, out.NativeActionPreviewHeader, raw)
	return out, e
}

func loadNativeAssetPreview(ctx context.Context, q queryRow, p Principal, id funds.ID, kind bankv2.Kind) (NativeAssetPreview, error) {
	var out NativeAssetPreview
	header, raw, e := loadNativeActionPreview(ctx, q, p, kind, id)
	if e != nil {
		return out, e
	}
	if decode(raw, &out) != nil || out.NativeActionPreviewHeader != header || out.Protocol != NativeAssetProtocol || !nativeAssetKind(kind) || out.Kind != out.BankEffect.Kind {
		return out, reject("EVIDENCE_INVALID", nil)
	}
	body, h, e := nativeAssetReviewBody(out)
	eh, ee := out.BankEffect.Digest()
	if e != nil || ee != nil || h != out.ReviewedHash || eh != out.EffectHash || out.BankAuthority || out.Policy.Version.Scope != out.Scope || out.ForecastInput.Scope != out.Scope || !out.ForecastInput.AsOf.Equal(out.CreatedAt) || out.ForecastInput.Timezone != out.Timezone || out.Request.Timezone != out.Timezone || out.ForecastInput.Facts.SourceHash != out.SourceHash || out.ForecastInput.InventoryHash != out.InventoryHash {
		return out, reject("EVIDENCE_INVALID", e)
	}
	forecast := newNativeAssetForecastReplay(planning.Forecast365)
	before, e := forecast.evaluate(out.ForecastInput)
	if e != nil {
		return out, e
	}
	afterInput, e := nativeAssetCounterfactual(out.ForecastInput, out.BankEffect)
	if e != nil {
		return out, e
	}
	after, e := forecast.evaluate(afterInput)
	if e != nil {
		return out, e
	}
	if !nativeAssetForecastResultsMatch(before, out.ForecastBefore, after, out.ForecastAfter) {
		return out, reject("EVIDENCE_INVALID", nil)
	}
	// Only this loader owns out: it has just decoded a private original, has
	// made no external call since capture, and uses the fixed pure calculator.
	// This closure cannot escape, accept another preview or inject a callback.
	replayLoaded := func() error {
		snapshot, err := nativeAssetReplaySnapshot(out)
		if err != nil {
			return err
		}
		var capture nativeAssetReviewCapture
		if nativeAssetStreamReviewAvailable && len(body) != 0 && h == out.ReviewedHash {
			capture.stream = newNativeAssetReviewStream(body)
		}
		expected, err := deriveNativeAssetPreviewWithReplayBody(forecast.evaluate, &capture, snapshot, out.Request, out.ID, out.SessionID, out.BankState, out.Quote, out.PendingPurchases, nil, out.ExpiresAt)
		if err != nil {
			return reject("EVIDENCE_INVALID", err)
		}
		if capture.stream != nil && capture.stream.complete && capture.reviewedHash == expected.ReviewedHash {
			if !capture.stream.matches() || capture.reviewedHash != out.ReviewedHash {
				return reject("EVIDENCE_INVALID", nil)
			}
			return nil
		}
		if len(body) == 0 || h != out.ReviewedHash || len(capture.original) == 0 || capture.reviewedHash != expected.ReviewedHash {
			return compareNativeAssetReplayPreview(expected, out, &capture)
		}
		if !bytes.Equal(capture.original, body) || capture.reviewedHash != out.ReviewedHash {
			return reject("EVIDENCE_INVALID", nil)
		}
		return nil
	}
	if e = replayLoaded(); e != nil {
		return out, e
	}
	return out, nil
}

// Retained previews are read-only candidates. Reading one does not assert that
// its policy, bank quote or sources remain current; admission rechecks all.
func (s *Service) NativeAssetPreview(ctx context.Context, p Principal, id funds.ID, kind bankv2.Kind) (NativeAssetPreview, error) {
	if e := s.auditHuman(ctx, p); e != nil {
		return NativeAssetPreview{}, e
	}
	return loadNativeAssetPreview(ctx, s.Pool, p, id, kind)
}
