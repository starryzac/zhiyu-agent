package domain

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"reflect"
	"regexp"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	"zhiyu.local/zhiyu-go/internal/audit"
	funds "zhiyu.local/zhiyu-go/internal/funds/domain"
)

const TemplateProtocol = "policy-templates-go-v1"
const MaxTemplateBytes = 65536

type TemplateName string

const (
	RecurringObligationTemplate   TemplateName = "RecurringObligationPolicy"
	LivingReserveTemplate         TemplateName = "LivingReservePolicy"
	EmergencyBufferTemplate       TemplateName = "EmergencyBufferPolicy"
	DatedExpenseTemplate          TemplateName = "DatedExpensePolicy"
	LongTermGoalTemplate          TemplateName = "LongTermGoalPolicy"
	PeriodicTransferTemplate      TemplateName = "PeriodicTransferPolicy"
	AssetAuthorizationTemplate    TemplateName = "AssetAuthorizationPolicy"
	RecoveryTemplate              TemplateName = "RecoveryPolicy"
	GoalAllocationTemplate        TemplateName = "GoalAllocationPolicy"
	CrossGoalReallocationTemplate TemplateName = "CrossGoalReallocationPolicy"
	SeasonalReserveTemplate       TemplateName = "SeasonalReservePolicy"
	InterventionTemplate          TemplateName = "InterventionPolicy"
)

var (
	ErrTemplate         = errors.New("INVALID_TEMPLATE_CONFIGURATION")
	ErrTemplateCapacity = errors.New("TEMPLATE_CAPACITY_EXCEEDED")
	ErrTemplateFacts    = errors.New("TEMPLATE_FACTS_INCOMPLETE")
	ErrTemplateInactive = errors.New("TEMPLATE_NOT_CURRENT_ACTIVE")
)

// Fixed lowercase UUID text has the same order as its 16 underlying bytes.
func templateIDLess(a, b funds.ID) bool {
	return bytes.Compare(a[:], b[:]) < 0
}

func normalizedTemplateFacts(f TemplateFacts) TemplateFacts {
	f.Accounts = append([]TemplateAccountFact(nil), f.Accounts...)
	sort.Slice(f.Accounts, func(i, j int) bool { return templateIDLess(f.Accounts[i].ID, f.Accounts[j].ID) })
	f.Income = append([]TemplateIncomeFact(nil), f.Income...)
	for i := range f.Income {
		f.Income[i].OccurredAt = f.Income[i].OccurredAt.UTC()
	}
	sort.Slice(f.Income, func(i, j int) bool { return templateIDLess(f.Income[i].ID, f.Income[j].ID) })
	f.Goals = append([]TemplateGoalFact(nil), f.Goals...)
	for i := range f.Goals {
		if f.Goals[i].GoalVersion != nil {
			version := *f.Goals[i].GoalVersion
			version.ConfirmedAt = version.ConfirmedAt.UTC()
			f.Goals[i].GoalVersion = &version
		}
	}
	sort.Slice(f.Goals, func(i, j int) bool { return templateIDLess(f.Goals[i].ID, f.Goals[j].ID) })
	f.Bills = append([]TemplateBillFact(nil), f.Bills...)
	sort.Slice(f.Bills, func(i, j int) bool { return templateIDLess(f.Bills[i].ID, f.Bills[j].ID) })
	f.Settlements = append([]TemplateSettlementFact(nil), f.Settlements...)
	sort.Slice(f.Settlements, func(i, j int) bool {
		return f.Settlements[i].PolicyID.String()+f.Settlements[i].Period < f.Settlements[j].PolicyID.String()+f.Settlements[j].Period
	})
	f.HistoryAccounts = append([]funds.ID(nil), f.HistoryAccounts...)
	sort.Slice(f.HistoryAccounts, func(i, j int) bool { return templateIDLess(f.HistoryAccounts[i], f.HistoryAccounts[j]) })
	f.History = append([]TemplateHistoryTransaction(nil), f.History...)
	sort.Slice(f.History, func(i, j int) bool { return templateIDLess(f.History[i].ID, f.History[j].ID) })
	f.Coverage = append([]TemplateHistoryCoverage(nil), f.Coverage...)
	for i := range f.Coverage {
		f.Coverage[i].Dates = append([]string(nil), f.Coverage[i].Dates...)
		sort.Strings(f.Coverage[i].Dates)
	}
	sort.Slice(f.Coverage, func(i, j int) bool { return templateIDLess(f.Coverage[i].AccountID, f.Coverage[j].AccountID) })
	f.Products = append([]TemplateAssetProductFact(nil), f.Products...)
	sort.Slice(f.Products, func(i, j int) bool { return templateIDLess(f.Products[i].ID, f.Products[j].ID) })
	f.Positions = append([]TemplatePositionFact(nil), f.Positions...)
	sort.Slice(f.Positions, func(i, j int) bool { return templateIDLess(f.Positions[i].ID, f.Positions[j].ID) })
	f.EmergencyDeficits = append([]TemplateEmergencyDeficit(nil), f.EmergencyDeficits...)
	sort.Slice(f.EmergencyDeficits, func(i, j int) bool { return f.EmergencyDeficits[i].Condition < f.EmergencyDeficits[j].Condition })
	f.SeasonalWindows = append([]TemplateSeasonalWindow(nil), f.SeasonalWindows...)
	sort.Slice(f.SeasonalWindows, func(i, j int) bool { return f.SeasonalWindows[i].Start < f.SeasonalWindows[j].Start })
	f.ProtectedReferences = append([]TemplatePolicyReference(nil), f.ProtectedReferences...)
	sort.Slice(f.ProtectedReferences, func(i, j int) bool {
		return templateIDLess(f.ProtectedReferences[i].PolicyID, f.ProtectedReferences[j].PolicyID)
	})
	if f.Intervention != nil {
		event := *f.Intervention
		event.Reasons = append([]string(nil), event.Reasons...)
		event.PriorReasons = append([]string(nil), event.PriorReasons...)
		sort.Strings(event.Reasons)
		sort.Strings(event.PriorReasons)
		if event.LastAskedAt != nil {
			at := event.LastAskedAt.UTC()
			event.LastAskedAt = &at
		}
		f.Intervention = &event
	}
	return f
}
func templateRemaining(f TemplateFacts, policyID funds.ID, period string, registered funds.Money, historical bool) (funds.Money, error) {
	var found *TemplateSettlementFact
	for i := range f.Settlements {
		fact := &f.Settlements[i]
		if fact.PolicyID == policyID && fact.Period == period {
			if found != nil || !fact.Verified {
				return funds.Money{}, ErrTemplateFacts
			}
			found = fact
		}
	}
	if found == nil {
		if historical {
			return funds.Money{}, ErrTemplateFacts
		}
		return registered, nil
	}
	total := registered
	if found.FinalTotal != nil {
		total = *found.FinalTotal
	}
	if found.Paid.Cents() > total.Cents() {
		return funds.Money{}, ErrTemplateFacts
	}
	return total.Sub(found.Paid)
}
func templateReferenceSet(ids []funds.ID, facts TemplateFacts) error {
	for _, id := range ids {
		found := false
		for _, ref := range facts.ProtectedReferences {
			if ref.PolicyID == id {
				if found || ref.VersionID == (funds.ID{}) || !ref.Current || !ref.ConfirmationVerified || !validHash(ref.ConfigurationHash) || !ref.ImpactVerified || ref.ProtectedAfter.Cents() < ref.ProtectedBefore.Cents() {
					return ErrTemplateFacts
				}
				found = true
			}
		}
		if !found {
			return ErrTemplateFacts
		}
	}
	return nil
}

// TemplateActiveOnDate treats validity as natural dates. A confirmation during
// the day may authorize that day's occurrence, but never an earlier day.
func TemplateActiveOnDate(version TemplateVersion, date, timezone string) (bool, error) {
	day, err := TemplateDate(date)
	if err != nil {
		return false, err
	}
	zone, err := TemplateLocation(timezone)
	if err != nil {
		return false, err
	}
	start, end, err := TemplateValidity(version.Compiled, version.ConfirmedAt, timezone)
	if err != nil {
		return false, err
	}
	if start.Before(version.ConfirmedAt) {
		start = version.ConfirmedAt
	}
	local := time.Date(day.Year(), day.Month(), day.Day(), 0, 0, 0, 0, zone)
	return date >= start.In(zone).Format("2006-01-02") && (end == nil || local.Before(*end)), nil
}

// PreviewTemplate consumes current supplied facts. Its bounded requests still
// need the owning solver/executor and cannot confer USER or bank authority.
func PreviewTemplate(version TemplateVersion, facts TemplateFacts, now time.Time, timezone string) (TemplatePreview, error) {
	state, err := version.EffectiveState(now, timezone)
	if err != nil {
		return TemplatePreview{}, err
	}
	if err = facts.validate(version.Scope, now); err != nil {
		return TemplatePreview{}, err
	}
	if state != "ACTIVE" && state != "CONFIRMED" {
		return TemplatePreview{}, ErrTemplateInactive
	}
	config, err := version.Compiled.Decode()
	if err != nil {
		return TemplatePreview{}, err
	}
	zone, _ := TemplateLocation(timezone)
	today := now.In(zone).Format("2006-01-02")
	facts = normalizedTemplateFacts(facts)
	version.ConfirmedAt = version.ConfirmedAt.UTC()
	result := TemplatePreview{Protocol: TemplateProtocol, Template: version.Compiled.Name, ConfigurationHash: version.Compiled.Hash, State: state, Commitments: []TemplateCommitment{}, Candidates: []TemplateCandidate{}, GoalDemands: []TemplateGoalDemand{}, Questions: []string{}, Reasons: []string{}}
	result.InputHash = digest(struct {
		Version  TemplateVersion
		Facts    TemplateFacts
		Now      time.Time
		Timezone string
	}{version, facts, now.UTC(), timezone})
	if result.InputHash == "" {
		return TemplatePreview{}, ErrTemplateFacts
	}
	if state == "CONFIRMED" {
		result.Reasons = append(result.Reasons, "FUTURE_VALIDITY_NO_CURRENT_EFFECT")
		return result, nil
	}
	result.State = "READY"
	add := func(kind, due, end string, amount funds.Money, account *funds.ID, payee string) {
		result.Commitments = append(result.Commitments, TemplateCommitment{version.VersionID.String() + ":" + kind + ":" + due, kind, version.PolicyID, version.VersionID, due, end, amount, account, payee})
	}
	switch v := config.(type) {
	case *RecurringObligationConfig:
		if v.AmountRule.Kind == "bill_balance" {
			seen := map[funds.ID]bool{}
			for _, bill := range facts.Bills {
				if bill.ID == (funds.ID{}) || seen[bill.ID] || !bill.Verified || bill.Paid.Cents() > bill.Total.Cents() {
					return TemplatePreview{}, ErrTemplateFacts
				}
				seen[bill.ID] = true
				if _, err := TemplateDate(bill.DueDate); err != nil {
					return TemplatePreview{}, err
				}
				if bill.AccountID != *v.AmountRule.AccountID {
					continue
				}
				remaining, _ := bill.Total.Sub(bill.Paid)
				if !remaining.IsZero() {
					add("BILL_"+bill.ID.String(), bill.DueDate, "", remaining, &bill.AccountID, v.PayeeID)
				}
			}
		} else {
			due := TemplateDueDate(now.In(zone).Year(), now.In(zone).Month(), v.DueDay)
			start, _, _ := TemplateValidity(version.Compiled, version.ConfirmedAt, timezone)
			if start.Before(version.ConfirmedAt) {
				start = version.ConfirmedAt
			}
			activeOnDue, err := TemplateActiveOnDate(version, due, timezone)
			if err != nil {
				return TemplatePreview{}, err
			}
			if due >= start.In(zone).Format("2006-01-02") && activeOnDue {
				upper := v.AmountRule.Amount
				if v.AmountRule.Kind == "range" {
					upper = v.AmountRule.Max
				}
				remaining, err := templateRemaining(facts, version.PolicyID, now.In(zone).Format("2006-01"), upper, due < today)
				if err != nil {
					return TemplatePreview{}, err
				}
				if !remaining.IsZero() {
					add("RECURRING_OBLIGATION", due, "", remaining, nil, v.PayeeID)
				}
			}
		}
		for _, commitment := range result.Commitments {
			result.Amount, err = templateSum(result.Amount, commitment.Amount)
			if err != nil {
				return TemplatePreview{}, err
			}
			result.Candidates = append(result.Candidates, TemplateCandidate{Kind: "PAYMENT_CONSTRAINT", SubjectID: version.PolicyID, AmountCap: commitment.Amount, RequiresConfirmation: !v.AutoExecute || !facts.StandingAuthorizationCovered, Reasons: []string{"PAYEE_AND_CURRENT_OBLIGATION_RECHECK_REQUIRED"}})
		}
	case *LivingReserveConfig:
		amount, err := EstimateLivingReserve(*v, facts, today)
		if err != nil {
			return TemplatePreview{}, err
		}
		result.Amount = amount
		add("LIVING_RESERVE", today, "", amount, nil, "")
	case *EmergencyBufferConfig:
		result.Amount = v.Amount
		add("EMERGENCY_BUFFER", today, "", v.Amount, nil, "")
	case *DatedExpenseConfig:
		if err = templateReferenceSet(v.MustNotReducePolicyIDs, facts); err != nil {
			return TemplatePreview{}, err
		}
		period := v.Window.Start + "/" + v.Window.End
		remaining, err := templateRemaining(facts, version.PolicyID, period, v.Amount.Max, v.Window.End < today)
		if err != nil {
			return TemplatePreview{}, err
		}
		result.Amount = remaining
		if !remaining.IsZero() {
			add("DATED_EXPENSE", v.Window.Start, v.Window.End, remaining, nil, "")
		}
	case *LongTermGoalConfig:
		var goal *TemplateGoalFact
		for i := range facts.Goals {
			if facts.Goals[i].PolicyID == version.PolicyID {
				if goal != nil {
					return TemplatePreview{}, ErrTemplateFacts
				}
				goal = &facts.Goals[i]
			}
		}
		if goal == nil {
			return TemplatePreview{}, ErrTemplateFacts
		}
		pace, err := templateGoalPacing(version, v, *goal, facts, now, timezone)
		if err != nil {
			return TemplatePreview{}, err
		}
		result.State, result.Amount, result.MinimumShortfall, result.GuaranteeShortfall, result.GoalDemands = pace.State, pace.Amount, pace.MinimumShortfall, pace.GuaranteeShortfall, pace.GoalDemands
		if !result.Amount.IsZero() {
			result.Candidates = append(result.Candidates, TemplateCandidate{Kind: "GOAL_CONTRIBUTION_CONSTRAINT", SubjectID: goal.ID, AmountCap: result.Amount, RequiresConfirmation: !facts.StandingAuthorizationCovered, Reasons: []string{"CURRENT_CONFIRMED_INCOME_ONLY", "OWNED_CASH_NOT_NEW_INCOME"}})
		}
	case *PeriodicTransferConfig:
		accountKnown := false
		for _, account := range facts.Accounts {
			if account.ID == v.SourceAccountID {
				accountKnown = true
			}
		}
		if !accountKnown {
			return TemplatePreview{}, ErrTemplateFacts
		}
		due := TemplateDueDate(now.In(zone).Year(), now.In(zone).Month(), v.DueDay)
		start, _, _ := TemplateValidity(version.Compiled, version.ConfirmedAt, timezone)
		if start.Before(version.ConfirmedAt) {
			start = version.ConfirmedAt
		}
		activeOnDue, err := TemplateActiveOnDate(version, due, timezone)
		if err != nil {
			return TemplatePreview{}, err
		}
		if due >= start.In(zone).Format("2006-01-02") && activeOnDue {
			upper := v.AmountRule.Amount
			if v.AmountRule.Kind == "range" {
				upper = v.AmountRule.Max
			}
			remaining, err := templateRemaining(facts, version.PolicyID, now.In(zone).Format("2006-01"), upper, due < today)
			if err != nil {
				return TemplatePreview{}, err
			}
			result.Amount = remaining
			if !remaining.IsZero() {
				add("PERIODIC_TRANSFER", due, "", remaining, &v.SourceAccountID, v.PayeeID)
				if remaining.Cents() > v.SingleActionCap.Cents() {
					result.State = "OUT_OF_AUTHORIZATION"
				} else {
					result.Candidates = append(result.Candidates, TemplateCandidate{Kind: "PERIODIC_PAYMENT_CONSTRAINT", SubjectID: v.SourceAccountID, AmountCap: remaining, RequiresConfirmation: !v.AutoExecute || !facts.StandingAuthorizationCovered, Reasons: []string{"SOURCE_ACCOUNT_PROTECTION_AND_PAYEE_BINDING_REQUIRED"}})
				}
			}
		}
	case *AssetAuthorizationConfig:
		err = previewAssetTemplate(&result, version, *v, facts, now, timezone)
	case *RecoveryConfig:
		err = previewRecoveryTemplate(&result, version, *v, facts)
	case *GoalAllocationConfig:
		err = previewGoalAllocationTemplate(&result, version, *v, facts, now, timezone)
	case *CrossGoalReallocationConfig:
		err = previewCrossGoalTemplate(&result, version, *v, facts, now, timezone)
	case *SeasonalReserveConfig:
		err = previewSeasonalTemplate(&result, version, *v, facts, today)
	case *InterventionConfig:
		err = previewInterventionTemplate(&result, *v, facts, now)
	default:
		return TemplatePreview{}, ErrTemplate
	}
	if err != nil {
		return TemplatePreview{}, err
	}
	return result, nil
}

func previewAssetTemplate(result *TemplatePreview, version TemplateVersion, config AssetAuthorizationConfig, facts TemplateFacts, now time.Time, timezone string) error {
	if !facts.CurrentSafeVerified {
		return ErrTemplateFacts
	}
	available := facts.CurrentSafe.Cents()
	if config.Scope == "goal" {
		goal, ok := facts.goal(*config.GoalID)
		if !ok {
			return ErrTemplateFacts
		}
		available = goal.ScopeAvailable.Cents()
	}
	room := templateMax(0, config.MaxAutoManaged.Cents()-facts.ManagedAmount.Cents())
	budget := templateMin(available, room, config.SingleActionCap.Cents())
	result.Amount, _ = templateMoney(budget)
	seen := map[funds.ID]bool{}
	zone, _ := TemplateLocation(timezone)
	for _, product := range facts.Products {
		if product.ID == (funds.ID{}) || seen[product.ID] || product.RiskLevel < 0 || product.RiskLevel > 5 || product.LockDays < 0 || product.LockDays > 3660 || product.RedemptionDelayDays < 0 || product.RedemptionDelayDays > 3660 {
			return ErrTemplateFacts
		}
		seen[product.ID] = true
		reasons := []string{}
		allowed := false
		for _, class := range config.AllowedAssetClasses {
			if product.AssetClass == class {
				allowed = true
			}
		}
		if !product.Current || !product.TermsVerified || !validHash(product.TermsHash) {
			reasons = append(reasons, "PRODUCT_NOT_CURRENT_VERIFIED")
		}
		if !allowed {
			reasons = append(reasons, "ASSET_CLASS_NOT_AUTHORIZED")
		}
		if product.PrincipalFluctuation {
			reasons = append(reasons, "PRINCIPAL_FLUCTUATION_NEVER_AUTO")
		}
		if product.RiskLevel > config.MaxPrincipalRiskLevel {
			reasons = append(reasons, "RISK_CAP_EXCEEDED")
		}
		if product.LockDays > config.MaxLockDays || product.RedemptionDelayDays > config.MaxRedemptionDelayDays {
			reasons = append(reasons, "LIQUIDITY_CAP_EXCEEDED")
		}
		kind := "ASSET_PURCHASE_CONSTRAINT"
		if product.AssetClass == "CASH" {
			kind = "RETAIN_CASH"
		} else {
			if !product.AutoPurchaseAllowed {
				reasons = append(reasons, "PRODUCT_AUTO_PURCHASE_DISABLED")
			}
			useDate, err := TemplateDate(facts.AssetUseDate)
			if err != nil {
				return ErrTemplateFacts
			}
			limit := time.Date(useDate.Year(), useDate.Month(), useDate.Day(), 0, 0, 0, 0, zone)
			if product.TermsSettlementDelayDays != product.RedemptionDelayDays || product.TermsYieldBPS != product.YieldBPS {
				reasons = append(reasons, "PRODUCT_TERMS_CONTRADICT_CATALOG")
			}
			var availableAt time.Time
			switch product.ReturnKind {
			case "FIXED_MATURITY":
				expected := map[string]int{"FIXED_DEPOSIT_7D": 7, "FIXED_DEPOSIT_30D": 30, "FIXED_DEPOSIT_90D": 90}
				days, known := expected[product.AssetClass]
				if (!known && product.AssetClass != "LOW_RISK_TERM") || (known && days != product.TermDays) || product.TermDays < 1 || product.TermDays > 3660 || product.TermDays < product.LockDays || product.TermDays > config.MaxLockDays || product.Accrual != "UNTIL_MATURITY" {
					reasons = append(reasons, "FIXED_TERMS_CONTRADICT_SCOPE")
				}
				if product.TermDays >= 0 && product.TermDays <= 3660 {
					availableAt = now.Add(time.Duration(product.TermDays+product.RedemptionDelayDays) * 24 * time.Hour)
				}
			case "PLANNED_REDEMPTION":
				if (product.AssetClass != "CASH_MGMT_T0" && product.AssetClass != "CASH_MGMT_T1") || (product.AssetClass == "CASH_MGMT_T0" && product.RedemptionDelayDays != 0) || (product.AssetClass == "CASH_MGMT_T1" && product.RedemptionDelayDays != 1) || product.Accrual != "UNTIL_REDEMPTION_REQUEST" || !product.AutoRedeemAllowed || !config.AllowAutoRecoveryWithoutPenalty {
					reasons = append(reasons, "ZERO_LOSS_PLANNED_RECOVERY_NOT_CONFIRMED")
				}
				earning := (limit.Unix()-now.Unix())/86400 - int64(product.RedemptionDelayDays)
				_, end, err := TemplateValidity(version.Compiled, version.ConfirmedAt, timezone)
				if err != nil {
					return err
				}
				if end != nil {
					endSeconds := end.Unix() - now.Unix()
					if end.Nanosecond() <= now.Nanosecond() {
						endSeconds--
					}
					if max := endSeconds / 86400; max < earning {
						earning = max
					}
				}
				if earning < 1 || earning < int64(product.LockDays) || earning > 3660 {
					reasons = append(reasons, "NO_CONFIRMED_EXIT_BEFORE_USE")
				} else {
					availableAt = now.Add(time.Duration(earning+int64(product.RedemptionDelayDays)) * 24 * time.Hour)
				}
			default:
				reasons = append(reasons, "UNSUPPORTED_RETURN_TERMS")
			}
			if availableAt.IsZero() || availableAt.After(limit) {
				reasons = append(reasons, "PRINCIPAL_NOT_AVAILABLE_BEFORE_USE")
			}
		}
		if budget < product.Minimum.Cents() {
			reasons = append(reasons, "BELOW_PRODUCT_MINIMUM")
		}
		amount := result.Amount
		if len(reasons) > 0 {
			kind = "REJECTED_ASSET"
			amount = funds.Money{}
		}
		result.Candidates = append(result.Candidates, TemplateCandidate{Kind: kind, SubjectID: product.ID, AmountCap: amount, RequiresConfirmation: kind != "RETAIN_CASH" && !facts.StandingAuthorizationCovered, Reasons: reasons})
	}
	if budget == 0 {
		result.State = "NO_ACTION"
	}
	return nil
}
func previewRecoveryTemplate(result *TemplatePreview, _ TemplateVersion, config RecoveryConfig, facts TemplateFacts) error {
	triggered := false
	for _, trigger := range config.Triggers {
		if trigger == facts.RecoveryTrigger {
			triggered = true
		}
	}
	if !triggered {
		result.State = "NO_ACTION"
		return nil
	}
	seen := map[funds.ID]bool{}
	for _, position := range facts.Positions {
		if position.ID == (funds.ID{}) || seen[position.ID] {
			return ErrTemplateFacts
		}
		seen[position.ID] = true
		if position.AssetPolicyID != config.AssetPolicyID || (position.GoalID == nil) != (config.GoalID == nil) || (position.GoalID != nil && *position.GoalID != *config.GoalID) {
			continue
		}
		if !position.Verified || !position.FeeLossKnown || position.Recoverable.Cents() > position.Principal.Cents() || position.RedemptionDelayDays < 0 {
			return ErrTemplateFacts
		}
		if !position.Current || (position.State != "HELD" && position.State != "MATURED") || !position.Fee.IsZero() || !position.Loss.IsZero() || position.RedemptionDelayDays > config.MaxRedemptionDelayDays {
			result.Reasons = append(result.Reasons, "POSITION_NOT_ZERO_LOSS_CURRENT_RECOVERABLE:"+position.ID.String())
			continue
		}
		amount, _ := templateMoney(templateMin(position.Recoverable.Cents(), config.SingleActionCap.Cents()))
		if amount.IsZero() {
			continue
		}
		var err error
		result.Amount, err = templateSum(result.Amount, amount)
		if err != nil {
			return err
		}
		result.Candidates = append(result.Candidates, TemplateCandidate{Kind: "ZERO_LOSS_RECOVERY_CONSTRAINT", SubjectID: position.ID, AmountCap: amount, RequiresConfirmation: !config.AllowAutoRecoveryWithoutPenalty || !facts.StandingAuthorizationCovered, Reasons: []string{"ORIGINAL_PRINCIPAL_NOT_NEW_INCOME", "SAME_POSITION_AND_RETURN_ACCOUNT_REQUIRED"}})
	}
	if len(result.Candidates) == 0 {
		result.State = "NO_ACTION"
	}
	return nil
}
func previewGoalAllocationTemplate(result *TemplatePreview, version TemplateVersion, config GoalAllocationConfig, facts TemplateFacts, now time.Time, timezone string) error {
	if len(config.GoalIDs) > 8 {
		return ErrTemplateCapacity
	}
	if !facts.CurrentSafeVerified {
		return ErrTemplateFacts
	}
	budget := templateMin(facts.CurrentSafe.Cents(), config.MaxSingleAllocation.Cents())
	totalMinimum := funds.Money{}
	for _, id := range config.GoalIDs {
		goal, ok := facts.goal(id)
		if !ok || goal.GoalVersion == nil || goal.GoalVersion.Scope != version.Scope {
			return ErrTemplateFacts
		}
		state, err := goal.GoalVersion.EffectiveState(now, timezone)
		if err != nil || state != "ACTIVE" {
			return ErrTemplateInactive
		}
		decoded, err := goal.GoalVersion.Compiled.Decode()
		if err != nil {
			return err
		}
		goalConfig, ok := decoded.(*LongTermGoalConfig)
		if !ok {
			return ErrTemplateFacts
		}
		pace, err := templateGoalPacing(*goal.GoalVersion, goalConfig, goal, facts, now, timezone)
		if err != nil {
			return err
		}
		result.GoalDemands = append(result.GoalDemands, pace.GoalDemands...)
		totalMinimum, err = templateSum(totalMinimum, pace.GoalDemands[0].Minimum)
		if err != nil {
			return err
		}
	}
	sort.Slice(result.GoalDemands, func(i, j int) bool {
		a, b := result.GoalDemands[i], result.GoalDemands[j]
		if a.Importance != b.Importance {
			return a.Importance > b.Importance
		}
		return a.GoalID.String() < b.GoalID.String()
	})
	if totalMinimum.Cents() > budget {
		result.State = "MINIMUM_SHORTFALL"
		result.MinimumShortfall, _ = templateMoney(totalMinimum.Cents() - budget)
		return nil
	}
	result.Amount, _ = templateMoney(budget)
	result.State = "CONSTRAINTS_READY"
	result.Reasons = append(result.Reasons, "EXACT_SHARED_SOURCE_RF021_SOLVER_REQUIRED", "NO_CENT_GREEDY_ALLOCATION_OR_OPTIMALITY_CLAIM")
	return nil
}
func previewCrossGoalTemplate(result *TemplatePreview, version TemplateVersion, config CrossGoalReallocationConfig, facts TemplateFacts, now time.Time, timezone string) error {
	if !config.Enabled {
		result.State = "NO_ACTION"
		return nil
	}
	remaining := templateMax(0, config.TotalCap.Cents()-facts.AlreadyReallocated.Cents())
	cap := templateMin(config.SingleActionCap.Cents(), remaining)
	result.Amount, _ = templateMoney(cap)
	if config.ScopeVersion == "GOAL_TRANSFER_V1" {
		if err := templateReferenceSet(config.MustNotReducePolicyIDs, facts); err != nil {
			return err
		}
		for _, sourceID := range config.SourceGoalIDs {
			source, ok := facts.goal(sourceID)
			if !ok || source.GoalVersion == nil || source.GoalVersion.Scope != version.Scope || source.PolicyID != source.GoalVersion.PolicyID || source.VersionID != source.GoalVersion.VersionID {
				return ErrTemplateFacts
			}
			if state, err := source.GoalVersion.EffectiveState(now, timezone); err != nil || state != "ACTIVE" {
				return ErrTemplateInactive
			}
			for _, targetID := range config.TargetGoalIDs {
				target, ok := facts.goal(targetID)
				if !ok || target.GoalVersion == nil || target.GoalVersion.Scope != version.Scope || target.PolicyID != target.GoalVersion.PolicyID || target.VersionID != target.GoalVersion.VersionID {
					return ErrTemplateFacts
				}
				if state, err := target.GoalVersion.EffectiveState(now, timezone); err != nil || state != "ACTIVE" {
					return ErrTemplateInactive
				}
				if sourceID == targetID || source.AccountID == target.AccountID {
					continue
				}
				targetConfig, err := target.GoalVersion.Compiled.Decode()
				if err != nil {
					return err
				}
				goalConfig, ok := targetConfig.(*LongTermGoalConfig)
				if !ok {
					return ErrTemplateFacts
				}
				amount, _ := templateMoney(templateMin(cap, source.ReleaseableCash.Cents(), templateMax(0, goalConfig.Target.Cents()-target.Owned.Cents())))
				if amount.IsZero() {
					continue
				}
				id := targetID
				result.Candidates = append(result.Candidates, TemplateCandidate{Kind: "PAIRED_GOAL_TRANSFER_CONSTRAINT", SubjectID: sourceID, TargetID: &id, AmountCap: amount, RequiresConfirmation: true, Reasons: []string{"NEW_USER_RELEASE_SOURCE_AND_RECEIVE_TARGET_REQUIRED", "NO_STANDING_OR_PROTECTED_CASH_AUTHORITY_INHERITANCE", "ALTERNATIVE_PAIRS_NOT_AN_ATOMIC_BATCH"}})
			}
		}
	} else {
		triggered := false
		seen := map[string]bool{}
		for _, deficit := range facts.EmergencyDeficits {
			if !deficit.Verified || seen[deficit.Condition] {
				return ErrTemplateFacts
			}
			seen[deficit.Condition] = true
			for _, condition := range config.EmergencyConditions {
				if condition == deficit.Condition && !deficit.Amount.IsZero() {
					triggered = true
				}
			}
		}
		if !triggered {
			result.State = "NO_ACTION"
			result.Amount = funds.Money{}
			return nil
		}
		if facts.VerifiedProtectedCashDeficit == nil {
			return ErrTemplateFacts
		}
		need := templateMin(cap, facts.VerifiedProtectedCashDeficit.Cents())
		requested := need
		for _, id := range config.SourceGoalIDs {
			goal, ok := facts.goal(id)
			if !ok {
				return ErrTemplateFacts
			}
			amount, _ := templateMoney(templateMin(need, goal.ReleaseableCash.Cents()))
			if amount.IsZero() {
				continue
			}
			result.Candidates = append(result.Candidates, TemplateCandidate{Kind: "PROTECTED_CASH_RELEASE_CONSTRAINT", SubjectID: id, AmountCap: amount, RequiresConfirmation: !facts.StandingAuthorizationCovered, Reasons: []string{"SOURCE_GOAL_MINIMUMS_RECHECK_REQUIRED", "POLICY_LIFETIME_CAP_INCLUDES_PENDING_AND_UNKNOWN"}})
			need -= amount.Cents()
			if need == 0 {
				break
			}
		}
		result.Amount, _ = templateMoney(requested - need)
		if need != 0 {
			result.Reasons = append(result.Reasons, "RELEASEABLE_SOURCE_SHORTFALL")
		}
	}
	if len(result.Candidates) == 0 || cap == 0 {
		result.State = "NO_ACTION"
	}
	return nil
}
func previewSeasonalTemplate(result *TemplatePreview, version TemplateVersion, config SeasonalReserveConfig, facts TemplateFacts, today string) error {
	if adoption := facts.SeasonalAdoption; adoption != nil {
		if !adoption.Verified || adoption.PolicyID != version.PolicyID || adoption.ConfigurationHash != version.Compiled.Hash || adoption.ProtectionEnd != config.Window.End || adoption.Amount.Cents() > config.AdjustmentCap.Cents() {
			return ErrTemplateFacts
		}
		if today > adoption.ProtectionEnd {
			result.State = "FLOOR_RELEASED"
			result.Reasons = append(result.Reasons, "END_RELEASES_PROTECTION_ONLY_NO_CASH_CREDIT")
			return nil
		}
		result.Amount = adoption.Amount
		result.Commitments = append(result.Commitments, TemplateCommitment{ID: version.VersionID.String() + ":ADOPTED_SEASONAL", Kind: "ADOPTED_SEASONAL_FLOOR", PolicyID: version.PolicyID, VersionID: version.VersionID, DueDate: today, EndDate: adoption.ProtectionEnd, Amount: adoption.Amount})
		return nil
	}
	windows := []TemplateSeasonalWindow{}
	for _, window := range facts.SeasonalWindows {
		if window.SourceProtocol == "" || window.SourceProtocol == HistoryStatementProtocol && window.HolidayCode == config.HolidayCode {
			windows = append(windows, window)
		} else if window.SourceProtocol != HistoryStatementProtocol {
			return ErrTemplateFacts
		}
	}
	if len(windows) < config.MinimumHistoricalWindows {
		return ErrTemplateFacts
	}
	todayDate, err := TemplateDate(today)
	if err != nil {
		return err
	}
	startWindow, _ := TemplateDate(config.Window.Start)
	endWindow, _ := TemplateDate(config.Window.End)
	duration := (endWindow.Unix() - startWindow.Unix()) / 86400
	values := []int64{}
	previousEnd := ""
	for _, window := range windows {
		a, err := TemplateDate(window.Start)
		if err != nil {
			return err
		}
		b, err := TemplateDate(window.End)
		if err != nil || b.Before(a) || !window.Verified || !validHash(window.EvidenceHash) || window.End >= today || window.Start < todayDate.AddDate(0, 0, -config.LookbackDays).Format("2006-01-02") || (b.Unix()-a.Unix())/86400 != duration || (previousEnd != "" && window.Start <= previousEnd) {
			return ErrTemplateFacts
		}
		previousEnd = window.End
		amount := window.Amount
		if window.SourceProtocol == HistoryStatementProtocol {
			amount, err = HistorySeasonalAmount(facts, window, config.EssentialCategories)
			if err != nil {
				return err
			}
		}
		values = append(values, amount.Cents())
	}
	sort.Slice(values, func(i, j int) bool { return values[i] < values[j] })
	rank, err := config.Quantile.Rank(len(values))
	if err != nil {
		return err
	}
	result.Amount, _ = templateMoney(templateMin(values[rank-1], config.AdjustmentCap.Cents()))
	result.State = "ADVICE_ONLY"
	result.Reasons = append(result.Reasons, "QUANTILE_CANNOT_CREATE_PROTECTION_OR_PERMISSION", "EXPLICIT_CURRENT_SOURCE_ADOPTION_REQUIRED")
	return nil
}
func previewInterventionTemplate(result *TemplatePreview, config InterventionConfig, facts TemplateFacts, now time.Time) error {
	event := facts.Intervention
	if event == nil || !validHash(event.BoundaryEventHash) || !validHash(event.ActionSetHash) || (event.PriorBoundaryEventHash != "" && !validHash(event.PriorBoundaryEventHash)) || (event.PriorActionSetHash != "" && !validHash(event.PriorActionSetHash)) || (event.LastAskedAt != nil && event.LastAskedAt.After(now)) {
		return ErrTemplateFacts
	}
	if !validTemplateStrings(event.Reasons, defaultInterventions, 0, 11, true) || !validTemplateStrings(event.PriorReasons, defaultInterventions, 0, 11, true) {
		return ErrTemplateFacts
	}
	for _, reason := range event.Reasons {
		configured := false
		for _, ask := range config.MustAskOn {
			if ask == reason {
				configured = true
			}
		}
		if !configured {
			continue
		}
		mandatory := false
		for _, ask := range mandatoryInterventions {
			if ask == reason {
				mandatory = true
			}
		}
		alreadyAsked := false
		if event.BoundaryEventHash == event.PriorBoundaryEventHash {
			for _, prior := range event.PriorReasons {
				if prior == reason {
					alreadyAsked = true
				}
			}
		}
		if alreadyAsked {
			continue
		}
		if !mandatory && event.ActionSetHash == event.PriorActionSetHash {
			continue
		}
		if !mandatory && event.LastAskedAt != nil && now.Sub(*event.LastAskedAt) < time.Duration(config.MinimumReaskIntervalSeconds)*time.Second {
			continue
		}
		result.Questions = append(result.Questions, reason)
	}
	if len(result.Questions) == 0 {
		result.State = "SILENT_STABLE_OR_DEDUPLICATED"
	} else {
		result.State = "USER_QUESTION_REQUIRED"
	}
	return nil
}

func TemplateNames() []TemplateName {
	return []TemplateName{RecurringObligationTemplate, LivingReserveTemplate, EmergencyBufferTemplate, DatedExpenseTemplate, LongTermGoalTemplate, PeriodicTransferTemplate, AssetAuthorizationTemplate, RecoveryTemplate, GoalAllocationTemplate, CrossGoalReallocationTemplate, SeasonalReserveTemplate, InterventionTemplate}
}

// TemplateVersion is built from a scoped locked application read. These flags
// are provenance preconditions, not a replacement for session authentication
// or persisted USER confirmation. Browsers/models must not supply this DTO.
type TemplateOwnerScope struct {
	EnvironmentID funds.ID `json:"environment_id"`
	UserID        funds.ID `json:"user_id"`
}
type TemplateVersion struct {
	PolicyID                   funds.ID           `json:"policy_id"`
	VersionID                  funds.ID           `json:"version_id"`
	Version                    uint64             `json:"version"`
	Scope                      TemplateOwnerScope `json:"scope"`
	Compiled                   CompiledTemplate   `json:"compiled"`
	State                      string             `json:"state"`
	ConfirmedAt                time.Time          `json:"confirmed_at"`
	Current                    bool               `json:"current"`
	ConfirmationVerified       bool               `json:"confirmation_verified"`
	ConfirmedConfigurationHash string             `json:"confirmed_configuration_hash"`
}

func TemplateValidity(compiled CompiledTemplate, confirmedAt time.Time, timezone string) (time.Time, *time.Time, error) {
	config, err := compiled.Decode()
	if err != nil {
		return time.Time{}, nil, err
	}
	zone, err := TemplateLocation(timezone)
	if err != nil || confirmedAt.IsZero() {
		return time.Time{}, nil, ErrTemplate
	}
	common := config.CommonFields()
	start := confirmedAt.UTC()
	if common.ValidFrom != nil {
		day, _ := TemplateDate(*common.ValidFrom)
		start = time.Date(day.Year(), day.Month(), day.Day(), 0, 0, 0, 0, zone).UTC()
	}
	var end *time.Time
	if common.ValidUntil != nil {
		day, _ := TemplateDate(*common.ValidUntil)
		local := time.Date(day.Year(), day.Month(), day.Day(), 0, 0, 0, 0, zone).AddDate(0, 0, 1)
		if local.Year() > 9999 {
			return time.Time{}, nil, ErrTemplate
		}
		value := local.UTC()
		end = &value
	}
	if end != nil && start.After(*end) {
		return time.Time{}, nil, ErrTemplate
	}
	return start, end, nil
}
func (v TemplateVersion) EffectiveState(now time.Time, timezone string) (string, error) {
	if v.PolicyID == (funds.ID{}) || v.VersionID == (funds.ID{}) || v.Version == 0 || v.Scope.EnvironmentID == (funds.ID{}) || v.Scope.UserID == (funds.ID{}) || !v.Current || !v.ConfirmationVerified || v.ConfirmedConfigurationHash != v.Compiled.Hash || now.IsZero() {
		return "", ErrTemplateFacts
	}
	start, end, err := TemplateValidity(v.Compiled, v.ConfirmedAt, timezone)
	if err != nil {
		return "", err
	}
	switch v.State {
	case "ACTIVE", "CONFIRMED", "SUSPENDED", "EXPIRED", "REVOKED":
	default:
		return "", ErrTemplate
	}
	if v.State == "REVOKED" {
		return "REVOKED", nil
	}
	if v.ConfirmedAt.After(now) {
		return "CONFIRMATION_IN_FUTURE", nil
	}
	if v.State == "EXPIRED" || (end != nil && !now.Before(*end)) {
		return "EXPIRED", nil
	}
	if v.State == "SUSPENDED" {
		return "SUSPENDED", nil
	}
	if now.Before(start) {
		return "CONFIRMED", nil
	}
	return "ACTIVE", nil
}

type TemplateAccountFact struct {
	ID       funds.ID    `json:"id"`
	Balance  funds.Money `json:"balance_cents"`
	Verified bool        `json:"verified"`
}
type TemplateIncomeFact struct {
	ID         funds.ID    `json:"id"`
	Available  funds.Money `json:"available_cents"`
	OccurredAt time.Time   `json:"occurred_at"`
	Verified   bool        `json:"verified"`
}
type TemplateGoalFact struct {
	ID               funds.ID         `json:"id"`
	AccountID        funds.ID         `json:"account_id"`
	PolicyID         funds.ID         `json:"policy_id"`
	VersionID        funds.ID         `json:"version_id"`
	Owned            funds.Money      `json:"owned_cents"`
	CashOwned        funds.Money      `json:"cash_owned_cents"`
	ReleaseableCash  funds.Money      `json:"releaseable_cash_cents"`
	ScopeAvailable   funds.Money      `json:"scope_available_cents"`
	MonthContributed funds.Money      `json:"month_contributed_cents"`
	MonthPeriod      string           `json:"month_period"`
	Verified         bool             `json:"verified"`
	GoalVersion      *TemplateVersion `json:"goal_version,omitempty"`
}
type TemplateBillFact struct {
	ID        funds.ID    `json:"id"`
	AccountID funds.ID    `json:"account_id"`
	DueDate   string      `json:"due_date"`
	Total     funds.Money `json:"total_cents"`
	Paid      funds.Money `json:"paid_cents"`
	Verified  bool        `json:"verified"`
}
type TemplateSettlementFact struct {
	PolicyID   funds.ID     `json:"policy_id"`
	Period     string       `json:"period"`
	Paid       funds.Money  `json:"paid_cents"`
	FinalTotal *funds.Money `json:"final_total_cents,omitempty"`
	Verified   bool         `json:"verified"`
}
type TemplateHistoryTransaction struct {
	ID                funds.ID    `json:"id"`
	AccountID         funds.ID    `json:"account_id"`
	Date              string      `json:"date"`
	Direction         string      `json:"direction"`
	Amount            funds.Money `json:"amount_cents"`
	Category          string      `json:"category"`
	CategoryConfirmed bool        `json:"category_confirmed"`
	OneOff            bool        `json:"one_off"`
	EconomicRole      string      `json:"economic_role"`
}
type TemplateHistoryCoverage struct {
	AccountID funds.ID `json:"account_id"`
	Dates     []string `json:"dates"`
}
type TemplateAssetProductFact struct {
	ID                       funds.ID    `json:"id"`
	AssetClass               string      `json:"asset_class"`
	Minimum                  funds.Money `json:"minimum_cents"`
	RiskLevel                int         `json:"risk_level"`
	LockDays                 int         `json:"lock_days"`
	RedemptionDelayDays      int         `json:"redemption_delay_days"`
	PrincipalFluctuation     bool        `json:"principal_fluctuation"`
	AutoPurchaseAllowed      bool        `json:"auto_purchase_allowed"`
	AutoRedeemAllowed        bool        `json:"auto_redeem_allowed"`
	Current                  bool        `json:"current"`
	TermsVerified            bool        `json:"terms_verified"`
	TermsHash                string      `json:"terms_hash"`
	ReturnKind               string      `json:"return_kind"`
	TermDays                 int         `json:"term_days"`
	TermsSettlementDelayDays int         `json:"terms_settlement_delay_days"`
	YieldBPS                 int         `json:"yield_bps"`
	TermsYieldBPS            int         `json:"terms_yield_bps"`
	Accrual                  string      `json:"accrual"`
}
type TemplatePositionFact struct {
	ID                  funds.ID    `json:"id"`
	AssetPolicyID       funds.ID    `json:"asset_policy_id"`
	GoalID              *funds.ID   `json:"goal_id,omitempty"`
	Principal           funds.Money `json:"principal_cents"`
	Recoverable         funds.Money `json:"recoverable_cents"`
	Fee                 funds.Money `json:"fee_cents"`
	Loss                funds.Money `json:"loss_cents"`
	RedemptionDelayDays int         `json:"redemption_delay_days"`
	Current             bool        `json:"current"`
	Verified            bool        `json:"verified"`
	FeeLossKnown        bool        `json:"fee_loss_known"`
	State               string      `json:"state"`
}
type TemplateEmergencyDeficit struct {
	Condition string      `json:"condition"`
	Amount    funds.Money `json:"amount_cents"`
	Verified  bool        `json:"verified"`
}
type TemplateSeasonalWindow struct {
	SourceProtocol string      `json:"source_protocol,omitempty"`
	HolidayCode    string      `json:"holiday_code,omitempty"`
	Start          string      `json:"start"`
	End            string      `json:"end"`
	Amount         funds.Money `json:"amount_cents"`
	Verified       bool        `json:"verified"`
	EvidenceHash   string      `json:"evidence_hash"`
}
type TemplateSeasonalAdoption struct {
	PolicyID          funds.ID    `json:"policy_id"`
	ConfigurationHash string      `json:"configuration_hash"`
	Amount            funds.Money `json:"amount_cents"`
	ProtectionEnd     string      `json:"protection_end"`
	Verified          bool        `json:"verified"`
}
type TemplateInterventionEvent struct {
	Reasons                []string   `json:"reasons"`
	BoundaryEventHash      string     `json:"boundary_event_hash"`
	PriorBoundaryEventHash string     `json:"prior_boundary_event_hash,omitempty"`
	ActionSetHash          string     `json:"action_set_hash"`
	PriorActionSetHash     string     `json:"prior_action_set_hash,omitempty"`
	LastAskedAt            *time.Time `json:"last_asked_at,omitempty"`
	PriorReasons           []string   `json:"prior_reasons"`
}
type TemplatePolicyReference struct {
	PolicyID             funds.ID    `json:"policy_id"`
	VersionID            funds.ID    `json:"version_id"`
	ConfigurationHash    string      `json:"configuration_hash"`
	Current              bool        `json:"current"`
	ConfirmationVerified bool        `json:"confirmation_verified"`
	ImpactVerified       bool        `json:"impact_verified"`
	ProtectedBefore      funds.Money `json:"protected_before_cents"`
	ProtectedAfter       funds.Money `json:"protected_after_cents"`
}
type TemplateFacts struct {
	Scope               TemplateOwnerScope           `json:"scope"`
	Complete            bool                         `json:"complete"`
	SourceHash          string                       `json:"source_hash"`
	CurrentCash         funds.Money                  `json:"current_cash_cents"`
	CurrentSafe         funds.Money                  `json:"current_safe_cents"`
	CurrentSafeVerified bool                         `json:"current_safe_verified"`
	Accounts            []TemplateAccountFact        `json:"accounts"`
	Income              []TemplateIncomeFact         `json:"income"`
	IncomeComplete      bool                         `json:"income_complete"`
	Goals               []TemplateGoalFact           `json:"goals"`
	Bills               []TemplateBillFact           `json:"bills"`
	Settlements         []TemplateSettlementFact     `json:"settlements"`
	HistoryAccounts     []funds.ID                   `json:"history_accounts"`
	History             []TemplateHistoryTransaction `json:"history"`
	Coverage            []TemplateHistoryCoverage    `json:"coverage"`
	Products            []TemplateAssetProductFact   `json:"products"`
	Positions           []TemplatePositionFact       `json:"positions"`
	ManagedAmount       funds.Money                  `json:"managed_amount_cents"`
	AssetUseDate        string                       `json:"asset_use_date,omitempty"`
	RecoveryTrigger     string                       `json:"recovery_trigger,omitempty"`
	EmergencyDeficits   []TemplateEmergencyDeficit   `json:"emergency_deficits"`
	// AlreadyReallocated includes all policy versions and held QUEUED/UNKNOWN
	// reservations, not just settled releases. The scoped adapter proves it.
	AlreadyReallocated           funds.Money                `json:"already_reallocated_cents"`
	SeasonalWindows              []TemplateSeasonalWindow   `json:"seasonal_windows"`
	SeasonalAdoption             *TemplateSeasonalAdoption  `json:"seasonal_adoption,omitempty"`
	Intervention                 *TemplateInterventionEvent `json:"intervention,omitempty"`
	ProtectedReferences          []TemplatePolicyReference  `json:"protected_references"`
	StandingAuthorizationCovered bool                       `json:"standing_authorization_covered"`
	VerifiedProtectedCashDeficit *funds.Money               `json:"verified_protected_cash_deficit_cents,omitempty"`
}
type TemplateCommitment struct {
	ID        string      `json:"id"`
	Kind      string      `json:"kind"`
	PolicyID  funds.ID    `json:"policy_id"`
	VersionID funds.ID    `json:"version_id"`
	DueDate   string      `json:"due_date"`
	EndDate   string      `json:"end_date,omitempty"`
	Amount    funds.Money `json:"amount_cents"`
	AccountID *funds.ID   `json:"account_id,omitempty"`
	PayeeID   string      `json:"payee_id,omitempty"`
}
type TemplateCandidate struct {
	Kind                 string      `json:"kind"`
	SubjectID            funds.ID    `json:"subject_id"`
	TargetID             *funds.ID   `json:"target_id,omitempty"`
	AmountCap            funds.Money `json:"amount_cap_cents"`
	RequiresConfirmation bool        `json:"requires_confirmation"`
	Reasons              []string    `json:"reasons"`
}
type TemplateGoalDemand struct {
	GoalID           funds.ID    `json:"goal_id"`
	Minimum          funds.Money `json:"minimum_cents"`
	Desired          funds.Money `json:"desired_cents"`
	Maximum          funds.Money `json:"maximum_cents"`
	Importance       int         `json:"importance"`
	EarliestIncomeAt time.Time   `json:"earliest_income_at"`
}
type TemplatePreview struct {
	Protocol             string               `json:"protocol"`
	Template             TemplateName         `json:"template_name"`
	ConfigurationHash    string               `json:"configuration_hash"`
	InputHash            string               `json:"input_hash"`
	State                string               `json:"state"`
	Commitments          []TemplateCommitment `json:"commitments"`
	Candidates           []TemplateCandidate  `json:"candidates"`
	GoalDemands          []TemplateGoalDemand `json:"goal_demands"`
	Questions            []string             `json:"questions"`
	Reasons              []string             `json:"reasons"`
	Amount               funds.Money          `json:"amount_cents"`
	MinimumShortfall     funds.Money          `json:"minimum_shortfall_cents"`
	GuaranteeShortfall   funds.Money          `json:"guarantee_shortfall_cents"`
	BankAuthority        bool                 `json:"bank_authority"`
	FutureIncomeIncluded funds.Money          `json:"future_income_included_cents"`
}

func TemplateDueDate(year int, month time.Month, dueDay int) string {
	last := time.Date(year, month+1, 0, 0, 0, 0, 0, time.UTC).Day()
	if dueDay > last {
		dueDay = last
	}
	return time.Date(year, month, dueDay, 0, 0, 0, 0, time.UTC).Format("2006-01-02")
}
func templateMin(values ...int64) int64 {
	v := values[0]
	for _, next := range values[1:] {
		if next < v {
			v = next
		}
	}
	return v
}
func templateMax(a, b int64) int64 {
	if a > b {
		return a
	}
	return b
}
func templateMoney(v int64) (funds.Money, error) {
	value, err := funds.NewMoney(v)
	if err != nil {
		return funds.Money{}, ErrTemplateCapacity
	}
	return value, nil
}
func templateSum(values ...funds.Money) (funds.Money, error) {
	v, err := funds.SumMoney(values...)
	if err != nil {
		return funds.Money{}, ErrTemplateCapacity
	}
	return v, nil
}
func (f TemplateFacts) goal(id funds.ID) (TemplateGoalFact, bool) {
	for _, goal := range f.Goals {
		if goal.ID == id {
			return goal, true
		}
	}
	return TemplateGoalFact{}, false
}
func (f TemplateFacts) validate(scope TemplateOwnerScope, now time.Time) error {
	if !f.Complete || f.Scope != scope || !validHash(f.SourceHash) || now.IsZero() {
		return ErrTemplateFacts
	}
	if len(f.Accounts) > 100 || len(f.Goals) > 100 || len(f.Bills) > 10000 || len(f.Settlements) > 10000 || len(f.Income) > 100000 || len(f.History) > 100000 || len(f.HistoryAccounts) > 100 || len(f.Coverage) > 100 || len(f.Products) > 100 || len(f.Positions) > 10000 || len(f.SeasonalWindows) > 10 {
		return ErrTemplateCapacity
	}
	if f.CurrentSafeVerified && f.CurrentSafe.Cents() > f.CurrentCash.Cents() {
		return ErrTemplateFacts
	}
	seen := map[funds.ID]bool{}
	for _, account := range f.Accounts {
		if account.ID == (funds.ID{}) || !account.Verified || seen[account.ID] {
			return ErrTemplateFacts
		}
		seen[account.ID] = true
	}
	seen = map[funds.ID]bool{}
	for _, goal := range f.Goals {
		if goal.ID == (funds.ID{}) || goal.AccountID == (funds.ID{}) || !goal.Verified || seen[goal.ID] || goal.CashOwned.Cents() > goal.Owned.Cents() || goal.ReleaseableCash.Cents() > goal.CashOwned.Cents() || goal.ScopeAvailable.Cents() > goal.CashOwned.Cents() {
			return ErrTemplateFacts
		}
		seen[goal.ID] = true
	}
	seen = map[funds.ID]bool{}
	for _, income := range f.Income {
		if income.ID == (funds.ID{}) || seen[income.ID] || !income.Verified || income.OccurredAt.IsZero() || income.OccurredAt.After(now) {
			return ErrTemplateFacts
		}
		seen[income.ID] = true
	}
	return nil
}
func templateIncome(facts TemplateFacts, start time.Time) (funds.Money, error) {
	if !facts.IncomeComplete {
		return funds.Money{}, ErrTemplateFacts
	}
	total := funds.Money{}
	for _, income := range facts.Income {
		if !income.OccurredAt.Before(start) {
			var err error
			total, err = templateSum(total, income.Available)
			if err != nil {
				return total, err
			}
		}
	}
	return total, nil
}
func templateGoalPacing(version TemplateVersion, config *LongTermGoalConfig, goal TemplateGoalFact, facts TemplateFacts, now time.Time, timezone string) (TemplatePreview, error) {
	zone, err := TemplateLocation(timezone)
	if err != nil {
		return TemplatePreview{}, err
	}
	today := now.In(zone).Format("2006-01-02")
	if goal.PolicyID != version.PolicyID || goal.VersionID != version.VersionID || goal.MonthPeriod != now.In(zone).Format("2006-01") || !facts.CurrentSafeVerified {
		return TemplatePreview{}, ErrTemplateFacts
	}
	start, _, err := TemplateValidity(version.Compiled, version.ConfirmedAt, timezone)
	if err != nil {
		return TemplatePreview{}, err
	}
	if start.Before(version.ConfirmedAt) {
		start = version.ConfirmedAt
	}
	eligible, err := templateIncome(facts, start)
	if err != nil {
		return TemplatePreview{}, err
	}
	remaining := templateMax(0, config.Target.Cents()-goal.Owned.Cents())
	contributed := goal.MonthContributed.Cents()
	deadline, _ := TemplateDate(config.Deadline)
	slots := (deadline.Year()-now.In(zone).Year())*12 + int(deadline.Month()) - int(now.In(zone).Month()) + 1
	if slots < 1 {
		slots = 1
	}
	gross := new(big.Int).Add(big.NewInt(remaining), big.NewInt(contributed))
	gross.Add(gross, big.NewInt(int64(slots-1)))
	gross.Quo(gross, big.NewInt(int64(slots)))
	if !gross.IsInt64() {
		return TemplatePreview{}, ErrTemplateCapacity
	}
	total := templateMin(remaining+contributed, templateMax(config.Monthly.Min.Cents(), templateMin(gross.Int64(), config.Monthly.Max.Cents())))
	maximum := templateMin(remaining, templateMax(0, config.Monthly.Max.Cents()-contributed))
	minimum := templateMin(remaining, templateMax(0, config.Monthly.Min.Cents()-contributed))
	guarantee := templateMax(0, config.MinimumGuarantee.Cents()-goal.Owned.Cents())
	if config.Deadline <= today && !config.AllowPartial && !config.AllowDeferral {
		guarantee = templateMax(guarantee, remaining)
	}
	desired := templateMax(templateMin(remaining, templateMax(0, total-contributed), maximum), templateMin(guarantee, maximum))
	available := templateMin(eligible.Cents(), facts.CurrentSafe.Cents(), maximum)
	suggested := templateMin(desired, available)
	minimumShortfall := templateMax(0, minimum-available)
	guaranteeShortfall := templateMax(0, guarantee-available)
	result := TemplatePreview{State: "READY"}
	switch {
	case remaining == 0:
		result.State = "COMPLETE"
		suggested = 0
	case contributed > config.Monthly.Max.Cents():
		result.State = "MONTHLY_MAX_ALREADY_EXCEEDED"
		suggested = 0
	case guaranteeShortfall > 0:
		result.State = "HARD_GUARANTEE_SHORTFALL"
		if guarantee == remaining && config.Deadline <= today {
			result.State = "DEADLINE_BLOCKED"
		}
		suggested = 0
	case minimumShortfall > 0 && !config.AllowPartial:
		result.State = "MINIMUM_SHORTFALL"
		suggested = 0
	case suggested < desired:
		result.State = "PARTIAL"
	case today > config.Deadline:
		result.State = "OVERDUE_READY"
	}
	result.Amount, _ = templateMoney(suggested)
	result.MinimumShortfall, _ = templateMoney(minimumShortfall)
	result.GuaranteeShortfall, _ = templateMoney(guaranteeShortfall)
	minAmount, _ := templateMoney(templateMax(minimum, guarantee))
	desiredAmount, _ := templateMoney(desired)
	maxAmount, _ := templateMoney(maximum)
	result.GoalDemands = []TemplateGoalDemand{{goal.ID, minAmount, desiredAmount, maxAmount, config.Importance, start}}
	return result, nil
}

// EstimateLivingReserve uses covered natural dates, confirmed consumption and
// exact nearest rank. Unknown economic roles make history incomplete; internal
// transfers, unconfirmed categories and optional one-offs cannot inflate it.
func EstimateLivingReserve(config LivingReserveConfig, facts TemplateFacts, referenceDate string) (funds.Money, error) {
	if len(facts.History) > 100000 || len(facts.Coverage) > 100 || len(facts.HistoryAccounts) > 100 {
		return funds.Money{}, ErrTemplateCapacity
	}
	if config.Method.LookbackDays < 1 || config.Method.LookbackDays > 366 || config.HorizonDays < 1 || config.HorizonDays > config.Method.LookbackDays {
		return funds.Money{}, ErrTemplateCapacity
	}
	end, err := TemplateDate(referenceDate)
	if err != nil {
		return funds.Money{}, err
	}
	first := end.AddDate(0, 0, -config.Method.LookbackDays)
	if first.Year() < 1 || len(facts.HistoryAccounts) == 0 || !validTemplateIDs(facts.HistoryAccounts, 100) {
		return funds.Money{}, ErrTemplateFacts
	}
	coverage := map[funds.ID]map[string]bool{}
	for _, entry := range facts.Coverage {
		if coverage[entry.AccountID] != nil || len(entry.Dates) > 366 {
			return funds.Money{}, ErrTemplateFacts
		}
		dates := map[string]bool{}
		for _, day := range entry.Dates {
			if _, err := TemplateDate(day); err != nil || dates[day] {
				return funds.Money{}, ErrTemplateFacts
			}
			dates[day] = true
		}
		coverage[entry.AccountID] = dates
	}
	accounts := map[funds.ID]bool{}
	for _, id := range facts.HistoryAccounts {
		accounts[id] = true
		for day := first; day.Before(end); day = day.AddDate(0, 0, 1) {
			if !coverage[id][day.Format("2006-01-02")] {
				return funds.Money{}, ErrTemplateFacts
			}
		}
	}
	daily := map[string]funds.Money{}
	for day := first; day.Before(end); day = day.AddDate(0, 0, 1) {
		daily[day.Format("2006-01-02")] = funds.Money{}
	}
	seen := map[funds.ID]bool{}
	for _, transaction := range facts.History {
		if transaction.ID == (funds.ID{}) || seen[transaction.ID] || transaction.Amount.IsZero() {
			return funds.Money{}, ErrTemplateFacts
		}
		seen[transaction.ID] = true
		if _, err := TemplateDate(transaction.Date); err != nil {
			return funds.Money{}, err
		}
		if transaction.Direction != "CREDIT" && transaction.Direction != "DEBIT" {
			return funds.Money{}, ErrTemplateFacts
		}
		if transaction.EconomicRole != "CONSUMPTION" && transaction.EconomicRole != "NON_CONSUMPTION" && transaction.EconomicRole != "UNKNOWN" {
			return funds.Money{}, ErrTemplateFacts
		}
		if !accounts[transaction.AccountID] || transaction.Date < first.Format("2006-01-02") || transaction.Date >= referenceDate {
			continue
		}
		if transaction.EconomicRole == "UNKNOWN" {
			return funds.Money{}, ErrTemplateFacts
		}
		selected := false
		for _, category := range config.Method.EssentialCategories {
			if category == transaction.Category {
				selected = true
			}
		}
		if transaction.Direction != "DEBIT" || transaction.EconomicRole != "CONSUMPTION" || !transaction.CategoryConfirmed || !selected || (config.Method.ExcludeOneOff && transaction.OneOff) {
			continue
		}
		value, err := templateSum(daily[transaction.Date], transaction.Amount)
		if err != nil {
			return funds.Money{}, err
		}
		daily[transaction.Date] = value
	}
	windows := []int64{}
	for offset := 0; offset <= config.Method.LookbackDays-config.HorizonDays; offset++ {
		total := funds.Money{}
		for d := 0; d < config.HorizonDays; d++ {
			value := daily[first.AddDate(0, 0, offset+d).Format("2006-01-02")]
			total, err = templateSum(total, value)
			if err != nil {
				return funds.Money{}, err
			}
		}
		windows = append(windows, total.Cents())
	}
	sort.Slice(windows, func(i, j int) bool { return windows[i] < windows[j] })
	rank, err := config.Method.Quantile.Rank(len(windows))
	if err != nil {
		return funds.Money{}, err
	}
	base, _ := templateMoney(windows[rank-1])
	return templateSum(base, config.ExtraBuffer)
}

// Quantile is an exact decimal string in the new protocol. Legacy FULL_V1
// float JSON/hash semantics remain frozen and are not silently reinterpreted.
type Quantile string

var quantileSyntax = regexp.MustCompile(`^(0(\.[0-9]{1,18})?|1(\.0{1,18})?)$`)

func parseQuantileString(value string) (Quantile, error) {
	if !quantileSyntax.MatchString(value) {
		return "", ErrTemplate
	}
	ratio, ok := new(big.Rat).SetString(value)
	if !ok || ratio.Sign() <= 0 || ratio.Cmp(big.NewRat(1, 1)) > 0 {
		return "", ErrTemplate
	}
	if strings.Contains(value, ".") {
		value = strings.TrimRight(strings.TrimRight(value, "0"), ".")
	}
	return Quantile(value), nil
}

func (q *Quantile) UnmarshalJSON(raw []byte) error {
	var value string
	if json.Unmarshal(raw, &value) != nil {
		return ErrTemplate
	}
	checked, err := parseQuantileString(value)
	if err != nil {
		return err
	}
	*q = checked
	return nil
}
func (q Quantile) Rank(count int) (int, error) {
	if count < 1 {
		return 0, ErrTemplateFacts
	}
	checked, err := parseQuantileString(string(q))
	if err != nil {
		return 0, ErrTemplate
	}
	ratio, _ := new(big.Rat).SetString(string(checked))
	n := new(big.Int).Mul(ratio.Num(), big.NewInt(int64(count)))
	n.Add(n, new(big.Int).Sub(ratio.Denom(), big.NewInt(1)))
	n.Quo(n, ratio.Denom())
	return int(n.Int64()), nil
}

type TemplateCommon struct {
	Name       *string `json:"name,omitempty"`
	ValidFrom  *string `json:"valid_from,omitempty"`
	ValidUntil *string `json:"valid_until,omitempty"`
}
type TemplateConfiguration interface {
	templateConfiguration()
	CommonFields() *TemplateCommon
}

func (*TemplateCommon) templateConfiguration()          {}
func (c *TemplateCommon) CommonFields() *TemplateCommon { return c }

type TemplatePriority struct {
	Importance int         `json:"importance"`
	Minimum    funds.Money `json:"minimum_cents"`
	Reducible  bool        `json:"reducible"`
	Deferrable bool        `json:"deferrable"`
}
type TemplateAmountRule struct {
	Kind      string      `json:"kind"`
	Amount    funds.Money `json:"amount_cents,omitempty"`
	Min       funds.Money `json:"min_cents,omitempty"`
	Max       funds.Money `json:"max_cents,omitempty"`
	AccountID *funds.ID   `json:"account_id,omitempty"`
}

func (r TemplateAmountRule) MarshalJSON() ([]byte, error) {
	switch r.Kind {
	case "exact":
		return json.Marshal(struct {
			Kind   string      `json:"kind"`
			Amount funds.Money `json:"amount_cents"`
		}{r.Kind, r.Amount})
	case "range":
		return json.Marshal(struct {
			Kind string      `json:"kind"`
			Min  funds.Money `json:"min_cents"`
			Max  funds.Money `json:"max_cents"`
		}{r.Kind, r.Min, r.Max})
	case "bill_balance":
		return json.Marshal(struct {
			Kind      string    `json:"kind"`
			AccountID *funds.ID `json:"account_id"`
		}{r.Kind, r.AccountID})
	default:
		return nil, ErrTemplate
	}
}

type TemplateMonthlyContribution struct {
	Min    funds.Money `json:"min_cents"`
	Target funds.Money `json:"target_cents"`
	Max    funds.Money `json:"max_cents"`
}
type TemplateDateWindow struct {
	Start string `json:"start"`
	End   string `json:"end"`
}
type RecurringObligationConfig struct {
	TemplateCommon
	Type              string             `json:"type"`
	PayeeID           string             `json:"payee_id"`
	AmountRule        TemplateAmountRule `json:"amount_rule"`
	DueDay            int                `json:"due_day"`
	PrepareDaysBefore int                `json:"prepare_days_before"`
	AutoExecute       bool               `json:"auto_execute"`
	Priority          TemplatePriority   `json:"priority"`
}
type ReserveMethod struct {
	Name                string   `json:"name"`
	LookbackDays        int      `json:"lookback_days"`
	Quantile            Quantile `json:"quantile"`
	EssentialCategories []string `json:"essential_categories"`
	ExcludeOneOff       bool     `json:"exclude_one_off"`
}
type LivingReserveConfig struct {
	TemplateCommon
	Type                        string        `json:"type"`
	HorizonDays                 int           `json:"horizon_days"`
	Method                      ReserveMethod `json:"method"`
	ExtraBuffer                 funds.Money   `json:"extra_buffer_cents"`
	ReconfirmOnBoundaryCrossing bool          `json:"reconfirm_on_boundary_crossing"`
}
type EmergencyBufferConfig struct {
	TemplateCommon
	Type   string      `json:"type"`
	Amount funds.Money `json:"amount_cents"`
}
type DatedExpenseConfig struct {
	TemplateCommon
	Type                   string                      `json:"type"`
	Window                 TemplateDateWindow          `json:"window"`
	Amount                 TemplateMonthlyContribution `json:"amount"`
	Priority               TemplatePriority            `json:"priority"`
	MustNotReducePolicyIDs []funds.ID                  `json:"must_not_reduce_policy_ids"`
}
type LongTermGoalConfig struct {
	TemplateCommon
	Type                          string                      `json:"type"`
	Target                        funds.Money                 `json:"target_cents"`
	Deadline                      string                      `json:"deadline"`
	Monthly                       TemplateMonthlyContribution `json:"monthly_contribution"`
	Importance                    int                         `json:"importance"`
	MinimumGuarantee              funds.Money                 `json:"minimum_guarantee_cents"`
	AllowPartial                  bool                        `json:"allow_partial"`
	DynamicReserveMathVersion     *string                     `json:"dynamic_reserve_math_version,omitempty"`
	AllowDeferral                 bool                        `json:"allow_deferral"`
	DeferralCostPerDay            funds.Money                 `json:"deferral_cost_cents_per_day"`
	AssetPolicyID                 *funds.ID                   `json:"asset_policy_id,omitempty"`
	CrossGoalReallocationAllowed  bool                        `json:"cross_goal_reallocation_allowed"`
	CrossGoalReallocationPolicyID *funds.ID                   `json:"cross_goal_reallocation_policy_id,omitempty"`
}
type PeriodicTransferConfig struct {
	TemplateCommon
	Type              string             `json:"type"`
	SourceAccountID   funds.ID           `json:"source_account_id"`
	PayeeID           string             `json:"payee_id"`
	AmountRule        TemplateAmountRule `json:"amount_rule"`
	DueDay            int                `json:"due_day"`
	PrepareDaysBefore int                `json:"prepare_days_before"`
	SingleActionCap   funds.Money        `json:"single_action_cap_cents"`
	AutoExecute       bool               `json:"auto_execute"`
}
type AssetAuthorizationConfig struct {
	TemplateCommon
	Type                            string      `json:"type"`
	Scope                           string      `json:"scope"`
	GoalID                          *funds.ID   `json:"goal_id,omitempty"`
	AllowedAssetClasses             []string    `json:"allowed_asset_classes"`
	MaxAutoManaged                  funds.Money `json:"max_auto_managed_cents"`
	SingleActionCap                 funds.Money `json:"single_action_cap_cents"`
	MaxRedemptionDelayDays          int         `json:"max_redemption_delay_days"`
	MaxLockDays                     int         `json:"max_lock_days"`
	MaxPrincipalRiskLevel           int         `json:"max_principal_risk_level"`
	AllowAutoRecoveryWithoutPenalty bool        `json:"allow_auto_recovery_without_penalty"`
	AllowEarlyWithdrawalWithPenalty bool        `json:"allow_early_withdrawal_with_penalty"`
}
type RecoveryConfig struct {
	TemplateCommon
	Type                            string      `json:"type"`
	Scope                           string      `json:"scope"`
	GoalID                          *funds.ID   `json:"goal_id,omitempty"`
	AssetPolicyID                   funds.ID    `json:"asset_policy_id"`
	Triggers                        []string    `json:"triggers"`
	SingleActionCap                 funds.Money `json:"single_action_cap_cents"`
	MaxRedemptionDelayDays          int         `json:"max_redemption_delay_days"`
	AllowAutoRecoveryWithoutPenalty bool        `json:"allow_auto_recovery_without_penalty"`
	MaxFee                          funds.Money `json:"max_fee_cents"`
	MaxLoss                         funds.Money `json:"max_loss_cents"`
}
type GoalAllocationConfig struct {
	TemplateCommon
	Type                string      `json:"type"`
	GoalIDs             []funds.ID  `json:"goal_ids"`
	Method              string      `json:"method"`
	FundsScope          string      `json:"funds_scope"`
	MaxSingleAllocation funds.Money `json:"max_single_allocation_cents"`
}
type CrossGoalReallocationConfig struct {
	TemplateCommon
	Type                   string      `json:"type"`
	ScopeVersion           string      `json:"scope_version,omitempty"`
	DestinationScope       string      `json:"destination_scope"`
	Enabled                bool        `json:"enabled"`
	SourceGoalIDs          []funds.ID  `json:"source_goal_ids"`
	TargetGoalIDs          []funds.ID  `json:"target_goal_ids,omitempty"`
	EmergencyConditions    []string    `json:"emergency_conditions,omitempty"`
	SingleActionCap        funds.Money `json:"single_action_cap_cents"`
	TotalCap               funds.Money `json:"total_cap_cents"`
	MustNotReducePolicyIDs []funds.ID  `json:"must_not_reduce_policy_ids,omitempty"`
}
type SeasonalReserveConfig struct {
	TemplateCommon
	Type                     string             `json:"type"`
	HolidayCode              string             `json:"holiday_code"`
	Window                   TemplateDateWindow `json:"window"`
	LookbackDays             int                `json:"lookback_days"`
	MinimumHistoricalWindows int                `json:"minimum_historical_windows"`
	Quantile                 Quantile           `json:"quantile"`
	EssentialCategories      []string           `json:"essential_categories"`
	AdjustmentCap            funds.Money        `json:"adjustment_cap_cents"`
	RequiresConfirmation     bool               `json:"requires_confirmation"`
	AdviceOnly               bool               `json:"advice_only"`
}

var mandatoryInterventions = []string{"NEW_PAYEE", "OUT_OF_AUTHORIZATION", "NEW_ASSET_CLASS", "NEW_LOSS", "NEW_RISK", "VALUE_PREFERENCE_CHANGE", "UNAUTHORIZED_CONFLICT_REPAIR"}

func MandatoryInterventionReasons() []string { return append([]string(nil), mandatoryInterventions...) }

var defaultInterventions = []string{"ACTION_SET_CHANGED", "AUTONOMOUS_AMOUNT_DECREASE", "RECOVERY_REQUIRED", "GOAL_MINIMUM_SHORTFALL", "NEW_PAYEE", "OUT_OF_AUTHORIZATION", "NEW_ASSET_CLASS", "NEW_LOSS", "NEW_RISK", "VALUE_PREFERENCE_CHANGE", "UNAUTHORIZED_CONFLICT_REPAIR"}

type InterventionConfig struct {
	TemplateCommon
	Type                         string   `json:"type"`
	MustAskOn                    []string `json:"must_ask_on"`
	DeduplicateByBoundaryEvent   bool     `json:"deduplicate_by_boundary_event"`
	MinimumReaskIntervalSeconds  int      `json:"minimum_reask_interval_seconds"`
	SafetyEventsBypassThrottle   bool     `json:"safety_events_bypass_throttle"`
	SilentWhenActionSetUnchanged bool     `json:"silent_when_action_set_unchanged"`
}
type CompiledTemplate struct {
	Protocol      string          `json:"protocol"`
	Name          TemplateName    `json:"template_name"`
	Configuration json.RawMessage `json:"configuration"`
	Hash          string          `json:"configuration_hash"`
}

func (c CompiledTemplate) Decode() (TemplateConfiguration, error) {
	if c.Protocol != TemplateProtocol || !validHash(c.Hash) {
		return nil, ErrTemplate
	}
	parsed, value, err := compileTemplate(c.Name, c.Configuration)
	if err != nil || parsed.Hash != c.Hash || !bytes.Equal(parsed.Configuration, c.Configuration) {
		return nil, ErrTemplate
	}
	return value, nil
}
func CompileTemplate(name TemplateName, raw []byte) (CompiledTemplate, error) {
	compiled, _, err := compileTemplate(name, raw)
	return compiled, err
}
func templateDefaults(name TemplateName) TemplateConfiguration {
	priority := TemplatePriority{Importance: 50}
	switch name {
	case RecurringObligationTemplate:
		return &RecurringObligationConfig{Priority: priority}
	case LivingReserveTemplate:
		return &LivingReserveConfig{Method: ReserveMethod{ExcludeOneOff: true}, ReconfirmOnBoundaryCrossing: true}
	case EmergencyBufferTemplate:
		return &EmergencyBufferConfig{}
	case DatedExpenseTemplate:
		return &DatedExpenseConfig{Priority: priority, MustNotReducePolicyIDs: []funds.ID{}}
	case LongTermGoalTemplate:
		return &LongTermGoalConfig{Importance: 50}
	case PeriodicTransferTemplate:
		return &PeriodicTransferConfig{}
	case AssetAuthorizationTemplate:
		return &AssetAuthorizationConfig{}
	case RecoveryTemplate:
		return &RecoveryConfig{}
	case GoalAllocationTemplate:
		return &GoalAllocationConfig{Method: "lexicographic_v1", FundsScope: "NEW_UNASSIGNED_SAFE_FUNDS"}
	case CrossGoalReallocationTemplate:
		return &CrossGoalReallocationConfig{DestinationScope: "PROTECTED_CASH", SourceGoalIDs: []funds.ID{}, EmergencyConditions: []string{}}
	case SeasonalReserveTemplate:
		return &SeasonalReserveConfig{RequiresConfirmation: true, AdviceOnly: true}
	case InterventionTemplate:
		return &InterventionConfig{MustAskOn: append([]string(nil), defaultInterventions...), DeduplicateByBoundaryEvent: true, SafetyEventsBypassThrottle: true, SilentWhenActionSetUnchanged: true}
	default:
		return nil
	}
}

var jsonUnmarshaler = reflect.TypeFor[json.Unmarshaler]()

func exactTemplateFields(value any, t reflect.Type) error {
	if value == nil {
		if t.Kind() == reflect.Pointer {
			return nil
		}
		return ErrTemplate
	}
	for t.Kind() == reflect.Pointer {
		t = t.Elem()
	}
	if reflect.PointerTo(t).Implements(jsonUnmarshaler) {
		return nil
	}
	switch t.Kind() {
	case reflect.Struct:
		object, ok := value.(map[string]any)
		if !ok {
			return ErrTemplate
		}
		fields := map[string]reflect.Type{}
		var collect func(reflect.Type)
		collect = func(st reflect.Type) {
			for i := 0; i < st.NumField(); i++ {
				f := st.Field(i)
				if f.PkgPath != "" {
					continue
				}
				if f.Anonymous {
					collect(f.Type)
					continue
				}
				tag := strings.Split(f.Tag.Get("json"), ",")[0]
				if tag != "" && tag != "-" {
					fields[tag] = f.Type
				}
			}
		}
		collect(t)
		for key, child := range object {
			ft, found := fields[key]
			if !found {
				return ErrTemplate
			}
			if err := exactTemplateFields(child, ft); err != nil {
				return err
			}
		}
	case reflect.Slice:
		items, ok := value.([]any)
		if !ok {
			return ErrTemplate
		}
		for _, item := range items {
			if err := exactTemplateFields(item, t.Elem()); err != nil {
				return err
			}
		}
	}
	return nil
}
func requiredTemplateFields(object map[string]any, keys ...string) error {
	for _, key := range keys {
		if _, ok := object[key]; !ok {
			return fmt.Errorf("%w: missing %s", ErrTemplate, key)
		}
	}
	return nil
}
func compileTemplate(name TemplateName, raw []byte) (CompiledTemplate, TemplateConfiguration, error) {
	if len(raw) == 0 || len(raw) > MaxTemplateBytes {
		return CompiledTemplate{}, nil, ErrTemplateCapacity
	}
	object, err := audit.ParseRawObject(raw)
	if err != nil {
		return CompiledTemplate{}, nil, ErrTemplate
	}
	value := templateDefaults(name)
	if value == nil {
		return CompiledTemplate{}, nil, ErrTemplate
	}
	if err = requiredTemplateFields(object, "type"); err != nil {
		return CompiledTemplate{}, nil, err
	}
	if err = exactTemplateFields(object, reflect.TypeOf(value)); err != nil {
		return CompiledTemplate{}, nil, err
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(value) != nil {
		return CompiledTemplate{}, nil, ErrTemplate
	}
	if err = validateTemplate(name, value, object); err != nil {
		return CompiledTemplate{}, nil, err
	}
	normalized, err := json.Marshal(value)
	if err != nil {
		return CompiledTemplate{}, nil, ErrTemplate
	}
	compiled := CompiledTemplate{TemplateProtocol, name, normalized, ""}
	compiled.Hash = digest(struct {
		Protocol      string
		Name          TemplateName
		Configuration json.RawMessage
	}{TemplateProtocol, name, normalized})
	return compiled, value, nil
}
func TemplateLocation(name string) (*time.Location, error) {
	switch name {
	case "UTC":
		return time.UTC, nil
	case "Asia/Shanghai":
		return time.FixedZone("Asia/Shanghai", 8*3600), nil
	default:
		return nil, ErrTemplate
	}
}
func TemplateDate(value string) (time.Time, error) {
	day, err := time.Parse("2006-01-02", value)
	if err != nil || day.Year() < 1 || day.Year() > 9999 || day.Format("2006-01-02") != value {
		return time.Time{}, ErrTemplate
	}
	return day, nil
}
func validateTemplateCommon(c *TemplateCommon) error {
	if c.Name != nil {
		name := strings.TrimSpace(*c.Name)
		if name == "" || !utf8.ValidString(name) || utf8.RuneCountInString(name) > 120 {
			return ErrTemplate
		}
		c.Name = &name
	}
	for _, value := range []*string{c.ValidFrom, c.ValidUntil} {
		if value != nil {
			if _, err := TemplateDate(*value); err != nil {
				return err
			}
		}
	}
	if c.ValidFrom != nil && c.ValidUntil != nil && *c.ValidFrom > *c.ValidUntil {
		return ErrTemplate
	}
	return nil
}
func validTemplateIDs(ids []funds.ID, max int) bool {
	if len(ids) > max {
		return false
	}
	seen := map[funds.ID]bool{}
	for _, id := range ids {
		if id == (funds.ID{}) || seen[id] {
			return false
		}
		seen[id] = true
	}
	return true
}
func validTemplateStrings(values []string, allowed []string, min, max int, unique bool) bool {
	if len(values) < min || len(values) > max {
		return false
	}
	seen := map[string]bool{}
	for _, value := range values {
		if unique && seen[value] {
			return false
		}
		seen[value] = true
		if len(allowed) > 0 {
			found := false
			for _, a := range allowed {
				if value == a {
					found = true
				}
			}
			if !found {
				return false
			}
		}
	}
	return true
}
func normalizeCategories(values []string, unique bool) bool {
	for i, value := range values {
		values[i] = strings.TrimSpace(value)
		if values[i] == "" || !utf8.ValidString(values[i]) || utf8.RuneCountInString(values[i]) > 48 {
			return false
		}
	}
	return validTemplateStrings(values, nil, 1, 48, unique)
}
func validPriority(p TemplatePriority) bool { return p.Importance >= 0 && p.Importance <= 100 }
func validMonthly(m TemplateMonthlyContribution) bool {
	return m.Min.Cents() <= m.Target.Cents() && m.Target.Cents() <= m.Max.Cents()
}
func validScopedGoal(scope string, id *funds.ID) bool {
	return (scope == "goal" && id != nil && *id != (funds.ID{})) || (scope == "general_idle_funds" && id == nil)
}
func validOptionalID(id *funds.ID) bool { return id == nil || *id != (funds.ID{}) }
func nestedFields(raw map[string]any, key string, required ...string) error {
	value, ok := raw[key].(map[string]any)
	if !ok {
		return ErrTemplate
	}
	return requiredTemplateFields(value, required...)
}
func validateAmountRule(rule TemplateAmountRule, raw map[string]any, bill bool) error {
	if err := requiredTemplateFields(raw, "kind"); err != nil {
		return err
	}
	allowed := map[string]bool{"kind": true}
	switch rule.Kind {
	case "exact":
		allowed["amount_cents"] = true
		if requiredTemplateFields(raw, "amount_cents") != nil {
			return ErrTemplate
		}
	case "range":
		allowed["min_cents"], allowed["max_cents"] = true, true
		if requiredTemplateFields(raw, "min_cents", "max_cents") != nil || rule.Min.Cents() > rule.Max.Cents() {
			return ErrTemplate
		}
	case "bill_balance":
		if !bill || rule.AccountID == nil || *rule.AccountID == (funds.ID{}) {
			return ErrTemplate
		}
		allowed["account_id"] = true
	default:
		return ErrTemplate
	}
	for key := range raw {
		if !allowed[key] {
			return ErrTemplate
		}
	}
	return nil
}
func validateWindow(common *TemplateCommon, window TemplateDateWindow) bool {
	a, err := TemplateDate(window.Start)
	if err != nil {
		return false
	}
	b, err := TemplateDate(window.End)
	if err != nil || b.Before(a) {
		return false
	}
	return (common.ValidFrom == nil || window.Start >= *common.ValidFrom) && (common.ValidUntil == nil || window.End <= *common.ValidUntil)
}
func validateTemplate(name TemplateName, value TemplateConfiguration, raw map[string]any) error {
	if err := validateTemplateCommon(value.CommonFields()); err != nil {
		return err
	}
	amountRaw := func() map[string]any { v, _ := raw["amount_rule"].(map[string]any); return v }
	switch v := value.(type) {
	case *RecurringObligationConfig:
		v.PayeeID = strings.TrimSpace(v.PayeeID)
		if requiredTemplateFields(raw, "payee_id", "amount_rule", "due_day") != nil || v.Type != "recurring_obligation" || strings.TrimSpace(v.PayeeID) == "" || utf8.RuneCountInString(v.PayeeID) > 160 || v.DueDay < 1 || v.DueDay > 31 || v.PrepareDaysBefore < 0 || v.PrepareDaysBefore > 3650 || !validPriority(v.Priority) {
			return ErrTemplate
		}
		return validateAmountRule(v.AmountRule, amountRaw(), true)
	case *LivingReserveConfig:
		if requiredTemplateFields(raw, "horizon_days", "method") != nil || nestedFields(raw, "method", "name", "lookback_days", "quantile", "essential_categories") != nil || v.Type != "living_reserve" || v.Method.Name != "rolling_window_quantile" || v.HorizonDays < 1 || v.Method.LookbackDays < v.HorizonDays || v.Method.LookbackDays > 3650 || !normalizeCategories(v.Method.EssentialCategories, false) {
			return ErrTemplate
		}
		_, err := v.Method.Quantile.Rank(1)
		return err
	case *EmergencyBufferConfig:
		if v.Type != "emergency_buffer" || requiredTemplateFields(raw, "amount_cents") != nil {
			return ErrTemplate
		}
	case *DatedExpenseConfig:
		if v.Type != "dated_expense" || requiredTemplateFields(raw, "window", "amount") != nil || nestedFields(raw, "window", "start", "end") != nil || nestedFields(raw, "amount", "min_cents", "target_cents", "max_cents") != nil || !validMonthly(v.Amount) || !validPriority(v.Priority) || v.Priority.Minimum.Cents() > v.Amount.Max.Cents() || !validateWindow(&v.TemplateCommon, v.Window) || !validTemplateIDs(v.MustNotReducePolicyIDs, 32) {
			return ErrTemplate
		}
	case *LongTermGoalConfig:
		if v.Type != "long_term_goal" || requiredTemplateFields(raw, "target_cents", "deadline", "monthly_contribution") != nil || nestedFields(raw, "monthly_contribution", "min_cents", "target_cents", "max_cents") != nil || v.Target.IsZero() || !validMonthly(v.Monthly) || v.Importance < 0 || v.Importance > 100 || v.MinimumGuarantee.Cents() > v.Target.Cents() || (!v.AllowDeferral && !v.DeferralCostPerDay.IsZero()) || v.CrossGoalReallocationAllowed != (v.CrossGoalReallocationPolicyID != nil) || !validOptionalID(v.AssetPolicyID) || !validOptionalID(v.CrossGoalReallocationPolicyID) {
			return ErrTemplate
		}
		if _, err := TemplateDate(v.Deadline); err != nil {
			return err
		}
		if (v.ValidFrom != nil && v.Deadline < *v.ValidFrom) || (v.ValidUntil != nil && v.Deadline > *v.ValidUntil) || (v.DynamicReserveMathVersion != nil && *v.DynamicReserveMathVersion != "SAFE_PARTIAL_V2") {
			return ErrTemplate
		}
	case *PeriodicTransferConfig:
		v.PayeeID = strings.TrimSpace(v.PayeeID)
		if v.Type != "periodic_transfer" || requiredTemplateFields(raw, "source_account_id", "payee_id", "amount_rule", "due_day", "single_action_cap_cents") != nil || v.SourceAccountID == (funds.ID{}) || strings.TrimSpace(v.PayeeID) == "" || utf8.RuneCountInString(v.PayeeID) > 160 || v.DueDay < 1 || v.DueDay > 31 || v.PrepareDaysBefore < 0 || v.PrepareDaysBefore > 3650 || v.SingleActionCap.IsZero() {
			return ErrTemplate
		}
		if err := validateAmountRule(v.AmountRule, amountRaw(), false); err != nil {
			return err
		}
		upper := v.AmountRule.Amount
		if v.AmountRule.Kind == "range" {
			upper = v.AmountRule.Max
		}
		if upper.Cents() > v.SingleActionCap.Cents() {
			return ErrTemplate
		}
	case *AssetAuthorizationConfig:
		if v.Type != "asset_authorization" || requiredTemplateFields(raw, "scope", "allowed_asset_classes", "max_auto_managed_cents", "single_action_cap_cents", "max_redemption_delay_days", "max_lock_days") != nil || !validScopedGoal(v.Scope, v.GoalID) || !validTemplateStrings(v.AllowedAssetClasses, []string{"CASH", "CASH_MGMT_T0", "CASH_MGMT_T1", "FIXED_DEPOSIT_7D", "FIXED_DEPOSIT_30D", "FIXED_DEPOSIT_90D", "LOW_RISK_TERM"}, 1, 7, true) || v.SingleActionCap.Cents() > v.MaxAutoManaged.Cents() || v.MaxRedemptionDelayDays < 0 || v.MaxRedemptionDelayDays > 3660 || v.MaxLockDays < 0 || v.MaxLockDays > 3660 || v.MaxPrincipalRiskLevel < 0 || v.MaxPrincipalRiskLevel > 5 {
			return ErrTemplate
		}
	case *RecoveryConfig:
		if v.Type != "recovery" || requiredTemplateFields(raw, "scope", "asset_policy_id", "triggers", "single_action_cap_cents", "max_redemption_delay_days") != nil || !validScopedGoal(v.Scope, v.GoalID) || v.AssetPolicyID == (funds.ID{}) || !validTemplateStrings(v.Triggers, []string{"BOUNDARY_SHRINK", "AUTHORIZATION_REVOKED", "POLICY_EXPIRED", "LIQUIDITY_SHORTFALL"}, 1, 4, true) || v.SingleActionCap.IsZero() || v.MaxRedemptionDelayDays < 0 || v.MaxRedemptionDelayDays > 3660 || !v.MaxFee.IsZero() || !v.MaxLoss.IsZero() {
			return ErrTemplate
		}
	case *GoalAllocationConfig:
		if v.Type != "goal_allocation" || requiredTemplateFields(raw, "goal_ids", "max_single_allocation_cents") != nil || len(v.GoalIDs) < 2 || !validTemplateIDs(v.GoalIDs, 32) || v.Method != "lexicographic_v1" || v.FundsScope != "NEW_UNASSIGNED_SAFE_FUNDS" || v.MaxSingleAllocation.IsZero() {
			return ErrTemplate
		}
	case *CrossGoalReallocationConfig:
		if v.Type != "cross_goal_reallocation" || !validTemplateIDs(v.SourceGoalIDs, 32) || !validTemplateIDs(v.TargetGoalIDs, 32) || !validTemplateIDs(v.MustNotReducePolicyIDs, 32) {
			return ErrTemplate
		}
		if v.ScopeVersion == "GOAL_TRANSFER_V1" {
			if _, present := raw["emergency_conditions"]; present {
				return ErrTemplate
			}
			if requiredTemplateFields(raw, "scope_version", "destination_scope", "enabled", "source_goal_ids", "target_goal_ids", "single_action_cap_cents", "total_cap_cents") != nil || v.DestinationScope != "GOAL" || len(v.SourceGoalIDs) < 1 || len(v.TargetGoalIDs) < 1 || v.SingleActionCap.IsZero() || v.SingleActionCap.Cents() > v.TotalCap.Cents() || v.ValidFrom == nil || v.ValidUntil == nil || len(v.EmergencyConditions) > 0 {
				return ErrTemplate
			}
		} else {
			for _, key := range []string{"scope_version", "target_goal_ids", "must_not_reduce_policy_ids"} {
				if _, present := raw[key]; present {
					return ErrTemplate
				}
			}
			if v.ScopeVersion != "" || v.DestinationScope != "PROTECTED_CASH" || len(v.TargetGoalIDs) > 0 || len(v.MustNotReducePolicyIDs) > 0 || !validTemplateStrings(v.EmergencyConditions, []string{"HARD_OBLIGATION_SHORTFALL", "LIVING_RESERVE_SHORTFALL", "EMERGENCY_BUFFER_SHORTFALL"}, 0, 3, true) {
				return ErrTemplate
			}
			if !v.Enabled {
				if !v.SingleActionCap.IsZero() || !v.TotalCap.IsZero() || len(v.EmergencyConditions) > 0 {
					return ErrTemplate
				}
			} else if len(v.SourceGoalIDs) == 0 || len(v.EmergencyConditions) == 0 || v.ValidFrom == nil || v.ValidUntil == nil || v.SingleActionCap.IsZero() || v.SingleActionCap.Cents() > v.TotalCap.Cents() {
				return ErrTemplate
			}
		}
	case *SeasonalReserveConfig:
		v.HolidayCode = strings.TrimSpace(v.HolidayCode)
		if v.Type != "seasonal_reserve" || requiredTemplateFields(raw, "holiday_code", "window", "lookback_days", "minimum_historical_windows", "quantile", "essential_categories", "adjustment_cap_cents") != nil || nestedFields(raw, "window", "start", "end") != nil || !validateWindow(&v.TemplateCommon, v.Window) || strings.TrimSpace(v.HolidayCode) == "" || utf8.RuneCountInString(v.HolidayCode) > 48 || v.LookbackDays < 1 || v.LookbackDays > 3650 || v.MinimumHistoricalWindows < 1 || v.MinimumHistoricalWindows > 10 || !normalizeCategories(v.EssentialCategories, true) || !v.RequiresConfirmation || !v.AdviceOnly {
			return ErrTemplate
		}
		a, _ := TemplateDate(v.Window.Start)
		b, _ := TemplateDate(v.Window.End)
		if (b.Unix()-a.Unix())/86400+1 > int64(v.LookbackDays) {
			return ErrTemplate
		}
		_, err := v.Quantile.Rank(1)
		return err
	case *InterventionConfig:
		if v.Type != "intervention" || !validTemplateStrings(v.MustAskOn, defaultInterventions, 7, 11, true) || v.MinimumReaskIntervalSeconds < 0 || v.MinimumReaskIntervalSeconds > 86400 || !v.DeduplicateByBoundaryEvent || !v.SafetyEventsBypassThrottle || !v.SilentWhenActionSetUnchanged {
			return ErrTemplate
		}
		for _, required := range mandatoryInterventions {
			found := false
			for _, reason := range v.MustAskOn {
				if reason == required {
					found = true
				}
			}
			if !found {
				return ErrTemplate
			}
		}
	default:
		return ErrTemplate
	}
	return nil
}
