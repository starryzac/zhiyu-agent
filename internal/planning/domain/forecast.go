package domain

import (
	"bytes"
	"errors"
	"sort"
	"strconv"
	"time"

	funds "zhiyu.local/zhiyu-go/internal/funds/domain"
	policy "zhiyu.local/zhiyu-go/internal/policy/domain"
)

const ForecastAlgorithm = "cash-protection-forecast-go-v1"
const MaxForecastDays = 365

var (
	ErrForecastInput    = errors.New("FORECAST_INPUT_INCOMPLETE")
	ErrForecastCapacity = errors.New("FORECAST_CAPACITY_EXCEEDED")
)

// These facts are supplied by a scoped complete application read. Retained
// liabilities/adoptions survive policy changes, suspension and revocation.
// Complete is an adapter precondition, never an assertion accepted from HTTP.
type ForecastObligation struct {
	ID         string      `json:"id"`
	PolicyID   funds.ID    `json:"policy_id"`
	VersionID  funds.ID    `json:"version_id"`
	DueDate    string      `json:"due_date"`
	Amount     funds.Money `json:"amount_cents"`
	Verified   bool        `json:"verified"`
	SourceHash string      `json:"source_hash"`
}

// A verified external bill is a cash obligation even when no policy authorizes
// its payment. Its identity is the actual bill, never a fabricated policy ID.
type ForecastExternalLiability struct {
	ID         string      `json:"id"`
	DueDate    string      `json:"due_date"`
	Remaining  funds.Money `json:"remaining_cents"`
	Verified   bool        `json:"verified"`
	SourceHash string      `json:"source_hash"`
}
type ForecastFloor struct {
	ID         string      `json:"id"`
	PolicyID   funds.ID    `json:"policy_id"`
	VersionID  funds.ID    `json:"version_id"`
	StartDate  string      `json:"start_date"`
	EndDate    string      `json:"end_date"`
	Amount     funds.Money `json:"amount_cents"`
	Verified   bool        `json:"verified"`
	SourceHash string      `json:"source_hash"`
}
type ForecastIncome struct {
	ID             funds.ID    `json:"id"`
	ExpectedAt     time.Time   `json:"expected_at"`
	Amount         funds.Money `json:"amount_cents"`
	AssumptionHash string      `json:"assumption_hash"`
}

// Principal returns are separately proven obligations of an existing position.
// Returning principal is never a new income origin. Unproven yield is omitted.
type ForecastPrincipalReturn struct {
	ID         funds.ID    `json:"id"`
	Date       string      `json:"date"`
	Amount     funds.Money `json:"amount_cents"`
	GoalID     *funds.ID   `json:"goal_id,omitempty"`
	Verified   bool        `json:"verified"`
	SourceHash string      `json:"source_hash"`
}
type ForecastInput struct {
	Scope               policy.TemplateOwnerScope   `json:"scope"`
	AsOf                time.Time                   `json:"as_of"`
	Timezone            string                      `json:"timezone"`
	HorizonDays         int                         `json:"horizon_days"`
	Complete            bool                        `json:"complete"`
	InventoryHash       string                      `json:"inventory_hash"`
	Facts               policy.TemplateFacts        `json:"facts"`
	Versions            []policy.TemplateVersion    `json:"versions"`
	RetainedObligations []ForecastObligation        `json:"retained_obligations"`
	ExternalLiabilities []ForecastExternalLiability `json:"external_liabilities,omitempty"`
	RetainedFloors      []ForecastFloor             `json:"retained_floors"`
	UnassignedGoalCash  funds.Money                 `json:"unassigned_goal_cash_cents"`
	// HeldCash is the current non-overlapping cash encumbrance of queued,
	// accepted, UNKNOWN and reconciling operations. Time never releases it.
	HeldCash         funds.Money               `json:"held_cash_cents"`
	FutureIncome     []ForecastIncome          `json:"future_income"`
	PrincipalReturns []ForecastPrincipalReturn `json:"principal_returns"`
}
type ForecastPoint struct {
	ID                string      `json:"id"`
	Date              string      `json:"date"`
	Phase             string      `json:"phase"`
	At                time.Time   `json:"at"`
	CashCents         string      `json:"cash_cents"`
	Protected         funds.Money `json:"protected_cents"`
	MarginCents       string      `json:"margin_cents"`
	FutureIncome      funds.Money `json:"future_income_cents"`
	ForecastCashCents string      `json:"forecast_cash_cents"`
}
type ForecastResult struct {
	Algorithm           string                      `json:"algorithm"`
	InputHash           string                      `json:"input_hash"`
	AsOf                time.Time                   `json:"as_of"`
	Timezone            string                      `json:"timezone"`
	HorizonDays         int                         `json:"horizon_days"`
	State               string                      `json:"state"`
	CurrentSafe         funds.Money                 `json:"current_safe_cents"`
	MaximumDeficit      funds.Money                 `json:"maximum_deficit_cents"`
	Points              []ForecastPoint             `json:"points"`
	Obligations         []ForecastObligation        `json:"obligations"`
	ExternalLiabilities []ForecastExternalLiability `json:"external_liabilities,omitempty"`
	Reasons             []string                    `json:"reasons"`
	BankAuthority       bool                        `json:"bank_authority"`
}

func forecastMoney(n int64) (funds.Money, error) {
	m, err := funds.NewMoney(n)
	if err != nil {
		return funds.Money{}, ErrForecastCapacity
	}
	return m, nil
}
func forecastAdd(a, b int64) (int64, error) {
	if a < 0 || b < 0 || b > funds.MaxMoneyCents-a {
		return 0, ErrForecastCapacity
	}
	return a + b, nil
}
func forecastDay(date string, zone *time.Location) (time.Time, error) {
	d, err := policy.TemplateDate(date)
	if err != nil {
		return time.Time{}, ErrForecastInput
	}
	return time.Date(d.Year(), d.Month(), d.Day(), 0, 0, 0, 0, zone), nil
}
func forecastSettlement(f policy.TemplateFacts, policyID funds.ID, period string, registered funds.Money, historical bool) (funds.Money, error) {
	var found *policy.TemplateSettlementFact
	for i := range f.Settlements {
		s := &f.Settlements[i]
		if s.PolicyID == policyID && s.Period == period {
			if found != nil || !s.Verified {
				return funds.Money{}, ErrForecastInput
			}
			found = s
		}
	}
	if found == nil {
		if historical {
			return funds.Money{}, ErrForecastInput
		}
		return registered, nil
	}
	total := registered
	if found.FinalTotal != nil {
		total = *found.FinalTotal
	}
	if found.Paid.Cents() > total.Cents() {
		return funds.Money{}, ErrForecastInput
	}
	return total.Sub(found.Paid)
}

// Canonical UUID text has fixed separators and monotone lowercase hex digits,
// so its lexicographic order is exactly the underlying 16-byte order.
func forecastIDLess(a, b funds.ID) bool {
	return bytes.Compare(a[:], b[:]) < 0
}

// normalizedForecast copies slices before ordering; all business instants are
// UTC. Collection order does not change a replay hash or caller-owned facts.
func normalizedForecast(in ForecastInput) ForecastInput {
	in.AsOf = in.AsOf.UTC()
	in.Versions = append([]policy.TemplateVersion(nil), in.Versions...)
	for i := range in.Versions {
		in.Versions[i].ConfirmedAt = in.Versions[i].ConfirmedAt.UTC()
	}
	sort.Slice(in.Versions, func(i, j int) bool { return forecastIDLess(in.Versions[i].PolicyID, in.Versions[j].PolicyID) })
	in.RetainedObligations = append([]ForecastObligation(nil), in.RetainedObligations...)
	sort.Slice(in.RetainedObligations, func(i, j int) bool { return in.RetainedObligations[i].ID < in.RetainedObligations[j].ID })
	in.ExternalLiabilities = append([]ForecastExternalLiability(nil), in.ExternalLiabilities...)
	sort.Slice(in.ExternalLiabilities, func(i, j int) bool { return in.ExternalLiabilities[i].ID < in.ExternalLiabilities[j].ID })
	in.RetainedFloors = append([]ForecastFloor(nil), in.RetainedFloors...)
	sort.Slice(in.RetainedFloors, func(i, j int) bool { return in.RetainedFloors[i].ID < in.RetainedFloors[j].ID })
	in.FutureIncome = append([]ForecastIncome(nil), in.FutureIncome...)
	for i := range in.FutureIncome {
		in.FutureIncome[i].ExpectedAt = in.FutureIncome[i].ExpectedAt.UTC()
	}
	sort.Slice(in.FutureIncome, func(i, j int) bool { return forecastIDLess(in.FutureIncome[i].ID, in.FutureIncome[j].ID) })
	in.PrincipalReturns = append([]ForecastPrincipalReturn(nil), in.PrincipalReturns...)
	sort.Slice(in.PrincipalReturns, func(i, j int) bool { return forecastIDLess(in.PrincipalReturns[i].ID, in.PrincipalReturns[j].ID) })
	f := in.Facts
	f.Accounts = append([]policy.TemplateAccountFact(nil), f.Accounts...)
	sort.Slice(f.Accounts, func(i, j int) bool { return forecastIDLess(f.Accounts[i].ID, f.Accounts[j].ID) })
	f.Goals = append([]policy.TemplateGoalFact(nil), f.Goals...)
	for i := range f.Goals {
		if f.Goals[i].GoalVersion != nil {
			v := *f.Goals[i].GoalVersion
			v.ConfirmedAt = v.ConfirmedAt.UTC()
			f.Goals[i].GoalVersion = &v
		}
	}
	sort.Slice(f.Goals, func(i, j int) bool { return forecastIDLess(f.Goals[i].ID, f.Goals[j].ID) })
	f.Income = append([]policy.TemplateIncomeFact(nil), f.Income...)
	for i := range f.Income {
		f.Income[i].OccurredAt = f.Income[i].OccurredAt.UTC()
	}
	sort.Slice(f.Income, func(i, j int) bool { return forecastIDLess(f.Income[i].ID, f.Income[j].ID) })
	f.Bills = append([]policy.TemplateBillFact(nil), f.Bills...)
	sort.Slice(f.Bills, func(i, j int) bool { return forecastIDLess(f.Bills[i].ID, f.Bills[j].ID) })
	f.Settlements = append([]policy.TemplateSettlementFact(nil), f.Settlements...)
	sort.Slice(f.Settlements, func(i, j int) bool {
		return f.Settlements[i].PolicyID.String()+f.Settlements[i].Period < f.Settlements[j].PolicyID.String()+f.Settlements[j].Period
	})
	f.HistoryAccounts = append([]funds.ID(nil), f.HistoryAccounts...)
	sort.Slice(f.HistoryAccounts, func(i, j int) bool { return forecastIDLess(f.HistoryAccounts[i], f.HistoryAccounts[j]) })
	f.History = append([]policy.TemplateHistoryTransaction(nil), f.History...)
	sort.Slice(f.History, func(i, j int) bool { return forecastIDLess(f.History[i].ID, f.History[j].ID) })
	f.Coverage = append([]policy.TemplateHistoryCoverage(nil), f.Coverage...)
	for i := range f.Coverage {
		f.Coverage[i].Dates = append([]string(nil), f.Coverage[i].Dates...)
		sort.Strings(f.Coverage[i].Dates)
	}
	sort.Slice(f.Coverage, func(i, j int) bool { return forecastIDLess(f.Coverage[i].AccountID, f.Coverage[j].AccountID) })
	// Non-protection consumer facts are excluded from this algorithm's input.
	// Their authoritative inventory version still participates via InventoryHash.
	f.Products = nil
	f.Positions = nil
	f.SeasonalWindows = nil
	f.SeasonalAdoption = nil
	f.Intervention = nil
	f.ProtectedReferences = nil
	f.EmergencyDeficits = nil
	in.Facts = f
	return in
}

type forecastPolicy struct {
	version     policy.TemplateVersion
	config      policy.TemplateConfiguration
	living      funds.Money
	goalMinimum funds.Money
	state       string
	dates       policy.TemplateDateRange
}

// Forecast365 protects current confirmed cash against every generated unpaid
// obligation. Hypothetical payment removes both cash and the matching debt.
// Future income changes ForecastCash only, never Cash/Margin/CurrentSafe.
func Forecast365(in ForecastInput) (ForecastResult, error) {
	forecast365Attempts.Add(1)
	var dateScope policy.TemplateDateParseScope
	return forecast365DateScoped(in, &dateScope)
}

func forecast365DateScoped(in ForecastInput, dateScope *policy.TemplateDateParseScope) (ForecastResult, error) {
	zone, err := policy.TemplateLocation(in.Timezone)
	if err != nil || in.AsOf.IsZero() || in.AsOf.Year() < 1 || in.AsOf.Year() > 9998 || !in.Complete || !validHash(in.InventoryHash) || in.Scope.EnvironmentID == (funds.ID{}) || in.Scope.UserID == (funds.ID{}) || in.Facts.Scope != in.Scope || !in.Facts.Complete || !validHash(in.Facts.SourceHash) {
		return ForecastResult{}, ErrForecastInput
	}
	if in.HorizonDays == 0 {
		in.HorizonDays = MaxForecastDays
	}
	if in.HorizonDays < 1 || in.HorizonDays > MaxForecastDays || len(in.Versions) > 100 || len(in.RetainedObligations) > 10000 || len(in.ExternalLiabilities) > 10000 || len(in.RetainedFloors) > 100 || len(in.FutureIncome) > 1000 || len(in.PrincipalReturns) > 10000 || len(in.Facts.Goals) > 100 || len(in.Facts.Accounts) > 100 || len(in.Facts.Bills) > 10000 || len(in.Facts.Settlements) > 10000 || len(in.Facts.Income) > 100000 {
		return ForecastResult{}, ErrForecastCapacity
	}
	in = normalizedForecast(in)
	local := in.AsOf.In(zone)
	today := local.Format("2006-01-02")
	day0 := time.Date(local.Year(), local.Month(), local.Day(), 0, 0, 0, 0, zone)
	end := day0.AddDate(0, 0, in.HorizonDays)
	if end.Year() > 9999 {
		return ForecastResult{}, ErrForecastCapacity
	}
	endDate := end.Format("2006-01-02")
	result := ForecastResult{Algorithm: ForecastAlgorithm, InputHash: hash(in), AsOf: in.AsOf, Timezone: in.Timezone, HorizonDays: in.HorizonDays, State: "READY", Points: []ForecastPoint{}, Obligations: []ForecastObligation{}, Reasons: []string{"FUTURE_INCOME_IS_FORECAST_ONLY", "PAYMENTS_ARE_HYPOTHETICAL_NOT_EXECUTION", "CURRENT_FACTS_REQUIRE_ROLLING_RECOMPUTATION"}}
	if result.InputHash == "" {
		return ForecastResult{}, ErrForecastInput
	}
	accounts := map[funds.ID]bool{}
	var accountTotal int64
	for _, a := range in.Facts.Accounts {
		if a.ID == (funds.ID{}) || !a.Verified || accounts[a.ID] {
			return ForecastResult{}, ErrForecastInput
		}
		accounts[a.ID] = true
		accountTotal, err = forecastAdd(accountTotal, a.Balance.Cents())
		if err != nil {
			return ForecastResult{}, err
		}
	}
	if accountTotal != in.Facts.CurrentCash.Cents() {
		return ForecastResult{}, ErrForecastInput
	}
	goals := map[funds.ID]policy.TemplateGoalFact{}
	goalCash := in.UnassignedGoalCash.Cents()
	for _, g := range in.Facts.Goals {
		if g.ID == (funds.ID{}) || goals[g.ID].ID != (funds.ID{}) || !g.Verified || !accounts[g.AccountID] || g.CashOwned.Cents() > g.Owned.Cents() {
			return ForecastResult{}, ErrForecastInput
		}
		goals[g.ID] = g
		goalCash, err = forecastAdd(goalCash, g.CashOwned.Cents())
		if err != nil {
			return ForecastResult{}, err
		}
	}
	ownedAndHeld, err := forecastAdd(goalCash, in.HeldCash.Cents())
	if err != nil || ownedAndHeld > in.Facts.CurrentCash.Cents() {
		return ForecastResult{}, ErrForecastInput
	}
	incomeIDs := map[funds.ID]bool{}
	for _, inc := range in.Facts.Income {
		if inc.ID == (funds.ID{}) || incomeIDs[inc.ID] || !inc.Verified || inc.OccurredAt.IsZero() || inc.OccurredAt.After(in.AsOf) {
			return ForecastResult{}, ErrForecastInput
		}
		incomeIDs[inc.ID] = true
	}
	obligationIDs := map[string]bool{}
	retained := map[string]ForecastObligation{}
	var outstanding int64
	addObligation := func(o ForecastObligation) error {
		if len(result.Obligations) >= 10000 {
			return ErrForecastCapacity
		}
		if o.ID == "" || len(o.ID) > 160 || obligationIDs[o.ID] || o.PolicyID == (funds.ID{}) || o.VersionID == (funds.ID{}) || !o.Verified || !validHash(o.SourceHash) {
			return ErrForecastInput
		}
		if _, e := policy.TemplateDate(o.DueDate); e != nil {
			return ErrForecastInput
		}
		obligationIDs[o.ID] = true
		if o.Amount.IsZero() {
			return nil
		}
		var e error
		outstanding, e = forecastAdd(outstanding, o.Amount.Cents())
		if e != nil {
			return e
		}
		result.Obligations = append(result.Obligations, o)
		return nil
	}
	for _, o := range in.RetainedObligations {
		if err = addObligation(o); err != nil {
			return ForecastResult{}, err
		}
		retained[o.ID] = o
	}
	external := map[string]ForecastExternalLiability{}
	matchedExternal := map[string]bool{}
	for _, liability := range in.ExternalLiabilities {
		if len(liability.ID) != 41 || liability.ID[:5] != "bill:" || !liability.Verified || !validHash(liability.SourceHash) {
			return ForecastResult{}, ErrForecastInput
		}
		id, e := funds.ParseID(liability.ID[5:])
		if e != nil || id == (funds.ID{}) || "bill:"+id.String() != liability.ID {
			return ForecastResult{}, ErrForecastInput
		}
		if _, e = policy.TemplateDate(liability.DueDate); e != nil {
			return ForecastResult{}, ErrForecastInput
		}
		if _, duplicate := external[liability.ID]; duplicate {
			return ForecastResult{}, ErrForecastInput
		}
		external[liability.ID] = liability
		if old, exists := retained[liability.ID]; exists {
			if old.DueDate != liability.DueDate || old.Amount != liability.Remaining {
				return ForecastResult{}, ErrForecastInput
			}
			matchedExternal[liability.ID] = true
		}
	}
	for _, f := range in.RetainedFloors {
		if f.ID == "" || f.PolicyID == (funds.ID{}) || f.VersionID == (funds.ID{}) || !f.Verified || !validHash(f.SourceHash) || f.StartDate > f.EndDate || f.StartDate > today {
			return ForecastResult{}, ErrForecastInput
		}
		if _, e := policy.TemplateDate(f.StartDate); e != nil {
			return ForecastResult{}, ErrForecastInput
		}
		if _, e := policy.TemplateDate(f.EndDate); e != nil {
			return ForecastResult{}, ErrForecastInput
		}
	}
	for i, f := range in.RetainedFloors {
		for j := 0; j < i; j++ {
			p := in.RetainedFloors[j]
			if p.ID == f.ID || !(f.EndDate < p.StartDate || f.StartDate > p.EndDate) {
				return ForecastResult{}, ErrForecastInput
			}
		}
	}
	policies := []forecastPolicy{}
	seenPolicies := map[funds.ID]bool{}
	for _, v := range in.Versions {
		if v.Scope != in.Scope || seenPolicies[v.PolicyID] {
			return ForecastResult{}, ErrForecastInput
		}
		seenPolicies[v.PolicyID] = true
		state, e := v.EffectiveState(in.AsOf, in.Timezone)
		if e != nil || state == "CONFIRMATION_IN_FUTURE" {
			return ForecastResult{}, ErrForecastInput
		}
		c, e := v.Compiled.Decode()
		if e != nil {
			return ForecastResult{}, ErrForecastInput
		}
		fp := forecastPolicy{version: v, config: c, state: state}
		if state != "ACTIVE" && state != "CONFIRMED" {
			policies = append(policies, fp)
			continue
		}
		dates, e := policy.PrepareTemplateDateRange(v, in.Timezone)
		if e != nil {
			return ForecastResult{}, ErrForecastInput
		}
		fp.dates = dates
		start := dates.Start()
		firstMonth := time.Date(start.In(zone).Year(), start.In(zone).Month(), 1, 0, 0, 0, 0, zone)
		if (local.Year()-firstMonth.Year())*12+int(local.Month())-int(firstMonth.Month()) > 120 {
			return ForecastResult{}, ErrForecastCapacity
		}
		add := func(id, due string, amount funds.Money) error {
			// A real registered liability belongs to its original immutable
			// version. A changed current configuration cannot replace its due
			// date, remaining amount or source proof by regenerating the ID.
			if old, ok := retained[id]; ok {
				if old.PolicyID != v.PolicyID {
					return ErrForecastInput
				}
				return nil
			}
			if liability, exists := external[id]; exists {
				if liability.DueDate != due || liability.Remaining != amount {
					return ErrForecastInput
				}
				matchedExternal[id] = true
			}
			return addObligation(ForecastObligation{ID: id, PolicyID: v.PolicyID, VersionID: v.VersionID, DueDate: due, Amount: amount, Verified: true, SourceHash: v.Compiled.Hash})
		}
		var rule *policy.TemplateAmountRule
		dueDay := 0
		switch c := c.(type) {
		case *policy.RecurringObligationConfig:
			if c.AmountRule.Kind == "bill_balance" {
				if !accounts[*c.AmountRule.AccountID] {
					return ForecastResult{}, ErrForecastInput
				}
				for _, b := range in.Facts.Bills {
					if !b.Verified || b.ID == (funds.ID{}) || b.Paid.Cents() > b.Total.Cents() {
						return ForecastResult{}, ErrForecastInput
					}
					if b.AccountID != *c.AmountRule.AccountID {
						continue
					}
					amount, _ := b.Total.Sub(b.Paid)
					if e := add("bill:"+b.ID.String(), b.DueDate, amount); e != nil {
						return ForecastResult{}, e
					}
				}
			} else {
				rule = &c.AmountRule
				dueDay = c.DueDay
			}
		case *policy.PeriodicTransferConfig:
			if !accounts[c.SourceAccountID] {
				return ForecastResult{}, ErrForecastInput
			}
			rule = &c.AmountRule
			dueDay = c.DueDay
		case *policy.DatedExpenseConfig:
			if old, exists := retained[v.PolicyID.String()+":dated:"+c.Window.Start]; exists {
				if old.PolicyID != v.PolicyID {
					return ForecastResult{}, ErrForecastInput
				}
				break
			}
			amount, e := forecastSettlement(in.Facts, v.PolicyID, c.Window.Start+"/"+c.Window.End, c.Amount.Max, c.Window.End < today)
			if e != nil {
				return ForecastResult{}, e
			}
			due := c.Window.Start
			if due < today {
				due = today
			}
			if e = add(v.PolicyID.String()+":dated:"+c.Window.Start, due, amount); e != nil {
				return ForecastResult{}, e
			}
		case *policy.LivingReserveConfig:
			fp.living, e = policy.EstimateLivingReserve(*c, in.Facts, today)
			if e != nil {
				return ForecastResult{}, e
			}
		case *policy.LongTermGoalConfig:
			var g *policy.TemplateGoalFact
			for i := range in.Facts.Goals {
				x := &in.Facts.Goals[i]
				if x.PolicyID == v.PolicyID {
					if g != nil {
						return ForecastResult{}, ErrForecastInput
					}
					g = x
				}
			}
			if g == nil || g.VersionID != v.VersionID || g.MonthPeriod != local.Format("2006-01") {
				return ForecastResult{}, ErrForecastInput
			}
			term, e := forecastGoalProtection(v, *g, in.AsOf, in.Timezone, endDate)
			if e != nil {
				return ForecastResult{}, e
			}
			term.Active = true
			fp.goalMinimum, e = term.Occupancy(funds.Money{})
			if e != nil {
				return ForecastResult{}, e
			}
		}
		if rule != nil {
			for month := firstMonth; !month.After(end); month = month.AddDate(0, 1, 0) {
				due := policy.TemplateDueDate(month.Year(), month.Month(), dueDay)
				if due > endDate {
					break
				}
				active, e := dates.ActiveOnDate(due)
				if e != nil {
					return ForecastResult{}, e
				}
				if !active {
					continue
				}
				id := v.PolicyID.String() + ":monthly:" + month.Format("2006-01")
				if old, exists := retained[id]; exists {
					if old.PolicyID != v.PolicyID || old.DueDate[:7] != month.Format("2006-01") {
						return ForecastResult{}, ErrForecastInput
					}
					continue
				}
				registered := rule.Amount
				if rule.Kind == "range" {
					registered = rule.Max
				}
				amount, e := forecastSettlement(in.Facts, v.PolicyID, month.Format("2006-01"), registered, due < today)
				if e != nil {
					return ForecastResult{}, e
				}
				if e = add(id, due, amount); e != nil {
					return ForecastResult{}, e
				}
			}
		}
		policies = append(policies, fp)
	}
	for _, liability := range in.ExternalLiabilities {
		if matchedExternal[liability.ID] || liability.Remaining.IsZero() {
			continue
		}
		if len(result.Obligations)+len(result.ExternalLiabilities) >= 10000 {
			return ForecastResult{}, ErrForecastCapacity
		}
		outstanding, err = forecastAdd(outstanding, liability.Remaining.Cents())
		if err != nil {
			return ForecastResult{}, err
		}
		result.ExternalLiabilities = append(result.ExternalLiabilities, liability)
	}
	sort.Slice(result.Obligations, func(i, j int) bool {
		a, b := result.Obligations[i], result.Obligations[j]
		if a.DueDate != b.DueDate {
			return a.DueDate < b.DueDate
		}
		return a.ID < b.ID
	})
	futureByDate := map[string]int64{}
	returnByDate := map[string]int64{}
	goalReturnByDate := map[string]int64{}
	var futureTotal, returnTotal int64
	for _, inc := range in.FutureIncome {
		if inc.ID == (funds.ID{}) || incomeIDs[inc.ID] || !inc.ExpectedAt.After(in.AsOf) || !validHash(inc.AssumptionHash) {
			return ForecastResult{}, ErrForecastInput
		}
		incomeIDs[inc.ID] = true
		futureTotal, err = forecastAdd(futureTotal, inc.Amount.Cents())
		if err != nil {
			return ForecastResult{}, err
		}
		date := inc.ExpectedAt.In(zone).Format("2006-01-02")
		futureByDate[date], err = forecastAdd(futureByDate[date], inc.Amount.Cents())
		if err != nil {
			return ForecastResult{}, err
		}
	}
	seenReturns := map[funds.ID]bool{}
	for _, p := range in.PrincipalReturns {
		if p.ID == (funds.ID{}) || seenReturns[p.ID] || !p.Verified || !validHash(p.SourceHash) || p.Date < today || (p.GoalID != nil && goals[*p.GoalID].ID == (funds.ID{})) {
			return ForecastResult{}, ErrForecastInput
		}
		seenReturns[p.ID] = true
		if _, e := policy.TemplateDate(p.Date); e != nil {
			return ForecastResult{}, ErrForecastInput
		}
		returnTotal, err = forecastAdd(returnTotal, p.Amount.Cents())
		if err != nil {
			return ForecastResult{}, err
		}
		returnByDate[p.Date], err = forecastAdd(returnByDate[p.Date], p.Amount.Cents())
		if err != nil {
			return ForecastResult{}, err
		}
		if p.GoalID != nil {
			goalReturnByDate[p.Date], err = forecastAdd(goalReturnByDate[p.Date], p.Amount.Cents())
			if err != nil {
				return ForecastResult{}, err
			}
		}
	}
	if _, err = forecastAdd(in.Facts.CurrentCash.Cents(), returnTotal); err != nil {
		return ForecastResult{}, err
	}
	if _, err = forecastAdd(in.Facts.CurrentCash.Cents()+returnTotal, futureTotal); err != nil {
		return ForecastResult{}, err
	}
	cash := in.Facts.CurrentCash.Cents()
	future := int64(0)
	minMargin := int64(funds.MaxMoneyCents)
	// Only immutable policy date predicates are shared across the three phases.
	// Cash, outstanding debt, principal and protected totals remain phase-local.
	policyDateKnown := make([]bool, len(policies))
	policyDateActive := make([]bool, len(policies))
	protected := func(date string) (int64, error) {
		total, e := forecastAdd(goalCash, in.HeldCash.Cents())
		if e != nil {
			return 0, e
		}
		total, e = forecastAdd(total, outstanding)
		if e != nil {
			return 0, e
		}
		for _, floor := range in.RetainedFloors {
			if date >= floor.StartDate && date <= floor.EndDate {
				total, e = forecastAdd(total, floor.Amount.Cents())
				if e != nil {
					return 0, e
				}
			}
		}
		for index, fp := range policies {
			if fp.state != "ACTIVE" && fp.state != "CONFIRMED" {
				continue
			}
			active := policyDateActive[index]
			if !policyDateKnown[index] {
				active, e = fp.dates.ActiveOnDateScoped(date, dateScope)
				if e != nil {
					return 0, e
				}
				policyDateActive[index], policyDateKnown[index] = active, true
			}
			if !active {
				continue
			}
			var amount funds.Money
			switch c := fp.config.(type) {
			case *policy.EmergencyBufferConfig:
				amount = c.Amount
			case *policy.LivingReserveConfig:
				amount = fp.living
			case *policy.LongTermGoalConfig:
				amount = fp.goalMinimum
			}
			total, e = forecastAdd(total, amount.Cents())
			if e != nil {
				return 0, e
			}
		}
		return total, nil
	}
	for offset := 0; offset <= in.HorizonDays; offset++ {
		day := day0.AddDate(0, 0, offset)
		date := day.Format("2006-01-02")
		clear(policyDateKnown)
		for phaseIndex, phase := range []string{"BEFORE_PAYMENT", "AFTER_PAYMENT", "AFTER_PRINCIPAL"} {
			if phaseIndex == 1 {
				for _, o := range result.Obligations {
					if o.DueDate == date || (offset == 0 && o.DueDate < date) {
						cash -= o.Amount.Cents()
						outstanding -= o.Amount.Cents()
					}
				}
				for _, liability := range result.ExternalLiabilities {
					if liability.DueDate == date || (offset == 0 && liability.DueDate < date) {
						cash -= liability.Remaining.Cents()
						outstanding -= liability.Remaining.Cents()
					}
				}
			}
			if phaseIndex == 2 {
				cash += returnByDate[date]
				goalCash += goalReturnByDate[date]
				future += futureByDate[date]
			}
			floor, e := protected(date)
			if e != nil {
				return ForecastResult{}, e
			}
			margin := cash - floor
			if margin < minMargin {
				minMargin = margin
			}
			at := day.UTC()
			if offset == 0 {
				at = in.AsOf
			}
			at = at.Add(time.Duration(phaseIndex) * time.Nanosecond)
			floorMoney, _ := forecastMoney(floor)
			futureMoney, _ := forecastMoney(future)
			if offset == 0 && phaseIndex == 0 {
				result.Points = make([]ForecastPoint, 0, (in.HorizonDays+1)*3)
			}
			result.Points = append(result.Points, ForecastPoint{date + ":" + phase, date, phase, at, strconv.FormatInt(cash, 10), floorMoney, strconv.FormatInt(margin, 10), futureMoney, strconv.FormatInt(cash+future, 10)})
		}
	}
	if minMargin < 0 {
		result.State = "PROTECTION_DEFICIT"
		result.MaximumDeficit, err = forecastMoney(-minMargin)
	} else {
		result.CurrentSafe, err = forecastMoney(minMargin)
	}
	if err != nil {
		return ForecastResult{}, err
	}
	return result, nil
}
