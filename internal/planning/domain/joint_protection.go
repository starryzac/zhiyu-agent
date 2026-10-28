package domain

import (
	"sort"
	"strconv"
	"time"

	funds "zhiyu.local/zhiyu-go/internal/funds/domain"
	policy "zhiyu.local/zhiyu-go/internal/policy/domain"
)

// R/M/F/G are pre-contribution remaining target, actual current-month unmet
// minimum, future-month minima, and guarantee/deadline protection. Ownership
// contributed now persists after policy expiry, so inactive points use q=x.
type JointGoalProtection struct {
	GoalID            funds.ID    `json:"goal_id"`
	PolicyID          funds.ID    `json:"policy_id"`
	VersionID         funds.ID    `json:"version_id"`
	ConfigurationHash string      `json:"configuration_hash"`
	Remaining         funds.Money `json:"remaining_cents"`
	CurrentMinimum    funds.Money `json:"current_minimum_cents"`
	FutureMinimum     funds.Money `json:"future_minimum_cents"`
	Guarantee         funds.Money `json:"guarantee_cents"`
	Active            bool        `json:"active"`
}

func forecastGoalProtection(v policy.TemplateVersion, g policy.TemplateGoalFact, asOf time.Time, timezone, endDate string) (JointGoalProtection, error) {
	result := JointGoalProtection{GoalID: g.ID, PolicyID: v.PolicyID, VersionID: v.VersionID, ConfigurationHash: v.Compiled.Hash}
	zone, err := policy.TemplateLocation(timezone)
	if err != nil {
		return result, ErrForecastInput
	}
	decoded, err := v.Compiled.Decode()
	if err != nil {
		return result, ErrForecastInput
	}
	config, ok := decoded.(*policy.LongTermGoalConfig)
	if !ok || g.PolicyID != v.PolicyID || g.VersionID != v.VersionID || g.MonthPeriod != asOf.In(zone).Format("2006-01") {
		return result, ErrForecastInput
	}
	end, err := forecastDay(endDate, zone)
	if err != nil {
		return result, err
	}
	local := asOf.In(zone)
	today := local.Format("2006-01-02")
	dates, err := policy.PrepareTemplateDateRange(v, timezone)
	if err != nil {
		return result, err
	}
	start := dates.Start()
	remaining := jointMax(0, config.Target.Cents()-g.Owned.Cents())
	result.Remaining, _ = forecastMoney(remaining)
	for month := time.Date(local.Year(), local.Month(), 1, 0, 0, 0, 0, zone); !month.After(end); month = month.AddDate(0, 1, 0) {
		if month.Format("2006-01") > config.Deadline[:7] {
			break
		}
		first := month.Format("2006-01-02")
		if first < today {
			first = today
		}
		if first < start.In(zone).Format("2006-01-02") {
			first = start.In(zone).Format("2006-01-02")
		}
		if first > endDate || first > config.Deadline || first[:7] != month.Format("2006-01") {
			continue
		}
		active, e := dates.ActiveOnDate(first)
		if e != nil {
			return result, e
		}
		if !active {
			continue
		}
		if month.Format("2006-01") == local.Format("2006-01") {
			result.CurrentMinimum, _ = forecastMoney(jointMax(0, config.Monthly.Min.Cents()-g.MonthContributed.Cents()))
		} else {
			result.FutureMinimum, e = result.FutureMinimum.Add(config.Monthly.Min)
			if e != nil {
				return result, ErrForecastCapacity
			}
		}
	}
	if _, e := result.CurrentMinimum.Add(result.FutureMinimum); e != nil {
		return result, ErrForecastCapacity
	}
	guarantee := jointMax(0, config.MinimumGuarantee.Cents()-g.Owned.Cents())
	if config.Deadline <= endDate && !config.AllowPartial && !config.AllowDeferral {
		guarantee = remaining
	}
	result.Guarantee, _ = forecastMoney(guarantee)
	return result, nil
}

// Occupancy is ownership x plus the still-needed selected-goal floor. Future
// income never enters it. The expression exactly equals a fresh post-x forecast:
// q(x)=min(R,max(F+x,max(M+F,G))), or x outside confirmed policy validity.
func (t JointGoalProtection) Occupancy(x funds.Money) (funds.Money, error) {
	if x.Cents() > t.Remaining.Cents() {
		return funds.Money{}, ErrJointInput
	}
	if !t.Active {
		return x, nil
	}
	f, h := t.FutureMinimum.Cents(), jointMax(t.CurrentMinimum.Cents()+t.FutureMinimum.Cents(), t.Guarantee.Cents())
	// f+x may exceed Money capacity before the remaining-target cap; int64
	// safely contains two supported money values, and the final result is bounded.
	return forecastMoney(jointMin(t.Remaining.Cents(), jointMax(f+x.Cents(), h)))
}

// BuildJointProtection consumes the FULL forecast, removes only the selected
// goal's exact pre-contribution floor, and attaches its q(x) replacement. It
// keeps current ownership, held cash, old debts, all other policies and timing.
func BuildJointProtection(in ForecastInput, selected []funds.ID) ([]JointProtectionPoint, error) {
	if len(selected) < 2 || len(selected) > 8 {
		return nil, ErrJointInput
	}
	seen := map[funds.ID]bool{}
	for _, id := range selected {
		if id == (funds.ID{}) || seen[id] {
			return nil, ErrJointInput
		}
		seen[id] = true
	}
	selected = append([]funds.ID(nil), selected...)
	sort.Slice(selected, func(i, j int) bool { return selected[i].String() < selected[j].String() })
	forecast, err := Forecast365(in)
	if err != nil {
		return nil, err
	}
	endDate := forecast.Points[len(forecast.Points)-1].Date
	type termVersion struct {
		term  JointGoalProtection
		dates policy.TemplateDateRange
		state string
	}
	terms := []termVersion{}
	for _, id := range selected {
		var goal *policy.TemplateGoalFact
		for i := range in.Facts.Goals {
			if in.Facts.Goals[i].ID == id {
				if goal != nil {
					return nil, ErrJointInput
				}
				goal = &in.Facts.Goals[i]
			}
		}
		if goal == nil {
			return nil, ErrJointInput
		}
		var version *policy.TemplateVersion
		for i := range in.Versions {
			if in.Versions[i].PolicyID == goal.PolicyID {
				if version != nil {
					return nil, ErrJointInput
				}
				version = &in.Versions[i]
			}
		}
		if version == nil {
			return nil, ErrJointInput
		}
		term, e := forecastGoalProtection(*version, *goal, in.AsOf, in.Timezone, endDate)
		if e != nil {
			return nil, e
		}
		state, e := version.EffectiveState(in.AsOf, in.Timezone)
		if e != nil {
			return nil, e
		}
		dates, e := policy.PrepareTemplateDateRange(*version, in.Timezone)
		if e != nil {
			return nil, e
		}
		terms = append(terms, termVersion{term, dates, state})
	}
	result := make([]JointProtectionPoint, 0, len(forecast.Points))
	for _, point := range forecast.Points {
		row := JointProtectionPoint{ID: point.ID, At: point.At, SourceHash: forecast.InputHash, GoalTerms: make([]JointGoalProtection, 0, len(terms))}
		var selectedFloor int64
		for _, tv := range terms {
			term := tv.term
			active, e := tv.dates.ActiveOnDate(point.Date)
			if e != nil {
				return nil, e
			}
			term.Active = (tv.state == "ACTIVE" || tv.state == "CONFIRMED") && active
			row.GoalTerms = append(row.GoalTerms, term)
			floor, e := term.Occupancy(funds.Money{})
			if e != nil {
				return nil, e
			}
			selectedFloor, e = forecastAdd(selectedFloor, floor.Cents())
			if e != nil {
				return nil, e
			}
		}
		if selectedFloor > point.Protected.Cents() {
			return nil, ErrJointInput
		}
		cash, e := strconv.ParseInt(point.CashCents, 10, 64)
		if e != nil {
			return nil, ErrJointInput
		}
		available := cash - (point.Protected.Cents() - selectedFloor)
		if available < 0 {
			row.Deficit = true
		} else {
			row.Available, e = forecastMoney(available)
			if e != nil {
				return nil, e
			}
		}
		result = append(result, row)
	}
	return result, nil
}

// One complete read supplies both the spendable ledger and the full forecast.
// Binding prevents accidentally mixing a newer balance or a changed policy into
// an older protection curve. Neither object is accepted from an HTTP caller.
func jointBindProtection(in JointInput) ([]JointProtectionPoint, error) {
	f := in.ProtectionInput
	if f == nil || len(in.Protection) != 0 || f.Scope != in.Scope || !f.AsOf.Equal(in.Now) || f.Timezone != in.Timezone || f.InventoryHash != in.InventoryHash || len(f.Facts.Accounts) != len(in.Cash) {
		return nil, ErrJointInput
	}
	var held int64
	for _, location := range in.Ledger.Snapshot().Locations {
		var err error
		held, err = forecastAdd(held, location.Reserved.Cents())
		if err != nil {
			return nil, ErrJointInput
		}
	}
	if f.HeldCash.Cents() < held {
		return nil, ErrJointInput
	}
	for _, cash := range in.Cash {
		found := false
		for _, account := range f.Facts.Accounts {
			if account.ID == cash.AccountID && account.Verified && account.Balance == cash.Balance {
				found = true
			}
		}
		if !found {
			return nil, ErrJointInput
		}
	}
	var cashOwned, forecastOwned int64
	for _, cash := range in.Cash {
		var err error
		cashOwned, err = forecastAdd(cashOwned, cash.GoalOwned.Cents())
		if err != nil {
			return nil, ErrJointInput
		}
	}
	forecastOwned = f.UnassignedGoalCash.Cents()
	for _, goal := range f.Facts.Goals {
		var err error
		forecastOwned, err = forecastAdd(forecastOwned, goal.CashOwned.Cents())
		if err != nil {
			return nil, ErrJointInput
		}
	}
	if forecastOwned != cashOwned {
		return nil, ErrJointInput
	}
	selected := make([]funds.ID, len(in.Goals))
	for i, raw := range in.Goals {
		selected[i] = raw.Goal.ID
		wantGoal := raw.Goal
		wantGoal.GoalVersion = nil
		wantVersion := raw.Version
		wantVersion.ConfirmedAt = wantVersion.ConfirmedAt.UTC()
		goalFound, versionFound := false, false
		for _, goal := range f.Facts.Goals {
			if goal.ID == raw.Goal.ID {
				goal.GoalVersion = nil
				goalFound = hash(goal) == hash(wantGoal)
			}
		}
		for _, version := range f.Versions {
			if version.PolicyID == raw.Version.PolicyID {
				version.ConfirmedAt = version.ConfirmedAt.UTC()
				versionFound = hash(version) == hash(wantVersion)
			}
		}
		if !goalFound || !versionFound {
			return nil, ErrJointInput
		}
	}
	return BuildJointProtection(*f, selected)
}
