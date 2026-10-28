package executionaudit

import (
	"encoding/json"
	"sort"
	"strconv"

	funds "zhiyu.local/zhiyu-go/internal/funds/domain"
	planning "zhiyu.local/zhiyu-go/internal/planning/domain"
	policy "zhiyu.local/zhiyu-go/internal/policy/domain"
)

func nativeFactsEconomicProjectionV3(table string, value map[string]any) map[string]any {
	out := map[string]any{}
	for key, field := range value {
		out[key] = field
	}
	return out
}

func (g *nativeGraphV3) checkFundsFinalProjectionV3(state nativeFinancialRowSetV3) error {
	for _, table := range nativeFactsDeltaTablesV3(g.snapshot.Revision) {
		if g.snapshot.Revision >= 26 && (table == "bank_observations" || table == "native_bank_observations") {
			// Poll observations may arrive without changing money/FV. Every
			// sealed observation must retain its exact independent original;
			// later unsealed polls remain globally validated by operation/bank
			// closures and cannot qualify a terminal cause in an earlier FV.
			for _, original := range state[table] {
				value, err := nativeFundsObjectV3(original)
				row := &ledgerRow{values: value}
				current := g.row(table, row.text("id"))
				if err != nil || current == nil || !exactJSON(value, current.values) {
					return businessInvalid("sealed bank observation differs from exact captured original")
				}
			}
			continue
		}
		if len(state[table]) != len(g.rows[table]) {
			return businessInvalid("funds delta final inventory differs from captured " + table)
		}
		for _, current := range g.rows[table] {
			key, _, err := nativeFactsRowKeyV3(table, string(mustJSONV3(current.values)))
			if err != nil {
				return err
			}
			original, found := state[table][key]
			value, e := nativeFundsObjectV3(original)
			if !found || e != nil || !exactJSON(nativeFactsEconomicProjectionV3(table, value), nativeFactsEconomicProjectionV3(table, current.values)) {
				return businessInvalid("funds delta final exact financial row differs from captured " + table)
			}
		}
	}
	return nil
}

func (g *nativeGraphV3) checkSourceForecastEnvelopeV3(input planning.ForecastInput, n nativeFrozenLedgerV3, w nativeTemplateSourceWitnessV3, financial map[string][]string, proposed *policy.TemplateVersion, proposedGoal *funds.ID, publication bool) error {
	var basis nativeTemplateSourceBasisV3
	if json.Unmarshal(w.SourceBasisOriginal, &basis) != nil {
		return businessInvalid("source forecast exact basis")
	}
	for table, rows := range financial {
		declared := false
		for _, source := range w.SourceTables {
			declared = declared || source == table
		}
		if !declared {
			continue
		}
		if _, exists := basis.Rows[table]; !exists {
			basis.Rows[table] = rows
		}
	}
	if input.InventoryHash != nakedHash(mustJSONV3(basis.Inventory)) || !input.Complete || input.HorizonDays != 365 || len(input.RetainedFloors) != 0 || len(input.FutureIncome) != 0 || len(input.PrincipalReturns) != 0 {
		return businessInvalid("source forecast scope/inventory/horizon cannot invent future cash or floor")
	}
	var held, owned, cash funds.Money
	var err error
	for _, location := range n.Income.Snapshot().Locations {
		held, err = held.Add(location.Reserved)
		if err != nil {
			return err
		}
	}
	incomeHeld, cashHeld := map[funds.ID]funds.Money{}, map[funds.ID]funds.Money{}
	for _, r := range n.Income.Snapshot().Reservations {
		if r.State != funds.Reserved {
			continue
		}
		for _, u := range r.Uses {
			incomeHeld[r.ActionID], err = incomeHeld[r.ActionID].Add(u.Amount)
			if err != nil {
				return err
			}
		}
	}
	for _, h := range n.Holds {
		if h.State == funds.Reserved && h.ResourceKind == "CASH" {
			cashHeld[h.OperationID], err = cashHeld[h.OperationID].Add(h.Amount)
			if err != nil {
				return err
			}
		}
	}
	for action, amount := range cashHeld {
		if amount.Cents() > incomeHeld[action].Cents() {
			extra, _ := amount.Sub(incomeHeld[action])
			held, err = held.Add(extra)
			if err != nil {
				return err
			}
		}
	}
	for _, a := range n.Accounts {
		owned, err = owned.Add(a.GoalOwned)
		if err != nil {
			return err
		}
	}
	for _, goal := range n.Goals {
		cash, err = cash.Add(goal.Cash)
		if err != nil {
			return err
		}
	}
	unassigned, e := owned.Sub(cash)
	if e != nil || held != input.HeldCash || unassigned != input.UnassignedGoalCash {
		return businessInvalid("source forecast held/unassigned ownership differs from exact resource prefix")
	}
	policies := map[string]*ledgerRow{}
	versions := map[string]*ledgerRow{}
	for _, raw := range basis.Rows["template_policies"] {
		v, e := nativeFundsObjectV3(raw)
		if e != nil {
			return e
		}
		r := &ledgerRow{values: v}
		policies[r.text("id")] = r
	}
	for _, raw := range basis.Rows["template_policy_versions"] {
		v, e := nativeFundsObjectV3(raw)
		if e != nil {
			return e
		}
		r := &ledgerRow{values: v}
		versions[keyParts(r.text("policy_id"), strconv.FormatInt(r.positive("version"), 10))] = r
	}
	expected := []policy.TemplateVersion{}
	actualVersions := []policy.TemplateVersion{}
	byGoal := map[funds.ID]policy.TemplateVersion{}
	for id, p := range policies {
		r := versions[keyParts(id, strconv.FormatInt(p.positive("current_version"), 10))]
		if r == nil {
			return businessInvalid("source policy current original omitted")
		}
		var version policy.TemplateVersion
		nativeOriginalV3(r, "original", &version)
		original, ok := g.templates[version.VersionID.String()]
		if !ok || !exactJSON(original, version) || version.ConfirmedAt.After(w.AsOf) {
			return businessInvalid("source policy requires actual original USER configuration")
		}
		version.State = r.text("state")
		version.Current = true
		actualVersions = append(actualVersions, version)
		if r.err != nil || p.err != nil {
			return businessInvalid("source current policy status fields")
		}
		if proposed != nil && version.PolicyID == proposed.PolicyID {
			continue
		}
		expected = append(expected, version)
		if p.optional("goal_id") != "" {
			byGoal[p.id("goal_id")] = version
		}
	}
	if proposed != nil {
		expected = append(expected, *proposed)
		if proposedGoal != nil {
			byGoal[*proposedGoal] = *proposed
		}
	}
	sort.Slice(expected, func(i, j int) bool { return expected[i].PolicyID.String() < expected[j].PolicyID.String() })
	// No confirmed template is represented as nil by the original loader and
	// as an empty slice by this independent set reconstruction. Both encode
	// the same empty inventory; nonempty inventories remain exact and ordered.
	if len(expected) != len(input.Versions) || len(expected) != 0 && !exactJSON(expected, input.Versions) {
		return businessInvalid("source forecast complete current/proposed policy version set")
	}
	for _, goal := range input.Facts.Goals {
		version, bound := byGoal[goal.ID]
		if !bound {
			if goal.PolicyID != (funds.ID{}) || goal.VersionID != (funds.ID{}) || goal.GoalVersion != nil {
				return businessInvalid("source goal invented a policy binding")
			}
			continue
		}
		if goal.PolicyID != version.PolicyID || goal.VersionID != version.VersionID || goal.GoalVersion == nil || !exactJSON(*goal.GoalVersion, version) {
			return businessInvalid("source goal exact current/proposed policy binding")
		}
	}
	f := input.Facts
	// Seasonal windows are base history facts collected from the independently
	// signed closed statement. checkHistoryFactsV3 below requires the complete
	// exact window set, including issuer evidence hashes; an empty-only rule
	// would incorrectly reject legitimate signed history.
	if len(f.Products) != 0 || len(f.Positions) != 0 || !f.ManagedAmount.IsZero() || f.AssetUseDate != "" || f.RecoveryTrigger != "" || len(f.EmergencyDeficits) != 0 || !f.AlreadyReallocated.IsZero() || f.SeasonalAdoption != nil || len(f.ProtectedReferences) != 0 || f.StandingAuthorizationCovered || f.VerifiedProtectedCashDeficit != nil {
		return businessInvalid("base template source cannot invent action-specific qualification enrichments")
	}
	actions := nakedHash(mustJSONV3(struct{ Reservations, Holds []string }{basis.Rows["income_reservations"], basis.Rows["native_holds"]}))
	if f.Intervention == nil || len(f.Intervention.Reasons) != 0 || len(f.Intervention.PriorReasons) != 0 || f.Intervention.BoundaryEventHash != w.SourceHash || f.Intervention.ActionSetHash != actions {
		return businessInvalid("source intervention exact boundary/action originals")
	}
	visibleSource := w.SnapshotSourceVersion
	if publication {
		// Import commands retain the publication's post-increment admission
		// watermark. Its input witness still pins the exact pre-increment read.
		visibleSource++
	}
	if err = g.checkHistoryFactsV3(f, w.AsOf, w.Timezone, visibleSource); err != nil {
		return err
	}
	// New proposed permissions have not been adopted. Check the actual old
	// debt prefix with actual confirmed versions, then the proposed forecast
	// separately replays its typed configuration without erasing retained debt.
	billInput := input
	if proposed != nil {
		sort.Slice(actualVersions, func(i, j int) bool { return actualVersions[i].PolicyID.String() < actualVersions[j].PolicyID.String() })
		billInput.Versions = actualVersions
	}
	return g.checkBillForecastV3(billInput, visibleSource)
}
