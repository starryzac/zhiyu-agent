package executionaudit

import (
	"strconv"

	funds "zhiyu.local/zhiyu-go/internal/funds/domain"
	planning "zhiyu.local/zhiyu-go/internal/planning/domain"
)

// Native graphs can contain later spending, transfers and goal changes. Their
// legacy plans therefore require the exact original FV, not today's cash or
// a monotonic assigned-total comparison. Old v1/v2 checks retain their scope.
func (g *nativeGraphV3) checkLegacyEconomicPrefixesV3() error {
	if g.snapshot.Revision < 25 {
		return nil
	}
	for id, input := range g.legacy.inputs {
		candidate, ok := g.legacy.plans[id]
		if !ok {
			return businessInvalid("legacy economic consumer has no replayed candidate")
		}
		if err := g.checkLegacyEconomicInputV3(input, candidate); err != nil {
			return err
		}
	}
	return g.checkedRowsV3()
}

func (g *nativeGraphV3) checkLegacyEconomicInputV3(input frozenBusinessInput, candidate planning.Candidate) error {
	d := input.Dependencies
	rows, commit, err := g.fundsPrefixRowsV3(d.FundsVersion, input.Now)
	if err != nil {
		return err
	}
	if d.SourceEvidenceVersion < commit.SourceVersion || d.WriterGeneration < commit.WriterGeneration || d.ControlVersion < commit.ControlVersion || d.SourceEvidenceVersion > uint64(g.snapshot.Watermarks["source_version"]) || d.WriterGeneration > uint64(g.snapshot.Watermarks["writer_generation"]) || d.ControlVersion > uint64(g.snapshot.Watermarks["control_version"]) {
		return businessInvalid("legacy dependencies precede exact financial/authority prefix")
	}
	prefix, err := g.fundsPrefixLedgerV3(d.FundsVersion, input.Now)
	if err != nil {
		return err
	}
	actual := wireNativeJointLedger{UserID: g.ownerScopeV3().UserID, Currency: funds.CNY, AsOf: input.Now, ScopeAccountIDs: input.ScopeAccounts, OriginFacts: input.OriginFacts, Locations: input.Locations, Reservations: input.Reservations}
	if !nativeIncomePrefixEqualV3(actual, nativeIncomePrefixWireV3(prefix)) {
		return businessInvalid("legacy frozen income differs from exact funds prefix")
	}
	// Compare copies of timestamps by instant, preserving original bytes.
	cash := append([]funds.CashLocationFact(nil), input.Cash...)
	expectedCash := make([]funds.CashLocationFact, 0, len(prefix.Accounts))
	for i := range cash {
		cash[i].ObservedAt = cash[i].ObservedAt.UTC()
	}
	for _, account := range prefix.Accounts {
		expectedCash = append(expectedCash, funds.CashLocationFact{AccountID: account.ID, Currency: funds.CNY, Balance: account.Balance, GoalOwned: account.GoalOwned, ObservedAt: account.ObservedAt.UTC()})
	}
	if !nativeSameEconomicRowsV3(cash, expectedCash) {
		return businessInvalid("legacy frozen cash differs from exact funds prefix")
	}
	foundGoal := false
	for _, raw := range rows["goals"] {
		values, err := nativeFundsObjectV3(raw)
		if err != nil {
			return err
		}
		goal := &ledgerRow{values: values}
		if goal.text("id") != candidate.Scope.GoalID.String() {
			continue
		}
		if foundGoal || goal.text("account_id") != candidate.Scope.SourceAccountID.String() || input.GoalTarget != goal.money("target_cents") || input.GoalAssigned != goal.money("assigned_cents") || input.MonthContributed != goal.money("month_contributed_cents") || input.MonthPeriod != goal.text("month_period") || goal.err != nil {
			return businessInvalid("legacy frozen goal/month differs from exact funds prefix")
		}
		foundGoal = true
	}
	if !foundGoal {
		return businessInvalid("legacy goal absent from its actual funds prefix")
	}
	source := g.row("protection_snapshots", strconv.FormatUint(d.SourceEvidenceVersion, 10))
	var protection planning.Protection
	if source == nil {
		return businessInvalid("legacy exact protection version absent")
	}
	nativeOriginalV3(source, "original", &protection)
	if source.err != nil || nativeHashFieldV3(source, "original", "original_hash") != nil || !exactJSON(input.Protection, protection) {
		return businessInvalid("legacy frozen protection differs from exact original source version")
	}
	return nil
}
