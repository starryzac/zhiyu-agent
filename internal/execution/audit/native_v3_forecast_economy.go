package executionaudit

import (
	"fmt"
	"sort"

	evidence "zhiyu.local/zhiyu-go/internal/audit"
	funds "zhiyu.local/zhiyu-go/internal/funds/domain"
	planning "zhiyu.local/zhiyu-go/internal/planning/domain"
)

type nativeForecastEconomicConsumerV3 struct {
	input        planning.ForecastInput
	dependencies planning.DependencyVector
	ledger       *nativeFrozenLedgerV3
	income       *wireNativeJointLedger
	neutralized  []funds.ID
}

// Only factual before-effect forecasts may use this check. The caller supplies
// the candidate's own retained, independently checked ledger, never today's
// ledger for a historical input. Counterfactual after-effect forecasts remain
// tied to their verified before input and exact proposed effect by replay.
func (g *nativeGraphV3) frozenForecastEconomyV3(input planning.ForecastInput, result planning.ForecastResult, ledger nativeFrozenLedgerV3, dependencies planning.DependencyVector, neutralized ...funds.ID) error {
	if err := g.checkTemplateFactsLedgerV3(input.Facts, ledger, input.AsOf, input.Timezone, dependencies.SourceEvidenceVersion, neutralized...); err != nil {
		return err
	}
	if err := g.queueForecastEconomyV3(input, dependencies, &ledger, neutralized...); err != nil {
		return err
	}
	return g.frozenForecastV3(input, result, dependencies.SourceEvidenceVersion)
}

func (g *nativeGraphV3) queueForecastEconomyV3(input planning.ForecastInput, dependencies planning.DependencyVector, ledger *nativeFrozenLedgerV3, neutralized ...funds.ID) error {
	return g.queueForecastConsumerV3(nativeForecastEconomicConsumerV3{input: input, dependencies: dependencies, ledger: ledger, neutralized: append([]funds.ID(nil), neutralized...)})
}

func (g *nativeGraphV3) queueForecastConsumerV3(consumer nativeForecastEconomicConsumerV3) error {
	if len(g.forecastConsumers) >= evidence.DefaultBounds().MaxNodes {
		return fmt.Errorf("%w: causal forecast consumers exceed captured graph capacity", evidence.ErrIncomplete)
	}
	g.forecastConsumers = append(g.forecastConsumers, consumer)
	return nil
}

// Runs after the complete immutable funds/source graph is validated. A
// candidate's own ledger must be the exact stated causal FV, not merely some
// internally consistent selection of known receipts at the same clock time.
func (g *nativeGraphV3) checkForecastEconomicPrefixesV3() error {
	for _, c := range g.forecastConsumers {
		d := c.dependencies
		if err := g.checkPrefixSourceHashV3(d.FundsVersion, d.SourceEvidenceVersion, d.WriterGeneration, d.ControlVersion, c.input.Facts.SourceHash, c.input.InventoryHash, c.input.AsOf, c.input.Timezone); err != nil {
			return err
		}
		prefix, err := g.fundsPrefixLedgerV3(c.dependencies.FundsVersion, c.input.AsOf, c.neutralized...)
		if err != nil {
			return err
		}
		if c.ledger != nil {
			if dimension := nativeFrozenEconomyMismatchV3(*c.ledger, prefix); dimension != "" {
				return businessInvalid(fmt.Sprintf("forecast retained ledger differs from exact immutable funds prefix: %s; FV=%d; own neutralized=%d", dimension, d.FundsVersion, len(c.neutralized)))
			}
		}
		if c.income != nil && !nativeIncomePrefixEqualV3(*c.income, nativeIncomePrefixWireV3(prefix)) {
			return businessInvalid("joint planner qualification ledger differs from its exact funds prefix")
		}
		if err := g.checkTemplateFactsLedgerV3(c.input.Facts, prefix, c.input.AsOf, c.input.Timezone, c.dependencies.SourceEvidenceVersion, c.neutralized...); err != nil {
			return err
		}
	}
	return g.checkedRowsV3()
}

func nativeIncomePrefixWireV3(n nativeFrozenLedgerV3) wireNativeJointLedger {
	s := n.Income.Snapshot()
	out := wireNativeJointLedger{UserID: s.UserID, Currency: s.Currency, AsOf: s.AsOf, ScopeAccountIDs: s.ScopeAccountIDs, Locations: s.Locations, Reservations: s.Reservations}
	for _, origin := range s.Origins {
		out.OriginFacts = append(out.OriginFacts, origin.Fact())
	}
	return out
}

func nativeIncomePrefixEqualV3(a, b wireNativeJointLedger) bool {
	return nativeIncomePrefixMismatchV3(a, b) == ""
}

func nativeIncomePrefixMismatchV3(a, b wireNativeJointLedger) string {
	// PostgreSQL's typed timestamptz scan and retained to_jsonb(row) can
	// encode one instant with different offsets. Preserve both originals;
	// compare the three semantic fact instants in UTC, keeping every ID,
	// amount, role, source and evidence hash exact.
	x, y := append([]funds.BankCreditFact(nil), a.OriginFacts...), append([]funds.BankCreditFact(nil), b.OriginFacts...)
	for _, facts := range [][]funds.BankCreditFact{x, y} {
		for i := range facts {
			facts[i].OccurredAt = facts[i].OccurredAt.UTC()
			facts[i].ObservedAt = facts[i].ObservedAt.UTC()
			facts[i].RecordedAt = facts[i].RecordedAt.UTC()
		}
	}
	checks := []struct {
		name  string
		equal bool
	}{
		{"header", a.UserID == b.UserID && a.Currency == b.Currency && a.AsOf.Equal(b.AsOf)},
		{"scope-accounts", nativeSameEconomicRowsV3(a.ScopeAccountIDs, b.ScopeAccountIDs)},
		{"origin-facts", nativeSameEconomicRowsV3(x, y)},
		{"locations", nativeSameEconomicRowsV3(a.Locations, b.Locations)},
		{"reservations", nativeSameEconomicRowsV3(a.Reservations, b.Reservations)},
	}
	for _, check := range checks {
		if !check.equal {
			return check.name
		}
	}
	return ""
}

func nativeFrozenEconomyEqualV3(a, b nativeFrozenLedgerV3) bool {
	return nativeFrozenEconomyMismatchV3(a, b) == ""
}

func nativeFrozenEconomyMismatchV3(a, b nativeFrozenLedgerV3) string {
	checks := []struct {
		name  string
		equal bool
	}{
		{"namespace", a.Namespace == b.Namespace},
		{"income", nativeIncomePrefixEqualV3(nativeIncomePrefixWireV3(a), nativeIncomePrefixWireV3(b))},
		{"accounts", nativeSameEconomicRowsV3(a.Accounts, b.Accounts)},
		{"goals", nativeSameEconomicRowsV3(a.Goals, b.Goals)},
		{"goal-lots", nativeSameEconomicRowsV3(a.GoalLots, b.GoalLots)},
		{"holds", nativeSameEconomicRowsV3(a.Holds, b.Holds)},
		{"positions", nativeSameEconomicRowsV3(a.Positions, b.Positions)},
		{"principal-returns", nativeSameEconomicRowsV3(a.PrincipalReturns, b.PrincipalReturns)},
		{"return-locations", nativeSameEconomicRowsV3(a.ReturnLocations, b.ReturnLocations)},
		{"return-claims", nativeSameEconomicRowsV3(a.ReturnClaims, b.ReturnClaims)},
	}
	for _, check := range checks {
		if !check.equal {
			if check.name == "income" {
				return "income/" + nativeIncomePrefixMismatchV3(nativeIncomePrefixWireV3(a), nativeIncomePrefixWireV3(b))
			}
			return check.name
		}
	}
	return ""
}

func nativeSameEconomicRowsV3[T any](a, b []T) bool {
	if len(a) != len(b) {
		return false
	}
	x, y := make([]string, len(a)), make([]string, len(b))
	for i := range a {
		x[i] = string(mustJSONV3(a[i]))
		y[i] = string(mustJSONV3(b[i]))
	}
	sort.Strings(x)
	sort.Strings(y)
	for i := range x {
		if x[i] != y[i] {
			return false
		}
	}
	return true
}
