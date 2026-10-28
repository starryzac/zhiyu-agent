package executionaudit

import (
	"fmt"
	"time"

	evidence "zhiyu.local/zhiyu-go/internal/audit"
	"zhiyu.local/zhiyu-go/internal/execution/bankv2"
	funds "zhiyu.local/zhiyu-go/internal/funds/domain"
	policy "zhiyu.local/zhiyu-go/internal/policy/domain"
)

// checkTemplateFactsLedgerV3 binds actual economic facts to an independently
// checked frozen ledger. Its caller must obtain n through frozenLedgerV3 from
// the EXACT retained sourceHash/sourceVersion witness. It must not fabricate a
// current n for an older preview, or use this method for counterfactual after-
// effect inputs. Missing or ambiguous prefix evidence stays INCOMPLETE.
// History/bills, policy references, current-safe derivation, and consumer-
// specific asset/reallocation enrichments are verified by their own closures.
func (g *nativeGraphV3) checkTemplateFactsLedgerV3(facts policy.TemplateFacts, n nativeFrozenLedgerV3, at time.Time, timezone string, sourceVersion uint64, neutralized ...funds.ID) error {
	if g.bank == nil || sourceVersion == 0 || sourceVersion > uint64(g.snapshot.Watermarks["source_version"]) {
		return fmt.Errorf("%w: template facts exact frozen source witness unavailable", evidence.ErrIncomplete)
	}
	if at.IsZero() || n.Namespace != g.manifest.Scope.Namespace || facts.Scope != g.ownerScopeV3() || !facts.Complete || !facts.IncomeComplete || !n.Income.Snapshot().AsOf.Equal(at) {
		return businessInvalid("template facts exact frozen scope/time/completeness")
	}
	if _, err := funds.ParseEvidenceHash(facts.SourceHash); err != nil {
		return businessInvalid("template facts source hash")
	}
	zone, err := policy.TemplateLocation(timezone)
	if err != nil || n.validate(g.ownerScopeV3().UserID) != nil {
		return businessInvalid("template facts frozen ledger invariant/timezone")
	}
	if err := g.checkFrozenLedgerProjectionV3(n, at, neutralized...); err != nil {
		return err
	}
	accounts := map[funds.ID]funds.Money{}
	var cash funds.Money
	for _, account := range n.Accounts {
		if _, exists := accounts[account.ID]; exists {
			return businessInvalid("template facts duplicate frozen account")
		}
		accounts[account.ID] = account.Balance
		cash, err = cash.Add(account.Balance)
		if err != nil {
			return businessInvalid("template facts cash sum overflow")
		}
	}
	if len(facts.Accounts) != len(accounts) || facts.CurrentCash != cash {
		return businessInvalid("template facts cash/account inventory differs from original bank prefix")
	}
	for _, fact := range facts.Accounts {
		amount, exists := accounts[fact.ID]
		if !exists || !fact.Verified || amount != fact.Balance {
			return businessInvalid("template facts exact account balance")
		}
		delete(accounts, fact.ID)
	}
	income := map[funds.ID]policy.TemplateIncomeFact{}
	available := map[funds.ID]funds.Money{}
	lots, err := n.Income.IncomeLots(at)
	if err != nil {
		return businessInvalid("template facts exact original-income locations")
	}
	for _, lot := range lots {
		id := lot.Origin.ID()
		available[id], err = available[id].Add(lot.Available)
		if err != nil {
			return businessInvalid("template facts income sum overflow")
		}
	}
	for _, origin := range n.Income.Snapshot().Origins {
		original := origin.Fact()
		income[origin.ID()] = policy.TemplateIncomeFact{ID: origin.ID(), Available: available[origin.ID()], OccurredAt: original.OccurredAt, Verified: true}
	}
	if len(facts.Income) != len(income) {
		return businessInvalid("template facts income inventory omitted or invented an original")
	}
	for _, fact := range facts.Income {
		original, exists := income[fact.ID]
		if !exists || !fact.Verified || fact.Available != original.Available || !fact.OccurredAt.Equal(original.OccurredAt) {
			return businessInvalid("template facts original income identity/time/available disposition")
		}
		delete(income, fact.ID)
	}
	monthly, err := g.templateContributionPrefixV3(n, at, zone)
	if err != nil {
		return err
	}
	goals := map[funds.ID]wireNativeGoalBalance{}
	for _, goal := range n.Goals {
		if _, exists := goals[goal.GoalID]; exists {
			return businessInvalid("template facts duplicate frozen goal")
		}
		goals[goal.GoalID] = goal
	}
	if len(facts.Goals) != len(goals) {
		return businessInvalid("template facts exact complete goal inventory")
	}
	for _, fact := range facts.Goals {
		original, exists := goals[fact.ID]
		owned, addErr := original.Cash.Add(original.Principal)
		if !exists || addErr != nil || !fact.Verified || fact.AccountID != original.AccountID || fact.Owned != owned || fact.CashOwned != original.Cash || fact.MonthContributed != monthly[fact.ID] || fact.MonthPeriod != at.In(zone).Format("2006-01") {
			return businessInvalid("template facts goal cash/principal/monthly contribution provenance")
		}
		delete(goals, fact.ID)
	}
	return g.checkedRowsV3()
}

func (g *nativeGraphV3) templateContributionPrefixV3(n nativeFrozenLedgerV3, at time.Time, zone *time.Location) (map[funds.ID]funds.Money, error) {
	monthly := map[funds.ID]funds.Money{}
	add := func(goal string, amount funds.Money, settled time.Time) error {
		id, err := funds.ParseID(goal)
		if err != nil || settled.IsZero() || settled.After(at) {
			return businessInvalid("template facts actual allocation receipt time/goal")
		}
		if settled.In(zone).Format("2006-01") == at.In(zone).Format("2006-01") {
			monthly[id], err = monthly[id].Add(amount)
		}
		return err
	}
	for _, reservation := range n.Income.Snapshot().Reservations {
		if reservation.State != funds.Committed || g.legacy == nil {
			continue
		}
		id := reservation.ActionID.String()
		request, legacy := g.legacy.requests[id]
		if !legacy || request.Kind != "ALLOCATE_GOAL" {
			continue
		}
		op := g.row("operations", id)
		if op == nil {
			return nil, businessInvalid("template facts original legacy allocation operation")
		}
		row := g.row("receipts", op.text("receipt_id"))
		if row == nil {
			return nil, fmt.Errorf("%w: template facts original legacy allocation receipt", evidence.ErrIncomplete)
		}
		var receipt businessReceipt
		nativeOriginalV3(row, "original", &receipt)
		if receipt.RecordedAt.After(at) || add(request.GoalID, request.Amount, receipt.SettledAt) != nil {
			return nil, businessInvalid("template facts legacy contribution cannot precede its receipt")
		}
	}
	seen := map[string]bool{}
	for _, hold := range n.Holds {
		id := hold.OperationID.String()
		if seen[id] || hold.State != funds.Committed {
			continue
		}
		seen[id] = true
		request, exists := g.nativeRequests[id]
		if !exists || request.Effect.Kind != bankv2.Allocate {
			continue // MoveGoal is ownership transfer, never fresh monthly income.
		}
		receipt, exists := g.nativeReceipts[id]
		if !exists || receipt.RecordedAt.After(at) || receipt.BankResult.SettledAt == nil || add(request.Effect.DestinationGoalID, request.Effect.Amount, *receipt.BankResult.SettledAt) != nil {
			return nil, businessInvalid("template facts native contribution requires original settled receipt")
		}
	}
	return monthly, nil
}
