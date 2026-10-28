package executionaudit

import (
	"fmt"
	"math/big"
	"time"

	evidence "zhiyu.local/zhiyu-go/internal/audit"
	"zhiyu.local/zhiyu-go/internal/execution/bankv2"

	funds "zhiyu.local/zhiyu-go/internal/funds/domain"
)

// A captured candidate is not its own source. Reconstruct its balances from
// immutable origins, exact original actions and actual independently checked
// bank receipts. RESERVED is never treated as a settled effect.
func (g *nativeGraphV3) checkFrozenLedgerProjectionV3(n nativeFrozenLedgerV3, at time.Time, neutralized ...funds.ID) error {
	snapshot := n.Income.Snapshot()
	own := map[string]bool{}
	for _, id := range neutralized {
		if g.row("native_operations", id.String()) == nil {
			return businessInvalid("native neutralized witness operation missing")
		}
		own[id.String()] = true
	}
	available, assigned, spent, reserved := map[string]*big.Int{}, map[string]*big.Int{}, map[string]*big.Int{}, map[string]*big.Int{}
	sourceSeen := map[string]bool{}
	for _, origin := range snapshot.Origins {
		f := origin.Fact()
		sourceSeen[origin.ID().String()] = true
		addBusinessSum(available, f.TransactionID.String()+"/"+f.AccountID.String(), f.Amount.Cents())
		if f.RecordedAt.After(at) || f.ObservedAt.After(at) {
			return businessInvalid("native frozen source was not yet known")
		}
	}
	for _, row := range g.rows["income_origins"] {
		if row.instant("recorded_at").Before(at) && !sourceSeen[row.text("id")] {
			return businessInvalid("native frozen complete source inventory omitted known origin")
		}
	}
	actionState := map[string]funds.ReservationState{}
	for _, r := range snapshot.Reservations {
		current, ok := g.reservations[r.ActionID.String()]
		original := r
		original.State = current.State
		if !ok || !exactJSON(original, current) || !(nativeHistoricalResourceStateV3(r.State, current.State) || own[r.ActionID.String()] && r.State == funds.Released) {
			return businessInvalid("native frozen origin reservation changed its original command")
		}
		actionState[r.ActionID.String()] = r.State
		for _, u := range r.Uses {
			key := u.OriginID.String() + "/" + u.AccountID.String()
			switch r.State {
			case funds.Reserved:
				addBusinessSum(available, key, -u.Amount.Cents())
				addBusinessSum(reserved, key, u.Amount.Cents())
			case funds.Committed:
				addBusinessSum(available, key, -u.Amount.Cents())
				switch r.Operation {
				case funds.AllocateGoal:
					addBusinessSum(assigned, key, u.Amount.Cents())
				case funds.Spend:
					addBusinessSum(spent, key, u.Amount.Cents())
				case funds.TransferInternal:
					if r.DestinationAccountID == nil {
						return businessInvalid("native frozen transfer destination")
					}
					addBusinessSum(available, u.OriginID.String()+"/"+r.DestinationAccountID.String(), u.Amount.Cents())
				default:
					return businessInvalid("native frozen origin operation")
				}
			case funds.Released:
			default:
				return businessInvalid("native frozen origin state")
			}
		}
	}
	nativeStates := map[string]funds.ReservationState{}
	holdSeen := map[string]bool{}
	for _, h := range n.Holds {
		id := h.OperationID.String()
		op := g.row("native_operations", id)
		row := g.row("native_holds", id, h.ResourceKind, h.ResourceID, h.ResourceDetail)
		if op == nil || row == nil || op.instant("created_at").After(at) || row.money("amount_cents") != h.Amount || !(nativeHistoricalResourceStateV3(h.State, funds.ReservationState(row.text("state"))) || own[id] && h.State == funds.Released) {
			return businessInvalid("native frozen resource requires exact historical operation/amount/state")
		}
		if previous, ok := nativeStates[id]; ok && previous != h.State {
			return businessInvalid("native frozen one action has mixed resource states")
		}
		nativeStates[id] = h.State
		holdSeen[nativeHoldKeyV3(id, h.ResourceKind, h.ResourceID+"\x00"+h.ResourceDetail)] = true
	}
	for _, row := range g.rows["native_holds"] {
		id := row.text("operation_id")
		op := g.row("native_operations", id)
		if state, ok := nativeStates[id]; ok {
			if !holdSeen[nativeHoldKeyV3(id, row.text("resource_kind"), row.text("resource_id")+"\x00"+nativeStringV3(row, "resource_detail"))] {
				return businessInvalid("native frozen action omitted part of its full resource set")
			}
			if state == funds.Committed && g.nativeReceipts[id].RecordedAt.After(at) {
				return businessInvalid("native frozen ledger uses future settlement")
			}
			if state == funds.Released && !own[id] && op.instant("updated_at").After(at) {
				return businessInvalid("native frozen ledger releases before actual terminal no-effect")
			}
		} else if op != nil && op.instant("created_at").Before(at) {
			return businessInvalid("native frozen ledger omitted earlier action resources")
		}
	}
	// Goal source lots are derived from actual committed economic effects, not
	// inferred from an arbitrary goal-owned total or an attractive source UUID.
	lots, goalCash, principal, loss := map[string]*big.Int{}, map[string]*big.Int{}, map[string]*big.Int{}, map[string]*big.Int{}
	lotReserved, returnAvailable, returnReserved := map[string]*big.Int{}, map[string]*big.Int{}, map[string]*big.Int{}
	addLot := func(goal, account, kind, source string, amount int64) {
		addBusinessSum(lots, keyParts(goal, account, kind, source), amount)
	}
	for id, state := range actionState {
		if state != funds.Committed {
			continue
		}
		if request, ok := g.legacy.requests[id]; ok {
			op := g.row("operations", id)
			if op == nil || op.text("status") != "SETTLED" {
				return businessInvalid("native frozen legacy allocation lacks actual receipt")
			}
			addBusinessSum(goalCash, request.GoalID, request.Amount.Cents())
			for _, u := range g.reservations[id].Uses {
				addLot(request.GoalID, request.DestinationAccountID, "INCOME", u.OriginID.String(), u.Amount.Cents())
			}
		}
	}
	for id, state := range nativeStates {
		if state != funds.Committed {
			continue
		}
		request, ok := g.nativeRequests[id]
		receipt, settled := g.nativeReceipts[id]
		if !ok || !settled || receipt.RecordedAt.After(at) {
			return businessInvalid("native frozen committed effect requires actual original receipt")
		}
		e := request.Effect
		switch e.Kind {
		case bankv2.Allocate:
			addBusinessSum(goalCash, e.DestinationGoalID, e.Amount.Cents())
			for _, u := range e.OriginUses {
				// ALLOCATE preserves each source location. Its wire contract has
				// no destination account: only a destination goal is created.
				addLot(e.DestinationGoalID, u.AccountID, "INCOME", u.OriginID, u.Amount.Cents())
			}
		case bankv2.Purchase:
			if e.SourceGoalID != "" {
				addBusinessSum(goalCash, e.SourceGoalID, -e.Amount.Cents())
				addBusinessSum(principal, e.SourceGoalID, e.Amount.Cents())
				for _, u := range e.OriginUses {
					addLot(e.SourceGoalID, u.AccountID, "INCOME", u.OriginID, -u.Amount.Cents())
				}
				for _, u := range e.ReturnUses {
					addLot(e.SourceGoalID, u.AccountID, "PRINCIPAL_RETURN", u.OperationKey, -u.Amount.Cents())
				}
			}
			for _, u := range e.ReturnUses {
				addBusinessSum(returnAvailable, keyParts(u.OperationKey, u.AccountID), -u.Amount.Cents())
			}
		case bankv2.Redeem, bankv2.Mature:
			returned := receipt.BankResult.PrincipalReturn
			if returned == nil {
				return businessInvalid("native frozen principal return absent")
			}
			addBusinessSum(returnAvailable, keyParts(returned.OperationKey, e.DestinationAccountID), returned.Amount.Cents())
			if e.SourceGoalID != "" {
				addBusinessSum(goalCash, e.SourceGoalID, e.Net.Cents())
				addBusinessSum(principal, e.SourceGoalID, -e.Amount.Cents())
				addBusinessSum(loss, e.SourceGoalID, e.Loss.Cents())
				addLot(e.SourceGoalID, e.DestinationAccountID, "PRINCIPAL_RETURN", returned.OperationKey, e.Net.Cents())
			}
		case bankv2.MoveGoal:
			addBusinessSum(goalCash, e.SourceGoalID, -e.Amount.Cents())
			addBusinessSum(goalCash, e.DestinationGoalID, e.Amount.Cents())
			for _, u := range e.OriginUses {
				addLot(e.SourceGoalID, u.AccountID, "INCOME", u.OriginID, -u.Amount.Cents())
				addLot(e.DestinationGoalID, e.DestinationAccountID, "INCOME", u.OriginID, u.Amount.Cents())
				addBusinessSum(assigned, u.OriginID+"/"+u.AccountID, -u.Amount.Cents())
				addBusinessSum(assigned, u.OriginID+"/"+e.DestinationAccountID, u.Amount.Cents())
			}
			for _, u := range e.ReturnUses {
				addLot(e.SourceGoalID, u.AccountID, "PRINCIPAL_RETURN", u.OperationKey, -u.Amount.Cents())
				addLot(e.DestinationGoalID, e.DestinationAccountID, "PRINCIPAL_RETURN", u.OperationKey, u.Amount.Cents())
				addBusinessSum(returnAvailable, keyParts(u.OperationKey, u.AccountID), -u.Amount.Cents())
				addBusinessSum(returnAvailable, keyParts(u.OperationKey, e.DestinationAccountID), u.Amount.Cents())
			}
		case bankv2.Transfer, bankv2.Payment:
		default:
			return fmt.Errorf("%w: frozen economic family", evidence.ErrUnsupportedVersion)
		}
	}
	for _, h := range n.Holds {
		if h.State == funds.Reserved && h.ResourceKind == "GOAL_LOT" {
			var ref mirrorNativeLotReferenceV3
			if nativeCompactOriginalV3([]byte(h.ResourceDetail), &ref) != nil {
				return businessInvalid("native frozen goal lot pin detail")
			}
			addBusinessSum(lotReserved, keyParts(h.ResourceID, ref.AccountID, ref.SourceKind, ref.SourceID), h.Amount.Cents())
		}
	}
	if err := nativeExactFrozenLocationsV3(snapshot.Locations, available, assigned, spent, reserved); err != nil {
		return err
	}
	seenLots := map[string]bool{}
	for _, l := range n.GoalLots {
		key := keyParts(l.GoalID.String(), l.AccountID.String(), l.SourceKind, l.SourceID)
		if seenLots[key] || !businessSum(lots, key, l.Available.Cents()) || !businessSum(lotReserved, key, l.Reserved.Cents()) {
			return businessInvalid("native frozen goal lot exact effect provenance")
		}
		seenLots[key] = true
	}
	if err := nativeNoMissingPositiveV3(lots, seenLots); err != nil {
		return err
	}
	seenGoals := map[string]bool{}
	for _, goal := range n.Goals {
		id := goal.GoalID.String()
		row := g.row("goals", id)
		if row == nil || row.text("account_id") != goal.AccountID.String() || !businessSum(goalCash, id, goal.Cash.Cents()) || !businessSum(principal, id, goal.Principal.Cents()) || !businessSum(loss, id, goal.Loss.Cents()) {
			return businessInvalid("native frozen goal cash/principal/loss exact original effects")
		}
		seenGoals[id] = true
	}
	for _, values := range []map[string]*big.Int{goalCash, principal, loss} {
		if err := nativeNoMissingPositiveV3(values, seenGoals); err != nil {
			return err
		}
	}
	// Every existing position and return must be born from the exact committed
	// purchase/closing action represented by this frozen prefix.
	positions := map[string]bool{}
	for _, p := range n.Positions {
		if p.OpeningOperationID == nil {
			return fmt.Errorf("%w: historical position import lacks registered independent source witness", evidence.ErrIncomplete)
		}
		if nativeStates[p.OpeningOperationID.String()] != funds.Committed || p.PurchasedAt.After(at) {
			return businessInvalid("native frozen position is not purchased yet")
		}
		closed := p.ClosingOperationID != nil && nativeStates[p.ClosingOperationID.String()] == funds.Committed
		if p.Closed != closed {
			return businessInvalid("native frozen position closure without actual return receipt")
		}
		positions[p.ID] = true
	}
	returns := map[string]bool{}
	for _, r := range n.PrincipalReturns {
		if nativeStates[r.OperationID.String()] != funds.Committed || !positions[r.PositionID] || r.OccurredAt.After(at) {
			return businessInvalid("native frozen PR was not actually returned")
		}
		returns[r.BankKey] = true
	}
	for id, state := range nativeStates {
		if state != funds.Committed {
			continue
		}
		r := g.nativeReceipts[id].BankResult
		if r.Position != nil && !positions[r.Position.PositionID] || r.PrincipalReturn != nil && !returns[r.PrincipalReturn.OperationKey] {
			return businessInvalid("native frozen immutable position/return inventory omitted")
		}
	}
	for _, claim := range n.ReturnClaims {
		request, ok := g.nativeRequests[claim.OperationID.String()]
		found := false
		for _, u := range request.Effect.ReturnUses {
			if u.OperationKey == claim.BankKey && u.AccountID == claim.AccountID.String() && u.Amount == claim.Amount {
				found = true
			}
		}
		if !ok || !found || nativeStates[claim.OperationID.String()] != claim.State {
			return businessInvalid("native frozen returned principal claim differs from original action")
		}
		if claim.State == funds.Reserved {
			addBusinessSum(returnReserved, keyParts(claim.BankKey, claim.AccountID.String()), claim.Amount.Cents())
		}
	}
	seenReturns := map[string]bool{}
	for _, l := range n.ReturnLocations {
		key := keyParts(l.BankKey, l.AccountID.String())
		if !returns[l.BankKey] || seenReturns[key] || !businessSum(returnAvailable, key, l.Available.Cents()) || !businessSum(returnReserved, key, l.Reserved.Cents()) {
			return businessInvalid("native frozen PR location cannot restore income or move source identity")
		}
		seenReturns[key] = true
	}
	if err := nativeNoMissingPositiveV3(returnAvailable, seenReturns); err != nil {
		return err
	}
	return g.frozenCashFromIndependentV3(n, nativeStates, actionState, sourceSeen)
}

func nativeHistoricalResourceStateV3(old, current funds.ReservationState) bool {
	return old == funds.Reserved || old == current && (old == funds.Committed || old == funds.Released)
}
func nativeNoMissingPositiveV3(values map[string]*big.Int, seen map[string]bool) error {
	for key, n := range values {
		if n.Sign() < 0 || n.Sign() != 0 && !seen[key] {
			return businessInvalid("native frozen economic source/cash inventory is incomplete or negative")
		}
	}
	return nil
}

func nativeExactFrozenLocationsV3(locations []funds.IncomeLocation, available, assigned, spent, reserved map[string]*big.Int) error {
	seen := map[string]bool{}
	for _, l := range locations {
		key := l.OriginID.String() + "/" + l.AccountID.String()
		if seen[key] || !l.LegacyReserved.IsZero() || !businessSum(available, key, l.Available.Cents()) || !businessSum(assigned, key, l.Assigned.Cents()) || !businessSum(spent, key, l.Spent.Cents()) || !businessSum(reserved, key, l.Reserved.Cents()) {
			return businessInvalid("native frozen origin disposition cannot be invented or recycled")
		}
		seen[key] = true
	}
	for _, values := range []map[string]*big.Int{available, assigned, spent, reserved} {
		if err := nativeNoMissingPositiveV3(values, seen); err != nil {
			return err
		}
	}
	return nil
}

func (g *nativeGraphV3) frozenCashFromIndependentV3(n nativeFrozenLedgerV3, states, legacy map[string]funds.ReservationState, origins map[string]bool) error {
	balances := map[string]*big.Int{}
	for _, a := range g.bank.Stock.Accounts {
		balances[a.ID] = big.NewInt(a.Balance.Cents())
	}
	add := func(account string, amount int64) error {
		if balances[account] == nil {
			return businessInvalid("native frozen cash account missing from independent bank")
		}
		balances[account].Add(balances[account], big.NewInt(amount))
		return nil
	}
	for _, r := range g.bank.Native {
		if r.Status != bankv2.Settled || states[r.Request.OperationID] == funds.Committed {
			continue
		}
		e := r.Request.Effect
		switch e.Kind {
		case bankv2.Transfer, bankv2.MoveGoal:
			for _, u := range e.CashUses {
				if err := add(u.AccountID, u.Amount.Cents()); err != nil {
					return err
				}
			}
			if err := add(e.DestinationAccountID, -e.Amount.Cents()); err != nil {
				return err
			}
		case bankv2.Purchase, bankv2.Payment:
			for _, u := range e.CashUses {
				if err := add(u.AccountID, u.Amount.Cents()); err != nil {
					return err
				}
			}
		case bankv2.Redeem, bankv2.Mature:
			if err := add(e.DestinationAccountID, -e.Net.Cents()); err != nil {
				return err
			}
		case bankv2.Allocate:
		default:
			return fmt.Errorf("%w: frozen bank cash effect", evidence.ErrUnsupportedVersion)
		}
	}
	// Legacy allocations change ownership only, so their committed state never
	// changes cash. The argument remains explicit alongside the native prefix.
	_ = legacy
	// Origins is the complete independent qualification inventory, including
	// retained OpenIncome sources that predate sequenced external Credit.
	// Reverse each later origin once; Credits is a subset and must not be
	// subtracted a second time.
	for _, origin := range g.bank.Credit.Origins {
		if !origins[origin.ID] {
			if err := add(origin.OriginalAccountID, -origin.Amount.Cents()); err != nil {
				return err
			}
		}
	}
	seen := map[string]bool{}
	for _, a := range n.Accounts {
		value := balances[a.ID.String()]
		if value == nil || value.Cmp(big.NewInt(a.Balance.Cents())) != 0 || seen[a.ID.String()] {
			return businessInvalid("native frozen cash differs from independently reconstructed bank prefix")
		}
		seen[a.ID.String()] = true
	}
	for id, value := range balances {
		if !seen[id] && value.Sign() != 0 {
			return businessInvalid("native frozen omitted nonzero independent account")
		}
	}
	return nil
}
