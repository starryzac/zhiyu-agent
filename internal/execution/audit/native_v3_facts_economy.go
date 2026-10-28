package executionaudit

import (
	"fmt"
	"time"

	evidence "zhiyu.local/zhiyu-go/internal/audit"
	funds "zhiyu.local/zhiyu-go/internal/funds/domain"
)

// A final Released row and an equal wall clock do not prove WHICH FV made a
// cancellation/rejection effective. Old v1 witnesses predate the forward typed
// decision contract. Call only after delta validation proved a legitimate
// terminal transition; valid cancellations are incomplete, not invalid money.
func checkFundsReleasedDecisionsV3(commit nativeFundsCommitV3) error {
	for _, change := range commit.Changes {
		if change.AfterOriginal == nil || change.BeforeHash == nil {
			continue
		}
		switch change.Table {
		case "income_reservations", "native_income_reservations", "native_holds", "native_return_claims":
			value, err := nativeFundsObjectV3(*change.AfterOriginal)
			if err != nil {
				return err
			}
			if value["state"] == string(funds.Released) {
				return fmt.Errorf("%w: released-resource exact decision/FV authority absent at FV%d; final status/time cannot select a historical release prefix", evidence.ErrIncomplete, commit.FundsVersion)
			}
		}
	}
	return nil
}

// checkFundsPrefixEconomyV3 checks EVERY sealed prefix, including versions
// unused by a forecast consumer. Membership comes exclusively from FV deltas.
// The time below is an upper bound assembled from originals already present
// in that prefix, solely for the ledger's time invariants. It does not choose
// members, admit a later effect, or turn a counterfactual into a bank receipt.
func (g *nativeGraphV3) checkFundsPrefixEconomyV3(state nativeFinancialRowSetV3, commit nativeFundsCommitV3) error {
	if commit.TransactionStartedAt == nil || commit.TransactionStartedAt.IsZero() {
		return businessInvalid("funds prefix transaction lower bound missing")
	}
	if len(state["accounts"]) == 0 {
		if commit.FundsVersion != 1 {
			return businessInvalid("only initial user FV may have no accounts")
		}
		for _, rows := range state {
			if len(rows) != 0 {
				return businessInvalid("initial empty user FV contains economic rows")
			}
		}
		return nil
	}
	rows, err := nativeFactsRowsV3(state)
	if err != nil {
		return err
	}
	at := *commit.TransactionStartedAt
	bound := func(value time.Time) {
		if value.After(at) {
			at = value
		}
	}
	born := map[string]bool{}
	for table, values := range rows {
		for _, raw := range values {
			value, e := nativeFundsObjectV3(raw)
			if e != nil {
				return e
			}
			r := &ledgerRow{values: value}
			for _, field := range []string{"occurred_at", "observed_at", "recorded_at", "created_at", "purchased_at"} {
				if r.optional(field) != "" {
					bound(r.instant(field))
				}
			}
			if table == "native_holds" {
				id := r.text("operation_id")
				op := g.row("native_operations", id)
				if op == nil {
					return businessInvalid("funds prefix resource lacks original action")
				}
				born[id] = true
				bound(op.instant("created_at"))
				if r.text("state") == string(funds.Released) {
					bound(op.instant("updated_at"))
				}
			}
			if table == "native_receipts" {
				receipt, ok := g.nativeReceipts[r.text("operation_id")]
				if !ok {
					return businessInvalid("funds prefix missing bank verified receipt")
				}
				bound(receipt.RecordedAt)
			}
			if r.err != nil {
				return r.err
			}
		}
	}
	if at.After(g.manifest.Source.CapturedAt) {
		return businessInvalid("funds prefix original time after capture")
	}
	capture, err := nativeFactsLedgerFromRowsV3(g.ownerScopeV3(), g.manifest.Scope.Namespace, at, rows)
	if err != nil {
		return err
	}
	// Keep immutable commands, exact requests, final resource originals and
	// the independent bank inventory intact. Only completeness iteration is
	// scoped to origins and action births represented by this exact FV. For
	// a born action retain ALL final hold rows, so omitting one of its resource
	// rows cannot be made valid by trimming a caller supplied view.
	view := *g
	view.rows = make(map[string]map[string]*ledgerRow, len(g.rows))
	for table, values := range g.rows {
		view.rows[table] = values
	}
	view.rows["income_origins"] = map[string]*ledgerRow{}
	for _, raw := range rows["income_origins"] {
		value, _ := nativeFundsObjectV3(raw)
		id, _ := value["id"].(string)
		original := g.row("income_origins", id)
		if original == nil || !exactJSON(original.values, value) {
			return businessInvalid("funds prefix origin differs from independent original")
		}
		view.rows["income_origins"][keyParts(id)] = original
	}
	view.rows["native_holds"] = map[string]*ledgerRow{}
	for key, row := range g.rows["native_holds"] {
		if born[row.text("operation_id")] {
			view.rows["native_holds"][key] = row
		}
	}
	if _, err = view.frozenLedgerV3(capture, at); err != nil {
		return fmt.Errorf("funds FV%d independent economic prefix: %w", commit.FundsVersion, err)
	}
	return nil
}
