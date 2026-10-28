package executionaudit

import (
	"bytes"
	"encoding/json"
	"fmt"
	"sort"
	"time"

	evidence "zhiyu.local/zhiyu-go/internal/audit"
	funds "zhiyu.local/zhiyu-go/internal/funds/domain"
	policy "zhiyu.local/zhiyu-go/internal/policy/domain"
)

// These are the complete financial inputs of the native ledger loader. The
// source witness and each funds-version commit retain these rows themselves;
// present-day database rows are never a substitute for an earlier prefix.
var nativeFactsFinancialTablesV3 = []string{
	"accounts", "goals", "income_origins", "income_locations", "income_reservations", "income_claims",
	"native_income_reservations", "native_income_claims", "native_goal_balances", "native_goal_lots", "native_holds",
	"native_positions", "native_position_states", "native_principal_returns", "native_return_locations", "native_return_claims",
	"receipts", "native_receipts",
	"native_payment_sources", "native_obligation_payments", "template_obligation_payments",
	"template_policies", "template_policy_versions", "template_policy_confirmations", "template_policy_status_events",
}

var nativeFactsForward26TablesV3 = []string{"native_grants", "native_grant_state_events", "native_grant_states", "native_bank_observations", "bank_observations", "funds_terminal_decisions"}

func nativeFactsDeltaTablesV3(revision int) []string {
	if revision < 26 {
		return nativeFactsFinancialTablesV3
	}
	tables := append([]string(nil), nativeFactsFinancialTablesV3...)
	return append(tables, nativeFactsForward26TablesV3...)
}

func nativeCopyFundsStateV3(state nativeFinancialRowSetV3) nativeFinancialRowSetV3 {
	copy := nativeFinancialRowSetV3{}
	for table, rows := range state {
		copy[table] = map[string]string{}
		for key, raw := range rows {
			copy[table][key] = raw
		}
	}
	return copy
}

// nativeFactsLedgerFromRowsV3 independently interprets retained SQL row
// originals. It does not deserialize a caller-supplied ledger and bless it as a
// financial source. All joins are complete and scoped, including the native
// income reservation/claim tables missing from the old source-hash basis.
func nativeFactsLedgerFromRowsV3(scope policy.TemplateOwnerScope, namespace string, at time.Time, raw map[string][]string) (wireNativeAssetLedgerCapture, error) {
	out := wireNativeAssetLedgerCapture{Namespace: namespace, Income: wireNativeJointLedger{UserID: scope.UserID, Currency: funds.CNY, AsOf: at}}
	rows := map[string][]*ledgerRow{}
	for _, table := range nativeFactsFinancialTablesV3 {
		originals, exists := raw[table]
		if !exists {
			return out, fmt.Errorf("%w: retained financial prefix missing table %s", evidence.ErrIncomplete, table)
		}
		catalog, ok := nativeAuditTableV3(table)
		if !ok {
			return out, fmt.Errorf("%w: financial prefix table", evidence.ErrUnsupportedVersion)
		}
		seen := map[string]bool{}
		for _, original := range originals {
			if _, err := evidence.ParseRawObject([]byte(original)); err != nil {
				return out, businessInvalid("financial prefix original JSON")
			}
			var value map[string]any
			decoder := json.NewDecoder(bytes.NewBufferString(original))
			decoder.UseNumber()
			if decoder.Decode(&value) != nil {
				return out, businessInvalid("financial prefix original decode")
			}
			row := &ledgerRow{values: value}
			if row.text("environment_id") != scope.EnvironmentID.String() || row.text("user_id") != scope.UserID.String() {
				return out, businessInvalid("financial prefix crosses owner scope")
			}
			key := []string{}
			for _, field := range catalog.PrimaryKey {
				part, ok := row.values[field].(string)
				if number, numeric := row.values[field].(json.Number); numeric {
					part, ok = number.String(), true
				}
				if !ok {
					row.fail(field)
				}
				key = append(key, part)
			}
			if row.err != nil || seen[keyParts(key...)] {
				return out, businessInvalid("financial prefix duplicate/invalid identity: " + table)
			}
			seen[keyParts(key...)] = true
			rows[table] = append(rows[table], row)
		}
	}
	for _, row := range rows["accounts"] {
		id := row.id("id")
		out.Income.ScopeAccountIDs = append(out.Income.ScopeAccountIDs, id)
		out.Accounts = append(out.Accounts, wireNativeAccount{ID: id, Balance: row.money("balance_cents"), GoalOwned: row.money("goal_owned_cents"), ObservedAt: row.instant("observed_at")})
	}
	for _, row := range rows["income_origins"] {
		hash, err := funds.ParseEvidenceHash(row.text("evidence_hash"))
		if err != nil {
			return out, businessInvalid("financial prefix income evidence hash")
		}
		out.Income.OriginFacts = append(out.Income.OriginFacts, funds.BankCreditFact{TransactionID: row.id("id"), AccountID: row.id("original_account_id"), Currency: funds.Currency(row.text("currency")), Amount: row.money("amount_cents"), Role: funds.RoleIncome, Source: funds.BankConfirmed, OccurredAt: row.instant("occurred_at"), ObservedAt: row.instant("observed_at"), RecordedAt: row.instant("recorded_at"), EvidenceID: row.id("evidence_id"), EvidenceHash: hash})
	}
	locations := map[funds.ID]funds.IncomeLocation{}
	for _, row := range rows["income_locations"] {
		location := funds.IncomeLocation{FragmentID: row.id("id"), OriginID: row.id("origin_id"), AccountID: row.id("account_id"), Spent: row.money("spent_cents"), Assigned: row.money("assigned_cents"), Reserved: row.money("reserved_cents"), LegacyReserved: row.money("legacy_reserved_cents"), Available: row.money("available_cents")}
		locations[location.FragmentID] = location
		out.Income.Locations = append(out.Income.Locations, location)
	}
	reservations := map[funds.ID]*funds.IncomeReservation{}
	for _, table := range []string{"income_reservations", "native_income_reservations"} {
		for _, row := range rows[table] {
			r := &funds.IncomeReservation{ActionID: row.id("action_id"), Operation: funds.IncomeOperation(row.text("operation")), State: funds.ReservationState(row.text("state"))}
			if destination := row.optional("destination_account_id"); destination != "" {
				id := row.id("destination_account_id")
				r.DestinationAccountID = &id
			}
			if reservations[r.ActionID] != nil {
				return out, businessInvalid("financial prefix action appears in both income ledgers")
			}
			reservations[r.ActionID] = r
		}
	}
	for _, table := range []string{"income_claims", "native_income_claims"} {
		for _, row := range rows[table] {
			r, location := reservations[row.id("action_id")], locations[row.id("fragment_id")]
			if r == nil || location.FragmentID == (funds.ID{}) {
				return out, businessInvalid("financial prefix orphan income claim")
			}
			r.Uses = append(r.Uses, funds.IncomeUse{FragmentID: location.FragmentID, OriginID: location.OriginID, AccountID: location.AccountID, Amount: row.money("amount_cents")})
		}
	}
	for _, r := range reservations {
		sort.Slice(r.Uses, func(i, j int) bool { return r.Uses[i].FragmentID.String() < r.Uses[j].FragmentID.String() })
		out.Income.Reservations = append(out.Income.Reservations, *r)
	}
	sort.Slice(out.Income.Reservations, func(i, j int) bool {
		return out.Income.Reservations[i].ActionID.String() < out.Income.Reservations[j].ActionID.String()
	})
	goals := map[funds.ID]*ledgerRow{}
	for _, row := range rows["goals"] {
		goals[row.id("id")] = row
	}
	for _, row := range rows["native_goal_balances"] {
		goal := goals[row.id("goal_id")]
		if goal == nil {
			return out, businessInvalid("financial prefix goal balance without goal")
		}
		out.Goals = append(out.Goals, wireNativeGoalBalance{GoalID: row.id("goal_id"), AccountID: goal.id("account_id"), Cash: row.money("cash_cents"), Principal: row.money("principal_cents"), Loss: row.money("loss_cents")})
		owned, err := row.money("cash_cents").Add(row.money("principal_cents"))
		if err != nil || goal.money("assigned_cents") != owned {
			return out, businessInvalid("historical goal assigned amount differs from native cash/principal ownership")
		}
	}
	if len(goals) != len(out.Goals) {
		return out, businessInvalid("financial prefix complete goal balance inventory")
	}
	for _, row := range rows["native_goal_lots"] {
		out.GoalLots = append(out.GoalLots, wireNativeGoalLot{GoalID: row.id("goal_id"), AccountID: row.id("account_id"), SourceKind: row.text("source_kind"), SourceID: row.text("source_id"), Available: row.money("available_cents"), Reserved: row.money("reserved_cents")})
	}
	for _, row := range rows["native_holds"] {
		out.Holds = append(out.Holds, wireNativeHold{OperationID: row.id("operation_id"), ResourceKind: row.text("resource_kind"), ResourceID: row.text("resource_id"), ResourceDetail: nativeStringV3(row, "resource_detail"), Amount: row.money("amount_cents"), State: funds.ReservationState(row.text("state"))})
	}
	states := map[string]*ledgerRow{}
	for _, row := range rows["native_position_states"] {
		states[row.text("position_id")] = row
	}
	optionalID := func(row *ledgerRow, field string) *funds.ID {
		if row.optional(field) == "" {
			return nil
		}
		id := row.id(field)
		return &id
	}
	for _, row := range rows["native_positions"] {
		state := states[row.text("id")]
		if state == nil {
			return out, businessInvalid("financial prefix position state absent")
		}
		position := wireNativePosition{ID: row.text("id"), BankKey: row.text("bank_key"), OpeningOperationID: optionalID(row, "opening_operation_id"), Original: row.raw("original"), OriginalHash: row.text("original_hash"), Principal: row.money("principal_cents"), GoalID: optionalID(row, "goal_id"), ReturnAccountID: row.id("return_account_id"), PurchasedAt: row.instant("purchased_at"), ClosingOperationID: optionalID(state, "closing_operation_id"), Closed: state.boolean("closed")}
		if row.optional("maturity_at") != "" {
			value := row.instant("maturity_at")
			position.MaturityAt = &value
		}
		out.Positions = append(out.Positions, position)
	}
	if len(states) != len(out.Positions) {
		return out, businessInvalid("financial prefix orphan position state")
	}
	for _, row := range rows["native_principal_returns"] {
		out.PrincipalReturns = append(out.PrincipalReturns, wireNativePrincipalReturn{BankKey: row.text("bank_key"), OperationID: row.id("operation_id"), PositionID: row.text("position_id"), Original: row.raw("original"), OriginalHash: row.text("original_hash"), Amount: row.money("amount_cents"), OccurredAt: row.instant("occurred_at")})
	}
	for _, row := range rows["native_return_locations"] {
		out.ReturnLocations = append(out.ReturnLocations, wireNativeReturnLocation{BankKey: row.text("bank_key"), AccountID: row.id("account_id"), Available: row.money("available_cents"), Reserved: row.money("reserved_cents")})
	}
	for _, row := range rows["native_return_claims"] {
		out.ReturnClaims = append(out.ReturnClaims, wireNativeReturnClaim{OperationID: row.id("operation_id"), BankKey: row.text("bank_key"), AccountID: row.id("account_id"), Amount: row.money("amount_cents"), State: funds.ReservationState(row.text("state"))})
	}
	for _, table := range nativeFactsFinancialTablesV3 {
		for _, row := range rows[table] {
			if row.err != nil {
				return out, row.err
			}
		}
	}
	ledger, err := out.DomainLedger()
	if err != nil || at.IsZero() || namespace == "" || ledger.validate(scope.UserID) != nil {
		return out, businessInvalid("independently rebuilt financial prefix invariant")
	}
	return out, nil
}
