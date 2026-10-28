package app

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"sort"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"zhiyu.local/zhiyu-go/internal/adapters/postgres"
	funds "zhiyu.local/zhiyu-go/internal/funds/domain"
	planning "zhiyu.local/zhiyu-go/internal/planning/domain"
	policy "zhiyu.local/zhiyu-go/internal/policy/domain"
)

type ForecastRequest struct {
	HorizonDays int    `json:"horizon_days"`
	Timezone    string `json:"timezone"`
}

type ForecastView struct {
	Protocol                string                  `json:"protocol"`
	SourceHash              string                  `json:"source_hash"`
	InventoryHash           string                  `json:"inventory_hash"`
	FundsVersion            uint64                  `json:"funds_version"`
	SourceVersion           uint64                  `json:"source_version"`
	Result                  planning.ForecastResult `json:"result"`
	ProtectionSourceVersion *uint64                 `json:"protection_source_version,omitempty"`
	BankAuthority           bool                    `json:"bank_authority"`
}

type templateInventory struct {
	Protocol              string                    `json:"protocol"`
	Scope                 policy.TemplateOwnerScope `json:"scope"`
	SeedProtectionVersion uint64                    `json:"seed_protection_version"`
	SeedProtectionHash    string                    `json:"seed_protection_hash"`
	ClosedWorld           string                    `json:"closed_world"`
}

type templateSnapshot struct {
	Facts                            policy.TemplateFacts
	Versions                         []policy.TemplateVersion
	HistoricalVersions               []policy.TemplateVersion
	HistoricalEvents                 []planning.HistoricalPolicyEvent
	History                          planning.HistoricalObligationResult
	HistoricalBills                  []planning.HistoricalBillFact
	ExternalLiabilities              []planning.ForecastExternalLiability
	BillProofs                       map[string]NativeBillProof
	PaymentFinalTotals               map[string]funds.Money
	Views                            []TemplatePolicyView
	Retained                         []planning.ForecastObligation
	Held, UnassignedGoalCash         funds.Money
	Inventory                        templateInventory
	InventoryRaw                     []byte
	FundsVersion, SourceVersion      uint64
	WriterGeneration, ControlVersion uint64
	AsOf                             time.Time
	Timezone                         string
	Raw                              map[string][]string
	Native                           *postgres.NativeLedger
	SourceWitnessEnabled             bool
	SourceBasisOriginal              []byte
}

func templateTimezone(value string) (string, error) {
	if value == "" {
		value = "Asia/Shanghai"
	}
	if _, err := policy.TemplateLocation(value); err != nil {
		return "", reject("INVALID_TIMEZONE", err)
	}
	return value, nil
}

func templateScopedTimezone(ctx context.Context, q queryRow, p Principal, requested string) (string, error) {
	var existing string
	err := q.QueryRow(ctx, `SELECT v.timezone FROM template_policies t JOIN template_policy_versions v ON(v.environment_id=t.environment_id AND v.user_id=t.user_id AND v.policy_id=t.id AND v.version=t.current_version) WHERE t.environment_id=$1 AND t.user_id=$2 ORDER BY t.id LIMIT 1`, p.EnvironmentID.String(), p.UserID.String()).Scan(&existing)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return "", err
	}
	if existing != "" {
		if requested != "" && requested != existing {
			return "", reject("TEMPLATE_TIMEZONE_CONFLICT", nil)
		}
		requested = existing
	}
	return templateTimezone(requested)
}

func templateMoney(value int64) (funds.Money, error) {
	m, err := funds.NewMoney(value)
	if err != nil {
		return m, reject("TEMPLATE_FACTS_INVALID", err)
	}
	return m, nil
}

// A closed-world contract is recognized only from the explicit trusted local
// Bootstrap seed proof. Missing imported inventory is never an empty inventory.
func (s *Service) templateInventory(ctx context.Context, tx pgx.Tx, p Principal, sv uint64) (templateInventory, []byte, error) {
	var out templateInventory
	var raw []byte
	var hash string
	err := tx.QueryRow(ctx, `SELECT original,original_hash::text FROM template_inventory_contracts WHERE environment_id=$1 AND user_id=$2`, p.EnvironmentID.String(), p.UserID.String()).Scan(&raw, &hash)
	if err == nil {
		if Hash(raw) != hash || auditJSON(raw, &out) != nil || out.Protocol != "synthetic-seed-inventory-v1" || out.Scope != (policy.TemplateOwnerScope{EnvironmentID: p.EnvironmentID, UserID: p.UserID}) || out.ClosedWorld != "explicit-synthetic-empty-external-obligations-assets-history-v1" {
			return out, nil, reject("TEMPLATE_INVENTORY_INVALID", nil)
		}
		// An unrelated later protection source cannot be erased by reusing an
		// old seed's zero-external-obligations inventory contract.
		var currentRaw []byte
		var currentHash string
		var publication *string
		if e := tx.QueryRow(ctx, `SELECT s.original,s.original_hash,p.protection_hash::text FROM protection_snapshots s LEFT JOIN template_protection_publications p ON(p.environment_id=s.environment_id AND p.user_id=s.user_id AND p.source_version=s.version) WHERE s.environment_id=$1 AND s.user_id=$2 AND s.version=$3`, p.EnvironmentID.String(), p.UserID.String(), sv).Scan(&currentRaw, &currentHash, &publication); e != nil {
			return out, nil, reject("TEMPLATE_INVENTORY_INCOMPLETE", e)
		}
		if Hash(currentRaw) != currentHash {
			return out, nil, reject("TEMPLATE_INVENTORY_INVALID", nil)
		}
		if publication == nil || *publication != currentHash {
			var current planning.Protection
			expected := Hash([]byte(DemoSeedProtocol + "/synthetic-zero-obligations/" + p.EnvironmentID.String() + "/" + p.UserID.String()))
			if auditJSON(currentRaw, &current) != nil || !current.Complete || current.EvidenceHash != expected || len(current.Checkpoints) != 1 || current.Checkpoints[0].ID != "explicit-synthetic-zero-obligations" || !current.Checkpoints[0].OtherProtected.IsZero() || !current.Checkpoints[0].CurrentGoalMinimum.IsZero() {
				return out, nil, reject("TEMPLATE_INVENTORY_INCOMPLETE", nil)
			}
		}
		return out, raw, nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return out, nil, err
	}
	var protection planning.Protection
	if err = tx.QueryRow(ctx, `SELECT original,original_hash FROM protection_snapshots WHERE environment_id=$1 AND user_id=$2 AND version=$3`, p.EnvironmentID.String(), p.UserID.String(), sv).Scan(&raw, &hash); err != nil {
		return out, nil, reject("TEMPLATE_INVENTORY_INCOMPLETE", err)
	}
	expected := Hash([]byte(DemoSeedProtocol + "/synthetic-zero-obligations/" + p.EnvironmentID.String() + "/" + p.UserID.String()))
	if Hash(raw) != hash || auditJSON(raw, &protection) != nil || !protection.Complete || protection.EvidenceHash != expected || len(protection.Checkpoints) != 1 || protection.Checkpoints[0].ID != "explicit-synthetic-zero-obligations" || !protection.Checkpoints[0].OtherProtected.IsZero() || !protection.Checkpoints[0].CurrentGoalMinimum.IsZero() {
		return out, nil, reject("TEMPLATE_INVENTORY_INCOMPLETE", nil)
	}
	out = templateInventory{Protocol: "synthetic-seed-inventory-v1", Scope: policy.TemplateOwnerScope{EnvironmentID: p.EnvironmentID, UserID: p.UserID}, SeedProtectionVersion: sv, SeedProtectionHash: hash, ClosedWorld: "explicit-synthetic-empty-external-obligations-assets-history-v1"}
	raw, err = encode(out)
	return out, raw, err
}

func saveTemplateInventory(ctx context.Context, tx pgx.Tx, p Principal, snapshot templateSnapshot) error {
	_, err := tx.Exec(ctx, `INSERT INTO template_inventory_contracts(environment_id,user_id,protocol_version,seed_protection_version,seed_protection_hash,original,original_hash) VALUES($1,$2,$3,$4,$5,$6,$7) ON CONFLICT(environment_id,user_id) DO NOTHING`, p.EnvironmentID.String(), p.UserID.String(), snapshot.Inventory.Protocol, snapshot.Inventory.SeedProtectionVersion, snapshot.Inventory.SeedProtectionHash, snapshot.InventoryRaw, Hash(snapshot.InventoryRaw))
	return err
}

// templateRows is a fixed server whitelist. It binds source hashes to authority
// rows without including previews, projections, credentials or wall-clock noise.
var templateSourceTables = []struct{ name, order string }{
	{"accounts", "id"}, {"goals", "id"}, {"income_origins", "id"}, {"income_locations", "id"},
	{"income_reservations", "action_id"}, {"income_claims", "action_id,fragment_id"},
	{"template_policies", "id"}, {"template_policy_versions", "policy_id,version"},
	{"template_policy_confirmations", "id"}, {"template_policy_status_events", "version_id,sequence"},
	{"template_obligations", "id"}, {"template_obligation_payments", "id"},
	{"receipts", "id"},
}

func (s *Service) loadTemplateSnapshot(ctx context.Context, tx pgx.Tx, p Principal, now time.Time, timezone string) (templateSnapshot, error) {
	loadTemplateSnapshotAttempts.Add(1)
	out := templateSnapshot{AsOf: now, Timezone: timezone, Raw: map[string][]string{}}
	env, err := s.environment(ctx, tx, false)
	if err != nil {
		return out, err
	}
	if err = sameUser(p, env.ID); err != nil {
		return out, err
	}
	if err = ensureNativeBillsReady(ctx, tx, p); err != nil {
		return out, err
	}
	out.WriterGeneration, out.ControlVersion = env.WriterGeneration, env.ControlVersion
	if err = tx.QueryRow(ctx, `SELECT funds_version,source_version FROM users WHERE environment_id=$1 AND id=$2`, p.EnvironmentID.String(), p.UserID.String()).Scan(&out.FundsVersion, &out.SourceVersion); err != nil {
		return out, err
	}
	out.Inventory, out.InventoryRaw, err = s.templateInventory(ctx, tx, p, out.SourceVersion)
	if err != nil {
		return out, err
	}
	out.Facts = policy.TemplateFacts{Scope: out.Inventory.Scope, Complete: true, IncomeComplete: true, Accounts: []policy.TemplateAccountFact{}, Income: []policy.TemplateIncomeFact{}, Goals: []policy.TemplateGoalFact{}, Bills: []policy.TemplateBillFact{}, Settlements: []policy.TemplateSettlementFact{}, HistoryAccounts: []funds.ID{}, History: []policy.TemplateHistoryTransaction{}, Coverage: []policy.TemplateHistoryCoverage{}, Products: []policy.TemplateAssetProductFact{}, Positions: []policy.TemplatePositionFact{}, EmergencyDeficits: []policy.TemplateEmergencyDeficit{}, SeasonalWindows: []policy.TemplateSeasonalWindow{}, ProtectedReferences: []policy.TemplatePolicyReference{}}
	totalBytes, totalRows := 0, 0
	tables := append([]struct{ name, order string }(nil), templateSourceTables...)
	var nativeEnabled bool
	if err = tx.QueryRow(ctx, `SELECT to_regclass('native_goal_balances') IS NOT NULL`).Scan(&nativeEnabled); err != nil {
		return out, err
	}
	if nativeEnabled {
		tables = append(tables, templateNativeSourceTables...)
	}
	out.SourceWitnessEnabled, err = templateSourceWitnessEnabled(ctx, tx)
	if err != nil {
		return out, err
	}
	if out.SourceWitnessEnabled {
		// The previous basis omitted these rows although LoadLedger unions
		// them. Forward originals retain the complete native income prefix.
		tables = append(tables, struct{ name, order string }{"native_income_reservations", "action_id"}, struct{ name, order string }{"native_income_claims", "action_id,fragment_id"})
	}
	var paymentEnabled bool
	if err = tx.QueryRow(ctx, `SELECT to_regclass('native_obligation_payments') IS NOT NULL`).Scan(&paymentEnabled); err != nil {
		return out, err
	}
	if paymentEnabled {
		tables = append(tables, struct{ name, order string }{"native_payment_sources", "operation_id"}, struct{ name, order string }{"native_obligation_payments", "id"})
	}
	for _, table := range tables {
		query := `SELECT octet_length(to_jsonb(t)::text),CASE WHEN octet_length(to_jsonb(t)::text)<=$3 THEN to_jsonb(t)::text END FROM ` + table.name + ` t WHERE environment_id=$1 AND user_id=$2 ORDER BY ` + table.order + ` LIMIT 10001`
		rows, e := tx.Query(ctx, query, p.EnvironmentID.String(), p.UserID.String(), 4*1024*1024-totalBytes)
		if e != nil {
			return out, e
		}
		out.Raw[table.name] = []string{}
		for rows.Next() {
			var raw *string
			var n int64
			if e = rows.Scan(&n, &raw); e != nil {
				rows.Close()
				return out, e
			}
			totalRows++
			if raw == nil || n < 0 || n > int64(4*1024*1024-totalBytes) || totalRows > 10000 {
				rows.Close()
				return out, reject("TEMPLATE_CAPACITY_EXCEEDED", nil)
			}
			totalBytes += int(n)
			out.Raw[table.name] = append(out.Raw[table.name], *raw)
		}
		e = rows.Err()
		rows.Close()
		if e != nil {
			return out, e
		}
	}
	var owned funds.Money
	for _, raw := range out.Raw["accounts"] {
		var row struct {
			ID      funds.ID `json:"id"`
			Balance int64    `json:"balance_cents"`
			Owned   int64    `json:"goal_owned_cents"`
		}
		if json.Unmarshal([]byte(raw), &row) != nil {
			return out, reject("TEMPLATE_FACTS_INVALID", nil)
		}
		balance, e := templateMoney(row.Balance)
		if e != nil {
			return out, e
		}
		goalOwned, e := templateMoney(row.Owned)
		if e != nil || row.Owned > row.Balance {
			return out, reject("TEMPLATE_FACTS_INVALID", e)
		}
		out.Facts.Accounts = append(out.Facts.Accounts, policy.TemplateAccountFact{ID: row.ID, Balance: balance, Verified: true})
		out.Facts.CurrentCash, e = out.Facts.CurrentCash.Add(balance)
		if e != nil {
			return out, e
		}
		owned, e = owned.Add(goalOwned)
		if e != nil {
			return out, e
		}
	}
	ledger, err := s.Store.LoadLedger(ctx, tx, p.EnvironmentID, p.UserID, now)
	if err != nil {
		return out, reject("TEMPLATE_FACTS_INVALID", err)
	}
	for _, location := range ledger.Snapshot().Locations {
		out.Held, err = out.Held.Add(location.Reserved)
		if err != nil {
			return out, err
		}
	}
	if nativeEnabled {
		native, e := s.Store.LoadNativeLedger(ctx, tx, p.EnvironmentID, p.UserID, now)
		if e != nil {
			return out, reject("TEMPLATE_NATIVE_FACTS_INVALID", e)
		}
		out.Native = &native
		out.Held, err = nativeTemplateHeld(out.Held, ledger, native)
		if err != nil {
			return out, reject("TEMPLATE_NATIVE_FACTS_INVALID", err)
		}
	}
	lots, err := ledger.IncomeLots(now)
	if err != nil {
		return out, reject("TEMPLATE_FACTS_INVALID", err)
	}
	availableByOrigin := map[funds.ID]funds.Money{}
	for _, lot := range lots {
		id := lot.Origin.ID()
		availableByOrigin[id], err = availableByOrigin[id].Add(lot.Available)
		if err != nil {
			return out, err
		}
	}
	for _, origin := range ledger.Snapshot().Origins {
		fact := origin.Fact()
		if fact.OccurredAt.After(now) {
			return out, reject("TEMPLATE_FACTS_INVALID", nil)
		}
		out.Facts.Income = append(out.Facts.Income, policy.TemplateIncomeFact{ID: origin.ID(), Available: availableByOrigin[origin.ID()], OccurredAt: fact.OccurredAt, Verified: true})
	}
	out.Views, err = s.loadTemplatePolicies(ctx, tx, p)
	if err != nil {
		return out, err
	}
	byGoal := map[funds.ID]policy.TemplateVersion{}
	for _, view := range out.Views {
		if view.Timezone != timezone {
			return out, reject("TEMPLATE_TIMEZONE_CONFLICT", nil)
		}
		out.Versions = append(out.Versions, view.Version)
		if view.GoalID != nil {
			byGoal[*view.GoalID] = view.Version
		}
	}
	zone, _ := policy.TemplateLocation(timezone)
	monthly, contributionEvidence, err := s.templateContributionEvidence(ctx, tx, p, out)
	if err != nil {
		return out, err
	}
	var assigned funds.Money
	for _, raw := range out.Raw["goals"] {
		var row struct {
			ID, AccountID funds.ID
			Assigned      int64
			Month         int64
			Period        string
		}
		var value struct {
			ID        funds.ID `json:"id"`
			AccountID funds.ID `json:"account_id"`
			Assigned  int64    `json:"assigned_cents"`
			Month     int64    `json:"month_contributed_cents"`
			Period    string   `json:"month_period"`
		}
		if json.Unmarshal([]byte(raw), &value) != nil {
			return out, reject("TEMPLATE_FACTS_INVALID", nil)
		}
		row.ID, row.AccountID, row.Assigned, row.Month, row.Period = value.ID, value.AccountID, value.Assigned, value.Month, value.Period
		amount, e := templateMoney(row.Assigned)
		if e != nil {
			return out, e
		}
		cash := amount
		if out.Native != nil {
			found := false
			for _, balance := range out.Native.Goals {
				if balance.GoalID == row.ID {
					actual, e := balance.Cash.Add(balance.Principal)
					if e != nil || actual != amount || balance.AccountID != row.AccountID {
						return out, reject("TEMPLATE_NATIVE_FACTS_INVALID", e)
					}
					cash, found = balance.Cash, true
				}
			}
			if !found {
				return out, reject("TEMPLATE_NATIVE_FACTS_INVALID", nil)
			}
		}
		assigned, e = assigned.Add(cash)
		if e != nil {
			return out, e
		}
		if contributionEvidence[row.ID].Cents() < amount.Cents() {
			return out, reject("TEMPLATE_CONTRIBUTION_EVIDENCE_INCOMPLETE", nil)
		}
		goal := policy.TemplateGoalFact{ID: row.ID, AccountID: row.AccountID, Owned: amount, CashOwned: cash, MonthContributed: monthly[row.ID], MonthPeriod: now.In(zone).Format("2006-01"), Verified: true}
		if version, ok := byGoal[row.ID]; ok {
			goal.PolicyID = version.PolicyID
			goal.VersionID = version.VersionID
			v := version
			goal.GoalVersion = &v
		}
		out.Facts.Goals = append(out.Facts.Goals, goal)
	}
	out.UnassignedGoalCash, err = owned.Sub(assigned)
	if err != nil {
		return out, reject("TEMPLATE_FACTS_INVALID", err)
	}
	if err = s.loadNativeBillFacts(ctx, tx, p, &out); err != nil {
		return out, err
	}
	if err = s.templateRetained(ctx, tx, p, &out); err != nil {
		return out, err
	}
	if err = s.loadTemplateHistory(ctx, tx, p, &out); err != nil {
		return out, err
	}
	if err = templateSettlements(&out); err != nil {
		return out, err
	}
	if err = expandTemplateHistory(&out); err != nil {
		return out, err
	}
	if err = s.collectForecastHistory(ctx, tx, p, &out); err != nil {
		return out, err
	}
	basis := struct {
		Scope                         policy.TemplateOwnerScope
		Inventory                     templateInventory
		FundsVersion, Writer, Control uint64
		Rows                          map[string][]string
	}{out.Facts.Scope, out.Inventory, out.FundsVersion, out.WriterGeneration, out.ControlVersion, out.Raw}
	raw, err := encode(basis)
	if err != nil {
		return out, err
	}
	out.Facts.SourceHash = Hash(raw)
	out.SourceBasisOriginal = append([]byte(nil), raw...)
	// This is a deterministic current boundary/action fingerprint, not evidence
	// that the user was asked, answered, or authorized anything.
	actionsRaw, err := encode(struct{ Reservations, Holds []string }{out.Raw["income_reservations"], out.Raw["native_holds"]})
	if err != nil {
		return out, err
	}
	out.Facts.Intervention = &policy.TemplateInterventionEvent{Reasons: []string{}, PriorReasons: []string{}, BoundaryEventHash: out.Facts.SourceHash, ActionSetHash: Hash(actionsRaw)}
	return out, nil
}

func (snapshot templateSnapshot) forecastInput(days int) planning.ForecastInput {
	return planning.ForecastInput{Scope: snapshot.Facts.Scope, AsOf: snapshot.AsOf, Timezone: snapshot.Timezone, HorizonDays: days, Complete: true, InventoryHash: Hash(snapshot.InventoryRaw), Facts: snapshot.Facts, Versions: snapshot.Versions, RetainedObligations: snapshot.Retained, RetainedFloors: []planning.ForecastFloor{}, HeldCash: snapshot.Held, UnassignedGoalCash: snapshot.UnassignedGoalCash, FutureIncome: []planning.ForecastIncome{}, PrincipalReturns: []planning.ForecastPrincipalReturn{}, ExternalLiabilities: snapshot.ExternalLiabilities}
}

func forecastTemplateSnapshot(snapshot templateSnapshot, days int) (ForecastView, error) {
	result, err := planning.Forecast365(snapshot.forecastInput(days))
	if err != nil {
		return ForecastView{}, reject("TEMPLATE_FACTS_INCOMPLETE", err)
	}
	return ForecastView{Protocol: "template-forecast-view-v1", SourceHash: snapshot.Facts.SourceHash, InventoryHash: Hash(snapshot.InventoryRaw), FundsVersion: snapshot.FundsVersion, SourceVersion: snapshot.SourceVersion, Result: result}, nil
}

func (s *Service) Forecast(ctx context.Context, p Principal, in ForecastRequest) (ForecastView, error) {
	if err := s.auditHuman(ctx, p); err != nil {
		return ForecastView{}, err
	}
	tx, err := s.Pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	if err != nil {
		return ForecastView{}, err
	}
	defer rollback(ctx, tx)
	zone, err := templateScopedTimezone(ctx, tx, p, in.Timezone)
	if err != nil {
		return ForecastView{}, err
	}
	snapshot, err := s.loadTemplateSnapshot(ctx, tx, p, s.now(), zone)
	if err != nil {
		return ForecastView{}, err
	}
	if err = tx.Commit(ctx); err != nil {
		return ForecastView{}, err
	}
	return forecastTemplateSnapshot(snapshot, in.HorizonDays)
}

func (s *Service) templateRetained(ctx context.Context, tx pgx.Tx, p Principal, snapshot *templateSnapshot) error {
	paid, err := nativeTemplateDebtPayments(ctx, tx, p, *snapshot)
	if err != nil {
		return err
	}
	snapshot.PaymentFinalTotals, err = nativeAdoptedPaymentFinalTotals(*snapshot, paid)
	if err != nil {
		return err
	}
	for _, raw := range snapshot.Raw["template_obligation_payments"] {
		var row struct {
			ID           funds.ID `json:"id"`
			ObligationID string   `json:"obligation_id"`
			OperationID  funds.ID `json:"operation_id"`
			ReceiptID    funds.ID `json:"receipt_id"`
			Amount       int64    `json:"amount_cents"`
			Original     string   `json:"original"`
			Hash         string   `json:"original_hash"`
		}
		if json.Unmarshal([]byte(raw), &row) != nil {
			return reject("TEMPLATE_FACTS_INVALID", nil)
		}
		original, err := decodePGBytea(row.Original)
		if err != nil || Hash(original) != row.Hash || !json.Valid(original) {
			return reject("TEMPLATE_FACTS_INVALID", err)
		}
		// No first-chain ALLOCATE_GOAL receipt may clear an external debt. The
		// payment family registers its own proven SPEND consumer before use.
		var valid bool
		if err := tx.QueryRow(ctx, `SELECT o.status='SETTLED' AND o.receipt_id=$4::uuid AND r.operation_id=o.id AND convert_from(o.bank_request,'UTF8')::jsonb->>'kind'='SPEND' FROM operations o JOIN receipts r ON(r.environment_id=o.environment_id AND r.user_id=o.user_id AND r.id=$4) WHERE o.environment_id=$1 AND o.user_id=$2 AND o.id=$3`, p.EnvironmentID.String(), p.UserID.String(), row.OperationID.String(), row.ReceiptID.String()).Scan(&valid); err != nil || !valid {
			return reject("TEMPLATE_PAYMENT_EVIDENCE_INVALID", err)
		}
		amount, err := templateMoney(row.Amount)
		if err != nil {
			return err
		}
		paid[row.ObligationID], err = paid[row.ObligationID].Add(amount)
		if err != nil {
			return err
		}
	}
	for _, raw := range snapshot.Raw["template_obligations"] {
		var row struct {
			ID        string   `json:"id"`
			PolicyID  funds.ID `json:"policy_id"`
			VersionID funds.ID `json:"version_id"`
			Amount    int64    `json:"amount_cents"`
			DueDate   string   `json:"due_date"`
			Original  string   `json:"original"`
			Hash      string   `json:"original_hash"`
		}
		if json.Unmarshal([]byte(raw), &row) != nil {
			return reject("TEMPLATE_FACTS_INVALID", nil)
		}
		original, err := decodePGBytea(row.Original)
		if err != nil || Hash(original) != row.Hash {
			return reject("TEMPLATE_FACTS_INVALID", err)
		}
		var obligation planning.ForecastObligation
		if auditJSON(original, &obligation) != nil || obligation.ID != row.ID || obligation.PolicyID != row.PolicyID || obligation.VersionID != row.VersionID || obligation.Amount.Cents() != row.Amount || obligation.DueDate != row.DueDate || !obligation.Verified || !auditDigestOK(obligation.SourceHash) {
			return reject("TEMPLATE_FACTS_INVALID", nil)
		}
		if total, known := snapshot.PaymentFinalTotals[row.ID]; known {
			if total.Cents() > obligation.Amount.Cents() {
				return reject("TEMPLATE_PAYMENT_EVIDENCE_INVALID", nil)
			}
			obligation.Amount = total
		}
		obligation.Amount, err = obligation.Amount.Sub(paid[row.ID])
		if err != nil {
			return reject("TEMPLATE_FACTS_INVALID", err)
		}
		snapshot.Retained = append(snapshot.Retained, obligation)
	}
	return nil
}

func templateSettlements(snapshot *templateSnapshot) error {
	// The sealed seed inventory plus the complete native payment registry prove
	// no other native payment exists. Historical months therefore have explicit
	// zero-paid facts instead of silently treating a missing imported bill as 0.
	zone, _ := policy.TemplateLocation(snapshot.Timezone)
	paidByDebt := map[string]funds.Money{}
	for _, raw := range append(append([]string{}, snapshot.Raw["template_obligation_payments"]...), snapshot.Raw["native_obligation_payments"]...) {
		var payment struct {
			ObligationID string `json:"obligation_id"`
			Amount       int64  `json:"amount_cents"`
		}
		if json.Unmarshal([]byte(raw), &payment) != nil {
			return reject("TEMPLATE_FACTS_INVALID", nil)
		}
		amount, err := templateMoney(payment.Amount)
		if err != nil {
			return err
		}
		paidByDebt[payment.ObligationID], err = paidByDebt[payment.ObligationID].Add(amount)
		if err != nil {
			return err
		}
	}
	registered := map[string]policy.TemplateSettlementFact{}
	for _, raw := range snapshot.Raw["template_obligations"] {
		var debt struct {
			ID, Period string
			PolicyID   funds.ID
			Amount     int64
		}
		var row struct {
			ID       string   `json:"id"`
			Period   string   `json:"period_key"`
			PolicyID funds.ID `json:"policy_id"`
			Amount   int64    `json:"amount_cents"`
		}
		if json.Unmarshal([]byte(raw), &row) != nil {
			return reject("TEMPLATE_FACTS_INVALID", nil)
		}
		debt.ID, debt.Period, debt.PolicyID, debt.Amount = row.ID, row.Period, row.PolicyID, row.Amount
		total, err := templateMoney(debt.Amount)
		if err != nil {
			return err
		}
		if actual, known := snapshot.PaymentFinalTotals[debt.ID]; known {
			total = actual
		}
		fact := policy.TemplateSettlementFact{PolicyID: debt.PolicyID, Period: debt.Period, Paid: paidByDebt[debt.ID], FinalTotal: &total, Verified: true}
		key := debt.PolicyID.String() + "/" + debt.Period
		if _, duplicate := registered[key]; duplicate {
			return reject("TEMPLATE_FACTS_INVALID", nil)
		}
		registered[key] = fact
	}
	seen := map[string]bool{}
	add := func(id funds.ID, period string) {
		key := id.String() + "/" + period
		if seen[key] {
			return
		}
		seen[key] = true
		if fact, ok := registered[id.String()+"/"+period]; ok {
			snapshot.Facts.Settlements = append(snapshot.Facts.Settlements, fact)
		} else {
			snapshot.Facts.Settlements = append(snapshot.Facts.Settlements, policy.TemplateSettlementFact{PolicyID: id, Period: period, Verified: true})
		}
	}
	for _, version := range snapshot.HistoricalVersions {
		compiled, err := version.Compiled.Decode()
		if err != nil {
			return reject("TEMPLATE_FACTS_INVALID", err)
		}
		switch config := compiled.(type) {
		case *policy.RecurringObligationConfig:
			if config.AmountRule.Kind == "bill_balance" {
				continue
			}
		case *policy.PeriodicTransferConfig:
		case *policy.DatedExpenseConfig:
			add(version.PolicyID, config.Window.Start+"/"+config.Window.End)
			continue
		default:
			continue
		}
		start := version.ConfirmedAt.In(zone)
		month := time.Date(start.Year(), start.Month(), 1, 0, 0, 0, 0, zone)
		current := snapshot.AsOf.In(zone).Format("2006-01")
		for count := 0; month.Format("2006-01") <= current; count++ {
			if count > 120 {
				return reject("TEMPLATE_CAPACITY_EXCEEDED", nil)
			}
			add(version.PolicyID, month.Format("2006-01"))
			month = month.AddDate(0, 1, 0)
		}
	}
	return nil
}

func decodePGBytea(value string) ([]byte, error) {
	if !strings.HasPrefix(value, `\x`) {
		return nil, reject("TEMPLATE_FACTS_INVALID", nil)
	}
	return hex.DecodeString(value[2:])
}

func templateProtectionForForecast(input planning.ForecastInput, result planning.ForecastResult) (planning.Protection, error) {
	unowned := input.Facts.CurrentCash
	var err error
	for _, goal := range input.Facts.Goals {
		unowned, err = unowned.Sub(goal.CashOwned)
		if err != nil {
			return planning.Protection{}, reject("TEMPLATE_FACTS_INVALID", err)
		}
	}
	unowned, err = unowned.Sub(input.UnassignedGoalCash)
	if err != nil {
		return planning.Protection{}, reject("TEMPLATE_FACTS_INVALID", err)
	}
	unowned, err = unowned.Sub(input.HeldCash)
	if err != nil {
		return planning.Protection{}, reject("TEMPLATE_FACTS_INVALID", err)
	}
	other := funds.Money{}
	if result.CurrentSafe.Cents() < unowned.Cents() {
		other, _ = unowned.Sub(result.CurrentSafe)
	}
	other, err = other.Add(result.MaximumDeficit)
	if err != nil {
		return planning.Protection{}, reject("TEMPLATE_CAPACITY_EXCEEDED", err)
	}
	return planning.Protection{Complete: true, ObservedAt: input.AsOf, EvidenceHash: result.InputHash, Checkpoints: []planning.ProtectionCheckpoint{{ID: "native-template-protection-365-v1", At: input.AsOf, OtherProtected: other}}}, nil
}

// Before the first synthetic income exists, USER may already have confirmed
// native rules. Every intervening source version must be our exact immutable
// publication, with reproducible input/result/protection and the seed inventory.
// This never makes income before a policy's confirmation eligible for it.
func (s *Service) validateDemoNativeProtectionChain(ctx context.Context, tx pgx.Tx, p Principal, current uint64) error {
	if current < 2 || current > 128 {
		return reject("DEMO_NATIVE_PROTECTION_CHAIN_INCOMPLETE", nil)
	}
	_, inventory, err := s.templateInventory(ctx, tx, p, current)
	if err != nil {
		return err
	}
	rows, err := tx.Query(ctx, `SELECT p.source_version,p.input_original,p.input_hash::text,p.result_original,p.result_hash::text,p.protection_hash::text,s.original,s.original_hash::text,p.basis_hash::text,p.local_date::text,p.timezone FROM template_protection_publications p JOIN protection_snapshots s ON(s.environment_id=p.environment_id AND s.user_id=p.user_id AND s.version=p.source_version) WHERE p.environment_id=$1 AND p.user_id=$2 AND p.source_version BETWEEN 2 AND $3 ORDER BY p.source_version`, p.EnvironmentID.String(), p.UserID.String(), current)
	if err != nil {
		return err
	}
	defer rows.Close()
	expected, totalBytes := uint64(2), 0
	for rows.Next() {
		var version uint64
		var inputRaw, resultRaw, protectionRaw []byte
		var inputHash, resultHash, protectionHash, originalHash, basisHash, date, timezone string
		if err = rows.Scan(&version, &inputRaw, &inputHash, &resultRaw, &resultHash, &protectionHash, &protectionRaw, &originalHash, &basisHash, &date, &timezone); err != nil {
			return err
		}
		totalBytes += len(inputRaw) + len(resultRaw) + len(protectionRaw)
		var input planning.ForecastInput
		if version != expected || totalBytes > 16*1024*1024 || Hash(inputRaw) != inputHash || Hash(resultRaw) != resultHash || Hash(protectionRaw) != protectionHash || protectionHash != originalHash || auditJSON(inputRaw, &input) != nil || input.Scope != (policy.TemplateOwnerScope{EnvironmentID: p.EnvironmentID, UserID: p.UserID}) || input.InventoryHash != Hash(inventory) || input.Timezone != timezone || !input.Complete || !input.Facts.CurrentCash.IsZero() || len(input.Facts.Income) != 0 || len(input.FutureIncome) != 0 || len(input.PrincipalReturns) != 0 {
			return reject("DEMO_NATIVE_PROTECTION_CHAIN_INVALID", nil)
		}
		zone, e := policy.TemplateLocation(timezone)
		if e != nil || input.AsOf.In(zone).Format("2006-01-02") != date {
			return reject("DEMO_NATIVE_PROTECTION_CHAIN_INVALID", e)
		}
		basis, _ := encode(struct{ SourceHash, Date, Timezone string }{input.Facts.SourceHash, date, timezone})
		if Hash(basis) != basisHash {
			return reject("DEMO_NATIVE_PROTECTION_CHAIN_INVALID", nil)
		}
		result, e := planning.Forecast365(input)
		replayed, _ := encode(result)
		if e != nil || !bytes.Equal(replayed, resultRaw) {
			return reject("DEMO_NATIVE_PROTECTION_CHAIN_INVALID", e)
		}
		protection, e := templateProtectionForForecast(input, result)
		replayed, _ = encode(protection)
		if e != nil || !bytes.Equal(replayed, protectionRaw) {
			return reject("DEMO_NATIVE_PROTECTION_CHAIN_INVALID", e)
		}
		expected++
	}
	if err = rows.Err(); err != nil {
		return err
	}
	if expected != current+1 {
		return reject("DEMO_NATIVE_PROTECTION_CHAIN_INCOMPLETE", nil)
	}
	return nil
}

// refreshTemplateProtection runs inside the normal environment/user lock order.
// It publishes a new source version only when semantic inputs or natural date
// change. A wall-clock-only refresh cannot invalidate every pending candidate.
func (s *Service) refreshTemplateProtection(ctx context.Context, tx pgx.Tx, p Principal, timezone string) (ForecastView, error) {
	snapshot, err := s.loadTemplateSnapshot(ctx, tx, p, s.now(), timezone)
	if err != nil {
		return ForecastView{}, err
	}
	if err = saveTemplateInventory(ctx, tx, p, snapshot); err != nil {
		return ForecastView{}, err
	}
	if changed, e := s.persistTemplateHistory(ctx, tx, p, snapshot); e != nil {
		return ForecastView{}, e
	} else if changed {
		// Rebind source hash and original remaining amounts to the just-written
		// authority rows before publishing a new protection version.
		snapshot, err = s.loadTemplateSnapshot(ctx, tx, p, s.now(), timezone)
		if err != nil {
			return ForecastView{}, err
		}
	}
	view, err := forecastTemplateSnapshot(snapshot, 365)
	if err != nil {
		return view, err
	}
	zone, _ := policy.TemplateLocation(timezone)
	today := snapshot.AsOf.In(zone).Format("2006-01-02")
	basisRaw, _ := encode(struct{ SourceHash, Date, Timezone string }{snapshot.Facts.SourceHash, today, timezone})
	basis := Hash(basisRaw)
	var existing uint64
	err = tx.QueryRow(ctx, `SELECT source_version FROM template_protection_publications WHERE environment_id=$1 AND user_id=$2 AND basis_hash=$3`, p.EnvironmentID.String(), p.UserID.String(), basis).Scan(&existing)
	if err == nil {
		view.ProtectionSourceVersion = &existing
		return view, nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return view, err
	}
	protection, err := templateProtectionForForecast(snapshot.forecastInput(365), view.Result)
	if err != nil {
		return view, err
	}
	raw, err := encode(protection)
	if err != nil {
		return view, err
	}
	var sv uint64
	if err = tx.QueryRow(ctx, `UPDATE users SET source_version=source_version+1 WHERE environment_id=$1 AND id=$2 RETURNING source_version`, p.EnvironmentID.String(), p.UserID.String()).Scan(&sv); err != nil {
		return view, err
	}
	_, err = tx.Exec(ctx, `INSERT INTO protection_snapshots(environment_id,user_id,version,original,original_hash,observed_at) VALUES($1,$2,$3,$4,$5,$6)`, p.EnvironmentID.String(), p.UserID.String(), sv, raw, Hash(raw), snapshot.AsOf)
	if err != nil {
		return view, err
	}
	inputRaw, err := encode(snapshot.forecastInput(365))
	if err != nil {
		return view, err
	}
	resultRaw, err := encode(view.Result)
	if err != nil {
		return view, err
	}
	witnessID, witnessHash, err := s.saveTemplateSourceWitness(ctx, tx, p, snapshot)
	if err != nil {
		return view, err
	}
	if snapshot.SourceWitnessEnabled {
		_, err = tx.Exec(ctx, `INSERT INTO template_protection_publications(environment_id,user_id,source_version,basis_hash,local_date,timezone,input_original,input_hash,result_original,result_hash,protection_hash,created_at,source_witness_id,source_witness_hash) VALUES($1,$2,$3,$4,$5::date,$6,$7,$8,$9,$10,$11,$12,$13,$14)`, p.EnvironmentID.String(), p.UserID.String(), sv, basis, today, timezone, inputRaw, Hash(inputRaw), resultRaw, Hash(resultRaw), Hash(raw), snapshot.AsOf, witnessID.String(), witnessHash)
	} else {
		_, err = tx.Exec(ctx, `INSERT INTO template_protection_publications(environment_id,user_id,source_version,basis_hash,local_date,timezone,input_original,input_hash,result_original,result_hash,protection_hash,created_at) VALUES($1,$2,$3,$4,$5::date,$6,$7,$8,$9,$10,$11,$12)`, p.EnvironmentID.String(), p.UserID.String(), sv, basis, today, timezone, inputRaw, Hash(inputRaw), resultRaw, Hash(resultRaw), Hash(raw), snapshot.AsOf)
	}
	if err != nil {
		return view, err
	}
	view.SourceVersion = sv
	view.ProtectionSourceVersion = &sv
	return view, nil
}

func (s *Service) RefreshTemplateProtection(ctx context.Context, p Principal) (ForecastView, error) {
	tx, err := s.begin(ctx)
	if err != nil {
		return ForecastView{}, err
	}
	defer rollback(ctx, tx)
	env, err := s.environment(ctx, tx, true)
	if err != nil {
		return ForecastView{}, err
	}
	if err = sameUser(p, env.ID); err != nil {
		return ForecastView{}, err
	}
	if _, _, err = lockUser(ctx, tx, p); err != nil {
		return ForecastView{}, err
	}
	if p.Kind == "USER" {
		if err = s.human(ctx, tx, p); err != nil {
			return ForecastView{}, err
		}
	}
	zone, err := templateScopedTimezone(ctx, tx, p, "")
	if err != nil {
		return ForecastView{}, err
	}
	view, err := s.refreshTemplateProtection(ctx, tx, p, zone)
	if err != nil {
		return view, err
	}
	return view, tx.Commit(ctx)
}

// Helpers shared by native policy lifecycle code; neither changes originals.
func templateSameBytes(a, b []byte) bool { return bytes.Equal(a, b) }
func templateSortedVersions(versions []policy.TemplateVersion) {
	sort.Slice(versions, func(i, j int) bool { return versions[i].PolicyID.String() < versions[j].PolicyID.String() })
}
