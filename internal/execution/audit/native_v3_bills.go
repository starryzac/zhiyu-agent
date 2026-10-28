package executionaudit

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	evidence "zhiyu.local/zhiyu-go/internal/audit"
	"zhiyu.local/zhiyu-go/internal/execution/bankv2"
	funds "zhiyu.local/zhiyu-go/internal/funds/domain"
	planning "zhiyu.local/zhiyu-go/internal/planning/domain"
	policy "zhiyu.local/zhiyu-go/internal/policy/domain"
)

type nativeBillResolutionV3 struct {
	Protocol        string                    `json:"protocol"`
	Scope           policy.TemplateOwnerScope `json:"scope"`
	CaptureID       funds.ID                  `json:"capture_id"`
	ResultCaptureID funds.ID                  `json:"result_capture_id"`
	RecordedAt      time.Time                 `json:"recorded_at"`
}

type nativeDebtPaymentV3 struct {
	Protocol      string      `json:"protocol"`
	ID            funds.ID    `json:"id"`
	ObligationID  string      `json:"obligation_id"`
	OperationID   funds.ID    `json:"operation_id"`
	ReceiptID     funds.ID    `json:"receipt_id"`
	Amount        funds.Money `json:"amount_cents"`
	LiabilityHash string      `json:"liability_hash"`
	RecordedAt    time.Time   `json:"recorded_at"`
	// The payment is later than this immutable T1/T2 source watermark. The
	// injected business clock may stay equal across both transactions.
	afterSourceVersion uint64
}

type nativeVerifiedBillV3 struct {
	original     wireNativeBillOriginal
	raw          []byte
	hash, source string
	first, added time.Time
	reference    bankv2.LiabilityReference
}

type nativeBillIndexV3 struct {
	captures    map[string]wireNativeBillCapture
	results     map[string]wireNativeBillImportResult
	resolutions map[string]nativeBillResolutionV3
	bills       map[string]nativeVerifiedBillV3 // bank liability identity bill:<uuid>
	payments    []nativeDebtPaymentV3
	paid        map[string]funds.Money
	finals      map[string]funds.Money
	missing     bool
}

func nativeBillIncompleteV3(reason string) error {
	return fmt.Errorf("%w: native bill/debt %s", evidence.ErrIncomplete, reason)
}

func (g *nativeGraphV3) billSourcesAndObligations() error {
	index, err := g.nativeBillIndexV3()
	if err != nil {
		return err
	}
	if err = g.nativeObligationsV3(index); err != nil {
		return err
	}
	if err = g.checkedRowsV3(); err != nil {
		return err
	}
	if index.missing {
		return nativeBillIncompleteV3("unresolved capture, missing independent original or settled receipt")
	}
	return nil
}

func (g *nativeGraphV3) nativeBillIndexV3() (nativeBillIndexV3, error) {
	i := nativeBillIndexV3{captures: map[string]wireNativeBillCapture{}, results: map[string]wireNativeBillImportResult{}, resolutions: map[string]nativeBillResolutionV3{}, bills: map[string]nativeVerifiedBillV3{}, paid: map[string]funds.Money{}, finals: map[string]funds.Money{}}
	for _, row := range g.rows["native_bill_captures"] {
		var c wireNativeBillCapture
		raw := nativeOriginalV3(row, "original", &c)
		if len(raw) > 4<<20 || nativeHashFieldV3(row, "original", "original_hash") != nil || c.Protocol != "zhiyu-external-bill-capture-v1" {
			return i, businessInvalid("bill capture original protocol/hash")
		}
		if c.Protocol != "zhiyu-external-bill-capture-v1" || c.ID.String() != row.text("id") || c.Scope != g.ownerScopeV3() || c.SourceID != row.text("source_id") || !mirrorhistoryKeyV3(c.SourceID) || c.ActorKind != row.text("actor_kind") || c.IdempotencyKey != row.text("idempotency_key") || c.RequestHash != row.text("request_hash") || c.RequestHash != nakedHash([]byte("native-bill-import-source-v1\x00"+c.SourceID)) || c.RecordedFundsVersion != uint64(row.positive("recorded_funds_version")) || c.RecordedFundsVersion != c.Basis.FundsVersion+1 || c.Basis.SourceVersion < 1 || c.Basis.WriterGeneration < 1 || c.Basis.ControlVersion < 1 || c.RecordedFundsVersion > uint64(g.snapshot.Watermarks["funds_version"]) || !c.ObservedAt.Equal(row.instant("observed_at")) || c.ObservedAt.After(g.manifest.Source.CapturedAt) || c.BankAuthority {
			return i, businessInvalid("bill capture physical columns, scope or source versions")
		}
		if c.ActorKind == "USER" {
			if c.SessionID.String() != row.text("session_id") {
				return i, businessInvalid("bill capture USER session column")
			}
			if err := g.humanAtV3(c.SessionID, c.ObservedAt); err != nil {
				return i, err
			}
		} else if c.ActorKind != "SYSTEM" || c.SessionID != (funds.ID{}) || row.optional("session_id") != "" {
			return i, businessInvalid("bill observation cannot invent USER authority")
		}
		hashes, err := g.nativeCaptureBillHashesV3(c)
		if err != nil || !exactJSON(hashes, c.OriginalHashes) {
			return i, businessInvalid("bill capture exact complete statement/bank original membership")
		}
		i.captures[c.ID.String()] = c
	}
	if err := g.nativeBillPaymentRowsV3(&i); err != nil {
		return i, err
	}
	for _, row := range g.rows["native_bill_originals"] {
		raw := nativeRawV3(row, "original")
		first := row.instant("first_observed_at")
		b, err := mirrordecodeNativeBillOriginalV3(raw, g.ownerScopeV3(), g.manifest.Scope.Namespace, first)
		if err != nil || nativeHashFieldV3(row, "original", "original_hash") != nil || b.ID.String() != row.text("id") || b.StatementAccountID.String() != row.text("statement_account_id") || b.DueDate != row.text("due_date") || !b.IssuedAt.Equal(row.instant("issued_at")) || b.FinalTotal != row.money("final_total_cents") || b.PayeeID != row.text("payee_id") || b.ExternalKey != row.text("external_key") || g.row("accounts", b.StatementAccountID.String()) == nil {
			return i, businessInvalid("bill immutable original and projected columns")
		}
		ref := bankv2.LiabilityReference{ID: "bill:" + b.ID.String(), Kind: "BILL", FinalTotal: b.FinalTotal, PayeeID: b.PayeeID, EvidenceHash: nakedHash(raw)}
		var stored bankv2.LiabilityReference
		nativeOriginalV3(row, "bank_reference_original", &stored)
		if nativeHashFieldV3(row, "bank_reference_original", "bank_reference_hash") != nil || ref != stored || ref.Validate() != nil || row.instant("materialized_at").Before(first) || row.instant("materialized_at").After(g.manifest.Source.CapturedAt) {
			return i, businessInvalid("bill exact independent liability reference")
		}
		c, ok := i.captures[row.text("first_capture_id")]
		if !ok {
			i.missing = true
			continue
		}
		if c.SourceID != row.text("source_id") || !c.ObservedAt.Equal(first) || c.OriginalHashes[b.ID.String()] != nakedHash(raw) {
			return i, businessInvalid("bill first actual observation binding")
		}
		for _, earlier := range i.captures {
			if earlier.SourceID == c.SourceID && earlier.OriginalHashes[b.ID.String()] == nakedHash(raw) && earlier.ObservedAt.Before(first) {
				return i, businessInvalid("bill first observation cannot be moved to a later capture")
			}
		}
		i.bills[ref.ID] = nativeVerifiedBillV3{b, raw, nakedHash(raw), c.SourceID, first, row.instant("materialized_at"), ref}
	}
	if err := g.nativeBillResultsV3(&i); err != nil {
		return i, err
	}
	if g.bank == nil {
		i.missing = true
	} else {
		seen := map[string]bool{}
		for _, state := range g.bank.Liabilities.Liabilities {
			if state.Original.Kind != "BILL" {
				continue
			}
			bill, ok := i.bills[state.Original.ID]
			if !ok {
				i.missing = true
				continue
			}
			if state.Original != bill.reference || state.OriginalHash != nakedHash(mustJSONV3(bill.reference)) || state.Paid.Cents() < i.paid[state.Original.ID].Cents() {
				return i, businessInvalid("bill independent current original/actual-paid contradict local evidence")
			}
			if state.Paid != i.paid[state.Original.ID] {
				i.missing = true // a bank effect awaiting its original local T3
			}
			seen[state.Original.ID] = true
		}
		for id := range i.bills {
			if !seen[id] {
				i.missing = true
			}
		}
	}
	return i, g.checkedRowsV3()
}

func (g *nativeGraphV3) nativeCaptureBillHashesV3(c wireNativeBillCapture) (map[string]string, error) {
	s := c.Statements
	if s.Protocol != "zhiyu-external-bill-capture-v1/statements" || s.Namespace != g.manifest.Scope.Namespace || s.UserID != g.manifest.Scope.UserID || s.SourceID != c.SourceID || !s.Complete || s.Originals == nil || len(s.Originals) > 1000 || c.Bank.Validate() != nil || c.Bank.Namespace != s.Namespace || c.Bank.UserID != s.UserID || c.Bank.CapturedAt.After(c.ObservedAt.Add(time.Second)) || c.ObservedAt.Sub(c.Bank.CapturedAt) > 30*time.Second {
		return nil, businessInvalid("bill complete trusted capture envelope")
	}
	bank := map[string]bankv2.LiabilityReference{}
	for _, state := range c.Bank.Liabilities {
		if state.Original.Kind == "BILL" {
			bank[state.Original.ID] = state.Original
		}
	}
	hashes, external := map[string]string{}, map[string]bool{}
	var total int
	for _, raw := range s.Originals {
		total += len(raw)
		b, err := mirrordecodeNativeBillOriginalV3(raw, g.ownerScopeV3(), s.Namespace, c.ObservedAt)
		if err != nil || total > 2<<20 || hashes[b.ID.String()] != "" || external[b.ExternalKey] {
			return nil, businessInvalid("bill duplicate or invalid statement original")
		}
		ref := bankv2.LiabilityReference{ID: "bill:" + b.ID.String(), Kind: "BILL", FinalTotal: b.FinalTotal, PayeeID: b.PayeeID, EvidenceHash: nakedHash(raw)}
		if bank[ref.ID] != ref {
			return nil, businessInvalid("bill original not bound by independent bank reference")
		}
		delete(bank, ref.ID)
		hashes[b.ID.String()], external[b.ExternalKey] = nakedHash(raw), true
	}
	if len(bank) != 0 {
		return nil, businessInvalid("bill statement inventory omitted an independent liability")
	}
	return hashes, nil
}

func (g *nativeGraphV3) nativeBillPaymentRowsV3(i *nativeBillIndexV3) error {
	sources := map[string]bankv2.LiabilityState{}
	for _, row := range g.rows["native_payment_sources"] {
		var state bankv2.LiabilityState
		nativeOriginalV3(row, "original", &state)
		op := g.row("native_operations", row.text("operation_id"))
		r, found := g.nativeRequests[row.text("operation_id")]
		if op == nil || !found {
			i.missing = true
			continue
		}
		if nativeHashFieldV3(row, "original", "original_hash") != nil || state.Validate() != nil || op.text("command_kind") != string(bankv2.Payment) || r.Effect.Kind != bankv2.Payment || r.Effect.Liability == nil || state.Original != *r.Effect.Liability || state.Original.ID != row.text("obligation_id") || !state.Reserved.IsZero() || row.instant("observed_at").After(op.instant("created_at")) || row.text("accepted_xid") != op.text("accepted_xid") {
			return businessInvalid("payment source exact immutable independent liability at T1")
		}
		if old, ok := i.finals[state.Original.ID]; ok && old != state.Original.FinalTotal {
			return businessInvalid("one obligation cannot change its independently registered final total")
		}
		i.finals[state.Original.ID] = state.Original.FinalTotal
		sources[row.text("operation_id")] = state
	}
	used := map[string]bool{}
	for _, row := range g.rows["native_obligation_payments"] {
		var p nativeDebtPaymentV3
		nativeOriginalV3(row, "original", &p)
		request, found := g.nativeRequests[p.OperationID.String()]
		receipt, settled := g.nativeReceipts[p.OperationID.String()]
		source, sourced := sources[p.OperationID.String()]
		if !found || !settled || !sourced {
			i.missing = true
			continue
		}
		if nativeHashFieldV3(row, "original", "original_hash") != nil || p.Protocol != "native-obligation-payment-v1" || p.ID.String() != row.text("id") || p.OperationID.String() != row.text("operation_id") || p.ReceiptID.String() != row.text("receipt_id") || p.ObligationID != row.text("obligation_id") || p.Amount != row.money("amount_cents") || p.Amount.IsZero() || !p.RecordedAt.Equal(row.instant("recorded_at")) || !p.RecordedAt.Equal(receipt.RecordedAt) || p.RecordedAt.After(g.manifest.Source.CapturedAt) || receipt.ID != p.ReceiptID || request.Effect.Kind != bankv2.Payment || request.Effect.Liability == nil || request.Effect.Liability.ID != p.ObligationID || request.Effect.Amount != p.Amount || source.OriginalHash != p.LiabilityHash || used[p.OperationID.String()] {
			return businessInvalid("debt paid requires one verified SETTLED receipt, original amount and original liability")
		}
		used[p.OperationID.String()] = true
		var dependencies planning.DependencyVector
		op := g.row("native_operations", p.OperationID.String())
		if op == nil {
			return nativeBillIncompleteV3("payment operation watermark unavailable")
		}
		op.object("dependencies", &dependencies)
		if dependencies.SourceEvidenceVersion < 1 {
			return businessInvalid("payment exact source watermark")
		}
		p.afterSourceVersion = dependencies.SourceEvidenceVersion
		var err error
		i.paid[p.ObligationID], err = i.paid[p.ObligationID].Add(p.Amount)
		if err != nil || i.paid[p.ObligationID].Cents() > source.Original.FinalTotal.Cents() {
			return businessInvalid("debt actual paid cannot exceed immutable final total")
		}
		i.payments = append(i.payments, p)
	}
	for op, request := range g.nativeRequests {
		if request.Effect.Kind != bankv2.Payment {
			continue
		}
		if _, ok := sources[op]; !ok {
			i.missing = true
		}
		if _, ok := g.nativeReceipts[op]; ok && !used[op] {
			i.missing = true
		}
	}
	for _, row := range g.rows["template_obligation_payments"] {
		// The retained v1 family has no externally payable SPEND protocol. An
		// allocation/transfer receipt cannot clear a bill. Preserve unknown future
		// consumer originals as incomplete instead of treating arbitrary hashes
		// as real paid cash.
		op := g.row("operations", row.text("operation_id"))
		if op != nil {
			var header struct {
				Kind string `json:"kind"`
			}
			nativeOriginalV3(op, "bank_request", &header)
			if header.Kind == "ALLOCATE_GOAL" || header.Kind == "TRANSFER" {
				return businessInvalid("legacy internal allocation/transfer cannot pay external debt")
			}
		}
		i.missing = true
	}
	return nil
}

func (g *nativeGraphV3) nativeBillResultsV3(i *nativeBillIndexV3) error {
	for _, row := range g.rows["native_bill_import_results"] {
		var result wireNativeBillImportResult
		nativeOriginalV3(row, "original", &result)
		capture, ok := i.captures[result.CaptureID.String()]
		protection := g.row("protection_snapshots", strconv.FormatUint(result.SourceVersion, 10))
		publication := g.row("template_protection_publications", strconv.FormatUint(result.SourceVersion, 10))
		if !ok || protection == nil || publication == nil {
			i.missing = true
			continue
		}
		if nativeHashFieldV3(row, "original", "original_hash") != nil || result.Protocol != "native-bill-import-result-v1" || result.Scope != g.ownerScopeV3() || result.CaptureID.String() != row.text("capture_id") || result.FundsVersion != uint64(row.positive("funds_version")) || result.SourceVersion != uint64(row.positive("source_version")) || result.SourceVersion > uint64(g.snapshot.Watermarks["source_version"]) || result.ProtectionHash != row.text("protection_hash") || result.ProtectionHash != protection.text("original_hash") || result.ProtectionHash != publication.text("protection_hash") || !result.RecordedAt.Equal(row.instant("recorded_at")) || result.RecordedAt.Before(capture.ObservedAt) || result.RecordedAt.After(g.manifest.Source.CapturedAt) || result.ImportedBillIDs == nil || result.ResolvedCaptureIDs == nil || len(result.ResolvedCaptureIDs) < 1 || len(result.ResolvedCaptureIDs) > 1000 || len(result.ImportedBillIDs) > 1000 || result.BankAuthority {
			return businessInvalid("bill result immutable scope/version/protection publication")
		}
		i.results[result.CaptureID.String()] = result
	}
	for _, row := range g.rows["native_bill_capture_resolutions"] {
		var resolution nativeBillResolutionV3
		nativeOriginalV3(row, "original", &resolution)
		prior, p := i.captures[resolution.CaptureID.String()]
		next, n := i.captures[resolution.ResultCaptureID.String()]
		result, r := i.results[resolution.ResultCaptureID.String()]
		if !p || !n || !r {
			i.missing = true
			continue
		}
		if nativeHashFieldV3(row, "original", "original_hash") != nil || resolution.Protocol != "native-bill-capture-resolution-v1" || resolution.Scope != g.ownerScopeV3() || resolution.CaptureID.String() != row.text("capture_id") || resolution.ResultCaptureID.String() != row.text("result_capture_id") || !resolution.RecordedAt.Equal(row.instant("recorded_at")) || !resolution.RecordedAt.Equal(result.RecordedAt) || prior.SourceID != next.SourceID || prior.ObservedAt.After(next.ObservedAt) {
			return businessInvalid("bill resolution exact prior and result identity")
		}
		for id, hash := range prior.OriginalHashes {
			if next.OriginalHashes[id] != hash {
				return businessInvalid("later capture cannot replace an earlier original")
			}
		}
		i.resolutions[resolution.CaptureID.String()] = resolution
	}
	for id, result := range i.results {
		declared := map[string]bool{}
		for _, resolved := range result.ResolvedCaptureIDs {
			if declared[resolved.String()] || i.resolutions[resolved.String()].ResultCaptureID.String() != id {
				return businessInvalid("bill result exact unique resolution members")
			}
			declared[resolved.String()] = true
		}
		if !declared[id] {
			return businessInvalid("bill result must close its own capture")
		}
		for source, resolution := range i.resolutions {
			if resolution.ResultCaptureID.String() == id && !declared[source] {
				return businessInvalid("bill result omitted a stored resolution")
			}
		}
		imported := map[string]bool{}
		for _, bill := range result.ImportedBillIDs {
			known, ok := i.bills["bill:"+bill.String()]
			if !ok || imported[bill.String()] || !known.added.Equal(result.RecordedAt) {
				return businessInvalid("bill imported identity missing or materialization differs")
			}
			imported[bill.String()] = true
		}
		for bill, hash := range i.captures[id].OriginalHashes {
			known, ok := i.bills["bill:"+bill]
			if !ok || known.hash != hash || known.added.After(result.RecordedAt) {
				return businessInvalid("bill successful result omitted a statement original")
			}
		}
		for _, state := range i.captures[id].Bank.Liabilities {
			if state.Original.Kind == "BILL" && (!state.Reserved.IsZero() || state.Paid.Cents() > nativePaidByV3(i.payments, state.Original.ID, result.RecordedAt).Cents()) {
				return businessInvalid("bill imported while original bank settlement was still unproved")
			}
		}
	}
	for id := range i.captures {
		if _, ok := i.resolutions[id]; !ok {
			i.missing = true
		}
	}
	return nil
}

func nativePaidByV3(payments []nativeDebtPaymentV3, id string, at time.Time, sourceVersions ...uint64) funds.Money {
	var total funds.Money
	for _, p := range payments {
		if len(sourceVersions) > 0 && sourceVersions[0] != 0 && p.afterSourceVersion >= sourceVersions[0] {
			continue
		}
		if p.ObligationID == id && !p.RecordedAt.After(at) {
			total, _ = total.Add(p.Amount) // bounded and checked in the source index
		}
	}
	return total
}

func (g *nativeGraphV3) nativeObligationsV3(i nativeBillIndexV3) error {
	for _, row := range g.rows["template_obligations"] {
		var debt planning.ForecastObligation
		nativeOriginalV3(row, "original", &debt)
		version, ok := g.templates[debt.VersionID.String()]
		if !ok {
			return nativeBillIncompleteV3("adopted original policy version unavailable")
		}
		if nativeHashFieldV3(row, "original", "original_hash") != nil || debt.ID != row.text("id") || debt.PolicyID.String() != row.text("policy_id") || debt.VersionID.String() != row.text("version_id") || debt.Amount != row.money("amount_cents") || debt.Amount.IsZero() || debt.DueDate != row.text("due_date") || debt.SourceHash != version.Compiled.Hash || !debt.Verified || row.instant("adopted_at").Before(version.ConfirmedAt) || row.instant("adopted_at").After(g.manifest.Source.CapturedAt) || i.paid[debt.ID].Cents() > debt.Amount.Cents() {
			return businessInvalid("retained debt keeps exact original adopted amount/version")
		}
		if strings.HasPrefix(debt.ID, "bill:") {
			bill, found := i.bills[debt.ID]
			if !found {
				return nativeBillIncompleteV3("adopted bill original unavailable")
			}
			config, err := version.Compiled.Decode()
			rule, recurring := config.(*policy.RecurringObligationConfig)
			if err != nil || !recurring || rule.AmountRule.Kind != "bill_balance" || rule.AmountRule.AccountID == nil || *rule.AmountRule.AccountID != bill.original.StatementAccountID || debt.Amount != bill.original.FinalTotal || debt.DueDate != bill.original.DueDate || row.text("kind") != "BILL" || row.text("period_key") != debt.DueDate || row.instant("adopted_at").Before(bill.first) {
				return businessInvalid("bill debt adoption binds exact original statement and confirmed account rule")
			}
		} else if err := nativeConfiguredDebtOriginalV3(row, debt, version); err != nil {
			return err
		}
		if final, found := i.finals[debt.ID]; found && final.Cents() > debt.Amount.Cents() {
			return businessInvalid("external final total cannot enlarge original adopted upper bound")
		}
	}
	for id, paid := range i.paid {
		if paid.IsZero() {
			continue
		}
		if g.row("template_obligations", id) == nil {
			return nativeBillIncompleteV3("paid debt original unavailable")
		}
	}
	return nil
}

// Rehashing an adopted row cannot change the amount/date declared by the
// original USER configuration. External final totals only reduce the later
// remaining amount; they never rewrite this original upper bound.
func nativeConfiguredDebtOriginalV3(row *ledgerRow, debt planning.ForecastObligation, version policy.TemplateVersion) error {
	config, err := version.Compiled.Decode()
	if err != nil {
		return businessInvalid("retained debt confirmed configuration")
	}
	var rule *policy.TemplateAmountRule
	var dueDay int
	switch value := config.(type) {
	case *policy.RecurringObligationConfig:
		if value.AmountRule.Kind == "bill_balance" {
			return businessInvalid("bill amount rule cannot create an invented monthly debt")
		}
		rule, dueDay = &value.AmountRule, value.DueDay
	case *policy.PeriodicTransferConfig:
		rule, dueDay = &value.AmountRule, value.DueDay
	case *policy.DatedExpenseConfig:
		if debt.ID != debt.PolicyID.String()+":dated:"+value.Window.Start || row.text("kind") != "DATED" || row.text("period_key") != value.Window.Start+"/"+value.Window.End || debt.DueDate < value.Window.Start || debt.DueDate > value.Window.End || debt.Amount != value.Amount.Max {
			return businessInvalid("dated debt exact original confirmed window and upper amount")
		}
		return nil
	default:
		return businessInvalid("template cannot create an external debt original")
	}
	period := row.text("period_key")
	month, err := time.Parse("2006-01", period)
	upper := rule.Amount
	if rule.Kind == "range" {
		upper = rule.Max
	}
	if err != nil || rule.Kind != "exact" && rule.Kind != "range" || row.text("kind") != "MONTHLY" || debt.ID != debt.PolicyID.String()+":monthly:"+period || debt.DueDate != policy.TemplateDueDate(month.Year(), month.Month(), dueDay) || debt.Amount != upper {
		return businessInvalid("monthly debt exact original confirmed amount and calendar identity")
	}
	return nil
}

// Called for EVERY frozen preview/publication/permit input. A previous capture
// does not gain current paid values or future materialized bills by replay.
func (g *nativeGraphV3) checkBillForecastV3(input planning.ForecastInput, sourceVersion uint64) error {
	i, err := g.nativeBillIndexV3()
	if err != nil {
		return err
	}
	expected := map[string]nativeVerifiedBillV3{}
	for id, bill := range i.bills {
		if !bill.added.After(input.AsOf) {
			if bill.added.Equal(input.AsOf) {
				if sourceVersion == 0 {
					return nativeBillIncompleteV3("same-instant bill import watermark unavailable")
				}
				visible := false
				for _, result := range i.results {
					for _, imported := range result.ImportedBillIDs {
						if "bill:"+imported.String() == id && result.SourceVersion <= sourceVersion {
							visible = true
						}
					}
				}
				if !visible {
					continue
				}
			}
			expected[id] = bill
		}
	}
	seen := map[string]bool{}
	for _, fact := range input.Facts.Bills {
		id := "bill:" + fact.ID.String()
		bill, ok := expected[id]
		paid := nativePaidByV3(i.payments, id, input.AsOf, sourceVersion)
		if !ok || seen[id] || !fact.Verified || fact.AccountID != bill.original.StatementAccountID || fact.DueDate != bill.original.DueDate || fact.Total != bill.original.FinalTotal || fact.Paid != paid {
			return businessInvalid("forecast bill fact must use observed original and actual local receipt paid")
		}
		seen[id] = true
	}
	if len(seen) != len(expected) {
		return businessInvalid("forecast omitted known original bill facts")
	}
	seen = map[string]bool{}
	for _, external := range input.ExternalLiabilities {
		bill, ok := expected[external.ID]
		if !ok {
			return businessInvalid("forecast external liability invented or observed too late")
		}
		remaining, err := bill.original.FinalTotal.Sub(nativePaidByV3(i.payments, external.ID, input.AsOf, sourceVersion))
		if err != nil || seen[external.ID] || external.DueDate != bill.original.DueDate || external.SourceHash != bill.hash || !external.Verified || external.Remaining != remaining {
			return businessInvalid("forecast external debt remains protected even without active policy")
		}
		seen[external.ID] = true
	}
	if len(seen) != len(expected) {
		return businessInvalid("forecast omitted unbound or paused external debt")
	}
	return g.nativeHistoricalDebtForecastV3(i, input, sourceVersion)
}

func (g *nativeGraphV3) nativeHistoricalDebtForecastV3(i nativeBillIndexV3, input planning.ForecastInput, sourceVersion uint64) error {
	// Registered originals are immutable totals. Subtract only receipt evidence
	// which existed at this frozen instant; zero remainder stays registered.
	expected := map[string]planning.ForecastObligation{}
	for _, row := range g.rows["template_obligations"] {
		if row.instant("adopted_at").After(input.AsOf) {
			continue
		}
		var debt planning.ForecastObligation
		nativeOriginalV3(row, "original", &debt)
		if nativeHashFieldV3(row, "original", "original_hash") != nil {
			return businessInvalid("forecast retained original raw/hash")
		}
		if row.instant("adopted_at").Equal(input.AsOf) {
			prior, err := g.nativeDebtPriorSourceV3(debt.VersionID)
			if err != nil {
				return err
			}
			if sourceVersion == 0 {
				return nativeBillIncompleteV3("same-instant debt adoption watermark unavailable")
			}
			if sourceVersion <= prior {
				continue
			}
		}
		total := debt.Amount
		for _, payment := range i.payments {
			if payment.ObligationID == debt.ID && !payment.RecordedAt.After(input.AsOf) && (sourceVersion == 0 || payment.afterSourceVersion < sourceVersion) {
				if final, ok := i.finals[debt.ID]; ok {
					total = final
				}
			}
		}
		var err error
		debt.Amount, err = total.Sub(nativePaidByV3(i.payments, debt.ID, input.AsOf, sourceVersion))
		if err != nil {
			return businessInvalid("forecast retained debt paid arithmetic")
		}
		expected[debt.ID] = debt
	}
	seen := map[string]bool{}
	for _, debt := range input.RetainedObligations {
		if seen[debt.ID] {
			return businessInvalid("forecast duplicate retained debt identity")
		}
		seen[debt.ID] = true
		if original, ok := expected[debt.ID]; ok {
			if debt != original {
				return businessInvalid("forecast cannot replace old debt with new permission or erase remaining")
			}
			delete(expected, debt.ID)
		} else {
			// A read-only forecast can discover an unmaterialized historical month;
			// it requires the full independent USER lifecycle reconstruction below.
			return nativeBillIncompleteV3("unmaterialized historical adoption requires complete timeline replay")
		}
	}
	if len(expected) != 0 {
		return businessInvalid("forecast omitted original retained debt after pause/version change")
	}
	return g.checkedRowsV3()
}

// USER confirmation requires the exact preview SourceHash. The immediately
// preceding persisted publication with that same hash proves which source
// watermark still precedes a same-clock adoption; time equality alone cannot.
func (g *nativeGraphV3) nativeDebtPriorSourceV3(version funds.ID) (uint64, error) {
	var prior uint64
	for _, preview := range g.rows["template_policy_previews"] {
		if preview.text("version_id") != version.String() {
			continue
		}
		for _, publication := range g.rows["template_protection_publications"] {
			var input planning.ForecastInput
			nativeOriginalV3(publication, "input_original", &input)
			if input.Facts.SourceHash == preview.text("source_hash") && !publication.instant("created_at").After(preview.instant("created_at")) {
				if value := uint64(publication.positive("source_version")); value > prior {
					prior = value
				}
			}
		}
	}
	if prior == 0 {
		return 0, nativeBillIncompleteV3("same-instant debt prior exact source publication unavailable")
	}
	return prior, nil
}
