package executionaudit

import (
	"bytes"
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	evidence "zhiyu.local/zhiyu-go/internal/audit"
	"zhiyu.local/zhiyu-go/internal/execution/bankv2"
	funds "zhiyu.local/zhiyu-go/internal/funds/domain"
	planning "zhiyu.local/zhiyu-go/internal/planning/domain"
	policy "zhiyu.local/zhiyu-go/internal/policy/domain"
)

type nativeFundsChangeV3 struct {
	Table         string  `json:"table"`
	RowKey        string  `json:"row_key"`
	BeforeHash    *string `json:"before_hash"`
	AfterOriginal *string `json:"after_original"`
}
type nativeFundsCommitV3 struct {
	Protocol             string                    `json:"protocol"`
	Scope                policy.TemplateOwnerScope `json:"scope"`
	Namespace            string                    `json:"namespace"`
	FundsVersion         uint64                    `json:"funds_version"`
	PreviousFundsVersion *uint64                   `json:"previous_funds_version"`
	PreviousHash         *string                   `json:"previous_hash"`
	SourceVersion        uint64                    `json:"source_version"`
	WriterGeneration     uint64                    `json:"writer_generation"`
	ControlVersion       uint64                    `json:"control_version"`
	TransactionStartedAt *time.Time                `json:"transaction_started_at"`
	PreviousStateHash    string                    `json:"previous_state_hash"`
	StateHash            string                    `json:"state_hash"`
	Changes              []nativeFundsChangeV3     `json:"changes"`
}
type nativeTemplateSourceWitnessV3 struct {
	Protocol               string                           `json:"protocol"`
	ID                     funds.ID                         `json:"id"`
	Scope                  policy.TemplateOwnerScope        `json:"scope"`
	Namespace              string                           `json:"namespace"`
	AsOf                   time.Time                        `json:"as_of"`
	Timezone               string                           `json:"timezone"`
	FundsVersion           uint64                           `json:"funds_version"`
	SnapshotSourceVersion  uint64                           `json:"snapshot_source_version"`
	WriterGeneration       uint64                           `json:"writer_generation"`
	ControlVersion         uint64                           `json:"control_version"`
	FundsCommitHash        string                           `json:"funds_commit_hash"`
	SourceHash             string                           `json:"source_hash"`
	SourceBasisOriginal    []byte                           `json:"source_basis_original"`
	SourceBasisHash        string                           `json:"source_basis_hash"`
	SourceTables           []string                         `json:"source_tables"`
	FundsStateHash         string                           `json:"funds_state_hash"`
	DatedConfirmationInput *nativeDatedConfirmationSourceV1 `json:"dated_confirmation_input,omitempty"`
}
type nativeTemplateSourceBasisV3 struct {
	Scope                         policy.TemplateOwnerScope
	Inventory                     mirrortemplateInventoryV3
	FundsVersion, Writer, Control uint64
	Rows                          map[string][]string
}
type nativeFinancialRowSetV3 map[string]map[string]string

func nativeFactsTableV3(table string) bool {
	for _, candidate := range nativeFactsDeltaTablesV3(26) {
		if candidate == table {
			return true
		}
	}
	return false
}
func nativeFactsRowKeyV3(table, original string) (string, []string, error) {
	catalog, ok := nativeAuditTableV3(table)
	if !ok || !nativeFactsTableV3(table) {
		return "", nil, businessInvalid("funds delta table outside economic allowlist")
	}
	var value map[string]any
	d := json.NewDecoder(strings.NewReader(original))
	d.UseNumber()
	if d.Decode(&value) != nil {
		return "", nil, businessInvalid("funds delta original JSON")
	}
	key, parts := "", []string{}
	for _, field := range catalog.PrimaryKey {
		part, ok := value[field].(string)
		if number, numeric := value[field].(json.Number); numeric {
			part, ok = number.String(), true
		}
		if !ok {
			return "", nil, businessInvalid("funds delta primary key")
		}
		key += strconv.Itoa(len([]byte(part))) + ":" + part
		parts = append(parts, part)
	}
	return key, parts, nil
}
func nativeFactsStateHashV3(state nativeFinancialRowSetV3) string {
	tables := make([]string, 0, len(state))
	for table := range state {
		tables = append(tables, table)
	}
	sort.Strings(tables)
	var frame strings.Builder
	for _, table := range tables {
		keys := make([]string, 0, len(state[table]))
		for key := range state[table] {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		for _, key := range keys {
			frame.WriteString(table + "\t" + key + "\t" + nakedHash([]byte(state[table][key])) + "\n")
		}
	}
	return nakedHash([]byte(frame.String()))
}
func nativeFactsRowsV3(state nativeFinancialRowSetV3) (map[string][]string, error) {
	out := map[string][]string{}
	for _, table := range nativeFactsDeltaTablesV3(26) {
		type indexed struct {
			raw string
			key []string
		}
		values := []indexed{}
		for _, raw := range state[table] {
			_, parts, err := nativeFactsRowKeyV3(table, raw)
			if err != nil {
				return nil, err
			}
			if table == "template_policy_status_events" {
				value, e := nativeFundsObjectV3(raw)
				if e != nil {
					return nil, e
				}
				version, ok := value["version_id"].(string)
				sequence, numeric := value["sequence"].(json.Number)
				if !ok || !numeric {
					return nil, businessInvalid("source lifecycle event order")
				}
				parts = []string{version, sequence.String()}
			}
			values = append(values, indexed{raw, parts})
		}
		sort.Slice(values, func(i, j int) bool {
			catalog, _ := nativeAuditTableV3(table)
			for k := range values[i].key {
				if values[i].key[k] != values[j].key[k] {
					if table == "template_policy_status_events" && k == 1 || k < len(catalog.PrimaryKey) && catalog.PrimaryKey[k] == "version" {
						a, _ := strconv.ParseUint(values[i].key[k], 10, 64)
						b, _ := strconv.ParseUint(values[j].key[k], 10, 64)
						return a < b
					}
					return values[i].key[k] < values[j].key[k]
				}
			}
			return false
		})
		out[table] = []string{}
		for _, value := range values {
			out[table] = append(out[table], value.raw)
		}
	}
	return out, nil
}
func nativeApplyFundsDeltaV3(state nativeFinancialRowSetV3, commit nativeFundsCommitV3) error {
	if nativeFactsStateHashV3(state) != commit.PreviousStateHash {
		return businessInvalid("funds delta predecessor state hash")
	}
	seen := map[string]bool{}
	for _, change := range commit.Changes {
		if !nativeFactsTableV3(change.Table) || seen[change.Table+"\x00"+change.RowKey] {
			return businessInvalid("funds delta unknown/duplicate row")
		}
		if commit.Protocol == "funds-commit-witness-v1" {
			for _, table := range nativeFactsForward26TablesV3 {
				if change.Table == table {
					return businessInvalid("forward terminal/authority row requires funds commit v2")
				}
			}
		}
		seen[change.Table+"\x00"+change.RowKey] = true
		if state[change.Table] == nil {
			state[change.Table] = map[string]string{}
		}
		old, exists := state[change.Table][change.RowKey]
		if exists != (change.BeforeHash != nil) || exists && nakedHash([]byte(old)) != *change.BeforeHash {
			return businessInvalid("funds delta missing/replaced predecessor original")
		}
		if change.AfterOriginal == nil {
			return businessInvalid("funds delta cannot erase a financial identity")
		}
		if _, err := evidence.ParseRawObject([]byte(*change.AfterOriginal)); err != nil {
			return businessInvalid("funds delta raw object")
		}
		key, _, err := nativeFactsRowKeyV3(change.Table, *change.AfterOriginal)
		if err != nil || key != change.RowKey || exists && old == *change.AfterOriginal {
			return businessInvalid("funds delta key/no-op original")
		}
		if exists {
			switch change.Table {
			case "income_origins", "income_claims", "native_income_claims", "native_positions", "native_principal_returns", "receipts", "native_receipts", "native_payment_sources", "native_obligation_payments", "template_obligation_payments", "template_policy_confirmations", "template_policy_status_events", "native_grants", "native_grant_state_events", "native_bank_observations", "bank_observations", "funds_terminal_decisions":
				return businessInvalid("funds delta rewrites immutable financial original")
			case "income_reservations", "native_income_reservations", "native_holds", "native_return_claims":
				var before, after map[string]json.RawMessage
				if json.Unmarshal([]byte(old), &before) != nil || json.Unmarshal([]byte(*change.AfterOriginal), &after) != nil {
					return businessInvalid("funds delta resource state original")
				}
				var oldState, newState string
				if json.Unmarshal(before["state"], &oldState) != nil || json.Unmarshal(after["state"], &newState) != nil || oldState != string(funds.Reserved) || (newState != string(funds.Committed) && newState != string(funds.Released)) {
					return businessInvalid("funds delta resource cannot reverse terminal disposition")
				}
				delete(before, "state")
				delete(after, "state")
				if !exactJSON(before, after) {
					return businessInvalid("funds delta changed immutable resource amount/identity")
				}
			}
		}
		var scope struct {
			EnvironmentID string `json:"environment_id"`
			UserID        string `json:"user_id"`
		}
		if json.Unmarshal([]byte(*change.AfterOriginal), &scope) != nil || scope.EnvironmentID != commit.Scope.EnvironmentID.String() || scope.UserID != commit.Scope.UserID.String() {
			return businessInvalid("funds delta crosses scope")
		}
		state[change.Table][change.RowKey] = *change.AfterOriginal
	}
	if nativeFactsStateHashV3(state) != commit.StateHash {
		return businessInvalid("funds delta exact resulting state hash")
	}
	return nil
}

func nativeFundsObjectV3(raw string) (map[string]any, error) {
	var value map[string]any
	d := json.NewDecoder(strings.NewReader(raw))
	d.UseNumber()
	err := d.Decode(&value)
	return value, err
}

func (g *nativeGraphV3) checkFundsCommitEffectsV3(before nativeFinancialRowSetV3, commit nativeFundsCommitV3) error {
	nativeReceipts, legacyReceipts := map[string]bool{}, map[string]bool{}
	terminal := map[string]bool{}
	terminalRows := map[string]bool{}
	for _, change := range commit.Changes {
		if change.AfterOriginal == nil {
			continue
		}
		v, err := nativeFundsObjectV3(*change.AfterOriginal)
		if err != nil {
			return businessInvalid("funds commit effect original JSON")
		}
		if change.BeforeHash == nil && (change.Table == "native_holds" || change.Table == "native_income_reservations" || change.Table == "native_return_claims" || change.Table == "income_reservations") {
			id, _ := v["operation_id"].(string)
			if id == "" {
				id, _ = v["action_id"].(string)
			}
			table := "native_operations"
			if change.Table == "income_reservations" {
				table = "operations"
			}
			op := g.row(table, id)
			if op == nil || v["state"] != string(funds.Reserved) || uint64(op.positive("reserved_funds_version")) != commit.FundsVersion && !(table == "native_operations" && g.lateBridgeFundsBirthV3(op, before, commit)) {
				return businessInvalid("funds commit reservation must be its exact original T1 funds boundary")
			}
		}
		switch change.Table {
		case "receipts", "native_receipts":
			id, _ := v["id"].(string)
			op, _ := v["operation_id"].(string)
			row := g.row(change.Table, id)
			if change.BeforeHash != nil || row == nil || !exactJSON(row.values, v) || op == "" {
				return businessInvalid("funds commit receipt must be exact immutable bank-verified original")
			}
			if change.Table == "native_receipts" {
				nativeReceipts[op] = true
			} else {
				legacyReceipts[op] = true
			}
			permitTable := "submission_permits"
			opTable := "operations"
			if change.Table == "native_receipts" {
				permitTable = "native_submission_permits"
				opTable = "native_operations"
			}
			operation, permit := g.row(opTable, op), g.row(permitTable, op)
			if operation == nil || permit == nil {
				return businessInvalid("funds commit receipt requires actual earlier T1/T2")
			}
			var proof any
			decoder := json.NewDecoder(bytes.NewReader(nativeRawV3(permit, "original")))
			decoder.UseNumber()
			if decoder.Decode(&proof) != nil {
				return businessInvalid("funds commit original T2 proof")
			}
			var maxFunds uint64
			var scan func(any)
			scan = func(value any) {
				switch typed := value.(type) {
				case map[string]any:
					for key, child := range typed {
						if key == "funds_version" || key == "reserved_funds_version" {
							if n, ok := child.(json.Number); ok {
								v, e := strconv.ParseUint(n.String(), 10, 64)
								if e == nil && v > maxFunds {
									maxFunds = v
								}
							}
						}
						scan(child)
					}
				case []any:
					for _, child := range typed {
						scan(child)
					}
				}
			}
			scan(proof)
			if maxFunds == 0 || commit.FundsVersion <= maxFunds {
				return businessInvalid("funds commit T3 cannot precede its exact original T2 funds watermark")
			}
		case "native_holds", "native_income_reservations", "native_return_claims", "income_reservations":
			state, _ := v["state"].(string)
			if state != string(funds.Committed) {
				continue
			}
			op, _ := v["operation_id"].(string)
			if op == "" {
				op, _ = v["action_id"].(string)
			}
			old := before[change.Table][change.RowKey]
			prior, e := nativeFundsObjectV3(old)
			if e != nil || prior["state"] != string(funds.Reserved) {
				return businessInvalid("funds commit T3 needs the actual previously reserved resource")
			}
			terminal[change.Table+"\x00"+op] = true
			terminalRows[change.Table+"\x00"+change.RowKey] = true
		}
	}
	for key := range terminal {
		parts := strings.SplitN(key, "\x00", 2)
		if parts[0] == "income_reservations" {
			if !legacyReceipts[parts[1]] {
				return businessInvalid("legacy terminal resources and receipt must share one exact booked FV")
			}
		} else if !nativeReceipts[parts[1]] {
			return businessInvalid("native terminal resources and receipt must share one exact booked FV")
		}
	}
	for op := range nativeReceipts {
		if !terminal["native_holds\x00"+op] {
			return businessInvalid("native receipt cannot appear before its same-FV complete terminal resources")
		}
		for table, rows := range before {
			if table != "native_holds" && table != "native_income_reservations" && table != "native_return_claims" {
				continue
			}
			for key, raw := range rows {
				v, e := nativeFundsObjectV3(raw)
				if e != nil {
					return e
				}
				id, _ := v["operation_id"].(string)
				if id == "" {
					id, _ = v["action_id"].(string)
				}
				if id == op && v["state"] == string(funds.Reserved) && !terminalRows[table+"\x00"+key] {
					return businessInvalid("native receipt omitted part of its exact T3 resource transition")
				}
			}
		}
	}
	for op := range legacyReceipts {
		if !terminal["income_reservations\x00"+op] {
			return businessInvalid("legacy receipt cannot precede same-FV source disposition")
		}
	}
	for _, change := range commit.Changes {
		if change.AfterOriginal == nil || change.BeforeHash != nil {
			continue
		}
		if change.Table != "native_payment_sources" && change.Table != "native_obligation_payments" {
			continue
		}
		value, _ := nativeFundsObjectV3(*change.AfterOriginal)
		row := &ledgerRow{values: value}
		op := row.text("operation_id")
		if change.Table == "native_payment_sources" {
			operation := g.row("native_operations", op)
			if operation == nil || uint64(operation.positive("reserved_funds_version")) != commit.FundsVersion {
				return businessInvalid("payment source must be born in its exact original T1 funds prefix")
			}
		} else if !nativeReceipts[op] || row.text("receipt_id") != g.nativeReceipts[op].ID.String() {
			return businessInvalid("paid debt original and its actual external receipt must share one booked FV")
		}
	}
	return nil
}

func (g *nativeGraphV3) lateBridgeFundsBirthV3(op *ledgerRow, before nativeFinancialRowSetV3, commit nativeFundsCommitV3) bool {
	kind := op.text("command_kind")
	if kind != "BRIDGE_ALLOCATE" && kind != "STANDING_BRIDGE_ALLOCATE" {
		return false
	}
	stepTable, batchTable := "native_next_steps", "native_group_batches"
	if kind == "STANDING_BRIDGE_ALLOCATE" {
		stepTable, batchTable = "native_standing_bridge_steps", "native_standing_bridge_groups"
	}
	var step *ledgerRow
	for _, candidate := range g.rows[stepTable] {
		if candidate.text("operation_id") == op.text("id") {
			if step != nil {
				return false
			}
			step = candidate
		}
	}
	if step == nil || step.boolean("initial_source") || step.text("command_kind") != kind || step.text("group_id") != op.text("group_id") {
		return false
	}
	batch := g.row(batchTable, step.text("group_id"))
	previous := step.optional("previous_operation_id")
	if batch == nil || previous == "" || op.optional("previous_operation_id") != previous || batch.positive("reserved_funds_version") != op.positive("reserved_funds_version") || uint64(op.positive("reserved_funds_version")) >= commit.FundsVersion {
		return false
	}
	request, exists := g.nativeRequests[previous]
	if !exists || request.Effect.Kind != bankv2.Transfer {
		return false
	}
	hasReceipt := false
	for _, raw := range before["native_receipts"] {
		v, e := nativeFundsObjectV3(raw)
		if e == nil && v["operation_id"] == previous {
			hasReceipt = true
		}
	}
	for _, change := range commit.Changes {
		if change.Table == "native_receipts" && change.BeforeHash == nil && change.AfterOriginal != nil {
			v, e := nativeFundsObjectV3(*change.AfterOriginal)
			if e == nil && v["operation_id"] == previous {
				hasReceipt = true
			}
		}
	}
	// The predecessor receipt is a real bank-verified original in this or a
	// prior sealed prefix. The existing bridge closure verifies the full USER/
	// standing step request and exact resource vector; time alone never births it.
	return hasReceipt
}

// checkTemplateSourceWitnessesV3 consumes immutable FV deltas, never the
// mutable cache. Equal wall-clock values do not select a prefix: exact FV,
// predecessor hashes and resource/receipt originals select it.
func (g *nativeGraphV3) checkTemplateSourceWitnessesV3() error {
	consumers := len(g.rows["template_policy_previews"]) + len(g.rows["template_protection_publications"])
	if g.snapshot.Revision < 25 && consumers == 0 && len(g.rows["funds_commit_witnesses"]) == 0 && len(g.rows["template_source_witnesses"]) == 0 {
		return nil
	}
	if len(g.rows["funds_commit_witnesses"]) == 0 || consumers > 0 && len(g.rows["template_source_witnesses"]) == 0 {
		return fmt.Errorf("%w: historical template sources lack forward funds/source witnesses", evidence.ErrIncomplete)
	}
	if int64(len(g.rows["funds_commit_witnesses"])) != g.snapshot.Watermarks["funds_version"] {
		return fmt.Errorf("%w: funds witness complete version inventory", evidence.ErrIncomplete)
	}
	witnesses := map[uint64][]nativeTemplateSourceWitnessV3{}
	witnessRows := map[string]*ledgerRow{}
	for _, row := range g.rows["template_source_witnesses"] {
		var w nativeTemplateSourceWitnessV3
		nativeOriginalV3(row, "original", &w)
		if nativeHashFieldV3(row, "original", "original_hash") != nil || row.err != nil || w.Protocol != "template-source-witness-v1" || w.Scope != g.ownerScopeV3() || w.Namespace != g.manifest.Scope.Namespace || w.ID.String() != row.text("id") || w.FundsVersion != uint64(row.positive("funds_version")) || w.SnapshotSourceVersion != uint64(row.positive("source_version")) || w.SourceHash != row.text("source_hash") || !w.AsOf.Equal(row.instant("created_at")) || w.AsOf.After(g.manifest.Source.CapturedAt) || nakedHash(w.SourceBasisOriginal) != w.SourceBasisHash {
			return businessInvalid("template source witness exact original/header")
		}
		witnesses[w.FundsVersion] = append(witnesses[w.FundsVersion], w)
		witnessRows[w.ID.String()] = row
	}
	state := nativeFinancialRowSetV3{}
	var previousHash, previousProtocol string
	var previousSource, previousWriter, previousControl uint64
	consumed := map[string]bool{}
	usedWitnesses := map[string]bool{}
	for fv := uint64(1); fv <= uint64(g.snapshot.Watermarks["funds_version"]); fv++ {
		row := g.row("funds_commit_witnesses", strconv.FormatUint(fv, 10))
		if row == nil {
			return fmt.Errorf("%w: funds witness version %d absent; old prefixes cannot be backfilled", evidence.ErrIncomplete, fv)
		}
		var commit nativeFundsCommitV3
		// This original is emitted by PostgreSQL jsonb::text, whose byte
		// order/spacing differs from Go DTO serialization. Preserve its exact
		// bytes and strict typed fields without inventing a Go re-encoding.
		commitRaw := nativeRawV3(row, "original")
		decoder := json.NewDecoder(bytes.NewReader(commitRaw))
		decoder.DisallowUnknownFields()
		if _, err := evidence.ParseRawObject(commitRaw); err != nil || decoder.Decode(&commit) != nil {
			return businessInvalid("funds commit exact SQL original JSON")
		}
		if nativeHashFieldV3(row, "original", "original_hash") != nil || row.err != nil || !g.fundsProtocolV3(commit.Protocol) || commit.Scope != g.ownerScopeV3() || commit.Namespace != g.manifest.Scope.Namespace || commit.FundsVersion != fv || fv == 1 && (commit.PreviousFundsVersion != nil || commit.PreviousHash != nil) || fv > 1 && (commit.PreviousFundsVersion == nil || *commit.PreviousFundsVersion != fv-1 || commit.PreviousHash == nil || *commit.PreviousHash != previousHash) {
			return businessInvalid("funds commit exact complete causal chain")
		}
		if previousProtocol == "funds-commit-witness-v2" && commit.Protocol != previousProtocol {
			return businessInvalid("funds commit protocol cannot downgrade after terminal authority admission")
		}
		if fv > 1 && uint64(row.positive("previous_funds_version")) != fv-1 || fv == 1 && row.values["previous_funds_version"] != nil || commit.SourceVersion < 1 || commit.SourceVersion > uint64(g.snapshot.Watermarks["source_version"]) || commit.WriterGeneration < 1 || commit.WriterGeneration > uint64(g.snapshot.Watermarks["writer_generation"]) || commit.ControlVersion < 1 || commit.ControlVersion > uint64(g.snapshot.Watermarks["control_version"]) {
			return businessInvalid("funds commit physical version and authority bounds")
		}
		if commit.SourceVersion < previousSource || commit.WriterGeneration < previousWriter || commit.ControlVersion < previousControl {
			return businessInvalid("funds commit source/writer/control sequence cannot move backward")
		}
		if err := g.checkFundsCommitEffectsV3(state, commit); err != nil {
			return err
		}
		if err := g.checkFundsGoalCountersV3(state, commit); err != nil {
			return err
		}
		before := state
		state = nativeCopyFundsStateV3(before)
		if err := nativeApplyFundsDeltaV3(state, commit); err != nil {
			return err
		}
		if err := g.checkFundsTemplateAuthorityV3(state, commit); err != nil {
			return err
		}
		if err := g.checkNativeGrantPrefixV3(state, commit); err != nil {
			return err
		}
		if err := g.checkFundsTerminalDecisionsV3(before, state, commit); err != nil {
			return err
		}
		if err := g.checkFundsPrefixEconomyV3(state, commit); err != nil {
			return err
		}
		for _, w := range witnesses[fv] {
			if w.FundsCommitHash != row.text("original_hash") || w.FundsStateHash != commit.StateHash || commit.TransactionStartedAt == nil || w.AsOf.Before(*commit.TransactionStartedAt) || w.SnapshotSourceVersion < commit.SourceVersion || w.WriterGeneration < commit.WriterGeneration || w.ControlVersion < commit.ControlVersion {
				return businessInvalid("source witness pins exact funds commit and transaction lower bound")
			}
			raw, err := nativeFactsRowsV3(state)
			if err != nil {
				return err
			}
			capture, err := nativeFactsLedgerFromRowsV3(w.Scope, w.Namespace, w.AsOf, raw)
			if err != nil {
				return err
			}
			ledger, err := g.frozenLedgerV3(capture, w.AsOf)
			if err != nil {
				return fmt.Errorf("funds prefix %d source %d: %w", fv, w.SnapshotSourceVersion, err)
			}
			if err = g.checkTemplateSourceBasisV3(w, raw); err != nil {
				return err
			}
			for _, preview := range g.rows["template_policy_previews"] {
				var p nativeTemplatePreviewV3
				if json.Unmarshal(nativeRawV3(preview, "review_bundle"), &p) != nil {
					return businessInvalid("source consumer policy preview decode")
				}
				if p.SourceWitnessID == nil || *p.SourceWitnessID != w.ID {
					continue
				}
				if w.DatedConfirmationInput != nil {
					return businessInvalid("Dated confirmation source cannot substitute a preview source")
				}
				if p.SourceWitnessHash != witnessRows[w.ID.String()].text("original_hash") || p.SnapshotFundsVersion != w.FundsVersion || p.SnapshotSourceVersion != w.SnapshotSourceVersion || p.SourceHash != w.SourceHash || !p.CreatedAt.Equal(w.AsOf) || p.Timezone != w.Timezone || p.ForecastInput == nil {
					return businessInvalid("policy preview exact retained source reference")
				}
				if err = g.checkTemplateFactsLedgerV3(p.Facts, ledger, w.AsOf, w.Timezone, w.SnapshotSourceVersion); err != nil {
					return err
				}
				input := *p.ForecastInput
				if input.Scope != w.Scope || input.Facts.SourceHash != w.SourceHash || !input.AsOf.Equal(w.AsOf) || input.Timezone != w.Timezone || input.Facts.CurrentSafeVerified || !input.Facts.CurrentSafe.IsZero() || len(input.FutureIncome) != 0 || len(input.PrincipalReturns) != 0 {
					return businessInvalid("policy counterfactual forecast input is the actual before money prefix")
				}
				if err = g.checkTemplateFactsLedgerV3(input.Facts, ledger, w.AsOf, w.Timezone, w.SnapshotSourceVersion); err != nil {
					return err
				}
				proposed := policy.TemplateVersion{PolicyID: p.PolicyID, VersionID: p.VersionID, Version: p.BaseVersion + 1, Scope: p.Scope, Compiled: p.Compiled, State: "ACTIVE", ConfirmedAt: p.CreatedAt, Current: true, ConfirmationVerified: true, ConfirmedConfigurationHash: p.Compiled.Hash}
				if err = g.checkSourceForecastEnvelopeV3(input, ledger, w, raw, &proposed, p.GoalID, false); err != nil {
					return err
				}
				expected, e := planning.Forecast365(input)
				if e != nil || !exactJSON(expected, p.Forecast) || !p.Facts.CurrentSafeVerified || p.Facts.CurrentSafe != expected.CurrentSafe {
					return businessInvalid("policy forecast/current-safe exact proposed-policy deterministic replay")
				}
				input.Facts.CurrentSafe, input.Facts.CurrentSafeVerified = p.Facts.CurrentSafe, p.Facts.CurrentSafeVerified
				refs, e := g.replayDatedPreviewReferencesV3(p, ledger, w, raw)
				if e != nil {
					return e
				}
				if len(refs) != 0 {
					input.Facts.ProtectedReferences = refs
				}
				if !exactJSON(input.Facts, p.Facts) {
					return businessInvalid("policy preview facts differ from retained forecast facts")
				}
				consumed["preview:"+preview.text("id")] = true
				usedWitnesses[w.ID.String()] = true
			}
			for _, publication := range g.rows["template_protection_publications"] {
				if publication.optional("source_witness_id") != w.ID.String() {
					continue
				}
				if w.DatedConfirmationInput != nil {
					return businessInvalid("Dated confirmation source cannot substitute a publication source")
				}
				var input planning.ForecastInput
				nativeOriginalV3(publication, "input_original", &input)
				if publication.text("source_witness_hash") != witnessRows[w.ID.String()].text("original_hash") || uint64(publication.positive("source_version")) != w.SnapshotSourceVersion+1 || !input.AsOf.Equal(w.AsOf) || input.Timezone != w.Timezone || input.Facts.SourceHash != w.SourceHash {
					return businessInvalid("publication pins pre-increment source and funds prefix")
				}
				if err = g.checkTemplateFactsLedgerV3(input.Facts, ledger, w.AsOf, w.Timezone, w.SnapshotSourceVersion); err != nil {
					return err
				}
				if err = g.checkSourceForecastEnvelopeV3(input, ledger, w, raw, nil, nil, true); err != nil {
					return err
				}
				consumed["publication:"+strconv.FormatInt(publication.positive("source_version"), 10)] = true
				usedWitnesses[w.ID.String()] = true
			}
			if w.DatedConfirmationInput != nil {
				id, e := g.checkDatedConfirmationSourceV3(w, witnessRows[w.ID.String()].text("original_hash"), ledger, raw)
				if e != nil {
					return e
				}
				consumed["dated-confirmation:"+id] = true
				usedWitnesses[w.ID.String()] = true
			}
		}
		previousHash, previousProtocol = row.text("original_hash"), commit.Protocol
		previousSource, previousWriter, previousControl = commit.SourceVersion, commit.WriterGeneration, commit.ControlVersion
	}
	if err := g.checkFundsFinalProjectionV3(state); err != nil {
		return err
	}
	for id := range witnessRows {
		if !usedWitnesses[id] {
			return businessInvalid("unreferenced or future template source witness")
		}
	}
	for _, row := range g.rows["template_policy_previews"] {
		if !consumed["preview:"+row.text("id")] {
			return fmt.Errorf("%w: policy preview has no exact forward source witness", evidence.ErrIncomplete)
		}
	}
	for _, row := range g.rows["template_protection_publications"] {
		if !consumed["publication:"+strconv.FormatInt(row.positive("source_version"), 10)] {
			return fmt.Errorf("%w: protection publication has no exact forward source witness", evidence.ErrIncomplete)
		}
	}
	for _, row := range g.rows["template_policy_confirmations"] {
		var c nativeTemplateConfirmationV3
		nativeOriginalV3(row, "original", &c)
		p := g.row("template_policy_previews", c.PreviewID.String())
		if p == nil {
			return businessInvalid("Dated confirmation preview missing")
		}
		var preview nativeTemplatePreviewV3
		nativeOriginalV3(p, "review_bundle", &preview)
		ids, e := nativeDatedRequiredV3(preview.Compiled)
		if e != nil {
			return e
		}
		if len(ids) != 0 && (c.DatedReferences == nil || !consumed["dated-confirmation:"+row.text("id")]) {
			return fmt.Errorf("%w: Dated protected confirmation has no exact fresh source witness", evidence.ErrIncomplete)
		}
		if len(ids) == 0 && c.DatedReferences != nil {
			return businessInvalid("unrequested Dated confirmation witness")
		}
	}
	return g.checkedRowsV3()
}

func (g *nativeGraphV3) checkTemplateSourceBasisV3(w nativeTemplateSourceWitnessV3, financial map[string][]string) error {
	var basis nativeTemplateSourceBasisV3
	decoder := json.NewDecoder(bytes.NewReader(w.SourceBasisOriginal))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&basis) != nil || basis.Scope != w.Scope || basis.FundsVersion != w.FundsVersion || basis.Writer != w.WriterGeneration || basis.Control != w.ControlVersion || basis.Inventory.Scope != w.Scope || !sort.StringsAreSorted(w.SourceTables) {
		return businessInvalid("source witness independently reconstructed basis header")
	}
	seen := map[string]bool{}
	for _, table := range w.SourceTables {
		if seen[table] {
			return businessInvalid("source witness duplicate source table")
		}
		seen[table] = true
		if nativeFactsTableV3(table) {
			if _, exists := basis.Rows[table]; exists {
				return businessInvalid("source witness duplicates financial authority")
			}
			basis.Rows[table] = financial[table]
		}
	}
	for _, table := range nativeFactsFinancialTablesV3 {
		if !seen[table] {
			return businessInvalid("source witness omits economic source table")
		}
	}
	for table := range basis.Rows {
		if !seen[table] {
			return businessInvalid("source witness undeclared source table")
		}
	}
	if nakedHash(mustJSONV3(basis)) != w.SourceHash {
		return businessInvalid("source hash differs from independently reconstructed exact historical rows")
	}
	// Accounts/goals retain source-only metadata in the basis. Their money and
	// scope must still equal the immutable FV projection; no current row is used.
	for _, table := range []string{"accounts", "goals"} {
		if len(basis.Rows[table]) != len(financial[table]) {
			return businessInvalid("source metadata changes economic inventory")
		}
		project := func(raw string) string {
			var v map[string]json.RawMessage
			if json.Unmarshal([]byte(raw), &v) != nil {
				return ""
			}
			if table == "accounts" {
				delete(v, "name")
			} else {
				for key := range v {
					if key != "environment_id" && key != "user_id" && key != "id" && key != "account_id" && key != "assigned_cents" && key != "month_period" && key != "month_contributed_cents" {
						delete(v, key)
					}
				}
			}
			encoded, _ := json.Marshal(v)
			return string(encoded)
		}
		set := map[string]bool{}
		for _, raw := range financial[table] {
			set[project(raw)] = true
		}
		for _, raw := range basis.Rows[table] {
			if !set[project(raw)] {
				return businessInvalid("source metadata rewrites economic prefix")
			}
		}
	}
	return nil
}
