package executionaudit

import (
	"bytes"
	"encoding/json"
	"fmt"
	"math/big"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	evidence "zhiyu.local/zhiyu-go/internal/audit"
	"zhiyu.local/zhiyu-go/internal/execution/bankcredit"
	"zhiyu.local/zhiyu-go/internal/execution/bankv2"
	execution "zhiyu.local/zhiyu-go/internal/execution/domain"
	funds "zhiyu.local/zhiyu-go/internal/funds/domain"
)

type nativeGoalDetailV3 struct {
	ID        funds.ID    `json:"id"`
	Name      string      `json:"name"`
	AccountID funds.ID    `json:"account_id"`
	Target    funds.Money `json:"target_cents"`
	Assigned  funds.Money `json:"assigned_cents"`
	Version   uint64      `json:"version"`
}
type nativeGoalConfigurationV3 struct {
	Protocol      string              `json:"protocol"`
	EnvironmentID funds.ID            `json:"environment_id"`
	UserID        funds.ID            `json:"user_id"`
	SessionID     funds.ID            `json:"session_id"`
	PrincipalKind string              `json:"principal_kind"`
	Action        string              `json:"action"`
	Before        *nativeGoalDetailV3 `json:"before,omitempty"`
	After         nativeGoalDetailV3  `json:"after"`
	ConfirmedAt   time.Time           `json:"confirmed_at"`
}
type nativeGoalRequestV3 struct {
	GoalID        funds.ID `json:"goal_id"`
	Configuration struct {
		Name            string      `json:"name"`
		AccountID       funds.ID    `json:"account_id"`
		Target          funds.Money `json:"target_cents"`
		ExpectedVersion uint64      `json:"expected_version"`
	} `json:"configuration"`
}
type nativeGoalTargetEventV3 struct {
	at            time.Time
	before, after funds.Money
	create        bool
	version       uint64
}

func nativeGoalNameV3(name string) bool {
	if name != strings.TrimSpace(name) || !utf8.ValidString(name) || utf8.RuneCountInString(name) < 1 || utf8.RuneCountInString(name) > 80 {
		return false
	}
	for _, r := range name {
		if unicode.IsControl(r) {
			return false
		}
	}
	return true
}

// Configuration versions may have gaps because economic effects and explicit
// template target mutations also increment goals.version. Bootstrap goals do
// not acquire invented USER history. Target replay consumes real USER changes
// from both writers, including changes at the same injected business instant.
func (g *nativeGraphV3) checkGoalConfigurationV3() error {
	configs := map[string][]nativeGoalConfigurationV3{}
	targets := map[string][]nativeGoalTargetEventV3{}
	keys := map[string]bool{}
	for _, row := range g.rows["goal_configuration_events"] {
		var c nativeGoalConfigurationV3
		var request nativeGoalRequestV3
		nativeOriginalV3(row, "original", &c)
		nativeOriginalV3(row, "request", &request)
		id := row.id("goal_id").String()
		goal := g.row("goals", id)
		key := row.text("idempotency_key")
		if goal == nil || keys[key] || len(key) < 16 || len(key) > 128 || nativeHashFieldV3(row, "original", "original_hash") != nil || nativeHashFieldV3(row, "request", "request_hash") != nil || c.Protocol != "human-goal-configuration-v1" || c.EnvironmentID.String() != g.manifest.Scope.EnvironmentID || c.UserID.String() != g.manifest.Scope.UserID || c.SessionID.String() != row.text("session_id") || c.PrincipalKind != "USER" || c.Action != row.text("action") || c.After.ID.String() != id || c.After.Version != uint64(row.positive("goal_version")) || c.After.Version > uint64(goal.positive("version")) || !c.ConfirmedAt.Equal(row.instant("confirmed_at")) || c.ConfirmedAt.After(g.manifest.Source.CapturedAt) || !nativeGoalNameV3(c.After.Name) || c.After.Target.IsZero() || c.After.Target.Cents() < c.After.Assigned.Cents() || c.After.AccountID.String() != goal.text("account_id") || g.row("accounts", c.After.AccountID.String()) == nil || request.Configuration.Name != c.After.Name || request.Configuration.AccountID != c.After.AccountID || request.Configuration.Target != c.After.Target {
			return businessInvalid("native actual USER goal configuration command/original")
		}
		keys[key] = true
		if err := g.humanAtV3(c.SessionID, c.ConfirmedAt); err != nil {
			return err
		}
		event := nativeGoalTargetEventV3{at: c.ConfirmedAt, after: c.After.Target, version: c.After.Version}
		switch c.Action {
		case "CREATE":
			if c.Before != nil || request.GoalID != (funds.ID{}) || request.Configuration.ExpectedVersion != 0 || c.After.Version != 1 || !c.After.Assigned.IsZero() {
				return businessInvalid("native goal CREATE original state")
			}
			event.create = true
		case "UPDATE":
			before := c.Before
			if before == nil || request.GoalID != c.After.ID || before.ID != c.After.ID || before.AccountID != c.After.AccountID || before.Version == 0 || before.Version == ^uint64(0) || before.Version+1 != c.After.Version || request.Configuration.ExpectedVersion != before.Version || before.Assigned != c.After.Assigned || !nativeGoalNameV3(before.Name) || before.Target.IsZero() {
				return businessInvalid("native goal UPDATE exact before/CAS/no financial effect")
			}
			event.before = before.Target
		default:
			return fmt.Errorf("%w: native goal configuration action", evidence.ErrUnsupportedVersion)
		}
		configs[id] = append(configs[id], c)
		targets[id] = append(targets[id], event)
	}
	for _, row := range g.rows["template_policy_confirmations"] {
		var c nativeTemplateConfirmationV3
		nativeOriginalV3(row, "original", &c)
		if c.TargetMutation == nil {
			continue
		}
		m := c.TargetMutation
		_, ok := g.templates[c.VersionID.String()]
		policyRow := g.row("template_policies", c.PolicyID.String())
		if !ok || policyRow == nil || policyRow.optional("goal_id") != m.GoalID.String() || c.Scope != g.ownerScopeV3() || c.PrincipalKind != "USER" || c.Protocol != "template-user-confirmation-v1" || m.Before.IsZero() || m.After.IsZero() || m.Before == m.After || g.row("goals", m.GoalID.String()) == nil || nativeHashFieldV3(row, "original", "original_hash") != nil || !c.ConfirmedAt.Equal(row.instant("confirmed_at")) || c.ConfirmedAt.After(g.manifest.Source.CapturedAt) {
			return businessInvalid("native goal target change requires retained USER template confirmation")
		}
		if err := g.humanAtV3(c.SessionID, c.ConfirmedAt); err != nil {
			return err
		}
		targets[m.GoalID.String()] = append(targets[m.GoalID.String()], nativeGoalTargetEventV3{at: c.ConfirmedAt, before: m.Before, after: m.After})
	}
	for id, history := range configs {
		sort.Slice(history, func(i, j int) bool { return history[i].After.Version < history[j].After.Version })
		for i, c := range history {
			if i > 0 {
				p := history[i-1]
				if c.Action != "UPDATE" || c.Before.Version < p.After.Version || c.Before.Name != p.After.Name || c.ConfirmedAt.Before(p.ConfirmedAt) {
					return businessInvalid("native goal configuration omitted or rewrote earlier USER history")
				}
			}
		}
		last := history[len(history)-1]
		goal := g.row("goals", id)
		if goal.text("name") != last.After.Name || goal.text("account_id") != last.After.AccountID.String() {
			return businessInvalid("native current goal configuration projection")
		}
	}
	for id, history := range targets {
		if err := nativeReplayGoalTargetsV3(history, g.row("goals", id).money("target_cents")); err != nil {
			return err
		}
	}
	if err := g.checkGoalVersionSourcesV3(configs, targets); err != nil {
		return err
	}
	return g.checkGoalConfiguredOutboxV3(configs)
}

// Every production writer of goals.version is an explicit USER change, an
// initial legacy policy installation, or a committed economic receipt. A gap
// may be legitimate, but cannot stand in for a removed configuration event.
func (g *nativeGraphV3) checkGoalVersionSourcesV3(configs map[string][]nativeGoalConfigurationV3, targets map[string][]nativeGoalTargetEventV3) error {
	versions := map[string]int64{}
	for _, row := range g.rows["goals"] {
		versions[row.id("id").String()] = 1
	}
	add := func(id string) error {
		if _, ok := versions[id]; !ok {
			return businessInvalid("native goal version source references absent goal")
		}
		versions[id]++
		return nil
	}
	for id, history := range configs {
		for _, c := range history {
			if c.Action == "UPDATE" {
				if err := add(id); err != nil {
					return err
				}
			}
		}
	}
	for id, history := range targets {
		for _, e := range history {
			if e.version == 0 {
				if err := add(id); err != nil {
					return err
				}
			}
		}
	}
	if g.legacy != nil {
		for _, p := range g.legacy.policies {
			if p.Version == 1 {
				if err := add(p.Scope.GoalID.String()); err != nil {
					return err
				}
			}
		}
		for id, request := range g.legacy.requests {
			if g.row("operations", id).text("status") == "SETTLED" {
				if err := add(request.GoalID); err != nil {
					return err
				}
			}
		}
	}
	for id, request := range g.nativeRequests {
		if _, settled := g.nativeReceipts[id]; !settled {
			continue
		}
		op := g.row("native_operations", id)
		switch op.text("command_kind") {
		case "JOINT_ALLOCATE", "STANDING_ALLOCATE", "BRIDGE_ALLOCATE", "STANDING_BRIDGE_ALLOCATE":
			if err := add(request.Effect.DestinationGoalID); err != nil {
				return err
			}
		case "PURCHASE_ASSET", "REDEEM_ASSET", "MATURE_ASSET":
			if request.Effect.SourceGoalID != "" {
				if err := add(request.Effect.SourceGoalID); err != nil {
					return err
				}
			}
		case "TRANSFER_GOAL":
			for _, goal := range []string{request.Effect.SourceGoalID, request.Effect.DestinationGoalID} {
				if err := add(goal); err != nil {
					return err
				}
			}
		}
	}
	for id, want := range versions {
		if g.row("goals", id).positive("version") != want {
			return businessInvalid("native goal version lacks complete USER/economic source history")
		}
	}
	return nil
}

func nativeReplayGoalTargetsV3(history []nativeGoalTargetEventV3, want funds.Money) error {
	sort.SliceStable(history, func(i, j int) bool { return history[i].at.Before(history[j].at) })
	var target funds.Money
	initialized := false
	for start := 0; start < len(history); {
		end := start + 1
		for end < len(history) && history[end].at.Equal(history[start].at) {
			end++
		}
		pending := append([]nativeGoalTargetEventV3(nil), history[start:end]...)
		if !initialized {
			// Prefer an actual CREATE. Otherwise an unchanged bootstrap state is
			// anchored by the first retained transition's exact before value.
			found := false
			for i, e := range pending {
				if e.create {
					target = e.after
					pending = append(pending[:i], pending[i+1:]...)
					initialized = true
					found = true
					break
				}
			}
			if !found {
				starts := map[int64]bool{}
				for _, e := range pending {
					incoming := false
					for _, other := range pending {
						if other.before != other.after && other.after == e.before {
							incoming = true
						}
					}
					if !incoming {
						starts[e.before.Cents()] = true
					}
				}
				if len(starts) != 1 {
					return fmt.Errorf("%w: same-instant goal target order lacks a unique original basis", evidence.ErrIncomplete)
				}
				for cents := range starts {
					target, _ = funds.NewMoney(cents)
				}
				initialized = true
			}
		}
		for len(pending) > 0 {
			selected := -1
			for i, e := range pending {
				if e.create {
					return businessInvalid("native goal duplicate or late CREATE")
				}
				if e.before != target {
					continue
				}
				if selected == -1 || e.before == e.after && pending[selected].before != pending[selected].after || e.before == e.after && pending[selected].before == pending[selected].after && e.version < pending[selected].version {
					selected = i
				}
			}
			if selected < 0 {
				return businessInvalid("native goal target transition missing or rewritten")
			}
			chosen := pending[selected]
			if chosen.before != chosen.after {
				for i, e := range pending {
					if i != selected && e.before == target && e.before != e.after {
						return fmt.Errorf("%w: ambiguous same-instant goal target changes", evidence.ErrIncomplete)
					}
				}
			}
			target = chosen.after
			pending = append(pending[:selected], pending[selected+1:]...)
		}
		start = end
	}
	if !initialized || target != want {
		return businessInvalid("native final goal target differs from retained USER changes")
	}
	return nil
}

func (g *nativeGraphV3) checkGoalConfiguredOutboxV3(configs map[string][]nativeGoalConfigurationV3) error {
	expected := map[string]nativeGoalConfigurationV3{}
	for id, history := range configs {
		for _, c := range history {
			expected[keyParts(id, strconv.FormatUint(c.After.Version, 10))] = c
		}
	}
	seen := map[string]bool{}
	for _, row := range g.rows["outbox"] {
		if row.text("kind") != "GOAL_CONFIGURED" {
			continue
		}
		id := row.text("aggregate_id")
		version := row.positive("aggregate_version")
		key := keyParts(id, strconv.FormatInt(version, 10))
		c, ok := expected[key]
		original := g.row("goal_configuration_events", id, strconv.FormatInt(version, 10))
		if !ok || seen[key] || original == nil || !bytes.Equal(nativeRawV3(row, "payload"), nativeRawV3(original, "original")) || !row.instant("created_at").Equal(c.ConfirmedAt) {
			return businessInvalid("native goal configured outbox exact original")
		}
		row.id("id")
		row.positive("event_sequence")
		seen[key] = true
	}
	if len(seen) != len(expected) {
		return fmt.Errorf("%w: goal USER configuration outbox missing", evidence.ErrIncomplete)
	}
	return g.checkedRowsV3()
}

func nativeSettlementBlobV3(kind string) (prefix, evidenceKind string) {
	switch kind {
	case "JOINT_ALLOCATE":
		return "native-settlement:", "NATIVE_EXECUTION_SETTLEMENT"
	case "BRIDGE_TRANSFER", "BRIDGE_ALLOCATE":
		return "native-bridge-settlement:", "NATIVE_BRIDGE_SETTLEMENT"
	case "STANDING_BRIDGE_TRANSFER", "STANDING_BRIDGE_ALLOCATE":
		return "native-standing-bridge-settlement:", "NATIVE_STANDING_BRIDGE_SETTLEMENT"
	case "STANDING_ALLOCATE":
		return "native-standing-settlement:", "NATIVE_STANDING_SETTLEMENT"
	case "PURCHASE_ASSET", "REDEEM_ASSET", "MATURE_ASSET":
		return "native-asset:", "NATIVE_ASSET_SETTLEMENT"
	case "TRANSFER_GOAL":
		return "native-goal-transfer:", "NATIVE_GOAL_TRANSFER_SETTLEMENT"
	}
	return "", ""
}

// This scoped check closes native T3 events and the evidence families actually
// written by those T3 implementations. Other event/source families remain
// separate gates; this method never removes the final remaining guard.
func (g *nativeGraphV3) checkNativeSettlementEventsV3() error {
	seen, used := map[string]bool{}, map[string]bool{}
	for _, row := range g.rows["outbox"] {
		if row.text("kind") != "NATIVE_OPERATION_SETTLED" {
			continue
		}
		id := row.id("aggregate_id").String()
		op := g.row("native_operations", id)
		receipt, ok := g.nativeReceipts[id]
		if !ok || op == nil || op.text("status") != "SETTLED" || seen[id] || row.positive("aggregate_version") != op.positive("version") || !row.instant("created_at").Equal(receipt.RecordedAt) {
			return businessInvalid("native settlement outbox operation/version/time")
		}
		original := g.row("native_receipts", receipt.ID.String())
		if original == nil || !bytes.Equal(nativeRawV3(row, "payload"), nativeRawV3(original, "original")) {
			return businessInvalid("native settlement outbox receipt bytes")
		}
		row.id("id")
		row.positive("event_sequence")
		seen[id] = true
	}
	for id, receipt := range g.nativeReceipts {
		if !seen[id] {
			return fmt.Errorf("%w: native SETTLED receipt outbox missing", evidence.ErrIncomplete)
		}
		op := g.row("native_operations", id)
		prefix, kind := nativeSettlementBlobV3(op.text("command_kind"))
		if kind == "" {
			if op.text("command_kind") != "PAY_RECURRING" {
				return fmt.Errorf("%w: native settlement evidence family", evidence.ErrUnsupportedVersion)
			}
			continue
		}
		blob := g.row("evidence_blobs", prefix+id)
		original := g.row("native_receipts", receipt.ID.String())
		if blob == nil {
			return fmt.Errorf("%w: native settlement evidence missing", evidence.ErrIncomplete)
		}
		if original == nil || blob.text("kind") != kind || nativeHashFieldV3(blob, "canonical", "digest") != nil || !bytes.Equal(nativeRawV3(blob, "canonical"), nativeRawV3(original, "original")) || !blob.instant("created_at").Equal(receipt.RecordedAt) {
			return businessInvalid("native settlement evidence exact receipt/kind/time")
		}
		used[prefix+id] = true
	}
	for _, row := range g.rows["evidence_blobs"] {
		kind := row.text("kind")
		if strings.HasPrefix(kind, "NATIVE_") && strings.HasSuffix(kind, "_SETTLEMENT") {
			switch kind {
			case "NATIVE_EXECUTION_SETTLEMENT", "NATIVE_BRIDGE_SETTLEMENT", "NATIVE_STANDING_BRIDGE_SETTLEMENT", "NATIVE_STANDING_SETTLEMENT", "NATIVE_ASSET_SETTLEMENT", "NATIVE_GOAL_TRANSFER_SETTLEMENT":
				if !used[row.text("id")] {
					return businessInvalid("native orphan or mismatched settlement evidence")
				}
			default:
				return fmt.Errorf("%w: native settlement evidence kind", evidence.ErrUnsupportedVersion)
			}
		}
	}
	return g.checkedRowsV3()
}

// Mixed v3 ledgers cannot run legacy's allocation-only balance projection.
// Its independently registered settlement protocol still verifies the exact
// retained request/result/receipt and the public event, without changing v1/v2.
func (g *nativeGraphV3) checkLegacySettlementEventsV3() error {
	seen, used := map[string]bool{}, map[string]bool{}
	for _, row := range g.rows["outbox"] {
		if row.text("kind") != "OPERATION_SETTLED" {
			continue
		}
		id := row.id("aggregate_id").String()
		op := g.row("operations", id)
		if op == nil || op.text("status") != "SETTLED" || seen[id] || row.positive("aggregate_version") != op.positive("version") {
			return businessInvalid("legacy settlement outbox operation/version")
		}
		receiptRow := g.row("receipts", op.text("receipt_id"))
		var receipt businessReceipt
		if receiptRow == nil {
			return fmt.Errorf("%w: legacy settlement event receipt missing", evidence.ErrIncomplete)
		}
		nativeOriginalV3(receiptRow, "original", &receipt)
		if !bytes.Equal(nativeRawV3(row, "payload"), nativeRawV3(receiptRow, "original")) || !row.instant("created_at").Equal(receipt.RecordedAt) {
			return businessInvalid("legacy settlement outbox exact receipt/time")
		}
		row.id("id")
		row.positive("event_sequence")
		seen[id] = true
	}
	bank := map[string]execution.BankResult{}
	if g.bank != nil {
		for _, result := range g.bank.Legacy {
			bank[result.Key] = result
		}
	}
	for _, op := range g.rows["operations"] {
		if op.text("status") != "SETTLED" {
			continue
		}
		id := op.id("id").String()
		if !seen[id] {
			return fmt.Errorf("%w: legacy settled outbox missing", evidence.ErrIncomplete)
		}
		if g.legacy == nil {
			return fmt.Errorf("%w: legacy verified request graph missing", evidence.ErrIncomplete)
		}
		request, ok := g.legacy.requests[id]
		result, found := bank[request.Key]
		if !ok || !found {
			return fmt.Errorf("%w: independent legacy settlement source missing", evidence.ErrIncomplete)
		}
		if result.Status != execution.BankSettled || execution.VerifyBankResult(request, result) != nil {
			return businessInvalid("legacy settlement independent result")
		}
		row := g.row("evidence_blobs", "settlement:"+id)
		if row == nil {
			return fmt.Errorf("%w: legacy settlement evidence missing", evidence.ErrIncomplete)
		}
		if row.text("kind") != SettlementKind {
			return fmt.Errorf("%w: legacy settlement evidence kind", evidence.ErrUnsupportedVersion)
		}
		original := evidence.Original{Canonical: nativeRawV3(row, "canonical"), Digest: row.text("digest")}
		registry := evidence.NewRegistry()
		if Register(registry) != nil {
			return businessInvalid("legacy settlement registry")
		}
		verified := evidence.VerifyBundle([]string{"settlement:" + id}, map[string]evidence.Original{"settlement:" + id: original}, registry)
		if verified.Status != evidence.Valid {
			if verified.Status == evidence.UnsupportedVersion {
				return fmt.Errorf("%w: retained legacy settlement protocol", evidence.ErrUnsupportedVersion)
			}
			if verified.Status == evidence.Incomplete {
				return fmt.Errorf("%w: retained legacy settlement reference", evidence.ErrIncomplete)
			}
			return businessInvalid("legacy original settlement registered semantics")
		}
		var doc evidence.Document
		var evidenceRequest execution.BankRequest
		var evidenceResult execution.BankResult
		if json.Unmarshal(original.Canonical, &doc) != nil || doc.Data["operation_id"] != id || doc.Data["receipt_id"] != op.text("receipt_id") || doc.Data["environment"] != request.Namespace || doc.Data["user_id"] != request.UserID {
			return businessInvalid("legacy settlement original physical links")
		}
		requestHex, requestOK := doc.Data["bank_request_hex"].(string)
		resultHex, resultOK := doc.Data["bank_result_hex"].(string)
		if !requestOK || !resultOK || decodeHex(requestHex, &evidenceRequest) != nil || decodeHex(resultHex, &evidenceResult) != nil || !exactJSON(evidenceRequest, request) || !exactJSON(evidenceResult, result) {
			return businessInvalid("legacy evidence differs from actual independent original")
		}
		receiptRow := g.row("receipts", op.text("receipt_id"))
		var receipt businessReceipt
		if receiptRow == nil {
			return fmt.Errorf("%w: retained legacy receipt", evidence.ErrIncomplete)
		}
		nativeOriginalV3(receiptRow, "original", &receipt)
		if !row.instant("created_at").Equal(receipt.RecordedAt) {
			return businessInvalid("legacy settlement evidence time")
		}
		used[row.text("id")] = true
	}
	for _, row := range g.rows["evidence_blobs"] {
		if row.text("kind") == SettlementKind && !used[row.text("id")] {
			return businessInvalid("orphan legacy settlement evidence")
		}
	}
	return g.checkedRowsV3()
}

type nativeIncomeCaptureOriginalV3 struct {
	Protocol   string `json:"protocol"`
	LocalBasis struct {
		FundsVersion     uint64 `json:"funds_version"`
		SourceVersion    uint64 `json:"source_version"`
		WriterGeneration uint64 `json:"writer_generation"`
		ControlVersion   uint64 `json:"control_version"`
	} `json:"local_basis_before_bank_read"`
	State       bankcredit.CurrentState `json:"state"`
	Legacy      []execution.BankResult  `json:"legacy_operations"`
	Native      []bankv2.Result         `json:"native_operations"`
	NativeStock bankv2.CurrentState     `json:"native_stock"`
}

// A watermark fixes the operation inventory, not historical current balances.
// Reverse only independently verified later economic postings and credits.
// Application projections and this retained capture never supply bank facts.
func (g *nativeGraphV3) checkIncomeSnapshotEvidenceV3() error {
	for _, row := range g.rows["evidence_blobs"] {
		if row.text("kind") != "NATIVE_INCOME_SNAPSHOT_V1" {
			continue
		}
		if g.bank == nil {
			return fmt.Errorf("%w: historical income independent source", evidence.ErrIncomplete)
		}
		var capture nativeIncomeCaptureOriginalV3
		raw := nativeOriginalV3(row, "canonical", &capture)
		at := row.instant("created_at")
		state := capture.State
		basis := capture.LocalBasis
		if len(raw) > 4<<20 || nativeHashFieldV3(row, "canonical", "digest") != nil || row.text("id") != "native-income-capture:"+row.text("digest") || capture.Protocol != "native-income-import-v1/bank-capture" || state.Validate() != nil || state.Namespace != g.manifest.Scope.Namespace || state.UserID != g.manifest.Scope.UserID || state.CapturedAt.After(at) || state.CapturedAt.Before(at.Add(-30*time.Second)) || at.After(g.manifest.Source.CapturedAt) || basis.FundsVersion < 1 || basis.SourceVersion < 1 || basis.WriterGeneration < 1 || basis.ControlVersion < 1 || basis.FundsVersion >= uint64(g.snapshot.Watermarks["funds_version"]) || basis.SourceVersion > uint64(g.snapshot.Watermarks["source_version"]) || basis.WriterGeneration > uint64(g.snapshot.Watermarks["writer_generation"]) || basis.ControlVersion > uint64(g.snapshot.Watermarks["control_version"]) {
			return businessInvalid("native historical income capture bytes/scope/time/basis")
		}
		if state.CreditWatermark > g.bank.Credit.CreditWatermark || state.V1OperationWatermark > g.bank.Credit.V1OperationWatermark || state.V2OperationWatermark > g.bank.Credit.V2OperationWatermark {
			return businessInvalid("native historical income future bank watermark")
		}
		credits := []bankcredit.Entry{}
		legacy := []execution.BankResult{}
		native := []bankv2.Result{}
		for _, r := range g.bank.Credit.Credits {
			if r.Record.Sequence <= state.CreditWatermark {
				credits = append(credits, r)
			}
		}
		for _, r := range g.bank.Legacy {
			if r.Sequence <= state.V1OperationWatermark {
				if r.Status != execution.BankSettled && r.Status != execution.BankRejected {
					return businessInvalid("historical income captured unreconciled legacy bank effect")
				}
				legacy = append(legacy, r)
			}
		}
		for _, r := range g.bank.Native {
			if r.Sequence <= state.V2OperationWatermark {
				if r.Status != bankv2.Settled && r.Status != bankv2.Rejected {
					return businessInvalid("historical income captured unreconciled native bank effect")
				}
				native = append(native, r)
			}
		}
		if !exactJSON(credits, state.Credits) || !exactJSON(legacy, capture.Legacy) || !exactJSON(native, capture.Native) {
			return businessInvalid("native historical income exact independently retained inventory prefix")
		}
		if len(legacy) == 0 && state.V1OperationWatermark != 0 || len(legacy) > 0 && legacy[len(legacy)-1].Sequence != state.V1OperationWatermark || len(native) == 0 && state.V2OperationWatermark != 0 || len(native) > 0 && native[len(native)-1].Sequence != state.V2OperationWatermark {
			return businessInvalid("native historical complete operation prefix watermarks")
		}
		if err := g.nativeHistoricalIncomeBalancesV3(capture, at); err != nil {
			return err
		}
	}
	return g.checkedRowsV3()
}

func (g *nativeGraphV3) nativeHistoricalIncomeBalancesV3(capture nativeIncomeCaptureOriginalV3, recordedAt time.Time) error {
	state, stock := capture.State, capture.NativeStock
	if stock.Protocol != bankv2.Protocol || stock.Namespace != state.Namespace || stock.UserID != state.UserID || stock.OperationWatermark != state.V2OperationWatermark || stock.CatalogWatermark < 0 || stock.CatalogWatermark > g.bank.Stock.CatalogWatermark || stock.CapturedAt.IsZero() || stock.CapturedAt.After(recordedAt) || stock.CapturedAt.Before(state.CapturedAt.Add(-30*time.Second)) || len(stock.Accounts) != len(state.Accounts) || len(stock.Goals) > 8 || len(stock.Positions) > 1000 {
		return businessInvalid("native historical stock scope/watermark/time/capacity")
	}
	cash, available, assigned, goalCash, principal, loss := map[string]*big.Int{}, map[string]*big.Int{}, map[string]*big.Int{}, map[string]*big.Int{}, map[string]*big.Int{}, map[string]*big.Int{}
	for _, a := range g.bank.Credit.Accounts {
		addBusinessSum(cash, a.ID, a.Balance.Cents())
	}
	for _, o := range g.bank.Credit.Origins {
		for _, l := range o.Locations {
			key := keyParts(o.ID, l.AccountID)
			addBusinessSum(available, key, l.Available.Cents())
			addBusinessSum(assigned, key, l.Assigned.Cents())
		}
	}
	for _, goal := range g.bank.Stock.Goals {
		addBusinessSum(goalCash, goal.ID, goal.Cash.Cents())
		addBusinessSum(principal, goal.ID, goal.Principal.Cents())
		addBusinessSum(loss, goal.ID, goal.Loss.Cents())
	}
	reverse := func(dimension, ledger, direction string, amount funds.Money) error {
		delta := amount.Cents()
		if direction == "CREDIT" {
			delta = -delta
		} else if direction != "DEBIT" {
			return businessInvalid("native historical posting direction")
		}
		parts := strings.Split(ledger, ":")
		switch dimension {
		case "ECONOMIC":
			if len(parts) == 2 && parts[0] == "CASH" {
				addBusinessSum(cash, parts[1], delta)
			}
		case "INCOME_LOCATION":
			if len(parts) == 3 {
				switch parts[0] {
				case "AVAILABLE":
					addBusinessSum(available, keyParts(parts[1], parts[2]), delta)
				case "ASSIGNED":
					addBusinessSum(assigned, keyParts(parts[1], parts[2]), delta)
				}
			}
		case "GOAL_OWNERSHIP":
			if len(parts) == 2 {
				switch parts[0] {
				case "GOAL", "GOAL_CASH":
					addBusinessSum(goalCash, parts[1], delta)
				case "GOAL_PRINCIPAL":
					addBusinessSum(principal, parts[1], delta)
				case "GOAL_LOSS":
					addBusinessSum(loss, parts[1], delta)
				}
			}
		}
		return nil
	}
	for _, r := range g.bank.Legacy {
		if r.Sequence > state.V1OperationWatermark && r.Status == execution.BankSettled {
			for _, p := range r.Postings {
				if e := reverse(p.Dimension, p.LedgerID, p.Direction, p.Amount); e != nil {
					return e
				}
			}
		}
	}
	for _, r := range g.bank.Native {
		if r.Sequence > state.V2OperationWatermark && r.Status == bankv2.Settled {
			for _, p := range r.Postings {
				if e := reverse(p.Dimension, p.LedgerID, p.Direction, p.Amount); e != nil {
					return e
				}
			}
		}
	}
	oldAccounts := map[string]bankcredit.Account{}
	for _, a := range state.Accounts {
		oldAccounts[a.ID] = a
	}
	future := map[string]bool{}
	creditOrigins := map[string]bool{}
	for _, entry := range g.bank.Credit.Credits {
		origin := entry.Record.Event.OriginID
		creditOrigins[origin] = true
		if entry.Record.Sequence > state.CreditWatermark {
			future[origin] = true
			addBusinessSum(cash, entry.Record.Event.AccountID, -entry.Record.Event.Amount.Cents())
		}
	}
	for _, o := range g.bank.Credit.Origins {
		if creditOrigins[o.ID] {
			continue
		}
		row := g.row("income_origins", o.ID)
		if row == nil {
			return fmt.Errorf("%w: historical seeded income original missing", evidence.ErrIncomplete)
		}
		if row.instant("recorded_at").After(recordedAt) {
			if _, old := oldAccounts[o.OriginalAccountID]; old {
				return fmt.Errorf("%w: later unsequenced seed on existing historical account", evidence.ErrIncomplete)
			}
			future[o.ID] = true
			addBusinessSum(cash, o.OriginalAccountID, -o.Amount.Cents())
		}
	}
	for _, a := range state.Accounts {
		if !a.Reserved.IsZero() || !businessSum(cash, a.ID, a.Balance.Cents()) {
			return businessInvalid("native historical actual account cash/reservation")
		}
		delete(cash, a.ID)
	}
	for _, sum := range cash {
		if sum.Sign() != 0 {
			return businessInvalid("native historical omitted funded account")
		}
	}
	origins := map[string]bankcredit.Origin{}
	for _, o := range g.bank.Credit.Origins {
		if !future[o.ID] {
			origins[o.ID] = o
		}
	}
	for _, o := range state.Origins {
		current, ok := origins[o.ID]
		if !ok || o.OriginalAccountID != current.OriginalAccountID || o.Amount != current.Amount || !o.OccurredAt.Equal(current.OccurredAt) || o.EvidenceHash != current.EvidenceHash {
			return businessInvalid("native historical immutable income source inventory")
		}
		for _, l := range o.Locations {
			key := keyParts(o.ID, l.AccountID)
			if !l.Reserved.IsZero() || !businessSum(available, key, l.Available.Cents()) || !businessSum(assigned, key, l.Assigned.Cents()) {
				return businessInvalid("native historical origin qualification replay")
			}
			delete(available, key)
			delete(assigned, key)
		}
		for key, sum := range available {
			if nativeIncomeLocationOriginV3(key, o.ID) && sum.Sign() != 0 {
				return businessInvalid("native historical omitted source location")
			}
		}
		delete(origins, o.ID)
	}
	if len(origins) != 0 {
		return businessInvalid("native historical omitted immutable income source")
	}
	// Remaining nonzero locations may belong only to credits not yet present.
	for key, sum := range available {
		if sum.Sign() != 0 {
			allowed := false
			for id := range future {
				if nativeIncomeLocationOriginV3(key, id) {
					allowed = true
				}
			}
			if !allowed {
				return businessInvalid("native historical source location closure")
			}
		}
	}
	for key, sum := range assigned {
		if sum.Sign() != 0 {
			allowed := false
			for id := range future {
				if nativeIncomeLocationOriginV3(key, id) {
					allowed = true
				}
			}
			if !allowed {
				return businessInvalid("native historical assigned source location closure")
			}
		}
	}
	seenAccounts := map[string]bool{}
	for _, a := range stock.Accounts {
		old, ok := oldAccounts[a.ID]
		if !ok || seenAccounts[a.ID] || a.Balance != old.Balance || a.Reserved != old.Reserved {
			return businessInvalid("native historical stock and qualification cash disagree")
		}
		seenAccounts[a.ID] = true
	}
	currentGoals := map[string]bankv2.Goal{}
	for _, goal := range g.bank.Stock.Goals {
		currentGoals[goal.ID] = goal
	}
	seenGoals := map[string]bool{}
	for _, goal := range stock.Goals {
		current, ok := currentGoals[goal.ID]
		if !ok || seenGoals[goal.ID] || goal.AccountID != current.AccountID || !businessSum(goalCash, goal.ID, goal.Cash.Cents()) || !businessSum(principal, goal.ID, goal.Principal.Cents()) || !businessSum(loss, goal.ID, goal.Loss.Cents()) {
			return businessInvalid("native historical goal cash/principal/loss replay")
		}
		seenGoals[goal.ID] = true
		delete(goalCash, goal.ID)
		delete(principal, goal.ID)
		delete(loss, goal.ID)
	}
	for _, values := range []map[string]*big.Int{goalCash, principal, loss} {
		for _, sum := range values {
			if sum.Sign() != 0 {
				return businessInvalid("native historical omitted nonzero goal")
			}
		}
	}
	positions := map[string]bankv2.Position{}
	for _, position := range g.bank.Stock.Positions {
		row := g.row("native_positions", position.Opening.PositionID)
		if row == nil {
			return fmt.Errorf("%w: historical position original", evidence.ErrIncomplete)
		}
		if operation := row.optional("opening_operation_id"); operation != "" {
			receipt, ok := g.nativeReceipts[operation]
			if !ok {
				return businessInvalid("native historical position missing opening receipt")
			}
			if receipt.BankResult.Sequence > state.V2OperationWatermark {
				continue
			}
		}
		if position.ClosingKey != "" {
			found := false
			for _, r := range g.bank.Native {
				if r.Key == position.ClosingKey {
					found = true
					if r.Sequence > state.V2OperationWatermark {
						position.Closed = false
						position.ClosingKey = ""
					}
					break
				}
			}
			if !found {
				return businessInvalid("native historical closing position source")
			}
		}
		positions[position.Opening.PositionID] = position
	}
	for _, position := range stock.Positions {
		expected, ok := positions[position.Opening.PositionID]
		if !ok || !exactJSON(expected, position) {
			return businessInvalid("native historical position opening/closing replay")
		}
		delete(positions, position.Opening.PositionID)
	}
	if len(positions) != 0 {
		return fmt.Errorf("%w: historical position membership lacks exact prior import order", evidence.ErrIncomplete)
	}
	// Product catalog metadata is not used by income admission. Financial
	// product terms remain independently checked by preview/request/T2 closures.
	products := map[string]bool{}
	for _, product := range stock.Products {
		if product.Validate() != nil || products[product.Terms.ProductID] {
			return businessInvalid("native historical product metadata shape")
		}
		products[product.Terms.ProductID] = true
	}
	return nil
}

func nativeIncomeLocationOriginV3(key, origin string) bool {
	return strings.HasPrefix(key, strings.TrimSuffix(keyParts(origin), "]")+",")
}

type nativeImportedIncomeEventV3 struct {
	Protocol          string   `json:"protocol,omitempty"`
	OriginID          funds.ID `json:"origin_id"`
	EvidenceID        funds.ID `json:"evidence_id,omitempty"`
	RecordHash        string   `json:"record_hash,omitempty"`
	ExternalAuthority string   `json:"external_authority,omitempty"`
	ExternalEventID   string   `json:"external_event_id,omitempty"`
	CreditSequence    int64    `json:"credit_sequence,omitempty"`
	SourceVersion     uint64   `json:"source_version"`
	BankCaptureHash   string   `json:"bank_capture_hash,omitempty"`
}

type nativeSeedIncomeEventV3 struct {
	OriginID      funds.ID `json:"origin_id"`
	SourceVersion uint64   `json:"source_version"`
}

func nativeIncomeEventOriginalV3(row *ledgerRow) nativeImportedIncomeEventV3 {
	raw := nativeRawV3(row, "payload")
	object, err := evidence.ParseObject(raw)
	if err != nil {
		row.fail("payload")
		return nativeImportedIncomeEventV3{}
	}
	if _, hasProtocol := object["protocol"]; !hasProtocol {
		// The retained seed writer has exactly two fields. A union struct
		// would re-emit zero funds.ID arrays despite omitempty, changing the
		// real bytes. Preserve each actual writer's strict original schema.
		var seed nativeSeedIncomeEventV3
		nativeOriginalV3(row, "payload", &seed)
		return nativeImportedIncomeEventV3{OriginID: seed.OriginID, SourceVersion: seed.SourceVersion}
	}
	var native nativeImportedIncomeEventV3
	nativeOriginalV3(row, "payload", &native)
	return native
}

// Unlike a funds authorization, recovery merely reopens scheduling of the
// retained operation IDs. The actual writer deliberately used these Go JSON
// field names; do not synthesize a new financial command or a new bank key.
type nativeOriginalRecoveryEventV3 struct {
	GroupID, SessionID   funds.ID
	OriginalOperationIDs []string
	FinancialAuthority   bool
}

// Earlier family checks establish financial semantics. This final index binds
// the remaining public events to those originals and rejects unconsumed or
// unknown evidence. A successful local index is not by itself full v3 proof.
func (g *nativeGraphV3) checkEventEvidenceCoverageV3() error {
	used := map[string]bool{}
	consume := func(id string) error {
		if id == "" || used[id] || g.row("evidence_blobs", id) == nil {
			return businessInvalid("native evidence original identity/unique financial consumer")
		}
		used[id] = true
		return nil
	}
	for _, origin := range g.rows["income_origins"] {
		if err := consume(origin.text("evidence_id")); err != nil {
			return err
		}
	}
	for id := range g.nativeReceipts {
		op := g.row("native_operations", id)
		if op == nil {
			return businessInvalid("native event receipt without operation")
		}
		prefix, kind := nativeSettlementBlobV3(op.text("command_kind"))
		if kind != "" {
			if err := consume(prefix + id); err != nil {
				return err
			}
		}
	}
	for _, op := range g.rows["operations"] {
		if op.text("status") == "SETTLED" {
			if err := consume("settlement:" + op.text("id")); err != nil {
				return err
			}
		}
	}
	for _, row := range g.rows["evidence_blobs"] {
		switch row.text("kind") {
		case "FORECAST_HISTORY_STATEMENT_V1", "FORECAST_HISTORY_IMPORT_COMMAND_V1":
			// checkHistorySourcesV3 already binds both directions, signatures,
			// real USER sessions and every original-key import result.
			if err := consume(row.text("id")); err != nil {
				return err
			}
		}
	}
	sequences, incomeEvents, billEvents := map[int64]bool{}, map[string]bool{}, map[string]bool{}
	snapshots, recovered := map[string]bool{}, map[string]bool{}
	credits := map[string]bankcredit.Entry{}
	if g.bank != nil {
		for _, entry := range g.bank.Credit.Credits {
			credits[entry.Record.Event.OriginID] = entry
		}
	}
	for _, row := range g.rows["outbox"] {
		id := row.id("id").String()
		sequence, at := row.positive("event_sequence"), row.instant("created_at")
		if sequences[sequence] || at.After(g.manifest.Source.CapturedAt) || len(nativeRawV3(row, "payload")) > 4<<20 {
			return businessInvalid("native outbox original sequence/time/capacity")
		}
		sequences[sequence] = true
		switch row.text("kind") {
		case "GOAL_CONFIGURED", "NATIVE_OPERATION_SETTLED", "OPERATION_SETTLED":
			// Exact bytes, versions, time and reverse completeness are already
			// established by the three dedicated settlement/config gates.
		case "INCOME_IMPORTED":
			event := nativeIncomeEventOriginalV3(row)
			originID := event.OriginID.String()
			origin := g.row("income_origins", originID)
			if origin == nil || incomeEvents[originID] || id != origin.text("evidence_id") || row.text("aggregate_id") != originID || row.positive("aggregate_version") != 1 || !at.Equal(origin.instant("recorded_at")) || event.SourceVersion < 1 || event.SourceVersion > uint64(g.snapshot.Watermarks["source_version"]) || g.row("protection_snapshots", strconv.FormatUint(event.SourceVersion, 10)) == nil {
				return businessInvalid("native imported income exact origin/event/protection source")
			}
			blob := g.row("evidence_blobs", origin.text("evidence_id"))
			if blob == nil || !blob.instant("created_at").Equal(at) {
				return businessInvalid("native imported income evidence creation instant")
			}
			switch event.Protocol {
			case "":
				if blob.text("kind") != "EXPLICIT_SIMULATED_BANK_INCOME" || event.EvidenceID != (funds.ID{}) || event.RecordHash != "" || event.ExternalAuthority != "" || event.ExternalEventID != "" || event.CreditSequence != 0 || event.BankCaptureHash != "" {
					return businessInvalid("native retained explicit seed event cannot become external income")
				}
			case "native-income-import-v1":
				entry, ok := credits[originID]
				e := entry.Record.Event
				snapshotID := "native-income-capture:" + event.BankCaptureHash
				snapshot := g.row("evidence_blobs", snapshotID)
				if !ok || blob.text("kind") != "BANK_EXTERNAL_CREDIT_V1" || event.EvidenceID.String() != id || e.EvidenceID != id || event.RecordHash != entry.RecordHash || event.RecordHash != origin.text("evidence_hash") || event.ExternalAuthority != e.AuthorityID || event.ExternalEventID != e.EventID || event.CreditSequence != entry.Record.Sequence || snapshot == nil || snapshot.text("kind") != "NATIVE_INCOME_SNAPSHOT_V1" || snapshot.text("digest") != event.BankCaptureHash || !snapshot.instant("created_at").Equal(at) {
					return businessInvalid("native income event differs from actual independent credit/capture")
				}
				var capture nativeIncomeCaptureOriginalV3
				nativeOriginalV3(snapshot, "canonical", &capture)
				found := false
				for _, recorded := range capture.State.Credits {
					found = found || exactJSON(recorded, entry)
				}
				if !found || event.SourceVersion <= capture.LocalBasis.SourceVersion {
					return businessInvalid("native income event admits a credit absent from exact bank read/basis")
				}
				snapshots[snapshotID] = true
			default:
				return fmt.Errorf("%w: native imported income event protocol", evidence.ErrUnsupportedVersion)
			}
			incomeEvents[originID] = true
		case "NATIVE_BILLS_IMPORTED":
			captureID := row.id("aggregate_id").String()
			original := g.row("native_bill_import_results", captureID)
			if original == nil || billEvents[captureID] || row.positive("aggregate_version") != 1 || !bytes.Equal(nativeRawV3(row, "payload"), nativeRawV3(original, "original")) || !at.Equal(original.instant("recorded_at")) {
				return businessInvalid("native bill imported event exact actual result/version/time")
			}
			billEvents[captureID] = true
		case "NATIVE_ORIGINAL_RECOVERY_REQUESTED":
			var event nativeOriginalRecoveryEventV3
			nativeOriginalV3(row, "payload", &event)
			if event.FinancialAuthority || event.GroupID.String() != row.text("aggregate_id") || row.positive("aggregate_version") != 1 || len(event.OriginalOperationIDs) < 1 || len(event.OriginalOperationIDs) > 1000 {
				return businessInvalid("native recovery event cannot invent financial authority")
			}
			if err := g.humanAtV3(event.SessionID, at); err != nil {
				return err
			}
			unique := map[string]bool{}
			for _, operation := range event.OriginalOperationIDs {
				op := g.row("native_operations", operation)
				request, ok := g.nativeRequests[operation]
				if op == nil || !ok || unique[operation] || op.text("group_id") != event.GroupID.String() || request.Key != op.text("bank_key") || op.instant("created_at").After(at) {
					return businessInvalid("native recovery exact retained operation/group/original key")
				}
				unique[operation], recovered[operation] = true, true
			}
		default:
			return fmt.Errorf("%w: native outbox kind %s", evidence.ErrUnsupportedVersion, row.text("kind"))
		}
	}
	for _, origin := range g.rows["income_origins"] {
		blob := g.row("evidence_blobs", origin.text("evidence_id"))
		if blob != nil && blob.text("kind") != "CONTROLLED_BANK_BRIDGE_SOURCE" && !incomeEvents[origin.text("id")] {
			return fmt.Errorf("%w: actual imported income event missing", evidence.ErrIncomplete)
		}
	}
	for _, original := range g.rows["native_bill_import_results"] {
		if !billEvents[original.text("capture_id")] {
			return fmt.Errorf("%w: actual imported bill event missing", evidence.ErrIncomplete)
		}
	}
	for _, op := range g.rows["native_operations"] {
		if op.text("processing_health") == "RECOVERY_REQUESTED" && !recovered[op.text("id")] {
			return fmt.Errorf("%w: retained original recovery event missing", evidence.ErrIncomplete)
		}
	}
	for id := range snapshots {
		if err := consume(id); err != nil {
			return err
		}
	}
	for _, row := range g.rows["evidence_blobs"] {
		// Frozen legacy settlement uses the domain-separated evidence v1
		// digest, already checked by its registered VerifyBundle validator.
		// Other writers persist plain SHA256 over their exact raw original.
		if (row.text("kind") != SettlementKind && nativeHashFieldV3(row, "canonical", "digest") != nil) || row.instant("created_at").After(g.manifest.Source.CapturedAt) {
			return businessInvalid("native evidence original digest/time")
		}
		switch row.text("kind") {
		case SettlementKind, "EXPLICIT_SIMULATED_BANK_INCOME", "CONTROLLED_BANK_BRIDGE_SOURCE", "BANK_EXTERNAL_CREDIT_V1", "FORECAST_HISTORY_STATEMENT_V1", "FORECAST_HISTORY_IMPORT_COMMAND_V1", "NATIVE_INCOME_SNAPSHOT_V1", "NATIVE_EXECUTION_SETTLEMENT", "NATIVE_BRIDGE_SETTLEMENT", "NATIVE_STANDING_BRIDGE_SETTLEMENT", "NATIVE_STANDING_SETTLEMENT", "NATIVE_ASSET_SETTLEMENT", "NATIVE_GOAL_TRANSFER_SETTLEMENT":
			if !used[row.text("id")] {
				return businessInvalid("native orphan or differently keyed financial evidence")
			}
		default:
			return fmt.Errorf("%w: native evidence kind %s", evidence.ErrUnsupportedVersion, row.text("kind"))
		}
	}
	return g.checkedRowsV3()
}
