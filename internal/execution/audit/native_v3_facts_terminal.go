package executionaudit

import (
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"

	evidence "zhiyu.local/zhiyu-go/internal/audit"
	"zhiyu.local/zhiyu-go/internal/execution/bankv2"
	execution "zhiyu.local/zhiyu-go/internal/execution/domain"
	"zhiyu.local/zhiyu-go/internal/execution/fundswitness"
	funds "zhiyu.local/zhiyu-go/internal/funds/domain"
	planning "zhiyu.local/zhiyu-go/internal/planning/domain"
)

func (g *nativeGraphV3) fundsProtocolV3(protocol string) bool {
	return protocol == "funds-commit-witness-v1" || g.snapshot.Revision >= 26 && protocol == "funds-commit-witness-v2"
}

func nativeFundsRowByV3(state nativeFinancialRowSetV3, table, field, value string) *ledgerRow {
	for _, raw := range state[table] {
		v, err := nativeFundsObjectV3(raw)
		if err == nil && v[field] == value {
			return &ledgerRow{values: v}
		}
	}
	return nil
}

func checkFundsAuthorityAdmissionV3(commit nativeFundsCommitV3, table, kind string) error {
	if commit.Protocol != "funds-commit-witness-v2" {
		return nil
	}
	for _, change := range commit.Changes {
		if change.Table != table || change.BeforeHash != nil || change.AfterOriginal == nil {
			continue
		}
		value, err := nativeFundsObjectV3(*change.AfterOriginal)
		if err != nil {
			return err
		}
		row := &ledgerRow{values: value}
		var event struct {
			Admission *fundswitness.Boundary `json:"admission,omitempty"`
		}
		if json.Unmarshal(nativeRawV3(row, "original"), &event) != nil {
			return businessInvalid(kind + " admission original")
		}
		if event.Admission == nil {
			return fmt.Errorf("%w: %s original lacks exact funds admission boundary", evidence.ErrIncomplete, kind)
		}
		before := event.Admission
		if commit.PreviousHash == nil || before.FundsVersion+1 != commit.FundsVersion || before.CommitHash != *commit.PreviousHash || before.StateHash != commit.PreviousStateHash || before.SourceVersion != commit.SourceVersion || before.WriterGeneration != commit.WriterGeneration || before.ControlVersion != commit.ControlVersion {
			return businessInvalid(kind + " event cannot move from its original funds admission")
		}
	}
	return nil
}

func (g *nativeGraphV3) checkNativeGrantPrefixV3(state nativeFinancialRowSetV3, commit nativeFundsCommitV3) error {
	if commit.Protocol != "funds-commit-witness-v2" {
		return nil
	}
	if err := checkFundsAuthorityAdmissionV3(commit, "native_grant_state_events", "native USER lifecycle"); err != nil {
		return err
	}
	grants := map[string]*ledgerRow{}
	for _, raw := range state["native_grants"] {
		v, _ := nativeFundsObjectV3(raw)
		r := &ledgerRow{values: v}
		id, version := r.text("id"), strconv.FormatInt(r.positive("version"), 10)
		current := g.row("native_grants", id, version)
		if current == nil || !exactJSON(current.values, r.values) {
			return businessInvalid("funds prefix rewrote original native USER grant")
		}
		grants[keyParts(id, version)] = r
	}
	events := map[string][]*ledgerRow{}
	for _, raw := range state["native_grant_state_events"] {
		v, _ := nativeFundsObjectV3(raw)
		r := &ledgerRow{values: v}
		current := g.row("native_grant_state_events", r.text("id"))
		key := keyParts(r.text("grant_id"), strconv.FormatInt(r.positive("grant_version"), 10))
		if current == nil || !exactJSON(current.values, r.values) || grants[key] == nil {
			return businessInvalid("funds prefix orphan/rewritten native USER lifecycle")
		}
		events[key] = append(events[key], r)
	}
	projections := map[string]*ledgerRow{}
	for _, raw := range state["native_grant_states"] {
		v, _ := nativeFundsObjectV3(raw)
		r := &ledgerRow{values: v}
		key := keyParts(r.text("grant_id"), strconv.FormatInt(r.positive("grant_version"), 10))
		if grants[key] == nil || projections[key] != nil {
			return businessInvalid("funds prefix orphan native grant state")
		}
		projections[key] = r
	}
	for key := range grants {
		sequence := events[key]
		sort.Slice(sequence, func(i, j int) bool { return sequence[i].positive("sequence") < sequence[j].positive("sequence") })
		state := ""
		for i, event := range sequence {
			if event.positive("sequence") != int64(i+1) || event.optional("old_state") != state {
				return businessInvalid("funds prefix native grant lifecycle gap/order")
			}
			state = event.text("new_state")
		}
		p := projections[key]
		if len(sequence) == 0 || p == nil || p.positive("sequence") != int64(len(sequence)) || p.text("state") != state || p.text("event_id") != sequence[len(sequence)-1].text("id") {
			return businessInvalid("funds prefix native grant state differs from actual lifecycle prefix")
		}
	}
	return nil
}

func (g *nativeGraphV3) checkFundsTerminalDecisionsV3(before, after nativeFinancialRowSetV3, commit nativeFundsCommitV3) error {
	if commit.Protocol != "funds-commit-witness-v2" {
		return checkFundsReleasedDecisionsV3(commit)
	}
	released := map[string]bool{}
	decisions := map[string]fundswitness.TerminalDecision{}
	for _, change := range commit.Changes {
		if change.AfterOriginal == nil {
			continue
		}
		v, err := nativeFundsObjectV3(*change.AfterOriginal)
		if err != nil {
			return err
		}
		if change.Table == "funds_terminal_decisions" {
			row := &ledgerRow{values: v}
			var d fundswitness.TerminalDecision
			if change.BeforeHash != nil || nativeCompactOriginalV3(nativeRawV3(row, "original"), &d) != nil || nativeHashFieldV3(row, "original", "original_hash") != nil || d.Protocol != fundswitness.TerminalProtocol || d.ID.String() != row.text("id") || d.Scope != g.ownerScopeV3() || d.Namespace != g.manifest.Scope.Namespace || d.OperationID.String() != row.text("operation_id") || d.LedgerKind != row.text("ledger_kind") || d.Before.FundsVersion != uint64(row.positive("previous_funds_version")) || d.TerminalFundsVersion != uint64(row.positive("terminal_funds_version")) || !d.DecisionAt.Equal(row.instant("recorded_at")) {
				return businessInvalid("terminal decision exact immutable original/header")
			}
			current := g.row("funds_terminal_decisions", d.ID.String())
			key := keyParts(d.LedgerKind, d.OperationID.String())
			if current == nil || !exactJSON(current.values, row.values) || decisions[key].Protocol != "" {
				return businessInvalid("terminal decision duplicate/rewritten original")
			}
			decisions[key] = d
		}
		switch change.Table {
		case "income_reservations", "native_income_reservations", "native_holds", "native_return_claims":
			if v["state"] == string(funds.Released) {
				id, _ := v["operation_id"].(string)
				if id == "" {
					id, _ = v["action_id"].(string)
				}
				kind := "NATIVE"
				if change.Table == "income_reservations" {
					kind = "LEGACY"
				}
				released[keyParts(kind, id)] = true
			}
		}
	}
	for key := range decisions {
		if !released[key] {
			return businessInvalid("orphan terminal decision without exact released resources")
		}
	}
	for key := range released {
		d, found := decisions[key]
		if !found {
			return fmt.Errorf("%w: released-resource exact decision/FV authority absent at FV%d", evidence.ErrIncomplete, commit.FundsVersion)
		}
		if err := g.checkTerminalDecisionV3(before, after, commit, d); err != nil {
			return err
		}
		delete(decisions, key)
	}
	if len(decisions) != 0 {
		return businessInvalid("orphan terminal decision without exact released resources")
	}
	return nil
}

func (g *nativeGraphV3) checkTerminalDecisionV3(before, after nativeFinancialRowSetV3, c nativeFundsCommitV3, d fundswitness.TerminalDecision) error {
	table := "native_operations"
	if d.LedgerKind == "LEGACY" {
		table = "operations"
	} else if d.LedgerKind != "NATIVE" {
		return businessInvalid("terminal decision ledger kind")
	}
	op := g.row(table, d.OperationID.String())
	if op == nil || c.PreviousHash == nil || d.Before.FundsVersion+1 != c.FundsVersion || d.TerminalFundsVersion != c.FundsVersion || d.Before.CommitHash != *c.PreviousHash || d.Before.StateHash != c.PreviousStateHash || d.Before.StateHash != nativeFactsStateHashV3(before) || d.Before.SourceVersion != c.SourceVersion || d.Before.WriterGeneration != c.WriterGeneration || d.Before.ControlVersion != c.ControlVersion || d.ReservedFundsVersion != uint64(op.positive("reserved_funds_version")) || d.ReservedFundsVersion > d.Before.FundsVersion || d.BankRequestHash != op.text("bank_request_hash") || d.TerminalState != op.text("status") || d.TerminalState != "CANCELLED" && d.TerminalState != "REJECTED" || c.TransactionStartedAt == nil || d.DecisionAt.Before(*c.TransactionStartedAt) || d.DecisionAt.After(g.manifest.Source.CapturedAt) || !d.DecisionAt.Equal(op.instant("updated_at")) {
		return businessInvalid("terminal decision exact causal funds/request/state/time boundary")
	}
	signature := op.optional("permit_signature")
	if signature == "" && d.PermitSignatureHash != "" || signature != "" && d.PermitSignatureHash != nakedHash([]byte(signature)) {
		return businessInvalid("terminal decision exact signed/unsigned original")
	}
	resources, err := fundswitness.OperationResources(fundswitness.RowSet(before), d.LedgerKind, d.OperationID.String())
	if err != nil || fundswitness.RowCount(resources) < 1 || fundswitness.RowCount(resources) != d.ResourceRowCount || fundswitness.StateHash(resources) != d.ResourceVectorHash {
		return businessInvalid("terminal decision full actual BEFORE reserved resource vector")
	}
	for table, values := range resources {
		if strings.HasSuffix(table, "claims") && table != "native_return_claims" {
			continue
		}
		for key := range values {
			v, err := nativeFundsObjectV3(after[table][key])
			if err != nil || v["state"] != string(funds.Released) {
				return businessInvalid("terminal decision cannot omit part of the released resource vector")
			}
		}
	}
	if d.Cause.Kind == fundswitness.UnsupportedCause && d.Cause.Code == "AUTHORIZATION_EXPIRED" {
		return g.checkTerminalUnsignedOnceAssetExpiryV3(d, op)
	}
	switch d.Cause.Kind {
	case fundswitness.BankRejectedFinal:
		if d.TerminalState != "REJECTED" || signature == "" || d.Cause.VersionID != nil || d.Cause.GrantID != nil || d.Cause.GrantVersion != 0 || d.Cause.EventID != nil || d.Cause.EventSequence != 0 || d.Cause.EventOriginalHash != "" {
			return businessInvalid("bank rejection requires exact signed no-effect decision")
		}
		return g.checkTerminalBankRejectionV3(after, d)
	case fundswitness.TemplatePolicyInactive, fundswitness.NativeGrantNotActive:
		if d.TerminalState != "CANCELLED" || signature != "" || d.Cause.Code != op.text("processing_health") || d.Cause.BankObservationID != nil || d.Cause.BankObservationHash != "" {
			return businessInvalid("permission cancellation cannot release an already signed original")
		}
		return g.checkTerminalPermissionCauseV3(before, d, op)
	default:
		return fmt.Errorf("%w: terminal decision reason %q not independently supported", evidence.ErrIncomplete, d.Cause.Code)
	}
}

// checkTerminalUnsignedOnceAssetExpiryV3 supports only the original unsigned
// ONCE purchase deadline. The complete graph has already replayed the exact
// candidate and USER confirmation; neither today's rule validity nor another
// grant/preview can substitute for that retained deadline. The caller retains
// all exact terminal FV, request, time and released-resource boundary checks.
func (g *nativeGraphV3) checkTerminalUnsignedOnceAssetExpiryV3(d fundswitness.TerminalDecision, op *ledgerRow) error {
	if d.LedgerKind != "NATIVE" || op.text("mode") != "ONCE" || op.text("command_kind") != "PURCHASE_ASSET" {
		return fmt.Errorf("%w: exact unsigned ONCE purchase expiry proof unavailable", evidence.ErrIncomplete)
	}
	if !exactJSON(d.Cause, fundswitness.Cause{Kind: fundswitness.UnsupportedCause, Code: "AUTHORIZATION_EXPIRED"}) || d.TerminalState != "CANCELLED" || op.text("processing_health") != d.Cause.Code || op.optional("permit_signature") != "" || d.PermitSignatureHash != "" || g.row("native_submission_permits", d.OperationID.String()) != nil || op.optional("receipt_id") != "" {
		return businessInvalid("expired USER purchase cannot release signed, granted or settled authority")
	}
	if _, exists := g.nativeReceipts[d.OperationID.String()]; exists {
		return businessInvalid("expired USER purchase cannot erase a retained receipt")
	}
	preview, previewOK := g.nativeActions[op.text("preview_id")].(wireNativeAssetPreview)
	approval, approvalOK := g.onceApprovals[d.OperationID.String()].(wirenativeAssetApproval)
	request, requestOK := g.nativeRequests[d.OperationID.String()]
	if !previewOK || !approvalOK || !requestOK {
		return fmt.Errorf("%w: exact replayed purchase preview/USER original absent", evidence.ErrIncomplete)
	}
	if preview.ID.String() != op.text("preview_id") || preview.Kind != bankv2.Purchase || preview.Scope != g.ownerScopeV3() || approval.ID.String() != op.text("confirmation_id") || approval.PrincipalKind != "USER" || approval.Scope != preview.Scope || approval.PreviewID != preview.ID || approval.SessionID != preview.SessionID || approval.Command.PreviewID != preview.ID || approval.Command.ReviewedHash != preview.ReviewedHash || approval.EffectHash != preview.EffectHash || request.ReferenceHash != preview.ReviewedHash || request.Effect.Kind != bankv2.Purchase || !nativeSameBankEffectV3(request.Effect, preview.BankEffect) {
		return businessInvalid("expired USER purchase must retain its own exact reviewed preview")
	}
	if request.OperationID != d.OperationID.String() || request.Key != op.text("bank_key") || request.Namespace != g.manifest.Scope.Namespace || request.UserID != g.manifest.Scope.UserID || len(request.Authorities) < 1 || request.Authorities[0].SourceID != approval.ID.String() || request.Authorities[0].Role != "EXECUTE" || preview.Dependencies.FundsVersion+1 != d.ReservedFundsVersion || !request.RequestedAt.Equal(op.instant("created_at")) {
		return businessInvalid("expired USER purchase exact original T1/request admission")
	}
	if preview.ExpiresAt.IsZero() || !approval.ExpiresAt.Equal(preview.ExpiresAt) || !request.ExpiresAt.Equal(preview.ExpiresAt) || approval.ConfirmedAt.Before(preview.CreatedAt) || !approval.ConfirmedAt.Before(preview.ExpiresAt) || request.RequestedAt.Before(approval.ConfirmedAt) || !request.RequestedAt.Before(preview.ExpiresAt) || d.DecisionAt.Before(preview.ExpiresAt) {
		return businessInvalid("expired USER purchase decision must follow its own immutable deadline")
	}
	if g.bank == nil || !g.bank.Complete || len(g.bank.Problems) != 0 {
		return fmt.Errorf("%w: unsigned expiry complete independent bank inventory absent", evidence.ErrIncomplete)
	}
	for _, result := range g.bank.Native {
		if result.Key == request.Key {
			return businessInvalid("unsigned expired purchase conflicts with independent original-key bank evidence")
		}
	}
	return nil
}

func (g *nativeGraphV3) checkTerminalBankRejectionV3(after nativeFinancialRowSetV3, d fundswitness.TerminalDecision) error {
	if d.Cause.BankObservationID == nil {
		return fmt.Errorf("%w: exact final no-effect bank observation absent", evidence.ErrIncomplete)
	}
	table, permits := "native_bank_observations", "native_submission_permits"
	if d.LedgerKind == "LEGACY" {
		table, permits = "bank_observations", "submission_permits"
	}
	row := nativeFundsRowByV3(after, table, "id", d.Cause.BankObservationID.String())
	permit := g.row(permits, d.OperationID.String())
	if row == nil || row.text("operation_id") != d.OperationID.String() || row.instant("observed_at").After(d.DecisionAt) || nakedHash(nativeRawV3(row, "original")) != d.Cause.BankObservationHash || permit == nil || d.LedgerKind == "NATIVE" && nativeHashFieldV3(row, "original", "original_hash") != nil {
		return businessInvalid("terminal rejection exact original observation/permit")
	}
	var proof any
	decoder := json.NewDecoder(strings.NewReader(string(nativeRawV3(permit, "original"))))
	decoder.UseNumber()
	if decoder.Decode(&proof) != nil || nativeHighestFundsVersionV3(proof) == 0 || d.Before.FundsVersion < nativeHighestFundsVersionV3(proof) {
		return businessInvalid("terminal rejection precedes its actual original T2 funds prefix")
	}
	if d.LedgerKind == "NATIVE" {
		var result bankv2.Result
		if json.Unmarshal(nativeRawV3(row, "original"), &result) != nil || result.Status != bankv2.Rejected || !result.AbsenceIsFinal || len(result.Postings) != 0 || d.Cause.Code != result.RejectionCode || bankv2.VerifyResult(g.nativeRequests[d.OperationID.String()], result) != nil {
			return businessInvalid("terminal rejection cannot use NOT_FOUND/timeout/accepted as final no-effect")
		}
		for _, actual := range g.bank.Native {
			if actual.Key == d.OperationID.String() && exactJSON(actual, result) {
				return nil
			}
		}
	} else {
		var result execution.BankResult
		if json.Unmarshal(nativeRawV3(row, "original"), &result) != nil || result.Status != execution.BankRejected || !result.AbsenceIsFinal || len(result.Postings) != 0 || d.Cause.Code != result.RejectionCode || execution.VerifyBankResult(g.legacy.requests[d.OperationID.String()], result) != nil {
			return businessInvalid("legacy terminal rejection requires independent exact no-effect")
		}
		for _, actual := range g.bank.Legacy {
			if actual.Key == d.OperationID.String() && exactJSON(actual, result) {
				return nil
			}
		}
	}
	return businessInvalid("terminal rejection differs from independent original-key bank source")
}

func nativeHighestFundsVersionV3(value any) uint64 {
	var max uint64
	switch value := value.(type) {
	case map[string]any:
		for key, child := range value {
			if key == "funds_version" || key == "reserved_funds_version" {
				if n, ok := child.(json.Number); ok {
					v, _ := strconv.ParseUint(n.String(), 10, 64)
					if v > max {
						max = v
					}
				}
			}
			if v := nativeHighestFundsVersionV3(child); v > max {
				max = v
			}
		}
	case []any:
		for _, child := range value {
			if v := nativeHighestFundsVersionV3(child); v > max {
				max = v
			}
		}
	}
	return max
}

func (g *nativeGraphV3) checkTerminalPermissionCauseV3(before nativeFinancialRowSetV3, d fundswitness.TerminalDecision, op *ledgerRow) error {
	if d.LedgerKind != "NATIVE" || d.Cause.EventID == nil || d.Cause.EventSequence == 0 || d.Cause.EventOriginalHash == "" {
		return fmt.Errorf("%w: exact permission lifecycle admission prefix absent", evidence.ErrIncomplete)
	}
	if d.Cause.Kind == fundswitness.NativeGrantNotActive {
		if d.Cause.Code != fundswitness.NativeGrantNotActive || d.Cause.VersionID != nil || d.Cause.GrantID == nil || op.optional("grant_id") != d.Cause.GrantID.String() || uint64(op.positive("grant_version")) != d.Cause.GrantVersion {
			return businessInvalid("terminal cancellation unrelated native grant")
		}
		var state *ledgerRow
		for _, raw := range before["native_grant_states"] {
			v, _ := nativeFundsObjectV3(raw)
			r := &ledgerRow{values: v}
			if r.text("grant_id") == d.Cause.GrantID.String() && uint64(r.positive("grant_version")) == d.Cause.GrantVersion {
				state = r
			}
		}
		event := nativeFundsRowByV3(before, "native_grant_state_events", "id", d.Cause.EventID.String())
		var original nativeGrantStateV3
		if state == nil || event == nil || state.text("state") == "ACTIVE" || state.text("event_id") != d.Cause.EventID.String() || uint64(state.positive("sequence")) != d.Cause.EventSequence || event.text("original_hash") != d.Cause.EventOriginalHash || json.Unmarshal(nativeRawV3(event, "original"), &original) != nil || original.GrantID != *d.Cause.GrantID || original.GrantVersion != d.Cause.GrantVersion || original.Sequence != d.Cause.EventSequence || original.NewState != state.text("state") || original.At.After(d.DecisionAt) || original.PrincipalKind != "USER" {
			return businessInvalid("terminal cancellation cannot borrow a future grant revoke/pause or final mutable state")
		}
		return nil
	}
	if d.Cause.VersionID == nil {
		return businessInvalid("terminal template cancellation version absent")
	}
	if d.Cause.GrantID != nil || d.Cause.GrantVersion != 0 {
		return businessInvalid("template cancellation must identify its exact policy cause")
	}
	switch d.Cause.Code {
	case "TEMPLATE_POLICY_INACTIVE", "PAYMENT_POLICY_NOT_ACTIVE", "ASSET_POLICY_NOT_ACTIVE":
	case "SOURCE_CHANGED":
		var dependencies planning.DependencyVector
		op.object("dependencies", &dependencies)
		if op.err != nil || dependencies.SourceEvidenceVersion == 0 || dependencies.SourceEvidenceVersion == d.Before.SourceVersion {
			return businessInvalid("SOURCE_CHANGED template cause requires actual original source dependency mismatch")
		}
	default:
		return fmt.Errorf("%w: exact template cancellation reason unsupported", evidence.ErrIncomplete)
	}
	version := nativeFundsRowByV3(before, "template_policy_versions", "id", d.Cause.VersionID.String())
	event := nativeFundsRowByV3(before, "template_policy_status_events", "id", d.Cause.EventID.String())
	var original nativeTemplateStatusV3
	if version == nil || event == nil || version.text("state") == "ACTIVE" || version.text("status_event_id") != d.Cause.EventID.String() || uint64(version.positive("status_sequence")) != d.Cause.EventSequence || event.text("original_hash") != d.Cause.EventOriginalHash || json.Unmarshal(nativeRawV3(event, "original"), &original) != nil || original.VersionID != *d.Cause.VersionID || original.Sequence != d.Cause.EventSequence || original.NewState != version.text("state") || original.At.After(d.DecisionAt) {
		return businessInvalid("terminal cancellation cannot borrow a future template pause/revoke/expiry")
	}
	related := false
	for _, authority := range g.nativeRequests[d.OperationID.String()].Authorities {
		if authority.PolicyID == version.text("policy_id") && authority.PolicyVersion == version.positive("version") {
			related = true
		}
	}
	if id := op.optional("grant_id"); id != "" {
		grantRow := g.row("native_grants", id, strconv.FormatInt(op.positive("grant_version"), 10))
		var grant nativeGrantV3
		if grantRow != nil && json.Unmarshal(nativeRawV3(grantRow, "original"), &grant) == nil {
			for _, reference := range grant.Terms.Policies {
				related = related || reference.VersionID == *d.Cause.VersionID
			}
		}
	}
	if !related {
		return businessInvalid("terminal template cancellation not related to original reviewed authority")
	}
	return nil
}
