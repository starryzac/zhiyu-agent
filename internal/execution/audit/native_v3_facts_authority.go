package executionaudit

import (
	"encoding/json"
	"sort"
	"strconv"

	policy "zhiyu.local/zhiyu-go/internal/policy/domain"
)

// Fold the actual authority originals at every FV, including unused prefixes.
// Mutable state/pointers cannot temporarily introduce permissions and then
// return to the correct final rows without their complete original events.
func (g *nativeGraphV3) checkFundsTemplateAuthorityV3(state nativeFinancialRowSetV3, commit nativeFundsCommitV3) error {
	if err := checkFundsAuthorityAdmissionV3(commit, "template_policy_status_events", "template lifecycle"); err != nil {
		return err
	}
	rows := map[string]map[string]*ledgerRow{}
	for _, table := range []string{"template_policies", "template_policy_versions", "template_policy_confirmations", "template_policy_status_events"} {
		rows[table] = map[string]*ledgerRow{}
		for _, raw := range state[table] {
			v, err := nativeFundsObjectV3(raw)
			if err != nil {
				return err
			}
			r := &ledgerRow{values: v}
			id := r.text("id")
			rows[table][id] = r
			key := []string{id}
			if table == "template_policy_versions" {
				key = []string{r.text("policy_id"), strconv.FormatInt(r.positive("version"), 10)}
			}
			current := g.row(table, key...)
			if current == nil {
				return businessInvalid("funds prefix authority has no exact original source")
			}
			left, right := map[string]any{}, map[string]any{}
			for field, value := range r.values {
				left[field] = value
			}
			for field, value := range current.values {
				right[field] = value
			}
			for _, field := range []string{"current_version", "state", "status_sequence", "status_event_id"} {
				if table == "template_policies" && field == "current_version" || table == "template_policy_versions" && field != "current_version" {
					delete(left, field)
					delete(right, field)
				}
			}
			if !exactJSON(left, right) {
				return businessInvalid("funds prefix rewrote immutable USER authority fields")
			}
		}
	}
	events := map[string][]*ledgerRow{}
	for _, event := range rows["template_policy_status_events"] {
		if rows["template_policy_versions"][event.text("version_id")] == nil {
			return businessInvalid("funds prefix orphan lifecycle original")
		}
		events[event.text("version_id")] = append(events[event.text("version_id")], event)
	}
	maxVersion := map[string]int64{}
	versionCount := map[string]int64{}
	for id, version := range rows["template_policy_versions"] {
		var original policy.TemplateVersion
		if json.Unmarshal(nativeRawV3(version, "original"), &original) != nil || !exactJSON(g.templates[id], original) || rows["template_policies"][version.text("policy_id")] == nil {
			return businessInvalid("funds prefix exact confirmed template version")
		}
		confirmation := rows["template_policy_confirmations"][version.text("confirmation_id")]
		if confirmation == nil || confirmation.text("version_id") != id || confirmation.text("policy_id") != version.text("policy_id") {
			return businessInvalid("funds prefix version missing same-boundary USER confirmation")
		}
		sequence := events[id]
		sort.Slice(sequence, func(i, j int) bool { return sequence[i].positive("sequence") < sequence[j].positive("sequence") })
		state := ""
		for index, event := range sequence {
			if event.positive("sequence") != int64(index+1) || event.optional("old_state") != state {
				return businessInvalid("funds prefix authority event sequence gap/reordering")
			}
			var lifecycle nativeTemplateStatusV3
			if json.Unmarshal(nativeRawV3(event, "original"), &lifecycle) != nil {
				return businessInvalid("funds prefix lifecycle exact original")
			}
			if err := checkTemplateLifecycleExpiryV3(original, version.text("timezone"), lifecycle); err != nil {
				return err
			}
			state = event.text("new_state")
		}
		if len(sequence) == 0 || version.positive("status_sequence") != int64(len(sequence)) || version.text("state") != state || version.text("status_event_id") != sequence[len(sequence)-1].text("id") {
			return businessInvalid("funds prefix template state/pointer lacks exact complete original lifecycle")
		}
		pid := version.text("policy_id")
		versionCount[pid]++
		if version.positive("version") > maxVersion[pid] {
			maxVersion[pid] = version.positive("version")
		}
	}
	for id, p := range rows["template_policies"] {
		if p.positive("current_version") != maxVersion[id] || versionCount[id] != maxVersion[id] {
			return businessInvalid("funds prefix current policy pointer omits or borrows confirmed version")
		}
	}
	for _, confirmation := range rows["template_policy_confirmations"] {
		if rows["template_policy_versions"][confirmation.text("version_id")] == nil {
			return businessInvalid("funds prefix orphan USER confirmation")
		}
	}
	for _, change := range commit.Changes {
		if change.Table == "template_policy_versions" && change.BeforeHash == nil && change.AfterOriginal != nil {
			value, _ := nativeFundsObjectV3(*change.AfterOriginal)
			v := &ledgerRow{values: value}
			c := rows["template_policy_confirmations"][v.text("confirmation_id")]
			if c == nil {
				return businessInvalid("funds prefix template birth confirmation absent")
			}
			preview := g.row("template_policy_previews", c.text("preview_id"))
			var p nativeTemplatePreviewV3
			if preview == nil || json.Unmarshal(nativeRawV3(preview, "review_bundle"), &p) != nil || p.SnapshotFundsVersion+1 != commit.FundsVersion {
				return businessInvalid("template USER confirmation must follow its exact reviewed funds prefix")
			}
		}
	}
	return nil
}

func checkTemplateLifecycleExpiryV3(version policy.TemplateVersion, timezone string, event nativeTemplateStatusV3) error {
	if event.Action != "EXPIRE" {
		return nil
	}
	_, end, err := policy.TemplateValidity(version.Compiled, version.ConfirmedAt, timezone)
	if err != nil || end == nil || event.ActorKind != "SYSTEM" || event.NewState != "EXPIRED" || event.At.Before(*end) {
		return businessInvalid("template expiry requires exact original natural-date deadline and SYSTEM event")
	}
	return nil
}
