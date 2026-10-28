package executionaudit

import (
	"encoding/json"
	"fmt"
	"sort"
	"strconv"

	evidence "zhiyu.local/zhiyu-go/internal/audit"
	"zhiyu.local/zhiyu-go/internal/execution/fundswitness"
	funds "zhiyu.local/zhiyu-go/internal/funds/domain"
	planning "zhiyu.local/zhiyu-go/internal/planning/domain"
	policy "zhiyu.local/zhiyu-go/internal/policy/domain"
)

// Uses the existing 16MiB raw / 1MiB canonical gzip+hex budget without raising
// either bound. The whole graph's independent aggregate bounds still apply.
func ValidateDatedSourceRowCapacityV1(raw []byte) error {
	_, err := nativeEncodeBytesV3(raw)
	return err
}

type nativeDatedConfirmationSourceV1 struct {
	Protocol    string                 `json:"protocol"`
	PreviewID   funds.ID               `json:"preview_id"`
	BeforeInput planning.ForecastInput `json:"before_input"`
}
type nativeDatedConfirmationWitnessV1 struct {
	Protocol          string                           `json:"protocol"`
	SourceWitnessID   funds.ID                         `json:"source_witness_id"`
	SourceWitnessHash string                           `json:"source_witness_hash"`
	Admission         *fundswitness.Boundary           `json:"admission"`
	References        []policy.TemplatePolicyReference `json:"references"`
}

func nativeDatedRequiredV3(compiled policy.CompiledTemplate) ([]funds.ID, error) {
	if compiled.Name != policy.DatedExpenseTemplate {
		return nil, nil
	}
	c, e := compiled.Decode()
	if e != nil {
		return nil, businessInvalid("Dated typed reference configuration")
	}
	return c.(*policy.DatedExpenseConfig).MustNotReducePolicyIDs, nil
}

// Reconstruct current versions from the actual financial prefix, never the
// counterfactual array or today's projection. Envelope validation follows.
func nativeDatedBeforeInputV3(after planning.ForecastInput, financial map[string][]string) (planning.ForecastInput, error) {
	before, e := planning.CloneForecastInput(after)
	if e != nil {
		return before, e
	}
	versions := map[string]*ledgerRow{}
	for _, raw := range financial["template_policy_versions"] {
		v, e := nativeFundsObjectV3(raw)
		if e != nil {
			return before, e
		}
		r := &ledgerRow{values: v}
		versions[keyParts(r.text("policy_id"), strconv.FormatInt(r.positive("version"), 10))] = r
	}
	before.Versions = nil
	for _, raw := range financial["template_policies"] {
		v, e := nativeFundsObjectV3(raw)
		if e != nil {
			return before, e
		}
		p := &ledgerRow{values: v}
		r := versions[keyParts(p.text("id"), strconv.FormatInt(p.positive("current_version"), 10))]
		if r == nil {
			return before, businessInvalid("Dated before current version missing")
		}
		var actual policy.TemplateVersion
		nativeOriginalV3(r, "original", &actual)
		actual.State, actual.Current = r.text("state"), true
		if p.err != nil || r.err != nil {
			return before, businessInvalid("Dated before current version original")
		}
		before.Versions = append(before.Versions, actual)
	}
	sort.Slice(before.Versions, func(i, j int) bool {
		return before.Versions[i].PolicyID.String() < before.Versions[j].PolicyID.String()
	})
	return before, nil
}

func (g *nativeGraphV3) replayDatedPreviewReferencesV3(p nativeTemplatePreviewV3, ledger nativeFrozenLedgerV3, w nativeTemplateSourceWitnessV3, financial map[string][]string) ([]policy.TemplatePolicyReference, error) {
	ids, e := nativeDatedRequiredV3(p.Compiled)
	if e != nil || len(ids) == 0 {
		return nil, e
	}
	if p.ForecastInput == nil {
		return nil, fmt.Errorf("%w: Dated protected preview source input missing", evidence.ErrIncomplete)
	}
	before, e := nativeDatedBeforeInputV3(*p.ForecastInput, financial)
	if e != nil {
		return nil, e
	}
	if e = g.checkSourceForecastEnvelopeV3(before, ledger, w, financial, nil, nil, false); e != nil {
		return nil, e
	}
	refs, e := planning.CompareProtectedPolicyReferencesV1(before, *p.ForecastInput, p.PolicyID, ids)
	if e != nil {
		return nil, businessInvalid("Dated protected preview exact full-curve replay")
	}
	return refs, nil
}

func (g *nativeGraphV3) checkDatedConfirmationSourceV3(w nativeTemplateSourceWitnessV3, hash string, ledger nativeFrozenLedgerV3, financial map[string][]string) (string, error) {
	source := w.DatedConfirmationInput
	if source == nil || source.Protocol != "dated-protected-confirmation-source-v1" {
		return "", businessInvalid("Dated confirmation source protocol")
	}
	wraw, e := json.Marshal(w)
	if e != nil || len(wraw) > planning.MaxDatedConfirmationSourceBytesV1 {
		return "", fmt.Errorf("%w: Dated source original v1 capacity", evidence.ErrIncomplete)
	}
	pRow := g.row("template_policy_previews", source.PreviewID.String())
	if pRow == nil {
		return "", businessInvalid("Dated confirmation source preview")
	}
	var p nativeTemplatePreviewV3
	nativeOriginalV3(pRow, "review_bundle", &p)
	var c nativeTemplateConfirmationV3
	var cRow *ledgerRow
	for _, row := range g.rows["template_policy_confirmations"] {
		if row.text("preview_id") != source.PreviewID.String() {
			continue
		}
		if cRow != nil {
			return "", businessInvalid("Dated source duplicate confirmation consumer")
		}
		cRow = row
		nativeOriginalV3(row, "original", &c)
	}
	ids, e := nativeDatedRequiredV3(p.Compiled)
	if e != nil {
		return "", e
	}
	if cRow == nil || len(ids) == 0 || c.DatedReferences == nil {
		return "", businessInvalid("unconsumed Dated fresh confirmation source")
	}
	ref := c.DatedReferences
	expectedBoundary := fundswitness.Boundary{FundsVersion: w.FundsVersion, SourceVersion: w.SnapshotSourceVersion, WriterGeneration: w.WriterGeneration, ControlVersion: w.ControlVersion, CommitHash: w.FundsCommitHash, StateHash: w.FundsStateHash}
	if ref.Protocol != "dated-protected-confirmation-v1" || ref.SourceWitnessID != w.ID || ref.SourceWitnessHash != hash || ref.Admission == nil || *ref.Admission != expectedBoundary || !c.ConfirmedAt.Equal(w.AsOf) || p.Timezone != w.Timezone || p.SourceHash != w.SourceHash || c.Scope != w.Scope || c.PolicyID != p.PolicyID || c.VersionID != p.VersionID || c.ConfigurationHash != p.Compiled.Hash || c.ReviewedBundleHash != p.ReviewedBundleHash {
		return "", businessInvalid("Dated confirmation exact fresh source/admission")
	}
	matched := false
	for _, row := range g.rows["template_policy_status_events"] {
		if row.text("version_id") != c.VersionID.String() || row.positive("sequence") != 1 {
			continue
		}
		var event nativeTemplateStatusV3
		nativeOriginalV3(row, "original", &event)
		if matched || event.Action != "CONFIRM" || !event.At.Equal(w.AsOf) || event.Admission == nil || *event.Admission != expectedBoundary {
			return "", businessInvalid("Dated confirmation lifecycle admission differs")
		}
		matched = true
	}
	if !matched {
		return "", businessInvalid("Dated confirmation lifecycle admission missing")
	}
	before := source.BeforeInput
	if before.Scope != w.Scope || !before.AsOf.Equal(w.AsOf) || before.Timezone != w.Timezone || before.Facts.SourceHash != w.SourceHash || before.Facts.CurrentSafeVerified || !before.Facts.CurrentSafe.IsZero() {
		return "", businessInvalid("Dated fresh before scope/time/base")
	}
	if e = g.checkTemplateFactsLedgerV3(before.Facts, ledger, w.AsOf, w.Timezone, w.SnapshotSourceVersion); e != nil {
		return "", e
	}
	if e = g.checkSourceForecastEnvelopeV3(before, ledger, w, financial, nil, nil, false); e != nil {
		return "", e
	}
	var old uint64
	for _, v := range before.Versions {
		if v.PolicyID == p.PolicyID {
			old = v.Version
		}
	}
	if old != p.BaseVersion {
		return "", businessInvalid("Dated confirmation current base changed")
	}
	proposed := policy.TemplateVersion{PolicyID: p.PolicyID, VersionID: p.VersionID, Version: p.BaseVersion + 1, Scope: p.Scope, Compiled: p.Compiled, State: "ACTIVE", ConfirmedAt: w.AsOf, Current: true, ConfirmationVerified: true, ConfirmedConfigurationHash: p.Compiled.Hash}
	after, e := planning.CloneForecastInput(before)
	if e != nil {
		return "", e
	}
	after.Versions = nil
	for _, v := range before.Versions {
		if v.PolicyID != p.PolicyID {
			after.Versions = append(after.Versions, v)
		}
	}
	after.Versions = append(after.Versions, proposed)
	sort.Slice(after.Versions, func(i, j int) bool { return after.Versions[i].PolicyID.String() < after.Versions[j].PolicyID.String() })
	refs, e := planning.CompareProtectedPolicyReferencesV1(before, after, p.PolicyID, ids)
	if e != nil || !exactJSON(refs, ref.References) {
		return "", businessInvalid("Dated fresh confirmation full curve/reference replay")
	}
	forecast, e := planning.Forecast365(after)
	if e != nil {
		return "", businessInvalid("Dated fresh confirmation forecast")
	}
	facts := after.Facts
	facts.CurrentSafe, facts.CurrentSafeVerified, facts.ProtectedReferences = forecast.CurrentSafe, true, refs
	if _, e = policy.PreviewTemplate(proposed, facts, w.AsOf, w.Timezone); e != nil {
		return "", businessInvalid("Dated fresh confirmation typed facts replay")
	}
	return cRow.text("id"), nil
}
