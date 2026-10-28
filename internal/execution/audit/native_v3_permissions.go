package executionaudit

import (
	"bytes"
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"time"

	evidence "zhiyu.local/zhiyu-go/internal/audit"
	"zhiyu.local/zhiyu-go/internal/execution/fundswitness"
	funds "zhiyu.local/zhiyu-go/internal/funds/domain"
	planning "zhiyu.local/zhiyu-go/internal/planning/domain"
	policy "zhiyu.local/zhiyu-go/internal/policy/domain"
)

type nativeTemplateTargetV3 struct {
	GoalID funds.ID    `json:"goal_id"`
	Before funds.Money `json:"before_cents"`
	After  funds.Money `json:"after_cents"`
}
type nativeTemplatePreviewV3 struct {
	ID                    funds.ID                  `json:"id"`
	PolicyID              funds.ID                  `json:"policy_id"`
	VersionID             funds.ID                  `json:"version_id"`
	BaseVersion           uint64                    `json:"base_version"`
	Mode                  string                    `json:"mode"`
	Scope                 policy.TemplateOwnerScope `json:"scope"`
	GoalID                *funds.ID                 `json:"goal_id,omitempty"`
	TargetMutation        *nativeTemplateTargetV3   `json:"target_mutation,omitempty"`
	Timezone              string                    `json:"timezone"`
	Compiled              policy.CompiledTemplate   `json:"compiled"`
	FactsHash             string                    `json:"facts_hash"`
	SourceHash            string                    `json:"source_hash"`
	SourceWitnessID       *funds.ID                 `json:"source_witness_id,omitempty"`
	SourceWitnessHash     string                    `json:"source_witness_hash,omitempty"`
	SnapshotFundsVersion  uint64                    `json:"snapshot_funds_version,omitempty"`
	SnapshotSourceVersion uint64                    `json:"snapshot_source_version,omitempty"`
	Facts                 policy.TemplateFacts      `json:"facts"`
	Preview               policy.TemplatePreview    `json:"preview"`
	ForecastInput         *planning.ForecastInput   `json:"forecast_input,omitempty"`
	Forecast              planning.ForecastResult   `json:"forecast"`
	ReviewedBundleHash    string                    `json:"reviewed_bundle_hash"`
	CreatedAt             time.Time                 `json:"created_at"`
	ExpiresAt             time.Time                 `json:"expires_at"`
	Authority             string                    `json:"authority"`
	BankAuthority         bool                      `json:"bank_authority"`
}
type nativeTemplateConfirmationV3 struct {
	Protocol                                             string `json:"protocol"`
	ID, PolicyID, VersionID, PreviewID, SessionID        funds.ID
	Scope                                                policy.TemplateOwnerScope
	PrincipalKind, ReviewedBundleHash, ConfigurationHash string
	ConfirmedAt                                          time.Time
	TargetMutation                                       *nativeTemplateTargetV3           `json:"target_mutation,omitempty"`
	DatedReferences                                      *nativeDatedConfirmationWitnessV1 `json:"dated_references,omitempty"`
}
type nativeTemplateStatusV3 struct {
	Protocol                              string
	ID, VersionID                         funds.ID
	Sequence                              uint64
	Action, OldState, NewState, ActorKind string
	SessionID                             *funds.ID
	At                                    time.Time
	Admission                             *fundswitness.Boundary `json:"admission,omitempty"`
}

type nativeGrantV3 struct {
	Protocol      string                     `json:"protocol"`
	ID            funds.ID                   `json:"id"`
	Version       uint64                     `json:"version"`
	Scope         policy.TemplateOwnerScope  `json:"scope"`
	Terms         policy.NativeStandingTerms `json:"terms"`
	ReviewedTerms policy.NativeStandingTerms `json:"reviewed_terms"`
	PreviewID     funds.ID                   `json:"preview_id"`
	SessionID     funds.ID                   `json:"session_id"`
	ReviewedHash  string                     `json:"reviewed_hash"`
	PrincipalKind string                     `json:"principal_kind"`
	ConfirmedAt   time.Time                  `json:"confirmed_at"`
}
type nativeGrantPreviewV3 struct {
	Protocol     string                     `json:"protocol"`
	ID           funds.ID                   `json:"id"`
	Scope        policy.TemplateOwnerScope  `json:"scope"`
	SessionID    funds.ID                   `json:"session_id"`
	Terms        policy.NativeStandingTerms `json:"terms"`
	ReviewedHash string                     `json:"reviewed_hash"`
	CreatedAt    time.Time                  `json:"created_at"`
	ExpiresAt    time.Time                  `json:"expires_at"`
}
type nativeGrantStateV3 struct {
	Protocol      string                    `json:"protocol"`
	ID            funds.ID                  `json:"id"`
	Scope         policy.TemplateOwnerScope `json:"scope"`
	GrantID       funds.ID                  `json:"grant_id"`
	GrantVersion  uint64                    `json:"grant_version"`
	Sequence      uint64                    `json:"sequence"`
	Action        string                    `json:"action"`
	OldState      string                    `json:"old_state"`
	NewState      string                    `json:"new_state"`
	SessionID     funds.ID                  `json:"session_id"`
	PrincipalKind string                    `json:"principal_kind"`
	At            time.Time                 `json:"at"`
	Admission     *fundswitness.Boundary    `json:"admission,omitempty"`
}

func (g *nativeGraphV3) ownerScopeV3() policy.TemplateOwnerScope {
	return policy.TemplateOwnerScope{EnvironmentID: mustBusinessID(g.manifest.Scope.EnvironmentID), UserID: mustBusinessID(g.manifest.Scope.UserID)}
}

func (g *nativeGraphV3) humanAtV3(session funds.ID, at time.Time) error {
	row := g.row("audit_session_subjects", session.String())
	if row == nil {
		return &evidence.ReferenceError{ID: RowID("audit_session_subjects", keyParts(session.String())), Cause: fmt.Errorf("%w: actual USER session subject", evidence.ErrIncomplete)}
	}
	if session == (funds.ID{}) || at.IsZero() || !at.Before(row.instant("expires_at")) {
		return businessInvalid("native USER confirmation session/time")
	}
	return nil
}

func (g *nativeGraphV3) checkTemplatesV3() error {
	g.templates = map[string]policy.TemplateVersion{}
	previews := map[string]nativeTemplatePreviewV3{}
	for _, row := range g.rows["template_policy_previews"] {
		var preview nativeTemplatePreviewV3
		nativeOriginalV3(row, "review_bundle", &preview)
		copy := preview
		copy.ReviewedBundleHash = ""
		raw, _ := json.Marshal(copy)
		if row.err != nil || nakedHash(raw) != row.text("reviewed_bundle_hash") || preview.ReviewedBundleHash != row.text("reviewed_bundle_hash") || preview.ID.String() != row.text("id") || preview.PolicyID.String() != row.text("policy_id") || preview.VersionID.String() != row.text("version_id") || preview.BaseVersion != uint64(row.integer("base_version")) || preview.Scope != g.ownerScopeV3() || preview.Compiled.Name != policy.TemplateName(row.text("template_name")) || preview.Compiled.Hash != row.text("configuration_hash") || !bytes.Equal(preview.Compiled.Configuration, nativeRawV3(row, "configuration")) || preview.FactsHash != row.text("facts_hash") || preview.SourceHash != row.text("source_hash") || preview.Timezone != row.text("timezone") || !preview.CreatedAt.Equal(row.instant("created_at")) || !preview.ExpiresAt.Equal(row.instant("expires_at")) || preview.Mode != "IF_USER_CONFIRMED" || preview.Authority != "POLICY_CONFIGURATION_ONLY_NO_BANK_GRANT" || preview.BankAuthority || preview.ExpiresAt.Sub(preview.CreatedAt) > 2*time.Minute {
			return businessInvalid("template complete counterfactual review bundle")
		}
		if _, err := preview.Compiled.Decode(); err != nil {
			return businessInvalid("template actual typed configuration compilation")
		}
		facts, _ := json.Marshal(preview.Facts)
		rendered, _ := json.Marshal(preview.Preview)
		if !bytes.Equal(facts, nativeRawV3(row, "facts_original")) || nakedHash(facts) != preview.FactsHash || !bytes.Equal(rendered, nativeRawV3(row, "preview_original")) || nakedHash(rendered) != row.text("preview_hash") {
			return businessInvalid("template preview/facts original binding")
		}
		proposed := policy.TemplateVersion{PolicyID: preview.PolicyID, VersionID: preview.VersionID, Version: preview.BaseVersion + 1, Scope: preview.Scope, Compiled: preview.Compiled, State: "ACTIVE", ConfirmedAt: preview.CreatedAt, Current: true, ConfirmationVerified: true, ConfirmedConfigurationHash: preview.Compiled.Hash}
		replayed, err := policy.PreviewTemplate(proposed, preview.Facts, preview.CreatedAt, preview.Timezone)
		if err != nil || !exactJSON(replayed, preview.Preview) {
			return businessInvalid("template pure candidate preview replay")
		}
		if err = g.humanAtV3(row.id("session_id"), preview.CreatedAt); err != nil {
			return err
		}
		previews[preview.ID.String()] = preview
	}
	for _, row := range g.rows["template_policy_versions"] {
		var version policy.TemplateVersion
		nativeOriginalV3(row, "original", &version)
		policyRow := g.row("template_policies", row.text("policy_id"))
		confirmation := g.row("template_policy_confirmations", row.text("confirmation_id"))
		if policyRow == nil || confirmation == nil || nativeHashFieldV3(row, "original", "original_hash") != nil || version.Scope != g.ownerScopeV3() || version.PolicyID.String() != row.text("policy_id") || version.VersionID.String() != row.text("id") || version.Version != uint64(row.positive("version")) || string(version.Compiled.Name) != policyRow.text("template_name") || version.Compiled.Hash != row.text("configuration_hash") || version.ConfirmedConfigurationHash != version.Compiled.Hash || !bytes.Equal(version.Compiled.Configuration, nativeRawV3(row, "configuration")) || !version.ConfirmedAt.Equal(row.instant("confirmed_at")) || version.State != "ACTIVE" || !version.Current || !version.ConfirmationVerified {
			return businessInvalid("template original confirmed typed version")
		}
		if _, err := version.Compiled.Decode(); err != nil {
			return businessInvalid("template original compiled configuration")
		}
		if version.Version > 1 && g.row("template_policy_versions", version.PolicyID.String(), strconv.FormatUint(version.Version-1, 10)) == nil {
			return businessInvalid("template missing historical version")
		}
		var c nativeTemplateConfirmationV3
		nativeOriginalV3(confirmation, "original", &c)
		p, ok := previews[c.PreviewID.String()]
		var command struct {
			PreviewID          funds.ID `json:"preview_id"`
			ReviewedBundleHash string   `json:"reviewed_bundle_hash"`
		}
		nativeOriginalV3(confirmation, "request", &command)
		if !ok || nativeHashFieldV3(confirmation, "original", "original_hash") != nil || nativeHashFieldV3(confirmation, "request", "request_hash") != nil || c.Protocol != "template-user-confirmation-v1" || c.ID.String() != confirmation.text("id") || c.PolicyID != version.PolicyID || c.VersionID != version.VersionID || c.Scope != g.ownerScopeV3() || c.PrincipalKind != "USER" || c.SessionID.String() != confirmation.text("session_id") || c.PreviewID.String() != confirmation.text("preview_id") || c.ConfigurationHash != version.Compiled.Hash || c.ConfigurationHash != confirmation.text("configuration_hash") || c.ReviewedBundleHash != p.ReviewedBundleHash || c.ReviewedBundleHash != confirmation.text("reviewed_bundle_hash") || !c.ConfirmedAt.Equal(version.ConfirmedAt) || !c.ConfirmedAt.Equal(confirmation.instant("confirmed_at")) || c.ConfirmedAt.Before(p.CreatedAt) || !c.ConfirmedAt.Before(p.ExpiresAt) || command.PreviewID != c.PreviewID || command.ReviewedBundleHash != c.ReviewedBundleHash || !exactJSON(c.TargetMutation, p.TargetMutation) || p.Compiled.Hash != version.Compiled.Hash || p.BaseVersion+1 != version.Version {
			return businessInvalid("template actual USER full bundle confirmation")
		}
		if err := g.humanAtV3(c.SessionID, c.ConfirmedAt); err != nil {
			return err
		}
		events := []nativeTemplateStatusV3{}
		for _, eventRow := range g.rows["template_policy_status_events"] {
			if eventRow.text("version_id") != version.VersionID.String() {
				continue
			}
			var event nativeTemplateStatusV3
			nativeOriginalV3(eventRow, "original", &event)
			if nativeHashFieldV3(eventRow, "original", "original_hash") != nil || event.Protocol != "template-lifecycle-v1" || event.ID.String() != eventRow.text("id") || event.VersionID != version.VersionID || event.Sequence != uint64(eventRow.positive("sequence")) || event.Action != eventRow.text("action") || event.OldState != eventRow.optional("old_state") || event.NewState != eventRow.text("new_state") || event.ActorKind != eventRow.text("actor_kind") || !event.At.Equal(eventRow.instant("occurred_at")) {
				return businessInvalid("template original lifecycle event")
			}
			if event.ActorKind == "USER" {
				if event.SessionID == nil || event.SessionID.String() != eventRow.text("session_id") {
					return businessInvalid("template USER event identity")
				}
				if err := g.humanAtV3(*event.SessionID, event.At); err != nil {
					return err
				}
			} else if event.ActorKind != "SYSTEM" || event.Action != "EXPIRE" || event.SessionID != nil {
				return businessInvalid("template model/system cannot confirm")
			}
			events = append(events, event)
		}
		sort.Slice(events, func(i, j int) bool { return events[i].Sequence < events[j].Sequence })
		state := ""
		var previous time.Time
		for i, event := range events {
			if event.Sequence != uint64(i+1) || event.OldState != state || event.At.Before(previous) || event.At.Before(c.ConfirmedAt) {
				return businessInvalid("template complete sequential lifecycle")
			}
			valid := i == 0 && event.Action == "CONFIRM" && event.NewState == "ACTIVE" && event.At.Equal(c.ConfirmedAt)
			if i > 0 {
				valid = (state == "ACTIVE" && event.Action == "PAUSE" && event.NewState == "SUSPENDED") || (state == "SUSPENDED" && event.Action == "RESUME" && event.NewState == "ACTIVE") || ((state == "ACTIVE" || state == "SUSPENDED") && event.Action == "REVOKE" && event.NewState == "REVOKED") || ((state == "ACTIVE" || state == "SUSPENDED") && event.Action == "EXPIRE" && event.NewState == "EXPIRED")
			}
			if !valid {
				return businessInvalid("template lifecycle transition semantics")
			}
			state, previous = event.NewState, event.At
		}
		if len(events) == 0 || state != row.text("state") || uint64(len(events)) != uint64(row.positive("status_sequence")) || events[len(events)-1].ID.String() != row.text("status_event_id") {
			return businessInvalid("template current lifecycle projection")
		}
		g.templates[version.VersionID.String()] = version
	}
	for _, row := range g.rows["template_policies"] {
		if g.row("template_policy_versions", row.text("id"), strconv.FormatInt(row.positive("current_version"), 10)) == nil {
			return businessInvalid("template current version pointer")
		}
	}
	return g.checkedRowsV3()
}

func (g *nativeGraphV3) checkNativeGrantsV3() error {
	g.nativeGrants = map[string]nativeGrantV3{}
	g.nativeGrantEvents = map[string][]nativeGrantStateV3{}
	previews := map[string]nativeGrantPreviewV3{}
	for _, row := range g.rows["native_grant_previews"] {
		var preview nativeGrantPreviewV3
		nativeOriginalV3(row, "original", &preview)
		copy := preview
		copy.ReviewedHash = ""
		raw, _ := json.Marshal(copy)
		if nativeHashFieldV3(row, "original", "original_hash") != nil || preview.Protocol != "native-automation-v1/grant-preview" || preview.Scope != g.ownerScopeV3() || preview.Terms.Scope != preview.Scope || preview.Terms.Validate() != nil || preview.ID.String() != row.text("id") || preview.SessionID.String() != row.text("session_id") || !preview.CreatedAt.Equal(row.instant("created_at")) || !preview.ExpiresAt.Equal(row.instant("expires_at")) || preview.ExpiresAt.Sub(preview.CreatedAt) > 2*time.Minute || preview.ReviewedHash != nakedHash(raw) || preview.ReviewedHash != row.text("reviewed_hash") {
			return businessInvalid("native reviewed closed five-family grant preview")
		}
		if err := g.humanAtV3(preview.SessionID, preview.CreatedAt); err != nil {
			return err
		}
		previews[preview.ID.String()] = preview
	}
	for _, row := range g.rows["native_grants"] {
		var grant nativeGrantV3
		nativeOriginalV3(row, "original", &grant)
		preview, ok := previews[grant.PreviewID.String()]
		var command struct {
			PreviewID    funds.ID `json:"preview_id"`
			ReviewedHash string   `json:"reviewed_hash"`
		}
		nativeOriginalV3(row, "request", &command)
		final := grant.Terms
		final.EffectiveFrom = grant.ReviewedTerms.EffectiveFrom
		if !ok || nativeHashFieldV3(row, "original", "original_hash") != nil || nativeHashFieldV3(row, "request", "request_hash") != nil || grant.Protocol != "native-automation-v1/grant" || grant.ID.String() != row.text("id") || grant.Version != uint64(row.positive("version")) || grant.Version != 1 || grant.Scope != g.ownerScopeV3() || grant.Terms.Scope != grant.Scope || grant.ReviewedTerms.Scope != grant.Scope || grant.PrincipalKind != "USER" || grant.SessionID.String() != row.text("session_id") || grant.SessionID != preview.SessionID || grant.PreviewID.String() != row.text("preview_id") || grant.Terms.Validate() != nil || grant.ReviewedTerms.Validate() != nil || !exactJSON(final, grant.ReviewedTerms) || !exactJSON(grant.ReviewedTerms, preview.Terms) || !grant.ConfirmedAt.Equal(row.instant("confirmed_at")) || !grant.ConfirmedAt.Equal(grant.Terms.EffectiveFrom) || !grant.Terms.EffectiveFrom.Equal(row.instant("effective_from")) || !grant.Terms.ExpiresAt.Equal(row.instant("expires_at")) || string(grant.Terms.Family) != row.text("family") || grant.ConfirmedAt.Before(preview.CreatedAt) || !grant.ConfirmedAt.Before(preview.ExpiresAt) || grant.ReviewedHash != preview.ReviewedHash || command.PreviewID != preview.ID || command.ReviewedHash != preview.ReviewedHash {
			return businessInvalid("native actual USER grant exact terms/window/preview")
		}
		if err := g.humanAtV3(grant.SessionID, grant.ConfirmedAt); err != nil {
			return err
		}
		for _, ref := range grant.Terms.Policies {
			version, ok := g.templates[ref.VersionID.String()]
			if !ok || version.PolicyID != ref.PolicyID || version.Version != ref.Version || version.Compiled.Hash != ref.ConfigurationHash || version.Compiled.Name != ref.Template || version.ConfirmedAt.After(grant.ConfirmedAt) {
				return businessInvalid("native grant exact reviewed policy version")
			}
		}
		for _, id := range grant.Terms.AccountIDs {
			if g.row("accounts", id.String()) == nil {
				return businessInvalid("native grant account scope")
			}
		}
		for _, id := range grant.Terms.GoalIDs {
			if g.row("goals", id.String()) == nil {
				return businessInvalid("native grant goal scope")
			}
		}
		g.nativeGrants[grant.ID.String()] = grant
	}
	for _, row := range g.rows["native_grant_state_events"] {
		var event nativeGrantStateV3
		nativeOriginalV3(row, "original", &event)
		grant, ok := g.nativeGrants[event.GrantID.String()]
		if !ok || nativeHashFieldV3(row, "original", "original_hash") != nil || event.Protocol != "native-automation-v1/grant-state" || event.Scope != g.ownerScopeV3() || event.ID.String() != row.text("id") || event.GrantID.String() != row.text("grant_id") || event.GrantVersion != grant.Version || event.GrantVersion != uint64(row.positive("grant_version")) || event.Sequence != uint64(row.positive("sequence")) || event.Action != row.text("action") || event.OldState != nativeStringV3(row, "old_state") || event.NewState != row.text("new_state") || event.SessionID.String() != row.text("session_id") || event.PrincipalKind != "USER" || !event.At.Equal(row.instant("created_at")) {
			return businessInvalid("native grant actual USER lifecycle original")
		}
		if err := g.humanAtV3(event.SessionID, event.At); err != nil {
			return err
		}
		g.nativeGrantEvents[event.GrantID.String()] = append(g.nativeGrantEvents[event.GrantID.String()], event)
	}
	for id, grant := range g.nativeGrants {
		events := g.nativeGrantEvents[id]
		sort.Slice(events, func(i, j int) bool { return events[i].Sequence < events[j].Sequence })
		state := ""
		previous := grant.ConfirmedAt
		for i, event := range events {
			valid := i == 0 && event.Action == "CONFIRM" && event.NewState == "ACTIVE" && event.At.Equal(grant.ConfirmedAt)
			if i > 0 {
				valid = (state == "ACTIVE" && event.Action == "PAUSE" && event.NewState == "PAUSED") || (state == "PAUSED" && event.Action == "RESUME" && event.NewState == "ACTIVE") || ((state == "ACTIVE" || state == "PAUSED") && event.Action == "REVOKE" && event.NewState == "REVOKED")
			}
			if !valid || event.Sequence != uint64(i+1) || event.OldState != state || event.At.Before(previous) {
				return businessInvalid("native complete ordered grant lifecycle")
			}
			state, previous = event.NewState, event.At
		}
		projection := g.row("native_grant_states", id, strconv.FormatUint(grant.Version, 10))
		if len(events) == 0 || projection == nil || projection.text("state") != state || projection.positive("sequence") != int64(len(events)) || projection.text("event_id") != events[len(events)-1].ID.String() || !projection.instant("updated_at").Equal(previous) {
			return businessInvalid("native current grant lifecycle projection")
		}
		g.nativeGrantEvents[id] = events
	}
	if len(g.rows["native_grant_states"]) != len(g.nativeGrants) {
		return businessInvalid("native orphan grant state")
	}
	return g.checkedRowsV3()
}

func (g *nativeGraphV3) grantActiveAtV3(id string, sequence uint64, at time.Time) error {
	grant, ok := g.nativeGrants[id]
	events := g.nativeGrantEvents[id]
	if !ok || sequence == 0 || sequence > uint64(len(events)) || events[sequence-1].NewState != "ACTIVE" || at.Before(events[sequence-1].At) || at.Before(grant.Terms.EffectiveFrom) || !at.Before(grant.Terms.ExpiresAt) {
		return businessInvalid("native grant authority at original decision")
	}
	// Equal business instants do not order distinct committed transactions.
	// The original state sequence disambiguates same-clock pause/recovery.
	if sequence < uint64(len(events)) && events[sequence].At.Before(at) {
		return businessInvalid("native original decision used an already superseded grant state")
	}
	return nil
}
