package app

import (
	"encoding/json"
	"sort"
	"time"

	funds "zhiyu.local/zhiyu-go/internal/funds/domain"
	policy "zhiyu.local/zhiyu-go/internal/policy/domain"
)

const (
	agentNativeGrantMaxCount       = 100
	agentNativeGrantMaxEvents      = 256
	agentNativeGrantMaxTotalEvents = 4096
	agentNativeGrantMaxSubjects    = 4296
	agentNativeGrantOriginalBudget = 8 * 1024 * 1024
	agentNativeGrantPreviewBudget  = 4 * 1024 * 1024
	agentNativeGrantEventBudget    = 8 * 1024 * 1024
	agentNativeGrantSubjectBudget  = 512 * 1024
)

// These private rows contain source bytes only while the same RR read is being
// validated. Neither these types nor historical session IDs enter Agent DTOs.
type agentNativeGrantRow struct {
	ID, PreviewID, SessionID              funds.ID
	Version                               uint64
	Family                                policy.NativeFamily
	Original, Request                     []byte
	OriginalHash, RequestHash             string
	EffectiveFrom, ExpiresAt, ConfirmedAt time.Time
}

type agentNativeGrantPreviewRow struct {
	ID, SessionID              funds.ID
	Original                   []byte
	OriginalHash, ReviewedHash string
	CreatedAt, ExpiresAt       time.Time
}

type agentNativeGrantProjection struct {
	GrantID                funds.ID
	GrantVersion, Sequence uint64
	State                  string
	EventID                funds.ID
	UpdatedAt              time.Time
}

type agentNativeGrantEventRow struct {
	ID, GrantID, SessionID     funds.ID
	GrantVersion, Sequence     uint64
	Action, OldState, NewState string
	Original                   []byte
	OriginalHash               string
	CreatedAt                  time.Time
}

type agentNativeGrantSubject struct {
	ID        funds.ID
	Scope     policy.TemplateOwnerScope
	ExpiresAt time.Time
	Revoked   bool
}

type agentNativeGrantRawBundle struct {
	Scope                         policy.TemplateOwnerScope
	AsOf                          time.Time
	Grant                         agentNativeGrantRow
	Preview                       agentNativeGrantPreviewRow
	Projection                    agentNativeGrantProjection
	Events                        []agentNativeGrantEventRow
	Subjects                      map[funds.ID]agentNativeGrantSubject
	HistoricalVersions            map[funds.ID]TemplatePolicyView
	CurrentViews                  []TemplatePolicyView
	OwnedAccountIDs, OwnedGoalIDs map[funds.ID]bool
}

type agentNativeGrantVerified struct {
	View                                                    NativeStandingGrantView
	OriginalDigest, TermsDigest, ChainDigest                string
	EffectiveState, EvaluatedLocalDate, SessionVerification string
	ReasonCodes                                             []string
}

// This second in-memory check does not replace the reader's length/sum checks
// before fetching bytea. It rejects oversized or inconsistent package inputs.
func validateAgentNativeGrantRawBudgets(bundles []agentNativeGrantRawBundle) error {
	if len(bundles) > agentNativeGrantMaxCount {
		return reject("NATIVE_GRANT_CAPACITY", nil)
	}
	var grantBytes, previewBytes, eventBytes, events int
	subjects := map[funds.ID]agentNativeGrantSubject{}
	previews := map[funds.ID]string{}
	grants := map[funds.ID]bool{}
	eventIDs := map[funds.ID]bool{}
	for _, b := range bundles {
		if grants[b.Grant.ID] || b.Grant.ID == (funds.ID{}) {
			return reject("EVIDENCE_INVALID", nil)
		}
		grants[b.Grant.ID] = true
		if len(b.Grant.Original) == 0 || len(b.Grant.Original) > 524288 || len(b.Grant.Request) == 0 || len(b.Grant.Request) > 4096 || len(b.Preview.Original) == 0 || len(b.Preview.Original) > 262144 || len(b.Events) == 0 || len(b.Events) > agentNativeGrantMaxEvents || len(b.HistoricalVersions) > 1600 || len(b.CurrentViews) > 100 || len(b.Subjects) > agentNativeGrantMaxSubjects || len(b.OwnedAccountIDs) > 100 || len(b.OwnedGoalIDs) > 100 {
			return reject("NATIVE_GRANT_CAPACITY", nil)
		}
		grantBytes += len(b.Grant.Original)
		if prior, seen := previews[b.Preview.ID]; seen {
			if prior != Hash(b.Preview.Original) {
				return reject("EVIDENCE_INVALID", nil)
			}
		} else {
			previews[b.Preview.ID] = Hash(b.Preview.Original)
			previewBytes += len(b.Preview.Original)
		}
		for _, e := range b.Events {
			if len(e.Original) == 0 || len(e.Original) > 8192 {
				return reject("NATIVE_GRANT_CAPACITY", nil)
			}
			if e.ID == (funds.ID{}) || eventIDs[e.ID] || e.GrantID != b.Grant.ID || e.GrantVersion != b.Grant.Version {
				return reject("EVIDENCE_INVALID", nil)
			}
			eventIDs[e.ID] = true
			eventBytes += len(e.Original)
		}
		events += len(b.Events)
		for id, subject := range b.Subjects {
			if id == (funds.ID{}) || subject.ID != id || subject.Scope != b.Scope || subject.ExpiresAt.IsZero() {
				return reject("EVIDENCE_INVALID", nil)
			}
			if old, exists := subjects[id]; exists && old != subject {
				return reject("EVIDENCE_INVALID", nil)
			}
			subjects[id] = subject
		}
		if grantBytes > agentNativeGrantOriginalBudget || previewBytes > agentNativeGrantPreviewBudget || eventBytes > agentNativeGrantEventBudget || events > agentNativeGrantMaxTotalEvents || len(subjects) > agentNativeGrantMaxSubjects {
			return reject("NATIVE_GRANT_CAPACITY", nil)
		}
	}
	subjectIDs := make([]funds.ID, 0, len(subjects))
	for id := range subjects {
		subjectIDs = append(subjectIDs, id)
	}
	sort.Slice(subjectIDs, func(i, j int) bool { return subjectIDs[i].String() < subjectIDs[j].String() })
	metadataRows := make([]agentNativeGrantSubject, 0, len(subjectIDs))
	for _, id := range subjectIDs {
		metadataRows = append(metadataRows, subjects[id])
	}
	metadata, err := json.Marshal(metadataRows)
	if err != nil || len(metadata) > agentNativeGrantSubjectBudget {
		return reject("NATIVE_GRANT_CAPACITY", nil)
	}
	return nil
}

func agentNativeGrantSameOptionalID(a, b *funds.ID) bool {
	return a == nil && b == nil || a != nil && b != nil && *a == *b
}

func agentNativeGrantPolicyBinding(v TemplatePolicyView) any {
	return struct {
		Version            policy.TemplateVersion
		GoalID             *funds.ID
		Timezone           string
		ConfirmationID     funds.ID
		ReviewedBundleHash string
		StatusSequence     uint64
	}{v.Version, v.GoalID, v.Timezone, v.ConfirmationID, v.ReviewedBundleHash, v.StatusSequence}
}

func validateAgentNativeGrantPolicy(v TemplatePolicyView, scope policy.TemplateOwnerScope) error {
	p := v.Version
	if p.Scope != scope || p.PolicyID == (funds.ID{}) || p.VersionID == (funds.ID{}) || p.Version == 0 || !p.ConfirmationVerified || p.ConfirmedConfigurationHash != p.Compiled.Hash || p.ConfirmedAt.IsZero() || v.ConfirmationID == (funds.ID{}) || v.StatusSequence == 0 || v.BankAuthority || !agentNativeGrantHash(v.ReviewedBundleHash) {
		return reject("EVIDENCE_INVALID", nil)
	}
	if _, err := p.Compiled.Decode(); err != nil {
		return reject("EVIDENCE_INVALID", nil)
	}
	if _, err := policy.TemplateLocation(v.Timezone); err != nil {
		return reject("EVIDENCE_INVALID", nil)
	}
	switch p.State {
	case "ACTIVE", "CONFIRMED", "SUSPENDED", "EXPIRED", "REVOKED":
	default:
		return reject("EVIDENCE_INVALID", nil)
	}
	return nil
}

func agentNativeGrantHash(value string) bool {
	if len(value) != 64 {
		return false
	}
	for _, c := range value {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}

// Asset/recovery goal bindings live in the typed compiled configuration,
// whereas the template policy row's goal_id is used by long-term goals.
func agentNativeGrantPolicyGoal(v TemplatePolicyView) (*funds.ID, error) {
	configuration, err := v.Version.Compiled.Decode()
	if err != nil {
		return nil, reject("EVIDENCE_INVALID", nil)
	}
	goal := v.GoalID
	switch config := configuration.(type) {
	case *policy.AssetAuthorizationConfig:
		goal = config.GoalID
	case *policy.RecoveryConfig:
		goal = config.GoalID
	}
	if v.GoalID != nil && !agentNativeGrantSameOptionalID(v.GoalID, goal) {
		return nil, reject("EVIDENCE_INVALID", nil)
	}
	return goal, nil
}

func validateAgentNativeGrantBundle(b agentNativeGrantRawBundle) (agentNativeGrantVerified, error) {
	var out agentNativeGrantVerified
	invalid := func() (agentNativeGrantVerified, error) {
		return agentNativeGrantVerified{}, reject("EVIDENCE_INVALID", nil)
	}
	if err := validateAgentNativeGrantRawBudgets([]agentNativeGrantRawBundle{b}); err != nil {
		return out, err
	}
	if b.Scope.EnvironmentID == (funds.ID{}) || b.Scope.UserID == (funds.ID{}) || b.AsOf.IsZero() {
		return invalid()
	}
	var grant NativeStandingGrant
	var preview NativeStandingGrantPreview
	var command NativeStandingGrantConfirmation
	if Hash(b.Grant.Original) != b.Grant.OriginalHash || Hash(b.Grant.Request) != b.Grant.RequestHash || Hash(b.Preview.Original) != b.Preview.OriginalHash || auditJSON(b.Grant.Original, &grant) != nil || auditJSON(b.Grant.Request, &command) != nil || auditJSON(b.Preview.Original, &preview) != nil {
		return invalid()
	}
	if grant.Protocol != NativeAutomationProtocol+"/grant" || grant.ID != b.Grant.ID || grant.Version != 1 || grant.Version != b.Grant.Version || grant.Scope != b.Scope || grant.Terms.Scope != b.Scope || grant.ReviewedTerms.Scope != b.Scope || grant.Terms.Validate() != nil || grant.ReviewedTerms.Validate() != nil || grant.PrincipalKind != "USER" || grant.SessionID == (funds.ID{}) || grant.SessionID != b.Grant.SessionID || grant.PreviewID == (funds.ID{}) || grant.PreviewID != b.Grant.PreviewID || grant.Terms.Family != b.Grant.Family || !grant.ConfirmedAt.Equal(b.Grant.ConfirmedAt) || !grant.ConfirmedAt.Equal(grant.Terms.EffectiveFrom) || !grant.Terms.ExpiresAt.Equal(b.Grant.ExpiresAt) {
		return invalid()
	}
	if !grant.Terms.EffectiveFrom.Equal(b.Grant.EffectiveFrom) {
		return invalid()
	}
	if preview.Protocol != NativeAutomationProtocol+"/grant-preview" || preview.ID != grant.PreviewID || preview.ID != b.Preview.ID || preview.Scope != b.Scope || preview.Terms.Scope != b.Scope || preview.Terms.Validate() != nil || preview.SessionID != grant.SessionID || preview.SessionID != b.Preview.SessionID || !preview.CreatedAt.Equal(b.Preview.CreatedAt) || !preview.ExpiresAt.Equal(b.Preview.ExpiresAt) || !preview.ExpiresAt.After(preview.CreatedAt) || preview.ExpiresAt.After(preview.CreatedAt.Add(2*time.Minute)) || preview.ReviewedHash != b.Preview.ReviewedHash || grant.ReviewedHash != preview.ReviewedHash || command.PreviewID != preview.ID || command.ReviewedHash != preview.ReviewedHash || grant.ConfirmedAt.Before(preview.CreatedAt) || !grant.ConfirmedAt.Before(preview.ExpiresAt) || preview.Terms.EffectiveFrom.After(grant.ConfirmedAt) {
		return invalid()
	}
	want, err := NativeStandingGrantReviewHash(preview)
	if err != nil || want != preview.ReviewedHash {
		return invalid()
	}
	final := grant.Terms
	final.EffectiveFrom = grant.ReviewedTerms.EffectiveFrom
	a, e1 := final.Digest()
	c, e2 := grant.ReviewedTerms.Digest()
	d, e3 := preview.Terms.Digest()
	if e1 != nil || e2 != nil || e3 != nil || a == "" || a != c || c != d {
		return invalid()
	}
	termsDigest, err := grant.Terms.Digest()
	if err != nil {
		return invalid()
	}
	for _, id := range grant.Terms.AccountIDs {
		if !b.OwnedAccountIDs[id] {
			return invalid()
		}
	}
	for _, id := range grant.Terms.GoalIDs {
		if !b.OwnedGoalIDs[id] {
			return invalid()
		}
	}

	usedSubjects := map[funds.ID]agentNativeGrantSubject{}
	revocationUnknown := false
	subjectAt := func(id funds.ID, at time.Time) error {
		subject, ok := b.Subjects[id]
		if !ok || id == (funds.ID{}) || subject.ID != id || subject.Scope != b.Scope || subject.ExpiresAt.IsZero() {
			return reject("SUBJECT_UNAVAILABLE", nil)
		}
		if at.IsZero() || !at.Before(subject.ExpiresAt) {
			return reject("SESSION_EXPIRED_AT_EVENT", nil)
		}
		usedSubjects[id] = subject
		revocationUnknown = revocationUnknown || subject.Revoked
		return nil
	}
	if err = subjectAt(preview.SessionID, preview.CreatedAt); err != nil {
		return out, err
	}
	if err = subjectAt(grant.SessionID, grant.ConfirmedAt); err != nil {
		return out, err
	}

	// Validate a copied ordering; never mutate a reader/caller's slice aliases.
	events := append([]agentNativeGrantEventRow(nil), b.Events...)
	sort.Slice(events, func(i, j int) bool { return events[i].Sequence < events[j].Sequence })
	state := ""
	previous := grant.ConfirmedAt
	seenEvent := map[funds.ID]bool{}
	chain := []struct {
		ID           funds.ID
		Sequence     uint64
		OriginalHash string
	}{}
	for i, row := range events {
		var event nativeGrantStateOriginal
		if Hash(row.Original) != row.OriginalHash || auditJSON(row.Original, &event) != nil || event.ID == (funds.ID{}) || seenEvent[event.ID] || event.Protocol != NativeAutomationProtocol+"/grant-state" || event.Scope != b.Scope || event.ID != row.ID || event.GrantID != grant.ID || event.GrantID != row.GrantID || event.GrantVersion != grant.Version || event.GrantVersion != row.GrantVersion || event.Sequence != row.Sequence || event.Sequence != uint64(i+1) || event.Action != row.Action || event.OldState != row.OldState || event.NewState != row.NewState || event.SessionID != row.SessionID || event.PrincipalKind != "USER" || !event.At.Equal(row.CreatedAt) || event.At.Before(previous) || event.At.After(b.AsOf) || event.OldState != state {
			return invalid()
		}
		valid := i == 0 && event.Action == "CONFIRM" && event.OldState == "" && event.NewState == "ACTIVE" && event.At.Equal(grant.ConfirmedAt) && event.SessionID == grant.SessionID
		if i > 0 {
			valid = state == "ACTIVE" && event.Action == "PAUSE" && event.NewState == "PAUSED" || state == "PAUSED" && event.Action == "RESUME" && event.NewState == "ACTIVE" || (state == "ACTIVE" || state == "PAUSED") && event.Action == "REVOKE" && event.NewState == "REVOKED"
		}
		if !valid {
			return invalid()
		}
		if err = subjectAt(event.SessionID, event.At); err != nil {
			return out, err
		}
		seenEvent[event.ID] = true
		chain = append(chain, struct {
			ID           funds.ID
			Sequence     uint64
			OriginalHash string
		}{event.ID, event.Sequence, row.OriginalHash})
		state, previous = event.NewState, event.At
	}
	last := events[len(events)-1]
	projection := b.Projection
	if projection.GrantID != grant.ID || projection.GrantVersion != grant.Version || projection.State != state || projection.Sequence != uint64(len(events)) || projection.EventID != last.ID || !projection.UpdatedAt.Equal(previous) {
		return invalid()
	}

	history := []any{}
	current := []any{}
	changed, unavailable := false, false
	currentByPolicy := map[funds.ID]TemplatePolicyView{}
	for _, v := range b.CurrentViews {
		if !v.Version.Current {
			return invalid()
		}
		if err := validateAgentNativeGrantPolicy(v, b.Scope); err != nil {
			return invalid()
		}
		if _, duplicate := currentByPolicy[v.Version.PolicyID]; duplicate {
			return invalid()
		}
		currentByPolicy[v.Version.PolicyID] = v
	}
	for _, ref := range grant.Terms.Policies {
		v, ok := b.HistoricalVersions[ref.VersionID]
		if !ok {
			return invalid()
		}
		if err := validateAgentNativeGrantPolicy(v, b.Scope); err != nil {
			return invalid()
		}
		p := v.Version
		goal, err := agentNativeGrantPolicyGoal(v)
		if err != nil {
			return invalid()
		}
		if p.PolicyID != ref.PolicyID || p.VersionID != ref.VersionID || p.Version != ref.Version || p.Compiled.Name != ref.Template || p.Compiled.Hash != ref.ConfigurationHash || !agentNativeGrantSameOptionalID(goal, ref.GoalID) || p.ConfirmedAt.After(grant.ConfirmedAt) || ref.GoalID != nil && !b.OwnedGoalIDs[*ref.GoalID] {
			return invalid()
		}
		history = append(history, agentNativeGrantPolicyBinding(v))
		changed = changed || !p.Current
		live, ok := currentByPolicy[ref.PolicyID]
		if !ok {
			unavailable = true
			continue
		}
		if err := validateAgentNativeGrantPolicy(live, b.Scope); err != nil {
			return invalid()
		}
		liveGoal, err := agentNativeGrantPolicyGoal(live)
		if err != nil {
			return invalid()
		}
		effective, err := live.Version.EffectiveState(b.AsOf, live.Timezone)
		if err != nil {
			return invalid()
		}
		current = append(current, struct {
			Binding        any
			EffectiveState string
		}{agentNativeGrantPolicyBinding(live), effective})
		if live.Version.VersionID != ref.VersionID || live.Version.Version != ref.Version || live.Version.Compiled.Hash != ref.ConfigurationHash || live.Version.Compiled.Name != ref.Template || !agentNativeGrantSameOptionalID(liveGoal, ref.GoalID) || effective != "ACTIVE" {
			changed = true
		}
	}

	subjectIDs := make([]funds.ID, 0, len(usedSubjects))
	for id := range usedSubjects {
		subjectIDs = append(subjectIDs, id)
	}
	sort.Slice(subjectIDs, func(i, j int) bool { return subjectIDs[i].String() < subjectIDs[j].String() })
	subjects := make([]agentNativeGrantSubject, 0, len(subjectIDs))
	for _, id := range subjectIDs {
		subjects = append(subjects, usedSubjects[id])
	}
	chainRaw, err := encode(struct {
		Protocol                            string
		GrantHash, PreviewHash, RequestHash string
		Projection                          agentNativeGrantProjection
		Events                              any
		Subjects                            []agentNativeGrantSubject
		HistoricalPolicies, CurrentPolicies []any
	}{"agent-native-grant-chain-v1", b.Grant.OriginalHash, b.Preview.OriginalHash, b.Grant.RequestHash, projection, chain, subjects, history, current})
	if err != nil {
		return invalid()
	}
	out = agentNativeGrantVerified{View: NativeStandingGrantView{Grant: grant, State: state, StateSequence: projection.Sequence, StateAt: projection.UpdatedAt}, OriginalDigest: b.Grant.OriginalHash, TermsDigest: termsDigest, ChainDigest: Hash(chainRaw), EffectiveState: "CURRENT_DISPLAY_ONLY", SessionVerification: "SCOPED_SUBJECT_AND_EVENT_EXPIRY_ONLY", ReasonCodes: []string{}}
	zone, _ := policy.TemplateLocation(grant.Terms.Timezone)
	out.EvaluatedLocalDate = b.AsOf.In(zone).Format("2006-01-02")
	if changed {
		out.ReasonCodes = append(out.ReasonCodes, "POLICY_CHANGED")
	}
	if unavailable {
		out.ReasonCodes = append(out.ReasonCodes, "POLICY_UNAVAILABLE")
	}
	if revocationUnknown {
		out.ReasonCodes = append(out.ReasonCodes, "SESSION_REVOCATION_HISTORY_UNAVAILABLE")
		out.SessionVerification = "HISTORY_INCOMPLETE"
	}
	if b.AsOf.Before(grant.Terms.EffectiveFrom) {
		out.ReasonCodes = append(out.ReasonCodes, "NOT_YET_EFFECTIVE")
	}
	if !b.AsOf.Before(grant.Terms.ExpiresAt) {
		out.ReasonCodes = append(out.ReasonCodes, "EXPIRED")
	}
	if state == "PAUSED" || state == "REVOKED" {
		out.ReasonCodes = append(out.ReasonCodes, state)
	}
	switch {
	case state == "REVOKED":
		out.EffectiveState = "REVOKED"
	case !b.AsOf.Before(grant.Terms.ExpiresAt):
		out.EffectiveState = "EXPIRED"
	case state == "PAUSED":
		out.EffectiveState = "PAUSED"
	case b.AsOf.Before(grant.Terms.EffectiveFrom):
		out.EffectiveState = "NOT_YET_EFFECTIVE"
	case changed:
		out.EffectiveState = "POLICY_CHANGED"
	case unavailable || revocationUnknown:
		out.EffectiveState = "UNAVAILABLE"
	}
	sort.Strings(out.ReasonCodes)
	return out, nil
}
