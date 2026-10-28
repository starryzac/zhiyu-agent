package app

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"zhiyu.local/zhiyu-go/internal/execution/fundswitness"
	funds "zhiyu.local/zhiyu-go/internal/funds/domain"
	planning "zhiyu.local/zhiyu-go/internal/planning/domain"
	policy "zhiyu.local/zhiyu-go/internal/policy/domain"
)

type TemplatePolicyRequest struct {
	Name          policy.TemplateName `json:"template_name"`
	Configuration json.RawMessage     `json:"configuration"`
	PolicyID      *funds.ID           `json:"policy_id,omitempty"`
	GoalID        *funds.ID           `json:"goal_id,omitempty"`
	Timezone      string              `json:"timezone"`
}
type TemplatePolicyConfirmation struct {
	PreviewID          funds.ID `json:"preview_id"`
	ReviewedBundleHash string   `json:"reviewed_bundle_hash"`
}
type TemplateGoalTargetMutation struct {
	GoalID funds.ID    `json:"goal_id"`
	Before funds.Money `json:"before_cents"`
	After  funds.Money `json:"after_cents"`
}
type TemplatePolicyPreview struct {
	ID                    funds.ID                    `json:"id"`
	PolicyID              funds.ID                    `json:"policy_id"`
	VersionID             funds.ID                    `json:"version_id"`
	BaseVersion           uint64                      `json:"base_version"`
	Mode                  string                      `json:"mode"`
	Scope                 policy.TemplateOwnerScope   `json:"scope"`
	GoalID                *funds.ID                   `json:"goal_id,omitempty"`
	TargetMutation        *TemplateGoalTargetMutation `json:"target_mutation,omitempty"`
	Timezone              string                      `json:"timezone"`
	Compiled              policy.CompiledTemplate     `json:"compiled"`
	FactsHash             string                      `json:"facts_hash"`
	SourceHash            string                      `json:"source_hash"`
	SourceWitnessID       *funds.ID                   `json:"source_witness_id,omitempty"`
	SourceWitnessHash     string                      `json:"source_witness_hash,omitempty"`
	SnapshotFundsVersion  uint64                      `json:"snapshot_funds_version,omitempty"`
	SnapshotSourceVersion uint64                      `json:"snapshot_source_version,omitempty"`
	Facts                 policy.TemplateFacts        `json:"facts"`
	Preview               policy.TemplatePreview      `json:"preview"`
	ForecastInput         *planning.ForecastInput     `json:"forecast_input,omitempty"`
	Forecast              planning.ForecastResult     `json:"forecast"`
	ReviewedBundleHash    string                      `json:"reviewed_bundle_hash"`
	CreatedAt             time.Time                   `json:"created_at"`
	ExpiresAt             time.Time                   `json:"expires_at"`
	Authority             string                      `json:"authority"`
	BankAuthority         bool                        `json:"bank_authority"`
}
type TemplatePolicyView struct {
	Version            policy.TemplateVersion `json:"version"`
	GoalID             *funds.ID              `json:"goal_id,omitempty"`
	Timezone           string                 `json:"timezone"`
	EffectiveState     string                 `json:"effective_state"`
	ConfirmationID     funds.ID               `json:"confirmation_id"`
	ReviewedBundleHash string                 `json:"reviewed_bundle_hash"`
	StatusSequence     uint64                 `json:"status_sequence"`
	BankAuthority      bool                   `json:"bank_authority"`
}
type templateConfirmationOriginal struct {
	Protocol                                             string `json:"protocol"`
	ID, PolicyID, VersionID, PreviewID, SessionID        funds.ID
	Scope                                                policy.TemplateOwnerScope
	PrincipalKind, ReviewedBundleHash, ConfigurationHash string
	ConfirmedAt                                          time.Time
	TargetMutation                                       *TemplateGoalTargetMutation `json:"target_mutation,omitempty"`
	DatedReferences                                      *datedConfirmationWitnessV1 `json:"dated_references,omitempty"`
}
type templateStatusOriginal struct {
	Protocol                              string
	ID, VersionID                         funds.ID
	Sequence                              uint64
	Action, OldState, NewState, ActorKind string
	SessionID                             *funds.ID
	At                                    time.Time
	Admission                             *fundswitness.Boundary `json:"admission,omitempty"`
}

type templateQuery interface {
	queryRow
	Query(context.Context, string, ...any) (pgx.Rows, error)
}

// A native goal rule does not silently inherit a former per-event standing
// grant. New execution must use an explicitly reviewed native/dual-hash route.
// Existing signed/known bank operations are recovered by their original path.
func ensureLegacyGoalUnbound(ctx context.Context, q queryRow, p Principal, goal funds.ID) error {
	var present bool
	if err := q.QueryRow(ctx, `SELECT to_regclass('template_policies') IS NOT NULL`).Scan(&present); err != nil {
		return err
	}
	if !present {
		return nil
	}
	var bound bool
	if err := q.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM template_policies WHERE environment_id=$1 AND user_id=$2 AND goal_id=$3)`, p.EnvironmentID.String(), p.UserID.String(), goal.String()).Scan(&bound); err != nil {
		return err
	}
	if bound {
		return reject("NATIVE_GOAL_AUTHORIZATION_REQUIRED", nil)
	}
	return nil
}

func (s *Service) loadTemplatePolicies(ctx context.Context, q templateQuery, p Principal) ([]TemplatePolicyView, error) {
	return s.loadTemplatePoliciesAt(ctx, q, p, nil)
}

func (s *Service) loadTemplatePoliciesAt(ctx context.Context, q templateQuery, p Principal, versionID *funds.ID) ([]TemplatePolicyView, error) {
	rows, err := q.Query(ctx, `SELECT v.original,v.original_hash::text,v.policy_id::text,v.id::text,v.version,v.state,v.timezone,v.configuration,v.configuration_hash::text,v.confirmed_at,v.confirmation_id::text,c.original,c.original_hash::text,c.reviewed_bundle_hash::text,t.goal_id::text,v.status_sequence,e.original,e.original_hash::text,v.version=t.current_version,t.template_name FROM template_policies t JOIN template_policy_versions v ON(v.environment_id=t.environment_id AND v.user_id=t.user_id AND v.policy_id=t.id AND (($3::uuid IS NULL AND v.version=t.current_version) OR v.id=$3::uuid)) JOIN template_policy_confirmations c ON(c.environment_id=v.environment_id AND c.user_id=v.user_id AND c.id=v.confirmation_id) JOIN template_policy_status_events e ON(e.environment_id=v.environment_id AND e.user_id=v.user_id AND e.id=v.status_event_id) WHERE t.environment_id=$1 AND t.user_id=$2 ORDER BY t.id LIMIT 101`, p.EnvironmentID.String(), p.UserID.String(), templateIDArgument(versionID))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	views := []TemplatePolicyView{}
	for rows.Next() {
		if len(views) >= 100 {
			return nil, reject("TEMPLATE_CAPACITY_EXCEEDED", nil)
		}
		var view TemplatePolicyView
		var raw, configuration, confirmation, event []byte
		var hash, pid, vid, state, configHash, cid, cHash, eHash, name string
		var current bool
		var goal *string
		var version uint64
		var confirmedAt time.Time
		if err = rows.Scan(&raw, &hash, &pid, &vid, &version, &state, &view.Timezone, &configuration, &configHash, &confirmedAt, &cid, &confirmation, &cHash, &view.ReviewedBundleHash, &goal, &view.StatusSequence, &event, &eHash, &current, &name); err != nil {
			return nil, err
		}
		if Hash(raw) != hash || Hash(confirmation) != cHash || Hash(event) != eHash || auditJSON(raw, &view.Version) != nil {
			return nil, reject("TEMPLATE_FACTS_INVALID", nil)
		}
		v := &view.Version
		if v.PolicyID.String() != pid || v.VersionID.String() != vid || v.Version != version || string(v.Compiled.Name) != name || v.Scope != (policy.TemplateOwnerScope{EnvironmentID: p.EnvironmentID, UserID: p.UserID}) || !v.Current || !v.ConfirmationVerified || v.ConfirmedConfigurationHash != configHash || v.Compiled.Hash != configHash || !bytes.Equal(v.Compiled.Configuration, configuration) || !v.ConfirmedAt.Equal(confirmedAt) {
			return nil, reject("TEMPLATE_FACTS_INVALID", nil)
		}
		if _, err = v.Compiled.Decode(); err != nil {
			return nil, reject("TEMPLATE_FACTS_INVALID", err)
		}
		var c templateConfirmationOriginal
		var e templateStatusOriginal
		if auditJSON(confirmation, &c) != nil || auditJSON(event, &e) != nil || c.Protocol != "template-user-confirmation-v1" || c.PolicyID != v.PolicyID || c.VersionID != v.VersionID || c.Scope != v.Scope || c.ConfigurationHash != configHash || c.ReviewedBundleHash != view.ReviewedBundleHash || c.PrincipalKind != "USER" || !c.ConfirmedAt.Equal(confirmedAt) || c.ID.String() != cid || e.Protocol != "template-lifecycle-v1" || e.VersionID != v.VersionID || e.Sequence != view.StatusSequence || e.NewState != state {
			return nil, reject("TEMPLATE_FACTS_INVALID", nil)
		}
		view.ConfirmationID = c.ID
		if goal != nil {
			id, e := funds.ParseID(*goal)
			if e != nil {
				return nil, e
			}
			view.GoalID = &id
		}
		v.State = state
		v.Current = current
		if !current {
			view.EffectiveState = "SUPERSEDED"
		} else {
			view.EffectiveState, err = v.EffectiveState(s.now(), view.Timezone)
			if err != nil {
				return nil, reject("TEMPLATE_FACTS_INVALID", err)
			}
		}
		views = append(views, view)
	}
	return views, rows.Err()
}

func (s *Service) TemplatePolicyVersion(ctx context.Context, p Principal, id funds.ID) (TemplatePolicyView, error) {
	if err := s.auditHuman(ctx, p); err != nil {
		return TemplatePolicyView{}, err
	}
	views, err := s.loadTemplatePoliciesAt(ctx, s.Pool, p, &id)
	if err != nil {
		return TemplatePolicyView{}, err
	}
	if len(views) != 1 {
		return TemplatePolicyView{}, reject("NOT_FOUND", nil)
	}
	return views[0], nil
}

func (s *Service) TemplatePolicies(ctx context.Context, p Principal) ([]TemplatePolicyView, error) {
	if err := s.auditHuman(ctx, p); err != nil {
		return nil, err
	}
	return s.loadTemplatePolicies(ctx, s.Pool, p)
}
func (s *Service) TemplatePolicy(ctx context.Context, p Principal, id funds.ID) (TemplatePolicyView, error) {
	views, err := s.TemplatePolicies(ctx, p)
	if err != nil {
		return TemplatePolicyView{}, err
	}
	for _, view := range views {
		if view.Version.PolicyID == id {
			return view, nil
		}
	}
	return TemplatePolicyView{}, reject("NOT_FOUND", nil)
}

func templatePreviewHash(view TemplatePolicyPreview) (string, error) {
	view.ReviewedBundleHash = ""
	raw, err := encode(view)
	if err != nil {
		return "", err
	}
	return Hash(raw), nil
}

func (s *Service) PreviewTemplatePolicy(ctx context.Context, p Principal, in TemplatePolicyRequest) (TemplatePolicyPreview, error) {
	var view TemplatePolicyPreview
	if err := s.auditHuman(ctx, p); err != nil {
		return view, err
	}
	compiled, err := policy.CompileTemplate(in.Name, in.Configuration)
	if err != nil {
		return view, reject("INVALID_TEMPLATE_CONFIGURATION", err)
	}
	if (in.Name == policy.LongTermGoalTemplate) != (in.GoalID != nil) {
		return view, reject("TEMPLATE_GOAL_BINDING_REQUIRED", nil)
	}
	now := s.now()
	tx, err := s.Pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	if err != nil {
		return view, err
	}
	defer rollback(ctx, tx)
	zone, err := templateScopedTimezone(ctx, tx, p, in.Timezone)
	if err != nil {
		return view, err
	}
	snapshot, err := s.loadTemplateSnapshot(ctx, tx, p, now, zone)
	if err != nil {
		return view, err
	}
	view = TemplatePolicyPreview{Mode: "IF_USER_CONFIRMED", Scope: snapshot.Facts.Scope, GoalID: in.GoalID, Timezone: zone, Compiled: compiled, SourceHash: snapshot.Facts.SourceHash, CreatedAt: now, ExpiresAt: now.Add(2 * time.Minute), Authority: "POLICY_CONFIGURATION_ONLY_NO_BANK_GRANT"}
	view.ID, err = newID()
	if err != nil {
		return view, err
	}
	view.VersionID, err = newID()
	if err != nil {
		return view, err
	}
	if in.PolicyID != nil {
		found := false
		for _, existing := range snapshot.Views {
			if existing.Version.PolicyID == *in.PolicyID {
				if existing.Version.Compiled.Name != in.Name || !auditSameID(existing.GoalID, in.GoalID) {
					return view, reject("TEMPLATE_IDENTITY_CONFLICT", nil)
				}
				view.PolicyID = *in.PolicyID
				view.BaseVersion = existing.Version.Version
				found = true
			}
		}
		if !found {
			return view, reject("NOT_FOUND", nil)
		}
	} else {
		view.PolicyID, err = newID()
		if err != nil {
			return view, err
		}
		if in.GoalID != nil {
			for _, existing := range snapshot.Views {
				if auditSameID(existing.GoalID, in.GoalID) {
					return view, reject("TEMPLATE_GOAL_ALREADY_BOUND", nil)
				}
			}
		}
	}
	// These flags belong only to a clearly marked counterfactual invocation.
	// No such version/confirmation/authority is persisted by a preview.
	var protectedBefore *planning.ForecastInput
	protectedIDs, err := datedRequiredReferences(compiled)
	if err != nil {
		return view, reject("INVALID_TEMPLATE_CONFIGURATION", err)
	}
	if len(protectedIDs) != 0 {
		input, e := planning.CloneForecastInput(snapshot.forecastInput(365))
		if e != nil {
			return view, reject("TEMPLATE_PROTECTED_REFERENCE_INCOMPLETE", e)
		}
		protectedBefore = &input
	}
	proposed := policy.TemplateVersion{PolicyID: view.PolicyID, VersionID: view.VersionID, Version: view.BaseVersion + 1, Scope: view.Scope, Compiled: compiled, State: "ACTIVE", ConfirmedAt: now, Current: true, ConfirmationVerified: true, ConfirmedConfigurationHash: compiled.Hash}
	versions := []policy.TemplateVersion{}
	for _, v := range snapshot.Versions {
		if v.PolicyID != proposed.PolicyID {
			versions = append(versions, v)
		}
	}
	snapshot.Versions = append(versions, proposed)
	templateSortedVersions(snapshot.Versions)
	if in.GoalID != nil {
		config, e := compiled.Decode()
		if e != nil {
			return view, reject("INVALID_TEMPLATE_CONFIGURATION", e)
		}
		goalConfig, ok := config.(*policy.LongTermGoalConfig)
		if !ok {
			return view, reject("TEMPLATE_GOAL_BINDING_REQUIRED", nil)
		}
		for _, raw := range snapshot.Raw["goals"] {
			var row struct {
				ID       funds.ID `json:"id"`
				Target   int64    `json:"target_cents"`
				Assigned int64    `json:"assigned_cents"`
			}
			if json.Unmarshal([]byte(raw), &row) != nil {
				return view, reject("TEMPLATE_FACTS_INVALID", nil)
			}
			if row.ID != *in.GoalID {
				continue
			}
			if goalConfig.Target.Cents() < row.Assigned {
				return view, reject("GOAL_TARGET_BELOW_OWNED", nil)
			}
			if row.Target != goalConfig.Target.Cents() {
				before, e := templateMoney(row.Target)
				if e != nil {
					return view, e
				}
				view.TargetMutation = &TemplateGoalTargetMutation{GoalID: row.ID, Before: before, After: goalConfig.Target}
			}
		}
		found := false
		for i := range snapshot.Facts.Goals {
			goal := &snapshot.Facts.Goals[i]
			if goal.ID == *in.GoalID {
				goal.PolicyID = proposed.PolicyID
				goal.VersionID = proposed.VersionID
				version := proposed
				goal.GoalVersion = &version
				found = true
			}
		}
		if !found {
			return view, reject("NOT_FOUND", nil)
		}
	}
	if snapshot.SourceWitnessEnabled {
		input := snapshot.forecastInput(365)
		view.ForecastInput = &input
	}
	forecast, err := forecastTemplateSnapshot(snapshot, 365)
	if err != nil {
		return view, err
	}
	snapshot.Facts.CurrentSafe = forecast.Result.CurrentSafe
	snapshot.Facts.CurrentSafeVerified = true
	view.Facts = snapshot.Facts
	view.Forecast = forecast.Result
	if protectedBefore != nil {
		after := snapshot.forecastInput(365)
		after.Facts.CurrentSafe, after.Facts.CurrentSafeVerified = funds.Money{}, false
		view.Facts.ProtectedReferences, err = planning.CompareProtectedPolicyReferencesV1(*protectedBefore, after, proposed.PolicyID, protectedIDs)
		if err != nil {
			return view, reject("TEMPLATE_PROTECTED_REFERENCE_INCOMPLETE", err)
		}
	}
	view.Preview, err = policy.PreviewTemplate(proposed, view.Facts, now, zone)
	if err != nil {
		return view, reject("TEMPLATE_PREVIEW_INCOMPLETE", err)
	}
	factsRaw, err := encode(view.Facts)
	if err != nil {
		return view, err
	}
	view.FactsHash = Hash(factsRaw)
	// Persist the exact read witness in the same write transaction as its
	// review bundle. The retained snapshot precedes the proposed policy.
	if snapshot.SourceWitnessEnabled {
		if err = tx.Commit(ctx); err != nil {
			return view, err
		}
		tx, err = s.begin(ctx)
		if err != nil {
			return view, err
		}
		defer rollback(ctx, tx)
		view.SourceWitnessID, view.SourceWitnessHash, err = s.saveTemplateSourceWitness(ctx, tx, p, snapshot)
		if err != nil {
			return view, err
		}
		view.SnapshotFundsVersion, view.SnapshotSourceVersion = snapshot.FundsVersion, snapshot.SourceVersion
	}
	view.ReviewedBundleHash, err = templatePreviewHash(view)
	if err != nil {
		return view, err
	}
	bundle, err := encode(view)
	if err != nil {
		return view, err
	}
	previewRaw, err := encode(view.Preview)
	if err != nil {
		return view, err
	}
	if len(bundle) > 8*1024*1024 || len(factsRaw) > 4*1024*1024 {
		return view, reject("TEMPLATE_CAPACITY_EXCEEDED", nil)
	}
	if err = s.human(ctx, tx, p); err != nil {
		return view, err
	}
	if !snapshot.SourceWitnessEnabled {
		if err = tx.Commit(ctx); err != nil {
			return view, err
		}
		tx, err = s.begin(ctx)
		if err != nil {
			return view, err
		}
		defer rollback(ctx, tx)
	}
	_, err = tx.Exec(ctx, `INSERT INTO template_policy_previews(environment_id,user_id,id,policy_id,version_id,base_version,template_name,goal_id,timezone,session_id,configuration,configuration_hash,facts_original,facts_hash,source_hash,preview_original,preview_hash,review_bundle,reviewed_bundle_hash,created_at,expires_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21)`, p.EnvironmentID.String(), p.UserID.String(), view.ID.String(), view.PolicyID.String(), view.VersionID.String(), view.BaseVersion, string(in.Name), templateIDArgument(in.GoalID), zone, p.SessionID.String(), compiled.Configuration, compiled.Hash, factsRaw, view.FactsHash, view.SourceHash, previewRaw, Hash(previewRaw), bundle, view.ReviewedBundleHash, now, view.ExpiresAt)
	if err != nil {
		return view, err
	}
	err = tx.Commit(ctx)
	return view, err
}

func templateIDArgument(id *funds.ID) any {
	if id == nil {
		return nil
	}
	return id.String()
}

func (s *Service) loadTemplatePreview(ctx context.Context, q queryRow, p Principal, id funds.ID) (TemplatePolicyPreview, error) {
	var view TemplatePolicyPreview
	var raw []byte
	var hash string
	err := q.QueryRow(ctx, `SELECT review_bundle,reviewed_bundle_hash::text FROM template_policy_previews WHERE environment_id=$1 AND user_id=$2 AND id=$3`, p.EnvironmentID.String(), p.UserID.String(), id.String()).Scan(&raw, &hash)
	if errors.Is(err, pgx.ErrNoRows) {
		return view, reject("NOT_FOUND", err)
	}
	if err != nil {
		return view, err
	}
	if auditJSON(raw, &view) != nil {
		return view, reject("TEMPLATE_PREVIEW_INVALID", nil)
	}
	expected, err := templatePreviewHash(view)
	if err != nil || expected != hash || view.ReviewedBundleHash != hash || view.ID != id || view.Scope != (policy.TemplateOwnerScope{EnvironmentID: p.EnvironmentID, UserID: p.UserID}) || view.Mode != "IF_USER_CONFIRMED" || view.Authority != "POLICY_CONFIGURATION_ONLY_NO_BANK_GRANT" || view.BankAuthority {
		return view, reject("TEMPLATE_PREVIEW_INVALID", err)
	}
	return view, nil
}

func (s *Service) ConfirmTemplatePolicy(ctx context.Context, p Principal, key string, in TemplatePolicyConfirmation) (TemplatePolicyView, error) {
	var out TemplatePolicyView
	if err := validateKey(key); err != nil {
		return out, err
	}
	if !auditDigestOK(in.ReviewedBundleHash) {
		return out, reject("TEMPLATE_REVIEW_REQUIRED", nil)
	}
	request, err := encode(in)
	if err != nil {
		return out, err
	}
	tx, err := s.begin(ctx)
	if err != nil {
		return out, err
	}
	defer rollback(ctx, tx)
	env, err := s.environment(ctx, tx, true)
	if err != nil {
		return out, err
	}
	if err = sameUser(p, env.ID); err != nil {
		return out, err
	}
	if _, _, err = lockUser(ctx, tx, p); err != nil {
		return out, err
	}
	if err = s.human(ctx, tx, p); err != nil {
		return out, err
	}
	var existing, existingVersion, requestHash string
	err = tx.QueryRow(ctx, `SELECT policy_id::text,version_id::text,request_hash::text FROM template_policy_confirmations WHERE environment_id=$1 AND user_id=$2 AND idempotency_key=$3`, p.EnvironmentID.String(), p.UserID.String(), key).Scan(&existing, &existingVersion, &requestHash)
	if err == nil {
		if requestHash != Hash(request) {
			return out, reject("IDEMPOTENCY_CONFLICT", nil)
		}
		id, e := funds.ParseID(existing)
		if e != nil {
			return out, e
		}
		versionID, e := funds.ParseID(existingVersion)
		if e != nil {
			return out, e
		}
		views, e := s.loadTemplatePoliciesAt(ctx, tx, p, &versionID)
		if e != nil {
			return out, e
		}
		for _, view := range views {
			if view.Version.PolicyID == id {
				return view, nil
			}
		}
		return out, reject("TEMPLATE_FACTS_INVALID", nil)
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return out, err
	}
	preview, err := s.loadTemplatePreview(ctx, tx, p, in.PreviewID)
	if err != nil {
		return out, err
	}
	now := s.now()
	zone, _ := policy.TemplateLocation(preview.Timezone)
	if preview.ReviewedBundleHash != in.ReviewedBundleHash {
		return out, reject("TEMPLATE_REVIEW_REQUIRED", nil)
	}
	if now.Before(preview.CreatedAt) || !now.Before(preview.ExpiresAt) || now.In(zone).Format("2006-01-02") != preview.CreatedAt.In(zone).Format("2006-01-02") {
		return out, reject("TEMPLATE_PREVIEW_EXPIRED", nil)
	}
	snapshot, err := s.loadTemplateSnapshot(ctx, tx, p, now, preview.Timezone)
	if err != nil {
		return out, err
	}
	if snapshot.Facts.SourceHash != preview.SourceHash {
		return out, reject("SOURCE_CHANGED", nil)
	}
	var base uint64
	for _, view := range snapshot.Views {
		if view.Version.PolicyID == preview.PolicyID {
			base = view.Version.Version
		}
	}
	if base != preview.BaseVersion {
		return out, reject("SOURCE_CHANGED", nil)
	}
	datedReferences, err := s.validateDatedConfirmation(ctx, tx, p, preview, snapshot, now)
	if err != nil {
		return out, err
	}
	if err = saveTemplateInventory(ctx, tx, p, snapshot); err != nil {
		return out, err
	}
	if err = s.adoptTemplateObligations(ctx, tx, p, snapshot); err != nil {
		return out, err
	}
	confirmationID, err := newID()
	if err != nil {
		return out, err
	}
	eventID, err := newID()
	if err != nil {
		return out, err
	}
	version := policy.TemplateVersion{PolicyID: preview.PolicyID, VersionID: preview.VersionID, Version: preview.BaseVersion + 1, Scope: preview.Scope, Compiled: preview.Compiled, State: "ACTIVE", ConfirmedAt: now, Current: true, ConfirmationVerified: true, ConfirmedConfigurationHash: preview.Compiled.Hash}
	if _, _, err = policy.TemplateValidity(version.Compiled, now, preview.Timezone); err != nil {
		return out, reject("INVALID_TEMPLATE_CONFIGURATION", err)
	}
	confirmation := templateConfirmationOriginal{Protocol: "template-user-confirmation-v1", ID: confirmationID, PolicyID: version.PolicyID, VersionID: version.VersionID, PreviewID: preview.ID, SessionID: p.SessionID, Scope: version.Scope, PrincipalKind: "USER", ReviewedBundleHash: preview.ReviewedBundleHash, ConfigurationHash: version.Compiled.Hash, ConfirmedAt: now, TargetMutation: preview.TargetMutation}
	confirmation.DatedReferences = datedReferences
	cRaw, err := encode(confirmation)
	if err != nil {
		return out, err
	}
	if datedReferences != nil && len(cRaw) > 65536 {
		return out, reject("TEMPLATE_PROTECTED_REFERENCE_CAPACITY", nil)
	}
	if base == 0 {
		_, err = tx.Exec(ctx, `INSERT INTO template_policies(environment_id,user_id,id,template_name,goal_id,current_version,created_at) VALUES($1,$2,$3,$4,$5,1,$6)`, p.EnvironmentID.String(), p.UserID.String(), version.PolicyID.String(), string(version.Compiled.Name), templateIDArgument(preview.GoalID), now)
	} else {
		_, err = tx.Exec(ctx, `UPDATE template_policies SET current_version=current_version+1 WHERE environment_id=$1 AND user_id=$2 AND id=$3 AND current_version=$4`, p.EnvironmentID.String(), p.UserID.String(), version.PolicyID.String(), base)
	}
	if err != nil {
		return out, err
	}
	_, err = tx.Exec(ctx, `INSERT INTO template_policy_confirmations(environment_id,user_id,id,policy_id,version_id,preview_id,session_id,idempotency_key,request,request_hash,reviewed_bundle_hash,configuration_hash,confirmed_at,original,original_hash) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15)`, p.EnvironmentID.String(), p.UserID.String(), confirmationID.String(), version.PolicyID.String(), version.VersionID.String(), preview.ID.String(), p.SessionID.String(), key, request, Hash(request), preview.ReviewedBundleHash, version.Compiled.Hash, now, cRaw, Hash(cRaw))
	if err != nil {
		return out, err
	}
	vRaw, err := encode(version)
	if err != nil {
		return out, err
	}
	_, err = tx.Exec(ctx, `INSERT INTO template_policy_versions(environment_id,user_id,policy_id,version,id,state,status_event_id,confirmation_id,timezone,configuration,configuration_hash,original,original_hash,confirmed_at) VALUES($1,$2,$3,$4,$5,'ACTIVE',$6,$7,$8,$9,$10,$11,$12,$13)`, p.EnvironmentID.String(), p.UserID.String(), version.PolicyID.String(), version.Version, version.VersionID.String(), eventID.String(), confirmationID.String(), preview.Timezone, version.Compiled.Configuration, version.Compiled.Hash, vRaw, Hash(vRaw), now)
	if err != nil {
		return out, err
	}
	if err = saveTemplateStatus(ctx, tx, p, eventID, version.VersionID, 1, "CONFIRM", "", "ACTIVE", now); err != nil {
		return out, err
	}
	if preview.TargetMutation != nil {
		mutation := preview.TargetMutation
		if err = ensureGoalAvailable(ctx, tx, p, mutation.GoalID); err != nil {
			return out, err
		}
		tag, e := tx.Exec(ctx, `UPDATE goals SET target_cents=$4,version=version+1 WHERE environment_id=$1 AND user_id=$2 AND id=$3 AND target_cents=$5 AND assigned_cents<=$4`, p.EnvironmentID.String(), p.UserID.String(), mutation.GoalID.String(), mutation.After.Cents(), mutation.Before.Cents())
		if e != nil {
			return out, e
		}
		if tag.RowsAffected() != 1 {
			return out, reject("SOURCE_CHANGED", nil)
		}
		if !snapshot.SourceWitnessEnabled {
			if _, err = tx.Exec(ctx, `UPDATE users SET funds_version=funds_version+1 WHERE environment_id=$1 AND id=$2`, p.EnvironmentID.String(), p.UserID.String()); err != nil {
				return out, err
			}
		}
	}
	newSnapshot, err := s.loadTemplateSnapshot(ctx, tx, p, now, preview.Timezone)
	if err != nil {
		return out, err
	}
	if err = s.adoptTemplateObligations(ctx, tx, p, newSnapshot); err != nil {
		return out, err
	}
	if snapshot.SourceWitnessEnabled {
		// Seal authority and any target mutation together, after their full
		// original set. Source-only lifecycle changes also receive a precise FV.
		if _, err = tx.Exec(ctx, `UPDATE users SET funds_version=funds_version+1 WHERE environment_id=$1 AND id=$2`, p.EnvironmentID.String(), p.UserID.String()); err != nil {
			return out, err
		}
	}
	if _, err = s.refreshTemplateProtection(ctx, tx, p, preview.Timezone); err != nil {
		return out, err
	}
	views, err := s.loadTemplatePolicies(ctx, tx, p)
	if err != nil {
		return out, err
	}
	for _, view := range views {
		if view.Version.PolicyID == version.PolicyID {
			out = view
		}
	}
	if out.Version.PolicyID == (funds.ID{}) {
		return out, reject("TEMPLATE_FACTS_INVALID", nil)
	}
	return out, tx.Commit(ctx)
}

func saveTemplateStatus(ctx context.Context, tx pgx.Tx, p Principal, id, version funds.ID, sequence uint64, action, old, state string, at time.Time) error {
	var oldArg any
	if old != "" {
		oldArg = old
	}
	var session *funds.ID
	if p.Kind == "USER" {
		sid := p.SessionID
		session = &sid
	}
	original := templateStatusOriginal{Protocol: "template-lifecycle-v1", ID: id, VersionID: version, Sequence: sequence, Action: action, OldState: old, NewState: state, ActorKind: p.Kind, SessionID: session, At: at}
	admission, err := fundsAuthorityAdmission(ctx, tx, p)
	if err != nil {
		return err
	}
	original.Admission = admission
	raw, err := encode(original)
	if err != nil {
		return err
	}
	_, err = tx.Exec(ctx, `INSERT INTO template_policy_status_events(environment_id,user_id,id,version_id,sequence,action,old_state,new_state,actor_kind,session_id,original,original_hash,occurred_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)`, p.EnvironmentID.String(), p.UserID.String(), id.String(), version.String(), sequence, action, oldArg, state, p.Kind, templateIDArgument(session), raw, Hash(raw), at)
	return err
}

func (s *Service) SetTemplatePolicyState(ctx context.Context, p Principal, id, expectedVersion funds.ID, action string) (TemplatePolicyView, error) {
	var out TemplatePolicyView
	states := map[string]string{"PAUSE": "SUSPENDED", "RESUME": "ACTIVE", "REVOKE": "REVOKED"}
	state, ok := states[action]
	if !ok {
		return out, reject("INVALID_TEMPLATE_TRANSITION", nil)
	}
	tx, err := s.begin(ctx)
	if err != nil {
		return out, err
	}
	defer rollback(ctx, tx)
	env, err := s.environment(ctx, tx, true)
	if err != nil {
		return out, err
	}
	if err = sameUser(p, env.ID); err != nil {
		return out, err
	}
	if _, _, err = lockUser(ctx, tx, p); err != nil {
		return out, err
	}
	if err = s.human(ctx, tx, p); err != nil {
		return out, err
	}
	views, err := s.loadTemplatePolicies(ctx, tx, p)
	if err != nil {
		return out, err
	}
	for _, view := range views {
		if view.Version.PolicyID == id {
			out = view
		}
	}
	if out.Version.PolicyID == (funds.ID{}) {
		return out, reject("NOT_FOUND", nil)
	}
	if out.Version.VersionID != expectedVersion {
		return out, reject("SOURCE_CHANGED", nil)
	}
	if out.Version.State == "REVOKED" || out.Version.State == "EXPIRED" || out.EffectiveState == "EXPIRED" && action != "REVOKE" {
		return out, reject("INVALID_TEMPLATE_TRANSITION", nil)
	}
	if out.Version.State == state {
		return out, nil
	}
	now := s.now()
	snapshot, err := s.loadTemplateSnapshot(ctx, tx, p, now, out.Timezone)
	if err != nil {
		return out, err
	}
	if err = s.adoptTemplateObligations(ctx, tx, p, snapshot); err != nil {
		return out, err
	}
	event, err := newID()
	if err != nil {
		return out, err
	}
	if err = saveTemplateStatus(ctx, tx, p, event, out.Version.VersionID, out.StatusSequence+1, action, out.Version.State, state, now); err != nil {
		return out, err
	}
	_, err = tx.Exec(ctx, `UPDATE template_policy_versions SET state=$4,status_sequence=status_sequence+1,status_event_id=$5 WHERE environment_id=$1 AND user_id=$2 AND id=$3`, p.EnvironmentID.String(), p.UserID.String(), out.Version.VersionID.String(), state, event.String())
	if err != nil {
		return out, err
	}
	if snapshot.SourceWitnessEnabled {
		if _, err = tx.Exec(ctx, `UPDATE users SET funds_version=funds_version+1 WHERE environment_id=$1 AND id=$2`, p.EnvironmentID.String(), p.UserID.String()); err != nil {
			return out, err
		}
	}
	if _, err = s.refreshTemplateProtection(ctx, tx, p, out.Timezone); err != nil {
		return out, err
	}
	views, err = s.loadTemplatePolicies(ctx, tx, p)
	if err != nil {
		return out, err
	}
	for _, view := range views {
		if view.Version.PolicyID == id {
			out = view
		}
	}
	return out, tx.Commit(ctx)
}

func (s *Service) adoptTemplateObligations(ctx context.Context, tx pgx.Tx, p Principal, snapshot templateSnapshot) error {
	if _, err := s.persistTemplateHistory(ctx, tx, p, snapshot); err != nil {
		return err
	}
	view, err := forecastTemplateSnapshot(snapshot, 365)
	if err != nil {
		return err
	}
	zone, _ := policy.TemplateLocation(snapshot.Timezone)
	today := snapshot.AsOf.In(zone).Format("2006-01-02")
	for _, obligation := range view.Result.Obligations {
		kind, period := "DATED", obligation.DueDate
		if at := strings.Index(obligation.ID, ":monthly:"); at >= 0 {
			kind = "MONTHLY"
			period = obligation.ID[at+len(":monthly:"):]
		}
		if kind == "DATED" {
			for _, version := range snapshot.Versions {
				if version.VersionID == obligation.VersionID {
					config, e := version.Compiled.Decode()
					if e != nil {
						return reject("TEMPLATE_FACTS_INVALID", e)
					}
					if dated, ok := config.(*policy.DatedExpenseConfig); ok {
						period = dated.Window.Start + "/" + dated.Window.End
					}
				}
			}
		}
		if obligation.DueDate > today && (kind != "MONTHLY" || period != today[:7]) {
			continue
		}
		if obligation.Amount.IsZero() {
			continue
		}
		raw, err := encode(obligation)
		if err != nil {
			return err
		}
		_, err = tx.Exec(ctx, `INSERT INTO template_obligations(environment_id,user_id,id,policy_id,version_id,period_key,kind,due_date,amount_cents,original,original_hash,adopted_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8::date,$9,$10,$11,$12) ON CONFLICT(environment_id,user_id,id) DO NOTHING`, p.EnvironmentID.String(), p.UserID.String(), obligation.ID, obligation.PolicyID.String(), obligation.VersionID.String(), period, kind, obligation.DueDate, obligation.Amount.Cents(), raw, Hash(raw), snapshot.AsOf)
		if err != nil {
			return err
		}
	}
	return nil
}
