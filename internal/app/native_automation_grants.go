package app

import (
	"context"
	"errors"
	"sort"
	"time"

	"github.com/jackc/pgx/v5"
	"zhiyu.local/zhiyu-go/internal/execution/fundswitness"
	funds "zhiyu.local/zhiyu-go/internal/funds/domain"
	policy "zhiyu.local/zhiyu-go/internal/policy/domain"
)

type nativeGrantStateOriginal struct {
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

func nativeAutomationScope(p Principal) policy.TemplateOwnerScope {
	return policy.TemplateOwnerScope{EnvironmentID: p.EnvironmentID, UserID: p.UserID}
}

func nativeGrantReferences(ctx context.Context, q templateQuery, s *Service, p Principal, versionIDs []funds.ID) ([]policy.NativePolicyReference, []funds.ID, []string, error) {
	if len(versionIDs) == 0 || len(versionIDs) > 16 {
		return nil, nil, nil, reject("NATIVE_GRANT_INVALID", nil)
	}
	views, err := s.loadTemplatePolicies(ctx, q, p)
	if err != nil {
		return nil, nil, nil, err
	}
	byID := map[funds.ID]TemplatePolicyView{}
	for _, v := range views {
		byID[v.Version.VersionID] = v
	}
	refs := []policy.NativePolicyReference{}
	goals := []funds.ID{}
	payees := []string{}
	seen := map[funds.ID]bool{}
	seenGoals := map[funds.ID]bool{}
	for _, id := range versionIDs {
		v, exists := byID[id]
		if !exists || seen[id] || v.EffectiveState != "ACTIVE" {
			return nil, nil, nil, reject("NATIVE_GRANT_POLICY_CHANGED", nil)
		}
		seen[id] = true
		configuration, e := v.Version.Compiled.Decode()
		if e != nil {
			return nil, nil, nil, reject("NATIVE_GRANT_POLICY_CHANGED", e)
		}
		goalID := v.GoalID
		switch cfg := configuration.(type) {
		case *policy.AssetAuthorizationConfig:
			goalID = cfg.GoalID
		case *policy.RecoveryConfig:
			goalID = cfg.GoalID
		}
		if v.GoalID != nil && (goalID == nil || *goalID != *v.GoalID) {
			return nil, nil, nil, reject("NATIVE_GRANT_POLICY_CHANGED", nil)
		}
		ref := policy.NativePolicyReference{PolicyID: v.Version.PolicyID, VersionID: v.Version.VersionID, Version: v.Version.Version, Template: v.Version.Compiled.Name, ConfigurationHash: v.Version.Compiled.Hash, GoalID: goalID}
		if goalID != nil {
			var goalExists bool
			if err = q.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM goals WHERE environment_id=$1 AND user_id=$2 AND id=$3)`, p.EnvironmentID.String(), p.UserID.String(), goalID.String()).Scan(&goalExists); err != nil {
				return nil, nil, nil, err
			}
			if !goalExists {
				return nil, nil, nil, reject("NATIVE_GRANT_POLICY_CHANGED", nil)
			}
			if !seenGoals[*goalID] {
				goals = append(goals, *goalID)
				seenGoals[*goalID] = true
			}
		}
		switch cfg := configuration.(type) {
		case *policy.RecurringObligationConfig:
			if !cfg.AutoExecute {
				return nil, nil, nil, reject("NATIVE_GRANT_AUTO_EXECUTE_DISABLED", nil)
			}
			payees = append(payees, cfg.PayeeID)
		case *policy.PeriodicTransferConfig:
			if !cfg.AutoExecute {
				return nil, nil, nil, reject("NATIVE_GRANT_AUTO_EXECUTE_DISABLED", nil)
			}
			payees = append(payees, cfg.PayeeID)
		}
		refs = append(refs, ref)
	}
	sort.Slice(refs, func(i, j int) bool { return refs[i].PolicyID.String() < refs[j].PolicyID.String() })
	sort.Slice(goals, func(i, j int) bool { return goals[i].String() < goals[j].String() })
	sort.Strings(payees)
	return refs, goals, payees, nil
}

func (s *Service) PreviewNativeStandingGrant(ctx context.Context, p Principal, in NativeStandingGrantRequest) (NativeStandingGrantPreview, error) {
	var out NativeStandingGrantPreview
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
	refs, goals, payees, err := nativeGrantReferences(ctx, tx, s, p, in.PolicyVersionIDs)
	if err != nil {
		return out, err
	}
	accounts := append([]funds.ID(nil), in.AccountIDs...)
	products := append([]string(nil), in.ProductIDs...)
	sort.Slice(accounts, func(i, j int) bool { return accounts[i].String() < accounts[j].String() })
	sort.Strings(products)
	now := s.now()
	terms := policy.NativeStandingTerms{Protocol: policy.NativeStandingProtocol, Scope: nativeAutomationScope(p), Family: in.Family, Policies: refs, AccountIDs: accounts, GoalIDs: goals, ProductIDs: products, PayeeIDs: payees, SingleCap: in.SingleCap, LifetimeCap: in.LifetimeCap, MonthlyCap: in.MonthlyCap, Timezone: in.Timezone, EffectiveFrom: now, ExpiresAt: in.ExpiresAt.UTC()}
	if terms.Validate() != nil {
		return out, reject("NATIVE_GRANT_INVALID", nil)
	}
	for _, id := range accounts {
		var owned bool
		if err = tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM accounts WHERE environment_id=$1 AND user_id=$2 AND id=$3)`, p.EnvironmentID.String(), p.UserID.String(), id.String()).Scan(&owned); err != nil {
			return out, err
		}
		if !owned {
			return out, reject("FORBIDDEN", nil)
		}
	}
	// Cross-account scope requires the independent staged-arrival schema.
	// Every target account must itself be included in the reviewed grant.
	if in.Family == policy.NativeJointGoals {
		cross := len(accounts) > 1
		for _, id := range goals {
			var account string
			if err = tx.QueryRow(ctx, `SELECT account_id::text FROM goals WHERE environment_id=$1 AND user_id=$2 AND id=$3`, p.EnvironmentID.String(), p.UserID.String(), id.String()).Scan(&account); err != nil {
				return out, err
			}
			found := false
			for _, a := range accounts {
				found = found || a.String() == account
			}
			if !found {
				return out, reject("NATIVE_GRANT_SCOPE", nil)
			}
		}
		if cross {
			if err = standingBridgeSchema(ctx, tx); err != nil {
				return out, err
			}
		}
	}
	out = NativeStandingGrantPreview{Protocol: NativeAutomationProtocol + "/grant-preview", Scope: nativeAutomationScope(p), SessionID: p.SessionID, Terms: terms, CreatedAt: now, ExpiresAt: now.Add(2 * time.Minute)}
	out.ID, err = newID()
	if err != nil {
		return out, err
	}
	out.ReviewedHash, err = NativeStandingGrantReviewHash(out)
	if err != nil {
		return out, err
	}
	raw, err := encode(out)
	if err != nil {
		return out, err
	}
	_, err = tx.Exec(ctx, `INSERT INTO native_grant_previews(environment_id,user_id,id,session_id,original,original_hash,reviewed_hash,created_at,expires_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9)`, p.EnvironmentID.String(), p.UserID.String(), out.ID.String(), p.SessionID.String(), raw, Hash(raw), out.ReviewedHash, out.CreatedAt, out.ExpiresAt)
	if err != nil {
		return out, err
	}
	return out, tx.Commit(ctx)
}

func loadNativeGrantPreview(ctx context.Context, q queryRow, p Principal, id funds.ID) (NativeStandingGrantPreview, error) {
	var out NativeStandingGrantPreview
	var raw []byte
	var hash, reviewed, session string
	var created, expires time.Time
	err := q.QueryRow(ctx, `SELECT original,original_hash,reviewed_hash,session_id::text,created_at,expires_at FROM native_grant_previews WHERE environment_id=$1 AND user_id=$2 AND id=$3`, p.EnvironmentID.String(), p.UserID.String(), id.String()).Scan(&raw, &hash, &reviewed, &session, &created, &expires)
	if err != nil {
		return out, reject("NOT_FOUND", err)
	}
	if Hash(raw) != hash || auditJSON(raw, &out) != nil || out.Protocol != NativeAutomationProtocol+"/grant-preview" || out.ID != id || out.Scope != nativeAutomationScope(p) || out.Terms.Scope != out.Scope || out.Terms.Validate() != nil || out.SessionID.String() != session || out.ReviewedHash != reviewed || !out.CreatedAt.Equal(created) || !out.ExpiresAt.Equal(expires) {
		return out, reject("EVIDENCE_INVALID", nil)
	}
	want, err := NativeStandingGrantReviewHash(out)
	if err != nil || want != reviewed {
		return out, reject("EVIDENCE_INVALID", err)
	}
	return out, nil
}

func (s *Service) ConfirmNativeStandingGrant(ctx context.Context, p Principal, key string, in NativeStandingGrantConfirmation) (NativeStandingGrantView, error) {
	var zero NativeStandingGrantView
	if err := validateKey(key); err != nil {
		return zero, err
	}
	request, err := encode(in)
	if err != nil {
		return zero, err
	}
	tx, err := s.begin(ctx)
	if err != nil {
		return zero, err
	}
	defer rollback(ctx, tx)
	env, err := s.environment(ctx, tx, true)
	if err != nil {
		return zero, err
	}
	if err = sameUser(p, env.ID); err != nil {
		return zero, err
	}
	if _, _, err = lockUser(ctx, tx, p); err != nil {
		return zero, err
	}
	if err = s.human(ctx, tx, p); err != nil {
		return zero, err
	}
	var oldID, oldHash string
	err = tx.QueryRow(ctx, `SELECT id::text,request_hash FROM native_grants WHERE environment_id=$1 AND user_id=$2 AND idempotency_key=$3`, p.EnvironmentID.String(), p.UserID.String(), key).Scan(&oldID, &oldHash)
	if err == nil {
		if oldHash != Hash(request) {
			return zero, reject("IDEMPOTENCY_CONFLICT", nil)
		}
		id, e := funds.ParseID(oldID)
		if e != nil {
			return zero, e
		}
		return loadNativeStandingGrant(ctx, tx, p, id)
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return zero, err
	}
	preview, err := loadNativeGrantPreview(ctx, tx, p, in.PreviewID)
	if err != nil {
		return zero, err
	}
	now := s.now()
	if preview.SessionID != p.SessionID || in.ReviewedHash != preview.ReviewedHash {
		return zero, reject("REVIEW_MISMATCH", nil)
	}
	if !now.Before(preview.ExpiresAt) || !now.Before(preview.Terms.ExpiresAt) {
		return zero, reject("PREVIEW_EXPIRED", nil)
	}
	versions := make([]funds.ID, len(preview.Terms.Policies))
	for i, r := range preview.Terms.Policies {
		versions[i] = r.VersionID
	}
	refs, goals, payees, err := nativeGrantReferences(ctx, tx, s, p, versions)
	if err != nil {
		return zero, err
	}
	current := preview.Terms
	current.Policies = refs
	current.GoalIDs = goals
	current.PayeeIDs = payees
	a, _ := current.Digest()
	b, _ := preview.Terms.Digest()
	if a == "" || a != b {
		return zero, reject("NATIVE_GRANT_POLICY_CHANGED", nil)
	}
	current.EffectiveFrom = now
	if current.Validate() != nil {
		return zero, reject("NATIVE_GRANT_INVALID", nil)
	}
	id, err := newID()
	if err != nil {
		return zero, err
	}
	eventID, err := newID()
	if err != nil {
		return zero, err
	}
	grant := NativeStandingGrant{Protocol: NativeAutomationProtocol + "/grant", ID: id, Version: 1, Scope: nativeAutomationScope(p), Terms: current, ReviewedTerms: preview.Terms, PreviewID: preview.ID, SessionID: p.SessionID, ReviewedHash: in.ReviewedHash, PrincipalKind: "USER", ConfirmedAt: now}
	raw, err := encode(grant)
	if err != nil {
		return zero, err
	}
	_, err = tx.Exec(ctx, `INSERT INTO native_grants(environment_id,user_id,id,version,family,preview_id,session_id,original,original_hash,idempotency_key,request,request_hash,effective_from,expires_at,confirmed_at) VALUES($1,$2,$3,1,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)`, p.EnvironmentID.String(), p.UserID.String(), id.String(), string(current.Family), preview.ID.String(), p.SessionID.String(), raw, Hash(raw), key, request, Hash(request), current.EffectiveFrom, current.ExpiresAt, now)
	if err != nil {
		return zero, err
	}
	event := nativeGrantStateOriginal{Protocol: NativeAutomationProtocol + "/grant-state", ID: eventID, Scope: nativeAutomationScope(p), GrantID: id, GrantVersion: 1, Sequence: 1, Action: "CONFIRM", NewState: "ACTIVE", SessionID: p.SessionID, PrincipalKind: "USER", At: now}
	if event.Admission, err = fundsAuthorityAdmission(ctx, tx, p); err != nil {
		return zero, err
	}
	if err = insertNativeGrantState(ctx, tx, event); err != nil {
		return zero, err
	}
	_, err = tx.Exec(ctx, `INSERT INTO native_grant_states(environment_id,user_id,grant_id,grant_version,state,sequence,event_id,updated_at) VALUES($1,$2,$3,1,'ACTIVE',1,$4,$5)`, p.EnvironmentID.String(), p.UserID.String(), id.String(), eventID.String(), now)
	if err != nil {
		return zero, err
	}
	if err = s.sealNativeGrantAuthority(ctx, tx, p); err != nil {
		return zero, err
	}
	out, err := loadNativeStandingGrant(ctx, tx, p, id)
	if err != nil {
		return zero, err
	}
	return out, tx.Commit(ctx)
}

func insertNativeGrantState(ctx context.Context, tx pgx.Tx, event nativeGrantStateOriginal) error {
	raw, err := encode(event)
	if err != nil {
		return err
	}
	_, err = tx.Exec(ctx, `INSERT INTO native_grant_state_events(environment_id,user_id,id,grant_id,grant_version,sequence,session_id,action,old_state,new_state,original,original_hash,created_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)`, event.Scope.EnvironmentID.String(), event.Scope.UserID.String(), event.ID.String(), event.GrantID.String(), event.GrantVersion, event.Sequence, event.SessionID.String(), event.Action, event.OldState, event.NewState, raw, Hash(raw), event.At)
	return err
}

func loadNativeStandingGrant(ctx context.Context, q queryRow, p Principal, id funds.ID) (NativeStandingGrantView, error) {
	var out NativeStandingGrantView
	var raw, eventRaw []byte
	var hash, eventHash, eventID string
	err := q.QueryRow(ctx, `SELECT g.original,g.original_hash,s.state,s.sequence,s.updated_at,e.id::text,e.original,e.original_hash FROM native_grants g JOIN native_grant_states s ON(s.environment_id=g.environment_id AND s.user_id=g.user_id AND s.grant_id=g.id AND s.grant_version=g.version) JOIN native_grant_state_events e ON(e.environment_id=s.environment_id AND e.user_id=s.user_id AND e.id=s.event_id) WHERE g.environment_id=$1 AND g.user_id=$2 AND g.id=$3`, p.EnvironmentID.String(), p.UserID.String(), id.String()).Scan(&raw, &hash, &out.State, &out.StateSequence, &out.StateAt, &eventID, &eventRaw, &eventHash)
	if err != nil {
		return out, reject("NOT_FOUND", err)
	}
	var event nativeGrantStateOriginal
	if Hash(raw) != hash || Hash(eventRaw) != eventHash || auditJSON(raw, &out.Grant) != nil || auditJSON(eventRaw, &event) != nil {
		return out, reject("EVIDENCE_INVALID", nil)
	}
	g := out.Grant
	if g.Protocol != NativeAutomationProtocol+"/grant" || g.ID != id || g.Version != 1 || g.Scope != nativeAutomationScope(p) || g.Terms.Scope != g.Scope || g.ReviewedTerms.Scope != g.Scope || g.Terms.Validate() != nil || g.ReviewedTerms.Validate() != nil || g.PrincipalKind != "USER" || g.SessionID == (funds.ID{}) || !g.Terms.EffectiveFrom.Equal(g.ConfirmedAt) || g.ConfirmedAt.Before(g.ReviewedTerms.EffectiveFrom) || g.ConfirmedAt.IsZero() || event.Protocol != NativeAutomationProtocol+"/grant-state" || event.ID.String() != eventID || event.Scope != g.Scope || event.GrantID != id || event.GrantVersion != g.Version || event.Sequence != out.StateSequence || event.NewState != out.State || !event.At.Equal(out.StateAt) || event.PrincipalKind != "USER" || event.SessionID == (funds.ID{}) {
		return out, reject("EVIDENCE_INVALID", nil)
	}
	final := g.Terms
	final.EffectiveFrom = g.ReviewedTerms.EffectiveFrom
	a, _ := final.Digest()
	b, _ := g.ReviewedTerms.Digest()
	if a == "" || a != b {
		return out, reject("EVIDENCE_INVALID", nil)
	}
	preview, err := loadNativeGrantPreview(ctx, q, p, g.PreviewID)
	if err != nil {
		return out, err
	}
	want, _ := g.ReviewedTerms.Digest()
	have, _ := preview.Terms.Digest()
	if want != have || preview.ReviewedHash != g.ReviewedHash || preview.SessionID != g.SessionID || !g.ConfirmedAt.Before(preview.ExpiresAt) {
		return out, reject("EVIDENCE_INVALID", nil)
	}
	return out, nil
}

func (s *Service) NativeStandingGrant(ctx context.Context, p Principal, id funds.ID) (NativeStandingGrantView, error) {
	if err := s.auditHuman(ctx, p); err != nil {
		return NativeStandingGrantView{}, err
	}
	return loadNativeStandingGrant(ctx, s.Pool, p, id)
}

func (s *Service) ListNativeStandingGrants(ctx context.Context, p Principal) ([]NativeStandingGrantView, error) {
	if err := s.auditHuman(ctx, p); err != nil {
		return nil, err
	}
	tx, err := s.Pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	if err != nil {
		return nil, err
	}
	defer rollback(ctx, tx)
	rows, err := tx.Query(ctx, `SELECT id::text FROM native_grants WHERE environment_id=$1 AND user_id=$2 ORDER BY confirmed_at,id LIMIT 101`, p.EnvironmentID.String(), p.UserID.String())
	if err != nil {
		return nil, err
	}
	ids := []funds.ID{}
	for rows.Next() {
		var raw string
		if err = rows.Scan(&raw); err != nil {
			rows.Close()
			return nil, err
		}
		id, e := funds.ParseID(raw)
		if e != nil {
			rows.Close()
			return nil, e
		}
		ids = append(ids, id)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return nil, err
	}
	if len(ids) > 100 {
		return nil, reject("NATIVE_GRANT_CAPACITY", nil)
	}
	out := []NativeStandingGrantView{}
	for _, id := range ids {
		v, e := loadNativeStandingGrant(ctx, tx, p, id)
		if e != nil {
			return nil, e
		}
		out = append(out, v)
	}
	return out, tx.Commit(ctx)
}

func (s *Service) SetNativeStandingGrantState(ctx context.Context, p Principal, id funds.ID, expected uint64, action string) (NativeStandingGrantView, error) {
	var zero NativeStandingGrantView
	tx, err := s.begin(ctx)
	if err != nil {
		return zero, err
	}
	defer rollback(ctx, tx)
	env, err := s.environment(ctx, tx, true)
	if err != nil {
		return zero, err
	}
	if err = sameUser(p, env.ID); err != nil {
		return zero, err
	}
	if _, _, err = lockUser(ctx, tx, p); err != nil {
		return zero, err
	}
	if err = s.human(ctx, tx, p); err != nil {
		return zero, err
	}
	view, err := loadNativeStandingGrant(ctx, tx, p, id)
	if err != nil {
		return zero, err
	}
	if view.StateSequence != expected {
		return zero, reject("NATIVE_GRANT_STATE_CHANGED", nil)
	}
	next := ""
	switch action {
	case "PAUSE":
		if view.State == "ACTIVE" {
			next = "PAUSED"
		}
	case "RESUME":
		if view.State == "PAUSED" {
			next = "ACTIVE"
		}
	case "REVOKE":
		if view.State != "REVOKED" {
			next = "REVOKED"
		}
	}
	if next == "" {
		return zero, reject("NATIVE_GRANT_TRANSITION_INVALID", nil)
	}
	eventID, err := newID()
	if err != nil {
		return zero, err
	}
	event := nativeGrantStateOriginal{Protocol: NativeAutomationProtocol + "/grant-state", ID: eventID, Scope: nativeAutomationScope(p), GrantID: id, GrantVersion: view.Grant.Version, Sequence: expected + 1, Action: action, OldState: view.State, NewState: next, SessionID: p.SessionID, PrincipalKind: "USER", At: s.now()}
	if event.Admission, err = fundsAuthorityAdmission(ctx, tx, p); err != nil {
		return zero, err
	}
	if err = insertNativeGrantState(ctx, tx, event); err != nil {
		return zero, err
	}
	_, err = tx.Exec(ctx, `UPDATE native_grant_states SET state=$4,sequence=$5,event_id=$6,updated_at=$7 WHERE environment_id=$1 AND user_id=$2 AND grant_id=$3`, p.EnvironmentID.String(), p.UserID.String(), id.String(), next, event.Sequence, eventID.String(), event.At)
	if err != nil {
		return zero, err
	}
	if err = s.sealNativeGrantAuthority(ctx, tx, p); err != nil {
		return zero, err
	}
	// Publish the new source version with its corresponding protection snapshot.
	// Already signed bank requests retain their original recovery.
	if _, err = s.refreshTemplateProtection(ctx, tx, p, view.Grant.Terms.Timezone); err != nil {
		return zero, err
	}
	out, err := loadNativeStandingGrant(ctx, tx, p, id)
	if err != nil {
		return zero, err
	}
	return out, tx.Commit(ctx)
}
