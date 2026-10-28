package app

import (
	"context"
	"encoding/json"
	"errors"
	"sort"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	agent "zhiyu.local/zhiyu-go/internal/agent/domain"
	funds "zhiyu.local/zhiyu-go/internal/funds/domain"
	policy "zhiyu.local/zhiyu-go/internal/policy/domain"
)

const (
	agentGrantLimit           = 100
	agentGrantEventLimit      = 256
	agentGrantTotalEvents     = 4096
	agentGrantRawLimit        = 8 * 1024 * 1024
	agentGrantPreviewRawLimit = 4 * 1024 * 1024
	agentGrantEventRawLimit   = 8 * 1024 * 1024
	agentGrantSubjectLimit    = 4296
)

type agentGrantMetadata struct {
	row                         agentNativeGrantRow
	originalBytes, requestBytes int64
}

type agentGrantPreviewMetadata struct {
	row           agentNativeGrantPreviewRow
	originalBytes int64
}

type agentGrantEventMetadata struct {
	count, bytes int64
}

func agentGrantUnavailable(reason string) (*agent.NativeGrantCollection, error) {
	return agent.UnavailableNativeGrants(reason), nil
}

// Only finite integrity/absence failures become an unavailable collection.
// SQL/connection/cancellation failures must abort the shared snapshot tx.
func agentGrantReadFailure(err error) (*agent.NativeGrantCollection, error) {
	var pg *pgconn.PgError
	if errors.As(err, &pg) || errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return nil, err
	}
	switch Code(err) {
	case "NATIVE_GRANT_CAPACITY":
		return agentGrantUnavailable("CAPACITY")
	case "SUBJECT_UNAVAILABLE":
		return agentGrantUnavailable("SUBJECT_UNAVAILABLE")
	case "SESSION_EXPIRED_AT_EVENT":
		return agentGrantUnavailable("SESSION_EXPIRED_AT_EVENT")
	case "EVIDENCE_INVALID", "TEMPLATE_FACTS_INVALID", "AGENT_NATIVE_GRANT_EVIDENCE_INVALID":
		return agentGrantUnavailable("EVIDENCE_INVALID")
	case "NOT_FOUND":
		if errors.Is(err, pgx.ErrNoRows) {
			return agentGrantUnavailable("EVIDENCE_INVALID")
		}
	}
	return nil, err
}

func agentGrantID(raw string) (funds.ID, error) {
	id, err := funds.ParseID(raw)
	if err != nil || id == (funds.ID{}) {
		return funds.ID{}, reject("EVIDENCE_INVALID", nil)
	}
	return id, nil
}

// loadAgentNativeGrants never opens a transaction, locks rows, writes state or
// returns raw originals. Every preflight and load uses AgentSnapshot's tx.
func (s *Service) loadAgentNativeGrants(ctx context.Context, tx pgx.Tx, p Principal, snapshot agent.Snapshot, current []TemplatePolicyView) (*agent.NativeGrantCollection, error) {
	if p.Kind != "USER" || p.SessionID == (funds.ID{}) || p.EnvironmentID == (funds.ID{}) || p.UserID == (funds.ID{}) {
		return nil, reject("FORBIDDEN", nil)
	}
	if snapshot.Scope != (agent.Scope{EnvironmentID: p.EnvironmentID, UserID: p.UserID}) || snapshot.AsOf.IsZero() {
		return nil, reject("EVIDENCE_INVALID", nil)
	}
	var present bool
	err := tx.QueryRow(ctx, `SELECT to_regclass('native_grants') IS NOT NULL AND to_regclass('native_grant_previews') IS NOT NULL AND to_regclass('native_grant_state_events') IS NOT NULL AND to_regclass('native_grant_states') IS NOT NULL AND to_regclass('audit_session_subjects') IS NOT NULL`).Scan(&present)
	if err != nil {
		return nil, err
	}
	if !present {
		return agentGrantUnavailable("SCHEMA_UNAVAILABLE")
	}
	metas := map[funds.ID]agentGrantMetadata{}
	order := []funds.ID{}
	rows, err := tx.Query(ctx, `SELECT id::text,version,family,preview_id::text,session_id::text,original_hash::text,request_hash::text,effective_from,expires_at,confirmed_at,octet_length(original),octet_length(request) FROM native_grants WHERE environment_id=$1 AND user_id=$2 ORDER BY id LIMIT 101`, p.EnvironmentID.String(), p.UserID.String())
	if err != nil {
		return nil, err
	}
	var grantBytes int64
	for rows.Next() {
		var m agentGrantMetadata
		var id, preview, session, family string
		if err = rows.Scan(&id, &m.row.Version, &family, &preview, &session, &m.row.OriginalHash, &m.row.RequestHash, &m.row.EffectiveFrom, &m.row.ExpiresAt, &m.row.ConfirmedAt, &m.originalBytes, &m.requestBytes); err != nil {
			rows.Close()
			return nil, err
		}
		m.row.ID, err = agentGrantID(id)
		if err != nil {
			rows.Close()
			return agentGrantReadFailure(err)
		}
		m.row.PreviewID, err = agentGrantID(preview)
		if err != nil {
			rows.Close()
			return agentGrantReadFailure(err)
		}
		m.row.SessionID, err = agentGrantID(session)
		if err != nil {
			rows.Close()
			return agentGrantReadFailure(err)
		}
		m.row.Family = policy.NativeFamily(family)
		if _, duplicate := metas[m.row.ID]; duplicate {
			rows.Close()
			return agentGrantUnavailable("EVIDENCE_INVALID")
		}
		if len(order) >= agentGrantLimit || m.originalBytes < 1 || m.originalBytes > 524288 || m.requestBytes < 1 || m.requestBytes > 4096 || grantBytes > agentGrantRawLimit-m.originalBytes {
			rows.Close()
			return agentGrantUnavailable("CAPACITY")
		}
		grantBytes += m.originalBytes
		metas[m.row.ID] = m
		order = append(order, m.row.ID)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return nil, err
	}
	projections := map[funds.ID]agentNativeGrantProjection{}
	rows, err = tx.Query(ctx, `SELECT grant_id::text,grant_version,state,sequence,event_id::text,updated_at FROM native_grant_states WHERE environment_id=$1 AND user_id=$2 ORDER BY grant_id,grant_version LIMIT 101`, p.EnvironmentID.String(), p.UserID.String())
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var v agentNativeGrantProjection
		var id, event string
		if err = rows.Scan(&id, &v.GrantVersion, &v.State, &v.Sequence, &event, &v.UpdatedAt); err != nil {
			rows.Close()
			return nil, err
		}
		v.GrantID, err = agentGrantID(id)
		if err != nil {
			rows.Close()
			return agentGrantReadFailure(err)
		}
		v.EventID, err = agentGrantID(event)
		if err != nil {
			rows.Close()
			return agentGrantReadFailure(err)
		}
		m, exists := metas[v.GrantID]
		if !exists || v.GrantVersion != m.row.Version {
			rows.Close()
			return agentGrantUnavailable("EVIDENCE_INVALID")
		}
		if _, duplicate := projections[v.GrantID]; duplicate {
			rows.Close()
			return agentGrantUnavailable("EVIDENCE_INVALID")
		}
		if v.Sequence > agentGrantEventLimit {
			rows.Close()
			return agentGrantUnavailable("CAPACITY")
		}
		projections[v.GrantID] = v
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return nil, err
	}
	if len(projections) != len(order) {
		return agentGrantUnavailable("EVIDENCE_INVALID")
	}
	eventMeta := map[funds.ID]agentGrantEventMetadata{}
	rows, err = tx.Query(ctx, `SELECT grant_id::text,grant_version,count(*),sum(octet_length(original)),max(octet_length(original)),min(octet_length(original)) FROM native_grant_state_events WHERE environment_id=$1 AND user_id=$2 GROUP BY grant_id,grant_version ORDER BY grant_id,grant_version LIMIT 101`, p.EnvironmentID.String(), p.UserID.String())
	if err != nil {
		return nil, err
	}
	var totalEvents, eventBytes int64
	for rows.Next() {
		var id string
		var version uint64
		var m agentGrantEventMetadata
		var maximum, minimum int64
		if err = rows.Scan(&id, &version, &m.count, &m.bytes, &maximum, &minimum); err != nil {
			rows.Close()
			return nil, err
		}
		gid, e := agentGrantID(id)
		if e != nil {
			rows.Close()
			return agentGrantReadFailure(e)
		}
		grant, exists := metas[gid]
		if !exists || version != grant.row.Version {
			rows.Close()
			return agentGrantUnavailable("EVIDENCE_INVALID")
		}
		if _, duplicate := eventMeta[gid]; duplicate {
			rows.Close()
			return agentGrantUnavailable("EVIDENCE_INVALID")
		}
		if m.count < 1 || m.count > agentGrantEventLimit || minimum < 1 || maximum > 8192 || m.bytes < 1 || totalEvents > agentGrantTotalEvents-m.count || eventBytes > agentGrantEventRawLimit-m.bytes {
			rows.Close()
			return agentGrantUnavailable("CAPACITY")
		}
		totalEvents += m.count
		eventBytes += m.bytes
		eventMeta[gid] = m
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return nil, err
	}
	if len(eventMeta) != len(order) {
		return agentGrantUnavailable("EVIDENCE_INVALID")
	}
	previewIDs := map[funds.ID]bool{}
	for _, id := range order {
		previewIDs[metas[id].row.PreviewID] = true
	}
	ids := make([]string, 0, len(previewIDs))
	for id := range previewIDs {
		ids = append(ids, id.String())
	}
	sort.Strings(ids)
	previewMeta := map[funds.ID]agentGrantPreviewMetadata{}
	if len(ids) != 0 {
		rows, err = tx.Query(ctx, `SELECT id::text,session_id::text,original_hash::text,reviewed_hash::text,created_at,expires_at,octet_length(original) FROM native_grant_previews WHERE environment_id=$1 AND user_id=$2 AND id=ANY($3::uuid[]) ORDER BY id LIMIT 101`, p.EnvironmentID.String(), p.UserID.String(), ids)
		if err != nil {
			return nil, err
		}
		var previewBytes int64
		for rows.Next() {
			var m agentGrantPreviewMetadata
			var id, session string
			if err = rows.Scan(&id, &session, &m.row.OriginalHash, &m.row.ReviewedHash, &m.row.CreatedAt, &m.row.ExpiresAt, &m.originalBytes); err != nil {
				rows.Close()
				return nil, err
			}
			m.row.ID, err = agentGrantID(id)
			if err != nil {
				rows.Close()
				return agentGrantReadFailure(err)
			}
			m.row.SessionID, err = agentGrantID(session)
			if err != nil {
				rows.Close()
				return agentGrantReadFailure(err)
			}
			if !previewIDs[m.row.ID] {
				rows.Close()
				return agentGrantUnavailable("EVIDENCE_INVALID")
			}
			if _, duplicate := previewMeta[m.row.ID]; duplicate {
				rows.Close()
				return agentGrantUnavailable("EVIDENCE_INVALID")
			}
			if m.originalBytes < 1 || m.originalBytes > 262144 || previewBytes > agentGrantPreviewRawLimit-m.originalBytes {
				rows.Close()
				return agentGrantUnavailable("CAPACITY")
			}
			previewBytes += m.originalBytes
			previewMeta[m.row.ID] = m
		}
		err = rows.Err()
		rows.Close()
		if err != nil {
			return nil, err
		}
	}
	if len(previewMeta) != len(previewIDs) {
		return agentGrantUnavailable("EVIDENCE_INVALID")
	}
	// All grant/preview/event byte/count gates above run before any raw load.
	ownedAccounts, ownedGoals := map[funds.ID]bool{}, map[funds.ID]bool{}
	for _, a := range snapshot.Accounts {
		id, e := agentGrantID(a.ID)
		if e != nil {
			return agentGrantReadFailure(e)
		}
		ownedAccounts[id] = true
	}
	for _, g := range snapshot.Goals {
		id, e := agentGrantID(g.ID)
		if e != nil {
			return agentGrantReadFailure(e)
		}
		ownedGoals[id] = true
	}
	subjectIDs := map[funds.ID]bool{}
	historical := map[funds.ID]TemplatePolicyView{}
	historicalIDs := map[funds.ID]bool{}
	previewRaw := map[funds.ID][]byte{}
	bundles := []agentNativeGrantRawBundle{}
	for _, id := range order {
		m := metas[id]
		preview := previewMeta[m.row.PreviewID]
		if err = tx.QueryRow(ctx, `SELECT original,request FROM native_grants WHERE environment_id=$1 AND user_id=$2 AND id=$3`, p.EnvironmentID.String(), p.UserID.String(), id.String()).Scan(&m.row.Original, &m.row.Request); err != nil {
			return nil, err
		}
		if int64(len(m.row.Original)) != m.originalBytes || int64(len(m.row.Request)) != m.requestBytes {
			return agentGrantUnavailable("EVIDENCE_INVALID")
		}
		if raw, cached := previewRaw[preview.row.ID]; cached {
			preview.row.Original = raw
		} else {
			if err = tx.QueryRow(ctx, `SELECT original FROM native_grant_previews WHERE environment_id=$1 AND user_id=$2 AND id=$3`, p.EnvironmentID.String(), p.UserID.String(), preview.row.ID.String()).Scan(&preview.row.Original); err != nil {
				return nil, err
			}
			if int64(len(preview.row.Original)) != preview.originalBytes {
				return agentGrantUnavailable("EVIDENCE_INVALID")
			}
			previewRaw[preview.row.ID] = preview.row.Original
		}
		// Reuse the existing latest/terms/preview verifier on this same tx.
		view, e := loadNativeStandingGrant(ctx, tx, p, id)
		if e != nil {
			return agentGrantReadFailure(e)
		}
		bundle := agentNativeGrantRawBundle{Scope: nativeAutomationScope(p), AsOf: snapshot.AsOf, Grant: m.row, Preview: preview.row, Projection: projections[id], HistoricalVersions: historical, CurrentViews: current, OwnedAccountIDs: ownedAccounts, OwnedGoalIDs: ownedGoals}
		rows, err = tx.Query(ctx, `SELECT id::text,grant_id::text,grant_version,sequence,session_id::text,action,old_state,new_state,original,original_hash::text,created_at FROM native_grant_state_events WHERE environment_id=$1 AND user_id=$2 AND grant_id=$3 ORDER BY sequence,id LIMIT 257`, p.EnvironmentID.String(), p.UserID.String(), id.String())
		if err != nil {
			return nil, err
		}
		var rawBytes int64
		for rows.Next() {
			var event agentNativeGrantEventRow
			var eid, gid, sid string
			if err = rows.Scan(&eid, &gid, &event.GrantVersion, &event.Sequence, &sid, &event.Action, &event.OldState, &event.NewState, &event.Original, &event.OriginalHash, &event.CreatedAt); err != nil {
				rows.Close()
				return nil, err
			}
			event.ID, err = agentGrantID(eid)
			if err != nil {
				rows.Close()
				return agentGrantReadFailure(err)
			}
			event.GrantID, err = agentGrantID(gid)
			if err != nil {
				rows.Close()
				return agentGrantReadFailure(err)
			}
			event.SessionID, err = agentGrantID(sid)
			if err != nil {
				rows.Close()
				return agentGrantReadFailure(err)
			}
			if len(bundle.Events) >= agentGrantEventLimit || len(event.Original) < 1 || len(event.Original) > 8192 {
				rows.Close()
				return agentGrantUnavailable("CAPACITY")
			}
			rawBytes += int64(len(event.Original))
			bundle.Events = append(bundle.Events, event)
			subjectIDs[event.SessionID] = true
		}
		err = rows.Err()
		rows.Close()
		if err != nil {
			return nil, err
		}
		if int64(len(bundle.Events)) != eventMeta[id].count || rawBytes != eventMeta[id].bytes {
			return agentGrantUnavailable("EVIDENCE_INVALID")
		}
		subjectIDs[m.row.SessionID], subjectIDs[preview.row.SessionID] = true, true
		for _, ref := range view.Grant.Terms.Policies {
			historicalIDs[ref.VersionID] = true
			if len(historicalIDs) > 1600 {
				return agentGrantUnavailable("CAPACITY")
			}
		}
		bundles = append(bundles, bundle)
	}
	// New historical-policy loads share the existing 8MiB grant-original raw
	// budget rather than silently adding an unbounded evidence category.
	ids = ids[:0]
	for id := range historicalIDs {
		ids = append(ids, id.String())
	}
	sort.Strings(ids)
	if len(ids) != 0 {
		rows, err = tx.Query(ctx, `SELECT v.id::text,octet_length(v.original),octet_length(v.configuration),octet_length(c.original),octet_length(e.original) FROM template_policy_versions v JOIN template_policy_confirmations c ON(c.environment_id=v.environment_id AND c.user_id=v.user_id AND c.id=v.confirmation_id) JOIN template_policy_status_events e ON(e.environment_id=v.environment_id AND e.user_id=v.user_id AND e.id=v.status_event_id) WHERE v.environment_id=$1 AND v.user_id=$2 AND v.id=ANY($3::uuid[]) ORDER BY v.id LIMIT 1601`, p.EnvironmentID.String(), p.UserID.String(), ids)
		if err != nil {
			return nil, err
		}
		seen := map[funds.ID]bool{}
		for rows.Next() {
			var raw string
			var lengths [4]int64
			if err = rows.Scan(&raw, &lengths[0], &lengths[1], &lengths[2], &lengths[3]); err != nil {
				rows.Close()
				return nil, err
			}
			id, e := agentGrantID(raw)
			if e != nil {
				rows.Close()
				return agentGrantReadFailure(e)
			}
			if !historicalIDs[id] || seen[id] {
				rows.Close()
				return agentGrantUnavailable("EVIDENCE_INVALID")
			}
			seen[id] = true
			for _, length := range lengths {
				if length < 1 || grantBytes > agentGrantRawLimit-length {
					rows.Close()
					return agentGrantUnavailable("CAPACITY")
				}
				grantBytes += length
			}
		}
		err = rows.Err()
		rows.Close()
		if err != nil {
			return nil, err
		}
		if len(seen) != len(historicalIDs) {
			return agentGrantUnavailable("EVIDENCE_INVALID")
		}
		for _, raw := range ids {
			id, e := agentGrantID(raw)
			if e != nil {
				return agentGrantReadFailure(e)
			}
			versions, e := s.loadTemplatePoliciesAt(ctx, tx, p, &id)
			if e != nil {
				return agentGrantReadFailure(e)
			}
			if len(versions) != 1 {
				return agentGrantUnavailable("EVIDENCE_INVALID")
			}
			historical[id] = versions[0]
		}
	}
	if len(subjectIDs) > agentGrantSubjectLimit {
		return agentGrantUnavailable("CAPACITY")
	}
	ids = ids[:0]
	for id := range subjectIDs {
		ids = append(ids, id.String())
	}
	sort.Strings(ids)
	subjects := map[funds.ID]agentNativeGrantSubject{}
	if len(ids) != 0 {
		rows, err = tx.Query(ctx, `SELECT id::text,environment_id::text,user_id::text,expires_at,revoked FROM audit_session_subjects WHERE environment_id=$1 AND user_id=$2 AND id=ANY($3::uuid[]) ORDER BY id`, p.EnvironmentID.String(), p.UserID.String(), ids)
		if err != nil {
			return nil, err
		}
		bytes := 2 // JSON array brackets, then exact per-subject bytes and commas.
		for rows.Next() {
			var subject agentNativeGrantSubject
			var id, env, user string
			if err = rows.Scan(&id, &env, &user, &subject.ExpiresAt, &subject.Revoked); err != nil {
				rows.Close()
				return nil, err
			}
			subject.ID, err = agentGrantID(id)
			if err != nil {
				rows.Close()
				return agentGrantReadFailure(err)
			}
			subject.Scope.EnvironmentID, err = agentGrantID(env)
			if err != nil {
				rows.Close()
				return agentGrantReadFailure(err)
			}
			subject.Scope.UserID, err = agentGrantID(user)
			if err != nil {
				rows.Close()
				return agentGrantReadFailure(err)
			}
			if !subjectIDs[subject.ID] || len(subjects) >= agentGrantSubjectLimit {
				rows.Close()
				return agentGrantUnavailable("CAPACITY")
			}
			if _, duplicate := subjects[subject.ID]; duplicate {
				rows.Close()
				return agentGrantUnavailable("EVIDENCE_INVALID")
			}
			raw, e := json.Marshal(subject)
			if e != nil {
				rows.Close()
				return agentGrantUnavailable("EVIDENCE_INVALID")
			}
			if len(subjects) != 0 {
				bytes++
			}
			bytes += len(raw)
			if bytes > 512*1024 {
				rows.Close()
				return agentGrantUnavailable("CAPACITY")
			}
			subjects[subject.ID] = subject
		}
		err = rows.Err()
		rows.Close()
		if err != nil {
			return nil, err
		}
	}
	if len(subjects) != len(subjectIDs) {
		return agentGrantUnavailable("SUBJECT_UNAVAILABLE")
	}
	for i := range bundles {
		bundles[i].Subjects = subjects
	}
	if err = validateAgentNativeGrantRawBudgets(bundles); err != nil {
		return agentGrantReadFailure(err)
	}
	displays := []agent.NativeGrantDisplay{}
	sessionVerification := "SCOPED_SUBJECT_AND_EVENT_EXPIRY_ONLY"
	for _, bundle := range bundles {
		verified, e := validateAgentNativeGrantBundle(bundle)
		if e != nil {
			return agentGrantReadFailure(e)
		}
		g, terms := verified.View.Grant, verified.View.Grant.Terms
		if verified.SessionVerification == "HISTORY_INCOMPLETE" {
			sessionVerification = "HISTORY_INCOMPLETE"
		}
		displays = append(displays, agent.NativeGrantDisplay{ID: g.ID.String(), Version: g.Version, Family: terms.Family, RecordedState: verified.View.State, EffectiveState: verified.EffectiveState, StateSequence: verified.View.StateSequence, StateAt: verified.View.StateAt, EffectiveFrom: terms.EffectiveFrom, ExpiresAt: terms.ExpiresAt, EvaluatedLocalDate: verified.EvaluatedLocalDate, Timezone: terms.Timezone, PolicyReferences: terms.Policies, AccountIDs: terms.AccountIDs, GoalIDs: terms.GoalIDs, ProductIDs: terms.ProductIDs, PayeeIDs: terms.PayeeIDs, SingleCap: terms.SingleCap, LifetimeCap: terms.LifetimeCap, MonthlyCap: terms.MonthlyCap, OriginalDigest: verified.OriginalDigest, TermsDigest: verified.TermsDigest, ChainDigest: verified.ChainDigest, ReasonCodes: verified.ReasonCodes})
	}
	raw, err := json.Marshal(displays)
	if err != nil {
		return agentGrantUnavailable("EVIDENCE_INVALID")
	}
	if len(raw) > 512*1024 {
		return agentGrantUnavailable("CAPACITY")
	}
	collection, err := agent.NewNativeGrantCollection(snapshot.Scope, displays, sessionVerification)
	if errors.Is(err, agent.ErrBudget) {
		return agentGrantUnavailable("CAPACITY")
	}
	if err != nil {
		return agentGrantUnavailable("EVIDENCE_INVALID")
	}
	return collection, nil
}
