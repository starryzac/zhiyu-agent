package app

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"math"
	"time"

	"github.com/jackc/pgx/v5"
	funds "zhiyu.local/zhiyu-go/internal/funds/domain"
	planning "zhiyu.local/zhiyu-go/internal/planning/domain"
	policy "zhiyu.local/zhiyu-go/internal/policy/domain"
)

const StandingConsumer = "standing-allocate-goal-v1"
const StandingDiscoveryBatch = 64

var ErrStandingClaimLost = errors.New("standing claim no longer current")

type standingEvent struct {
	ID            funds.ID
	EnvironmentID funds.ID
	UserID        funds.ID
	Kind          string
	Payload       []byte
	CreatedAt     time.Time
}

type standingProof struct {
	Protocol, Namespace                                            string
	EnvironmentID, UserID, AccountID, GoalID, OriginID, EvidenceID funds.ID
	Amount                                                         funds.Money
	OccurredAt                                                     time.Time
	Authority                                                      DemoAuthority
}

type standingBinding struct {
	EnvironmentID, UserID, EventID, OriginID funds.ID
	Authority                                DemoAuthority
	AcceptKey                                string
	PlanID, OperationID                      *funds.ID
	EventOriginal                            []byte
	EventHash                                string
	EventAt, IncomeAt                        time.Time
}

func standingStrict(raw []byte, v any) error {
	if len(raw) == 0 || len(raw) > 64*1024 {
		return errors.New("unsupported standing original capacity")
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if err := d.Decode(v); err != nil {
		return err
	}
	var extra any
	if d.Decode(&extra) != io.EOF {
		return errors.New("trailing standing original")
	}
	return nil
}

func standingKey(b standingBinding) string {
	raw, _ := encode(struct {
		Protocol                                 string
		EnvironmentID, UserID, EventID, OriginID funds.ID
		Authority                                DemoAuthority
		Family                                   string
	}{StandingConsumer, b.EnvironmentID, b.UserID, b.EventID, b.OriginID, b.Authority, "ALLOCATE_GOAL"})
	return "standing_" + Hash(raw)
}

func (s *Service) ensureStanding(ctx context.Context, tx pgx.Tx) (Environment, error) {
	env, err := s.environment(ctx, tx, false)
	if err != nil {
		return env, err
	}
	_, err = tx.Exec(ctx, `INSERT INTO standing_consumers(environment_id,consumer_name) VALUES($1,$2) ON CONFLICT DO NOTHING`, env.ID.String(), StandingConsumer)
	return env, err
}

// DiscoverStanding copies each event once into this consumer's own inbox. It
// never updates outbox.processed_at and never creates a financial reservation.
// Anti-join discovery admits late events without a lossy time watermark.
func (s *Service) DiscoverStanding(ctx context.Context) (int, error) {
	tx, err := s.begin(ctx)
	if err != nil {
		return 0, err
	}
	defer rollback(ctx, tx)
	env, err := s.ensureStanding(ctx, tx)
	if err != nil {
		return 0, err
	}
	var paused bool
	if err = tx.QueryRow(ctx, `SELECT paused FROM standing_consumers WHERE environment_id=$1 AND consumer_name=$2 FOR SHARE`, env.ID.String(), StandingConsumer).Scan(&paused); err != nil {
		return 0, err
	}
	if paused {
		return 0, tx.Commit(ctx)
	}
	rows, err := tx.Query(ctx, `SELECT o.id::text,o.user_id::text,o.kind,o.payload,o.created_at FROM outbox o WHERE o.environment_id=$1 AND o.kind='INCOME_IMPORTED' AND NOT EXISTS(SELECT 1 FROM standing_event_receipts r WHERE r.environment_id=o.environment_id AND r.user_id=o.user_id AND r.event_id=o.id AND r.consumer_name=$2) ORDER BY o.created_at,o.id LIMIT $3`, env.ID.String(), StandingConsumer, StandingDiscoveryBatch)
	if err != nil {
		return 0, err
	}
	var events []standingEvent
	for rows.Next() {
		var id, user string
		event := standingEvent{EnvironmentID: env.ID}
		if err = rows.Scan(&id, &user, &event.Kind, &event.Payload, &event.CreatedAt); err != nil {
			rows.Close()
			return 0, err
		}
		event.ID, err = funds.ParseID(id)
		if err != nil {
			rows.Close()
			return 0, err
		}
		event.UserID, err = funds.ParseID(user)
		if err != nil {
			rows.Close()
			return 0, err
		}
		event.CreatedAt = event.CreatedAt.UTC()
		events = append(events, event)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return 0, err
	}
	registered := 0
	for _, event := range events {
		original, err := encode(event)
		if err != nil {
			return 0, err
		}
		digest := Hash(original)
		binding, reason, err := s.standingSource(ctx, tx, event)
		if err != nil {
			return 0, err
		}
		outcome := "REGISTERED"
		if reason != "" {
			outcome = "INVALID"
			if reason == "UNSUPPORTED_SOURCE_PROOF" {
				outcome = "UNSUPPORTED"
			}
		}
		tag, err := tx.Exec(ctx, `INSERT INTO standing_event_receipts(environment_id,user_id,consumer_name,event_id,event_original,event_hash,outcome,reason) VALUES($1,$2,$3,$4,$5,$6,$7,$8) ON CONFLICT DO NOTHING`, env.ID.String(), event.UserID.String(), StandingConsumer, event.ID.String(), original, digest, outcome, reason)
		if err != nil {
			return 0, err
		}
		if tag.RowsAffected() == 0 || reason != "" {
			continue
		}
		binding.AcceptKey = standingKey(binding)
		tag, err = tx.Exec(ctx, `INSERT INTO standing_inbox(environment_id,user_id,consumer_name,event_id,origin_id,policy_id,policy_version,grant_id,grant_version,family,accept_key) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,'ALLOCATE_GOAL',$10) ON CONFLICT DO NOTHING`, env.ID.String(), binding.UserID.String(), StandingConsumer, binding.EventID.String(), binding.OriginID.String(), binding.Authority.PolicyID.String(), binding.Authority.PolicyVersion, binding.Authority.GrantID.String(), binding.Authority.GrantVersion, binding.AcceptKey)
		if err != nil {
			return 0, err
		}
		if tag.RowsAffected() == 1 {
			registered++
		}
	}
	return registered, tx.Commit(ctx)
}

// standingSource accepts only the implemented immutable synthetic-bank source
// proof. It never selects a convenient current grant for an old income event.
func (s *Service) standingSource(ctx context.Context, tx pgx.Tx, event standingEvent) (standingBinding, string, error) {
	b := standingBinding{EnvironmentID: event.EnvironmentID, UserID: event.UserID, EventID: event.ID, EventAt: event.CreatedAt}
	var payload struct {
		OriginID      funds.ID `json:"origin_id"`
		SourceVersion uint64   `json:"source_version"`
	}
	if standingStrict(event.Payload, &payload) != nil || payload.OriginID == (funds.ID{}) || payload.SourceVersion == 0 || payload.SourceVersion > math.MaxInt64 {
		return b, "INVALID_SOURCE_EVENT", nil
	}
	b.OriginID = payload.OriginID
	var account, evidence, digest, currency string
	var amount int64
	var occurred, observed, recorded time.Time
	err := tx.QueryRow(ctx, `SELECT original_account_id::text,currency,amount_cents,occurred_at,observed_at,recorded_at,evidence_id::text,evidence_hash::text FROM income_origins WHERE environment_id=$1 AND user_id=$2 AND id=$3`, b.EnvironmentID.String(), b.UserID.String(), b.OriginID.String()).Scan(&account, &currency, &amount, &occurred, &observed, &recorded, &evidence, &digest)
	if errors.Is(err, pgx.ErrNoRows) {
		return b, "MISSING_SOURCE_ORIGINAL", nil
	}
	if err != nil {
		return b, "", err
	}
	if currency != "CNY" || occurred.After(event.CreatedAt) || observed.After(event.CreatedAt) || recorded.After(event.CreatedAt) {
		return b, "EVENT_SOURCE_TIME_CONFLICT", nil
	}
	var raw []byte
	var blobHash, kind string
	err = tx.QueryRow(ctx, `SELECT canonical,digest,kind FROM evidence_blobs WHERE environment_id=$1 AND user_id=$2 AND id=$3`, b.EnvironmentID.String(), b.UserID.String(), evidence).Scan(&raw, &blobHash, &kind)
	if errors.Is(err, pgx.ErrNoRows) {
		return b, "UNSUPPORTED_SOURCE_PROOF", nil
	}
	if err != nil {
		return b, "", err
	}
	if kind != "EXPLICIT_SIMULATED_BANK_INCOME" {
		return b, "UNSUPPORTED_SOURCE_PROOF", nil
	}
	if Hash(raw) != blobHash || blobHash != digest {
		return b, "SOURCE_HASH_CONFLICT", nil
	}
	var proof standingProof
	if standingStrict(raw, &proof) != nil || proof.Protocol != "explicit-synthetic-bank-income-v1" {
		return b, "UNSUPPORTED_SOURCE_PROOF", nil
	}
	if proof.Namespace != s.Namespace || proof.EnvironmentID != b.EnvironmentID || proof.UserID != b.UserID || proof.OriginID != b.OriginID || proof.AccountID.String() != account || proof.EvidenceID.String() != evidence || proof.Amount.Cents() != amount || !proof.OccurredAt.Equal(occurred) || proof.OccurredAt.Before(proof.Authority.EffectiveFrom) {
		return b, "SOURCE_SCOPE_OR_IDENTITY_CONFLICT", nil
	}
	var supported bool
	err = tx.QueryRow(ctx, `SELECT u.source_version >= $3 AND EXISTS(SELECT 1 FROM protection_snapshots p WHERE p.environment_id=u.environment_id AND p.user_id=u.id AND p.version=$3) FROM users u WHERE u.environment_id=$1 AND u.id=$2`, b.EnvironmentID.String(), b.UserID.String(), payload.SourceVersion).Scan(&supported)
	if err != nil {
		return b, "", err
	}
	if !supported {
		return b, "MISSING_SOURCE_EPOCH", nil
	}
	b.Authority = proof.Authority
	b.IncomeAt = occurred.UTC()
	if b.Authority.PolicyID == (funds.ID{}) || b.Authority.GrantID == (funds.ID{}) || b.Authority.PolicyVersion == 0 || b.Authority.GrantVersion == 0 || b.Authority.PolicyVersion > math.MaxInt64 || b.Authority.GrantVersion > math.MaxInt64 {
		return b, "MISSING_ORIGINAL_AUTHORITY", nil
	}
	var pr, gr []byte
	err = tx.QueryRow(ctx, `SELECT p.original,g.original FROM policies p JOIN grants g ON(g.environment_id=p.environment_id AND g.user_id=p.user_id AND g.policy_id=p.id AND g.policy_version=p.version) WHERE p.environment_id=$1 AND p.user_id=$2 AND p.id=$3 AND p.version=$4 AND g.id=$5 AND g.version=$6`, b.EnvironmentID.String(), b.UserID.String(), b.Authority.PolicyID.String(), b.Authority.PolicyVersion, b.Authority.GrantID.String(), b.Authority.GrantVersion).Scan(&pr, &gr)
	if errors.Is(err, pgx.ErrNoRows) {
		return b, "MISSING_ORIGINAL_AUTHORITY", nil
	}
	if err != nil {
		return b, "", err
	}
	var pol policy.Policy
	var grant policy.Grant
	if decode(pr, &pol) != nil || decode(gr, &grant) != nil {
		return b, "INVALID_ORIGINAL_AUTHORITY", nil
	}
	if pol.ID != b.Authority.PolicyID || pol.Version != b.Authority.PolicyVersion || pol.Scope.EnvironmentID != b.EnvironmentID || pol.Scope.UserID != b.UserID || grant.ID != b.Authority.GrantID || grant.Version != b.Authority.GrantVersion {
		return b, "INVALID_ORIGINAL_AUTHORITY", nil
	}
	p := Principal{EnvironmentID: b.EnvironmentID, UserID: b.UserID, Kind: "SYSTEM"}
	if checkConfirmation(ctx, tx, p, pol.Confirmation) != nil || checkConfirmation(ctx, tx, p, grant.Confirmation) != nil {
		return b, "INVALID_ORIGINAL_AUTHORITY", nil
	}
	window, err := policy.CheckGrant(pol, grant, occurred)
	if err != nil || !window.EffectiveFrom.Equal(b.Authority.EffectiveFrom) || pol.Scope.GoalID != proof.GoalID || pol.Scope.SourceAccountID != proof.AccountID || pol.Scope.DestinationAccountID != proof.AccountID {
		return b, "INVALID_ORIGINAL_AUTHORITY", nil
	}
	return b, "", nil
}

type standingClaim struct {
	Principal             Principal
	AcceptKey, Owner      string
	Generation            uint64
	Attempts, MaxAttempts int
}

func (s *Service) claimStanding(ctx context.Context, owner string, lease time.Duration) (*standingClaim, error) {
	if owner == "" || len(owner) > 128 || lease < time.Millisecond || lease > time.Minute {
		return nil, reject("INVALID_WORKER_CONFIGURATION", nil)
	}
	tx, err := s.begin(ctx)
	if err != nil {
		return nil, err
	}
	defer rollback(ctx, tx)
	if _, err = s.environment(ctx, tx, true); err != nil {
		return nil, err
	}
	_, err = tx.Exec(ctx, `UPDATE standing_inbox i SET state='EXHAUSTED',last_error='LEASE_EXPIRED_AT_RETRY_LIMIT',lease_owner=NULL,lease_until=NULL,finished_at=clock_timestamp() FROM environments e WHERE e.id=i.environment_id AND e.namespace=$1 AND i.consumer_name=$2 AND i.occurrence_owner AND i.state='RUNNING' AND i.lease_until<=clock_timestamp() AND i.attempts>=i.max_attempts`, s.Namespace, StandingConsumer)
	if err != nil {
		return nil, err
	}
	var env, user string
	var c standingClaim
	err = tx.QueryRow(ctx, `WITH picked AS(SELECT i.environment_id,i.user_id,i.accept_key FROM standing_inbox i JOIN standing_consumers c USING(environment_id,consumer_name) JOIN environments e ON(e.id=i.environment_id) WHERE e.namespace=$1 AND i.consumer_name=$2 AND i.occurrence_owner AND NOT c.paused AND NOT i.paused AND i.state IN('READY','RUNNING') AND i.attempts<i.max_attempts AND i.next_attempt_at<=clock_timestamp() AND (i.lease_until IS NULL OR i.lease_until<=clock_timestamp()) ORDER BY i.next_attempt_at,i.event_id FOR UPDATE OF i SKIP LOCKED LIMIT 1) UPDATE standing_inbox i SET state='RUNNING',claim_generation=i.claim_generation+1,lease_owner=$3,lease_until=clock_timestamp()+$4::bigint*interval '1 millisecond',attempts=i.attempts+1 FROM picked p WHERE i.environment_id=p.environment_id AND i.user_id=p.user_id AND i.accept_key=p.accept_key RETURNING i.environment_id::text,i.user_id::text,i.accept_key,i.claim_generation,i.attempts,i.max_attempts`, s.Namespace, StandingConsumer, owner, lease.Milliseconds()).Scan(&env, &user, &c.AcceptKey, &c.Generation, &c.Attempts, &c.MaxAttempts)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	c.Principal.EnvironmentID, err = funds.ParseID(env)
	if err != nil {
		return nil, err
	}
	c.Principal.UserID, err = funds.ParseID(user)
	if err != nil {
		return nil, err
	}
	c.Principal.Kind = "SYSTEM"
	c.Owner = owner
	if err = tx.Commit(ctx); err != nil {
		return nil, err
	}
	return &c, nil
}

// standingGuard holds only the consumer control share lock. It never holds a
// funds lock and is never open across bank I/O. Accept obtains its own normal
// T1 transaction. A pause update waits for a previously admitted T1 to finish.
func (s *Service) standingGuard(ctx context.Context, c standingClaim) (pgx.Tx, standingBinding, bool, error) {
	var b standingBinding
	tx, err := s.begin(ctx)
	if err != nil {
		return nil, b, false, err
	}
	ok := false
	defer func() {
		if !ok {
			rollback(ctx, tx)
		}
	}()
	var paused bool
	err = tx.QueryRow(ctx, `SELECT c.paused FROM standing_consumers c JOIN environments e ON(e.id=c.environment_id) WHERE c.environment_id=$1 AND c.consumer_name=$2 AND e.namespace=$3 FOR SHARE OF c`, c.Principal.EnvironmentID.String(), StandingConsumer, s.Namespace).Scan(&paused)
	if err != nil {
		return nil, b, false, err
	}
	var eid, origin, pid, gid string
	var plan, op *string
	var pv, gv uint64
	var live bool
	err = tx.QueryRow(ctx, `SELECT i.event_id::text,i.origin_id::text,i.policy_id::text,i.policy_version,i.grant_id::text,i.grant_version,i.plan_id::text,i.operation_id::text,r.event_original,r.event_hash::text,i.claim_generation=$4 AND i.lease_owner=$5 AND i.lease_until>clock_timestamp() AND i.state='RUNNING' AND i.occurrence_owner AND NOT i.paused FROM standing_inbox i JOIN standing_event_receipts r USING(environment_id,user_id,consumer_name,event_id) WHERE i.environment_id=$1 AND i.user_id=$2 AND i.accept_key=$3`, c.Principal.EnvironmentID.String(), c.Principal.UserID.String(), c.AcceptKey, c.Generation, c.Owner).Scan(&eid, &origin, &pid, &pv, &gid, &gv, &plan, &op, &b.EventOriginal, &b.EventHash, &live)
	if err != nil {
		return nil, b, false, err
	}
	if !live {
		return nil, b, false, ErrStandingClaimLost
	}
	b.EnvironmentID = c.Principal.EnvironmentID
	b.UserID = c.Principal.UserID
	b.AcceptKey = c.AcceptKey
	b.EventID, err = funds.ParseID(eid)
	if err != nil {
		return nil, b, false, err
	}
	b.OriginID, err = funds.ParseID(origin)
	if err != nil {
		return nil, b, false, err
	}
	b.Authority.PolicyID, err = funds.ParseID(pid)
	if err != nil {
		return nil, b, false, err
	}
	b.Authority.GrantID, err = funds.ParseID(gid)
	if err != nil {
		return nil, b, false, err
	}
	b.Authority.PolicyVersion = pv
	b.Authority.GrantVersion = gv
	if plan != nil {
		id, e := funds.ParseID(*plan)
		if e != nil {
			return nil, b, false, e
		}
		b.PlanID = &id
	}
	if op != nil {
		id, e := funds.ParseID(*op)
		if e != nil {
			return nil, b, false, e
		}
		b.OperationID = &id
	}
	var event standingEvent
	if Hash(b.EventOriginal) != b.EventHash || standingStrict(b.EventOriginal, &event) != nil || event.ID != b.EventID || event.EnvironmentID != b.EnvironmentID || event.UserID != b.UserID {
		return nil, b, false, reject("EVIDENCE_INVALID", nil)
	}
	original, reason, err := s.standingSource(ctx, tx, event)
	if err != nil {
		return nil, b, false, err
	}
	if reason != "" || original.OriginID != b.OriginID || original.Authority.PolicyID != b.Authority.PolicyID || original.Authority.PolicyVersion != b.Authority.PolicyVersion || original.Authority.GrantID != b.Authority.GrantID || original.Authority.GrantVersion != b.Authority.GrantVersion || standingKey(original) != b.AcceptKey {
		return nil, b, false, reject("EVIDENCE_INVALID", nil)
	}
	b.EventAt = original.EventAt
	b.IncomeAt = original.IncomeAt
	b.Authority.EffectiveFrom = original.Authority.EffectiveFrom
	ok = true
	return tx, b, paused, nil
}

func standingFinish(ctx context.Context, tx pgx.Tx, c standingClaim, state, reason string, plan, operation *funds.ID) error {
	var p, o any
	if plan != nil {
		p = plan.String()
	}
	if operation != nil {
		o = operation.String()
	}
	tag, err := tx.Exec(ctx, `UPDATE standing_inbox SET plan_id=COALESCE(plan_id,$6::uuid),operation_id=COALESCE(operation_id,$7::uuid),state=$8,last_error=$9,lease_owner=NULL,lease_until=NULL,finished_at=CASE WHEN $8 IN('ACCEPTED','NO_ACTION','BLOCKED','EXHAUSTED') THEN clock_timestamp() ELSE NULL END,next_attempt_at=clock_timestamp() WHERE environment_id=$1 AND user_id=$2 AND accept_key=$3 AND claim_generation=$4 AND lease_owner=$5 AND lease_until>clock_timestamp() AND state='RUNNING'`, c.Principal.EnvironmentID.String(), c.Principal.UserID.String(), c.AcceptKey, c.Generation, c.Owner, p, o, state, reason)
	if err != nil {
		return err
	}
	if tag.RowsAffected() != 1 {
		return ErrStandingClaimLost
	}
	return nil
}

func (s *Service) standingCurrent(ctx context.Context, tx pgx.Tx, c standingClaim, b standingBinding) error {
	p, err := loadPolicy(ctx, tx, c.Principal, b.Authority.PolicyID, false)
	if err != nil {
		return err
	}
	g, err := loadGrant(ctx, tx, c.Principal, b.Authority.GrantID, false)
	if err != nil {
		return err
	}
	if p.Version != b.Authority.PolicyVersion || g.Version != b.Authority.GrantVersion {
		return reject("SOURCE_CHANGED", nil)
	}
	if _, err = policy.CheckGrant(p, g, s.now()); err != nil {
		return reject("AUTHORIZATION_REVOKED", err)
	}
	return nil
}

func (s *Service) standingExisting(ctx context.Context, c standingClaim, b standingBinding) (*Operation, error) {
	op, err := s.OperationByKey(ctx, c.Principal, c.AcceptKey)
	if Code(err) == "NOT_FOUND" {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if b.PlanID == nil || op.PlanID != *b.PlanID {
		return nil, reject("IDEMPOTENCY_CONFLICT", nil)
	}
	raw, err := encode(OperationRequest{PlanID: *b.PlanID, GrantID: &b.Authority.GrantID, Mode: "STANDING"})
	if err != nil {
		return nil, err
	}
	var valid bool
	err = s.Pool.QueryRow(ctx, `SELECT request_hash=$4 AND request=$5 AND policy_id=$6::uuid AND policy_version=$7 AND grant_id=$8::uuid AND grant_version=$9 FROM operations WHERE environment_id=$1 AND user_id=$2 AND id=$3`, b.EnvironmentID.String(), b.UserID.String(), op.ID.String(), Hash(raw), raw, b.Authority.PolicyID.String(), b.Authority.PolicyVersion, b.Authority.GrantID.String(), b.Authority.GrantVersion).Scan(&valid)
	if err != nil {
		return nil, err
	}
	if !valid {
		return nil, reject("IDEMPOTENCY_CONFLICT", nil)
	}
	return &op, nil
}

func standingCandidate(c planning.Candidate, b standingBinding) error {
	if c.Kind != funds.AllocateGoal || c.PolicyID != b.Authority.PolicyID || c.PolicyVersion != b.Authority.PolicyVersion || c.Dependencies.GrantVersion != b.Authority.GrantVersion || c.Scope.EnvironmentID != b.EnvironmentID || c.Scope.UserID != b.UserID {
		return reject("STANDING_SCOPE_UNSUPPORTED", nil)
	}
	if c.Status != "READY" || c.Amount.IsZero() {
		return nil
	}
	if len(c.Uses) != 1 || c.Uses[0].OriginID != b.OriginID || !c.EarliestIncomeAt.Equal(b.IncomeAt) || c.EarliestIncomeAt.After(b.EventAt) {
		return reject("STANDING_SCOPE_UNSUPPORTED", nil)
	}
	return nil
}

func (s *Service) standingRetry(ctx context.Context, c standingClaim, cause error) error {
	state := "READY"
	reason := Code(cause)
	switch reason {
	case "SOURCE_CHANGED", "GOAL_OPERATION_PENDING", "AUTHORIZATION_REVOKED", "NOT_FOUND", "EVIDENCE_INVALID", "EVIDENCE_INCOMPLETE", "STANDING_SCOPE_UNSUPPORTED", "IDEMPOTENCY_CONFLICT", "PLANNING_REJECTED", "UNSUPPORTED_MULTI_SOURCE", "INSUFFICIENT_FUNDS", "NATIVE_GOAL_AUTHORIZATION_REQUIRED":
		state = "BLOCKED"
	}
	if state == "READY" && c.Attempts >= c.MaxAttempts {
		state = "EXHAUSTED"
	}
	delay := 100 * time.Millisecond
	for n := 1; n < c.Attempts && delay < 5*time.Second; n++ {
		delay *= 2
	}
	if delay > 5*time.Second {
		delay = 5 * time.Second
	}
	tag, err := s.writerExec(ctx, `UPDATE standing_inbox SET state=$6,last_error=$7,lease_owner=NULL,lease_until=NULL,next_attempt_at=clock_timestamp()+$8::bigint*interval '1 millisecond',finished_at=CASE WHEN $6 IN('BLOCKED','EXHAUSTED') THEN clock_timestamp() ELSE NULL END WHERE environment_id=$1 AND user_id=$2 AND accept_key=$3 AND claim_generation=$4 AND lease_owner=$5 AND state='RUNNING' AND lease_until>clock_timestamp()`, c.Principal.EnvironmentID.String(), c.Principal.UserID.String(), c.AcceptKey, c.Generation, c.Owner, state, reason, delay.Milliseconds())
	if err != nil {
		return err
	}
	if tag.RowsAffected() != 1 {
		return ErrStandingClaimLost
	}
	return nil
}

// StandingStep owns no bank I/O. It creates one stable candidate/acceptance or
// recovers that same T1 by key; the normal Worker owns all later bank recovery.
func (s *Service) StandingStep(ctx context.Context, owner string, lease time.Duration) (bool, error) {
	if _, err := s.DiscoverStanding(ctx); err != nil {
		return false, err
	}
	claim, err := s.claimStanding(ctx, owner, lease)
	if err != nil || claim == nil {
		return false, err
	}
	c := *claim
	err = s.processStanding(ctx, c)
	if errors.Is(err, ErrStandingClaimLost) {
		return true, err
	}
	if err != nil {
		if retryErr := s.standingRetry(ctx, c, err); retryErr != nil {
			return true, retryErr
		}
	}
	return true, nil
}

func (s *Service) processStanding(ctx context.Context, c standingClaim) error {
	// Phase 1 commits the pinned plan BEFORE any call that may commit T1.
	tx, b, paused, err := s.standingGuard(ctx, c)
	if err != nil {
		return err
	}
	if paused {
		err = standingFinish(ctx, tx, c, "READY", "CONSUMER_PAUSED", b.PlanID, nil)
		if err == nil {
			err = tx.Commit(ctx)
		} else {
			rollback(ctx, tx)
		}
		return err
	}
	if existing, e := s.standingExisting(ctx, c, b); e != nil {
		rollback(ctx, tx)
		return e
	} else if existing != nil {
		err = standingFinish(ctx, tx, c, "ACCEPTED", "RECOVERED_ORIGINAL_T1", b.PlanID, &existing.ID)
		if err == nil {
			err = tx.Commit(ctx)
		} else {
			rollback(ctx, tx)
		}
		return err
	}
	if err = s.standingCurrent(ctx, tx, c, b); err != nil {
		rollback(ctx, tx)
		return err
	}
	if b.PlanID == nil {
		candidate, e := s.Plan(ctx, c.Principal, PlanRequest{PolicyID: b.Authority.PolicyID})
		if e != nil {
			rollback(ctx, tx)
			return e
		}
		if err = standingCandidate(candidate, b); err != nil {
			rollback(ctx, tx)
			return err
		}
		b.PlanID = &candidate.ID
		if candidate.Status != "READY" || candidate.Amount.IsZero() {
			state := "BLOCKED"
			if candidate.Status == "NO_ACTION" {
				state = "NO_ACTION"
			}
			err = standingFinish(ctx, tx, c, state, candidate.Status, b.PlanID, nil)
			if err == nil {
				err = tx.Commit(ctx)
			} else {
				rollback(ctx, tx)
			}
			return err
		}
		tag, e := tx.Exec(ctx, `UPDATE standing_inbox SET plan_id=$6 WHERE environment_id=$1 AND user_id=$2 AND accept_key=$3 AND claim_generation=$4 AND lease_owner=$5 AND lease_until>clock_timestamp() AND state='RUNNING' AND plan_id IS NULL`, b.EnvironmentID.String(), b.UserID.String(), b.AcceptKey, c.Generation, c.Owner, b.PlanID.String())
		if e != nil {
			rollback(ctx, tx)
			return e
		}
		if tag.RowsAffected() != 1 {
			rollback(ctx, tx)
			return ErrStandingClaimLost
		}
	}
	if err = tx.Commit(ctx); err != nil {
		return err
	}
	if s.Failpoint != nil {
		if err = s.Failpoint("after_standing_plan_pin"); err != nil {
			return err
		}
	}
	// Phase 2 reacquires the control share lock and checks current permissions.
	// Pause may linearize between the phases and will then stop new acceptance.
	tx, b, paused, err = s.standingGuard(ctx, c)
	if err != nil {
		return err
	}
	defer rollback(ctx, tx)
	if paused {
		if err = standingFinish(ctx, tx, c, "READY", "CONSUMER_PAUSED", b.PlanID, nil); err != nil {
			return err
		}
		return tx.Commit(ctx)
	}
	if existing, e := s.standingExisting(ctx, c, b); e != nil {
		return e
	} else if existing != nil {
		if err = standingFinish(ctx, tx, c, "ACCEPTED", "RECOVERED_ORIGINAL_T1", b.PlanID, &existing.ID); err != nil {
			return err
		}
		return tx.Commit(ctx)
	}
	if err = s.standingCurrent(ctx, tx, c, b); err != nil {
		return err
	}
	if b.PlanID == nil {
		return reject("EVIDENCE_INVALID", nil)
	}
	if s.Failpoint != nil {
		if err = s.Failpoint("before_standing_accept"); err != nil {
			return err
		}
	}
	op, err := s.Accept(ctx, c.Principal, c.AcceptKey, OperationRequest{PlanID: *b.PlanID, GrantID: &b.Authority.GrantID, Mode: "STANDING"})
	if err != nil {
		// Accept may have committed before its response/failpoint was lost.
		existing, recoveryErr := s.standingExisting(ctx, c, b)
		if recoveryErr != nil {
			return recoveryErr
		}
		if existing == nil {
			return err
		}
		op = *existing
	}
	if s.Failpoint != nil {
		if err = s.Failpoint("after_standing_accept_commit"); err != nil {
			return err
		}
	}
	if err = standingFinish(ctx, tx, c, "ACCEPTED", "", b.PlanID, &op.ID); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// SetStandingPaused affects scheduling only. It never revokes or rewrites USER
// permission and never touches the normal Worker's already accepted UNKNOWN.
func (s *Service) SetStandingPaused(ctx context.Context, paused bool) error {
	tx, err := s.begin(ctx)
	if err != nil {
		return err
	}
	defer rollback(ctx, tx)
	env, err := s.ensureStanding(ctx, tx)
	if err != nil {
		return err
	}
	_, err = tx.Exec(ctx, `UPDATE standing_consumers SET paused=$3,version=version+1 WHERE environment_id=$1 AND consumer_name=$2 AND paused IS DISTINCT FROM $3`, env.ID.String(), StandingConsumer, paused)
	if err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func (s *Service) RunStanding(ctx context.Context, owner string) error {
	var databaseFailures uint
	for {
		if ctx.Err() != nil {
			return nil
		}
		worked, err := s.StandingStep(ctx, owner, 30*time.Second)
		if retryBackgroundDatabase(ctx, err, &databaseFailures) {
			continue
		}
		if err != nil && !errors.Is(err, ErrStandingClaimLost) {
			return err
		}
		if !worked || err != nil {
			timer := time.NewTimer(250 * time.Millisecond)
			select {
			case <-ctx.Done():
				timer.Stop()
				return nil
			case <-timer.C:
			}
		}
	}
}
