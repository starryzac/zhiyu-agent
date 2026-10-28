package app

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"hash"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"
	"zhiyu.local/zhiyu-go/internal/execution/bankcredit"
	"zhiyu.local/zhiyu-go/internal/execution/bankv2"
	policy "zhiyu.local/zhiyu-go/internal/policy/domain"
)

const nativeIdleEntries = 64
const nativeIdleMaxVerifiedAge = 5 * time.Minute

var errNativeIdleUnavailable = errors.New("daemon negative idle cursor unavailable")

type NativeDaemonHeadSource interface {
	Head(context.Context, string, string) (bankcredit.ObservationHead, error)
	ScopeBinding() string
	MatchesSources(credit, legacy, native any) bool
}

type nativeIdleFence struct {
	Scope                                                         policy.TemplateOwnerScope
	FundsVersion, SourceVersion, WriterGeneration, ControlVersion uint64
	Writer                                                        RecoveryWriterControl
	SchemaRevision                                                int64
	Timezone, Date, PolicyMetadataHash, HistoryMetadataHash       string
}

type nativeIdleCursor struct {
	key                          string
	head                         bankcredit.ObservationHead
	verifiedWall, asOf, boundary time.Time
}

type nativeDaemonIdle struct {
	source          NativeDaemonHeadSource
	binding, config string
	mu              sync.Mutex
	income, payment map[string]nativeIdleCursor
	wallNow         func() time.Time
}

// EnableNativeDaemonIdle is an explicit operator/constructor configuration.
// The source client must identify the exact three configured source instances.
// Configuration is frozen for this Service lifetime; restart/re-enable empties
// every cursor. An arbitrary optional method on another Source is insufficient.
func (s *Service) EnableNativeDaemonIdle(source NativeDaemonHeadSource, configurationHash string) error {
	if source == nil || s.NativeIncomeSources == nil || !auditDigestOK(configurationHash) || !auditDigestOK(source.ScopeBinding()) || !source.MatchesSources(s.NativeIncomeSources.Credit, s.NativeIncomeSources.Legacy, s.NativeIncomeSources.Native) {
		return errNativeIdleUnavailable
	}
	s.nativeIdle = &nativeDaemonIdle{source: source, binding: source.ScopeBinding(), config: configurationHash, income: map[string]nativeIdleCursor{}, payment: map[string]nativeIdleCursor{}, wallNow: time.Now}
	return nil
}

func (s *Service) daemonIdle() *nativeDaemonIdle {
	i := s.nativeIdle
	if i == nil {
		return nil
	}
	if s.NativeIncomeSources == nil || i.binding != i.source.ScopeBinding() || !i.source.MatchesSources(s.NativeIncomeSources.Credit, s.NativeIncomeSources.Legacy, s.NativeIncomeSources.Native) {
		i.mu.Lock()
		clear(i.income)
		clear(i.payment)
		i.mu.Unlock()
		return nil
	}
	return i
}

func (i *nativeDaemonIdle) forget(table map[string]nativeIdleCursor, id string) {
	if i == nil {
		return
	}
	i.mu.Lock()
	delete(table, id)
	i.mu.Unlock()
}

func (i *nativeDaemonIdle) forgetAllIncome() {
	if i == nil {
		return
	}
	i.mu.Lock()
	clear(i.income)
	i.mu.Unlock()
}
func (i *nativeDaemonIdle) forgetAllPayment() {
	if i == nil {
		return
	}
	i.mu.Lock()
	clear(i.payment)
	i.mu.Unlock()
}

func (s *Service) forgetNativeIncomeIntake(p Principal) {
	if s.nativeIdle != nil {
		s.nativeIdle.forget(s.nativeIdle.income, p.EnvironmentID.String()+"/"+p.UserID.String())
	}
}

func nativeIdleFrame(h hash.Hash, value string) {
	var n [8]byte
	binary.BigEndian.PutUint64(n[:], uint64(len(value)))
	h.Write(n[:])
	h.Write([]byte(value))
}

func nativeIdleMetadata(ctx context.Context, tx pgx.Tx, p Principal, query string, extra ...any) (string, error) {
	args := append([]any{p.EnvironmentID.String(), p.UserID.String()}, extra...)
	rows, e := tx.Query(ctx, query, args...)
	if e != nil {
		return "", e
	}
	h := sha256.New()
	count, total := 0, 0
	seen := map[string]bool{}
	for rows.Next() {
		var n int64
		var value *string
		if e = rows.Scan(&n, &value); e != nil {
			break
		}
		count++
		if value == nil || n < 0 || n > 16384 || int64(len(*value)) != n || count > 1000 || total+int(n)+8 > 4<<20 {
			e = errNativeIdleUnavailable
			break
		}
		total += int(n) + 8
		if seen[*value] {
			e = errNativeIdleUnavailable
			break
		}
		seen[*value] = true
		nativeIdleFrame(h, *value)
	}
	if end := rows.Err(); e == nil {
		e = end
	}
	rows.Close()
	if e != nil {
		return "", e
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func (s *Service) nativeIdleFence(ctx context.Context, tx pgx.Tx, p Principal) (nativeIdleFence, error) {
	out := nativeIdleFence{Scope: nativeAutomationScope(p)}
	// Goose's version ledger is owner-only. Reuse the app-readable registered
	// feature gate; this is a revision marker, not a full application-DDL proof.
	var writerControl, writerEvents, recoveryRuns, recoveryScans, recoveryObservations, fundsWitness, sourceWitness, terminalDecision bool
	if e := tx.QueryRow(ctx, `SELECT to_regclass('public.writer_controls') IS NOT NULL,to_regclass('public.writer_control_events') IS NOT NULL,to_regclass('public.recovery_runs') IS NOT NULL,to_regclass('public.recovery_bank_scans') IS NOT NULL,to_regclass('public.recovery_bank_observations') IS NOT NULL,to_regclass('public.funds_commit_witnesses') IS NOT NULL,to_regclass('public.template_source_witnesses') IS NOT NULL,to_regclass('public.funds_terminal_decisions') IS NOT NULL`).Scan(&writerControl, &writerEvents, &recoveryRuns, &recoveryScans, &recoveryObservations, &fundsWitness, &sourceWitness, &terminalDecision); e != nil || !writerControl || !writerEvents || !recoveryRuns || !recoveryScans || !recoveryObservations || !fundsWitness || !sourceWitness || !terminalDecision {
		return out, errNativeIdleUnavailable
	}
	revision, e := nativeAuditSchemaCatalogRevisionV3(true, fundsWitness, sourceWitness, terminalDecision)
	if e != nil || revision != 26 {
		return out, errNativeIdleUnavailable
	}
	out.SchemaRevision = int64(revision)
	env, e := s.environment(ctx, tx, true)
	if e != nil {
		return out, e
	}
	if e = sameUser(p, env.ID); e != nil {
		return out, e
	}
	out.FundsVersion, out.SourceVersion, e = lockUser(ctx, tx, p)
	if e != nil {
		return out, e
	}
	out.WriterGeneration, out.ControlVersion = env.WriterGeneration, env.ControlVersion
	var present bool
	out.Writer, present, e = recoveryControl(ctx, tx, env.ID)
	if e != nil || !present || s.WriterPin == nil || out.Writer.Mode != "ACTIVE" || out.Writer.OwnerID != s.WriterPin.OwnerID || out.Writer.Generation != s.WriterPin.Generation || out.Writer.Generation != env.WriterGeneration {
		return out, errNativeIdleUnavailable
	}
	var pending bool
	e = tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM operations WHERE environment_id=$1 AND user_id=$2 AND status NOT IN ('SETTLED','REJECTED','CANCELLED')) OR EXISTS(SELECT 1 FROM native_operations WHERE environment_id=$1 AND user_id=$2 AND status NOT IN ('SETTLED','REJECTED','CANCELLED'))`, p.EnvironmentID.String(), p.UserID.String()).Scan(&pending)
	if e != nil || pending {
		return out, errNativeIdleUnavailable
	}
	if e = ensureNativeBillsReady(ctx, tx, p); e != nil {
		return out, e
	}
	out.Timezone, e = templateScopedTimezone(ctx, tx, p, "")
	if e != nil {
		return out, e
	}
	zone, e := policy.TemplateLocation(out.Timezone)
	if e != nil {
		return out, e
	}
	out.Date = s.now().In(zone).Format("2006-01-02")
	// FV/SV are complemented by original-identity/state metadata, not treated
	// as a universal implicit revision for every policy/history write.
	out.PolicyMetadataHash, e = nativeIdleMetadata(ctx, tx, p, `SELECT octet_length(m.body),CASE WHEN octet_length(m.body)<=16384 THEN m.body END FROM (SELECT jsonb_build_array(t.id,t.current_version,v.id,v.version,v.state,v.status_sequence,v.timezone,v.confirmed_at,v.confirmed_at<=$3,v.configuration_hash,v.original_hash,c.original_hash,e.original_hash)::text AS body FROM template_policies t JOIN template_policy_versions v ON(v.environment_id=t.environment_id AND v.user_id=t.user_id AND v.policy_id=t.id) JOIN template_policy_confirmations c ON(c.environment_id=v.environment_id AND c.user_id=v.user_id AND c.id=v.confirmation_id) JOIN template_policy_status_events e ON(e.environment_id=v.environment_id AND e.user_id=v.user_id AND e.id=v.status_event_id) WHERE t.environment_id=$1 AND t.user_id=$2 ORDER BY t.id,v.version LIMIT 1001) m`, s.now())
	if e != nil {
		return out, e
	}
	out.HistoryMetadataHash, e = nativeIdleMetadata(ctx, tx, p, `SELECT octet_length(m.body),CASE WHEN octet_length(m.body)<=16384 THEN m.body END FROM (
	 SELECT 'history' AS branch,id::text AS identity,jsonb_build_array('history',id,kind,digest)::text AS body FROM evidence_blobs WHERE environment_id=$1 AND user_id=$2 AND kind='FORECAST_HISTORY_STATEMENT_V1'
	 UNION ALL SELECT 'bill-capture',id::text,jsonb_build_array('bill-capture',id,source_id,request_hash,original_hash,recorded_funds_version,observed_at)::text FROM native_bill_captures WHERE environment_id=$1 AND user_id=$2
	 UNION ALL SELECT 'bill-original',id::text,jsonb_build_array('bill-original',id,source_id,external_key,original_hash,bank_reference_hash,final_total_cents,first_capture_id)::text FROM native_bill_originals WHERE environment_id=$1 AND user_id=$2
	 UNION ALL SELECT 'bill-resolution',capture_id::text,jsonb_build_array('bill-resolution',capture_id,result_capture_id,original_hash)::text FROM native_bill_capture_resolutions WHERE environment_id=$1 AND user_id=$2
	 UNION ALL SELECT 'protection',source_version::text,jsonb_build_array('protection',source_version,basis_hash,protection_hash,input_hash,result_hash,source_witness_id,source_witness_hash)::text FROM template_protection_publications WHERE environment_id=$1 AND user_id=$2
	 ORDER BY branch,identity LIMIT 1001) m`)
	return out, e
}

func nativeIdleBoundary(now time.Time, timezone string, others ...time.Time) (time.Time, error) {
	zone, e := policy.TemplateLocation(timezone)
	if e != nil {
		return time.Time{}, e
	}
	local := now.In(zone)
	boundary := time.Date(local.Year(), local.Month(), local.Day()+1, 0, 0, 0, 0, zone).UTC()
	for _, at := range others {
		if !at.IsZero() && at.After(now) && at.Before(boundary) {
			boundary = at
		}
	}
	return boundary, nil
}

// A full path can only establish the business date it actually observed.
// Committing an older result after midnight/expiry is valid old behavior, but
// must not create a negative cursor for a newer business date or due window.
func nativeIdlePrimeBoundary(asOf, post time.Time, date, timezone string, expiry ...time.Time) (time.Time, error) {
	if asOf.IsZero() || post.Before(asOf) {
		return time.Time{}, errNativeIdleUnavailable
	}
	zone, e := policy.TemplateLocation(timezone)
	if e != nil {
		return time.Time{}, e
	}
	if asOf.In(zone).Format("2006-01-02") != date || post.In(zone).Format("2006-01-02") != date {
		return time.Time{}, errNativeIdleUnavailable
	}
	for _, at := range expiry {
		if !at.IsZero() && !asOf.Before(at) {
			return time.Time{}, errNativeIdleUnavailable
		}
	}
	boundary, e := nativeIdleBoundary(asOf, timezone, expiry...)
	if e != nil || !post.Before(boundary) {
		return time.Time{}, errNativeIdleUnavailable
	}
	return boundary, nil
}

func nativeIdleNextPolicyBoundary(ctx context.Context, tx pgx.Tx, p Principal, asOf time.Time) (time.Time, error) {
	var at *time.Time
	e := tx.QueryRow(ctx, `SELECT min(v.confirmed_at) FROM template_policies t JOIN template_policy_versions v ON(v.environment_id=t.environment_id AND v.user_id=t.user_id AND v.policy_id=t.id AND v.version=t.current_version) WHERE t.environment_id=$1 AND t.user_id=$2 AND v.confirmed_at>$3`, p.EnvironmentID.String(), p.UserID.String(), asOf).Scan(&at)
	if e != nil {
		return time.Time{}, e
	}
	if at == nil {
		return time.Time{}, nil
	}
	return *at, nil
}

func (i *nativeDaemonIdle) cursor(table map[string]nativeIdleCursor, id, key string, head *bankcredit.ObservationHead, now time.Time) bool {
	i.mu.Lock()
	defer i.mu.Unlock()
	v, ok := table[id]
	if !ok {
		return false
	}
	age := i.wallNow().Sub(v.verifiedWall)
	valid := v.key == key && !now.Before(v.asOf) && now.Before(v.boundary) && age >= 0 && age < nativeIdleMaxVerifiedAge
	if head != nil {
		valid = valid && v.head.SameState(*head)
	}
	if !valid {
		delete(table, id)
	}
	return valid
}

func (i *nativeDaemonIdle) remember(table map[string]nativeIdleCursor, id, key string, head bankcredit.ObservationHead, now, boundary, fullDone time.Time) bool {
	i.mu.Lock()
	defer i.mu.Unlock()
	// The age starts when the original full transaction returned success,
	// before any head RPC or local postcheck. Postchecks cannot renew it.
	age := i.wallNow().Sub(fullDone)
	if fullDone.IsZero() || age < 0 || age >= nativeIdleMaxVerifiedAge {
		return false
	}
	if len(i.income)+len(i.payment) >= nativeIdleEntries {
		oldKind, oldID := "", ""
		var oldest time.Time
		for k, v := range i.income {
			if oldID == "" || v.verifiedWall.Before(oldest) {
				oldKind, oldID, oldest = "income", k, v.verifiedWall
			}
		}
		for k, v := range i.payment {
			if oldID == "" || v.verifiedWall.Before(oldest) {
				oldKind, oldID, oldest = "payment", k, v.verifiedWall
			}
		}
		if oldKind == "income" {
			delete(i.income, oldID)
		} else {
			delete(i.payment, oldID)
		}
	}
	table[id] = nativeIdleCursor{key: key, head: head, verifiedWall: fullDone, asOf: now, boundary: boundary}
	return true
}

func nativeIdleHeadFresh(head bankcredit.ObservationHead, now time.Time) bool {
	return head.Validate() == nil && !head.CapturedAt.After(now.Add(time.Second)) && now.Sub(head.CapturedAt) <= 30*time.Second
}

func (s *Service) nativeIdleHead(ctx context.Context, p Principal) (bankcredit.ObservationHead, bool) {
	i := s.daemonIdle()
	if i == nil {
		return bankcredit.ObservationHead{}, false
	}
	h, e := i.source.Head(ctx, s.Namespace, p.UserID.String())
	now := s.now()
	if e != nil || h.Namespace != s.Namespace || h.UserID != p.UserID.String() || !nativeIdleHeadFresh(h, now) {
		return bankcredit.ObservationHead{}, false
	}
	return h, true
}

func (s *Service) trySkipNativeIncomeIntake(ctx context.Context, c nativeIncomeIntakeClaim, head bankcredit.ObservationHead) bool {
	i := s.daemonIdle()
	if i == nil || c.Failures != 0 {
		return false
	}
	tx, e := s.begin(ctx)
	if e != nil {
		return false
	}
	defer rollback(ctx, tx)
	fence, e := s.nativeIdleFence(ctx, tx, c.Principal)
	if e != nil {
		return false
	}
	if e = currentNativeIncomeIntake(ctx, tx, c); e != nil {
		return false
	}
	raw, e := encode(struct {
		Fence           nativeIdleFence
		Config, Binding string
	}{fence, i.config, i.binding})
	if e != nil {
		return false
	}
	id := c.Principal.EnvironmentID.String() + "/" + c.Principal.UserID.String()
	post := s.now()
	if !nativeIdleHeadFresh(head, post) || !i.cursor(i.income, id, Hash(raw), &head, post) {
		return false
	}
	// No observation fact is advanced. The old real watermark/hash/time remain.
	tag, e := tx.Exec(ctx, `UPDATE native_income_intakes SET state='READY',lease_owner=NULL,lease_until=NULL,next_attempt_at=clock_timestamp()+interval '30 seconds',updated_at=clock_timestamp() WHERE environment_id=$1 AND user_id=$2 AND state='RUNNING' AND claim_generation=$3 AND lease_owner=$4 AND lease_until>clock_timestamp()`, c.Principal.EnvironmentID.String(), c.Principal.UserID.String(), c.Generation, c.Owner)
	return e == nil && tag.RowsAffected() == 1 && tx.Commit(ctx) == nil
}

func (s *Service) rememberNativeIncomeIntake(ctx context.Context, c nativeIncomeIntakeClaim, before bankcredit.ObservationHead, result NativeIncomeImportResult, fullDone time.Time) {
	i := s.daemonIdle()
	if i == nil {
		return
	}
	after, ok := s.nativeIdleHead(ctx, c.Principal)
	if !ok || !before.SameState(after) {
		return
	}
	tx, e := s.begin(ctx)
	if e != nil {
		return
	}
	defer rollback(ctx, tx)
	fence, e := s.nativeIdleFence(ctx, tx, c.Principal)
	if e != nil || fence.FundsVersion != result.FundsVersion || fence.SourceVersion != result.SourceVersion {
		return
	}
	var state string
	var generation uint64
	var captured *string
	e = tx.QueryRow(ctx, `SELECT state,claim_generation,capture_hash::text FROM native_income_intakes WHERE environment_id=$1 AND user_id=$2`, c.Principal.EnvironmentID.String(), c.Principal.UserID.String()).Scan(&state, &generation, &captured)
	if e != nil || state != "READY" || generation != c.Generation || captured == nil || *captured != result.BankCaptureHash {
		return
	}
	raw, e := encode(struct {
		Fence           nativeIdleFence
		Config, Binding string
	}{fence, i.config, i.binding})
	if e != nil {
		return
	}
	asOf := result.CapturedAt
	policyAt, e := nativeIdleNextPolicyBoundary(ctx, tx, c.Principal, asOf)
	if e != nil {
		return
	}
	_, e = nativeIdlePrimeBoundary(asOf, s.now(), fence.Date, fence.Timezone, policyAt)
	if e != nil || tx.Commit(ctx) != nil {
		return
	}
	post := s.now()
	boundary, e := nativeIdlePrimeBoundary(asOf, post, fence.Date, fence.Timezone, policyAt)
	if e != nil || !nativeIdleHeadFresh(after, post) {
		return
	}
	i.remember(i.income, c.Principal.EnvironmentID.String()+"/"+c.Principal.UserID.String(), Hash(raw), after, asOf, boundary, fullDone)
}

func (s *Service) nativePaymentIdleKey(ctx context.Context, tx pgx.Tx, p Principal, grant NativeStandingGrantView, bank bankv2.LiabilitySnapshot, asOf time.Time) (string, time.Time, error) {
	i := s.daemonIdle()
	if i == nil {
		return "", time.Time{}, errNativeIdleUnavailable
	}
	fence, e := s.nativeIdleFence(ctx, tx, p)
	if e != nil {
		return "", time.Time{}, e
	}
	now := s.now()
	if bank.Validate() != nil || bank.Namespace != s.Namespace || bank.UserID != p.UserID.String() || bank.CapturedAt.After(now.Add(time.Second)) || now.Sub(bank.CapturedAt) > 30*time.Second {
		return "", time.Time{}, errNativeIdleUnavailable
	}
	if fence.Timezone != grant.Grant.Terms.Timezone {
		return "", time.Time{}, errNativeIdleUnavailable
	}
	policyAt, e := nativeIdleNextPolicyBoundary(ctx, tx, p, asOf)
	if e != nil {
		return "", time.Time{}, e
	}
	boundary, e := nativeIdlePrimeBoundary(asOf, now, fence.Date, grant.Grant.Terms.Timezone, grant.Grant.Terms.ExpiresAt, policyAt)
	if e != nil {
		return "", boundary, e
	}
	// Prepare/due are local calendar midnights in standingPaymentSource; next
	// midnight precedes every future such boundary, including month/year edges.
	raw, e := encode(struct {
		Fence           nativeIdleFence
		Grant           NativeStandingGrantView
		Liabilities     []bankv2.LiabilityState
		Config, Binding string
	}{fence, grant, bank.Liabilities, i.config, i.binding})
	return Hash(raw), boundary, e
}
