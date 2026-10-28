package app

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5"
	"zhiyu.local/zhiyu-go/internal/adapters/postgres"
	"zhiyu.local/zhiyu-go/internal/execution/bankcredit"
	"zhiyu.local/zhiyu-go/internal/execution/bankv2"
	funds "zhiyu.local/zhiyu-go/internal/funds/domain"
	policy "zhiyu.local/zhiyu-go/internal/policy/domain"
)

const nativeStandingPaymentProtocol = NativeAutomationProtocol + "/payment-plan"
const nativeStandingPaymentPermitProtocol = NativeAutomationProtocol + "/payment-submission-permit"

type nativeStandingPaymentPlan struct {
	Protocol           string                         `json:"protocol"`
	ID                 funds.ID                       `json:"id"`
	Scope              policy.TemplateOwnerScope      `json:"scope"`
	Occurrence         NativeOccurrence               `json:"occurrence"`
	Grant              NativeStandingGrant            `json:"grant"`
	GrantStateSequence uint64                         `json:"grant_state_sequence"`
	Usage              policy.NativeStandingUsage     `json:"usage"`
	Authority          policy.NativeStandingCandidate `json:"authority"`
	Preview            NativePaymentPreview           `json:"preview"`
	PermitID           funds.ID                       `json:"permit_id"`
}

func standingPaymentSource(version policy.TemplateVersion, debtID, due string, bank bankv2.LiabilityState, timezone string) (policy.NativeOccurrenceSource, error) {
	var out policy.NativeOccurrenceSource
	cfg, e := version.Compiled.Decode()
	if e != nil {
		return out, e
	}
	prepare := 0
	switch v := cfg.(type) {
	case *policy.RecurringObligationConfig:
		if !v.AutoExecute {
			return out, reject("PAYMENT_AUTO_EXECUTE_DISABLED", nil)
		}
		prepare = v.PrepareDaysBefore
	case *policy.PeriodicTransferConfig:
		prepare = v.PrepareDaysBefore
	default:
		return out, reject("PAYMENT_RULE_INVALID", nil)
	}
	date, e := policy.TemplateDate(due)
	if e != nil || len(due) < 7 || bank.Original.ID != debtID || (bank.Original.Kind == "OCCURRENCE" && bank.Original.Period != due[:7]) || (bank.Original.Kind != "OCCURRENCE" && bank.Original.Kind != "BILL") {
		return out, reject("PAYMENT_LIABILITY_INVALID", e)
	}
	zone, e := policy.TemplateLocation(timezone)
	if e != nil {
		return out, e
	}
	at := time.Date(date.Year(), date.Month(), date.Day(), 0, 0, 0, 0, zone)
	out = policy.NativeOccurrenceSource{Kind: "PAYMENT_OCCURRENCE", ID: debtID, OriginalHash: bank.OriginalHash, Period: due[:7], OccurredAt: at.UTC(), AvailableAt: at.AddDate(0, 0, -prepare).UTC()}
	if out.Validate(policy.NativePeriodicPayment) != nil {
		return out, reject("PAYMENT_LIABILITY_INVALID", nil)
	}
	return out, nil
}

func standingPaymentAuthority(grant NativeStandingGrant, source policy.NativeOccurrenceSource, amount funds.Money) policy.NativeStandingCandidate {
	return policy.NativeStandingCandidate{Scope: grant.Scope, Family: policy.NativePeriodicPayment, Source: source, Policies: grant.Terms.Policies, AccountIDs: grant.Terms.AccountIDs, GoalIDs: []funds.ID{}, PayeeID: grant.Terms.PayeeIDs[0], Amount: amount}
}

// The bank snapshot is collected outside the environment/user lock. Discovery
// records the fixed due/prepare instants and original liability identity, never
// the changing observation clock, and never creates money or permission.
func (s *Service) discoverNativePaymentOccurrences(ctx context.Context) (discovered int, discoveryErr error) {
	defer func() {
		if discoveryErr != nil {
			if idle := s.daemonIdle(); idle != nil {
				idle.forgetAllPayment()
			}
		}
	}()
	rows, e := s.Pool.Query(ctx, `SELECT g.environment_id::text,g.user_id::text,g.id::text FROM native_grants g JOIN environments e ON(e.id=g.environment_id) WHERE e.namespace=$1 AND g.family='PERIODIC_PAYMENT' AND g.expires_at>clock_timestamp() ORDER BY g.id LIMIT 65`, s.Namespace)
	if e != nil {
		return 0, e
	}
	type target struct {
		p     Principal
		grant funds.ID
	}
	targets := []target{}
	for rows.Next() {
		var env, user, id string
		if e = rows.Scan(&env, &user, &id); e != nil {
			rows.Close()
			return 0, e
		}
		a, x := funds.ParseID(env)
		b, y := funds.ParseID(user)
		g, z := funds.ParseID(id)
		if x != nil || y != nil || z != nil {
			rows.Close()
			return 0, reject("EVIDENCE_INVALID", nil)
		}
		targets = append(targets, target{Principal{EnvironmentID: a, UserID: b, Kind: "SYSTEM"}, g})
	}
	e = rows.Err()
	rows.Close()
	if e != nil {
		return 0, e
	}
	if len(targets) > 64 {
		return 0, reject("NATIVE_PAYMENT_DISCOVERY_CAPACITY", nil)
	}
	reader, ok := s.NativeBank.(nativePaymentBankReader)
	if !ok && len(targets) > 0 {
		return 0, reject("BANK_UNAVAILABLE", nil)
	}
	total := 0
	for _, t := range targets {
		bank, e := reader.Liabilities(ctx, s.Namespace, t.p.UserID.String())
		if e != nil {
			return total, reject("BANK_UNAVAILABLE", e)
		}
		now := s.now()
		if bank.Validate() != nil || bank.Namespace != s.Namespace || bank.UserID != t.p.UserID.String() || bank.CapturedAt.After(now.Add(time.Second)) || now.Sub(bank.CapturedAt) > 30*time.Second {
			return total, reject("BANK_SNAPSHOT_STALE", nil)
		}
		added, e := s.registerStandingPaymentSources(ctx, t.p, t.grant, bank, now)
		total += added
		if e != nil {
			return total, e
		}
	}
	return total, nil
}

func (s *Service) registerStandingPaymentSources(ctx context.Context, p Principal, id funds.ID, bank bankv2.LiabilitySnapshot, now time.Time) (int, error) {
	idle := s.daemonIdle()
	idleID := p.EnvironmentID.String() + "/" + p.UserID.String() + "/" + id.String()
	keepCursor := false
	defer func() {
		if idle != nil && !keepCursor {
			idle.forget(idle.payment, idleID)
		}
	}()
	tx, e := s.begin(ctx)
	if e != nil {
		return 0, e
	}
	defer rollback(ctx, tx)
	env, e := s.environment(ctx, tx, true)
	if e != nil {
		return 0, e
	}
	if e = sameUser(p, env.ID); e != nil {
		return 0, e
	}
	if _, _, e = lockUser(ctx, tx, p); e != nil {
		return 0, e
	}
	grant, e := loadNativeStandingGrant(ctx, tx, p, id)
	if e != nil {
		return 0, e
	}
	if grant.Grant.Terms.Family != policy.NativePeriodicPayment || grant.State != "ACTIVE" || now.Before(grant.Grant.Terms.EffectiveFrom) || !now.Before(grant.Grant.Terms.ExpiresAt) {
		if idle != nil {
			idle.forget(idle.payment, idleID)
		}
		return 0, tx.Commit(ctx)
	}
	// Discovery may run again before the separate financial worker reaches T2.
	// Its own T1 holds are already protected and are not an external source
	// change. Publishing that reservation as a new source here would invalidate
	// the original unsigned request. Actual intake/policy publications still
	// occur through their normal paths and T2 retains its exact version checks.
	var pending bool
	if e = tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM native_operations WHERE environment_id=$1 AND user_id=$2 AND status NOT IN ('SETTLED','REJECTED','CANCELLED'))`, p.EnvironmentID.String(), p.UserID.String()).Scan(&pending); e != nil {
		return 0, e
	}
	if pending {
		if idle != nil {
			idle.forget(idle.payment, idleID)
		}
		return 0, tx.Commit(ctx)
	}
	// Only this daemon discovery can skip duplicate negative scheduling. Every
	// public preview/Import and actual T1/T2 retains its original fresh path.
	if idle != nil {
		key, _, x := s.nativePaymentIdleKey(ctx, tx, p, grant, bank, now)
		if x == nil && idle.cursor(idle.payment, idleID, key, nil, now) {
			e = tx.Commit(ctx)
			keepCursor = e == nil
			return 0, e
		}
		idle.forget(idle.payment, idleID)
	}
	if _, e = s.refreshTemplateProtection(ctx, tx, p, grant.Grant.Terms.Timezone); e != nil {
		return 0, e
	}
	snapshot, e := s.loadTemplateSnapshot(ctx, tx, p, now, grant.Grant.Terms.Timezone)
	if e != nil {
		return 0, e
	}
	ref := grant.Grant.Terms.Policies[0]
	var version *policy.TemplateVersion
	for i := range snapshot.Views {
		v := &snapshot.Views[i]
		if v.Version.VersionID == ref.VersionID && v.Version.Current && v.EffectiveState == "ACTIVE" && v.Version.Compiled.Hash == ref.ConfigurationHash {
			version = &v.Version
		}
	}
	if version == nil {
		return 0, tx.Commit(ctx)
	}
	count := 0
	for _, debt := range snapshot.Retained {
		if debt.PolicyID != ref.PolicyID {
			continue
		}
		for _, liability := range bank.Liabilities {
			if liability.Original.ID != debt.ID {
				continue
			}
			candidate := NativePaymentPreview{Policy: TemplatePolicyView{Version: *version}, Debt: debt, Liability: liability, Timezone: grant.Grant.Terms.Timezone}
			if liability.Original.Kind == "BILL" {
				proof, x := nativeBillProofForDebt(snapshot, debt)
				if x != nil {
					return count, x
				}
				candidate.BillProof = &proof
			} else if liability.Original.Kind == "OCCURRENCE" {
				proof, x := nativePaymentAdoptionProofForDebt(snapshot, debt)
				if x != nil {
					return count, x
				}
				candidate.AdoptionProof = &proof
			}
			if _, e = nativePaymentPreviewAmount(candidate, now); e != nil {
				continue
			}
			source, e := standingPaymentSource(*version, debt.ID, debt.DueDate, liability, grant.Grant.Terms.Timezone)
			if e != nil {
				continue
			}
			raw, e := encode(struct {
				Protocol   string                `json:"protocol"`
				Debt       any                   `json:"debt"`
				Bank       bankv2.LiabilityState `json:"bank"`
				CapturedAt time.Time             `json:"captured_at"`
			}{NativeAutomationProtocol + "/payment-source", debt, liability, bank.CapturedAt})
			if e != nil {
				return count, e
			}
			_, added, e := registerNativeOccurrence(ctx, tx, p, grant.Grant, source, nil, raw, now)
			if e != nil {
				return count, e
			}
			if added {
				count++
			}
		}
	}
	// Prime only after the unchanged full discovery and its publication have
	// committed successfully. Failures and pending returns never prime.
	key, boundary, x := s.nativePaymentIdleKey(ctx, tx, p, grant, bank, now)
	e = tx.Commit(ctx)
	fullDone := time.Time{}
	if e == nil && idle != nil {
		fullDone = idle.wallNow()
	}
	post := s.now()
	if e == nil && x == nil && idle != nil && !post.Before(now) && post.Before(boundary) {
		keepCursor = idle.remember(idle.payment, idleID, key, bankcredit.ObservationHead{}, now, boundary, fullDone)
	}
	return count, e
}

// T1 is a private SYSTEM admission. It consumes an authenticated immutable USER
// standing grant; it never reconstructs or borrows a USER session.
func (s *Service) admitStandingPayment(ctx context.Context, c NativeOccurrenceClaim) error {
	p := Principal{EnvironmentID: c.Occurrence.Scope.EnvironmentID, UserID: c.Occurrence.Scope.UserID, Kind: "SYSTEM"}
	bank, captured, e := s.paymentBankLiability(ctx, p, c.Occurrence.Source.ID)
	if e != nil {
		return e
	}
	tx, e := s.begin(ctx)
	if e != nil {
		return e
	}
	defer rollback(ctx, tx)
	env, e := s.environment(ctx, tx, true)
	if e != nil {
		return e
	}
	if e = sameUser(p, env.ID); e != nil {
		return e
	}
	fv, sv, e := lockUser(ctx, tx, p)
	if e != nil {
		return e
	}
	if e = nativeCurrentOccurrenceClaim(ctx, tx, c); e != nil {
		return e
	}
	grant, e := loadNativeStandingGrant(ctx, tx, p, c.Occurrence.GrantID)
	if e != nil {
		return e
	}
	now := s.now()
	if c.Occurrence.Family != policy.NativePeriodicPayment || grant.Grant.Terms.Family != c.Occurrence.Family {
		return reject("FAMILY_NOT_QUALIFIED", nil)
	}
	if grant.State != "ACTIVE" || now.Before(grant.Grant.Terms.EffectiveFrom) || !now.Before(grant.Grant.Terms.ExpiresAt) {
		if e = nativeFinishOccurrence(ctx, tx, c, "BLOCKED", "NATIVE_GRANT_NOT_ACTIVE"); e != nil {
			return e
		}
		return tx.Commit(ctx)
	}
	usage, e := nativeStandingUsage(ctx, tx, p, grant.Grant, now, nil)
	if e != nil {
		return e
	}
	life, e := funds.SumMoney(usage.LifetimeCommitted, usage.LifetimeReserved)
	if e != nil {
		return e
	}
	month, e := funds.SumMoney(usage.MonthCommitted, usage.MonthReserved)
	if e != nil {
		return e
	}
	a, e := grant.Grant.Terms.LifetimeCap.Sub(life)
	if e != nil {
		return reject("NATIVE_STANDING_CAP_EXCEEDED", e)
	}
	b, e := grant.Grant.Terms.MonthlyCap.Sub(month)
	if e != nil {
		return reject("NATIVE_STANDING_CAP_EXCEEDED", e)
	}
	amount, e := bank.Original.FinalTotal.Sub(bank.Paid)
	if e != nil {
		return e
	}
	amount = nativeResourceMinimum(amount, nativeResourceMinimum(grant.Grant.Terms.SingleCap, nativeResourceMinimum(a, b)))
	if amount.IsZero() {
		if e = nativeFinishOccurrence(ctx, tx, c, "NO_ACTION", "NO_CURRENT_ELIGIBLE_AMOUNT"); e != nil {
			return e
		}
		return tx.Commit(ctx)
	}
	snapshot, e := s.loadTemplateSnapshot(ctx, tx, p, now, grant.Grant.Terms.Timezone)
	if e != nil {
		return e
	}
	id, e := newID()
	if e != nil {
		return e
	}
	previewID, e := newID()
	if e != nil {
		return e
	}
	permit, e := newID()
	if e != nil {
		return e
	}
	expires := now.Add(2 * time.Minute)
	if grant.Grant.Terms.ExpiresAt.Before(expires) {
		expires = grant.Grant.Terms.ExpiresAt
	}
	zone, _ := policy.TemplateLocation(grant.Grant.Terms.Timezone)
	local := now.In(zone)
	midnight := time.Date(local.Year(), local.Month(), local.Day()+1, 0, 0, 0, 0, zone).UTC()
	if midnight.Before(expires) {
		expires = midnight
	}
	in := NativePaymentRequest{PolicyVersionID: grant.Grant.Terms.Policies[0].VersionID, ObligationID: c.Occurrence.Source.ID, SourceAccountID: grant.Grant.Terms.AccountIDs[0], Amount: amount, Timezone: grant.Grant.Terms.Timezone}
	preview, e := buildNativePaymentPreview(snapshot, in, bankv2.LiabilitySnapshot{Liabilities: []bankv2.LiabilityState{bank}}, now, expires, previewID)
	if e != nil {
		return e
	}
	source, e := standingPaymentSource(preview.Policy.Version, preview.Debt.ID, preview.Debt.DueDate, bank, in.Timezone)
	if e != nil {
		return e
	}
	x, _ := encode(source)
	y, _ := encode(c.Occurrence.Source)
	if string(x) != string(y) {
		return reject("NATIVE_SOURCE_ORIGINAL_CONFLICT", nil)
	}
	preview.Dependencies.GrantVersion = grant.Grant.Version
	preview.ReviewedHash, e = NativePaymentReviewHash(preview)
	if e != nil {
		return e
	}
	authority := standingPaymentAuthority(grant.Grant, source, amount)
	if e = policy.AuthorizeNativeStanding(grant.Grant.Terms, grant.State, authority, usage, now); e != nil {
		return reject(e.Error(), e)
	}
	plan := nativeStandingPaymentPlan{nativeStandingPaymentProtocol, id, nativeAutomationScope(p), c.Occurrence, grant.Grant, grant.StateSequence, usage, authority, preview, permit}
	planRaw, e := encode(plan)
	if e != nil || len(planRaw) > 8<<20 {
		return reject("NATIVE_STANDING_CAPTURE_CAPACITY", e)
	}
	planHash := Hash(planRaw)
	ref := grant.Grant.Terms.Policies[0]
	request := bankv2.Request{Protocol: bankv2.Protocol, Namespace: s.Namespace, Key: id.String(), OperationID: id.String(), UserID: p.UserID.String(), PermitID: permit.String(), ReferenceHash: planHash, RequestedAt: now, ExpiresAt: expires, Effect: preview.BankEffect, Authorities: []bankv2.Authority{{Role: "EXECUTE", SourceID: grant.Grant.ID.String(), Version: int64(grant.Grant.Version), PolicyID: ref.PolicyID.String(), PolicyVersion: int64(ref.Version)}}}
	bankRaw, e := request.CanonicalBytes()
	if e != nil {
		return reject("EVIDENCE_INVALID", e)
	}
	bankHash, _ := request.Digest()
	deps, _ := encode(preview.Dependencies)
	refs, _ := encode(grant.Grant.Terms.Policies)
	if _, e = tx.Exec(ctx, `INSERT INTO native_standing_plans(environment_id,user_id,id,occurrence_id,grant_id,grant_version,original,original_hash,created_at,expires_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`, p.EnvironmentID.String(), p.UserID.String(), id.String(), c.Occurrence.ID.String(), grant.Grant.ID.String(), grant.Grant.Version, planRaw, planHash, now, expires); e != nil {
		return e
	}
	if _, e = tx.Exec(ctx, `INSERT INTO native_previews(environment_id,user_id,id,kind,original,original_hash,effect_hash,policy_refs,source_hash,dependencies,dependencies_hash,bank_request,bank_request_hash,created_at,expires_at) VALUES($1,$2,$3,'PAY_RECURRING',$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)`, p.EnvironmentID.String(), p.UserID.String(), previewID.String(), planRaw, planHash, preview.EffectHash, refs, preview.SourceHash, deps, Hash(deps), bankRaw, bankHash, now, expires); e != nil {
		return e
	}
	if _, e = tx.Exec(ctx, `INSERT INTO native_operations(environment_id,user_id,id,command_kind,idempotency_key,request,request_hash,bank_namespace,bank_key,bank_request,bank_request_hash,effect_hash,dependencies,dependencies_hash,plan_id,preview_id,group_id,child_number,mode,grant_id,grant_version,permit_id,reserved_funds_version,created_at,updated_at) VALUES($1,$2,$3::uuid,'PAY_RECURRING',$4,$5,$6,$7,$3::text,$8,$9,$10,$11,$12,$3::uuid,$13,$13,1,'STANDING',$14,$15,$16,$17,$18,$18)`, p.EnvironmentID.String(), p.UserID.String(), id.String(), "native_standing_"+c.Occurrence.Key, planRaw, planHash, s.Namespace, bankRaw, bankHash, preview.EffectHash, deps, Hash(deps), previewID.String(), grant.Grant.ID.String(), grant.Grant.Version, permit.String(), fv+1, now); e != nil {
		return e
	}
	ledger := *snapshot.Native
	if e = reserveNativeUnownedCash(&ledger, id, bankv2.Payment, preview.Resources); e != nil {
		return e
	}
	ledger.Holds = append(ledger.Holds, postgres.NativeHold{OperationID: id, ResourceKind: "LIABILITY", ResourceID: preview.Debt.ID, Amount: amount, State: funds.Reserved})
	sourceRaw, _ := encode(bank)
	if _, e = tx.Exec(ctx, `INSERT INTO native_payment_sources(environment_id,user_id,operation_id,obligation_id,original,original_hash,observed_at) VALUES($1,$2,$3,$4,$5,$6,$7)`, p.EnvironmentID.String(), p.UserID.String(), id.String(), preview.Debt.ID, sourceRaw, Hash(sourceRaw), captured); e != nil {
		return e
	}
	budget, _ := encode(struct {
		Protocol     string      `json:"protocol"`
		OccurrenceID funds.ID    `json:"occurrence_id"`
		PlanID       funds.ID    `json:"plan_id"`
		PlanHash     string      `json:"plan_hash"`
		Amount       funds.Money `json:"amount_cents"`
		Period       string      `json:"period"`
	}{NativeAutomationProtocol + "/budget", c.Occurrence.ID, id, planHash, amount, usage.Period})
	if e = reserveNativeOccurrenceBudget(ctx, tx, p, c, grant.Grant, amount, budget, now); e != nil {
		return e
	}
	if e = bindNativeOccurrenceOperation(ctx, tx, p, c.Occurrence.ID, id, amount, preview.EffectHash, bankHash, now); e != nil {
		return e
	}
	if e = bridgeCreateJob(ctx, tx, p, id); e != nil {
		return e
	}
	if e = s.Store.PersistNativeLedger(ctx, tx, p.EnvironmentID, p.UserID, ledger); e != nil {
		return e
	}
	if _, e = tx.Exec(ctx, `UPDATE users SET funds_version=funds_version+1 WHERE environment_id=$1 AND id=$2 AND funds_version=$3 AND source_version=$4`, p.EnvironmentID.String(), p.UserID.String(), fv, sv); e != nil {
		return e
	}
	if e = nativeFinishOccurrence(ctx, tx, c, "ACCEPTED", ""); e != nil {
		return e
	}
	if e = tx.Commit(ctx); e != nil {
		return e
	}
	if s.Failpoint != nil {
		return s.Failpoint("native_standing_after_t1_commit")
	}
	return nil
}

func loadStandingPaymentPlan(ctx context.Context, q queryRow, p Principal, id funds.ID) (nativeStandingPaymentPlan, string, error) {
	var out nativeStandingPaymentPlan
	var raw []byte
	var hash string
	if e := q.QueryRow(ctx, `SELECT original,original_hash::text FROM native_standing_plans WHERE environment_id=$1 AND user_id=$2 AND id=$3`, p.EnvironmentID.String(), p.UserID.String(), id.String()).Scan(&raw, &hash); e != nil {
		return out, "", e
	}
	if Hash(raw) != hash || auditJSON(raw, &out) != nil || out.Protocol != nativeStandingPaymentProtocol || out.ID != id || out.Scope != nativeAutomationScope(p) || out.Grant.Scope != out.Scope || out.Occurrence.Scope != out.Scope || out.Occurrence.GrantID != out.Grant.ID || out.Occurrence.GrantVersion != out.Grant.Version || out.Grant.PrincipalKind != "USER" || out.Grant.Terms.Family != policy.NativePeriodicPayment || out.Grant.Terms.Validate() != nil || out.Preview.SessionID != (funds.ID{}) || out.Preview.Scope != out.Scope || out.Preview.Dependencies.GrantVersion != out.Grant.Version || out.PermitID == (funds.ID{}) {
		return out, "", reject("EVIDENCE_INVALID", nil)
	}
	grant, e := loadNativeStandingGrant(ctx, q, p, out.Grant.ID)
	if e != nil {
		return out, "", e
	}
	a, _ := encode(grant.Grant)
	b, _ := encode(out.Grant)
	if string(a) != string(b) {
		return out, "", reject("EVIDENCE_INVALID", nil)
	}
	occurrence, e := loadNativeOccurrence(ctx, q, p, out.Occurrence.ID)
	if e != nil {
		return out, "", e
	}
	a, _ = encode(occurrence)
	b, _ = encode(out.Occurrence)
	if string(a) != string(b) {
		return out, "", reject("EVIDENCE_INVALID", nil)
	}
	if e := replayNativePaymentPreview(out.Preview); e != nil {
		return out, "", e
	}
	source, e := standingPaymentSource(out.Preview.Policy.Version, out.Preview.Debt.ID, out.Preview.Debt.DueDate, out.Preview.Liability, out.Preview.Timezone)
	if e != nil {
		return out, "", e
	}
	x, _ := encode(source)
	y, _ := encode(out.Occurrence.Source)
	if string(x) != string(y) {
		return out, "", reject("EVIDENCE_INVALID", nil)
	}
	authority := standingPaymentAuthority(out.Grant, source, out.Preview.Resources.Amount)
	x, _ = encode(authority)
	y, _ = encode(out.Authority)
	if string(x) != string(y) || policy.AuthorizeNativeStanding(out.Grant.Terms, "ACTIVE", authority, out.Usage, out.Preview.CreatedAt) != nil {
		return out, "", reject("EVIDENCE_INVALID", nil)
	}
	return out, hash, nil
}

// Original lookup chooses the actual saved permission mode; no fallback turns a
// missing standing proof into an ONCE confirmation.
func loadNativePaymentExecutionPreview(ctx context.Context, q queryRow, p Principal, operation, preview funds.ID) (NativePaymentPreview, error) {
	var mode string
	if e := q.QueryRow(ctx, `SELECT mode FROM native_operations WHERE environment_id=$1 AND user_id=$2 AND id=$3 AND preview_id=$4 AND command_kind='PAY_RECURRING'`, p.EnvironmentID.String(), p.UserID.String(), operation.String(), preview.String()).Scan(&mode); e != nil {
		return NativePaymentPreview{}, e
	}
	if mode == "ONCE" {
		return loadNativePaymentPreview(ctx, q, p, preview)
	}
	if mode != "STANDING" {
		return NativePaymentPreview{}, reject("EVIDENCE_INVALID", nil)
	}
	plan, _, e := loadStandingPaymentPlan(ctx, q, p, operation)
	if e != nil {
		return NativePaymentPreview{}, e
	}
	if plan.Preview.ID != preview {
		return NativePaymentPreview{}, reject("EVIDENCE_INVALID", nil)
	}
	return plan.Preview, nil
}

func finalizeStandingPaymentBudget(ctx context.Context, tx pgx.Tx, p Principal, operation funds.ID, spent funds.Money, now time.Time) error {
	var mode string
	if e := tx.QueryRow(ctx, `SELECT mode FROM native_operations WHERE environment_id=$1 AND user_id=$2 AND id=$3`, p.EnvironmentID.String(), p.UserID.String(), operation.String()).Scan(&mode); e != nil {
		return e
	}
	if mode == "ONCE" {
		return nil
	}
	if mode != "STANDING" {
		return reject("EVIDENCE_INVALID", nil)
	}
	plan, _, e := loadStandingPaymentPlan(ctx, tx, p, operation)
	if e != nil {
		return e
	}
	return finalizeNativeStandingBudget(ctx, tx, p, plan.Occurrence.ID, spent, now)
}
