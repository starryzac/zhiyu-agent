package app

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	funds "zhiyu.local/zhiyu-go/internal/funds/domain"
)

var ErrNativeIncomeIntakeClaimLost = errors.New("native income observation claim no longer current")

type nativeIncomeIntakeClaim struct {
	Principal  Principal
	Owner      string
	Generation uint64
	Failures   int
}

func (s *Service) claimNativeIncomeIntake(ctx context.Context, owner string, lease time.Duration) (*nativeIncomeIntakeClaim, error) {
	if owner == "" || len(owner) > 128 || lease < time.Millisecond || lease > time.Minute {
		return nil, reject("INVALID_WORKER_CONFIGURATION", nil)
	}
	tx, e := s.begin(ctx)
	if e != nil {
		return nil, e
	}
	defer rollback(ctx, tx)
	if _, e = s.environment(ctx, tx, true); e != nil {
		return nil, e
	}
	// Subscription scope comes from stored server/USER grant identities. Once
	// subscribed, revocation stops execution permission, not observed facts.
	_, e = tx.Exec(ctx, `INSERT INTO native_income_intakes(environment_id,user_id) SELECT u.environment_id,u.id FROM users u JOIN environments e ON(e.id=u.environment_id) WHERE e.namespace=$1 AND EXISTS(SELECT 1 FROM native_grants g WHERE g.environment_id=u.environment_id AND g.user_id=u.id) AND NOT EXISTS(SELECT 1 FROM native_income_intakes i WHERE i.environment_id=u.environment_id AND i.user_id=u.id) ORDER BY u.id LIMIT 64 ON CONFLICT DO NOTHING`, s.Namespace)
	if e != nil {
		return nil, e
	}
	var env, user string
	out := nativeIncomeIntakeClaim{Owner: owner}
	e = tx.QueryRow(ctx, `WITH picked AS(SELECT i.environment_id,i.user_id FROM native_income_intakes i JOIN environments e ON(e.id=i.environment_id) WHERE e.namespace=$1 AND i.state IN ('READY','RUNNING') AND i.failures<8 AND i.next_attempt_at<=clock_timestamp() AND (i.lease_until IS NULL OR i.lease_until<=clock_timestamp()) ORDER BY i.next_attempt_at,i.user_id FOR UPDATE OF i SKIP LOCKED LIMIT 1) UPDATE native_income_intakes i SET state='RUNNING',claim_generation=i.claim_generation+1,lease_owner=$2,lease_until=clock_timestamp()+$3::bigint*interval '1 millisecond',updated_at=clock_timestamp() FROM picked p WHERE i.environment_id=p.environment_id AND i.user_id=p.user_id RETURNING i.environment_id::text,i.user_id::text,i.claim_generation,i.failures`, s.Namespace, owner, lease.Milliseconds()).Scan(&env, &user, &out.Generation, &out.Failures)
	if errors.Is(e, pgx.ErrNoRows) {
		return nil, tx.Commit(ctx)
	}
	if e != nil {
		return nil, e
	}
	out.Principal.Kind = "SYSTEM"
	out.Principal.EnvironmentID, e = funds.ParseID(env)
	if e != nil {
		return nil, e
	}
	out.Principal.UserID, e = funds.ParseID(user)
	if e != nil {
		return nil, e
	}
	return &out, tx.Commit(ctx)
}

func currentNativeIncomeIntake(ctx context.Context, tx pgx.Tx, c nativeIncomeIntakeClaim) error {
	if c.Principal.Kind != "SYSTEM" || c.Principal.SessionID != (funds.ID{}) {
		return reject("FORBIDDEN", nil)
	}
	var valid bool
	e := tx.QueryRow(ctx, `SELECT state='RUNNING' AND claim_generation=$3 AND lease_owner=$4 AND lease_until>clock_timestamp() FROM native_income_intakes WHERE environment_id=$1 AND user_id=$2 FOR UPDATE`, c.Principal.EnvironmentID.String(), c.Principal.UserID.String(), c.Generation, c.Owner).Scan(&valid)
	if e != nil {
		return e
	}
	if !valid {
		return ErrNativeIncomeIntakeClaimLost
	}
	return nil
}

func finishNativeIncomeIntake(ctx context.Context, tx pgx.Tx, c nativeIncomeIntakeClaim, result NativeIncomeImportResult) error {
	tag, e := tx.Exec(ctx, `UPDATE native_income_intakes SET state='READY',lease_owner=NULL,lease_until=NULL,failures=0,next_attempt_at=clock_timestamp()+interval '30 seconds',last_error='',credit_watermark=$5,v1_watermark=$6,v2_watermark=$7,capture_hash=$8,last_observed_at=$9,updated_at=clock_timestamp() WHERE environment_id=$1 AND user_id=$2 AND claim_generation=$3 AND lease_owner=$4 AND state='RUNNING' AND lease_until>clock_timestamp()`, c.Principal.EnvironmentID.String(), c.Principal.UserID.String(), c.Generation, c.Owner, result.CreditWatermark, result.V1OperationWatermark, result.V2OperationWatermark, result.BankCaptureHash, result.CapturedAt)
	if e != nil {
		return e
	}
	if tag.RowsAffected() != 1 {
		return ErrNativeIncomeIntakeClaimLost
	}
	return nil
}

func (s *Service) retryNativeIncomeIntake(ctx context.Context, c nativeIncomeIntakeClaim, cause error) error {
	tx, e := s.begin(ctx)
	if e != nil {
		return e
	}
	defer rollback(ctx, tx)
	if _, e = s.environment(ctx, tx, true); e != nil {
		return e
	}
	if _, _, e = lockUser(ctx, tx, c.Principal); e != nil {
		return e
	}
	if e = currentNativeIncomeIntake(ctx, tx, c); e != nil {
		return e
	}
	failures := c.Failures + 1
	deferred := Code(cause) == "INCOME_OPERATION_PENDING" || Code(cause) == "INCOME_SOURCE_CHANGED" || Code(cause) == "BILL_INTAKE_PENDING"
	state := "READY"
	delay := 1000 * (1 << min(failures, 6))
	if deferred {
		failures = c.Failures
		delay = 30000
	}
	if failures >= 8 {
		state = "EXHAUSTED"
	}
	_, e = tx.Exec(ctx, `UPDATE native_income_intakes SET state=$3,lease_owner=NULL,lease_until=NULL,failures=$4,next_attempt_at=clock_timestamp()+$5::bigint*interval '1 millisecond',last_error=$6,updated_at=clock_timestamp() WHERE environment_id=$1 AND user_id=$2`, c.Principal.EnvironmentID.String(), c.Principal.UserID.String(), state, failures, delay, Code(cause))
	if e != nil {
		return e
	}
	if e = tx.Commit(ctx); e != nil {
		return e
	}
	if deferred {
		return nil
	}
	return cause
}

// Bank I/O remains outside all financial locks. The exact PG lease is checked
// again under the common user lock and atomically completed with any import.
func (s *Service) NativeIncomeIntakeStep(ctx context.Context, owner string, lease time.Duration) (bool, error) {
	idle := s.daemonIdle()
	if s.NativeIncomeSources == nil {
		return false, nil
	}
	c, e := s.claimNativeIncomeIntake(ctx, owner, lease)
	if e != nil || c == nil {
		if e != nil && idle != nil {
			idle.forgetAllIncome()
		}
		return false, e
	}
	head, canObserve := s.nativeIdleHead(ctx, c.Principal)
	if canObserve && s.trySkipNativeIncomeIntake(ctx, *c, head) {
		return true, nil
	}
	s.forgetNativeIncomeIntake(c.Principal)
	result, e := s.importNativeIncomeClaimed(ctx, c.Principal, *s.NativeIncomeSources, true, c)
	fullDone := time.Time{}
	if e == nil && idle != nil {
		fullDone = idle.wallNow()
	}
	if e != nil {
		return true, s.retryNativeIncomeIntake(ctx, *c, e)
	}
	if canObserve {
		s.rememberNativeIncomeIntake(ctx, *c, head, result, fullDone)
	}
	return true, nil
}

func (s *Service) ResumeNativeIncomeIntake(ctx context.Context, p Principal) error {
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
	if _, _, e = lockUser(ctx, tx, p); e != nil {
		return e
	}
	if e = s.human(ctx, tx, p); e != nil {
		return e
	}
	tag, e := tx.Exec(ctx, `UPDATE native_income_intakes SET state='READY',lease_owner=NULL,lease_until=NULL,failures=0,next_attempt_at=clock_timestamp(),last_error='',updated_at=clock_timestamp() WHERE environment_id=$1 AND user_id=$2 AND state='EXHAUSTED'`, p.EnvironmentID.String(), p.UserID.String())
	if e = assertOne(tag, e); e != nil {
		return e
	}
	return tx.Commit(ctx)
}
