package app

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	executionaudit "zhiyu.local/zhiyu-go/internal/execution/audit"
	execution "zhiyu.local/zhiyu-go/internal/execution/domain"
	"zhiyu.local/zhiyu-go/internal/execution/fundswitness"
	funds "zhiyu.local/zhiyu-go/internal/funds/domain"
	planning "zhiyu.local/zhiyu-go/internal/planning/domain"
	policy "zhiyu.local/zhiyu-go/internal/policy/domain"
)

var ErrClaimLost = errors.New("worker claim no longer current")

type Claim struct {
	Principal          Principal
	JobID, OperationID funds.ID
	Generation         uint64
	Owner              string
}

// ClaimJob locks only the durable scheduling row. Lease time is PostgreSQL
// clock time, independent of the injected business clock.
func (s *Service) ClaimJob(ctx context.Context, owner string, lease time.Duration) (*Claim, error) {
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
	var eid, uid, jid, oid string
	var generation uint64
	err = tx.QueryRow(ctx, `WITH picked AS (
 SELECT j.environment_id,j.user_id,j.id FROM jobs j JOIN environments e ON e.id=j.environment_id
 WHERE e.namespace=$1 AND NOT j.paused AND j.state IN ('READY','RUNNING') AND j.next_attempt_at<=clock_timestamp() AND (j.lease_until IS NULL OR j.lease_until<=clock_timestamp())
 ORDER BY j.next_attempt_at,j.id FOR UPDATE OF j SKIP LOCKED LIMIT 1)
 UPDATE jobs j SET state='RUNNING',claim_generation=j.claim_generation+1,lease_owner=$2,lease_until=clock_timestamp()+$3::bigint*interval '1 millisecond',attempts=j.attempts+1
 FROM picked p WHERE j.environment_id=p.environment_id AND j.user_id=p.user_id AND j.id=p.id
 RETURNING j.environment_id::text,j.user_id::text,j.id::text,j.operation_id::text,j.claim_generation`, s.Namespace, owner, lease.Milliseconds()).Scan(&eid, &uid, &jid, &oid, &generation)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	env, err := funds.ParseID(eid)
	if err != nil {
		return nil, err
	}
	user, err := funds.ParseID(uid)
	if err != nil {
		return nil, err
	}
	job, err := funds.ParseID(jid)
	if err != nil {
		return nil, err
	}
	op, err := funds.ParseID(oid)
	if err != nil {
		return nil, err
	}
	if err = tx.Commit(ctx); err != nil {
		return nil, err
	}
	return &Claim{Principal{EnvironmentID: env, UserID: user, Kind: "SYSTEM"}, job, op, generation, owner}, nil
}

func currentClaim(ctx context.Context, tx pgx.Tx, c Claim) error {
	var valid bool
	err := tx.QueryRow(ctx, `SELECT claim_generation=$4 AND lease_owner=$5 AND lease_until>clock_timestamp() AND state='RUNNING' AND NOT paused AND operation_id=$6 FROM jobs WHERE environment_id=$1 AND user_id=$2 AND id=$3 FOR UPDATE`, c.Principal.EnvironmentID.String(), c.Principal.UserID.String(), c.JobID.String(), c.Generation, c.Owner, c.OperationID.String()).Scan(&valid)
	if err != nil {
		return err
	}
	if !valid {
		return ErrClaimLost
	}
	return nil
}

type permitted struct {
	Request          execution.BankRequest
	Signature, State string
	Cancelled        bool
}

func (s *Service) permit(ctx context.Context, c Claim) (permitted, error) {
	var out permitted
	tx, err := s.begin(ctx)
	if err != nil {
		return out, err
	}
	defer rollback(ctx, tx)
	env, err := s.environment(ctx, tx, true)
	if err != nil {
		return out, err
	}
	p := c.Principal
	if err = sameUser(p, env.ID); err != nil {
		return out, err
	}
	fv, sv, err := lockUser(ctx, tx, p)
	if err != nil {
		return out, err
	}
	decisionAt := s.now()
	var status string
	var planID, policyID string
	var grantID, confirmationID *string
	var raw, depRaw []byte
	var expectedFV uint64
	var signature *string
	err = tx.QueryRow(ctx, `SELECT status,plan_id::text,policy_id::text,grant_id::text,confirmation_id::text,bank_request,dependencies,reserved_funds_version,permit_signature FROM operations WHERE environment_id=$1 AND user_id=$2 AND id=$3`, env.ID.String(), p.UserID.String(), c.OperationID.String()).Scan(&status, &planID, &policyID, &grantID, &confirmationID, &raw, &depRaw, &expectedFV, &signature)
	if err != nil {
		return out, err
	}
	if err = decode(raw, &out.Request); err != nil {
		return out, reject("EVIDENCE_INVALID", err)
	}
	if err = out.Request.Validate(); err != nil {
		return out, reject("EVIDENCE_INVALID", err)
	}
	if out.Request.Namespace != s.Namespace || out.Request.UserID != p.UserID.String() || out.Request.OperationID != c.OperationID.String() {
		return out, reject("EVIDENCE_INVALID", nil)
	}
	if status == "SETTLED" || status == "REJECTED" || status == "CANCELLED" {
		out.Cancelled = true
		return out, nil
	}
	if status != "QUEUED" {
		if signature == nil {
			return out, reject("EVIDENCE_INVALID", nil)
		}
		if err = s.verifyLegacyStoredPermit(ctx, tx, p, c.OperationID, out.Request, *signature); err != nil {
			return out, err
		}
		if err = lockOperation(ctx, tx, c); err != nil {
			return out, err
		}
		if err = currentClaim(ctx, tx, c); err != nil {
			return out, err
		}
		out.Signature = *signature
		out.State = status
		return out, tx.Commit(ctx)
	}
	polID, err := funds.ParseID(policyID)
	if err != nil {
		return out, err
	}
	pol, policyErr := loadPolicy(ctx, tx, p, polID, true)
	plan, err := funds.ParseID(planID)
	if err != nil {
		return out, err
	}
	candidate, candidateErr := loadCandidate(ctx, tx, p, plan)
	var deps planning.DependencyVector
	if err = decode(depRaw, &deps); err != nil {
		return out, err
	}
	permissionErr := policyErr
	if permissionErr == nil {
		permissionErr = ensureNativeBillsReady(ctx, tx, p)
	}
	if permissionErr == nil {
		permissionErr = ensureLegacyGoalUnbound(ctx, tx, p, pol.Scope.GoalID)
	}
	var checkedGrant *policy.Grant
	var checkedConfirmation *policy.ConfirmationSource
	if permissionErr == nil {
		permissionErr = candidateErr
	}
	if permissionErr == nil && (fv != expectedFV || sv != deps.SourceEvidenceVersion || env.WriterGeneration != deps.WriterGeneration || env.ControlVersion != deps.ControlVersion) {
		permissionErr = reject("SOURCE_CHANGED", nil)
	}
	if permissionErr == nil {
		if grantID != nil {
			gid, e := funds.ParseID(*grantID)
			if e != nil {
				return out, e
			}
			g, e := loadGrant(ctx, tx, p, gid, true)
			if e != nil {
				permissionErr = e
			} else {
				_, permissionErr = planning.AuthorizeStanding(candidate, pol, g, decisionAt)
				if permissionErr == nil {
					checkedGrant = &g
				}
			}
		}
		if grantID == nil {
			if confirmationID == nil {
				permissionErr = reject("EVIDENCE_INVALID", nil)
			} else {
				var confirmationRaw []byte
				e := tx.QueryRow(ctx, "SELECT original FROM confirmations WHERE environment_id=$1 AND user_id=$2 AND id=$3", env.ID.String(), p.UserID.String(), *confirmationID).Scan(&confirmationRaw)
				if e != nil {
					permissionErr = e
				} else {
					var confirmation policy.ConfirmationSource
					e = decode(confirmationRaw, &confirmation)
					if e != nil {
						permissionErr = e
					} else {
						_, permissionErr = planning.AuthorizeOnce(candidate, pol, confirmation, decisionAt)
						if permissionErr == nil {
							checkedConfirmation = &confirmation
						}
					}
				}
			}
		}
	}
	if err = lockOperation(ctx, tx, c); err != nil {
		return out, err
	}
	if err = currentClaim(ctx, tx, c); err != nil {
		return out, err
	}
	if permissionErr != nil {
		if err = s.cancelBeforePermit(ctx, tx, c, Code(permissionErr)); err != nil {
			return out, err
		}
		out.Cancelled = true
		return out, tx.Commit(ctx)
	}
	out.Signature, err = execution.SignPermit(out.Request, s.PermitSecret)
	if err != nil {
		return out, err
	}
	_, err = tx.Exec(ctx, `UPDATE operations SET status='SUBMITTING',permit_signature=$4,version=version+1,updated_at=$5 WHERE environment_id=$1 AND user_id=$2 AND id=$3 AND status='QUEUED'`, env.ID.String(), p.UserID.String(), c.OperationID.String(), out.Signature, decisionAt)
	if err != nil {
		return out, err
	}
	requestHash, err := out.Request.Digest()
	if err != nil {
		return out, err
	}
	record := executionaudit.SubmissionPermitEvidence{Protocol: executionaudit.SubmissionPermitProtocol, EnvironmentID: env.ID, UserID: p.UserID, OperationID: c.OperationID, Namespace: s.Namespace, PermitID: out.Request.PermitID, BankRequestHash: requestHash, EffectHash: candidate.EffectHash, Dependencies: deps, Policy: pol, Grant: checkedGrant, Confirmation: checkedConfirmation, DecisionAt: decisionAt, ReservedFundsVersion: fv, SourceVersion: sv, SignatureHash: Hash([]byte(out.Signature))}
	original, err := encode(record)
	if err != nil {
		return out, err
	}
	_, err = tx.Exec(ctx, `INSERT INTO submission_permits(environment_id,user_id,operation_id,permit_id,protocol_version,original,original_hash,decision_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8)`, env.ID.String(), p.UserID.String(), c.OperationID.String(), out.Request.PermitID, executionaudit.SubmissionPermitProtocol, original, Hash(original), decisionAt)
	if err != nil {
		return out, err
	}
	out.State = "SUBMITTING"
	return out, tx.Commit(ctx)
}

func lockOperation(ctx context.Context, tx pgx.Tx, c Claim) error {
	var id string
	return tx.QueryRow(ctx, "SELECT id::text FROM operations WHERE environment_id=$1 AND user_id=$2 AND id=$3 FOR UPDATE", c.Principal.EnvironmentID.String(), c.Principal.UserID.String(), c.OperationID.String()).Scan(&id)
}

func (s *Service) cancelBeforePermit(ctx context.Context, tx pgx.Tx, c Claim, reason string) error {
	p := c.Principal
	var signature *string
	if err := tx.QueryRow(ctx, "SELECT permit_signature FROM operations WHERE environment_id=$1 AND user_id=$2 AND id=$3", p.EnvironmentID.String(), p.UserID.String(), c.OperationID.String()).Scan(&signature); err != nil {
		return err
	}
	if signature != nil {
		return reject("OPERATION_UNKNOWN", nil)
	}
	ledger, err := s.Store.LoadLedger(ctx, tx, p.EnvironmentID, p.UserID, s.now())
	if err != nil {
		return err
	}
	ledger, err = ledger.Release(c.OperationID, s.now(), true)
	if err != nil {
		return err
	}
	if err = s.Store.SaveLedger(ctx, tx, p.EnvironmentID, p.UserID, ledger); err != nil {
		return err
	}
	if _, err = tx.Exec(ctx, "UPDATE operations SET status='CANCELLED',processing_health=$4,updated_at=$5,version=version+1 WHERE environment_id=$1 AND user_id=$2 AND id=$3", p.EnvironmentID.String(), p.UserID.String(), c.OperationID.String(), reason, s.now()); err != nil {
		return err
	}
	if err = s.recordFundsTerminalDecision(ctx, tx, p, "LEGACY", c.OperationID, "CANCELLED", fundswitness.Cause{Kind: fundswitness.UnsupportedCause, Code: reason}); err != nil {
		return err
	}
	if _, err = tx.Exec(ctx, "UPDATE users SET funds_version=funds_version+1 WHERE environment_id=$1 AND id=$2", p.EnvironmentID.String(), p.UserID.String()); err != nil {
		return err
	}
	_, err = tx.Exec(ctx, "UPDATE jobs SET state='DONE',lease_owner=NULL,lease_until=NULL,last_error=$4 WHERE environment_id=$1 AND user_id=$2 AND id=$3", p.EnvironmentID.String(), p.UserID.String(), c.JobID.String(), reason)
	return err
}

// ProcessClaim performs external I/O only after the committed T2 permit. Every
// attempt uses the original immutable bank key and complete request.
func (s *Service) ProcessClaim(ctx context.Context, c Claim) error {
	permit, err := s.permit(ctx, c)
	if err != nil {
		return err
	}
	if permit.Cancelled {
		return nil
	}
	if s.Failpoint != nil {
		if err = s.Failpoint("after_permit_commit"); err != nil {
			return err
		}
	}
	if s.Bank == nil {
		return s.recordFailure(ctx, c, reject("BANK_UNAVAILABLE", nil))
	}
	result, err := s.Bank.Lookup(ctx, permit.Request.Namespace, permit.Request.UserID, permit.Request.Key)
	if err == nil {
		err = execution.VerifyBankResult(permit.Request, result)
	}
	if err == nil && result.Status == execution.BankNotFound {
		if _, recovering := ctx.Value(recoveryIntentKey{}).(recoveryIntent); recovering {
			return s.recordFailure(ctx, c, reject("OPERATION_UNKNOWN", nil))
		}
		if permit.State == "PENDING_SETTLEMENT" || permit.State == "RECONCILING" {
			return s.recordFailure(ctx, c, reject("OPERATION_UNKNOWN", nil))
		}
		result, err = s.Bank.Submit(ctx, permit.Request, permit.Signature)
	}
	if err == nil && result.Status == execution.BankAccepted && result.AvailableAt != nil && !s.now().Before(*result.AvailableAt) {
		result, err = s.Bank.Settle(ctx, permit.Request.Namespace, permit.Request.UserID, permit.Request.Key)
	}
	if err != nil {
		return s.recordFailure(ctx, c, reject("BANK_UNAVAILABLE", err))
	}
	if err = execution.VerifyBankResult(permit.Request, result); err != nil {
		return s.recordFailure(ctx, c, reject("EVIDENCE_INVALID", err))
	}
	if s.Failpoint != nil {
		if err = s.Failpoint("after_bank_commit"); err != nil {
			return err
		}
	}
	return s.projectObservation(ctx, c, permit.Request, result)
}

func (s *Service) WorkerStep(ctx context.Context, owner string, lease time.Duration) (bool, error) {
	c, err := s.ClaimJob(ctx, owner, lease)
	if err != nil || c == nil {
		return false, err
	}
	err = s.ProcessClaim(ctx, *c)
	return true, err
}

func (s *Service) recordFailure(ctx context.Context, c Claim, cause error) error {
	tx, err := s.begin(ctx)
	if err != nil {
		return err
	}
	defer rollback(ctx, tx)
	if _, err = s.environment(ctx, tx, true); err != nil {
		return err
	}
	if _, _, err = lockUser(ctx, tx, c.Principal); err != nil {
		return err
	}
	if err = lockOperation(ctx, tx, c); err != nil {
		return err
	}
	if err = currentClaim(ctx, tx, c); err != nil {
		return err
	}
	var attempts, max int
	if err = tx.QueryRow(ctx, "SELECT attempts,max_attempts FROM jobs WHERE environment_id=$1 AND user_id=$2 AND id=$3", c.Principal.EnvironmentID.String(), c.Principal.UserID.String(), c.JobID.String()).Scan(&attempts, &max); err != nil {
		return err
	}
	health := "RETRYING"
	paused := attempts >= max
	if paused {
		health = "PAUSED"
	}
	if _, err = tx.Exec(ctx, `UPDATE operations SET status=CASE WHEN status='SUBMITTING' THEN 'UNKNOWN' ELSE status END,processing_health=$4,version=version+1,updated_at=$5 WHERE environment_id=$1 AND user_id=$2 AND id=$3 AND status NOT IN ('SETTLED','REJECTED','CANCELLED')`, c.Principal.EnvironmentID.String(), c.Principal.UserID.String(), c.OperationID.String(), health, s.now()); err != nil {
		return err
	}
	backoff := 100 * (1 << min(attempts, 8))
	if _, err = tx.Exec(ctx, `UPDATE jobs SET state='READY',lease_owner=NULL,lease_until=NULL,paused=$4,last_error=$5,next_attempt_at=clock_timestamp()+$6::bigint*interval '1 millisecond' WHERE environment_id=$1 AND user_id=$2 AND id=$3`, c.Principal.EnvironmentID.String(), c.Principal.UserID.String(), c.JobID.String(), paused, Code(cause), backoff); err != nil {
		return err
	}
	if err = tx.Commit(ctx); err != nil {
		return err
	}
	return cause
}

func (s *Service) RunWorker(ctx context.Context, owner string) error {
	var databaseFailures uint
	for {
		if err := ctx.Err(); err != nil {
			return nil
		}
		worked, err := s.WorkerStep(ctx, owner, 30*time.Second)
		if err == nil && s.NativeBank != nil {
			nativeWorked, nativeErr := s.NativeWorkerStep(ctx, owner, 30*time.Second)
			worked = worked || nativeWorked
			err = nativeErr
		}
		if retryBackgroundDatabase(ctx, err, &databaseFailures) {
			continue
		}
		if err != nil && errors.Is(err, ErrClaimLost) {
			continue
		}
		if err != nil && Code(err) == "INTERNAL_ERROR" {
			return fmt.Errorf("worker database path failed: %w", err)
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
