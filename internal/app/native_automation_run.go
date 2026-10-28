package app

import (
	"context"
	"errors"
	"time"
)

// Retry accounting never releases a money reservation or invents a new source
// identity. A lost T1 response is recognized by the committed ACCEPTED row.
func (s *Service) retryNativeOccurrence(ctx context.Context, c NativeOccurrenceClaim, cause error) error {
	tx, err := s.begin(ctx)
	if err != nil {
		return err
	}
	defer rollback(ctx, tx)
	if _, err = s.environment(ctx, tx, true); err != nil {
		return err
	}
	p := Principal{Kind: "SYSTEM", EnvironmentID: c.Occurrence.Scope.EnvironmentID, UserID: c.Occurrence.Scope.UserID}
	if _, _, err = lockUser(ctx, tx, p); err != nil {
		return err
	}
	var state, owner string
	var generation uint64
	if err = tx.QueryRow(ctx, `SELECT state,coalesce(lease_owner,''),claim_generation FROM native_occurrences WHERE environment_id=$1 AND user_id=$2 AND id=$3 FOR UPDATE`, p.EnvironmentID.String(), p.UserID.String(), c.Occurrence.ID.String()).Scan(&state, &owner, &generation); err != nil {
		return err
	}
	if state == "ACCEPTED" && generation == c.Generation {
		return tx.Commit(ctx)
	}
	if state != "RUNNING" || generation != c.Generation || owner != c.Owner {
		return ErrNativeOccurrenceClaimLost
	}
	if err = nativeCurrentOccurrenceClaim(ctx, tx, c); err != nil {
		return err
	}
	if Code(cause) == "NATIVE_GRANT_POLICY_CHANGED" || Code(cause) == "EVIDENCE_INVALID" || Code(cause) == "NATIVE_GRANT_SCOPE" || Code(cause) == "NATIVE_JOINT_STANDING_BRIDGE_PENDING" {
		if err = nativeFinishOccurrence(ctx, tx, c, "BLOCKED", Code(cause)); err != nil {
			return err
		}
	} else if c.Attempts >= c.MaxAttempts {
		if err = nativeFinishOccurrence(ctx, tx, c, "EXHAUSTED", Code(cause)); err != nil {
			return err
		}
	} else {
		_, err = tx.Exec(ctx, `UPDATE native_occurrences SET state='READY',lease_owner=NULL,lease_until=NULL,last_error=$4,next_attempt_at=clock_timestamp()+$5::bigint*interval '1 millisecond' WHERE environment_id=$1 AND user_id=$2 AND id=$3`, p.EnvironmentID.String(), p.UserID.String(), c.Occurrence.ID.String(), Code(cause), 100*(1<<min(c.Attempts, 8)))
		if err != nil {
			return err
		}
	}
	if err = tx.Commit(ctx); err != nil {
		return err
	}
	return cause
}

func (s *Service) RunNativeStanding(ctx context.Context, owner string) error {
	var databaseFailures uint
	for {
		if ctx.Err() != nil {
			return nil
		}
		worked, err := s.NativeStandingStep(ctx, owner, 30*time.Second)
		if retryBackgroundDatabase(ctx, err, &databaseFailures) {
			continue
		}
		if err != nil && Code(err) == "INTERNAL_ERROR" && !errors.Is(err, ErrNativeOccurrenceClaimLost) {
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
