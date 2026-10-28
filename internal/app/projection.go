package app

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	funds "zhiyu.local/zhiyu-go/internal/funds/domain"
)

type ProjectionWatermark struct {
	SourceSequence  int64      `json:"source_sequence"`
	AppliedSequence int64      `json:"applied_sequence"`
	ProjectedAt     *time.Time `json:"projected_at,omitempty"`
	Status          string     `json:"status"`
}

type projectionEvent struct {
	Sequence          int64
	OperationID       string
	Version, Previous uint64
	Snapshot          []byte
	CreatedAt         time.Time
}

// ApplyProjectionEvent is an ordered, idempotent application of ONE persisted
// event. A late delivery cannot skip an earlier source event or roll back an
// aggregate. This read model is never consulted by Plan, Accept, T2 or T3.
func (s *Service) ApplyProjectionEvent(ctx context.Context, p Principal, sequence int64) (bool, error) {
	if sequence < 1 {
		return false, reject("INVALID_COMMAND", nil)
	}
	tx, err := s.begin(ctx)
	if err != nil {
		return false, err
	}
	defer rollback(ctx, tx)
	env, err := s.environment(ctx, tx, false)
	if err != nil {
		return false, err
	}
	if err = sameUser(p, env.ID); err != nil {
		return false, err
	}
	if _, _, err = lockUser(ctx, tx, p); err != nil {
		return false, err
	}
	var last int64
	err = tx.QueryRow(ctx, `SELECT last_sequence FROM operation_projection_offsets WHERE environment_id=$1 AND user_id=$2`, env.ID.String(), p.UserID.String()).Scan(&last)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return false, err
	}
	if sequence <= last {
		var owned bool
		if err = tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM operation_projection_events WHERE environment_id=$1 AND user_id=$2 AND event_sequence=$3)`, env.ID.String(), p.UserID.String(), sequence).Scan(&owned); err != nil {
			return false, err
		}
		if !owned {
			return false, reject("NOT_FOUND", nil)
		}
		return false, tx.Commit(ctx)
	}
	var event projectionEvent
	err = tx.QueryRow(ctx, `SELECT event_sequence,operation_id::text,aggregate_version,previous_version,snapshot,created_at FROM operation_projection_events WHERE environment_id=$1 AND user_id=$2 AND event_sequence>$3 ORDER BY event_sequence LIMIT 1`, env.ID.String(), p.UserID.String(), last).Scan(&event.Sequence, &event.OperationID, &event.Version, &event.Previous, &event.Snapshot, &event.CreatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, reject("NOT_FOUND", nil)
	}
	if err != nil {
		return false, err
	}
	if event.Sequence != sequence {
		return false, reject("PROJECTION_OUT_OF_ORDER", nil)
	}
	var previous uint64
	err = tx.QueryRow(ctx, `SELECT aggregate_version FROM operation_read_models WHERE environment_id=$1 AND user_id=$2 AND operation_id=$3`, env.ID.String(), p.UserID.String(), event.OperationID).Scan(&previous)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return false, err
	}
	if previous != event.Previous || event.Version <= previous {
		return false, reject("PROJECTION_GAP", nil)
	}
	_, err = tx.Exec(ctx, `INSERT INTO operation_read_models(environment_id,user_id,operation_id,source_sequence,aggregate_version,snapshot,created_at,updated_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8) ON CONFLICT(environment_id,user_id,operation_id) DO UPDATE SET source_sequence=EXCLUDED.source_sequence,aggregate_version=EXCLUDED.aggregate_version,snapshot=EXCLUDED.snapshot,updated_at=EXCLUDED.updated_at`, env.ID.String(), p.UserID.String(), event.OperationID, event.Sequence, event.Version, event.Snapshot, event.CreatedAt, s.now())
	if err != nil {
		return false, err
	}
	_, err = tx.Exec(ctx, `INSERT INTO operation_projection_offsets(environment_id,user_id,last_sequence,projected_at) VALUES($1,$2,$3,$4) ON CONFLICT(environment_id,user_id) DO UPDATE SET last_sequence=EXCLUDED.last_sequence,projected_at=EXCLUDED.projected_at`, env.ID.String(), p.UserID.String(), sequence, s.now())
	if err != nil {
		return false, err
	}
	return true, tx.Commit(ctx)
}

// RebuildProjection repairs only derived display state from the complete,
// immutable transition stream. It cannot submit/retry a bank command or alter
// an authoritative account, reservation, operation or receipt.
func (s *Service) RebuildProjection(ctx context.Context, p Principal) (ProjectionWatermark, error) {
	var result ProjectionWatermark
	tx, err := s.begin(ctx)
	if err != nil {
		return result, err
	}
	defer rollback(ctx, tx)
	env, err := s.environment(ctx, tx, false)
	if err != nil {
		return result, err
	}
	if err = sameUser(p, env.ID); err != nil {
		return result, err
	}
	if p.Kind == "USER" {
		if err = s.human(ctx, tx, p); err != nil {
			return result, err
		}
	}
	if _, _, err = lockUser(ctx, tx, p); err != nil {
		return result, err
	}
	var count int
	var gap bool
	if err = tx.QueryRow(ctx, `SELECT count(*) FROM (SELECT id FROM operations WHERE environment_id=$1 AND user_id=$2 LIMIT 10001) bounded`, env.ID.String(), p.UserID.String()).Scan(&count); err != nil {
		return result, err
	}
	if count > 10000 {
		return result, reject("CAPACITY_EXCEEDED", nil)
	}
	if err = tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM (SELECT previous_version,lag(aggregate_version,1,0::bigint) OVER(PARTITION BY operation_id ORDER BY event_sequence) expected FROM operation_projection_events WHERE environment_id=$1 AND user_id=$2) ordered WHERE previous_version<>expected)`, env.ID.String(), p.UserID.String()).Scan(&gap); err != nil {
		return result, err
	}
	if gap {
		return result, reject("PROJECTION_GAP", nil)
	}
	_, err = tx.Exec(ctx, `INSERT INTO operation_read_models(environment_id,user_id,operation_id,source_sequence,aggregate_version,snapshot,created_at,updated_at) SELECT environment_id,user_id,operation_id,event_sequence,aggregate_version,snapshot,created_at,$3 FROM (SELECT DISTINCT ON(operation_id) * FROM operation_projection_events WHERE environment_id=$1 AND user_id=$2 ORDER BY operation_id,event_sequence DESC) latest ON CONFLICT(environment_id,user_id,operation_id) DO UPDATE SET source_sequence=EXCLUDED.source_sequence,aggregate_version=EXCLUDED.aggregate_version,snapshot=EXCLUDED.snapshot,updated_at=EXCLUDED.updated_at`, env.ID.String(), p.UserID.String(), s.now())
	if err != nil {
		return result, err
	}
	_, err = tx.Exec(ctx, `INSERT INTO operation_projection_offsets(environment_id,user_id,last_sequence,projected_at) SELECT $1,$2,COALESCE(max(event_sequence),0),$3 FROM operation_projection_events WHERE environment_id=$1 AND user_id=$2 ON CONFLICT(environment_id,user_id) DO UPDATE SET last_sequence=EXCLUDED.last_sequence,projected_at=EXCLUDED.projected_at`, env.ID.String(), p.UserID.String(), s.now())
	if err != nil {
		return result, err
	}
	result, err = projectionWatermark(ctx, tx, p)
	if err != nil {
		return result, err
	}
	return result, tx.Commit(ctx)
}

// ProjectStep reads only the next indexed sequence in this namespace. The
// persistent offset makes stopping/restarting the consumer independent of
// financial recovery. Concurrent consumers serialize on the existing user lock.
func (s *Service) ProjectStep(ctx context.Context) (bool, error) {
	env, err := s.environment(ctx, s.Pool, false)
	if err != nil {
		return false, err
	}
	var user string
	var sequence int64
	err = s.Pool.QueryRow(ctx, `SELECT e.user_id::text,e.event_sequence FROM operation_projection_events e LEFT JOIN operation_projection_offsets p ON p.environment_id=e.environment_id AND p.user_id=e.user_id WHERE e.environment_id=$1 AND e.event_sequence>COALESCE(p.last_sequence,0) ORDER BY e.event_sequence LIMIT 1`, env.ID.String()).Scan(&user, &sequence)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	uid, err := funds.ParseID(user)
	if err != nil {
		return false, err
	}
	return s.ApplyProjectionEvent(ctx, Principal{EnvironmentID: env.ID, UserID: uid, Kind: "SYSTEM"}, sequence)
}

func (s *Service) RunProjection(ctx context.Context) error {
	var databaseFailures uint
	for {
		if ctx.Err() != nil {
			return nil
		}
		worked, err := s.ProjectStep(ctx)
		if retryBackgroundDatabase(ctx, err, &databaseFailures) {
			continue
		}
		if err != nil {
			return err
		}
		if worked {
			continue
		}
		timer := time.NewTimer(500 * time.Millisecond)
		select {
		case <-ctx.Done():
			timer.Stop()
			return nil
		case <-timer.C:
		}
	}
}

func projectionWatermark(ctx context.Context, tx pgx.Tx, p Principal) (ProjectionWatermark, error) {
	v := ProjectionWatermark{Status: "CURRENT"}
	var bad bool
	err := tx.QueryRow(ctx, `SELECT COALESCE((SELECT max(event_sequence) FROM operation_projection_events WHERE environment_id=$1 AND user_id=$2),0),COALESCE((SELECT last_sequence FROM operation_projection_offsets WHERE environment_id=$1 AND user_id=$2),0),(SELECT projected_at FROM operation_projection_offsets WHERE environment_id=$1 AND user_id=$2),EXISTS(SELECT 1 FROM operation_read_models m LEFT JOIN operation_projection_events e ON e.event_sequence=m.source_sequence WHERE m.environment_id=$1 AND m.user_id=$2 AND (e.event_sequence IS NULL OR e.environment_id<>m.environment_id OR e.user_id<>m.user_id OR e.operation_id<>m.operation_id OR e.aggregate_version<>m.aggregate_version OR e.snapshot<>m.snapshot))`, p.EnvironmentID.String(), p.UserID.String()).Scan(&v.SourceSequence, &v.AppliedSequence, &v.ProjectedAt, &bad)
	if err != nil {
		return v, err
	}
	if bad || v.AppliedSequence > v.SourceSequence {
		v.Status = "INVALID"
		return v, nil
	}
	if v.AppliedSequence < v.SourceSequence {
		v.Status = "DELAYED"
		return v, nil
	}
	var missing bool
	err = tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM operations o LEFT JOIN operation_read_models m ON m.environment_id=o.environment_id AND m.user_id=o.user_id AND m.operation_id=o.id WHERE o.environment_id=$1 AND o.user_id=$2 AND (m.operation_id IS NULL OR m.aggregate_version<>o.version))`, p.EnvironmentID.String(), p.UserID.String()).Scan(&missing)
	if missing {
		v.Status = "MISSING"
	}
	return v, err
}

func readProjectedOperations(ctx context.Context, tx pgx.Tx, p Principal, limit int) ([]Operation, error) {
	operations := []Operation{}
	rows, err := tx.Query(ctx, `SELECT snapshot FROM operation_read_models WHERE environment_id=$1 AND user_id=$2 ORDER BY created_at DESC,operation_id DESC LIMIT $3`, p.EnvironmentID.String(), p.UserID.String(), limit)
	if err != nil {
		return operations, err
	}
	defer rows.Close()
	for rows.Next() {
		var raw []byte
		var op Operation
		if err = rows.Scan(&raw); err != nil {
			return operations, err
		}
		if err = decode(raw, &op); err != nil {
			return operations, reject("PROJECTION_INVALID", err)
		}
		if op.ID == (funds.ID{}) || op.Version == 0 || op.Amount.IsZero() {
			return operations, reject("PROJECTION_INVALID", nil)
		}
		operations = append(operations, op)
	}
	return operations, rows.Err()
}
