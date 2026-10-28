// Package app coordinates trusted inputs, application transactions and the
// independent bank. Pure rules remain in the owning domain packages.
package app

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"zhiyu.local/zhiyu-go/internal/adapters/postgres"
	"zhiyu.local/zhiyu-go/internal/execution/bankv2"
	execution "zhiyu.local/zhiyu-go/internal/execution/domain"
	funds "zhiyu.local/zhiyu-go/internal/funds/domain"
)

type Error struct {
	Code  string
	Cause error
}

func (e *Error) Error() string              { return e.Code }
func (e *Error) Unwrap() error              { return e.Cause }
func reject(code string, cause error) error { return &Error{code, cause} }
func Code(err error) string {
	var e *Error
	if errors.As(err, &e) {
		return e.Code
	}
	return "INTERNAL_ERROR"
}

type Principal struct {
	EnvironmentID funds.ID
	UserID        funds.ID
	Kind          string
	SessionID     funds.ID
}
type Bank interface {
	Submit(context.Context, execution.BankRequest, string) (execution.BankResult, error)
	Lookup(context.Context, string, string, string) (execution.BankResult, error)
	Settle(context.Context, string, string, string) (execution.BankResult, error)
}

type NativeBank interface {
	Submit(context.Context, bankv2.Request, string) (bankv2.Result, error)
	Lookup(context.Context, string, string, string) (bankv2.Result, error)
	Settle(context.Context, string, string, string) (bankv2.Result, error)
}

type Service struct {
	Store                  *postgres.Store
	Pool                   *pgxpool.Pool
	Namespace              string
	Bank                   Bank
	NativeBank             NativeBank
	NativeIncomeSources    *NativeIncomeSources
	NativeBillSources      NativeBillSources
	ForecastHistorySources *ForecastHistorySources
	PermitSecret           []byte
	Clock                  func() time.Time
	AuditTrust             AuditTrustOptions
	// WriterPin is installed by the local operator. It never follows a database
	// generation automatically and is not a browser or model supplied identity.
	WriterPin *RecoveryWriterPin
	// Only explicitly enabled daemon discovery uses negative idle cursors.
	// Public Import, previews, T1/T2/T3, audit and recovery never consult it.
	nativeIdle *nativeDaemonIdle
	// Failpoint is configured only by isolated tests, never by a browser/model.
	Failpoint func(string) error
}

func New(store *postgres.Store, namespace string, bank Bank, secret []byte) *Service {
	return &Service{Store: store, Pool: store.Pool, Namespace: namespace, Bank: bank, PermitSecret: append([]byte(nil), secret...), Clock: time.Now}
}
func (s *Service) now() time.Time { return s.Clock().UTC().Truncate(time.Microsecond) }
func newID() (funds.ID, error) {
	var id funds.ID
	_, err := rand.Read(id[:])
	id[6] = (id[6] & 15) | 64
	id[8] = (id[8] & 63) | 128
	return id, err
}
func Hash(raw []byte) string         { h := sha256.Sum256(raw); return hex.EncodeToString(h[:]) }
func encode(v any) ([]byte, error)   { return json.Marshal(v) }
func decode(raw []byte, v any) error { return json.Unmarshal(raw, v) }

type Environment struct {
	ID                               funds.ID
	Namespace                        string
	WriterGeneration, ControlVersion uint64
}

func (s *Service) environment(ctx context.Context, q interface {
	QueryRow(context.Context, string, ...any) pgx.Row
}, lock bool) (Environment, error) {
	query := "SELECT id::text,namespace,writer_generation,control_version FROM environments WHERE namespace=$1"
	if lock {
		query += " FOR SHARE"
	}
	var v Environment
	var id string
	err := q.QueryRow(ctx, query, s.Namespace).Scan(&id, &v.Namespace, &v.WriterGeneration, &v.ControlVersion)
	if err != nil {
		return v, err
	}
	v.ID, err = funds.ParseID(id)
	if err == nil && lock {
		err = s.checkRecoveryWriter(ctx, q, v)
	}
	return v, err
}
func sameUser(p Principal, environment funds.ID) error {
	if p.EnvironmentID != environment || p.UserID == (funds.ID{}) || (p.Kind != "USER" && p.Kind != "SYSTEM") {
		return reject("FORBIDDEN", nil)
	}
	return nil
}

func (s *Service) begin(ctx context.Context) (pgx.Tx, error) {
	tx, err := s.Pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err == nil {
		err = s.installRecoveryWriter(ctx, tx)
	}
	if err == nil {
		// This is the transaction's business start, not the time of every
		// later financial mutation. A source witness supplies the exact AsOf
		// used to validate its already fixed funds-version prefix.
		_, err = tx.Exec(ctx, `SELECT set_config('zhiyu.business_as_of',$1,true)`, s.now().UTC().Format(time.RFC3339Nano))
	}
	if err != nil && tx != nil {
		rollback(ctx, tx)
	}
	return tx, err
}
func rollback(ctx context.Context, tx pgx.Tx) { _ = tx.Rollback(ctx) }

func lockUser(ctx context.Context, tx pgx.Tx, p Principal) (uint64, uint64, error) {
	var fundsVersion, sourceVersion uint64
	err := tx.QueryRow(ctx, "SELECT funds_version,source_version FROM users WHERE environment_id=$1 AND id=$2 FOR UPDATE", p.EnvironmentID.String(), p.UserID.String()).Scan(&fundsVersion, &sourceVersion)
	return fundsVersion, sourceVersion, err
}
func (s *Service) Check(ctx context.Context) error {
	if err := s.Pool.Ping(ctx); err != nil {
		return err
	}
	if _, err := s.environment(ctx, s.Pool, false); err != nil {
		return err
	}
	if bank, ok := s.Bank.(interface{ Health(context.Context) error }); ok {
		return bank.Health(ctx)
	}
	return reject("BANK_UNAVAILABLE", nil)
}

func validateKey(key string) error {
	if len(key) < 16 || len(key) > 128 {
		return reject("INVALID_IDEMPOTENCY_KEY", nil)
	}
	for _, r := range key {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-' || r == '_') {
			return reject("INVALID_IDEMPOTENCY_KEY", nil)
		}
	}
	return nil
}
func parseID(value string) (funds.ID, error) {
	id, err := funds.ParseID(value)
	if err != nil {
		return id, reject("INVALID_ID", err)
	}
	return id, nil
}
func assertOne(tag interface{ RowsAffected() int64 }, err error) error {
	if err != nil {
		return err
	}
	if tag.RowsAffected() != 1 {
		return fmt.Errorf("expected one scoped row")
	}
	return nil
}
