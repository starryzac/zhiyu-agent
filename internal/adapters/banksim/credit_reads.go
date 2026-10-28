package banksim

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5"
	"zhiyu.local/zhiyu-go/internal/execution/bankcredit"
	funds "zhiyu.local/zhiyu-go/internal/funds/domain"
)

func creditMoney(n int64) (funds.Money, error) { return funds.NewMoney(n) }

func (s *Store) CurrentIncomeState(ctx context.Context, namespace, user string) (bankcredit.CurrentState, error) {
	return s.currentIncomeState(ctx, namespace, user, nil)
}

// CurrentIncomeStateAt uses an explicit server-owned simulation clock. It
// changes only this observation's timestamp, never any economic original.
// Ordinary/default reads keep the PostgreSQL wall-clock path above.
func (s *Store) CurrentIncomeStateAt(ctx context.Context, namespace, user string, at time.Time) (bankcredit.CurrentState, error) {
	return s.currentIncomeState(ctx, namespace, user, &at)
}

func (s *Store) currentIncomeState(ctx context.Context, namespace, user string, at *time.Time) (bankcredit.CurrentState, error) {
	out := bankcredit.CurrentState{Protocol: bankcredit.Protocol + "/state", Namespace: namespace, UserID: user, Accounts: []bankcredit.Account{}, Credits: []bankcredit.Entry{}, Origins: []bankcredit.Origin{}}
	if !bankcredit.Scope(namespace, user) || at != nil && at.IsZero() {
		return out, bankcredit.ErrInvalid
	}
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	if err != nil {
		return out, err
	}
	defer tx.Rollback(ctx)
	if err = userLock(ctx, tx, namespace, user); err != nil {
		return out, err
	}
	if err = tx.QueryRow(ctx, `SELECT clock_timestamp(),coalesce((SELECT max(sequence) FROM bank.external_credits WHERE namespace=$1 AND user_id=$2),0),coalesce((SELECT max(sequence) FROM bank.operations WHERE namespace=$1 AND user_id=$2),0),coalesce((SELECT max(sequence) FROM bank.v2_operations WHERE namespace=$1 AND user_id=$2),0)`, namespace, user).Scan(&out.CapturedAt, &out.CreditWatermark, &out.V1OperationWatermark, &out.V2OperationWatermark); err != nil {
		return out, err
	}
	if at != nil {
		out.CapturedAt = at.UTC()
	}
	rows, err := tx.Query(ctx, `SELECT account_id,balance_cents,reserved_cents FROM bank.accounts WHERE namespace=$1 AND user_id=$2 ORDER BY account_id LIMIT $3`, namespace, user, bankcredit.MaxAccounts+1)
	if err != nil {
		return out, err
	}
	for rows.Next() {
		var a bankcredit.Account
		var balance, reserved int64
		if err = rows.Scan(&a.ID, &balance, &reserved); err != nil {
			break
		}
		if a.Balance, err = creditMoney(balance); err != nil {
			break
		}
		if a.Reserved, err = creditMoney(reserved); err != nil {
			break
		}
		out.Accounts = append(out.Accounts, a)
	}
	rowErr := rows.Err()
	rows.Close()
	if err != nil {
		return out, err
	}
	if rowErr != nil {
		return out, rowErr
	}
	if len(out.Accounts) > bankcredit.MaxAccounts {
		return out, ErrCreditCapacity
	}
	rows, err = tx.Query(ctx, `SELECT record_original,record_hash FROM bank.external_credits WHERE namespace=$1 AND user_id=$2 ORDER BY sequence LIMIT $3`, namespace, user, bankcredit.MaxRecords+1)
	if err != nil {
		return out, err
	}
	for rows.Next() {
		var raw []byte
		var hash string
		if err = rows.Scan(&raw, &hash); err != nil {
			break
		}
		var entry bankcredit.Entry
		if entry, err = decodeCredit(raw, hash); err != nil {
			break
		}
		out.Credits = append(out.Credits, entry)
	}
	rowErr = rows.Err()
	rows.Close()
	if err != nil {
		return out, err
	}
	if rowErr != nil {
		return out, rowErr
	}
	if len(out.Credits) > bankcredit.MaxRecords {
		return out, ErrCreditCapacity
	}
	rows, err = tx.Query(ctx, `SELECT origin_id,original_account_id,original_cents,occurred_at,evidence_hash FROM bank.origins WHERE namespace=$1 AND user_id=$2 ORDER BY origin_id LIMIT $3`, namespace, user, bankcredit.MaxOrigins+1)
	if err != nil {
		return out, err
	}
	origins := map[string]int{}
	for rows.Next() {
		var o bankcredit.Origin
		var amount int64
		if err = rows.Scan(&o.ID, &o.OriginalAccountID, &amount, &o.OccurredAt, &o.EvidenceHash); err != nil {
			break
		}
		if o.Amount, err = creditMoney(amount); err != nil {
			break
		}
		o.Locations = []bankcredit.Location{}
		origins[o.ID] = len(out.Origins)
		out.Origins = append(out.Origins, o)
	}
	rowErr = rows.Err()
	rows.Close()
	if err != nil {
		return out, err
	}
	if rowErr != nil {
		return out, rowErr
	}
	if len(out.Origins) > bankcredit.MaxOrigins {
		return out, ErrCreditCapacity
	}
	rows, err = tx.Query(ctx, `SELECT origin_id,account_id,available_cents,assigned_cents,reserved_cents FROM bank.income_locations WHERE namespace=$1 AND user_id=$2 ORDER BY origin_id,account_id LIMIT $3`, namespace, user, bankcredit.MaxLocations+1)
	if err != nil {
		return out, err
	}
	count := 0
	for rows.Next() {
		var origin string
		var l bankcredit.Location
		var available, assigned, reserved int64
		if err = rows.Scan(&origin, &l.AccountID, &available, &assigned, &reserved); err != nil {
			break
		}
		if l.Available, err = creditMoney(available); err != nil {
			break
		}
		if l.Assigned, err = creditMoney(assigned); err != nil {
			break
		}
		if l.Reserved, err = creditMoney(reserved); err != nil {
			break
		}
		i, exists := origins[origin]
		if !exists {
			err = bankcredit.ErrInvalid
			break
		}
		out.Origins[i].Locations = append(out.Origins[i].Locations, l)
		count++
	}
	rowErr = rows.Err()
	rows.Close()
	if err != nil {
		return out, err
	}
	if rowErr != nil {
		return out, rowErr
	}
	if count > bankcredit.MaxLocations {
		return out, ErrCreditCapacity
	}
	if err = out.Validate(); err != nil {
		return out, err
	}
	return out, tx.Commit(ctx)
}
