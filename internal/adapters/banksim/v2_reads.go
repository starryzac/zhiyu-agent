package banksim

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	bankv2 "zhiyu.local/zhiyu-go/internal/execution/bankv2"
	funds "zhiyu.local/zhiyu-go/internal/funds/domain"
)

var ErrV2Capacity = errors.New("BANK_V2_READ_CAPACITY_EXCEEDED")

func (s *Store) RegisterGoalV2(ctx context.Context, r bankv2.GoalRegistration, signature string, now time.Time) error {
	if _, err := r.CanonicalBytes(); err != nil {
		return err
	}
	if !bankv2.VerifyGoalRegistration(r, signature, s.secret) {
		return ErrUnauthorized
	}
	if r.RequestedAt.After(now) || !now.Before(r.ExpiresAt) {
		return bankv2.ErrInvalid
	}
	return s.OpenGoal(ctx, r.Namespace, r.UserID, r.GoalID, r.AccountID)
}

func (s *Store) InventoryV2(ctx context.Context, namespace, user string, after, watermark int64, limit int) (bankv2.Inventory, error) {
	r := bankv2.Inventory{Protocol: bankv2.Protocol, Namespace: namespace, UserID: user, Operations: []bankv2.Result{}}
	if !validIdentity(namespace, user) || after < 0 || watermark < 0 || limit < 1 || limit > 100 {
		return r, bankv2.ErrInvalid
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return r, err
	}
	defer tx.Rollback(ctx)
	if err = userLock(ctx, tx, namespace, user); err != nil {
		return r, err
	}
	if watermark == 0 {
		if err = tx.QueryRow(ctx, "SELECT coalesce(max(sequence),0) FROM bank.v2_operations WHERE namespace=$1 AND user_id=$2", namespace, user).Scan(&watermark); err != nil {
			return r, err
		}
	}
	r.Watermark = watermark
	r.NextAfter = after
	rows, err := tx.Query(ctx, "SELECT operation_key,sequence FROM bank.v2_operations WHERE namespace=$1 AND user_id=$2 AND sequence>$3 AND sequence<=$4 ORDER BY sequence LIMIT $5", namespace, user, after, watermark, limit+1)
	if err != nil {
		return r, err
	}
	type entry struct {
		key      string
		sequence int64
	}
	entries := []entry{}
	for rows.Next() {
		var e entry
		if err = rows.Scan(&e.key, &e.sequence); err != nil {
			rows.Close()
			return r, err
		}
		entries = append(entries, e)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return r, err
	}
	if len(entries) > limit {
		r.HasMore = true
		entries = entries[:limit]
	}
	for _, entry := range entries {
		result, err := loadV2(ctx, tx, namespace, user, entry.key)
		if err != nil {
			return r, err
		}
		r.Operations = append(r.Operations, result)
		r.NextAfter = entry.sequence
	}
	return r, tx.Commit(ctx)
}

func (s *Store) CurrentStateV2(ctx context.Context, namespace, user string) (bankv2.CurrentState, error) {
	return s.currentStateV2(ctx, namespace, user, nil)
}

// CurrentStateV2At accepts only an explicit server simulation timestamp; the
// same RR inventory and original validation is shared with default reads.
func (s *Store) CurrentStateV2At(ctx context.Context, namespace, user string, at time.Time) (bankv2.CurrentState, error) {
	return s.currentStateV2(ctx, namespace, user, &at)
}

func (s *Store) currentStateV2(ctx context.Context, namespace, user string, at *time.Time) (bankv2.CurrentState, error) {
	r := bankv2.CurrentState{Protocol: bankv2.Protocol, Namespace: namespace, UserID: user, Products: []bankv2.ProductSnapshot{}, Positions: []bankv2.Position{}, Accounts: []bankv2.Account{}, Goals: []bankv2.Goal{}}
	if !validIdentity(namespace, user) || at != nil && at.IsZero() {
		return r, bankv2.ErrInvalid
	}
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	if err != nil {
		return r, err
	}
	defer tx.Rollback(ctx)
	if err = userLock(ctx, tx, namespace, user); err != nil {
		return r, err
	}
	if err = tx.QueryRow(ctx, "SELECT transaction_timestamp(),coalesce((SELECT max(sequence) FROM bank.v2_operations WHERE namespace=$1 AND user_id=$2),0),coalesce((SELECT max(catalog_sequence) FROM bank.v2_product_availability WHERE namespace=$1),0)", namespace, user).Scan(&r.CapturedAt, &r.OperationWatermark, &r.CatalogWatermark); err != nil {
		return r, err
	}
	if at != nil {
		r.CapturedAt = at.UTC()
	}
	rows, err := tx.Query(ctx, "SELECT product_id,max(version) FROM bank.v2_product_terms WHERE namespace=$1 GROUP BY product_id ORDER BY product_id LIMIT 101", namespace)
	if err != nil {
		return r, err
	}
	type productRef struct {
		id      string
		version int64
	}
	products := []productRef{}
	for rows.Next() {
		var p productRef
		if err = rows.Scan(&p.id, &p.version); err != nil {
			rows.Close()
			return r, err
		}
		products = append(products, p)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return r, err
	}
	if len(products) > 100 {
		return r, ErrV2Capacity
	}
	for _, p := range products {
		product, err := productV2(ctx, tx, namespace, p.id, p.version)
		if err != nil {
			return r, err
		}
		r.Products = append(r.Products, product)
	}
	rows, err = tx.Query(ctx, "SELECT position_id FROM bank.v2_position_openings WHERE namespace=$1 AND user_id=$2 ORDER BY position_id LIMIT 1001", namespace, user)
	if err != nil {
		return r, err
	}
	ids := []string{}
	for rows.Next() {
		var id string
		if err = rows.Scan(&id); err != nil {
			rows.Close()
			return r, err
		}
		ids = append(ids, id)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return r, err
	}
	if len(ids) > 1000 {
		return r, ErrV2Capacity
	}
	for _, id := range ids {
		p, err := positionV2(ctx, tx, namespace, user, id)
		if err != nil {
			return r, err
		}
		r.Positions = append(r.Positions, p)
	}
	rows, err = tx.Query(ctx, "SELECT account_id,balance_cents,reserved_cents FROM bank.accounts WHERE namespace=$1 AND user_id=$2 ORDER BY account_id LIMIT 101", namespace, user)
	if err != nil {
		return r, err
	}
	for rows.Next() {
		var a bankv2.Account
		var balance, held int64
		if err = rows.Scan(&a.ID, &balance, &held); err != nil {
			rows.Close()
			return r, err
		}
		a.Balance, err = funds.NewMoney(balance)
		if err != nil {
			rows.Close()
			return r, err
		}
		a.Reserved, err = funds.NewMoney(held)
		if err != nil {
			rows.Close()
			return r, err
		}
		r.Accounts = append(r.Accounts, a)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return r, err
	}
	if len(r.Accounts) > 100 {
		return r, ErrV2Capacity
	}
	rows, err = tx.Query(ctx, `SELECT g.goal_id,g.account_id,g.balance_cents,coalesce(p.principal_cents,0),coalesce(p.loss_cents,0) FROM bank.goals g LEFT JOIN bank.v2_goal_principal p USING(namespace,user_id,goal_id) WHERE g.namespace=$1 AND g.user_id=$2 ORDER BY g.goal_id LIMIT 101`, namespace, user)
	if err != nil {
		return r, err
	}
	for rows.Next() {
		var g bankv2.Goal
		var cash, principal, loss int64
		if err = rows.Scan(&g.ID, &g.AccountID, &cash, &principal, &loss); err != nil {
			rows.Close()
			return r, err
		}
		g.Cash, err = funds.NewMoney(cash)
		if err != nil {
			rows.Close()
			return r, err
		}
		g.Principal, err = funds.NewMoney(principal)
		if err != nil {
			rows.Close()
			return r, err
		}
		g.Loss, err = funds.NewMoney(loss)
		if err != nil {
			rows.Close()
			return r, err
		}
		r.Goals = append(r.Goals, g)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return r, err
	}
	if len(r.Goals) > 100 {
		return r, ErrV2Capacity
	}
	return r, tx.Commit(ctx)
}
