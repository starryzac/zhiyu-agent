package postgres

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	bankv2 "zhiyu.local/zhiyu-go/internal/execution/bankv2"
	funds "zhiyu.local/zhiyu-go/internal/funds/domain"
)

func readNativeRows[T any](ctx context.Context, tx pgx.Tx, env, user funds.ID, query string) ([]T, error) {
	rows, err := tx.Query(ctx, query, env.String(), user.String())
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := []T{}
	for rows.Next() {
		var raw []byte
		if err = rows.Scan(&raw); err != nil {
			return nil, err
		}
		var item T
		decoder := json.NewDecoder(bytes.NewReader(raw))
		decoder.DisallowUnknownFields()
		if err = decoder.Decode(&item); err != nil {
			return nil, ErrLedgerConflict
		}
		items = append(items, item)
	}
	return items, rows.Err()
}

// LoadNativeLedger reads actual persisted resources; it never asks the bank to
// invent a response or promotes pending principal to cash. A caller must hold
// the same user lock used by v1 and roll back on every error.
func (s *Store) LoadNativeLedger(ctx context.Context, tx pgx.Tx, env, user funds.ID, now time.Time) (NativeLedger, error) {
	var n NativeLedger
	if tx == nil {
		return n, ErrLedgerConflict
	}
	enabled, err := nativeLedgerEnabled(ctx, tx)
	if err != nil {
		return n, err
	}
	if !enabled {
		return n, ErrLedgerConflict
	}
	if err = tx.QueryRow(ctx, `SELECT namespace FROM environments WHERE id=$1`, env.String()).Scan(&n.Namespace); err != nil {
		return n, err
	}
	if n.Income, err = s.LoadLedger(ctx, tx, env, user, now); err != nil {
		return n, err
	}
	if n.Accounts, err = readNativeRows[NativeAccount](ctx, tx, env, user, `SELECT jsonb_build_object('ID',id,'Balance',balance_cents::text,'GoalOwned',goal_owned_cents::text,'ObservedAt',observed_at) FROM accounts WHERE environment_id=$1 AND user_id=$2 ORDER BY id`); err != nil {
		return n, err
	}
	if n.Goals, err = readNativeRows[NativeGoalBalance](ctx, tx, env, user, `SELECT jsonb_build_object('GoalID',b.goal_id,'AccountID',g.account_id,'Cash',b.cash_cents::text,'Principal',b.principal_cents::text,'Loss',b.loss_cents::text) FROM native_goal_balances b JOIN goals g ON(g.environment_id=b.environment_id AND g.user_id=b.user_id AND g.id=b.goal_id) WHERE b.environment_id=$1 AND b.user_id=$2 ORDER BY b.goal_id`); err != nil {
		return n, err
	}
	if n.GoalLots, err = readNativeRows[NativeGoalLot](ctx, tx, env, user, `SELECT jsonb_build_object('GoalID',goal_id,'AccountID',account_id,'SourceKind',source_kind,'SourceID',source_id,'Available',available_cents::text,'Reserved',reserved_cents::text) FROM native_goal_lots WHERE environment_id=$1 AND user_id=$2 ORDER BY goal_id,account_id,source_kind,source_id`); err != nil {
		return n, err
	}
	if n.Holds, err = readNativeRows[NativeHold](ctx, tx, env, user, `SELECT jsonb_build_object('OperationID',operation_id,'ResourceKind',resource_kind,'ResourceID',resource_id,'ResourceDetail',resource_detail,'Amount',amount_cents::text,'State',state) FROM native_holds WHERE environment_id=$1 AND user_id=$2 ORDER BY operation_id,resource_kind,resource_id,resource_detail`); err != nil {
		return n, err
	}
	if n.Positions, err = readNativeRows[NativePosition](ctx, tx, env, user, `SELECT jsonb_build_object('ID',p.id,'BankKey',p.bank_key,'OpeningOperationID',p.opening_operation_id,'Original',encode(p.original,'base64'),'OriginalHash',p.original_hash,'Principal',p.principal_cents::text,'GoalID',p.goal_id,'ReturnAccountID',p.return_account_id,'PurchasedAt',p.purchased_at,'MaturityAt',p.maturity_at,'ClosingOperationID',s.closing_operation_id,'Closed',s.closed) FROM native_positions p JOIN native_position_states s ON(s.environment_id=p.environment_id AND s.user_id=p.user_id AND s.position_id=p.id) WHERE p.environment_id=$1 AND p.user_id=$2 ORDER BY p.id`); err != nil {
		return n, err
	}
	if n.PrincipalReturns, err = readNativeRows[NativePrincipalReturn](ctx, tx, env, user, `SELECT jsonb_build_object('BankKey',bank_key,'OperationID',operation_id,'PositionID',position_id,'Original',encode(original,'base64'),'OriginalHash',original_hash,'Amount',amount_cents::text,'OccurredAt',occurred_at) FROM native_principal_returns WHERE environment_id=$1 AND user_id=$2 ORDER BY bank_key`); err != nil {
		return n, err
	}
	if n.ReturnLocations, err = readNativeRows[NativeReturnLocation](ctx, tx, env, user, `SELECT jsonb_build_object('BankKey',bank_key,'AccountID',account_id,'Available',available_cents::text,'Reserved',reserved_cents::text) FROM native_return_locations WHERE environment_id=$1 AND user_id=$2 ORDER BY bank_key,account_id`); err != nil {
		return n, err
	}
	if n.ReturnClaims, err = readNativeRows[NativeReturnClaim](ctx, tx, env, user, `SELECT jsonb_build_object('OperationID',operation_id,'BankKey',bank_key,'AccountID',account_id,'Amount',amount_cents::text,'State',state) FROM native_return_claims WHERE environment_id=$1 AND user_id=$2 ORDER BY operation_id,bank_key,account_id`); err != nil {
		return n, err
	}
	return n, n.validate(user)
}

func validNativeState(s funds.ReservationState) bool {
	return s == funds.Reserved || s == funds.Committed || s == funds.Released
}
func nativeRawHash(raw []byte) string { h := sha256.Sum256(raw); return hex.EncodeToString(h[:]) }
func optionalNativeID(id *funds.ID) any {
	if id == nil {
		return nil
	}
	return id.String()
}
func nativeAdd(m map[string]funds.Money, key string, n funds.Money) error {
	value, err := m[key].Add(n)
	if err != nil {
		return err
	}
	m[key] = value
	return nil
}
func nativeLotKey(g, a funds.ID, k, id string) string {
	return g.String() + ":" + a.String() + ":" + k + ":" + id
}

// This validates the complete storage projection and original identities, not
// USER permission or bank HMAC authenticity. Application must VerifyResult
// against its immutable request before any settlement mutation.
func (n NativeLedger) validate(user funds.ID) error {
	if n.Namespace == "" || n.Income.Validate() != nil || n.Income.Snapshot().UserID != user {
		return ErrLedgerConflict
	}
	snapshot := n.Income.Snapshot()
	accounts := map[funds.ID]NativeAccount{}
	for _, a := range n.Accounts {
		if a.ID == (funds.ID{}) || a.ObservedAt.IsZero() || a.GoalOwned.Cents() > a.Balance.Cents() {
			return ErrLedgerConflict
		}
		if _, ok := accounts[a.ID]; ok {
			return ErrLedgerConflict
		}
		accounts[a.ID] = a
	}
	if len(accounts) != len(snapshot.ScopeAccountIDs) {
		return ErrLedgerConflict
	}
	for _, id := range snapshot.ScopeAccountIDs {
		if _, ok := accounts[id]; !ok {
			return ErrLedgerConflict
		}
	}
	goals := map[funds.ID]NativeGoalBalance{}
	owned := map[string]funds.Money{}
	lotTotals := map[string]funds.Money{}
	principalTotals := map[string]funds.Money{}
	for _, g := range n.Goals {
		if g.GoalID == (funds.ID{}) {
			return ErrLedgerConflict
		}
		if _, ok := goals[g.GoalID]; ok {
			return ErrLedgerConflict
		}
		if _, ok := accounts[g.AccountID]; !ok {
			return ErrLedgerConflict
		}
		if _, err := g.Cash.Add(g.Principal); err != nil {
			return err
		}
		goals[g.GoalID] = g
		if err := nativeAdd(owned, g.AccountID.String(), g.Cash); err != nil {
			return err
		}
	}
	for _, a := range n.Accounts {
		if owned[a.ID.String()] != a.GoalOwned {
			return ErrLedgerConflict
		}
	}
	origins := map[string]bool{}
	for _, o := range snapshot.Origins {
		origins[o.ID().String()] = true
	}
	returns := map[string]NativePrincipalReturn{}
	positions := map[string]NativePosition{}
	for _, p := range n.Positions {
		var original bankv2.PositionOpening
		if json.Unmarshal(p.Original, &original) != nil || original.Validate() != nil {
			return ErrLedgerConflict
		}
		h, err := original.Digest()
		if err != nil {
			return err
		}
		if h != p.OriginalHash || p.ID != original.PositionID || p.BankKey != original.OpeningKey || original.Namespace != n.Namespace || original.UserID != user.String() || p.Principal != original.Principal || p.ReturnAccountID.String() != original.ReturnAccountID || !p.PurchasedAt.Equal(original.PurchasedAt) || (p.MaturityAt == nil) != original.MaturityAt.IsZero() || p.MaturityAt != nil && !p.MaturityAt.Equal(original.MaturityAt) || (p.GoalID == nil) != (original.GoalID == "") || p.GoalID != nil && p.GoalID.String() != original.GoalID || p.Closed && p.ClosingOperationID == nil {
			return ErrLedgerConflict
		}
		if (p.OpeningOperationID == nil) != (original.SourceKind == "TRUSTED_HISTORICAL_IMPORT") {
			return ErrLedgerConflict
		}
		if _, ok := positions[p.ID]; ok {
			return ErrLedgerConflict
		}
		positions[p.ID] = p
		if _, ok := accounts[p.ReturnAccountID]; !ok {
			return ErrLedgerConflict
		}
		if p.GoalID != nil {
			if _, ok := goals[*p.GoalID]; !ok {
				return ErrLedgerConflict
			}
			if !p.Closed {
				if err := nativeAdd(principalTotals, p.GoalID.String(), p.Principal); err != nil {
					return err
				}
			}
		}
	}
	for _, r := range n.PrincipalReturns {
		var original bankv2.PrincipalReturn
		if json.Unmarshal(r.Original, &original) != nil || original.Role != "PRINCIPAL_RETURN" || nativeRawHash(r.Original) != r.OriginalHash || r.BankKey != original.OperationKey || r.PositionID != original.PositionID || r.Amount != original.Amount || !r.OccurredAt.Equal(original.OccurredAt) {
			return ErrLedgerConflict
		}
		p, ok := positions[r.PositionID]
		if !ok || !p.Closed || p.ClosingOperationID == nil || *p.ClosingOperationID != r.OperationID || p.OriginalHash != original.PositionOpeningHash || p.ReturnAccountID.String() != original.AccountID {
			return ErrLedgerConflict
		}
		if _, ok := returns[r.BankKey]; ok {
			return ErrLedgerConflict
		}
		returns[r.BankKey] = r
	}
	closedReturns := map[string]bool{}
	lossTotals := map[string]funds.Money{}
	for _, r := range n.PrincipalReturns {
		p := positions[r.PositionID]
		if closedReturns[p.ID] {
			return ErrLedgerConflict
		}
		closedReturns[p.ID] = true
		loss, err := p.Principal.Sub(r.Amount)
		if err != nil {
			return ErrLedgerConflict
		}
		if p.GoalID != nil {
			if err = nativeAdd(lossTotals, p.GoalID.String(), loss); err != nil {
				return err
			}
		}
	}
	for _, p := range n.Positions {
		if p.Closed && !closedReturns[p.ID] {
			return ErrLedgerConflict
		}
	}
	lotSeen := map[string]bool{}
	for _, l := range n.GoalLots {
		g, ok := goals[l.GoalID]
		if !ok || g.AccountID != l.AccountID || l.Reserved.Cents() > l.Available.Cents() {
			return ErrLedgerConflict
		}
		if l.SourceKind == "INCOME" {
			if !origins[l.SourceID] {
				return ErrLedgerConflict
			}
		} else if l.SourceKind == "PRINCIPAL_RETURN" {
			if _, ok := returns[l.SourceID]; !ok {
				return ErrLedgerConflict
			}
		} else {
			return ErrLedgerConflict
		}
		key := nativeLotKey(l.GoalID, l.AccountID, l.SourceKind, l.SourceID)
		if lotSeen[key] {
			return ErrLedgerConflict
		}
		lotSeen[key] = true
		if err := nativeAdd(lotTotals, l.GoalID.String(), l.Available); err != nil {
			return err
		}
	}
	for _, g := range n.Goals {
		if lotTotals[g.GoalID.String()] != g.Cash || principalTotals[g.GoalID.String()] != g.Principal || lossTotals[g.GoalID.String()] != g.Loss {
			return ErrLedgerConflict
		}
	}
	locationTotals := map[string]funds.Money{}
	claimTotals := map[string]funds.Money{}
	locationSeen := map[string]bool{}
	claimSeen := map[string]bool{}
	for _, c := range n.ReturnClaims {
		key := c.BankKey + ":" + c.AccountID.String()
		identity := c.OperationID.String() + ":" + key
		if claimSeen[identity] || c.Amount.IsZero() || !validNativeState(c.State) {
			return ErrLedgerConflict
		}
		claimSeen[identity] = true
		if c.State == funds.Reserved {
			if err := nativeAdd(claimTotals, key, c.Amount); err != nil {
				return err
			}
		}
	}
	for _, l := range n.ReturnLocations {
		key := l.BankKey + ":" + l.AccountID.String()
		if locationSeen[key] || l.Reserved.Cents() > l.Available.Cents() || claimTotals[key] != l.Reserved {
			return ErrLedgerConflict
		}
		locationSeen[key] = true
		if _, ok := returns[l.BankKey]; !ok {
			return ErrLedgerConflict
		}
		if _, ok := accounts[l.AccountID]; !ok {
			return ErrLedgerConflict
		}
		if err := nativeAdd(locationTotals, l.BankKey, l.Available); err != nil {
			return err
		}
	}
	for _, c := range n.ReturnClaims {
		if !locationSeen[c.BankKey+":"+c.AccountID.String()] {
			return ErrLedgerConflict
		}
	}
	for key, total := range locationTotals {
		if total.Cents() > returns[key].Amount.Cents() {
			return ErrLedgerConflict
		}
	}
	holdSeen := map[string]bool{}
	fragments := map[string]bool{}
	for _, l := range snapshot.Locations {
		fragments[l.FragmentID.String()] = true
	}
	for _, h := range n.Holds {
		key := h.OperationID.String() + ":" + h.ResourceKind + ":" + h.ResourceID + ":" + h.ResourceDetail
		if holdSeen[key] || h.Amount.IsZero() || !validNativeState(h.State) {
			return ErrLedgerConflict
		}
		holdSeen[key] = true
		switch h.ResourceKind {
		case "CASH", "INCOMING_CASH":
			id, err := funds.ParseID(h.ResourceID)
			if err != nil {
				return ErrLedgerConflict
			}
			if _, ok := accounts[id]; !ok {
				return ErrLedgerConflict
			}
		case "GOAL", "INCOMING_GOAL", "GOAL_LOT":
			id, err := funds.ParseID(h.ResourceID)
			if err != nil {
				return ErrLedgerConflict
			}
			if _, ok := goals[id]; !ok {
				return ErrLedgerConflict
			}
			if h.ResourceKind == "GOAL_LOT" {
				var ref NativeLotReference
				if json.Unmarshal([]byte(h.ResourceDetail), &ref) != nil {
					return ErrLedgerConflict
				}
				a, err := funds.ParseID(ref.AccountID)
				if err != nil || !lotSeen[nativeLotKey(id, a, ref.SourceKind, ref.SourceID)] {
					return ErrLedgerConflict
				}
			}
		case "ASSIGNED":
			if !fragments[h.ResourceID] {
				return ErrLedgerConflict
			}
		case "POSITION":
			if _, ok := positions[h.ResourceID]; !ok {
				return ErrLedgerConflict
			}
		case "LIABILITY":
		default:
			return ErrLedgerConflict
		}
	}
	return nil
}

func nativeExecOne(ctx context.Context, tx pgx.Tx, query string, args ...any) error {
	tag, err := tx.Exec(ctx, query, args...)
	if err != nil {
		return err
	}
	if tag.RowsAffected() != 1 {
		return ErrLedgerConflict
	}
	return nil
}
func nativeQueueOne(batch *pgx.Batch, query string, args ...any) {
	batch.Queue(query, args...).Exec(func(tag pgconn.CommandTag) error {
		if tag.RowsAffected() != 1 {
			return ErrLedgerConflict
		}
		return nil
	})
}

func nativeQueueOriginal(batch *pgx.Batch, query string, args ...any) {
	batch.Queue(query, args...).QueryRow(func(row pgx.Row) error {
		var same bool
		if err := row.Scan(&same); err != nil {
			return err
		}
		if !same {
			return ErrLedgerConflict
		}
		return nil
	})
}

// PersistNativeLedger saves a complete snapshot without deleting history. It
// does not insert commands/jobs or authorize any financial effect. All new
// action IDs must already belong to a native operation in this transaction.
// Callers must roll back on every error. A batch can execute later statements
// before an earlier result check fails; no part of that transaction may commit.
func (s *Store) PersistNativeLedger(ctx context.Context, tx pgx.Tx, env, user funds.ID, n NativeLedger) error {
	if tx == nil {
		return ErrLedgerConflict
	}
	if err := n.validate(user); err != nil {
		return err
	}
	var namespace string
	if err := tx.QueryRow(ctx, `SELECT namespace FROM environments WHERE id=$1`, env.String()).Scan(&namespace); err != nil {
		return err
	}
	if namespace != n.Namespace {
		return ErrLedgerConflict
	}
	// Read the complete actual scope in this same transaction, never a cached
	// or partial prior snapshot. Only four complete resource sets select deltas;
	// all other original writes and final full verification remain unchanged.
	previous, err := s.LoadNativeLedger(ctx, tx, env, user, n.Income.Snapshot().AsOf)
	if err != nil {
		return err
	}
	changes, err := nativeChangedResources(previous, n)
	if err != nil {
		return err
	}
	var writes pgx.Batch
	for _, a := range n.Accounts {
		nativeQueueOne(&writes, `UPDATE accounts SET balance_cents=$4,goal_owned_cents=$5,observed_at=$6 WHERE environment_id=$1 AND user_id=$2 AND id=$3`, env.String(), user.String(), a.ID.String(), a.Balance.Cents(), a.GoalOwned.Cents(), a.ObservedAt)
	}
	for _, g := range n.Goals {
		assigned, err := g.Cash.Add(g.Principal)
		if err != nil {
			return err
		}
		nativeQueueOne(&writes, `UPDATE goals SET assigned_cents=$4 WHERE environment_id=$1 AND user_id=$2 AND id=$3 AND account_id=$5`, env.String(), user.String(), g.GoalID.String(), assigned.Cents(), g.AccountID.String())
		nativeQueueOne(&writes, `INSERT INTO native_goal_balances(environment_id,user_id,goal_id,cash_cents,principal_cents,loss_cents) VALUES($1,$2,$3,$4,$5,$6) ON CONFLICT(environment_id,user_id,goal_id) DO UPDATE SET cash_cents=EXCLUDED.cash_cents,principal_cents=EXCLUDED.principal_cents,loss_cents=EXCLUDED.loss_cents`, env.String(), user.String(), g.GoalID.String(), g.Cash.Cents(), g.Principal.Cents(), g.Loss.Cents())
	}
	for _, l := range changes.GoalLots {
		nativeQueueOne(&writes, `INSERT INTO native_goal_lots(environment_id,user_id,goal_id,account_id,source_kind,source_id,available_cents,reserved_cents) VALUES($1,$2,$3,$4,$5,$6,$7,$8) ON CONFLICT(environment_id,user_id,goal_id,account_id,source_kind,source_id) DO UPDATE SET available_cents=EXCLUDED.available_cents,reserved_cents=EXCLUDED.reserved_cents`, env.String(), user.String(), l.GoalID.String(), l.AccountID.String(), l.SourceKind, l.SourceID, l.Available.Cents(), l.Reserved.Cents())
	}
	for _, h := range changes.Holds {
		nativeQueueOne(&writes, `INSERT INTO native_holds(environment_id,user_id,operation_id,resource_kind,resource_id,resource_detail,amount_cents,state) VALUES($1,$2,$3,$4,$5,$6,$7,$8) ON CONFLICT(environment_id,user_id,operation_id,resource_kind,resource_id,resource_detail) DO UPDATE SET state=EXCLUDED.state WHERE native_holds.amount_cents=EXCLUDED.amount_cents`, env.String(), user.String(), h.OperationID.String(), h.ResourceKind, h.ResourceID, h.ResourceDetail, h.Amount.Cents(), string(h.State))
	}
	for _, p := range n.Positions {
		args := []any{env.String(), user.String(), p.ID, optionalNativeID(p.OpeningOperationID), p.BankKey, p.Original, p.OriginalHash, p.Principal.Cents(), optionalNativeID(p.GoalID), p.ReturnAccountID.String(), p.PurchasedAt, p.MaturityAt}
		writes.Queue(`INSERT INTO native_positions(environment_id,user_id,id,opening_operation_id,bank_key,original,original_hash,principal_cents,goal_id,return_account_id,purchased_at,maturity_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12) ON CONFLICT(environment_id,user_id,id) DO NOTHING`, args...)
		nativeQueueOriginal(&writes, `SELECT opening_operation_id IS NOT DISTINCT FROM $4::uuid AND bank_key=$5 AND original=$6 AND original_hash=$7 AND principal_cents=$8 AND goal_id IS NOT DISTINCT FROM $9::uuid AND return_account_id=$10::uuid AND purchased_at=$11 AND maturity_at IS NOT DISTINCT FROM $12::timestamptz FROM native_positions WHERE environment_id=$1 AND user_id=$2 AND id=$3`, args...)
		nativeQueueOne(&writes, `INSERT INTO native_position_states(environment_id,user_id,position_id,closing_operation_id,closed) VALUES($1,$2,$3,$4,$5) ON CONFLICT(environment_id,user_id,position_id) DO UPDATE SET closing_operation_id=EXCLUDED.closing_operation_id,closed=EXCLUDED.closed`, env.String(), user.String(), p.ID, optionalNativeID(p.ClosingOperationID), p.Closed)
	}
	for _, r := range n.PrincipalReturns {
		args := []any{env.String(), user.String(), r.BankKey, r.OperationID.String(), r.PositionID, r.Original, r.OriginalHash, r.Amount.Cents(), r.OccurredAt}
		writes.Queue(`INSERT INTO native_principal_returns(environment_id,user_id,bank_key,operation_id,position_id,original,original_hash,amount_cents,occurred_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9) ON CONFLICT(environment_id,user_id,bank_key) DO NOTHING`, args...)
		nativeQueueOriginal(&writes, `SELECT operation_id=$4::uuid AND position_id=$5 AND original=$6 AND original_hash=$7 AND amount_cents=$8 AND occurred_at=$9 FROM native_principal_returns WHERE environment_id=$1 AND user_id=$2 AND bank_key=$3`, args...)
	}
	for _, l := range changes.ReturnLocations {
		nativeQueueOne(&writes, `INSERT INTO native_return_locations(environment_id,user_id,bank_key,account_id,available_cents,reserved_cents) VALUES($1,$2,$3,$4,$5,$6) ON CONFLICT(environment_id,user_id,bank_key,account_id) DO UPDATE SET available_cents=EXCLUDED.available_cents,reserved_cents=EXCLUDED.reserved_cents`, env.String(), user.String(), l.BankKey, l.AccountID.String(), l.Available.Cents(), l.Reserved.Cents())
	}
	for _, c := range changes.ReturnClaims {
		nativeQueueOne(&writes, `INSERT INTO native_return_claims(environment_id,user_id,operation_id,bank_key,account_id,amount_cents,state) VALUES($1,$2,$3,$4,$5,$6,$7) ON CONFLICT(environment_id,user_id,operation_id,bank_key,account_id) DO UPDATE SET state=EXCLUDED.state WHERE native_return_claims.amount_cents=EXCLUDED.amount_cents`, env.String(), user.String(), c.OperationID.String(), c.BankKey, c.AccountID.String(), c.Amount.Cents(), string(c.State))
	}
	// Close consumes every queued result and checks callbacks before the next
	// transaction query. Queue order and all per-result assertions are retained.
	if err := tx.SendBatch(ctx, &writes).Close(); err != nil {
		return err
	}
	if err := s.SaveLedger(ctx, tx, env, user, n.Income); err != nil {
		return err
	}
	for table, expected := range map[string]int{"accounts": len(n.Accounts), "goals": len(n.Goals), "native_goal_balances": len(n.Goals), "native_goal_lots": len(n.GoalLots), "native_holds": len(n.Holds), "native_positions": len(n.Positions), "native_position_states": len(n.Positions), "native_principal_returns": len(n.PrincipalReturns), "native_return_locations": len(n.ReturnLocations), "native_return_claims": len(n.ReturnClaims)} {
		var count int
		if err := tx.QueryRow(ctx, `SELECT count(*) FROM `+table+` WHERE environment_id=$1 AND user_id=$2`, env.String(), user.String()).Scan(&count); err != nil {
			return err
		}
		if count != expected {
			return ErrLedgerConflict
		}
	}
	if _, err := s.LoadNativeLedger(ctx, tx, env, user, n.Income.Snapshot().AsOf); err != nil {
		return fmt.Errorf("saved native ledger validation: %w", err)
	}
	return nil
}
