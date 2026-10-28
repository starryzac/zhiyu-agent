package app

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"zhiyu.local/zhiyu-go/internal/adapters/postgres"
	"zhiyu.local/zhiyu-go/internal/execution/bankv2"
	funds "zhiyu.local/zhiyu-go/internal/funds/domain"
)

func commitNativeAssetProjection(n *postgres.NativeLedger, operation funds.ID, preview NativeAssetPreview, request bankv2.Request, result bankv2.Result, observedAt time.Time) error {
	if n == nil || result.Status != bankv2.Settled || bankv2.VerifyResult(request, result) != nil || request.Effect.Kind != preview.Kind || observedAt.Before(*result.SettledAt) {
		return reject("EVIDENCE_INVALID", nil)
	}
	if e := checkNativeAssetResources(*n, operation, preview); e != nil {
		return e
	}
	next := cloneNativeAssetLedger(*n)
	effect := request.Effect
	var err error
	if effect.Kind == bankv2.Purchase {
		if result.Position == nil || result.PrincipalReturn != nil {
			return reject("EVIDENCE_INVALID", nil)
		}
		if effect.SourceGoalID == "" {
			if err = commitNativeUnownedCash(&next, operation, bankv2.Purchase); err != nil {
				return err
			}
		} else {
			for _, use := range preview.GoalUses {
				found := false
				for i := range next.GoalLots {
					lot := &next.GoalLots[i]
					if lot.GoalID.String() == effect.SourceGoalID && lot.AccountID.String() == effect.CashUses[0].AccountID && lot.SourceKind == use.SourceKind && lot.SourceID == use.SourceID {
						lot.Reserved, err = lot.Reserved.Sub(use.Amount)
						if err == nil {
							lot.Available, err = lot.Available.Sub(use.Amount)
						}
						if err != nil {
							return nativeResourceConflict()
						}
						found = true
					}
				}
				if !found {
					return nativeResourceConflict()
				}
			}
			for i := range next.ReturnClaims {
				claim := &next.ReturnClaims[i]
				if claim.OperationID != operation {
					continue
				}
				if claim.State != funds.Reserved {
					return nativeResourceConflict()
				}
				found := false
				for j := range next.ReturnLocations {
					r := &next.ReturnLocations[j]
					if r.BankKey == claim.BankKey && r.AccountID == claim.AccountID {
						r.Reserved, err = r.Reserved.Sub(claim.Amount)
						if err == nil {
							r.Available, err = r.Available.Sub(claim.Amount)
						}
						if err != nil {
							return nativeResourceConflict()
						}
						found = true
					}
				}
				if !found {
					return nativeResourceConflict()
				}
				claim.State = funds.Committed
			}
		}
		for _, use := range effect.CashUses {
			found := false
			for i := range next.Accounts {
				a := &next.Accounts[i]
				if a.ID.String() != use.AccountID {
					continue
				}
				a.Balance, err = a.Balance.Sub(use.Amount)
				if err == nil && effect.SourceGoalID != "" {
					a.GoalOwned, err = a.GoalOwned.Sub(use.Amount)
				}
				if err != nil {
					return nativeResourceConflict()
				}
				a.ObservedAt = observedAt
				found = true
			}
			if !found {
				return nativeResourceConflict()
			}
		}
		if effect.SourceGoalID != "" {
			found := false
			for i := range next.Goals {
				g := &next.Goals[i]
				if g.GoalID.String() != effect.SourceGoalID {
					continue
				}
				g.Cash, err = g.Cash.Sub(effect.Amount)
				if err == nil {
					g.Principal, err = g.Principal.Add(effect.Amount)
				}
				if err != nil {
					return nativeResourceConflict()
				}
				found = true
			}
			if !found {
				return nativeResourceConflict()
			}
		}
		for _, p := range next.Positions {
			if p.ID == result.Position.PositionID {
				return nativeResourceConflict()
			}
		}
		raw, e := encode(*result.Position)
		if e != nil {
			return e
		}
		hash, e := result.Position.Digest()
		if e != nil {
			return e
		}
		op := operation
		var goal *funds.ID
		if result.Position.GoalID != "" {
			id, e := funds.ParseID(result.Position.GoalID)
			if e != nil {
				return e
			}
			goal = &id
		}
		var maturity *time.Time
		if !result.Position.MaturityAt.IsZero() {
			t := result.Position.MaturityAt
			maturity = &t
		}
		account, e := funds.ParseID(result.Position.ReturnAccountID)
		if e != nil {
			return e
		}
		next.Positions = append(next.Positions, postgres.NativePosition{ID: result.Position.PositionID, BankKey: result.Position.OpeningKey, OpeningOperationID: &op, Original: raw, OriginalHash: hash, Principal: result.Position.Principal, GoalID: goal, ReturnAccountID: account, PurchasedAt: result.Position.PurchasedAt, MaturityAt: maturity})
	} else {
		if result.Position == nil || result.PrincipalReturn == nil {
			return reject("EVIDENCE_INVALID", nil)
		}
		found := false
		for i := range next.Positions {
			p := &next.Positions[i]
			if p.ID != effect.PositionID {
				continue
			}
			if p.Closed || p.ClosingOperationID == nil || *p.ClosingOperationID != operation || p.OriginalHash != effect.PositionOpeningHash {
				return nativeResourceConflict()
			}
			p.Closed = true
			found = true
		}
		if !found {
			return nativeResourceConflict()
		}
		found = false
		for i := range next.Accounts {
			a := &next.Accounts[i]
			if a.ID.String() != effect.ReturnAccountID {
				continue
			}
			a.Balance, err = a.Balance.Add(effect.Net)
			if err == nil && effect.SourceGoalID != "" {
				a.GoalOwned, err = a.GoalOwned.Add(effect.Net)
			}
			if err != nil {
				return err
			}
			a.ObservedAt = observedAt
			found = true
		}
		if !found {
			return nativeResourceConflict()
		}
		if effect.SourceGoalID != "" {
			found = false
			for i := range next.Goals {
				g := &next.Goals[i]
				if g.GoalID.String() != effect.SourceGoalID {
					continue
				}
				g.Principal, err = g.Principal.Sub(effect.Amount)
				if err == nil {
					g.Cash, err = g.Cash.Add(effect.Net)
				}
				cost, _ := effect.Fee.Add(effect.Loss)
				if err == nil {
					g.Loss, err = g.Loss.Add(cost)
				}
				if err != nil {
					return err
				}
				found = true
			}
			if !found {
				return nativeResourceConflict()
			}
		}
		for _, r := range next.PrincipalReturns {
			if r.BankKey == result.PrincipalReturn.OperationKey {
				return nativeResourceConflict()
			}
		}
		raw, e := encode(*result.PrincipalReturn)
		if e != nil {
			return e
		}
		account, e := funds.ParseID(result.PrincipalReturn.AccountID)
		if e != nil {
			return e
		}
		next.PrincipalReturns = append(next.PrincipalReturns, postgres.NativePrincipalReturn{BankKey: result.PrincipalReturn.OperationKey, OperationID: operation, PositionID: result.PrincipalReturn.PositionID, Original: raw, OriginalHash: Hash(raw), Amount: result.PrincipalReturn.Amount, OccurredAt: result.PrincipalReturn.OccurredAt})
		next.ReturnLocations = append(next.ReturnLocations, postgres.NativeReturnLocation{BankKey: result.PrincipalReturn.OperationKey, AccountID: account, Available: result.PrincipalReturn.Amount})
		if effect.SourceGoalID != "" {
			goal, e := funds.ParseID(effect.SourceGoalID)
			if e != nil {
				return e
			}
			next.GoalLots = append(next.GoalLots, postgres.NativeGoalLot{GoalID: goal, AccountID: account, SourceKind: "PRINCIPAL_RETURN", SourceID: result.PrincipalReturn.OperationKey, Available: result.PrincipalReturn.Amount})
		}
	}
	for i := range next.Holds {
		if next.Holds[i].OperationID == operation {
			next.Holds[i].State = funds.Committed
		}
	}
	*n = next
	return nil
}

// The caller already saved the verified bank rejection in the same observation
// transaction. This is the sole signed no-effect path that releases asset pins.
func (s *Service) assetReject(ctx context.Context, tx pgx.Tx, c Claim, request bankv2.Request, result bankv2.Result) error {
	if !nativeAssetKind(request.Effect.Kind) || result.Status != bankv2.Rejected || bankv2.VerifyResult(request, result) != nil {
		return reject("EVIDENCE_INVALID", nil)
	}
	p := c.Principal
	var signature *string
	if e := tx.QueryRow(ctx, `SELECT permit_signature FROM native_operations WHERE environment_id=$1 AND user_id=$2 AND id=$3`, p.EnvironmentID.String(), p.UserID.String(), c.OperationID.String()).Scan(&signature); e != nil {
		return e
	}
	if signature == nil {
		return reject("EVIDENCE_INVALID", nil)
	}
	if e := assetStoredPermit(ctx, tx, p, c.OperationID, request, *signature); e != nil {
		return e
	}
	ledger, e := s.Store.LoadNativeLedger(ctx, tx, p.EnvironmentID, p.UserID, s.now())
	if e != nil {
		return e
	}
	if e = releaseNativeAssetResources(&ledger, c.OperationID); e != nil {
		return e
	}
	if _, e = tx.Exec(ctx, `UPDATE native_operations SET status='REJECTED',bank_observed_status='REJECTED',processing_health=$4,version=version+1,updated_at=$5 WHERE environment_id=$1 AND user_id=$2 AND id=$3`, p.EnvironmentID.String(), p.UserID.String(), c.OperationID.String(), result.RejectionCode, s.now()); e != nil {
		return e
	}
	if e = s.Store.PersistNativeLedger(ctx, tx, p.EnvironmentID, p.UserID, ledger); e != nil {
		return e
	}
	if e = s.assetStandingFinalizeBudget(ctx, tx, p, c.OperationID, funds.Money{}); e != nil {
		return e
	}
	cause, e := s.nativeBankRejectionCause(ctx, tx, p, c.OperationID, result)
	if e != nil {
		return e
	}
	if e = s.recordFundsTerminalDecision(ctx, tx, p, "NATIVE", c.OperationID, "REJECTED", cause); e != nil {
		return e
	}
	if _, e = tx.Exec(ctx, `UPDATE users SET funds_version=funds_version+1 WHERE environment_id=$1 AND id=$2`, p.EnvironmentID.String(), p.UserID.String()); e != nil {
		return e
	}
	if e = s.assetProtection(ctx, tx, p, c.OperationID); e != nil {
		return e
	}
	if e = finishNativeJob(ctx, tx, c); e != nil {
		return e
	}
	return tx.Commit(ctx)
}

func (s *Service) bookNativeAsset(ctx context.Context, c Claim, request bankv2.Request, result bankv2.Result) error {
	if !nativeAssetKind(request.Effect.Kind) || result.Status != bankv2.Settled || bankv2.VerifyResult(request, result) != nil {
		return reject("EVIDENCE_INVALID", nil)
	}
	tx, e := s.begin(ctx)
	if e != nil {
		return e
	}
	defer rollback(ctx, tx)
	if e = s.lockNativeClaim(ctx, tx, c); e != nil {
		return e
	}
	p := c.Principal
	var state, previewText, stored string
	var signature *string
	if e = tx.QueryRow(ctx, `SELECT status,preview_id::text,bank_request_hash::text,permit_signature FROM native_operations WHERE environment_id=$1 AND user_id=$2 AND id=$3`, p.EnvironmentID.String(), p.UserID.String(), c.OperationID.String()).Scan(&state, &previewText, &stored, &signature); e != nil {
		return e
	}
	if state == "SETTLED" {
		return nil
	}
	if state != "RECONCILING" || signature == nil {
		return reject("OPERATION_UNKNOWN", nil)
	}
	hash, e := request.Digest()
	if e != nil || hash != stored {
		return reject("EVIDENCE_INVALID", e)
	}
	if e = assetStoredPermit(ctx, tx, p, c.OperationID, request, *signature); e != nil {
		return e
	}
	id, e := funds.ParseID(previewText)
	if e != nil {
		return e
	}
	preview, e := loadAssetExecutionPreview(ctx, tx, p, c.OperationID, id, request.Effect.Kind)
	if e != nil {
		return e
	}
	ledger, e := s.Store.LoadNativeLedger(ctx, tx, p.EnvironmentID, p.UserID, s.now())
	if e != nil {
		return e
	}
	now := s.now()
	if e = commitNativeAssetProjection(&ledger, c.OperationID, preview, request, result, now); e != nil {
		return e
	}
	journal, e := newID()
	if e != nil {
		return e
	}
	receiptID, e := newID()
	if e != nil {
		return e
	}
	if _, e = tx.Exec(ctx, `INSERT INTO native_journals(environment_id,user_id,id,operation_id,kind,status,created_at) VALUES($1,$2,$3,$4,$5,'DRAFT',$6)`, p.EnvironmentID.String(), p.UserID.String(), journal.String(), c.OperationID.String(), string(request.Effect.Kind), now); e != nil {
		return e
	}
	for i, leg := range result.Postings {
		if _, e = tx.Exec(ctx, `INSERT INTO native_postings(environment_id,user_id,journal_id,leg_ref,bank_posting_id,dimension,ledger_id,direction,amount_cents,occurred_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`, p.EnvironmentID.String(), p.UserID.String(), journal.String(), fmt.Sprintf("bank:%d:%s", i+1, leg.ID), leg.ID, leg.Dimension, leg.LedgerID, leg.Direction, leg.Amount.Cents(), leg.OccurredAt); e != nil {
			return e
		}
	}
	if _, e = tx.Exec(ctx, `UPDATE native_journals SET status='POSTED',posted_at=$4 WHERE environment_id=$1 AND user_id=$2 AND id=$3`, p.EnvironmentID.String(), p.UserID.String(), journal.String(), now); e != nil {
		return e
	}
	receipt := NativeReceipt{"native-receipt-v1", receiptID, c.OperationID, preview.ID, journal, result, now}
	raw, e := encode(receipt)
	if e != nil {
		return e
	}
	if _, e = tx.Exec(ctx, `INSERT INTO native_receipts(environment_id,user_id,id,operation_id,journal_id,original,original_hash,created_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8)`, p.EnvironmentID.String(), p.UserID.String(), receiptID.String(), c.OperationID.String(), journal.String(), raw, Hash(raw), now); e != nil {
		return e
	}
	if _, e = tx.Exec(ctx, `UPDATE native_operations SET status='SETTLED',receipt_id=$4,processing_health='HEALTHY',version=version+1,updated_at=$5 WHERE environment_id=$1 AND user_id=$2 AND id=$3`, p.EnvironmentID.String(), p.UserID.String(), c.OperationID.String(), receiptID.String(), now); e != nil {
		return e
	}
	if e = s.Store.PersistNativeLedger(ctx, tx, p.EnvironmentID, p.UserID, ledger); e != nil {
		return e
	}
	if e = s.assetStandingFinalizeBudget(ctx, tx, p, c.OperationID, request.Effect.Amount); e != nil {
		return e
	}
	if request.Effect.SourceGoalID != "" {
		tag, ue := tx.Exec(ctx, `UPDATE goals SET version=version+1 WHERE environment_id=$1 AND user_id=$2 AND id=$3`, p.EnvironmentID.String(), p.UserID.String(), request.Effect.SourceGoalID)
		if e = assertOne(tag, ue); e != nil {
			return e
		}
	}
	if _, e = tx.Exec(ctx, `UPDATE users SET funds_version=funds_version+1 WHERE environment_id=$1 AND id=$2`, p.EnvironmentID.String(), p.UserID.String()); e != nil {
		return e
	}
	if e = s.assetProtection(ctx, tx, p, c.OperationID); e != nil {
		return e
	}
	event, e := newID()
	if e != nil {
		return e
	}
	if _, e = tx.Exec(ctx, `INSERT INTO outbox(environment_id,user_id,id,aggregate_id,aggregate_version,kind,payload,created_at) SELECT $1,$2,$3,id,version,'NATIVE_OPERATION_SETTLED',$5,$6 FROM native_operations WHERE environment_id=$1 AND user_id=$2 AND id=$4`, p.EnvironmentID.String(), p.UserID.String(), event.String(), c.OperationID.String(), raw, now); e != nil {
		return e
	}
	if _, e = tx.Exec(ctx, `INSERT INTO evidence_blobs(environment_id,user_id,id,kind,canonical,digest,created_at) VALUES($1,$2,$3,'NATIVE_ASSET_SETTLEMENT',$4,$5,$6)`, p.EnvironmentID.String(), p.UserID.String(), "native-asset:"+c.OperationID.String(), raw, Hash(raw), now); e != nil {
		return e
	}
	if e = finishNativeJob(ctx, tx, c); e != nil {
		return e
	}
	if s.Failpoint != nil {
		if e = s.Failpoint("native_before_local_commit"); e != nil {
			return e
		}
	}
	return tx.Commit(ctx)
}
