package app

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5"
	"zhiyu.local/zhiyu-go/internal/execution/bankv2"
	funds "zhiyu.local/zhiyu-go/internal/funds/domain"
	policy "zhiyu.local/zhiyu-go/internal/policy/domain"
)

func (s *Service) standingBridgeReject(ctx context.Context, tx pgx.Tx, c Claim, request bankv2.Request, result bankv2.Result) error {
	if result.Status != bankv2.Rejected || bankv2.VerifyResult(request, result) != nil {
		return reject("EVIDENCE_INVALID", nil)
	}
	p := c.Principal
	g, _, _, e := loadStandingBridge(ctx, tx, p, c.OperationID)
	if e != nil {
		return e
	}
	ledger, e := s.Store.LoadNativeLedger(ctx, tx, p.EnvironmentID, p.UserID, s.now())
	if e != nil {
		return e
	}
	ledger.Income, e = ledger.Income.Release(c.OperationID, s.now(), true)
	if e != nil {
		return e
	}
	for i := range ledger.Holds {
		if ledger.Holds[i].OperationID == c.OperationID {
			ledger.Holds[i].State = funds.Released
		}
	}
	_, e = tx.Exec(ctx, `UPDATE native_operations SET status='REJECTED',bank_observed_status='REJECTED',processing_health=$4,version=version+1,updated_at=$5 WHERE environment_id=$1 AND user_id=$2 AND id=$3`, p.EnvironmentID.String(), p.UserID.String(), c.OperationID.String(), result.RejectionCode, s.now())
	if e != nil {
		return e
	}
	if e = s.cancelStandingBridgeSuffix(ctx, tx, p, g, &ledger, result.RejectionCode); e != nil {
		return e
	}
	if e = s.Store.PersistNativeLedger(ctx, tx, p.EnvironmentID, p.UserID, ledger); e != nil {
		return e
	}
	if e = s.finalizeStandingBridgeBudget(ctx, tx, p, g, true); e != nil {
		return e
	}
	if e = s.recordNativeRejection(ctx, tx, p, c.OperationID, result); e != nil {
		return e
	}
	if _, e = tx.Exec(ctx, `UPDATE users SET funds_version=funds_version+1 WHERE environment_id=$1 AND id=$2`, p.EnvironmentID.String(), p.UserID.String()); e != nil {
		return e
	}
	if _, _, e = s.refreshTemplateProtectionAfterNativeEffect(ctx, tx, p, g.Grant.Terms.Timezone); e != nil {
		return e
	}
	if e = finishNativeJob(ctx, tx, c); e != nil {
		return e
	}
	return tx.Commit(ctx)
}

func (s *Service) standingBridgeBook(ctx context.Context, c Claim, request bankv2.Request, result bankv2.Result) error {
	if result.Status != bankv2.Settled || bankv2.VerifyResult(request, result) != nil || (request.Effect.Kind != bankv2.Transfer && request.Effect.Kind != bankv2.Allocate) {
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
	var state, rh string
	var signature *string
	if e = tx.QueryRow(ctx, `SELECT status,bank_request_hash,permit_signature FROM native_operations WHERE environment_id=$1 AND user_id=$2 AND id=$3`, p.EnvironmentID.String(), p.UserID.String(), c.OperationID.String()).Scan(&state, &rh, &signature); e != nil {
		return e
	}
	if state == "SETTLED" {
		return nil
	}
	want, e := request.Digest()
	if e != nil || want != rh || signature == nil || state != "RECONCILING" {
		return reject("OPERATION_UNKNOWN", e)
	}
	if e = standingBridgeStoredPermit(ctx, tx, p, c.OperationID, request, *signature); e != nil {
		return e
	}
	g, hash, number, e := loadStandingBridge(ctx, tx, p, c.OperationID)
	if e != nil {
		return e
	}
	ledger, e := s.Store.LoadNativeLedger(ctx, tx, p.EnvironmentID, p.UserID, s.now())
	if e != nil {
		return e
	}
	ledger.Income, e = ledger.Income.Commit(c.OperationID, s.now())
	if e != nil {
		return e
	}
	if request.Effect.Kind == bankv2.Transfer {
		source := g.Steps[number-1].Resources.CashAccountID
		dest := g.Steps[number-1].Resources.DestinationAccountID
		if dest == nil {
			return reject("EVIDENCE_INVALID", nil)
		}
		sf, df := false, false
		for i := range ledger.Accounts {
			a := &ledger.Accounts[i]
			if a.ID == source {
				a.Balance, e = a.Balance.Sub(request.Effect.Amount)
				sf = true
			} else if a.ID == *dest {
				a.Balance, e = a.Balance.Add(request.Effect.Amount)
				df = true
			}
			if e != nil {
				return e
			}
			if a.ID == source || a.ID == *dest {
				a.ObservedAt = s.now()
			}
		}
		if !sf || !df {
			return reject("EVIDENCE_INVALID", nil)
		}
	} else if e = bridgeAssign(&ledger, request); e != nil {
		return e
	}
	for i := range ledger.Holds {
		if ledger.Holds[i].OperationID == c.OperationID {
			ledger.Holds[i].State = funds.Committed
		}
	}
	journal, e := newID()
	if e != nil {
		return e
	}
	rid, e := newID()
	if e != nil {
		return e
	}
	now := s.now()
	_, e = tx.Exec(ctx, `INSERT INTO native_journals(environment_id,user_id,id,operation_id,kind,status,created_at) VALUES($1,$2,$3,$4,$5,'DRAFT',$6)`, p.EnvironmentID.String(), p.UserID.String(), journal.String(), c.OperationID.String(), "STANDING_BRIDGE_"+string(request.Effect.Kind), now)
	if e != nil {
		return e
	}
	for i, leg := range result.Postings {
		_, e = tx.Exec(ctx, `INSERT INTO native_postings(environment_id,user_id,journal_id,leg_ref,bank_posting_id,dimension,ledger_id,direction,amount_cents,occurred_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`, p.EnvironmentID.String(), p.UserID.String(), journal.String(), fmt.Sprintf("bank:%d:%s", i+1, leg.ID), leg.ID, leg.Dimension, leg.LedgerID, leg.Direction, leg.Amount.Cents(), leg.OccurredAt)
		if e != nil {
			return e
		}
	}
	if _, e = tx.Exec(ctx, `UPDATE native_journals SET status='POSTED',posted_at=$4 WHERE environment_id=$1 AND user_id=$2 AND id=$3`, p.EnvironmentID.String(), p.UserID.String(), journal.String(), now); e != nil {
		return e
	}
	receipt := NativeReceipt{Protocol: "native-receipt-v1", ID: rid, OperationID: c.OperationID, GroupID: g.Occurrence.ID, JournalID: journal, BankResult: result, RecordedAt: now}
	raw, _ := encode(receipt)
	_, e = tx.Exec(ctx, `INSERT INTO native_receipts(environment_id,user_id,id,operation_id,journal_id,original,original_hash,created_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8)`, p.EnvironmentID.String(), p.UserID.String(), rid.String(), c.OperationID.String(), journal.String(), raw, Hash(raw), now)
	if e != nil {
		return e
	}
	if _, e = tx.Exec(ctx, `UPDATE native_operations SET status='SETTLED',receipt_id=$4,processing_health='HEALTHY',version=version+1,updated_at=$5 WHERE environment_id=$1 AND user_id=$2 AND id=$3`, p.EnvironmentID.String(), p.UserID.String(), c.OperationID.String(), rid.String(), now); e != nil {
		return e
	}
	if request.Effect.Kind == bankv2.Allocate {
		zone, e := policy.TemplateLocation(g.Grant.Terms.Timezone)
		if e != nil {
			return e
		}
		tag, e := tx.Exec(ctx, `UPDATE goals SET month_contributed_cents=CASE WHEN month_period=$4 THEN month_contributed_cents+$5 ELSE $5 END,month_period=$4,version=version+1 WHERE environment_id=$1 AND user_id=$2 AND id=$3`, p.EnvironmentID.String(), p.UserID.String(), request.Effect.DestinationGoalID, result.SettledAt.In(zone).Format("2006-01"), request.Effect.Amount.Cents())
		if e = assertOne(tag, e); e != nil {
			return e
		}
	}
	if e = s.Store.PersistNativeLedger(ctx, tx, p.EnvironmentID, p.UserID, ledger); e != nil {
		return e
	}
	closed := number == len(g.Steps)
	if !closed {
		// The receipt and its actual destination funds are present, but this
		// transaction's single FV/SV boundary is not published yet.
		permissionErr := s.validateStandingBridge(ctx, tx, p, g, number+1, now, false)
		if permissionErr != nil {
			if Code(permissionErr) == "INTERNAL_ERROR" || Code(permissionErr) == "EVIDENCE_INVALID" {
				return permissionErr
			}
			if e = s.cancelStandingBridgeSuffix(ctx, tx, p, g, &ledger, Code(permissionErr)); e != nil {
				return e
			}
			closed = true
		} else {
			next := g.Steps[number]
			if !next.InitialSource {
				if request.Effect.Kind != bankv2.Transfer || next.ChildNumber != g.Steps[number-1].ChildNumber || next.Resources.CashAccountID.String() != request.Effect.DestinationAccountID {
					return reject("EVIDENCE_INVALID", nil)
				}
				if e = s.insertStandingBridgeOperation(ctx, tx, p, g, hash, next, now); e != nil {
					return e
				}
				ledger, e = bridgeReserve(ledger, next, now)
				if e != nil {
					return e
				}
			}
			if e = bridgeCreateJob(ctx, tx, p, next.OperationID); e != nil {
				return e
			}
		}
		// Post-arrival allocation claims are inserted only with the new operation
		// in this transaction, after Income.Commit exposed its original location.
		if e = s.Store.PersistNativeLedger(ctx, tx, p.EnvironmentID, p.UserID, ledger); e != nil {
			return e
		}
	}
	// Seal the completed effect together with any newly materialized T1
	// reservation (or cancelled unsigned suffix), before publishing its source.
	if _, e = tx.Exec(ctx, `UPDATE users SET funds_version=funds_version+1 WHERE environment_id=$1 AND id=$2`, p.EnvironmentID.String(), p.UserID.String()); e != nil {
		return e
	}
	if _, _, e = s.refreshTemplateProtectionAfterNativeEffect(ctx, tx, p, g.Grant.Terms.Timezone); e != nil {
		return e
	}
	if e = s.finalizeStandingBridgeBudget(ctx, tx, p, g, closed); e != nil {
		return e
	}
	if _, e = tx.Exec(ctx, `INSERT INTO evidence_blobs(environment_id,user_id,id,kind,canonical,digest,created_at) VALUES($1,$2,$3,'NATIVE_STANDING_BRIDGE_SETTLEMENT',$4,$5,$6)`, p.EnvironmentID.String(), p.UserID.String(), "native-standing-bridge-settlement:"+c.OperationID.String(), raw, Hash(raw), now); e != nil {
		return e
	}
	event, e := newID()
	if e != nil {
		return e
	}
	if _, e = tx.Exec(ctx, `INSERT INTO outbox(environment_id,user_id,id,aggregate_id,aggregate_version,kind,payload,created_at) SELECT $1,$2,$3,id,version,'NATIVE_OPERATION_SETTLED',$5,$6 FROM native_operations WHERE environment_id=$1 AND user_id=$2 AND id=$4`, p.EnvironmentID.String(), p.UserID.String(), event.String(), c.OperationID.String(), raw, now); e != nil {
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
