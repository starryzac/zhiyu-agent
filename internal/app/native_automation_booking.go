package app

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5"
	"zhiyu.local/zhiyu-go/internal/execution/bankv2"
	funds "zhiyu.local/zhiyu-go/internal/funds/domain"
	policy "zhiyu.local/zhiyu-go/internal/policy/domain"
)

func (s *Service) standingNativeReject(ctx context.Context, tx pgx.Tx, c Claim, request bankv2.Request, result bankv2.Result) error {
	if request.Effect.Kind != bankv2.Allocate || result.Status != bankv2.Rejected || bankv2.VerifyResult(request, result) != nil {
		return reject("EVIDENCE_INVALID", nil)
	}
	p := c.Principal
	plan, _, err := loadStandingAllocationPlan(ctx, tx, p, c.OperationID)
	if err != nil {
		return err
	}
	if plan.Joint != nil {
		if err = s.cancelStandingJointSuffix(ctx, tx, c, plan, result.RejectionCode, true); err != nil {
			return err
		}
		return tx.Commit(ctx)
	}
	ledger, err := s.Store.LoadNativeLedger(ctx, tx, p.EnvironmentID, p.UserID, s.now())
	if err != nil {
		return err
	}
	ledger.Income, err = ledger.Income.Release(c.OperationID, s.now(), true)
	if err != nil {
		return err
	}
	for i := range ledger.Holds {
		if ledger.Holds[i].OperationID == c.OperationID {
			ledger.Holds[i].State = funds.Released
		}
	}
	_, err = tx.Exec(ctx, `UPDATE native_operations SET status='REJECTED',bank_observed_status='REJECTED',processing_health=$4,version=version+1,updated_at=$5 WHERE environment_id=$1 AND user_id=$2 AND id=$3`, p.EnvironmentID.String(), p.UserID.String(), c.OperationID.String(), result.RejectionCode, s.now())
	if err != nil {
		return err
	}
	if err = s.Store.PersistNativeLedger(ctx, tx, p.EnvironmentID, p.UserID, ledger); err != nil {
		return err
	}
	if err = finalizeNativeStandingBudget(ctx, tx, p, plan.Occurrence.ID, funds.Money{}, s.now()); err != nil {
		return err
	}
	if err = s.recordNativeRejection(ctx, tx, p, c.OperationID, result); err != nil {
		return err
	}
	if _, err = tx.Exec(ctx, `UPDATE users SET funds_version=funds_version+1 WHERE environment_id=$1 AND id=$2`, p.EnvironmentID.String(), p.UserID.String()); err != nil {
		return err
	}
	if _, _, err = s.refreshTemplateProtectionAfterNativeEffect(ctx, tx, p, plan.Grant.Terms.Timezone); err != nil {
		return err
	}
	if err = finishNativeJob(ctx, tx, c); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func (s *Service) standingNativeBookAllocation(ctx context.Context, c Claim, request bankv2.Request, result bankv2.Result) error {
	if request.Effect.Kind != bankv2.Allocate || result.Status != bankv2.Settled || bankv2.VerifyResult(request, result) != nil {
		return reject("EVIDENCE_INVALID", nil)
	}
	tx, err := s.begin(ctx)
	if err != nil {
		return err
	}
	defer rollback(ctx, tx)
	if err = s.lockNativeClaim(ctx, tx, c); err != nil {
		return err
	}
	p := c.Principal
	var state, rh, kind string
	var signature *string
	err = tx.QueryRow(ctx, `SELECT status,bank_request_hash,command_kind,permit_signature FROM native_operations WHERE environment_id=$1 AND user_id=$2 AND id=$3`, p.EnvironmentID.String(), p.UserID.String(), c.OperationID.String()).Scan(&state, &rh, &kind, &signature)
	if err != nil {
		return err
	}
	if state == "SETTLED" {
		return nil
	}
	if state != "RECONCILING" || kind != nativeStandingAllocateKind || signature == nil {
		return reject("OPERATION_UNKNOWN", nil)
	}
	want, err := request.Digest()
	if err != nil || want != rh {
		return reject("EVIDENCE_INVALID", err)
	}
	if err = standingNativeStoredPermit(ctx, tx, p, c.OperationID, request, *signature); err != nil {
		return err
	}
	plan, _, err := loadStandingAllocationPlan(ctx, tx, p, c.OperationID)
	if err != nil {
		return err
	}
	ledger, err := s.Store.LoadNativeLedger(ctx, tx, p.EnvironmentID, p.UserID, s.now())
	if err != nil {
		return err
	}
	ledger.Income, err = ledger.Income.Commit(c.OperationID, s.now())
	if err != nil {
		return err
	}
	if err = bridgeAssign(&ledger, request); err != nil {
		return err
	}
	for i := range ledger.Holds {
		if ledger.Holds[i].OperationID == c.OperationID {
			ledger.Holds[i].State = funds.Committed
		}
	}
	journal, err := newID()
	if err != nil {
		return err
	}
	receiptID, err := newID()
	if err != nil {
		return err
	}
	now := s.now()
	_, err = tx.Exec(ctx, `INSERT INTO native_journals(environment_id,user_id,id,operation_id,kind,status,created_at) VALUES($1,$2,$3,$4,'STANDING_ALLOCATION','DRAFT',$5)`, p.EnvironmentID.String(), p.UserID.String(), journal.String(), c.OperationID.String(), now)
	if err != nil {
		return err
	}
	for i, leg := range result.Postings {
		_, err = tx.Exec(ctx, `INSERT INTO native_postings(environment_id,user_id,journal_id,leg_ref,bank_posting_id,dimension,ledger_id,direction,amount_cents,occurred_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`, p.EnvironmentID.String(), p.UserID.String(), journal.String(), fmt.Sprintf("bank:%d:%s", i+1, leg.ID), leg.ID, leg.Dimension, leg.LedgerID, leg.Direction, leg.Amount.Cents(), leg.OccurredAt)
		if err != nil {
			return err
		}
	}
	if _, err = tx.Exec(ctx, `UPDATE native_journals SET status='POSTED',posted_at=$4 WHERE environment_id=$1 AND user_id=$2 AND id=$3`, p.EnvironmentID.String(), p.UserID.String(), journal.String(), now); err != nil {
		return err
	}
	receipt := NativeReceipt{Protocol: "native-receipt-v1", ID: receiptID, OperationID: c.OperationID, GroupID: plan.Occurrence.ID, JournalID: journal, BankResult: result, RecordedAt: now}
	raw, err := encode(receipt)
	if err != nil {
		return err
	}
	_, err = tx.Exec(ctx, `INSERT INTO native_receipts(environment_id,user_id,id,operation_id,journal_id,original,original_hash,created_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8)`, p.EnvironmentID.String(), p.UserID.String(), receiptID.String(), c.OperationID.String(), journal.String(), raw, Hash(raw), now)
	if err != nil {
		return err
	}
	_, err = tx.Exec(ctx, `UPDATE native_operations SET status='SETTLED',receipt_id=$4,processing_health='HEALTHY',version=version+1,updated_at=$5 WHERE environment_id=$1 AND user_id=$2 AND id=$3`, p.EnvironmentID.String(), p.UserID.String(), c.OperationID.String(), receiptID.String(), now)
	if err != nil {
		return err
	}
	if err = s.Store.PersistNativeLedger(ctx, tx, p.EnvironmentID, p.UserID, ledger); err != nil {
		return err
	}
	zone, err := policy.TemplateLocation(plan.Grant.Terms.Timezone)
	if err != nil {
		return err
	}
	tag, err := tx.Exec(ctx, `UPDATE goals SET month_contributed_cents=CASE WHEN month_period=$4 THEN month_contributed_cents+$5 ELSE $5 END,month_period=$4,version=version+1 WHERE environment_id=$1 AND user_id=$2 AND id=$3`, p.EnvironmentID.String(), p.UserID.String(), request.Effect.DestinationGoalID, result.SettledAt.In(zone).Format("2006-01"), request.Effect.Amount.Cents())
	if err = assertOne(tag, err); err != nil {
		return err
	}
	if _, err = tx.Exec(ctx, `UPDATE users SET funds_version=funds_version+1 WHERE environment_id=$1 AND id=$2`, p.EnvironmentID.String(), p.UserID.String()); err != nil {
		return err
	}
	_, deferred, err := s.refreshTemplateProtectionAfterNativeEffect(ctx, tx, p, plan.Grant.Terms.Timezone)
	if err != nil {
		return err
	}
	// An external bill awaiting incorporation can defer publication of this
	// real effect. It cannot lend an unrelated future source-version increment
	// to an unsigned joint suffix. Preserve this receipt, cancel that suffix.
	if deferred && plan.Joint != nil && plan.JointChild < len(plan.Joint.Slots) {
		next := plan.Joint.Slots[plan.JointChild].OperationID
		nextPlan, _, e := loadStandingAllocationPlan(ctx, tx, p, next)
		if e != nil {
			return e
		}
		if e = s.cancelStandingJointSuffix(ctx, tx, Claim{Principal: p, OperationID: next}, nextPlan, "BILL_INTAKE_PENDING", false); e != nil {
			return e
		}
	}
	if err = finalizeStandingAllocationBudgetIfDone(ctx, tx, p, plan, now); err != nil {
		return err
	}
	event, err := newID()
	if err != nil {
		return err
	}
	_, err = tx.Exec(ctx, `INSERT INTO outbox(environment_id,user_id,id,aggregate_id,aggregate_version,kind,payload,created_at) SELECT $1,$2,$3,id,version,'NATIVE_OPERATION_SETTLED',$5,$6 FROM native_operations WHERE environment_id=$1 AND user_id=$2 AND id=$4`, p.EnvironmentID.String(), p.UserID.String(), event.String(), c.OperationID.String(), raw, now)
	if err != nil {
		return err
	}
	_, err = tx.Exec(ctx, `INSERT INTO evidence_blobs(environment_id,user_id,id,kind,canonical,digest,created_at) VALUES($1,$2,$3,'NATIVE_STANDING_SETTLEMENT',$4,$5,$6)`, p.EnvironmentID.String(), p.UserID.String(), "native-standing-settlement:"+c.OperationID.String(), raw, Hash(raw), now)
	if err != nil {
		return err
	}
	if err = finishNativeJob(ctx, tx, c); err != nil {
		return err
	}
	if s.Failpoint != nil {
		if err = s.Failpoint("native_before_local_commit"); err != nil {
			return err
		}
	}
	return tx.Commit(ctx)
}
