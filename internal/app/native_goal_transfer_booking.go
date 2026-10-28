package app

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5"
	"zhiyu.local/zhiyu-go/internal/execution/bankv2"
	funds "zhiyu.local/zhiyu-go/internal/funds/domain"
)

// Called by nativeObservation inside its already locked observation transaction.
// Rejection is bank-proven no effect. NOT_FOUND/timeout/UNKNOWN never calls it.
func (s *Service) goalTransferReject(ctx context.Context, tx pgx.Tx, c Claim, request bankv2.Request, result bankv2.Result) error {
	if request.Effect.Kind != bankv2.MoveGoal || result.Status != bankv2.Rejected || bankv2.VerifyResult(request, result) != nil {
		return reject("EVIDENCE_INVALID", nil)
	}
	p := c.Principal
	var previewText, state, stored string
	var signature *string
	if err := tx.QueryRow(ctx, `SELECT status,preview_id::text,bank_request_hash::text,permit_signature FROM native_operations WHERE environment_id=$1 AND user_id=$2 AND id=$3 AND command_kind='TRANSFER_GOAL'`, p.EnvironmentID.String(), p.UserID.String(), c.OperationID.String()).Scan(&state, &previewText, &stored, &signature); err != nil {
		return err
	}
	if state == "SETTLED" || state == "REJECTED" || state == "CANCELLED" {
		return tx.Commit(ctx)
	}
	want, err := request.Digest()
	if err != nil || stored != want || signature == nil {
		return reject("EVIDENCE_INVALID", err)
	}
	if err = goalTransferStoredPermit(ctx, tx, p, c.OperationID, request, *signature); err != nil {
		return err
	}
	id, err := funds.ParseID(previewText)
	if err != nil {
		return err
	}
	preview, err := loadGoalTransferPreview(ctx, tx, p, id)
	if err != nil {
		return err
	}
	ledger, err := s.Store.LoadNativeLedger(ctx, tx, p.EnvironmentID, p.UserID, s.now())
	if err != nil {
		return err
	}
	ledger, err = releaseGoalTransferResources(ledger, c.OperationID, request.Effect, preview.LotUses, true)
	if err != nil {
		return err
	}
	if _, err = tx.Exec(ctx, `UPDATE native_operations SET status='REJECTED',bank_observed_status='REJECTED',processing_health=$4,version=version+1,updated_at=$5 WHERE environment_id=$1 AND user_id=$2 AND id=$3`, p.EnvironmentID.String(), p.UserID.String(), c.OperationID.String(), result.RejectionCode, s.now()); err != nil {
		return err
	}
	if err = s.Store.PersistNativeLedger(ctx, tx, p.EnvironmentID, p.UserID, ledger); err != nil {
		return err
	}
	if err = s.recordNativeRejection(ctx, tx, p, c.OperationID, result); err != nil {
		return err
	}
	if _, err = tx.Exec(ctx, `UPDATE users SET funds_version=funds_version+1 WHERE environment_id=$1 AND id=$2`, p.EnvironmentID.String(), p.UserID.String()); err != nil {
		return err
	}
	if err = s.goalTransferProtection(ctx, tx, p, c.OperationID); err != nil {
		return err
	}
	if err = finishNativeJob(ctx, tx, c); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func (s *Service) goalTransferBook(ctx context.Context, c Claim, request bankv2.Request, result bankv2.Result) error {
	if result.Status != bankv2.Settled || bankv2.VerifyResult(request, result) != nil || request.Effect.Kind != bankv2.MoveGoal {
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
	var state, previewText, stored string
	var signature *string
	if err = tx.QueryRow(ctx, `SELECT status,preview_id::text,bank_request_hash::text,permit_signature FROM native_operations WHERE environment_id=$1 AND user_id=$2 AND id=$3 AND command_kind='TRANSFER_GOAL'`, p.EnvironmentID.String(), p.UserID.String(), c.OperationID.String()).Scan(&state, &previewText, &stored, &signature); err != nil {
		return err
	}
	if state == "SETTLED" {
		return nil
	}
	if state != "RECONCILING" || signature == nil {
		return reject("OPERATION_UNKNOWN", nil)
	}
	want, err := request.Digest()
	if err != nil || want != stored {
		return reject("EVIDENCE_INVALID", err)
	}
	if err = goalTransferStoredPermit(ctx, tx, p, c.OperationID, request, *signature); err != nil {
		return err
	}
	previewID, err := funds.ParseID(previewText)
	if err != nil {
		return err
	}
	preview, err := loadGoalTransferPreview(ctx, tx, p, previewID)
	if err != nil {
		return err
	}
	ledger, err := s.Store.LoadNativeLedger(ctx, tx, p.EnvironmentID, p.UserID, s.now())
	if err != nil {
		return err
	}
	ledger, err = finishGoalTransferResources(ledger, c.OperationID, request.Effect, preview.LotUses, true, s.now())
	if err != nil {
		return err
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
	if _, err = tx.Exec(ctx, `INSERT INTO native_journals(environment_id,user_id,id,operation_id,kind,status,created_at) VALUES($1,$2,$3,$4,'TRANSFER_GOAL','DRAFT',$5)`, p.EnvironmentID.String(), p.UserID.String(), journal.String(), c.OperationID.String(), now); err != nil {
		return err
	}
	for i, leg := range result.Postings {
		if _, err = tx.Exec(ctx, `INSERT INTO native_postings(environment_id,user_id,journal_id,leg_ref,bank_posting_id,dimension,ledger_id,direction,amount_cents,occurred_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`, p.EnvironmentID.String(), p.UserID.String(), journal.String(), fmt.Sprintf("bank:%d:%s", i+1, leg.ID), leg.ID, leg.Dimension, leg.LedgerID, leg.Direction, leg.Amount.Cents(), leg.OccurredAt); err != nil {
			return err
		}
	}
	if _, err = tx.Exec(ctx, `UPDATE native_journals SET status='POSTED',posted_at=$4 WHERE environment_id=$1 AND user_id=$2 AND id=$3`, p.EnvironmentID.String(), p.UserID.String(), journal.String(), now); err != nil {
		return err
	}
	receipt := NativeReceipt{"native-receipt-v1", receiptID, c.OperationID, preview.ID, journal, result, now}
	receiptRaw, err := encode(receipt)
	if err != nil {
		return err
	}
	if _, err = tx.Exec(ctx, `INSERT INTO native_receipts(environment_id,user_id,id,operation_id,journal_id,original,original_hash,created_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8)`, p.EnvironmentID.String(), p.UserID.String(), receiptID.String(), c.OperationID.String(), journal.String(), receiptRaw, Hash(receiptRaw), now); err != nil {
		return err
	}
	if _, err = tx.Exec(ctx, `UPDATE native_operations SET status='SETTLED',receipt_id=$4,processing_health='HEALTHY',version=version+1,updated_at=$5 WHERE environment_id=$1 AND user_id=$2 AND id=$3`, p.EnvironmentID.String(), p.UserID.String(), c.OperationID.String(), receiptID.String(), now); err != nil {
		return err
	}
	if err = s.Store.PersistNativeLedger(ctx, tx, p.EnvironmentID, p.UserID, ledger); err != nil {
		return err
	}
	// Ownership evidence advances both goal versions; existing money is not a
	// new monthly contribution and never refreshes an income qualification.
	for _, goal := range []funds.ID{preview.PairedEffect.SourceGoalID, preview.PairedEffect.TargetGoalID} {
		tag, e := tx.Exec(ctx, `UPDATE goals SET version=version+1 WHERE environment_id=$1 AND user_id=$2 AND id=$3`, p.EnvironmentID.String(), p.UserID.String(), goal.String())
		if e = assertOne(tag, e); e != nil {
			return e
		}
	}
	if _, err = tx.Exec(ctx, `UPDATE users SET funds_version=funds_version+1 WHERE environment_id=$1 AND id=$2`, p.EnvironmentID.String(), p.UserID.String()); err != nil {
		return err
	}
	if err = s.goalTransferProtection(ctx, tx, p, c.OperationID); err != nil {
		return err
	}
	event, err := newID()
	if err != nil {
		return err
	}
	if _, err = tx.Exec(ctx, `INSERT INTO outbox(environment_id,user_id,id,aggregate_id,aggregate_version,kind,payload,created_at) SELECT $1,$2,$3,id,version,'NATIVE_OPERATION_SETTLED',$5,$6 FROM native_operations WHERE environment_id=$1 AND user_id=$2 AND id=$4`, p.EnvironmentID.String(), p.UserID.String(), event.String(), c.OperationID.String(), receiptRaw, now); err != nil {
		return err
	}
	if _, err = tx.Exec(ctx, `INSERT INTO evidence_blobs(environment_id,user_id,id,kind,canonical,digest,created_at) VALUES($1,$2,$3,'NATIVE_GOAL_TRANSFER_SETTLEMENT',$4,$5,$6)`, p.EnvironmentID.String(), p.UserID.String(), "native-goal-transfer:"+c.OperationID.String(), receiptRaw, Hash(receiptRaw), now); err != nil {
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
