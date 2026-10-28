package app

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	evidence "zhiyu.local/zhiyu-go/internal/audit"
	executionaudit "zhiyu.local/zhiyu-go/internal/execution/audit"
	execution "zhiyu.local/zhiyu-go/internal/execution/domain"
	funds "zhiyu.local/zhiyu-go/internal/funds/domain"
)

type Receipt struct {
	ID              funds.ID    `json:"id"`
	OperationID     funds.ID    `json:"operation_id"`
	Environment     string      `json:"environment"`
	UserID          funds.ID    `json:"user_id"`
	BankKey         string      `json:"bank_key"`
	BankRequestHash string      `json:"bank_request_hash"`
	Amount          funds.Money `json:"amount_cents"`
	JournalID       funds.ID    `json:"journal_id"`
	PostingIDs      []string    `json:"bank_posting_ids"`
	SettledAt       time.Time   `json:"settled_at"`
	RecordedAt      time.Time   `json:"recorded_at"`
}

func (s *Service) lockClaimOperation(ctx context.Context, tx pgx.Tx, c Claim) error {
	env, err := s.environment(ctx, tx, true)
	if err != nil {
		return err
	}
	if err = sameUser(c.Principal, env.ID); err != nil {
		return err
	}
	if _, _, err = lockUser(ctx, tx, c.Principal); err != nil {
		return err
	}
	if err = lockOperation(ctx, tx, c); err != nil {
		return err
	}
	return currentClaim(ctx, tx, c)
}

// The independently committed bank fact is persisted before local booking. If
// booking fails, RECONCILING and the original observation survive for recovery.
func (s *Service) projectObservation(ctx context.Context, c Claim, request execution.BankRequest, result execution.BankResult) error {
	if err := execution.VerifyBankResult(request, result); err != nil {
		return s.recordFailure(ctx, c, reject("EVIDENCE_INVALID", err))
	}
	if result.Status == execution.BankNotFound {
		return s.recordFailure(ctx, c, reject("OPERATION_UNKNOWN", nil))
	}
	tx, err := s.begin(ctx)
	if err != nil {
		return err
	}
	defer rollback(ctx, tx)
	if err = s.lockClaimOperation(ctx, tx, c); err != nil {
		return err
	}
	p := c.Principal
	var status, requestHash string
	var signature *string
	if err = tx.QueryRow(ctx, "SELECT status,bank_request_hash,permit_signature FROM operations WHERE environment_id=$1 AND user_id=$2 AND id=$3", p.EnvironmentID.String(), p.UserID.String(), c.OperationID.String()).Scan(&status, &requestHash, &signature); err != nil {
		return err
	}
	wantHash, err := request.Digest()
	if err != nil {
		return err
	}
	if requestHash != wantHash || signature == nil {
		return reject("EVIDENCE_INVALID", nil)
	}
	if err = s.verifyLegacyStoredPermit(ctx, tx, p, c.OperationID, request, *signature); err != nil {
		return err
	}
	if status == "SETTLED" || status == "REJECTED" || status == "CANCELLED" {
		return nil
	}
	observationID, err := newID()
	if err != nil {
		return err
	}
	raw, err := encode(result)
	if err != nil {
		return err
	}
	_, err = tx.Exec(ctx, `INSERT INTO bank_observations(environment_id,user_id,id,operation_id,status,original,observed_at) SELECT $1,$2,$3,$4,$5,$6,$7 WHERE NOT EXISTS(SELECT 1 FROM bank_observations WHERE environment_id=$1 AND user_id=$2 AND operation_id=$4 AND original=$6)`, p.EnvironmentID.String(), p.UserID.String(), observationID.String(), c.OperationID.String(), string(result.Status), raw, s.now())
	if err != nil {
		return err
	}
	switch result.Status {
	case execution.BankAccepted:
		_, err = tx.Exec(ctx, `UPDATE operations SET status='PENDING_SETTLEMENT',bank_observed_status='ACCEPTED',processing_health='HEALTHY',updated_at=$4,version=version+1 WHERE environment_id=$1 AND user_id=$2 AND id=$3`, p.EnvironmentID.String(), p.UserID.String(), c.OperationID.String(), s.now())
		if err != nil {
			return err
		}
		delay := max(250*time.Millisecond, min(time.Hour, result.AvailableAt.Sub(s.now())))
		_, err = tx.Exec(ctx, `UPDATE jobs SET state='READY',lease_owner=NULL,lease_until=NULL,last_error='',next_attempt_at=clock_timestamp()+$4::bigint*interval '1 millisecond' WHERE environment_id=$1 AND user_id=$2 AND id=$3`, p.EnvironmentID.String(), p.UserID.String(), c.JobID.String(), delay.Milliseconds())
		if err != nil {
			return err
		}
		return tx.Commit(ctx)
	case execution.BankRejected:
		ledger, err := s.Store.LoadLedger(ctx, tx, p.EnvironmentID, p.UserID, s.now())
		if err != nil {
			return err
		}
		ledger, err = ledger.Release(c.OperationID, s.now(), true)
		if err != nil {
			return err
		}
		if err = s.Store.SaveLedger(ctx, tx, p.EnvironmentID, p.UserID, ledger); err != nil {
			return err
		}
		_, err = tx.Exec(ctx, `UPDATE operations SET status='REJECTED',bank_observed_status='REJECTED',processing_health='HEALTHY',updated_at=$4,version=version+1 WHERE environment_id=$1 AND user_id=$2 AND id=$3`, p.EnvironmentID.String(), p.UserID.String(), c.OperationID.String(), s.now())
		if err != nil {
			return err
		}
		cause, err := s.legacyBankRejectionCause(ctx, tx, p, c.OperationID, result)
		if err != nil {
			return err
		}
		if err = s.recordFundsTerminalDecision(ctx, tx, p, "LEGACY", c.OperationID, "REJECTED", cause); err != nil {
			return err
		}
		_, err = tx.Exec(ctx, "UPDATE users SET funds_version=funds_version+1 WHERE environment_id=$1 AND id=$2", p.EnvironmentID.String(), p.UserID.String())
		if err != nil {
			return err
		}
		if err = finishJob(ctx, tx, c); err != nil {
			return err
		}
		return tx.Commit(ctx)
	case execution.BankSettled:
		_, err = tx.Exec(ctx, `UPDATE operations SET status='RECONCILING',bank_observed_status='SETTLED',processing_health='HEALTHY',updated_at=$4,version=version+1 WHERE environment_id=$1 AND user_id=$2 AND id=$3`, p.EnvironmentID.String(), p.UserID.String(), c.OperationID.String(), s.now())
		if err != nil {
			return err
		}
	default:
		return reject("EVIDENCE_INVALID", nil)
	}
	if err = tx.Commit(ctx); err != nil {
		return err
	}
	if s.Failpoint != nil {
		if err = s.Failpoint("after_observation_commit"); err != nil {
			return err
		}
	}
	return s.bookSettlement(ctx, c, request, result)
}

func finishJob(ctx context.Context, tx pgx.Tx, c Claim) error {
	_, err := tx.Exec(ctx, "UPDATE jobs SET state='DONE',lease_owner=NULL,lease_until=NULL,last_error='' WHERE environment_id=$1 AND user_id=$2 AND id=$3", c.Principal.EnvironmentID.String(), c.Principal.UserID.String(), c.JobID.String())
	return err
}

func (s *Service) bookSettlement(ctx context.Context, c Claim, request execution.BankRequest, result execution.BankResult) error {
	tx, err := s.begin(ctx)
	if err != nil {
		return err
	}
	defer rollback(ctx, tx)
	if err = s.lockClaimOperation(ctx, tx, c); err != nil {
		return err
	}
	p := c.Principal
	var state string
	if err = tx.QueryRow(ctx, "SELECT status FROM operations WHERE environment_id=$1 AND user_id=$2 AND id=$3", p.EnvironmentID.String(), p.UserID.String(), c.OperationID.String()).Scan(&state); err != nil {
		return err
	}
	if state == "SETTLED" {
		return nil
	}
	if state != "RECONCILING" {
		return reject("OPERATION_UNKNOWN", nil)
	}
	if result.Status != execution.BankSettled || execution.VerifyBankResult(request, result) != nil {
		return reject("EVIDENCE_INVALID", nil)
	}
	ledger, err := s.Store.LoadLedger(ctx, tx, p.EnvironmentID, p.UserID, s.now())
	if err != nil {
		return err
	}
	ledger, err = ledger.Commit(c.OperationID, s.now())
	if err != nil {
		return err
	}
	if err = s.Store.SaveLedger(ctx, tx, p.EnvironmentID, p.UserID, ledger); err != nil {
		return err
	}
	if request.Kind != "ALLOCATE_GOAL" {
		return reject("UNSUPPORTED_OPERATION", nil)
	}
	tag, err := tx.Exec(ctx, `UPDATE accounts SET goal_owned_cents=goal_owned_cents+$4 WHERE environment_id=$1 AND user_id=$2 AND id=$3`, p.EnvironmentID.String(), p.UserID.String(), request.SourceAccountID, request.Amount.Cents())
	if err = assertOne(tag, err); err != nil {
		return err
	}
	tag, err = tx.Exec(ctx, `UPDATE goals SET assigned_cents=assigned_cents+$4,month_contributed_cents=CASE WHEN month_period=$5 THEN month_contributed_cents+$4 ELSE $4 END,month_period=$5,version=version+1 WHERE environment_id=$1 AND user_id=$2 AND id=$3`, p.EnvironmentID.String(), p.UserID.String(), request.GoalID, request.Amount.Cents(), result.SettledAt.In(time.FixedZone("Asia/Shanghai", 8*3600)).Format("2006-01"))
	if err = assertOne(tag, err); err != nil {
		return err
	}
	journalID, err := newID()
	if err != nil {
		return err
	}
	receiptID, err := newID()
	if err != nil {
		return err
	}
	now := s.now()
	_, err = tx.Exec(ctx, `INSERT INTO journals(environment_id,user_id,id,operation_id,kind,status,created_at) VALUES($1,$2,$3,$4,'ALLOCATION','DRAFT',$5)`, p.EnvironmentID.String(), p.UserID.String(), journalID.String(), c.OperationID.String(), now)
	if err != nil {
		return err
	}
	for i, leg := range result.Postings {
		dimension := "GOAL_OWNERSHIP"
		if leg.Dimension == "INCOME_LOCATION" {
			dimension = "INCOME_QUALIFICATION"
		}
		_, err = tx.Exec(ctx, `INSERT INTO postings(environment_id,user_id,journal_id,leg_ref,dimension,currency,account_id,direction,amount_cents) VALUES($1,$2,$3,$4,$5,'CNY',$6,$7,$8)`, p.EnvironmentID.String(), p.UserID.String(), journalID.String(), fmt.Sprintf("bank:%d:%s", i+1, leg.ID), dimension, request.SourceAccountID, leg.Direction, leg.Amount.Cents())
		if err != nil {
			return err
		}
	}
	_, err = tx.Exec(ctx, "UPDATE journals SET status='POSTED',posted_at=$4 WHERE environment_id=$1 AND user_id=$2 AND id=$3", p.EnvironmentID.String(), p.UserID.String(), journalID.String(), now)
	if err != nil {
		return err
	}
	postingIDs := make([]string, len(result.Postings))
	for i, leg := range result.Postings {
		postingIDs[i] = leg.ID
	}
	requestHash, err := request.Digest()
	if err != nil {
		return err
	}
	receipt := Receipt{receiptID, c.OperationID, s.Namespace, p.UserID, request.Key, requestHash, request.Amount, journalID, postingIDs, *result.SettledAt, now}
	receiptRaw, err := encode(receipt)
	if err != nil {
		return err
	}
	_, err = tx.Exec(ctx, `INSERT INTO receipts(environment_id,user_id,id,operation_id,bank_operation_id,original,created_at) VALUES($1,$2,$3,$4,$4,$5,$6)`, p.EnvironmentID.String(), p.UserID.String(), receiptID.String(), c.OperationID.String(), receiptRaw, now)
	if err != nil {
		return err
	}
	original, err := executionaudit.SealSettlement(executionaudit.SettlementEvidence{ID: "settlement:" + c.OperationID.String(), Environment: s.Namespace, UserID: p.UserID.String(), OperationID: c.OperationID.String(), ReceiptID: receiptID.String(), Request: request, Result: result})
	if err != nil {
		return err
	}
	registry := evidence.NewRegistry()
	if err = executionaudit.Register(registry); err != nil {
		return err
	}
	verified := evidence.VerifyBundle([]string{"settlement:" + c.OperationID.String()}, map[string]evidence.Original{"settlement:" + c.OperationID.String(): original}, registry)
	if verified.Status != evidence.Valid {
		return reject("EVIDENCE_INVALID", nil)
	}
	_, err = tx.Exec(ctx, `INSERT INTO evidence_blobs(environment_id,user_id,id,kind,canonical,digest,created_at) VALUES($1,$2,$3,'EXECUTION_SETTLEMENT',$4,$5,$6)`, p.EnvironmentID.String(), p.UserID.String(), "settlement:"+c.OperationID.String(), original.Canonical, original.Digest, now)
	if err != nil {
		return err
	}
	_, err = tx.Exec(ctx, `UPDATE operations SET status='SETTLED',receipt_id=$4,processing_health='HEALTHY',version=version+1,updated_at=$5 WHERE environment_id=$1 AND user_id=$2 AND id=$3`, p.EnvironmentID.String(), p.UserID.String(), c.OperationID.String(), receiptID.String(), now)
	if err != nil {
		return err
	}
	// SETTLED synchronously projects legacy ownership into the native goal
	// balances and source lots. Seal the same funds-version boundary only
	// after that projection and the original receipt are both present.
	_, err = tx.Exec(ctx, "UPDATE users SET funds_version=funds_version+1 WHERE environment_id=$1 AND id=$2", p.EnvironmentID.String(), p.UserID.String())
	if err != nil {
		return err
	}
	eventID, err := newID()
	if err != nil {
		return err
	}
	_, err = tx.Exec(ctx, `INSERT INTO outbox(environment_id,user_id,id,aggregate_id,aggregate_version,kind,payload,created_at) SELECT $1,$2,$3,id,version,'OPERATION_SETTLED',$5,$6 FROM operations WHERE environment_id=$1 AND user_id=$2 AND id=$4`, p.EnvironmentID.String(), p.UserID.String(), eventID.String(), c.OperationID.String(), receiptRaw, now)
	if err != nil {
		return err
	}
	if err = finishJob(ctx, tx, c); err != nil {
		return err
	}
	if s.Failpoint != nil {
		if err = s.Failpoint("before_local_commit"); err != nil {
			return err
		}
	}
	return tx.Commit(ctx)
}
