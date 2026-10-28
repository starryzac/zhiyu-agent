package app

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"zhiyu.local/zhiyu-go/internal/adapters/postgres"
	"zhiyu.local/zhiyu-go/internal/execution/bankv2"
	funds "zhiyu.local/zhiyu-go/internal/funds/domain"
	policy "zhiyu.local/zhiyu-go/internal/policy/domain"
)

type NativeReceipt struct {
	Protocol    string        `json:"protocol"`
	ID          funds.ID      `json:"id"`
	OperationID funds.ID      `json:"operation_id"`
	GroupID     funds.ID      `json:"group_id"`
	JournalID   funds.ID      `json:"journal_id"`
	BankResult  bankv2.Result `json:"bank_result"`
	RecordedAt  time.Time     `json:"recorded_at"`
}

// A bank original is committed separately before T3. Local rollback retains
// RECONCILING, so recovery observes the original key and never repeats economics.
func (s *Service) nativeObservation(ctx context.Context, c Claim, request bankv2.Request, result bankv2.Result) error {
	if bankv2.VerifyResult(request, result) != nil {
		return s.nativeFailure(ctx, c, reject("EVIDENCE_INVALID", nil))
	}
	if result.Status == bankv2.NotFound {
		return s.nativeFailure(ctx, c, reject("OPERATION_UNKNOWN", nil))
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
	var state, hash, commandKind string
	var signature *string
	if err = tx.QueryRow(ctx, `SELECT status,bank_request_hash,permit_signature,command_kind FROM native_operations WHERE environment_id=$1 AND user_id=$2 AND id=$3`, p.EnvironmentID.String(), p.UserID.String(), c.OperationID.String()).Scan(&state, &hash, &signature, &commandKind); err != nil {
		return err
	}
	want, err := request.Digest()
	if err != nil {
		return err
	}
	if want != hash || signature == nil {
		return reject("EVIDENCE_INVALID", nil)
	}
	if err = nativeStoredPermit(ctx, tx, p, c.OperationID, request, *signature); err != nil {
		return err
	}
	if state == "SETTLED" || state == "REJECTED" || state == "CANCELLED" {
		return nil
	}
	observation, err := newID()
	if err != nil {
		return err
	}
	raw, err := encode(result)
	if err != nil {
		return err
	}
	_, err = tx.Exec(ctx, `INSERT INTO native_bank_observations(environment_id,user_id,id,operation_id,status,original,original_hash,observed_at) SELECT $1,$2,$3,$4,$5,$6::bytea,$7::hash256,$8 WHERE NOT EXISTS(SELECT 1 FROM native_bank_observations WHERE environment_id=$1 AND user_id=$2 AND operation_id=$4 AND original_hash=$7::hash256 AND original=$6::bytea)`, p.EnvironmentID.String(), p.UserID.String(), observation.String(), c.OperationID.String(), string(result.Status), raw, Hash(raw), s.now())
	if err != nil {
		return err
	}
	switch result.Status {
	case bankv2.Accepted:
		_, err = tx.Exec(ctx, `UPDATE native_operations SET status='PENDING_SETTLEMENT',bank_observed_status='ACCEPTED',processing_health='HEALTHY',version=version+1,updated_at=$4 WHERE environment_id=$1 AND user_id=$2 AND id=$3`, p.EnvironmentID.String(), p.UserID.String(), c.OperationID.String(), s.now())
		if err != nil {
			return err
		}
		delay := max(250*time.Millisecond, min(time.Hour, result.AvailableAt.Sub(s.now())))
		_, err = tx.Exec(ctx, `UPDATE native_jobs SET state='READY',lease_owner=NULL,lease_until=NULL,last_error='',next_attempt_at=clock_timestamp()+$4::bigint*interval '1 millisecond' WHERE environment_id=$1 AND user_id=$2 AND id=$3`, p.EnvironmentID.String(), p.UserID.String(), c.JobID.String(), delay.Milliseconds())
		if err != nil {
			return err
		}
		return tx.Commit(ctx)
	case bankv2.Rejected:
		if nativeStandingBridgeKind(commandKind) {
			return s.standingBridgeReject(ctx, tx, c, request, result)
		}
		if commandKind == string(bankv2.MoveGoal) {
			return s.goalTransferReject(ctx, tx, c, request, result)
		}
		if commandKind == string(bankv2.Payment) {
			return s.paymentReject(ctx, tx, c, request, result)
		}
		if commandKind == nativeStandingAllocateKind {
			return s.standingNativeReject(ctx, tx, c, request, result)
		}
		if nativeAssetKind(bankv2.Kind(commandKind)) {
			return s.assetReject(ctx, tx, c, request, result)
		}
		ledger, e := s.Store.LoadNativeLedger(ctx, tx, p.EnvironmentID, p.UserID, s.now())
		if e != nil {
			return e
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
		if commandKind == "BRIDGE_TRANSFER" || commandKind == "BRIDGE_ALLOCATE" {
			if err = s.bridgeCancelSuffix(ctx, tx, c, &ledger, result.RejectionCode); err != nil {
				return err
			}
		}
		_, err = tx.Exec(ctx, `UPDATE native_operations SET status='REJECTED',bank_observed_status='REJECTED',processing_health=$4,version=version+1,updated_at=$5 WHERE environment_id=$1 AND user_id=$2 AND id=$3`, p.EnvironmentID.String(), p.UserID.String(), c.OperationID.String(), result.RejectionCode, s.now())
		if err != nil {
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
		if err = s.refreshNativeOperationProtection(ctx, tx, p, c.OperationID); err != nil {
			return err
		}
		if err = finishNativeJob(ctx, tx, c); err != nil {
			return err
		}
		return tx.Commit(ctx)
	case bankv2.Settled:
		_, err = tx.Exec(ctx, `UPDATE native_operations SET status='RECONCILING',bank_observed_status='SETTLED',processing_health='HEALTHY',version=version+1,updated_at=$4 WHERE environment_id=$1 AND user_id=$2 AND id=$3`, p.EnvironmentID.String(), p.UserID.String(), c.OperationID.String(), s.now())
		if err != nil {
			return err
		}
		if err = tx.Commit(ctx); err != nil {
			return err
		}
		if s.Failpoint != nil {
			if err = s.Failpoint("native_after_observation_commit"); err != nil {
				return err
			}
		}
		switch commandKind {
		case nativeStandingBridgeTransfer, nativeStandingBridgeAllocate:
			return s.standingBridgeBook(ctx, c, request, result)
		case "BRIDGE_TRANSFER":
			return s.bridgeBookTransfer(ctx, c, request, result)
		case "BRIDGE_ALLOCATE":
			return s.bridgeBookAllocate(ctx, c, request, result)
		case "JOINT_ALLOCATE":
			return s.bookNativeAllocation(ctx, c, request, result)
		case string(bankv2.MoveGoal):
			return s.goalTransferBook(ctx, c, request, result)
		case string(bankv2.Payment):
			return s.paymentBook(ctx, c, request, result)
		case nativeStandingAllocateKind:
			return s.standingNativeBookAllocation(ctx, c, request, result)
		case string(bankv2.Purchase), string(bankv2.Redeem), string(bankv2.Mature):
			return s.bookNativeAsset(ctx, c, request, result)
		default:
			return reject("UNSUPPORTED_OPERATION", nil)
		}
	}
	return reject("EVIDENCE_INVALID", nil)
}

func finishNativeJob(ctx context.Context, tx pgx.Tx, c Claim) error {
	_, err := tx.Exec(ctx, `UPDATE native_jobs SET state='FINISHED',lease_owner=NULL,lease_until=NULL,last_error='' WHERE environment_id=$1 AND user_id=$2 AND id=$3`, c.Principal.EnvironmentID.String(), c.Principal.UserID.String(), c.JobID.String())
	return err
}

func (s *Service) bookNativeAllocation(ctx context.Context, c Claim, request bankv2.Request, result bankv2.Result) error {
	if result.Status != bankv2.Settled || bankv2.VerifyResult(request, result) != nil || request.Effect.Kind != bankv2.Allocate {
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
	var state, group string
	if err = tx.QueryRow(ctx, `SELECT status,group_id::text FROM native_operations WHERE environment_id=$1 AND user_id=$2 AND id=$3`, p.EnvironmentID.String(), p.UserID.String(), c.OperationID.String()).Scan(&state, &group); err != nil {
		return err
	}
	if state == "SETTLED" {
		return nil
	}
	if state != "RECONCILING" {
		return reject("OPERATION_UNKNOWN", nil)
	}
	groupID, err := funds.ParseID(group)
	if err != nil {
		return err
	}
	plan, err := loadNativeJointPlan(ctx, tx, p, groupID)
	if err != nil {
		return err
	}
	zone, err := policy.TemplateLocation(plan.Input.ProtectionForecast.Timezone)
	if err != nil {
		return reject("EVIDENCE_INVALID", err)
	}
	ledger, err := s.Store.LoadNativeLedger(ctx, tx, p.EnvironmentID, p.UserID, s.now())
	if err != nil {
		return err
	}
	ledger.Income, err = ledger.Income.Commit(c.OperationID, s.now())
	if err != nil {
		return err
	}
	goalID, err := funds.ParseID(request.Effect.DestinationGoalID)
	if err != nil {
		return err
	}
	accountID, err := funds.ParseID(request.Effect.CashUses[0].AccountID)
	if err != nil {
		return err
	}
	goalFound, accountFound := false, false
	for i := range ledger.Accounts {
		if ledger.Accounts[i].ID == accountID {
			ledger.Accounts[i].GoalOwned, err = ledger.Accounts[i].GoalOwned.Add(request.Effect.Amount)
			if err != nil {
				return err
			}
			accountFound = true
		}
	}
	for i := range ledger.Goals {
		if ledger.Goals[i].GoalID == goalID {
			if ledger.Goals[i].AccountID != accountID {
				return reject("EVIDENCE_INVALID", nil)
			}
			ledger.Goals[i].Cash, err = ledger.Goals[i].Cash.Add(request.Effect.Amount)
			if err != nil {
				return err
			}
			goalFound = true
		}
	}
	if !goalFound || !accountFound {
		return reject("EVIDENCE_INVALID", nil)
	}
	for _, use := range request.Effect.OriginUses {
		found := false
		for i := range ledger.GoalLots {
			lot := &ledger.GoalLots[i]
			if lot.GoalID == goalID && lot.AccountID == accountID && lot.SourceKind == "INCOME" && lot.SourceID == use.OriginID {
				lot.Available, err = lot.Available.Add(use.Amount)
				if err != nil {
					return err
				}
				found = true
			}
		}
		if !found {
			ledger.GoalLots = append(ledger.GoalLots, postgres.NativeGoalLot{GoalID: goalID, AccountID: accountID, SourceKind: "INCOME", SourceID: use.OriginID, Available: use.Amount})
		}
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
	_, err = tx.Exec(ctx, `INSERT INTO native_journals(environment_id,user_id,id,operation_id,kind,status,created_at) VALUES($1,$2,$3,$4,'ALLOCATION','DRAFT',$5)`, p.EnvironmentID.String(), p.UserID.String(), journal.String(), c.OperationID.String(), now)
	if err != nil {
		return err
	}
	for i, leg := range result.Postings {
		_, err = tx.Exec(ctx, `INSERT INTO native_postings(environment_id,user_id,journal_id,leg_ref,bank_posting_id,dimension,ledger_id,direction,amount_cents,occurred_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`, p.EnvironmentID.String(), p.UserID.String(), journal.String(), fmt.Sprintf("bank:%d:%s", i+1, leg.ID), leg.ID, leg.Dimension, leg.LedgerID, leg.Direction, leg.Amount.Cents(), leg.OccurredAt)
		if err != nil {
			return err
		}
	}
	_, err = tx.Exec(ctx, `UPDATE native_journals SET status='POSTED',posted_at=$4 WHERE environment_id=$1 AND user_id=$2 AND id=$3`, p.EnvironmentID.String(), p.UserID.String(), journal.String(), now)
	if err != nil {
		return err
	}
	receipt := NativeReceipt{"native-receipt-v1", receiptID, c.OperationID, groupID, journal, result, now}
	receiptRaw, err := encode(receipt)
	if err != nil {
		return err
	}
	_, err = tx.Exec(ctx, `INSERT INTO native_receipts(environment_id,user_id,id,operation_id,journal_id,original,original_hash,created_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8)`, p.EnvironmentID.String(), p.UserID.String(), receiptID.String(), c.OperationID.String(), journal.String(), receiptRaw, Hash(receiptRaw), now)
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
	period := result.SettledAt.In(zone).Format("2006-01")
	tag, err := tx.Exec(ctx, `UPDATE goals SET month_contributed_cents=CASE WHEN month_period=$4 THEN month_contributed_cents+$5 ELSE $5 END,month_period=$4,version=version+1 WHERE environment_id=$1 AND user_id=$2 AND id=$3`, p.EnvironmentID.String(), p.UserID.String(), goalID.String(), period, request.Effect.Amount.Cents())
	if err = assertOne(tag, err); err != nil {
		return err
	}
	if _, err = tx.Exec(ctx, `UPDATE users SET funds_version=funds_version+1 WHERE environment_id=$1 AND id=$2`, p.EnvironmentID.String(), p.UserID.String()); err != nil {
		return err
	}
	if _, _, err = s.refreshTemplateProtectionAfterNativeEffect(ctx, tx, p, plan.Input.ProtectionForecast.Timezone); err != nil {
		return err
	}
	event, err := newID()
	if err != nil {
		return err
	}
	_, err = tx.Exec(ctx, `INSERT INTO outbox(environment_id,user_id,id,aggregate_id,aggregate_version,kind,payload,created_at) SELECT $1,$2,$3,id,version,'NATIVE_OPERATION_SETTLED',$5,$6 FROM native_operations WHERE environment_id=$1 AND user_id=$2 AND id=$4`, p.EnvironmentID.String(), p.UserID.String(), event.String(), c.OperationID.String(), receiptRaw, now)
	if err != nil {
		return err
	}
	_, err = tx.Exec(ctx, `INSERT INTO evidence_blobs(environment_id,user_id,id,kind,canonical,digest,created_at) VALUES($1,$2,$3,'NATIVE_EXECUTION_SETTLEMENT',$4,$5,$6)`, p.EnvironmentID.String(), p.UserID.String(), "native-settlement:"+c.OperationID.String(), receiptRaw, Hash(receiptRaw), now)
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
