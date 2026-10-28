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

type nativeObligationPayment struct {
	Protocol      string      `json:"protocol"`
	ID            funds.ID    `json:"id"`
	ObligationID  string      `json:"obligation_id"`
	OperationID   funds.ID    `json:"operation_id"`
	ReceiptID     funds.ID    `json:"receipt_id"`
	Amount        funds.Money `json:"amount_cents"`
	LiabilityHash string      `json:"liability_hash"`
	RecordedAt    time.Time   `json:"recorded_at"`
}

func checkNativePaymentHolds(n postgres.NativeLedger, op funds.ID, preview NativePaymentPreview) error {
	cash := map[string]funds.Money{}
	for _, use := range preview.Resources.CashUses {
		cash[use.AccountID] = use.Amount
	}
	seen := map[string]bool{}
	liability := false
	for _, h := range n.Holds {
		if h.OperationID != op {
			continue
		}
		if h.State != funds.Reserved || h.ResourceDetail != "" {
			return reject("EVIDENCE_INVALID", nil)
		}
		switch h.ResourceKind {
		case "CASH":
			if seen[h.ResourceID] || cash[h.ResourceID] != h.Amount {
				return reject("EVIDENCE_INVALID", nil)
			}
			seen[h.ResourceID] = true
		case "LIABILITY":
			if liability || h.ResourceID != preview.Debt.ID || h.Amount != preview.Resources.Amount {
				return reject("EVIDENCE_INVALID", nil)
			}
			liability = true
		default:
			return reject("EVIDENCE_INVALID", nil)
		}
	}
	if !liability || len(seen) != len(cash) {
		return reject("EVIDENCE_INVALID", nil)
	}
	found := false
	for _, r := range n.Income.Snapshot().Reservations {
		if r.ActionID != op {
			continue
		}
		if found || r.State != funds.Reserved || r.Operation != funds.Spend {
			return reject("EVIDENCE_INVALID", nil)
		}
		found = true
		a, _ := encode(r.Uses)
		b, _ := encode(preview.Resources.IncomeUses)
		if !templateSameBytes(a, b) {
			return reject("EVIDENCE_INVALID", nil)
		}
	}
	if found != (len(preview.Resources.IncomeUses) > 0) {
		return reject("EVIDENCE_INVALID", nil)
	}
	returns := map[string]funds.Money{}
	for _, r := range preview.Resources.ReturnUses {
		returns[r.OperationKey+":"+r.AccountID] = r.Amount
	}
	count := 0
	for _, r := range n.ReturnClaims {
		if r.OperationID != op {
			continue
		}
		if r.State != funds.Reserved || returns[r.BankKey+":"+r.AccountID.String()] != r.Amount {
			return reject("EVIDENCE_INVALID", nil)
		}
		count++
	}
	if count != len(returns) {
		return reject("EVIDENCE_INVALID", nil)
	}
	return nil
}

func (s *Service) paymentReject(ctx context.Context, tx pgx.Tx, c Claim, request bankv2.Request, result bankv2.Result) error {
	if request.Effect.Kind != bankv2.Payment || result.Status != bankv2.Rejected || bankv2.VerifyResult(request, result) != nil {
		return reject("EVIDENCE_INVALID", nil)
	}
	p := c.Principal
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
	if e = finalizeStandingPaymentBudget(ctx, tx, p, c.OperationID, funds.Money{}, s.now()); e != nil {
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
	if e = s.paymentProtection(ctx, tx, p, c.OperationID); e != nil {
		return e
	}
	if e = finishNativeJob(ctx, tx, c); e != nil {
		return e
	}
	return tx.Commit(ctx)
}

func (s *Service) paymentBook(ctx context.Context, c Claim, request bankv2.Request, result bankv2.Result) error {
	if request.Effect.Kind != bankv2.Payment || result.Status != bankv2.Settled || bankv2.VerifyResult(request, result) != nil {
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
	var state, previewText, rh string
	var signature *string
	e = tx.QueryRow(ctx, `SELECT status,preview_id::text,bank_request_hash::text,permit_signature FROM native_operations WHERE environment_id=$1 AND user_id=$2 AND id=$3 AND command_kind='PAY_RECURRING'`, p.EnvironmentID.String(), p.UserID.String(), c.OperationID.String()).Scan(&state, &previewText, &rh, &signature)
	if e != nil {
		return e
	}
	if state == "SETTLED" {
		return nil
	}
	if state != "RECONCILING" || signature == nil {
		return reject("OPERATION_UNKNOWN", nil)
	}
	want, e := request.Digest()
	if e != nil || want != rh {
		return reject("EVIDENCE_INVALID", e)
	}
	if e = paymentStoredPermit(ctx, tx, p, c.OperationID, request, *signature); e != nil {
		return e
	}
	previewID, e := funds.ParseID(previewText)
	if e != nil {
		return e
	}
	preview, e := loadNativePaymentExecutionPreview(ctx, tx, p, c.OperationID, previewID)
	if e != nil {
		return e
	}
	ledger, e := s.Store.LoadNativeLedger(ctx, tx, p.EnvironmentID, p.UserID, s.now())
	if e != nil {
		return e
	}
	if e = checkNativePaymentHolds(ledger, c.OperationID, preview); e != nil {
		return e
	}
	// LIABILITY is a debt concurrency pin, not a cash resource consumed by the
	// shared asset/payment cash helper. Keep it as its original committed row.
	var liability postgres.NativeHold
	filtered := make([]postgres.NativeHold, 0, len(ledger.Holds))
	for _, h := range ledger.Holds {
		if h.OperationID == c.OperationID && h.ResourceKind == "LIABILITY" {
			liability = h
			continue
		}
		filtered = append(filtered, h)
	}
	ledger.Holds = filtered
	if e = commitNativeUnownedCash(&ledger, c.OperationID, bankv2.Payment); e != nil {
		return e
	}
	liability.State = funds.Committed
	ledger.Holds = append(ledger.Holds, liability)
	for _, use := range request.Effect.CashUses {
		found := false
		for i := range ledger.Accounts {
			a := &ledger.Accounts[i]
			if a.ID.String() != use.AccountID {
				continue
			}
			if found {
				return reject("EVIDENCE_INVALID", nil)
			}
			found = true
			a.Balance, e = a.Balance.Sub(use.Amount)
			if e != nil {
				return e
			}
			a.ObservedAt = *result.SettledAt
		}
		if !found {
			return reject("EVIDENCE_INVALID", nil)
		}
	}
	journal, e := newID()
	if e != nil {
		return e
	}
	receiptID, e := newID()
	if e != nil {
		return e
	}
	now := s.now()
	if _, e = tx.Exec(ctx, `INSERT INTO native_journals(environment_id,user_id,id,operation_id,kind,status,created_at) VALUES($1,$2,$3,$4,'PAY_RECURRING','DRAFT',$5)`, p.EnvironmentID.String(), p.UserID.String(), journal.String(), c.OperationID.String(), now); e != nil {
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
	receiptRaw, e := encode(receipt)
	if e != nil {
		return e
	}
	if _, e = tx.Exec(ctx, `INSERT INTO native_receipts(environment_id,user_id,id,operation_id,journal_id,original,original_hash,created_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8)`, p.EnvironmentID.String(), p.UserID.String(), receiptID.String(), c.OperationID.String(), journal.String(), receiptRaw, Hash(receiptRaw), now); e != nil {
		return e
	}
	if _, e = tx.Exec(ctx, `UPDATE native_operations SET status='SETTLED',receipt_id=$4,processing_health='HEALTHY',version=version+1,updated_at=$5 WHERE environment_id=$1 AND user_id=$2 AND id=$3`, p.EnvironmentID.String(), p.UserID.String(), c.OperationID.String(), receiptID.String(), now); e != nil {
		return e
	}
	if e = s.Store.PersistNativeLedger(ctx, tx, p.EnvironmentID, p.UserID, ledger); e != nil {
		return e
	}
	payment := nativeObligationPayment{Protocol: "native-obligation-payment-v1", ID: receiptID, ObligationID: preview.Debt.ID, OperationID: c.OperationID, ReceiptID: receiptID, Amount: request.Effect.Amount, LiabilityHash: preview.Liability.OriginalHash, RecordedAt: now}
	raw, e := encode(payment)
	if e != nil {
		return e
	}
	if _, e = tx.Exec(ctx, `INSERT INTO native_obligation_payments(environment_id,user_id,id,obligation_id,operation_id,receipt_id,amount_cents,original,original_hash,recorded_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`, p.EnvironmentID.String(), p.UserID.String(), payment.ID.String(), payment.ObligationID, c.OperationID.String(), receiptID.String(), payment.Amount.Cents(), raw, Hash(raw), now); e != nil {
		return e
	}
	if e = finalizeStandingPaymentBudget(ctx, tx, p, c.OperationID, payment.Amount, now); e != nil {
		return e
	}
	if _, e = tx.Exec(ctx, `UPDATE users SET funds_version=funds_version+1 WHERE environment_id=$1 AND id=$2`, p.EnvironmentID.String(), p.UserID.String()); e != nil {
		return e
	}
	if e = s.paymentProtection(ctx, tx, p, c.OperationID); e != nil {
		return e
	}
	event, e := newID()
	if e != nil {
		return e
	}
	if _, e = tx.Exec(ctx, `INSERT INTO outbox(environment_id,user_id,id,aggregate_id,aggregate_version,kind,payload,created_at) SELECT $1,$2,$3,id,version,'NATIVE_OPERATION_SETTLED',$5,$6 FROM native_operations WHERE environment_id=$1 AND user_id=$2 AND id=$4`, p.EnvironmentID.String(), p.UserID.String(), event.String(), c.OperationID.String(), receiptRaw, now); e != nil {
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
