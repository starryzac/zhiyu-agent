package app

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"zhiyu.local/zhiyu-go/internal/execution/bankv2"
	execution "zhiyu.local/zhiyu-go/internal/execution/domain"
)

type nativeIncomeLocalOperation struct {
	ID, State, Namespace, Key, RequestHash string
	Request                                []byte
	ReceiptID                              *string
}

func loadIncomeLocalOperations(ctx context.Context, tx pgx.Tx, p Principal, native bool) ([]nativeIncomeLocalOperation, error) {
	table := "operations"
	if native {
		table = "native_operations"
	}
	rows, err := tx.Query(ctx, `SELECT id::text,status,bank_namespace,bank_key,bank_request_hash,bank_request,receipt_id::text FROM `+table+` WHERE environment_id=$1 AND user_id=$2 ORDER BY id LIMIT $3`, p.EnvironmentID.String(), p.UserID.String(), nativeIncomeMaxOperations+1)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []nativeIncomeLocalOperation{}
	for rows.Next() {
		var o nativeIncomeLocalOperation
		if err = rows.Scan(&o.ID, &o.State, &o.Namespace, &o.Key, &o.RequestHash, &o.Request, &o.ReceiptID); err != nil {
			return nil, err
		}
		out = append(out, o)
	}
	if len(out) > nativeIncomeMaxOperations {
		return nil, reject("INCOME_CAPTURE_CAPACITY_OR_BOUNDS", nil)
	}
	return out, rows.Err()
}

func (s *Service) verifyIncomeOperations(ctx context.Context, tx pgx.Tx, p Principal, capture nativeIncomeCapture) error {
	verifyIncomeOperationsAttempts.Add(1)
	legacy := map[string]execution.BankResult{}
	for _, r := range capture.Legacy {
		if _, exists := legacy[r.Key]; exists {
			return reject("INCOME_BANK_SNAPSHOT_INVALID", nil)
		}
		legacy[r.Key] = r
	}
	native := map[string]bankv2.Result{}
	for _, r := range capture.Native {
		if _, exists := native[r.Key]; exists {
			return reject("INCOME_BANK_SNAPSHOT_INVALID", nil)
		}
		native[r.Key] = r
	}
	oldRows, err := loadIncomeLocalOperations(ctx, tx, p, false)
	if err != nil {
		return err
	}
	for _, o := range oldRows {
		var request execution.BankRequest
		if decode(o.Request, &request) != nil || request.Validate() != nil || request.Namespace != s.Namespace || o.Namespace != s.Namespace || request.UserID != p.UserID.String() || request.OperationID != o.ID || request.Key != o.Key {
			return reject("INCOME_LOCAL_OPERATION_INVALID", nil)
		}
		h, err := request.Digest()
		if err != nil || h != o.RequestHash {
			return reject("INCOME_LOCAL_OPERATION_INVALID", err)
		}
		r, found := legacy[o.Key]
		if o.State == "CANCELLED" {
			if found || o.ReceiptID != nil {
				return reject("INCOME_BANK_OPERATION_UNRECONCILED", nil)
			}
			continue
		}
		if !found || r.RequestHash != h || r.Request.OperationID != o.ID || execution.VerifyBankResult(request, r) != nil {
			return reject("INCOME_BANK_OPERATION_UNRECONCILED", nil)
		}
		if o.State == "REJECTED" {
			if r.Status != execution.BankRejected || o.ReceiptID != nil {
				return reject("INCOME_BANK_OPERATION_UNRECONCILED", nil)
			}
		} else if o.State != "SETTLED" || r.Status != execution.BankSettled || o.ReceiptID == nil {
			return reject("INCOME_OPERATION_PENDING", nil)
		} else if err = verifyIncomeLegacyReceipt(ctx, tx, p, s.Namespace, o, request, r, s.now()); err != nil {
			return err
		}
		delete(legacy, o.Key)
	}
	nativeRows, err := loadIncomeLocalOperations(ctx, tx, p, true)
	if err != nil {
		return err
	}
	receipts := nativeIncomeReceiptReader{ctx: ctx, tx: tx, p: p, namespace: s.Namespace, operations: nativeRows, bank: native}
	for i, o := range nativeRows {
		request, h, err := nativeIncomeRequest(s.Namespace, p, o)
		if err != nil {
			return err
		}
		r, found := native[o.Key]
		if o.State == "CANCELLED" {
			if found || o.ReceiptID != nil {
				return reject("INCOME_BANK_OPERATION_UNRECONCILED", nil)
			}
			continue
		}
		if !found || r.Request == nil || r.RequestHash != h || r.Request.OperationID != o.ID || bankv2.VerifyResult(request, r) != nil {
			return reject("INCOME_BANK_OPERATION_UNRECONCILED", nil)
		}
		if o.State == "REJECTED" {
			if r.Status != bankv2.Rejected || o.ReceiptID != nil {
				return reject("INCOME_BANK_OPERATION_UNRECONCILED", nil)
			}
		} else if o.State != "SETTLED" || r.Status != bankv2.Settled || o.ReceiptID == nil {
			return reject("INCOME_OPERATION_PENDING", nil)
		} else if err = receipts.verify(i, o, request, r, s.now()); err != nil {
			return err
		}
		delete(native, o.Key)
	}
	if len(legacy) != 0 || len(native) != 0 {
		return reject("INCOME_BANK_OPERATION_UNRECONCILED", nil)
	}
	return nil
}

func verifyIncomeLegacyReceipt(ctx context.Context, tx pgx.Tx, p Principal, namespace string, o nativeIncomeLocalOperation, request execution.BankRequest, result execution.BankResult, now time.Time) error {
	var raw []byte
	if err := tx.QueryRow(ctx, `SELECT original FROM receipts WHERE environment_id=$1 AND user_id=$2 AND id=$3 AND operation_id=$4`, p.EnvironmentID.String(), p.UserID.String(), *o.ReceiptID, o.ID).Scan(&raw); err != nil {
		return reject("INCOME_RECEIPT_INVALID", err)
	}
	var receipt Receipt
	if decode(raw, &receipt) != nil || receipt.ID.String() != *o.ReceiptID || receipt.OperationID.String() != o.ID || receipt.Environment != namespace || receipt.UserID != p.UserID || receipt.BankKey != o.Key || receipt.BankRequestHash != o.RequestHash || receipt.Amount != request.Amount || result.SettledAt == nil || !receipt.SettledAt.Equal(*result.SettledAt) || receipt.RecordedAt.Before(receipt.SettledAt) || receipt.RecordedAt.After(now) || len(receipt.PostingIDs) != len(result.Postings) || request.Kind != "ALLOCATE_GOAL" {
		return reject("INCOME_RECEIPT_INVALID", nil)
	}
	var posted bool
	if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM journals WHERE environment_id=$1 AND user_id=$2 AND id=$3 AND operation_id=$4 AND status='POSTED')`, p.EnvironmentID.String(), p.UserID.String(), receipt.JournalID.String(), o.ID).Scan(&posted); err != nil || !posted {
		return reject("INCOME_RECEIPT_INVALID", err)
	}
	expected := map[string]execution.BankPosting{}
	for i, leg := range result.Postings {
		if receipt.PostingIDs[i] != leg.ID {
			return reject("INCOME_RECEIPT_INVALID", nil)
		}
		expected[fmt.Sprintf("bank:%d:%s", i+1, leg.ID)] = leg
	}
	rows, err := tx.Query(ctx, `SELECT leg_ref,dimension,account_id::text,direction,amount_cents,currency FROM postings WHERE environment_id=$1 AND user_id=$2 AND journal_id=$3`, p.EnvironmentID.String(), p.UserID.String(), receipt.JournalID.String())
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var ref, dimension, account, direction, currency string
		var amount int64
		if err = rows.Scan(&ref, &dimension, &account, &direction, &amount, &currency); err != nil {
			return err
		}
		leg, exists := expected[ref]
		wantDimension := "GOAL_OWNERSHIP"
		if leg.Dimension == "INCOME_LOCATION" {
			wantDimension = "INCOME_QUALIFICATION"
		}
		if !exists || dimension != wantDimension || account != request.SourceAccountID || direction != leg.Direction || amount != leg.Amount.Cents() || currency != "CNY" {
			return reject("INCOME_RECEIPT_INVALID", nil)
		}
		delete(expected, ref)
	}
	if rows.Err() != nil || len(expected) != 0 {
		return reject("INCOME_RECEIPT_INVALID", rows.Err())
	}
	return nil
}

func verifyIncomeNativeReceipt(ctx context.Context, tx pgx.Tx, p Principal, o nativeIncomeLocalOperation, request bankv2.Request, result bankv2.Result, now time.Time) error {
	var raw []byte
	var hash string
	if err := tx.QueryRow(ctx, `SELECT original,original_hash FROM native_receipts WHERE environment_id=$1 AND user_id=$2 AND id=$3 AND operation_id=$4`, p.EnvironmentID.String(), p.UserID.String(), *o.ReceiptID, o.ID).Scan(&raw, &hash); err != nil {
		return reject("INCOME_RECEIPT_INVALID", err)
	}
	var receipt NativeReceipt
	if Hash(raw) != hash || decode(raw, &receipt) != nil || receipt.Protocol != "native-receipt-v1" || receipt.ID.String() != *o.ReceiptID || receipt.OperationID.String() != o.ID || receipt.BankResult.RequestHash != o.RequestHash || receipt.BankResult.Status != bankv2.Settled || receipt.BankResult.Sequence != result.Sequence || receipt.BankResult.Version != result.Version || bankv2.VerifyResult(request, receipt.BankResult) != nil || result.SettledAt == nil || receipt.BankResult.SettledAt == nil || !result.SettledAt.Equal(*receipt.BankResult.SettledAt) || receipt.RecordedAt.Before(*result.SettledAt) || receipt.RecordedAt.After(now) || len(receipt.BankResult.Postings) != len(result.Postings) {
		return reject("INCOME_RECEIPT_INVALID", nil)
	}
	var posted bool
	if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM native_journals WHERE environment_id=$1 AND user_id=$2 AND id=$3 AND operation_id=$4 AND status='POSTED')`, p.EnvironmentID.String(), p.UserID.String(), receipt.JournalID.String(), o.ID).Scan(&posted); err != nil || !posted {
		return reject("INCOME_RECEIPT_INVALID", err)
	}
	expected := map[string]bankv2.Posting{}
	for i, leg := range result.Postings {
		r := receipt.BankResult.Postings[i]
		if r.ID != leg.ID || r.Dimension != leg.Dimension || r.LedgerID != leg.LedgerID || r.Direction != leg.Direction || r.Amount != leg.Amount || !r.OccurredAt.Equal(leg.OccurredAt) {
			return reject("INCOME_RECEIPT_INVALID", nil)
		}
		expected[fmt.Sprintf("bank:%d:%s", i+1, leg.ID)] = leg
	}
	rows, err := tx.Query(ctx, `SELECT leg_ref,bank_posting_id,dimension,ledger_id,direction,amount_cents,occurred_at,currency FROM native_postings WHERE environment_id=$1 AND user_id=$2 AND journal_id=$3`, p.EnvironmentID.String(), p.UserID.String(), receipt.JournalID.String())
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var ref, id, dimension, ledger, direction, currency string
		var amount int64
		var occurred time.Time
		if err = rows.Scan(&ref, &id, &dimension, &ledger, &direction, &amount, &occurred, &currency); err != nil {
			return err
		}
		leg, exists := expected[ref]
		if !exists || id != leg.ID || dimension != leg.Dimension || ledger != leg.LedgerID || direction != leg.Direction || amount != leg.Amount.Cents() || !occurred.Equal(leg.OccurredAt) || currency != "CNY" {
			return reject("INCOME_RECEIPT_INVALID", nil)
		}
		delete(expected, ref)
	}
	if rows.Err() != nil || len(expected) != 0 {
		return reject("INCOME_RECEIPT_INVALID", rows.Err())
	}
	return nil
}
