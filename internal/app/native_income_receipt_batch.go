package app

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"zhiyu.local/zhiyu-go/internal/execution/bankv2"
)

// This is an I/O chunk, not a business/capture/history limit. Every original
// remains verified in the existing operation order and caller transaction.
const nativeIncomeReadChunk = 16

type nativeIncomeReceiptRaw struct {
	original []byte
	hash     string
	bytes    int64
}

type nativeIncomeJournalRow struct{ operation, state string }

type nativeIncomePostingRow struct {
	ref, id, dimension, ledger, direction, currency string
	amount                                          int64
	occurred                                        time.Time
	invalidSize                                     bool
}

type nativeIncomePostingBound struct{ count, ref, id, dimension, ledger, direction, currency int }

type nativeIncomeReceiptChunk struct {
	end                                               int
	receipts                                          map[string]nativeIncomeReceiptRaw
	journals                                          map[string]nativeIncomeJournalRow
	postings                                          map[string][]nativeIncomePostingRow
	receiptErr, journalErr, postingErr, postingEndErr error
}

type nativeIncomeReceiptReader struct {
	ctx        context.Context
	tx         pgx.Tx
	p          Principal
	namespace  string
	operations []nativeIncomeLocalOperation
	bank       map[string]bankv2.Result
	chunk      *nativeIncomeReceiptChunk
}

func nativeIncomeReceiptKey(operation, receipt string) string { return operation + "/" + receipt }

func nativeIncomeRequest(namespace string, p Principal, o nativeIncomeLocalOperation) (bankv2.Request, string, error) {
	var request bankv2.Request
	if decode(o.Request, &request) != nil || request.Validate() != nil || request.Namespace != namespace || o.Namespace != namespace || request.UserID != p.UserID.String() || request.OperationID != o.ID || request.Key != o.Key {
		return request, "", reject("INCOME_LOCAL_OPERATION_INVALID", nil)
	}
	hash, err := request.Digest()
	if err != nil || hash != o.RequestHash {
		return request, "", reject("INCOME_LOCAL_OPERATION_INVALID", err)
	}
	return request, hash, nil
}

// Static checks precede every journal/posting request. The caller retains its
// per-operation RecordedAt <= now check at the original validation position.
func nativeIncomeReceiptOriginal(o nativeIncomeLocalOperation, request bankv2.Request, result bankv2.Result, stored nativeIncomeReceiptRaw) (NativeReceipt, error) {
	var receipt NativeReceipt
	if stored.bytes != int64(len(stored.original)) || Hash(stored.original) != stored.hash || decode(stored.original, &receipt) != nil || receipt.Protocol != "native-receipt-v1" || o.ReceiptID == nil || receipt.ID.String() != *o.ReceiptID || receipt.OperationID.String() != o.ID || receipt.BankResult.RequestHash != o.RequestHash || receipt.BankResult.Status != bankv2.Settled || receipt.BankResult.Sequence != result.Sequence || receipt.BankResult.Version != result.Version || bankv2.VerifyResult(request, receipt.BankResult) != nil || result.SettledAt == nil || receipt.BankResult.SettledAt == nil || !result.SettledAt.Equal(*receipt.BankResult.SettledAt) || receipt.RecordedAt.Before(*result.SettledAt) || len(receipt.BankResult.Postings) != len(result.Postings) {
		return receipt, reject("INCOME_RECEIPT_INVALID", nil)
	}
	return receipt, nil
}

func (r *nativeIncomeReceiptReader) verify(index int, o nativeIncomeLocalOperation, request bankv2.Request, result bankv2.Result, now time.Time) error {
	if r.chunk == nil || index >= r.chunk.end {
		r.chunk = loadNativeIncomeReceiptChunk(r.ctx, r.tx, r.p, r.namespace, r.operations, r.bank, index)
	}
	return verifyIncomeNativeReceiptChunk(r.p, o, request, result, now, r.chunk)
}

func loadNativeIncomeReceiptChunk(ctx context.Context, tx pgx.Tx, p Principal, namespace string, operations []nativeIncomeLocalOperation, bank map[string]bankv2.Result, start int) *nativeIncomeReceiptChunk {
	end := start + nativeIncomeReadChunk
	if end > len(operations) {
		end = len(operations)
	}
	out := &nativeIncomeReceiptChunk{end: end, receipts: map[string]nativeIncomeReceiptRaw{}, journals: map[string]nativeIncomeJournalRow{}, postings: map[string][]nativeIncomePostingRow{}}
	ids, seen := []string{}, map[string]bool{}
	for _, o := range operations[start:end] {
		if o.State == "SETTLED" && o.ReceiptID != nil && !seen[*o.ReceiptID] {
			seen[*o.ReceiptID] = true
			ids = append(ids, *o.ReceiptID)
		}
	}
	if len(ids) == 0 {
		return out
	}
	// 1 MiB is the existing native_receipts CHECK, not a newly expanded limit.
	// An oversized/corrupt row is observed as mismatched metadata, never clipped.
	rows, err := tx.Query(ctx, `SELECT id::text,operation_id::text,octet_length(original),CASE WHEN octet_length(original)<=1048576 THEN original END,original_hash FROM native_receipts WHERE environment_id=$1 AND user_id=$2 AND id=ANY($3::uuid[]) ORDER BY id`, p.EnvironmentID.String(), p.UserID.String(), ids)
	if err != nil {
		out.receiptErr = err
		return out
	}
	for rows.Next() {
		var id, operation string
		var stored nativeIncomeReceiptRaw
		if err = rows.Scan(&id, &operation, &stored.bytes, &stored.original, &stored.hash); err != nil {
			out.receiptErr = err
			break
		}
		key := nativeIncomeReceiptKey(operation, id)
		if _, duplicate := out.receipts[key]; duplicate {
			out.receiptErr = reject("INCOME_RECEIPT_INVALID", nil)
			break
		}
		stored.original = append([]byte(nil), stored.original...)
		out.receipts[key] = stored
	}
	if err = rows.Err(); out.receiptErr == nil && err != nil {
		out.receiptErr = err
	}
	rows.Close()
	if out.receiptErr != nil {
		return out
	}
	journalIDs := []string{}
	bounds := map[string]nativeIncomePostingBound{}
	journalOperations := map[string]string{}
	for _, o := range operations[start:end] {
		if o.State != "SETTLED" || o.ReceiptID == nil {
			continue
		}
		request, hash, e := nativeIncomeRequest(namespace, p, o)
		result, found := bank[o.Key]
		stored, present := out.receipts[nativeIncomeReceiptKey(o.ID, *o.ReceiptID)]
		if e != nil || !found || result.Request == nil || result.RequestHash != hash || result.Request.OperationID != o.ID || result.Status != bankv2.Settled || bankv2.VerifyResult(request, result) != nil || !present {
			continue
		}
		receipt, e := nativeIncomeReceiptOriginal(o, request, result, stored)
		if e != nil {
			continue
		}
		journal := receipt.JournalID.String()
		bound, exists := bounds[journal]
		if !exists {
			journalIDs = append(journalIDs, journal)
			journalOperations[journal] = o.ID
		}
		if len(result.Postings)+1 > bound.count {
			bound.count = len(result.Postings) + 1
		}
		for i, leg := range result.Postings {
			for _, value := range []struct {
				n       int
				maximum *int
			}{{len(fmt.Sprintf("bank:%d:%s", i+1, leg.ID)), &bound.ref}, {len(leg.ID), &bound.id}, {len(leg.Dimension), &bound.dimension}, {len(leg.LedgerID), &bound.ledger}, {len(leg.Direction), &bound.direction}, {3, &bound.currency}} {
				if value.n > *value.maximum {
					*value.maximum = value.n
				}
			}
		}
		bounds[journal] = bound
	}
	if len(journalIDs) == 0 {
		return out
	}
	rows, err = tx.Query(ctx, `SELECT id::text,operation_id::text,status FROM native_journals WHERE environment_id=$1 AND user_id=$2 AND id=ANY($3::uuid[]) ORDER BY id`, p.EnvironmentID.String(), p.UserID.String(), journalIDs)
	if err != nil {
		out.journalErr = err
		return out
	}
	for rows.Next() {
		var id string
		var row nativeIncomeJournalRow
		if err = rows.Scan(&id, &row.operation, &row.state); err != nil {
			out.journalErr = err
			break
		}
		if _, duplicate := out.journals[id]; duplicate {
			out.journalErr = reject("INCOME_RECEIPT_INVALID", nil)
			break
		}
		out.journals[id] = row
	}
	if err = rows.Err(); out.journalErr == nil && err != nil {
		out.journalErr = err
	}
	rows.Close()
	if out.journalErr != nil {
		return out
	}
	validJournals := []string{}
	for _, id := range journalIDs {
		journal, found := out.journals[id]
		if found && journal.operation == journalOperations[id] && journal.state == "POSTED" {
			validJournals = append(validJournals, id)
		}
	}
	journalIDs = validJournals
	if len(journalIDs) == 0 {
		return out
	}
	limits, refBytes, idBytes, dimensionBytes, ledgerBytes, directionBytes, currencyBytes := []int{}, []int{}, []int{}, []int{}, []int{}, []int{}, []int{}
	for _, id := range journalIDs {
		b := bounds[id]
		limits = append(limits, b.count)
		refBytes = append(refBytes, b.ref)
		idBytes = append(idBytes, b.id)
		dimensionBytes = append(dimensionBytes, b.dimension)
		ledgerBytes = append(ledgerBytes, b.ledger)
		directionBytes = append(directionBytes, b.direction)
		currencyBytes = append(currencyBytes, b.currency)
	}
	// Each journal is read to expected+1, after validated original/Result.
	// That extra row is an explicit failure witness. It cannot yield success.
	rows, err = tx.Query(ctx, `SELECT w.id::text,
		CASE WHEN octet_length(p.leg_ref)<=w.ref_bytes THEN p.leg_ref ELSE '' END,
		CASE WHEN octet_length(p.bank_posting_id)<=w.id_bytes THEN p.bank_posting_id ELSE '' END,
		CASE WHEN octet_length(p.dimension)<=w.dimension_bytes THEN p.dimension ELSE '' END,
		CASE WHEN octet_length(p.ledger_id)<=w.ledger_bytes THEN p.ledger_id ELSE '' END,
		CASE WHEN octet_length(p.direction)<=w.direction_bytes THEN p.direction ELSE '' END,
		p.amount_cents,p.occurred_at,
		CASE WHEN octet_length(p.currency)<=w.currency_bytes THEN p.currency ELSE '' END,
		(octet_length(p.leg_ref)>w.ref_bytes OR octet_length(p.bank_posting_id)>w.id_bytes OR octet_length(p.dimension)>w.dimension_bytes OR octet_length(p.ledger_id)>w.ledger_bytes OR octet_length(p.direction)>w.direction_bytes OR octet_length(p.currency)>w.currency_bytes)
		FROM unnest($3::uuid[],$4::int[],$5::int[],$6::int[],$7::int[],$8::int[],$9::int[],$10::int[]) AS w(id,max_rows,ref_bytes,id_bytes,dimension_bytes,ledger_bytes,direction_bytes,currency_bytes)
		CROSS JOIN LATERAL (SELECT leg_ref,bank_posting_id,dimension,ledger_id,direction,amount_cents,occurred_at,currency FROM native_postings WHERE environment_id=$1 AND user_id=$2 AND journal_id=w.id ORDER BY leg_ref LIMIT w.max_rows) p ORDER BY w.id,p.leg_ref`, p.EnvironmentID.String(), p.UserID.String(), journalIDs, limits, refBytes, idBytes, dimensionBytes, ledgerBytes, directionBytes, currencyBytes)
	if err != nil {
		out.postingErr = err
		return out
	}
	for rows.Next() {
		var journal string
		var row nativeIncomePostingRow
		if err = rows.Scan(&journal, &row.ref, &row.id, &row.dimension, &row.ledger, &row.direction, &row.amount, &row.occurred, &row.currency, &row.invalidSize); err != nil {
			out.postingErr = err
			break
		}
		bound, exists := bounds[journal]
		if !exists {
			out.postingErr = reject("INCOME_RECEIPT_INVALID", nil)
			break
		}
		if row.invalidSize || len(row.ref) > bound.ref || len(row.id) > bound.id || len(row.dimension) > bound.dimension || len(row.ledger) > bound.ledger || len(row.direction) > bound.direction || len(row.currency) > bound.currency {
			// Keep the failure marker, not an arbitrarily large corrupt text row.
			row = nativeIncomePostingRow{invalidSize: true}
		}
		out.postings[journal] = append(out.postings[journal], row)
	}
	out.postingEndErr = rows.Err()
	rows.Close()
	return out
}

func verifyIncomeNativeReceiptChunk(p Principal, o nativeIncomeLocalOperation, request bankv2.Request, result bankv2.Result, now time.Time, chunk *nativeIncomeReceiptChunk) error {
	if o.ReceiptID == nil {
		return reject("INCOME_RECEIPT_INVALID", nil)
	}
	if chunk.receiptErr != nil {
		return reject("INCOME_RECEIPT_INVALID", chunk.receiptErr)
	}
	stored, found := chunk.receipts[nativeIncomeReceiptKey(o.ID, *o.ReceiptID)]
	if !found {
		return reject("INCOME_RECEIPT_INVALID", pgx.ErrNoRows)
	}
	receipt, err := nativeIncomeReceiptOriginal(o, request, result, stored)
	if err != nil {
		return err
	}
	if receipt.RecordedAt.After(now) {
		return reject("INCOME_RECEIPT_INVALID", nil)
	}
	journal, posted := chunk.journals[receipt.JournalID.String()]
	if chunk.journalErr != nil || !posted || journal.operation != o.ID || journal.state != "POSTED" {
		return reject("INCOME_RECEIPT_INVALID", chunk.journalErr)
	}
	expected := map[string]bankv2.Posting{}
	for i, leg := range result.Postings {
		r := receipt.BankResult.Postings[i]
		if r.ID != leg.ID || r.Dimension != leg.Dimension || r.LedgerID != leg.LedgerID || r.Direction != leg.Direction || r.Amount != leg.Amount || !r.OccurredAt.Equal(leg.OccurredAt) {
			return reject("INCOME_RECEIPT_INVALID", nil)
		}
		expected[fmt.Sprintf("bank:%d:%s", i+1, leg.ID)] = leg
	}
	if chunk.postingErr != nil {
		return chunk.postingErr
	}
	postings := chunk.postings[receipt.JournalID.String()]
	if len(postings) > len(result.Postings) {
		return reject("INCOME_RECEIPT_INVALID", nil)
	}
	for _, row := range postings {
		leg, exists := expected[row.ref]
		if row.invalidSize || !exists || row.id != leg.ID || row.dimension != leg.Dimension || row.ledger != leg.LedgerID || row.direction != leg.Direction || row.amount != leg.Amount.Cents() || !row.occurred.Equal(leg.OccurredAt) || row.currency != "CNY" {
			return reject("INCOME_RECEIPT_INVALID", nil)
		}
		delete(expected, row.ref)
	}
	if chunk.postingEndErr != nil || len(expected) != 0 {
		return reject("INCOME_RECEIPT_INVALID", chunk.postingEndErr)
	}
	return nil
}
