package app

import (
	"context"

	"github.com/jackc/pgx/v5"
	"zhiyu.local/zhiyu-go/internal/execution/bankcredit"
	funds "zhiyu.local/zhiyu-go/internal/funds/domain"
)

type nativeIncomeEvidenceRow struct {
	canonical    []byte
	digest, kind string
	bytes        int64
}

type nativeIncomeEvidenceReader struct {
	ctx     context.Context
	tx      pgx.Tx
	p       Principal
	credits []bankcredit.Entry
	known   map[string]funds.BankCreditFact
	end     int
	rows    map[string]nativeIncomeEvidenceRow
	err     error
}

func (r *nativeIncomeEvidenceReader) row(index int, entry bankcredit.Entry) (nativeIncomeEvidenceRow, error) {
	if r.rows == nil || index >= r.end {
		r.load(index)
	}
	if r.err != nil {
		return nativeIncomeEvidenceRow{}, r.err
	}
	row, found := r.rows[entry.Record.Event.EvidenceID]
	if !found {
		return nativeIncomeEvidenceRow{}, pgx.ErrNoRows
	}
	return row, nil
}

func (r *nativeIncomeEvidenceReader) load(start int) {
	r.end = start + nativeIncomeReadChunk
	if r.end > len(r.credits) {
		r.end = len(r.credits)
	}
	r.rows, r.err = map[string]nativeIncomeEvidenceRow{}, nil
	ids, sizes, positions := []string{}, []int{}, map[string]int{}
	for _, entry := range r.credits[start:r.end] {
		if _, exists := r.known[entry.Record.Event.OriginID]; !exists {
			continue
		}
		want, _ := entry.Record.CanonicalBytes()
		id := entry.Record.Event.EvidenceID
		if position, duplicate := positions[id]; duplicate {
			if len(want) > sizes[position] {
				sizes[position] = len(want)
			}
			continue
		}
		positions[id] = len(ids)
		ids, sizes = append(ids, id), append(sizes, len(want))
	}
	if len(ids) == 0 {
		return
	}
	// Only exact expected canonical lengths enter Go memory. The bank capture
	// already validates every Record; a stored length mismatch remains a hard
	// ledger mismatch in the existing per-credit order, never a clipped original.
	rows, err := r.tx.Query(r.ctx, `SELECT b.id,b.digest,CASE WHEN b.kind='BANK_EXTERNAL_CREDIT_V1' THEN b.kind ELSE '' END,octet_length(b.canonical),CASE WHEN octet_length(b.canonical)=w.expected_bytes THEN b.canonical END FROM unnest($3::text[],$4::int[]) AS w(id,expected_bytes) JOIN evidence_blobs b ON b.id=w.id AND b.environment_id=$1 AND b.user_id=$2 ORDER BY b.id`, r.p.EnvironmentID.String(), r.p.UserID.String(), ids, sizes)
	if err != nil {
		r.err = err
		return
	}
	for rows.Next() {
		var id string
		var row nativeIncomeEvidenceRow
		if err = rows.Scan(&id, &row.digest, &row.kind, &row.bytes, &row.canonical); err != nil {
			r.err = err
			break
		}
		if _, duplicate := r.rows[id]; duplicate {
			r.err = reject("INCOME_ORIGINAL_CONFLICT", nil)
			break
		}
		row.canonical = append([]byte(nil), row.canonical...)
		r.rows[id] = row
	}
	if err = rows.Err(); r.err == nil && err != nil {
		r.err = err
	}
	rows.Close()
}
