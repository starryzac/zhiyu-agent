package app

import (
	"context"
	"encoding/json"

	"github.com/jackc/pgx/v5"
	funds "zhiyu.local/zhiyu-go/internal/funds/domain"
)

type templateNativeOperationProjection struct {
	hash, state string
	receiptID   *string
}

type templateNativeOperationReader struct {
	ctx  context.Context
	tx   pgx.Tx
	p    Principal
	raw  []string
	end  int
	rows map[string]templateNativeOperationProjection
	err  error
}

func (r *templateNativeOperationReader) row(index int, operation funds.ID) (templateNativeOperationProjection, error) {
	if r.rows == nil || index >= r.end {
		r.load(index)
	}
	if r.err != nil {
		return templateNativeOperationProjection{}, r.err
	}
	row, found := r.rows[operation.String()]
	if !found {
		return templateNativeOperationProjection{}, pgx.ErrNoRows
	}
	return row, nil
}

func (r *templateNativeOperationReader) load(start int) {
	r.end = start + nativeIncomeReadChunk
	if r.end > len(r.raw) {
		r.end = len(r.raw)
	}
	r.rows, r.err = map[string]templateNativeOperationProjection{}, nil
	ids, seen := []string{}, map[string]bool{}
	for _, raw := range r.raw[start:r.end] {
		var row struct {
			OperationID funds.ID `json:"operation_id"`
		}
		// This is only key discovery. Full original/hash/identity validation stays
		// in templateContributionEvidence, in the existing raw row order.
		if json.Unmarshal([]byte(raw), &row) != nil {
			continue
		}
		id := row.OperationID.String()
		if !seen[id] {
			seen[id] = true
			ids = append(ids, id)
		}
	}
	if len(ids) == 0 {
		return
	}
	rows, err := r.tx.Query(r.ctx, `SELECT id::text,bank_request_hash::text,status,receipt_id::text FROM native_operations WHERE environment_id=$1 AND user_id=$2 AND id=ANY($3::uuid[]) ORDER BY id`, r.p.EnvironmentID.String(), r.p.UserID.String(), ids)
	if err != nil {
		r.err = err
		return
	}
	for rows.Next() {
		var id string
		var row templateNativeOperationProjection
		if err = rows.Scan(&id, &row.hash, &row.state, &row.receiptID); err != nil {
			r.err = err
			break
		}
		if _, duplicate := r.rows[id]; duplicate {
			r.err = reject("TEMPLATE_CONTRIBUTION_EVIDENCE_INVALID", nil)
			break
		}
		r.rows[id] = row
	}
	if err = rows.Err(); r.err == nil && err != nil {
		r.err = err
	}
	rows.Close()
}
