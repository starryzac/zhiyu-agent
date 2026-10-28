package app

import (
	"context"

	"github.com/jackc/pgx/v5/pgxpool"
	"zhiyu.local/zhiyu-go/internal/execution/bankv2"
	funds "zhiyu.local/zhiyu-go/internal/funds/domain"
)

// This fact is created only immediately after the first pgx bytea Scan in the
// retained activity read. pgx's []byte scan makes an owned copy. The fact stays
// in that request's stack, carries no verdict, and never exposes a decoded view.
type nativeActivityPermitRaw struct {
	tx        *pgxpool.Tx
	principal Principal
	operation funds.ID
	kind      bankv2.Kind
	original  []byte
}

func captureNativeActivityPermitRaw(q queryRow, bound *pgxpool.Tx, p Principal, operation funds.ID, kind bankv2.Kind, original []byte) *nativeActivityPermitRaw {
	tx, ok := q.(*pgxpool.Tx)
	if !ok || tx == nil || bound == nil || tx != bound || p.Kind != "USER" || p.EnvironmentID == (funds.ID{}) || p.UserID == (funds.ID{}) || p.SessionID == (funds.ID{}) || operation == (funds.ID{}) || !nativeAssetKind(kind) || len(original) == 0 {
		return nil
	}
	return &nativeActivityPermitRaw{tx: tx, principal: p, operation: operation, kind: kind, original: original}
}

func (fact *nativeActivityPermitRaw) matches(q queryRow, p Principal, operation funds.ID, kind bankv2.Kind) bool {
	if fact == nil {
		return false
	}
	tx, ok := q.(*pgxpool.Tx)
	return ok && tx != nil && tx == fact.tx && p == fact.principal && operation == fact.operation && kind == fact.kind
}

type nativeAssetStoredPermitRow struct {
	original                                                       []byte
	originalHash, requestHash, effectHash, signatureHash, permitID string
}

const nativeAssetPermitFullRead = `SELECT original,original_hash::text,bank_request_hash::text,effect_hash::text,signature_hash::text,permit_id::text FROM native_submission_permits WHERE environment_id=$1 AND user_id=$2 AND operation_id=$3`
const nativeAssetPermitMetadataRead = `SELECT original_hash::text,bank_request_hash::text,effect_hash::text,signature_hash::text,permit_id::text FROM native_submission_permits WHERE environment_id=$1 AND user_id=$2 AND operation_id=$3`

func loadNativeAssetPermitMetadata(ctx context.Context, q queryRow, p Principal, operation funds.ID) (nativeAssetStoredPermitRow, error) {
	var row nativeAssetStoredPermitRow
	err := q.QueryRow(ctx, nativeAssetPermitMetadataRead, p.EnvironmentID.String(), p.UserID.String(), operation.String()).Scan(&row.originalHash, &row.requestHash, &row.effectHash, &row.signatureHash, &row.permitID)
	return row, err
}

func loadNativeAssetStoredPermitRow(ctx context.Context, q queryRow, p Principal, operation funds.ID, kind bankv2.Kind, fact *nativeActivityPermitRaw) (nativeAssetStoredPermitRow, error) {
	if fact.matches(q, p, operation, kind) {
		// Keep the second scoped SQL statement at its original validation point.
		// Only its duplicate large bytea column is omitted. Each consumer still
		// hashes and decodes the actual owned original in the original order.
		row, err := loadNativeAssetPermitMetadata(ctx, q, p, operation)
		row.original = fact.original
		return row, err
	}
	var row nativeAssetStoredPermitRow
	err := q.QueryRow(ctx, nativeAssetPermitFullRead, p.EnvironmentID.String(), p.UserID.String(), operation.String()).Scan(&row.original, &row.originalHash, &row.requestHash, &row.effectHash, &row.signatureHash, &row.permitID)
	return row, err
}
