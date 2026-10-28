package app

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"zhiyu.local/zhiyu-go/internal/execution/bankv2"
	funds "zhiyu.local/zhiyu-go/internal/funds/domain"
)

type NativeActivityOriginal struct {
	Protocol          string          `json:"protocol"`
	VerificationScope string          `json:"verification_scope"`
	VerifiedAt        time.Time       `json:"verified_at"`
	Activity          Activity        `json:"activity"`
	Operation         NativeOperation `json:"operation"`
	Receipt           NativeReceipt   `json:"receipt"`
	OriginalHash      string          `json:"original_hash"`
	BankRequestHash   string          `json:"bank_request_hash"`
	BankEffectHash    string          `json:"bank_effect_hash"`
	BankAuthority     bool            `json:"bank_authority"`
}

// This is an independent read of retained originals and local posting equality,
// never a read of a dashboard cache and never a fresh independent bank query.
func (s *Service) NativeActivityOriginal(ctx context.Context, p Principal, eventID funds.ID) (NativeActivityOriginal, error) {
	out := NativeActivityOriginal{Protocol: "native-activity-original-v1", VerificationScope: "RETAINED_BANK_RESULT_AND_LOCAL_POSTINGS_VERIFIED_NOT_LIVE_BANK_QUERY", VerifiedAt: s.now()}
	if eventID == (funds.ID{}) {
		return out, reject("NOT_FOUND", nil)
	}
	tx, err := s.Pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	if err != nil {
		return out, err
	}
	defer rollback(ctx, tx)
	env, err := s.environment(ctx, tx, false)
	if err != nil {
		return out, err
	}
	if err = sameUser(p, env.ID); err != nil {
		return out, err
	}
	if err = s.human(ctx, tx, p); err != nil {
		return out, err
	}
	var eventRaw, receiptRaw, requestRaw []byte
	var operationID, group, receiptID, journalID, signature, journalKind, journalState, requestHash, effectHash, commandKind string
	var child int
	var receiptAt, postedAt time.Time
	var request bankv2.Request
	op := &out.Operation
	a := &out.Activity
	a.ID, a.OperationFamily = eventID, "NATIVE"
	err = tx.QueryRow(ctx, `SELECT e.kind,e.aggregate_id::text,e.aggregate_version,e.created_at,e.payload,o.group_id::text,o.child_number,o.status,o.bank_key,o.bank_observed_status,o.processing_health,o.version,o.created_at,o.updated_at,o.bank_request,o.bank_request_hash::text,o.effect_hash::text,o.permit_signature,o.receipt_id::text,r.journal_id::text,r.original,r.original_hash::text,r.created_at,j.kind,j.status,j.posted_at,o.command_kind FROM outbox e JOIN native_operations o ON(o.environment_id=e.environment_id AND o.user_id=e.user_id AND o.id=e.aggregate_id) JOIN native_receipts r ON(r.environment_id=o.environment_id AND r.user_id=o.user_id AND r.operation_id=o.id AND r.id=o.receipt_id) JOIN native_journals j ON(j.environment_id=r.environment_id AND j.user_id=r.user_id AND j.id=r.journal_id AND j.operation_id=o.id) WHERE e.environment_id=$1 AND e.user_id=$2 AND e.id=$3 AND e.kind='NATIVE_OPERATION_SETTLED'`, env.ID.String(), p.UserID.String(), eventID.String()).Scan(&a.Kind, &operationID, &a.AggregateVersion, &a.CreatedAt, &eventRaw, &group, &child, &op.State, &op.BankKey, &op.BankObservedStatus, &op.ProcessingHealth, &op.Version, &op.CreatedAt, &op.UpdatedAt, &requestRaw, &requestHash, &effectHash, &signature, &receiptID, &journalID, &receiptRaw, &out.OriginalHash, &receiptAt, &journalKind, &journalState, &postedAt, &commandKind)
	if errors.Is(err, pgx.ErrNoRows) {
		return out, reject("NOT_FOUND", nil)
	}
	if err != nil {
		return out, err
	}
	if auditJSON(requestRaw, &request) != nil || auditJSON(receiptRaw, &out.Receipt) != nil || !bytes.Equal(eventRaw, receiptRaw) || Hash(receiptRaw) != out.OriginalHash || out.Receipt.Protocol != "native-receipt-v1" || op.State != "SETTLED" || op.Version < a.AggregateVersion || request.Namespace != s.Namespace || request.UserID != p.UserID.String() || request.OperationID != operationID || request.Key != op.BankKey || out.Receipt.OperationID.String() != operationID || out.Receipt.ID.String() != receiptID || out.Receipt.GroupID.String() != group || out.Receipt.JournalID.String() != journalID || !out.Receipt.RecordedAt.Equal(receiptAt) || !receiptAt.Equal(a.CreatedAt) || journalKind != nativeActivityJournalKind(commandKind, request.Effect.Kind) || journalState != "POSTED" || !postedAt.Equal(receiptAt) || out.Receipt.BankResult.Status != bankv2.Settled || bankv2.VerifyResult(request, out.Receipt.BankResult) != nil {
		return out, reject("EVIDENCE_INVALID", errors.New("native activity original: header or receipt"))
	}
	rh, err := request.Digest()
	eh, e := request.Effect.Digest()
	if err != nil || e != nil || rh != requestHash || eh != effectHash || signature == "" {
		return out, reject("EVIDENCE_INVALID", nil)
	}
	if activityTx, ok := tx.(*pgxpool.Tx); ok {
		err = nativeActivityStoredPermit(ctx, activityTx, p, out.Receipt.OperationID, request, signature)
	} else {
		err = nativeStoredPermit(ctx, tx, p, out.Receipt.OperationID, request, signature)
	}
	if err != nil {
		return out, fmt.Errorf("native activity original: retained permit: %w", err)
	}
	resultRaw, err := encode(out.Receipt.BankResult)
	if err != nil {
		return out, err
	}
	var observed bool
	if err = tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM native_bank_observations WHERE environment_id=$1 AND user_id=$2 AND operation_id=$3 AND status='SETTLED' AND original=$4 AND original_hash=$5)`, env.ID.String(), p.UserID.String(), operationID, resultRaw, Hash(resultRaw)).Scan(&observed); err != nil {
		return out, err
	}
	if !observed {
		return out, reject("EVIDENCE_INVALID", errors.New("native activity original: retained bank observation"))
	}
	if err = nativeActivityPostings(ctx, tx, p, out.Receipt); err != nil {
		return out, fmt.Errorf("native activity original: local postings: %w", err)
	}
	op.ID, a.AggregateID = out.Receipt.OperationID, out.Receipt.OperationID
	op.GroupID, op.ChildNumber = out.Receipt.GroupID, child
	receiptText := out.Receipt.ID.String()
	op.Kind, op.Amount, op.ReceiptID = request.Effect.Kind, request.Effect.Amount, &receiptText
	a.OperationKind, a.ReceiptID = string(op.Kind), &out.Receipt.ID
	out.BankRequestHash, out.BankEffectHash = rh, eh
	return out, tx.Commit(ctx)
}

func nativeActivityPostings(ctx context.Context, tx pgx.Tx, p Principal, receipt NativeReceipt) error {
	rows, err := tx.Query(ctx, `SELECT bank_posting_id,dimension,ledger_id,currency,direction,amount_cents,occurred_at FROM native_postings WHERE environment_id=$1 AND user_id=$2 AND journal_id=$3 ORDER BY bank_posting_id LIMIT 1025`, p.EnvironmentID.String(), p.UserID.String(), receipt.JournalID.String())
	if err != nil {
		return err
	}
	defer rows.Close()
	expected := map[string]bankv2.Posting{}
	for _, leg := range receipt.BankResult.Postings {
		if _, duplicate := expected[leg.ID]; duplicate {
			return reject("EVIDENCE_INVALID", nil)
		}
		expected[leg.ID] = leg
	}
	count := 0
	for rows.Next() {
		count++
		var id, dimension, ledger, currency, direction string
		var amount int64
		var at time.Time
		if err = rows.Scan(&id, &dimension, &ledger, &currency, &direction, &amount, &at); err != nil {
			return err
		}
		leg, ok := expected[id]
		if !ok || count > 1024 || dimension != leg.Dimension || ledger != leg.LedgerID || currency != "CNY" || direction != leg.Direction || amount != leg.Amount.Cents() || !at.Equal(leg.OccurredAt) {
			return reject("EVIDENCE_INVALID", nil)
		}
		delete(expected, id)
	}
	if err = rows.Err(); err != nil {
		return err
	}
	if len(expected) != 0 || count == 0 {
		return reject("EVIDENCE_INVALID", nil)
	}
	return nil
}

func nativeActivityJournalKind(command string, kind bankv2.Kind) string {
	switch command {
	case "JOINT_ALLOCATE":
		return "ALLOCATION"
	case "BRIDGE_TRANSFER", "BRIDGE_ALLOCATE":
		return "BRIDGE_" + string(kind)
	case nativeStandingBridgeTransfer, nativeStandingBridgeAllocate:
		return "STANDING_BRIDGE_" + string(kind)
	case "STANDING_ALLOCATE":
		return "STANDING_ALLOCATION"
	default:
		return string(kind)
	}
}
