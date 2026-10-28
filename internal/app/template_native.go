package app

import (
	"context"
	"encoding/json"
	"time"

	"github.com/jackc/pgx/v5"
	"zhiyu.local/zhiyu-go/internal/adapters/postgres"
	"zhiyu.local/zhiyu-go/internal/execution/bankv2"
	execution "zhiyu.local/zhiyu-go/internal/execution/domain"
	funds "zhiyu.local/zhiyu-go/internal/funds/domain"
)

var templateNativeSourceTables = []struct{ name, order string }{
	{"native_goal_balances", "goal_id"}, {"native_goal_lots", "goal_id,account_id,source_kind,source_id"},
	{"native_holds", "operation_id,resource_kind,resource_id,resource_detail"},
	{"native_positions", "id"}, {"native_position_states", "position_id"},
	{"native_principal_returns", "bank_key"}, {"native_return_locations", "bank_key,account_id"},
	{"native_return_claims", "operation_id,bank_key,account_id"}, {"native_receipts", "id"},
}

// Receipt event time, rather than a mutable fixed-Shanghai display counter,
// determines a contribution's natural month in the user's frozen timezone.
func (s *Service) templateContributionEvidence(ctx context.Context, tx pgx.Tx, p Principal, snapshot templateSnapshot) (map[funds.ID]funds.Money, map[funds.ID]funds.Money, error) {
	monthly, gross := map[funds.ID]funds.Money{}, map[funds.ID]funds.Money{}
	zone, _ := time.LoadLocation(snapshot.Timezone)
	if snapshot.Timezone == "Asia/Shanghai" {
		zone = time.FixedZone("Asia/Shanghai", 8*3600)
	}
	period := snapshot.AsOf.In(zone).Format("2006-01")
	add := func(goal funds.ID, amount funds.Money, at time.Time, newContribution bool) error {
		if at.IsZero() || at.After(snapshot.AsOf) || amount.IsZero() {
			return reject("TEMPLATE_CONTRIBUTION_EVIDENCE_INVALID", nil)
		}
		var err error
		gross[goal], err = gross[goal].Add(amount)
		if err != nil {
			return err
		}
		if newContribution && at.In(zone).Format("2006-01") == period {
			monthly[goal], err = monthly[goal].Add(amount)
		}
		return err
	}
	for _, raw := range snapshot.Raw["receipts"] {
		var row struct {
			ID          funds.ID `json:"id"`
			OperationID funds.ID `json:"operation_id"`
			Original    string   `json:"original"`
		}
		if json.Unmarshal([]byte(raw), &row) != nil {
			return nil, nil, reject("TEMPLATE_CONTRIBUTION_EVIDENCE_INVALID", nil)
		}
		original, err := decodePGBytea(row.Original)
		var receipt Receipt
		if err != nil || auditJSON(original, &receipt) != nil || receipt.ID != row.ID || receipt.OperationID != row.OperationID || receipt.UserID != p.UserID || receipt.Environment != s.Namespace {
			return nil, nil, reject("TEMPLATE_CONTRIBUTION_EVIDENCE_INVALID", err)
		}
		var requestRaw []byte
		var hash, state string
		var receiptID *string
		if err = tx.QueryRow(ctx, `SELECT bank_request,bank_request_hash::text,status,receipt_id::text FROM operations WHERE environment_id=$1 AND user_id=$2 AND id=$3`, p.EnvironmentID.String(), p.UserID.String(), row.OperationID.String()).Scan(&requestRaw, &hash, &state, &receiptID); err != nil {
			return nil, nil, reject("TEMPLATE_CONTRIBUTION_EVIDENCE_INVALID", err)
		}
		var request execution.BankRequest
		if auditJSON(requestRaw, &request) != nil {
			return nil, nil, reject("TEMPLATE_CONTRIBUTION_EVIDENCE_INVALID", nil)
		}
		requestHash, err := request.Digest()
		if err != nil || state != "SETTLED" || receiptID == nil || *receiptID != receipt.ID.String() || hash != requestHash || receipt.BankRequestHash != hash || receipt.BankKey != request.Key || request.UserID != p.UserID.String() || request.Namespace != s.Namespace || request.OperationID != row.OperationID.String() || receipt.Amount != request.Amount || receipt.SettledAt.Before(request.RequestedAt) || receipt.RecordedAt.Before(receipt.SettledAt) || receipt.RecordedAt.After(snapshot.AsOf) {
			return nil, nil, reject("TEMPLATE_CONTRIBUTION_EVIDENCE_INVALID", err)
		}
		if request.Kind == "ALLOCATE_GOAL" {
			goal, err := funds.ParseID(request.GoalID)
			if err != nil || add(goal, receipt.Amount, receipt.SettledAt, true) != nil {
				return nil, nil, reject("TEMPLATE_CONTRIBUTION_EVIDENCE_INVALID", err)
			}
		}
	}
	nativeOperations := templateNativeOperationReader{ctx: ctx, tx: tx, p: p, raw: snapshot.Raw["native_receipts"]}
	for i, raw := range snapshot.Raw["native_receipts"] {
		var row struct {
			ID          funds.ID `json:"id"`
			OperationID funds.ID `json:"operation_id"`
			JournalID   funds.ID `json:"journal_id"`
			Original    string   `json:"original"`
			Hash        string   `json:"original_hash"`
		}
		if json.Unmarshal([]byte(raw), &row) != nil {
			return nil, nil, reject("TEMPLATE_CONTRIBUTION_EVIDENCE_INVALID", nil)
		}
		original, err := decodePGBytea(row.Original)
		var receipt NativeReceipt
		if err != nil || Hash(original) != row.Hash || auditJSON(original, &receipt) != nil || receipt.Protocol != "native-receipt-v1" || receipt.ID != row.ID || receipt.OperationID != row.OperationID || receipt.JournalID != row.JournalID || receipt.BankResult.Request == nil {
			return nil, nil, reject("TEMPLATE_CONTRIBUTION_EVIDENCE_INVALID", err)
		}
		request := *receipt.BankResult.Request
		projection, err := nativeOperations.row(i, row.OperationID)
		if err != nil {
			return nil, nil, reject("TEMPLATE_CONTRIBUTION_EVIDENCE_INVALID", err)
		}
		requestHash, err := request.Digest()
		result := receipt.BankResult
		if err != nil || projection.hash != requestHash || projection.state != "SETTLED" || projection.receiptID == nil || *projection.receiptID != receipt.ID.String() || request.UserID != p.UserID.String() || request.Namespace != s.Namespace || request.OperationID != row.OperationID.String() || result.Status != bankv2.Settled || bankv2.VerifyResult(request, result) != nil || result.SettledAt == nil || receipt.RecordedAt.Before(*result.SettledAt) || receipt.RecordedAt.After(snapshot.AsOf) {
			return nil, nil, reject("TEMPLATE_CONTRIBUTION_EVIDENCE_INVALID", err)
		}
		if request.Effect.Kind == bankv2.Allocate || request.Effect.Kind == bankv2.MoveGoal {
			goal, err := funds.ParseID(request.Effect.DestinationGoalID)
			// An actual paired transfer establishes receiving ownership. It does
			// not turn already assigned money into a new monthly contribution.
			if err != nil || add(goal, request.Effect.Amount, *result.SettledAt, request.Effect.Kind == bankv2.Allocate) != nil {
				return nil, nil, reject("TEMPLATE_CONTRIBUTION_EVIDENCE_INVALID", err)
			}
		}
	}
	return monthly, gross, nil
}

func nativeTemplateHeld(base funds.Money, ledger funds.IncomeLedger, native postgres.NativeLedger) (funds.Money, error) {
	incomeByAction, cashByAction := map[funds.ID]funds.Money{}, map[funds.ID]funds.Money{}
	for _, reservation := range ledger.Snapshot().Reservations {
		if reservation.State != funds.Reserved {
			continue
		}
		for _, use := range reservation.Uses {
			value, err := incomeByAction[reservation.ActionID].Add(use.Amount)
			if err != nil {
				return funds.Money{}, err
			}
			incomeByAction[reservation.ActionID] = value
		}
	}
	for _, hold := range native.Holds {
		if hold.State == funds.Reserved && hold.ResourceKind == "CASH" {
			value, err := cashByAction[hold.OperationID].Add(hold.Amount)
			if err != nil {
				return funds.Money{}, err
			}
			cashByAction[hold.OperationID] = value
		}
	}
	for action, cash := range cashByAction {
		if cash.Cents() > incomeByAction[action].Cents() {
			extra, _ := cash.Sub(incomeByAction[action])
			var err error
			base, err = base.Add(extra)
			if err != nil {
				return funds.Money{}, err
			}
		}
	}
	return base, nil
}
