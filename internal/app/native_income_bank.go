package app

import (
	"context"
	"time"

	"zhiyu.local/zhiyu-go/internal/execution/bankcredit"
	"zhiyu.local/zhiyu-go/internal/execution/bankv2"
	execution "zhiyu.local/zhiyu-go/internal/execution/domain"
)

const nativeIncomeProtocol = "native-income-import-v1"
const nativeIncomeMaxOperations = 1000
const nativeIncomeMaxCaptureBytes = 4 << 20

// NativeIncomeSources is constructed by trusted server configuration. It is
// not a request DTO and has no external-credit write capability.
type NativeIncomeSources struct {
	Credit interface {
		CurrentState(context.Context, string, string) (bankcredit.CurrentState, error)
	}
	Legacy interface {
		Inventory(context.Context, string, string, int64, int64, int) (execution.BankInventory, error)
	}
	Native interface {
		Inventory(context.Context, string, string, int64, int64, int) (bankv2.Inventory, error)
		CurrentState(context.Context, string, string) (bankv2.CurrentState, error)
	}
}

type nativeIncomeCapture struct {
	Protocol    string                  `json:"protocol"`
	LocalBasis  nativeIncomeLocalBasis  `json:"local_basis_before_bank_read"`
	State       bankcredit.CurrentState `json:"state"`
	Legacy      []execution.BankResult  `json:"legacy_operations"`
	Native      []bankv2.Result         `json:"native_operations"`
	NativeStock bankv2.CurrentState     `json:"native_stock"`
}

type nativeIncomeLocalBasis struct {
	FundsVersion     uint64 `json:"funds_version"`
	SourceVersion    uint64 `json:"source_version"`
	WriterGeneration uint64 `json:"writer_generation"`
	ControlVersion   uint64 `json:"control_version"`
}

func (s *Service) captureNativeIncome(ctx context.Context, p Principal, sources NativeIncomeSources) (nativeIncomeCapture, []byte, error) {
	captureNativeIncomeAttempts.Add(1)
	out := nativeIncomeCapture{Protocol: nativeIncomeProtocol + "/bank-capture", Legacy: []execution.BankResult{}, Native: []bankv2.Result{}}
	if sources.Credit == nil || sources.Legacy == nil || sources.Native == nil {
		return out, nil, reject("BANK_UNAVAILABLE", nil)
	}
	var err error
	if err = s.Pool.QueryRow(ctx, `SELECT u.funds_version,u.source_version,e.writer_generation,e.control_version FROM users u JOIN environments e ON(e.id=u.environment_id) WHERE e.namespace=$1 AND e.id=$2 AND u.id=$3`, s.Namespace, p.EnvironmentID.String(), p.UserID.String()).Scan(&out.LocalBasis.FundsVersion, &out.LocalBasis.SourceVersion, &out.LocalBasis.WriterGeneration, &out.LocalBasis.ControlVersion); err != nil {
		return out, nil, err
	}
	out.State, err = sources.Credit.CurrentState(ctx, s.Namespace, p.UserID.String())
	if err != nil {
		return out, nil, reject("BANK_UNAVAILABLE", err)
	}
	if out.State.Validate() != nil || out.State.Namespace != s.Namespace || out.State.UserID != p.UserID.String() || out.State.CapturedAt.After(s.now()) || out.State.CapturedAt.Before(s.now().Add(-30*time.Second)) {
		return out, nil, reject("INCOME_BANK_SNAPSHOT_INVALID", nil)
	}
	// The older bank protocols use zero as "capture current". An explicitly
	// empty RR snapshot must not accidentally discover newer operations.
	var after int64
	for after < out.State.V1OperationWatermark {
		page, e := sources.Legacy.Inventory(ctx, s.Namespace, p.UserID.String(), after, out.State.V1OperationWatermark, 100)
		if e != nil {
			return out, nil, reject("BANK_UNAVAILABLE", e)
		}
		if page.Namespace != s.Namespace || page.UserID != p.UserID.String() || page.Watermark != out.State.V1OperationWatermark || len(page.Operations) == 0 || len(page.Operations) > 100 || page.NextAfter <= after || page.NextAfter > page.Watermark {
			return out, nil, reject("INCOME_BANK_SNAPSHOT_INVALID", nil)
		}
		last := after
		for _, r := range page.Operations {
			if r.Status == execution.BankNotFound || r.Namespace != s.Namespace || r.UserID != p.UserID.String() || r.Sequence <= last || r.Sequence > page.Watermark || execution.VerifyBankResult(r.Request, r) != nil {
				return out, nil, reject("INCOME_BANK_SNAPSHOT_INVALID", nil)
			}
			out.Legacy = append(out.Legacy, r)
			last = r.Sequence
		}
		if last != page.NextAfter || !page.HasMore && last != page.Watermark || page.HasMore && len(page.Operations) != 100 || len(out.Legacy) > nativeIncomeMaxOperations {
			return out, nil, reject("INCOME_CAPTURE_CAPACITY_OR_BOUNDS", nil)
		}
		after = last
	}
	after = 0
	for after < out.State.V2OperationWatermark {
		page, e := sources.Native.Inventory(ctx, s.Namespace, p.UserID.String(), after, out.State.V2OperationWatermark, 100)
		if e != nil {
			return out, nil, reject("BANK_UNAVAILABLE", e)
		}
		if page.Protocol != bankv2.Protocol || page.Namespace != s.Namespace || page.UserID != p.UserID.String() || page.Watermark != out.State.V2OperationWatermark || len(page.Operations) == 0 || len(page.Operations) > 100 || page.NextAfter <= after || page.NextAfter > page.Watermark {
			return out, nil, reject("INCOME_BANK_SNAPSHOT_INVALID", nil)
		}
		last := after
		for _, r := range page.Operations {
			if r.Request == nil || r.Status == bankv2.NotFound || r.Namespace != s.Namespace || r.UserID != p.UserID.String() || r.Sequence <= last || r.Sequence > page.Watermark || bankv2.VerifyResult(*r.Request, r) != nil {
				return out, nil, reject("INCOME_BANK_SNAPSHOT_INVALID", nil)
			}
			out.Native = append(out.Native, r)
			last = r.Sequence
		}
		if last != page.NextAfter || !page.HasMore && last != page.Watermark || page.HasMore && len(page.Operations) != 100 || len(out.Native) > nativeIncomeMaxOperations {
			return out, nil, reject("INCOME_CAPTURE_CAPACITY_OR_BOUNDS", nil)
		}
		after = last
	}
	out.NativeStock, err = sources.Native.CurrentState(ctx, s.Namespace, p.UserID.String())
	if err != nil {
		return out, nil, reject("BANK_UNAVAILABLE", err)
	}
	stock := out.NativeStock
	if stock.Protocol != bankv2.Protocol || stock.Namespace != s.Namespace || stock.UserID != p.UserID.String() || stock.OperationWatermark != out.State.V2OperationWatermark || stock.CapturedAt.IsZero() || stock.CapturedAt.After(s.now()) || stock.CapturedAt.Before(out.State.CapturedAt.Add(-30*time.Second)) || len(stock.Accounts) != len(out.State.Accounts) || len(stock.Goals) > 8 || len(stock.Positions) > 1000 {
		return out, nil, reject("INCOME_BANK_SNAPSHOT_INVALID", nil)
	}
	accounts := map[string]bankcredit.Account{}
	for _, a := range out.State.Accounts {
		accounts[a.ID] = a
	}
	for _, a := range stock.Accounts {
		b, exists := accounts[a.ID]
		if !exists || b.Balance != a.Balance || b.Reserved != a.Reserved {
			return out, nil, reject("INCOME_BANK_SNAPSHOT_INVALID", nil)
		}
		delete(accounts, a.ID)
	}
	raw, err := encode(out)
	if err != nil || len(raw) > nativeIncomeMaxCaptureBytes {
		return out, nil, reject("INCOME_CAPTURE_CAPACITY_OR_BOUNDS", err)
	}
	return out, raw, nil
}
