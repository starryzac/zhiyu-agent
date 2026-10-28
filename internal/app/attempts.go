package app

import "sync/atomic"

var verifyIncomeOperationsAttempts, captureNativeIncomeAttempts, loadTemplateSnapshotAttempts, collectForecastHistoryAttempts atomic.Uint64

type FunctionAttempts struct {
	VerifyIncomeOperations uint64
	CaptureNativeIncome    uint64
	LoadTemplateSnapshot   uint64
	CollectForecastHistory uint64
}

// FunctionAttemptSnapshot reads process-local exact function entries, including
// early failures. Each field is loaded separately. These are not row counts,
// successful work counts, or coverage of every history verification function.
// No reset is provided and the values never control application behavior.
func FunctionAttemptSnapshot() FunctionAttempts {
	return FunctionAttempts{
		VerifyIncomeOperations: verifyIncomeOperationsAttempts.Load(),
		CaptureNativeIncome:    captureNativeIncomeAttempts.Load(),
		LoadTemplateSnapshot:   loadTemplateSnapshotAttempts.Load(),
		CollectForecastHistory: collectForecastHistoryAttempts.Load(),
	}
}
