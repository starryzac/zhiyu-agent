package domain

import "sync/atomic"

// These process-local counts observe exact function entries, including rejected
// inputs. They are never consulted by planning and do not identify a user or
// distinguish an original calculation from a replay. There is no reset API.
var planSingleGoalAttempts, solveJointAttempts, forecast365Attempts atomic.Uint64

type FunctionAttempts struct {
	PlanSingleGoal uint64
	SolveJoint     uint64
	Forecast365    uint64
}

// FunctionAttemptSnapshot reads each monotonic counter separately. A snapshot
// is not a cross-counter transaction and does not establish an idle window.
func FunctionAttemptSnapshot() FunctionAttempts {
	return FunctionAttempts{
		PlanSingleGoal: planSingleGoalAttempts.Load(),
		SolveJoint:     solveJointAttempts.Load(),
		Forecast365:    forecast365Attempts.Load(),
	}
}
