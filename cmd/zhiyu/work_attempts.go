package main

import (
	"log/slog"
	"os"
	"sync"
	"time"

	"zhiyu.local/zhiyu-go/internal/app"
	"zhiyu.local/zhiyu-go/internal/audit"
	planning "zhiyu.local/zhiyu-go/internal/planning/domain"
)

const workAttemptHeartbeatInterval = 5 * time.Second

func writeWorkAttemptSnapshot(logger *slog.Logger, command, phase string, started time.Time) {
	snapshotStarted := time.Since(started).Nanoseconds()
	plans := planning.FunctionAttemptSnapshot()
	application := app.FunctionAttemptSnapshot()
	captured := audit.VerifyCapturedAttemptSnapshot()
	snapshotFinished := time.Since(started).Nanoseconds()
	logger.Info("work_function_attempts",
		"protocol", "zhiyu-function-attempts-v1", "pid", os.Getpid(),
		"command", command, "phase", phase,
		"snapshot_started_uptime_ns", snapshotStarted, "observer_uptime_ns", snapshotFinished,
		slog.Group("attempts",
			slog.Uint64("planning.PlanSingleGoal", plans.PlanSingleGoal),
			slog.Uint64("planning.SolveJoint", plans.SolveJoint),
			slog.Uint64("planning.Forecast365", plans.Forecast365),
			slog.Uint64("audit.VerifyCaptured", captured),
			slog.Uint64("app.verifyIncomeOperations", application.VerifyIncomeOperations),
			slog.Uint64("app.captureNativeIncome", application.CaptureNativeIncome),
			slog.Uint64("app.loadTemplateSnapshot", application.LoadTemplateSnapshot),
			slog.Uint64("app.collectForecastHistory", application.CollectForecastHistory)),
		"scope", "PROCESS_LOCAL_EXACT_FUNCTION_ENTRIES_NOT_ALL_HISTORY_OR_SUCCESSFUL_REPLAY")
}

func runWorkAttemptHeartbeat(logger *slog.Logger, command string, started time.Time, ticks <-chan time.Time, stop <-chan struct{}) {
	for {
		select {
		case <-ticks:
			writeWorkAttemptSnapshot(logger, command, "heartbeat", started)
		case <-stop:
			writeWorkAttemptSnapshot(logger, command, "stopped", started)
			return
		}
	}
}

// This observer owns no business resources and has no error-return hook. Its
// stop record is emitted only after the configured command has returned.
func startWorkAttemptHeartbeat(logger *slog.Logger, command string) func() {
	started := time.Now()
	writeWorkAttemptSnapshot(logger, command, "started", started)
	ticker := time.NewTicker(workAttemptHeartbeatInterval)
	stop, done := make(chan struct{}), make(chan struct{})
	go func() {
		defer close(done)
		defer ticker.Stop()
		runWorkAttemptHeartbeat(logger, command, started, ticker.C, stop)
	}()
	var once sync.Once
	return func() { once.Do(func() { close(stop); <-done }) }
}
