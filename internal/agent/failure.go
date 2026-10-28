package agent

import (
	"context"
	"errors"
	"strconv"

	"zhiyu.local/zhiyu-go/internal/agent/domain"
)

var errUnavailable = errors.New("AGENT_UNAVAILABLE")

// TurnFailure retains only finite labels, sentinels and validated counters.
// No original error, raw reply, SQL, configuration, IDs or key is retained.
type TurnFailure struct {
	stage  string
	cause  error
	budget domain.Budget
	usage  ProviderUsage
}

func (e *TurnFailure) Error() string    { return e.cause.Error() }
func (e *TurnFailure) String() string   { return e.Error() }
func (e *TurnFailure) GoString() string { return e.Error() }
func (e *TurnFailure) Unwrap() error    { return e.cause }

func safeCause(err error) error {
	for _, cause := range []error{domain.ErrInvalid, domain.ErrTool, domain.ErrReference, domain.ErrStale, domain.ErrBudget, ErrProviderNotConfigured, ErrProvider, context.DeadlineExceeded, context.Canceled} {
		if errors.Is(err, cause) {
			return cause
		}
	}
	return errUnavailable
}

func safeStage(stage string) string {
	switch stage {
	case "BODY_DECODE", "TURN_DECODE", "SNAPSHOT_READ", "SNAPSHOT_VALIDATE", "INPUT_ENCODE", "RESERVE", "PROVIDER_CONFIGURATION", "PROVIDER", "PROVIDER_REPLY_SCHEMA", "PROVIDER_USAGE", "PROVIDER_ENVELOPE", "PROVIDER_HTTP_STATUS", "PROVIDER_RESPONSE", "USAGE", "REPLY_DECODE", "MODEL_TOOL_SCOPE", "DONE_WITHOUT_OBSERVATION", "REPEAT_TOOL", "TOOL_REFERENCE", "TOOL_LIMIT", "OBSERVE", "OBSERVATION_SIZE", "CONTEXT", "FRESH_SNAPSHOT", "FRESH_REFERENCES", "FINAL_SIZE":
		return stage
	}
	return "UNKNOWN"
}

func turnFailure(stage string, cause error, budget domain.Budget, usage ProviderUsage) error {
	if reason := domain.BudgetFailureReason(cause); reason != "" {
		return &TurnFailure{stage: safeStage(stage), cause: &budgetCause{reason}, budget: budget, usage: usage}
	}
	return &TurnFailure{stage: safeStage(stage), cause: safeCause(cause), budget: budget, usage: usage}
}

type budgetCause struct{ reason string }

func (e *budgetCause) Error() string { return domain.ErrBudget.Error() }
func (e *budgetCause) Unwrap() error { return domain.ErrBudget }

// InvalidTurnFailure labels only a failed closed HTTP-body decode; it never
// receives or retains the invalid request body or parser error.
func InvalidTurnFailure() error {
	return turnFailure("BODY_DECODE", domain.ErrInvalid, domain.Budget{}, ProviderUsage{})
}

// FailureDetails is a new map of bounded labels and actual runtime counters.
// Reserved calls are not a claim that a charged request reached the provider.
// A missing validated reply never becomes zero billed cost.
func FailureDetails(err error) map[string]string {
	var failure *TurnFailure
	if !errors.As(err, &failure) {
		return map[string]string{}
	}
	reason := "REJECTED"
	var budget *budgetCause
	if errors.As(failure.cause, &budget) {
		reason = budget.reason
	}
	usageScope := "PARTIAL_UNKNOWN_ATTEMPTS_NOT_INVOICE"
	if failure.budget.ProviderCalls == 0 {
		usageScope = "NO_PROVIDER_RESERVATIONS"
	} else if failure.usage.ReportedCalls == failure.budget.ProviderCalls {
		usageScope = "VALIDATED_RETURNED_REPLIES_ONLY_NOT_INVOICE"
	}
	return map[string]string{
		"failure_protocol": "zhiyu-agent-failure-v1", "failure_stage": failure.stage, "failure_reason": reason,
		"provider_calls_reserved": strconv.Itoa(failure.budget.ProviderCalls), "tool_calls_consumed": strconv.Itoa(failure.budget.ToolCalls),
		"reserved_tokens": strconv.FormatInt(failure.budget.ReservedTokens, 10), "reserved_cost_micros": strconv.FormatInt(failure.budget.ReservedCostMicros, 10),
		"validated_input_tokens": strconv.FormatInt(failure.usage.InputTokens, 10), "validated_output_tokens": strconv.FormatInt(failure.usage.OutputTokens, 10),
		"validated_reported_calls": strconv.Itoa(failure.usage.ReportedCalls), "usage_scope": usageScope,
	}
}

func providerFailureStage(err error) string {
	var rejection interface{ RejectionReason() string }
	if errors.As(err, &rejection) {
		switch rejection.RejectionReason() {
		case "REPLY_SCHEMA":
			return "PROVIDER_REPLY_SCHEMA"
		case "USAGE", "CACHE":
			return "PROVIDER_USAGE"
		case "ENVELOPE", "CHOICE":
			return "PROVIDER_ENVELOPE"
		case "HTTP_STATUS":
			return "PROVIDER_HTTP_STATUS"
		case "RESPONSE_JSON", "REASONING", "NATIVE_TOOL_CALLS", "MEDIA_TYPE", "RESPONSE_BOUND":
			return "PROVIDER_RESPONSE"
		}
	}
	return "PROVIDER"
}

// The real adapter attests usage only after all envelope/usage/cache checks
// and before a REPLY_SCHEMA rejection. Other failures stay UNKNOWN.
func rejectedReplyUsage(err error, reservation domain.Reservation) (int64, int64, bool) {
	var rejection interface {
		RejectionReason() string
		HTTPStatus() int
		ValidatedUsage() (int64, int64)
	}
	if !errors.As(err, &rejection) || rejection.RejectionReason() != "REPLY_SCHEMA" || rejection.HTTPStatus() != 200 {
		return 0, 0, false
	}
	input, output := rejection.ValidatedUsage()
	if input < 1 || output < 1 || reservation.CheckUsage(input, output) != nil {
		return 0, 0, false
	}
	return input, output, true
}
