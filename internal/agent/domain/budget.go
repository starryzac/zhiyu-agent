package domain

import "time"

type Limits struct {
	Timeout          time.Duration
	MaxProviderCalls int
	MaxToolCalls     int
	MaxInputBytes    int
	MaxOutputTokens  int64
	MaxTotalTokens   int64
	MaxCostMicros    int64
	// Operator-owned pricing in millionths of the configured billing currency
	// per million tokens. Real adapters must supply verified provider prices.
	InputPriceMicrosPerMillion  int64
	OutputPriceMicrosPerMillion int64
}

func DefaultLimits() Limits {
	return Limits{Timeout: 5 * time.Second, MaxProviderCalls: 3, MaxToolCalls: 3, MaxInputBytes: 16384, MaxOutputTokens: 1024, MaxTotalTokens: 65536, MaxCostMicros: 100000}
}
func (l Limits) Validate() error {
	if l.Timeout <= 0 || l.Timeout > 30*time.Second || l.MaxProviderCalls < 1 || l.MaxProviderCalls > 8 || l.MaxToolCalls < 1 || l.MaxToolCalls > 8 || l.MaxInputBytes < 256 || l.MaxInputBytes > 65536 || l.MaxOutputTokens < 1 || l.MaxOutputTokens > 4096 || l.MaxTotalTokens < 1 || l.MaxTotalTokens > 1000000 || l.MaxCostMicros < 1 || l.MaxCostMicros > 1000000000 || l.InputPriceMicrosPerMillion < 0 || l.InputPriceMicrosPerMillion > 1000000000000 || l.OutputPriceMicrosPerMillion < 0 || l.OutputPriceMicrosPerMillion > 1000000000000 {
		return ErrBudget
	}
	return nil
}

type Budget struct {
	ProviderCalls      int   `json:"provider_calls"`
	ToolCalls          int   `json:"tool_calls"`
	ReservedTokens     int64 `json:"reserved_tokens"`
	ReservedCostMicros int64 `json:"reserved_cost_micros"`
}
type Reservation struct {
	InputTokens  int64
	OutputTokens int64
}

func ceilingCost(tokens, price int64) int64 { return (tokens*price + 999999) / 1000000 }

// Reserve charges worst-case input/output before calling a provider. Charges
// are never refunded based on a model's self-reported usage. Byte count plus
// 4096 protocol tokens is a finite reservation contract for an adapter, not a
// tokenizer claim: real transport must reject input outside this same bound.
func (b *Budget) Reserve(l Limits, inputBytes int) (Reservation, error) {
	if l.Validate() != nil || l.InputPriceMicrosPerMillion == 0 || l.OutputPriceMicrosPerMillion == 0 {
		return Reservation{}, budgetFailure("RESERVE_CONFIGURATION")
	}
	if inputBytes < 0 || inputBytes > l.MaxInputBytes {
		return Reservation{}, budgetFailure("RESERVE_INPUT_BYTES")
	}
	if b.ProviderCalls >= l.MaxProviderCalls {
		return Reservation{}, budgetFailure("RESERVE_CALLS")
	}
	r := Reservation{int64(inputBytes) + 4096, l.MaxOutputTokens}
	tokens := r.InputTokens + r.OutputTokens
	cost := ceilingCost(r.InputTokens, l.InputPriceMicrosPerMillion) + ceilingCost(r.OutputTokens, l.OutputPriceMicrosPerMillion)
	if tokens > l.MaxTotalTokens-b.ReservedTokens {
		return Reservation{}, budgetFailure("RESERVE_TOKENS")
	}
	if cost > l.MaxCostMicros-b.ReservedCostMicros {
		return Reservation{}, budgetFailure("RESERVE_COST")
	}
	b.ProviderCalls++
	b.ReservedTokens += tokens
	b.ReservedCostMicros += cost
	return r, nil
}
func (b *Budget) Tool(l Limits) error {
	if b.ToolCalls >= l.MaxToolCalls {
		return budgetFailure("TOOL_CALLS")
	}
	b.ToolCalls++
	return nil
}
func (r Reservation) CheckUsage(input, output int64) error {
	if input < 0 || output < 0 || input > r.InputTokens || output > r.OutputTokens {
		return budgetFailure("REPORTED_USAGE")
	}
	return nil
}
