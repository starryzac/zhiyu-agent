// Package domain contains deterministic funds rules. It performs no I/O and
// takes every business instant explicitly from its caller.
package domain

import (
	"bytes"
	"errors"
	"fmt"
	"math/big"
	"sort"
	"strconv"
)

// MaxMoneyCents is the explicit Go v1 capacity (90 trillion yuan). Historical
// values above this limit require a migration decision; they are never clipped.
const MaxMoneyCents int64 = 9_000_000_000_000_000

var (
	ErrMoneyRange    = errors.New("money outside supported nonnegative range")
	ErrMoneyEncoding = errors.New("money must be a canonical decimal cents string")
	ErrRatio         = errors.New("ratio requires a nonnegative numerator and positive denominator")
	ErrRounding      = errors.New("unsupported rounding mode")
)

type Currency string

const CNY Currency = "CNY"

func (c Currency) Validate() error {
	if c != CNY {
		return fmt.Errorf("unsupported currency %q", c)
	}
	return nil
}

// Money stores nonnegative integer cents. Its zero value is a valid zero.
// Signed posting deltas must carry a separate debit/credit direction.
type Money struct{ cents int64 }

func NewMoney(cents int64) (Money, error) {
	if cents < 0 || cents > MaxMoneyCents {
		return Money{}, ErrMoneyRange
	}
	return Money{cents: cents}, nil
}

func (m Money) Cents() int64   { return m.cents }
func (m Money) IsZero() bool   { return m.cents == 0 }
func (m Money) String() string { return strconv.FormatInt(m.cents, 10) }

func ParseMoney(s string) (Money, error) {
	if s == "" || len(s) > 16 || (len(s) > 1 && s[0] == '0') {
		return Money{}, ErrMoneyEncoding
	}
	for _, c := range s {
		if c < '0' || c > '9' {
			return Money{}, ErrMoneyEncoding
		}
	}
	n, err := strconv.ParseInt(s, 10, 64)
	if err != nil {
		return Money{}, ErrMoneyRange
	}
	return NewMoney(n)
}

// MarshalJSON represents cents, not yuan, as a decimal string.
func (m Money) MarshalJSON() ([]byte, error) {
	out := make([]byte, 0, 22)
	out = append(out, '"')
	out = strconv.AppendInt(out, m.cents, 10)
	out = append(out, '"')
	return out, nil
}

func (m *Money) UnmarshalJSON(data []byte) error {
	// Reject numbers, null, signs, fractions, exponents and escaped digits.
	// A rejected decode leaves the receiver unchanged.
	data = bytes.TrimSpace(data)
	if len(data) < 3 || data[0] != '"' || data[len(data)-1] != '"' {
		return ErrMoneyEncoding
	}
	parsed, err := ParseMoney(string(data[1 : len(data)-1]))
	if err != nil {
		return err
	}
	*m = parsed
	return nil
}

func (m Money) Add(other Money) (Money, error) {
	if other.cents > MaxMoneyCents-m.cents {
		return Money{}, ErrMoneyRange
	}
	return NewMoney(m.cents + other.cents)
}

func (m Money) Sub(other Money) (Money, error) {
	if other.cents > m.cents {
		return Money{}, ErrMoneyRange
	}
	return NewMoney(m.cents - other.cents)
}

func SumMoney(values ...Money) (Money, error) {
	var total Money
	for _, v := range values {
		var err error
		total, err = total.Add(v)
		if err != nil {
			return Money{}, err
		}
	}
	return total, nil
}

type Rounding uint8

const (
	RoundDown Rounding = iota + 1
	RoundUp
	RoundHalfEven
)

// MulRatio computes m*numerator/denominator without floating point or int64
// intermediate overflow. Rounding is mandatory and the final value is bounded.
func (m Money) MulRatio(numerator, denominator int64, rounding Rounding) (Money, error) {
	if numerator < 0 || denominator <= 0 {
		return Money{}, ErrRatio
	}
	if rounding != RoundDown && rounding != RoundUp && rounding != RoundHalfEven {
		return Money{}, ErrRounding
	}
	product := new(big.Int).Mul(big.NewInt(m.cents), big.NewInt(numerator))
	den := big.NewInt(denominator)
	quotient, remainder := new(big.Int), new(big.Int)
	quotient.QuoRem(product, den, remainder)
	increment := false
	if remainder.Sign() != 0 {
		switch rounding {
		case RoundUp:
			increment = true
		case RoundHalfEven:
			comparison := new(big.Int).Lsh(remainder, 1).Cmp(den)
			increment = comparison > 0 || (comparison == 0 && quotient.Bit(0) == 1)
		}
	}
	if increment {
		quotient.Add(quotient, big.NewInt(1))
	}
	if !quotient.IsInt64() {
		return Money{}, ErrMoneyRange
	}
	return NewMoney(quotient.Int64())
}

// Apportion uses the largest-remainder rule so every cent is assigned exactly
// once. Equal fractional remainders go to the earlier input index. Weights are
// nonnegative, at least one is positive, and their sum may exceed int64.
func (m Money) Apportion(weights []int64) ([]Money, error) {
	if len(weights) == 0 || len(weights) > MaxLedgerItems {
		return nil, ErrRatio
	}
	totalWeight := new(big.Int)
	for _, weight := range weights {
		if weight < 0 {
			return nil, ErrRatio
		}
		totalWeight.Add(totalWeight, big.NewInt(weight))
	}
	if totalWeight.Sign() == 0 {
		return nil, ErrRatio
	}
	shares := make([]Money, len(weights))
	remainders := make([]*big.Int, len(weights))
	indices := make([]int, len(weights))
	var assigned Money
	for i, weight := range weights {
		product := new(big.Int).Mul(big.NewInt(m.cents), big.NewInt(weight))
		quotient, remainder := new(big.Int), new(big.Int)
		quotient.QuoRem(product, totalWeight, remainder)
		// Each floor share and their total are bounded by m by construction.
		var err error
		shares[i], err = NewMoney(quotient.Int64())
		if err != nil {
			return nil, err
		}
		assigned, err = assigned.Add(shares[i])
		if err != nil {
			return nil, err
		}
		remainders[i] = remainder
		indices[i] = i
	}
	sort.SliceStable(indices, func(i, j int) bool { return remainders[indices[i]].Cmp(remainders[indices[j]]) > 0 })
	remaining, err := m.Sub(assigned)
	if err != nil {
		return nil, err
	}
	for i := int64(0); i < remaining.Cents(); i++ {
		index := indices[i]
		shares[index], err = shares[index].Add(Money{cents: 1})
		if err != nil {
			return nil, err
		}
	}
	return shares, nil
}
