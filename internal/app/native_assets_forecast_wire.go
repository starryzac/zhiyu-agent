package app

import (
	"reflect"
	"time"

	planning "zhiyu.local/zhiyu-go/internal/planning/domain"
)

// This is only a sufficient condition for the existing RFC3339Nano wire value.
// Location names and monotonic clocks are not encoded. A bad/unknown boundary
// is a miss, never a new error or a reason to alter either original timestamp.
func nativeAssetForecastTimeFastEqual(a, b time.Time) bool {
	if a.Year() < 0 || a.Year() > 9999 || b.Year() < 0 || b.Year() > 9999 {
		return false
	}
	_, leftOffset := a.Zone()
	_, rightOffset := b.Zone()
	if leftOffset <= -24*60*60 || leftOffset >= 24*60*60 || rightOffset <= -24*60*60 || rightOffset >= 24*60*60 {
		return false
	}
	return a.Unix() == b.Unix() && a.Nanosecond() == b.Nanosecond() && leftOffset == rightOffset
}

func nativeAssetForecastResultFastEqual(a, b planning.ForecastResult) bool {
	if !nativeAssetForecastTimeFastEqual(a.AsOf, b.AsOf) || (a.Points == nil) != (b.Points == nil) || len(a.Points) != len(b.Points) {
		return false
	}
	for i, left := range a.Points {
		right := b.Points[i]
		if !nativeAssetForecastTimeFastEqual(left.At, right.At) {
			return false
		}
		left.At, right.At = time.Time{}, time.Time{}
		// Every other point field participates automatically. A future
		// non-comparable field makes this code fail to compile, not disappear.
		if left != right {
			return false
		}
	}
	// These are value copies; their slice elements and originals are untouched.
	// All remaining current and future result fields participate in DeepEqual.
	a.AsOf, b.AsOf = time.Time{}, time.Time{}
	a.Points, b.Points = nil, nil
	return reflect.DeepEqual(a, b)
}

func nativeAssetForecastResultsMatch(before, storedBefore, after, storedAfter planning.ForecastResult) bool {
	if nativeAssetForecastResultFastEqual(before, storedBefore) && nativeAssetForecastResultFastEqual(after, storedAfter) {
		return true
	}
	// Preserve all four original encodes, their order and ignored-error/nil
	// comparison behavior on every miss. Wire equality can be less strict.
	a, _ := encode(before)
	b, _ := encode(storedBefore)
	c, _ := encode(after)
	d, _ := encode(storedAfter)
	return string(a) == string(b) && string(c) == string(d)
}
