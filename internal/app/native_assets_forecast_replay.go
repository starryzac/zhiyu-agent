package app

import (
	"bytes"
	"encoding/json"
	"reflect"
	"slices"

	planning "zhiyu.local/zhiyu-go/internal/planning/domain"
)

type nativeAssetForecast func(planning.ForecastInput) (planning.ForecastResult, error)

type nativeAssetForecastReplayEntry struct {
	original []byte
	input    planning.ForecastInput
	result   planning.ForecastResult
}

// One retained-preview loader owns this two-entry replay scope. It never
// stores a failed calculation, a preview, a database read or authority.
type nativeAssetForecastReplay struct {
	calculate nativeAssetForecast
	entries   []nativeAssetForecastReplayEntry
}

func newNativeAssetForecastReplay(calculate nativeAssetForecast) *nativeAssetForecastReplay {
	return &nativeAssetForecastReplay{calculate: calculate}
}

func cloneNativeAssetForecastResult(result planning.ForecastResult) planning.ForecastResult {
	result.Points = slices.Clone(result.Points)
	result.Obligations = slices.Clone(result.Obligations)
	result.ExternalLiabilities = slices.Clone(result.ExternalLiabilities)
	result.Reasons = slices.Clone(result.Reasons)
	return result
}

// This call-local sink only compares the complete current encoding. It never
// retains encoder chunks, writes a key or reports a mismatch to the encoder.
type nativeAssetForecastKeyPair struct {
	keys     [2][]byte
	written  uint64
	mismatch [2]bool
	overflow bool
	complete bool
}

func (pair *nativeAssetForecastKeyPair) Write(p []byte) (int, error) {
	n := len(p)
	for index, key := range pair.keys {
		if pair.written < uint64(len(key)) {
			available := uint64(len(key)) - pair.written
			count := uint64(n)
			if count > available {
				count = available
				pair.mismatch[index] = true
			}
			if !bytes.Equal(p[:int(count)], key[int(pair.written):int(pair.written+count)]) {
				pair.mismatch[index] = true
			}
		} else if n != 0 {
			pair.mismatch[index] = true
		}
	}
	if ^uint64(0)-pair.written < uint64(n) {
		pair.overflow, pair.written = true, ^uint64(0)
	} else {
		pair.written += uint64(n)
	}
	return n, nil
}

func (pair *nativeAssetForecastKeyPair) matches() (matches [2]bool) {
	for index, key := range pair.keys {
		matches[index] = pair.complete && !pair.overflow && !pair.mismatch[index] && pair.written == uint64(len(key))
	}
	return matches
}

func nativeAssetForecastKeysMatch(input planning.ForecastInput, keys [2][]byte) ([2]bool, error) {
	pair := nativeAssetForecastKeyPair{keys: keys}
	if err := nativeAssetMarshalForecastInputV1(&pair, input); err != nil {
		return [2]bool{}, err
	}
	pair.complete = true
	return pair.matches(), nil
}

func (replay *nativeAssetForecastReplay) evaluate(input planning.ForecastInput) (planning.ForecastResult, error) {
	if nativeAssetForecastKeyStreamAvailable && len(replay.entries) == 2 && len(replay.entries[0].original) != 0 && len(replay.entries[1].original) != 0 {
		matched, encodingErr := nativeAssetForecastKeysMatch(input, [2][]byte{replay.entries[0].original, replay.entries[1].original})
		if encodingErr == nil {
			for index, entry := range replay.entries {
				if matched[index] && reflect.DeepEqual(input, entry.input) {
					return cloneNativeAssetForecastResult(entry.result), nil
				}
			}
		}
		// Preserve the old full-capacity miss/error semantics: encoding errors
		// only prevent hits; the calculator's partial result/error is returned.
		return replay.calculate(input)
	}
	original, encodingErr := encode(input)
	if encodingErr == nil {
		for _, entry := range replay.entries {
			// omitempty can serialize nil and empty identically. Complete Go-value
			// equality is a second gate; normalized InputHash is never a key.
			if bytes.Equal(original, entry.original) && reflect.DeepEqual(input, entry.input) {
				return cloneNativeAssetForecastResult(entry.result), nil
			}
		}
	}
	result, err := replay.calculate(input)
	if err != nil || encodingErr != nil || len(replay.entries) >= 2 {
		return result, err
	}
	// original is already an owned Marshal result. Decode that same complete
	// value into an independent graph; retain the post-calculate typed guard.
	var copy planning.ForecastInput
	cloneErr := json.Unmarshal(original, &copy)
	// JSON clone may lose nil/empty, timezone or monotonic-clock details.
	// Such inputs still get the original calculation; they are simply not stored.
	if cloneErr == nil && reflect.DeepEqual(input, copy) {
		replay.entries = append(replay.entries, nativeAssetForecastReplayEntry{
			original: original,
			input:    copy,
			result:   cloneNativeAssetForecastResult(result),
		})
	}
	return result, nil
}
