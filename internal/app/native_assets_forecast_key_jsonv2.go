//go:build goexperiment.jsonv2

package app

import (
	"encoding/json"
	jsonv2 "encoding/json/v2"
	"io"

	planning "zhiyu.local/zhiyu-go/internal/planning/domain"
)

const nativeAssetForecastKeyStreamAvailable = true

func nativeAssetMarshalForecastInputV1(writer io.Writer, input planning.ForecastInput) error {
	// By-value, full v1 defaults, identical legacy errors, and no newline.
	return jsonv2.MarshalWrite(writer, input, json.DefaultOptionsV1())
}
