//go:build goexperiment.jsonv2

package app

import (
	"encoding/json"
	jsonv2 "encoding/json/v2"
	"io"
)

const nativeAssetStreamReviewAvailable = true

func nativeAssetMarshalZeroReviewV1(writer io.Writer, zero NativeAssetPreview) error {
	// Same by-value input, complete v1 options, legacy errors and no newline.
	return jsonv2.MarshalWrite(writer, zero, json.DefaultOptionsV1())
}
