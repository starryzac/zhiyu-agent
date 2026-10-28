//go:build !goexperiment.jsonv2

package app

import (
	"io"

	planning "zhiyu.local/zhiyu-go/internal/planning/domain"
)

const nativeAssetForecastKeyStreamAvailable = false

func nativeAssetMarshalForecastInputV1(writer io.Writer, input planning.ForecastInput) error {
	raw, err := encode(input)
	if err != nil {
		return err
	}
	n, err := writer.Write(raw)
	if n != len(raw) && err == nil {
		return io.ErrShortWrite
	}
	return err
}
