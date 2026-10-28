//go:build !goexperiment.jsonv2

package app

import "io"

const nativeAssetStreamReviewAvailable = false

func nativeAssetMarshalZeroReviewV1(writer io.Writer, zero NativeAssetPreview) error {
	raw, err := encode(zero)
	if err != nil {
		return err
	}
	n, err := writer.Write(raw)
	if n != len(raw) && err == nil {
		return io.ErrShortWrite
	}
	return err
}
