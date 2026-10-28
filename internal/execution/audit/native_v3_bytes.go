package executionaudit

import (
	"bytes"
	"compress/gzip"
	"encoding/hex"
	"fmt"
	"io"

	evidence "zhiyu.local/zhiyu-go/internal/audit"
)

const NativeMaximumRawRowBytesV3 = 16 << 20
const NativeMaximumRawCaptureBytesV3 = 128 << 20

// gzip preserves exact source bytes while avoiding the fourfold expansion of
// bytea JSON followed by canonical hex. It is an explicit new-v3 encoding;
// neither legacy canonical bytes nor their limits/validators are changed.
func nativeEncodeBytesV3(raw []byte) (string, error) {
	if len(raw) == 0 || len(raw) > NativeMaximumRawRowBytesV3 {
		return "", fmt.Errorf("%w: native raw source capacity", evidence.ErrIncomplete)
	}
	var compressed bytes.Buffer
	writer := gzip.NewWriter(&compressed)
	if _, err := writer.Write(raw); err != nil {
		return "", err
	}
	if err := writer.Close(); err != nil {
		return "", err
	}
	if compressed.Len()*2 > evidence.MaxCanonicalBytes-8192 {
		return "", fmt.Errorf("%w: native compressed member capacity", evidence.ErrIncomplete)
	}
	return hex.EncodeToString(compressed.Bytes()), nil
}

func nativeDecodeBytesV3(encoded, digest, encoding string, size int64) ([]byte, error) {
	if encoding != "GZIP" {
		return nil, fmt.Errorf("%w: native raw encoding", evidence.ErrUnsupportedVersion)
	}
	if size < 1 || size > NativeMaximumRawRowBytesV3 || len(encoded) > evidence.MaxCanonicalBytes {
		return nil, fmt.Errorf("%w: native raw source capacity", evidence.ErrIncomplete)
	}
	compressed, err := hex.DecodeString(encoded)
	if err != nil {
		return nil, businessInvalid("native compressed bytes")
	}
	input := bytes.NewReader(compressed)
	reader, err := gzip.NewReader(input)
	if err != nil {
		return nil, businessInvalid("native compressed stream")
	}
	reader.Multistream(false)
	raw, err := io.ReadAll(io.LimitReader(reader, size+1))
	closed := reader.Close()
	if err != nil || closed != nil || int64(len(raw)) != size || input.Len() != 0 || nakedHash(raw) != digest {
		return nil, businessInvalid("native compressed stream exact length/digest")
	}
	return raw, nil
}
