package app

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"hash"
)

// Call-local, non-failing writer. It never stores encoder chunks and never
// reports mismatch to the encoder: all fields and later errors must be visited.
type nativeAssetReviewStream struct {
	retained []byte
	sum      hash.Hash
	written  uint64
	mismatch bool
	overflow bool
	complete bool
}

func newNativeAssetReviewStream(retained []byte) *nativeAssetReviewStream {
	if len(retained) == 0 {
		return nil
	}
	return &nativeAssetReviewStream{retained: retained, sum: sha256.New()}
}
func (s *nativeAssetReviewStream) reset() {
	if s.sum == nil {
		s.sum = sha256.New()
	}
	s.sum.Reset()
	s.written, s.mismatch, s.overflow, s.complete = 0, false, false, false
}
func (s *nativeAssetReviewStream) Write(p []byte) (int, error) {
	n := len(p)
	if s.written < uint64(len(s.retained)) {
		available := uint64(len(s.retained)) - s.written
		count := uint64(n)
		if count > available {
			count = available
			s.mismatch = true
		}
		if !bytes.Equal(p[:int(count)], s.retained[int(s.written):int(s.written+count)]) {
			s.mismatch = true
		}
	} else if n != 0 {
		s.mismatch = true
	}
	_, _ = s.sum.Write(p) // SHA256.Write always consumes all p without error.
	if ^uint64(0)-s.written < uint64(n) {
		s.overflow, s.mismatch, s.written = true, true, ^uint64(0)
	} else {
		s.written += uint64(n)
	}
	return n, nil
}
func (s *nativeAssetReviewStream) matches() bool {
	return s != nil && s.complete && !s.mismatch && !s.overflow && s.written == uint64(len(s.retained))
}
func nativeAssetStreamReviewHash(preview NativeAssetPreview, stream *nativeAssetReviewStream) (string, error) {
	if stream == nil || len(stream.retained) == 0 {
		_, hash, err := nativeAssetReviewBody(preview)
		return hash, err
	}
	preview.ReviewedHash = ""
	stream.reset()
	if err := nativeAssetMarshalZeroReviewV1(stream, preview); err != nil {
		// Prefix bytes may have reached this private sink. None is a proof or
		// published digest: preserve Marshal's nil-raw hash and original error.
		stream.sum.Reset()
		return Hash(nil), err
	}
	stream.complete = true
	return hex.EncodeToString(stream.sum.Sum(nil)), nil
}
