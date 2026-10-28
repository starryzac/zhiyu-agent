package app

import "bytes"

// The immediately preceding successful derive owns these Marshal bytes. The
// collector never retains a preview or database verdict across replay stages.
type nativeAssetReviewCapture struct {
	original     []byte
	reviewedHash string
	stream       *nativeAssetReviewStream // only the closed loader supplies this capability
}

func nativeAssetReviewBody(preview NativeAssetPreview) ([]byte, string, error) {
	preview.ReviewedHash = ""
	raw, err := encode(preview)
	return raw, Hash(raw), err
}

// Public/default capture remains buffered. Only a closed loader capability
// permits a streaming expected-body hash and complete byte comparison.
func finishNativeAssetReview(preview NativeAssetPreview, capture *nativeAssetReviewCapture) (NativeAssetPreview, error) {
	if nativeAssetStreamReviewAvailable && capture != nil && capture.stream != nil && len(capture.stream.retained) != 0 {
		capture.original, capture.reviewedHash = nil, ""
		hash, err := nativeAssetStreamReviewHash(preview, capture.stream)
		preview.ReviewedHash = hash
		if err == nil {
			capture.reviewedHash = hash
		}
		return preview, err
	}
	body, hash, err := nativeAssetReviewBody(preview)
	preview.ReviewedHash = hash
	if err == nil && capture != nil {
		capture.original, capture.reviewedHash = body, hash
	}
	return preview, err
}

// capture must come from the immediately preceding successful derive, with no
// mutation of expected between derivation and this comparison. The retained
// preview is always encoded here; its mutable fields are never cached.
func compareNativeAssetReplayPreview(expected, preview NativeAssetPreview, capture *nativeAssetReviewCapture) error {
	if capture != nil && len(capture.original) != 0 && capture.reviewedHash == expected.ReviewedHash {
		reviewedHash := preview.ReviewedHash
		if nativeAssetStreamReviewAvailable {
			// Fresh current-value encoding only: the owned expected body came
			// from this replay's immediately preceding successful derive.
			stream := newNativeAssetReviewStream(capture.original)
			_, err := nativeAssetStreamReviewHash(preview, stream)
			if err != nil || !stream.matches() || capture.reviewedHash != reviewedHash {
				return reject("EVIDENCE_INVALID", err)
			}
			return nil
		}
		preview.ReviewedHash = ""
		raw, err := encode(preview)
		if err != nil || !bytes.Equal(capture.original, raw) || capture.reviewedHash != reviewedHash {
			return reject("EVIDENCE_INVALID", err)
		}
		return nil
	}
	// Unknown/missing collector bytes retain the complete original comparison
	// and its error order. No digest alone can establish object equality.
	a, err := encode(expected)
	if err != nil {
		return err
	}
	b, err := encode(preview)
	if err != nil || string(a) != string(b) {
		return reject("EVIDENCE_INVALID", err)
	}
	return nil
}
