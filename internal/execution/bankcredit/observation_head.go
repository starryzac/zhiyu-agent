package bankcredit

import "time"

// ObservationHead is a change hint for daemon negative scheduling only. It is
// not financial evidence, permission, an independent Result, or a new balance.
const ObservationHeadProtocol = "zhiyu-bank-observation-head-v1"
const ObservationHeadMaxRows = 10000
const ObservationHeadMaxBytes = 4 << 20
const ObservationHeadMaxRowBytes = 16 << 10

type ObservationHead struct {
	Protocol      string    `json:"protocol"`
	Namespace     string    `json:"namespace"`
	UserID        string    `json:"user_id"`
	Instance      string    `json:"instance"`
	SchemaHash    string    `json:"schema_hash"`
	BindingHash   string    `json:"binding_hash"`
	Digest        string    `json:"digest"`
	CapturedAt    time.Time `json:"captured_at"`
	Rows          int       `json:"rows"`
	MetadataBytes int       `json:"metadata_bytes"`
	RawBytes      int64     `json:"raw_bytes"`
}

func (h ObservationHead) Validate() error {
	if h.Protocol != ObservationHeadProtocol || !Scope(h.Namespace, h.UserID) || !hashValid(h.Instance) || !hashValid(h.SchemaHash) || !hashValid(h.BindingHash) || !hashValid(h.Digest) || h.CapturedAt.IsZero() || h.Rows < 0 || h.Rows > ObservationHeadMaxRows || h.MetadataBytes < 0 || h.MetadataBytes > ObservationHeadMaxBytes || h.RawBytes < 0 || h.RawBytes > ObservationHeadMaxBytes {
		return ErrInvalid
	}
	return nil
}

func (h ObservationHead) SameState(other ObservationHead) bool {
	return h.Validate() == nil && other.Validate() == nil && h.Protocol == other.Protocol && h.Namespace == other.Namespace && h.UserID == other.UserID && h.Instance == other.Instance && h.SchemaHash == other.SchemaHash && h.BindingHash == other.BindingHash && h.Digest == other.Digest && h.Rows == other.Rows && h.MetadataBytes == other.MetadataBytes && h.RawBytes == other.RawBytes
}
