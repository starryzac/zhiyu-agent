package app

import (
	"bytes"
	"context"
	"encoding/json"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"zhiyu.local/zhiyu-go/internal/audit"
	"zhiyu.local/zhiyu-go/internal/execution/bankv2"
	funds "zhiyu.local/zhiyu-go/internal/funds/domain"
	planning "zhiyu.local/zhiyu-go/internal/planning/domain"
	policy "zhiyu.local/zhiyu-go/internal/policy/domain"
)

const MaxNativeActionPreviewBytes = 8 << 20

// Embed this exact header in a family-specific immutable preview. The raw
// original remains the family's contract; this envelope creates no authority.
type NativeActionPreviewHeader struct {
	ID            funds.ID                  `json:"id"`
	Scope         policy.TemplateOwnerScope `json:"scope"`
	SessionID     funds.ID                  `json:"session_id"`
	Kind          bankv2.Kind               `json:"kind"`
	EffectHash    string                    `json:"effect_hash"`
	Dependencies  planning.DependencyVector `json:"dependencies"`
	SourceHash    string                    `json:"source_hash"`
	InventoryHash string                    `json:"inventory_hash"`
	CreatedAt     time.Time                 `json:"created_at"`
	ExpiresAt     time.Time                 `json:"expires_at"`
	BankAuthority bool                      `json:"bank_authority"`
}
type nativeActionPreviewWriter interface {
	queryRow
	Exec(context.Context, string, ...any) (pgconn.CommandTag, error)
}

func nativeActionKind(kind bankv2.Kind) bool {
	switch kind {
	case bankv2.Purchase, bankv2.Redeem, bankv2.Mature, bankv2.Payment, bankv2.MoveGoal:
		return true
	}
	return false
}
func nativeActionHash(value string) bool {
	if len(value) != 64 {
		return false
	}
	for _, c := range value {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}
func validateNativeActionPreview(header NativeActionPreviewHeader, original []byte) error {
	if header.ID == (funds.ID{}) || header.Scope.EnvironmentID == (funds.ID{}) || header.Scope.UserID == (funds.ID{}) || header.SessionID == (funds.ID{}) || !nativeActionKind(header.Kind) || header.Dependencies.Validate() != nil || header.BankAuthority || !nativeActionHash(header.EffectHash) || !nativeActionHash(header.SourceHash) || !nativeActionHash(header.InventoryHash) || header.CreatedAt.IsZero() || !header.ExpiresAt.After(header.CreatedAt) || header.ExpiresAt.After(header.CreatedAt.Add(2*time.Minute)) || len(original) == 0 || len(original) > MaxNativeActionPreviewBytes {
		return reject("INVALID_NATIVE_ACTION_PREVIEW", nil)
	}
	// The fixed header schema supplies keys without encoding its values early.
	// Strict original parsing must still precede encode(header), including on
	// a bad original plus an unencodable header time.
	raw, e := audit.ParseRawObjectFields(original,
		"id", "scope", "session_id", "kind", "effect_hash", "dependencies",
		"source_hash", "inventory_hash", "created_at", "expires_at", "bank_authority",
	)
	if e != nil {
		return reject("INVALID_NATIVE_ACTION_PREVIEW", e)
	}
	headRaw, e := encode(header)
	if e != nil {
		return e
	}
	expected, e := audit.ParseRawObject(headRaw)
	if e != nil {
		return e
	}
	// Compare nested values too: extra scope/dependency members are not silently
	// erased by decoding the common subset of a family-specific original.
	for key, value := range expected {
		actual, present := raw[key]
		left, _ := json.Marshal(value)
		right, _ := json.Marshal(actual)
		if !present || !bytes.Equal(left, right) {
			return reject("INVALID_NATIVE_ACTION_PREVIEW", nil)
		}
	}
	return nil
}

// Save requires a real current USER session. Only a family-specific preview
// implementation may construct this header/raw pair; it is not an HTTP route.
// Callers may pass their transaction or the scoped application pool.
func (s *Service) saveNativeActionPreview(ctx context.Context, q nativeActionPreviewWriter, p Principal, header NativeActionPreviewHeader, original []byte) error {
	if e := s.human(ctx, q, p); e != nil {
		return e
	}
	if header.Scope != (policy.TemplateOwnerScope{EnvironmentID: p.EnvironmentID, UserID: p.UserID}) || header.SessionID != p.SessionID {
		return reject("FORBIDDEN", nil)
	}
	if e := validateNativeActionPreview(header, original); e != nil {
		return e
	}
	deps, e := encode(header.Dependencies)
	if e != nil {
		return e
	}
	execute := q.Exec
	if pool, ok := q.(*pgxpool.Pool); ok {
		if pool != s.Pool {
			return reject("FORBIDDEN", nil)
		}
		execute = s.writerExec
	}
	_, e = execute(ctx, `INSERT INTO native_action_previews(environment_id,user_id,id,session_id,kind,original,original_hash,effect_hash,dependencies,dependencies_original,dependencies_hash,source_hash,inventory_hash,created_at,expires_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,convert_from($9::bytea,'UTF8')::jsonb,$9::bytea,$10,$11,$12,$13,$14)`, p.EnvironmentID.String(), p.UserID.String(), header.ID.String(), header.SessionID.String(), string(header.Kind), original, Hash(original), header.EffectHash, deps, Hash(deps), header.SourceHash, header.InventoryHash, header.CreatedAt, header.ExpiresAt)
	return e
}

// Historical/system reads preserve the exact bytes and do not require that an
// old preview remain current or unexpired. New admission must check that in T1.
// The family must still strictly decode its protocol and replay its economics.
func loadNativeActionPreview(ctx context.Context, q queryRow, p Principal, kind bankv2.Kind, id funds.ID) (NativeActionPreviewHeader, []byte, error) {
	header := NativeActionPreviewHeader{ID: id, Scope: policy.TemplateOwnerScope{EnvironmentID: p.EnvironmentID, UserID: p.UserID}, Kind: kind}
	if !nativeActionKind(kind) || id == (funds.ID{}) {
		return header, nil, reject("NOT_FOUND", nil)
	}
	var raw, deps []byte
	var hash, dh, session string
	e := q.QueryRow(ctx, `SELECT session_id::text,original,original_hash::text,effect_hash::text,dependencies_original,dependencies_hash::text,source_hash::text,inventory_hash::text,created_at,expires_at FROM native_action_previews WHERE environment_id=$1 AND user_id=$2 AND kind=$3 AND id=$4`, p.EnvironmentID.String(), p.UserID.String(), string(kind), id.String()).Scan(&session, &raw, &hash, &header.EffectHash, &deps, &dh, &header.SourceHash, &header.InventoryHash, &header.CreatedAt, &header.ExpiresAt)
	if e != nil {
		return header, nil, reject("NOT_FOUND", e)
	}
	header.SessionID, e = funds.ParseID(session)
	if e != nil || Hash(raw) != hash || Hash(deps) != dh || auditJSON(deps, &header.Dependencies) != nil {
		return header, nil, reject("EVIDENCE_INVALID", e)
	}
	// pgx may return timestamptz in the process's local timezone. Compare the
	// actual instants, then retain the original JSON representation for hashing.
	var originalHeader NativeActionPreviewHeader
	if json.Unmarshal(raw, &originalHeader) != nil || !originalHeader.CreatedAt.Equal(header.CreatedAt) || !originalHeader.ExpiresAt.Equal(header.ExpiresAt) {
		return header, nil, reject("EVIDENCE_INVALID", nil)
	}
	header.CreatedAt, header.ExpiresAt = originalHeader.CreatedAt, originalHeader.ExpiresAt
	if e = validateNativeActionPreview(header, raw); e != nil {
		return header, nil, reject("EVIDENCE_INVALID", e)
	}
	return header, append([]byte(nil), raw...), nil
}
