package app

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	evidence "zhiyu.local/zhiyu-go/internal/audit"
	executionaudit "zhiyu.local/zhiyu-go/internal/execution/audit"
	funds "zhiyu.local/zhiyu-go/internal/funds/domain"
)

// AuditTrustOptions is operator-owned input. Public trust roots are never
// inferred from the audited database, and no private signing key is held here.
type AuditTrustOptions struct {
	HistoryAuthorityProfileHashes []string
	TrustedKeys                   map[string]ed25519.PublicKey
	RequireAnchor                 bool
	SourceManifestSHA256          string
	ConfigSHA256                  string
}

type AuditRequest struct {
	ProtocolVersion string    `json:"protocol_version,omitempty"`
	AnchorID        *funds.ID `json:"anchor_id,omitempty"`
	CaptureRunID    *funds.ID `json:"capture_run_id,omitempty"`
	RequireAnchor   bool      `json:"require_anchor"`
}

type AuditRun struct {
	ID                 funds.ID                      `json:"id"`
	State              string                        `json:"state"`
	Mode               string                        `json:"mode"`
	Request            AuditRequest                  `json:"request"`
	Attempts           int                           `json:"attempts"`
	MaxAttempts        int                           `json:"max_attempts"`
	ClaimGeneration    uint64                        `json:"claim_generation"`
	CaptureArtifactID  *funds.ID                     `json:"capture_artifact_id,omitempty"`
	ResultArtifactID   *funds.ID                     `json:"result_artifact_id,omitempty"`
	VerificationStatus *string                       `json:"verification_status,omitempty"`
	Assurance          *string                       `json:"assurance,omitempty"`
	CreatedAt          time.Time                     `json:"created_at"`
	FinishedAt         *time.Time                    `json:"finished_at,omitempty"`
	LastError          string                        `json:"last_error"`
	Verification       *evidence.CaptureVerification `json:"verification,omitempty"`
}

type AuditArtifact struct {
	ID              funds.ID `json:"id"`
	RunID           funds.ID `json:"run_id"`
	Kind            string   `json:"kind"`
	ProtocolVersion string   `json:"protocol_version"`
	ManifestDigest  string   `json:"manifest_digest"`
	OriginalHash    string   `json:"original_hash"`
	Original        []byte   `json:"original"`
}

type AuditAnchorRequest struct {
	CaptureRunID funds.ID        `json:"capture_run_id"`
	Anchor       evidence.Anchor `json:"anchor"`
}

type AuditAnchor struct {
	ID             funds.ID `json:"id"`
	KeyID          string   `json:"key_id"`
	ManifestDigest string   `json:"manifest_digest"`
}

type auditStoredResult struct {
	ProtocolVersion              string                       `json:"protocol_version"`
	Mode                         string                       `json:"mode"`
	CaptureRunID                 *funds.ID                    `json:"capture_run_id,omitempty"`
	VerifiedAt                   time.Time                    `json:"verified_at"`
	VerifierSourceManifestSHA256 string                       `json:"verifier_source_manifest_sha256"`
	VerifierConfigSHA256         string                       `json:"verifier_config_sha256"`
	Verification                 evidence.CaptureVerification `json:"verification"`
}

func auditMode(in AuditRequest) string {
	if in.CaptureRunID != nil {
		return "REVERIFY_CAPTURE"
	}
	return "CURRENT_USER_SNAPSHOT"
}

func auditDigestOK(value string) bool {
	raw, err := hex.DecodeString(value)
	return err == nil && len(raw) == 32 && strings.ToLower(value) == value
}

func (s *Service) auditConfigured() bool {
	return auditDigestOK(s.AuditTrust.SourceManifestSHA256) && auditDigestOK(s.AuditTrust.ConfigSHA256)
}

func (s *Service) auditHuman(ctx context.Context, p Principal) error {
	env, err := s.environment(ctx, s.Pool, false)
	if err != nil {
		return err
	}
	if err := sameUser(p, env.ID); err != nil {
		return err
	}
	return s.human(ctx, s.Pool, p)
}

// StartAudit accepts a bounded read-only audit request. No funds, grant, bank
// operation or existing captured artifact is changed by creating the task.
func (s *Service) StartAudit(ctx context.Context, p Principal, key string, in AuditRequest) (AuditRun, error) {
	if in.ProtocolVersion != "" && in.ProtocolVersion != executionaudit.NativeAuditProtocolV3 {
		return AuditRun{}, reject("AUDIT_PROTOCOL_UNSUPPORTED", nil)
	}
	if err := validateKey(key); err != nil {
		return AuditRun{}, err
	}
	if err := s.auditHuman(ctx, p); err != nil {
		return AuditRun{}, err
	}
	if !s.auditConfigured() {
		return AuditRun{}, reject("AUDIT_NOT_CONFIGURED", nil)
	}
	if in.AnchorID != nil && (in.CaptureRunID == nil || *in.AnchorID == (funds.ID{})) || in.CaptureRunID != nil && *in.CaptureRunID == (funds.ID{}) {
		return AuditRun{}, reject("AUDIT_CAPTURE_REQUIRED", nil)
	}
	in.RequireAnchor = in.RequireAnchor || s.AuditTrust.RequireAnchor
	if in.CaptureRunID != nil {
		if capture, _, err := s.loadAuditCapture(ctx, p, *in.CaptureRunID); err != nil {
			return AuditRun{}, err
		} else if in.ProtocolVersion != "" && !nativeAuditCaptureIsV3(capture) {
			return AuditRun{}, reject("AUDIT_CAPTURE_PROTOCOL_MISMATCH", nil)
		}
	}
	if in.AnchorID != nil {
		if _, err := s.loadAuditAnchor(ctx, p, *in.AnchorID); err != nil {
			return AuditRun{}, err
		}
	}
	raw, err := encode(in)
	if err != nil {
		return AuditRun{}, err
	}
	tx, err := s.begin(ctx)
	if err != nil {
		return AuditRun{}, err
	}
	defer rollback(ctx, tx)
	env, err := s.environment(ctx, tx, true)
	if err != nil {
		return AuditRun{}, err
	}
	if err = sameUser(p, env.ID); err != nil {
		return AuditRun{}, err
	}
	if _, _, err = lockUser(ctx, tx, p); err != nil {
		return AuditRun{}, err
	}
	if err = s.human(ctx, tx, p); err != nil {
		return AuditRun{}, err
	}
	var existing, existingHash string
	err = tx.QueryRow(ctx, `SELECT id::text,request_hash::text FROM audit_runs WHERE environment_id=$1 AND user_id=$2 AND idempotency_key=$3`, env.ID.String(), p.UserID.String(), key).Scan(&existing, &existingHash)
	if err == nil {
		if existingHash != Hash(raw) {
			return AuditRun{}, reject("IDEMPOTENCY_CONFLICT", nil)
		}
		id, e := funds.ParseID(existing)
		if e != nil {
			return AuditRun{}, e
		}
		return s.loadAudit(ctx, tx, p, id)
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return AuditRun{}, err
	}
	if in.CaptureRunID == nil && in.ProtocolVersion != executionaudit.NativeAuditProtocolV3 {
		if err = requireSupportedAuditScope(ctx, tx, p); err != nil {
			return AuditRun{}, err
		}
	}
	id, err := newID()
	if err != nil {
		return AuditRun{}, err
	}
	_, err = tx.Exec(ctx, `INSERT INTO audit_runs(environment_id,user_id,id,idempotency_key,request,request_hash,require_anchor) VALUES($1,$2,$3,$4,$5,$6,$7)`, env.ID.String(), p.UserID.String(), id.String(), key, raw, Hash(raw), in.RequireAnchor)
	if err != nil {
		return AuditRun{}, err
	}
	view, err := s.loadAudit(ctx, tx, p, id)
	if err != nil {
		return AuditRun{}, err
	}
	if err = tx.Commit(ctx); err != nil {
		return AuditRun{}, err
	}
	return view, nil
}

func (s *Service) loadAudit(ctx context.Context, q queryRow, p Principal, id funds.ID) (AuditRun, error) {
	var out AuditRun
	var raw []byte
	var capture, result *string
	var textID, requestHash string
	var requireAnchor bool
	err := q.QueryRow(ctx, `SELECT id::text,state,request,request_hash::text,require_anchor,attempts,max_attempts,claim_generation,capture_artifact_id::text,result_artifact_id::text,verification_status,assurance,created_at,finished_at,last_error FROM audit_runs WHERE environment_id=$1 AND user_id=$2 AND id=$3`, p.EnvironmentID.String(), p.UserID.String(), id.String()).Scan(&textID, &out.State, &raw, &requestHash, &requireAnchor, &out.Attempts, &out.MaxAttempts, &out.ClaimGeneration, &capture, &result, &out.VerificationStatus, &out.Assurance, &out.CreatedAt, &out.FinishedAt, &out.LastError)
	if errors.Is(err, pgx.ErrNoRows) {
		return out, reject("NOT_FOUND", err)
	}
	if err != nil {
		return out, err
	}
	out.ID, err = funds.ParseID(textID)
	if err != nil {
		return out, err
	}
	if Hash(raw) != requestHash || auditJSON(raw, &out.Request) != nil || out.Request.RequireAnchor != requireAnchor {
		return out, reject("AUDIT_ARTIFACT_INVALID", err)
	}
	out.Mode = auditMode(out.Request)
	for _, pair := range []struct {
		raw    *string
		target **funds.ID
	}{{capture, &out.CaptureArtifactID}, {result, &out.ResultArtifactID}} {
		rawID, target := pair.raw, pair.target
		if rawID != nil {
			id, err := funds.ParseID(*rawID)
			if err != nil {
				return out, err
			}
			*target = &id
		}
	}
	return out, nil
}

func (s *Service) Audit(ctx context.Context, p Principal, id funds.ID) (AuditRun, error) {
	if err := s.auditHuman(ctx, p); err != nil {
		return AuditRun{}, err
	}
	out, err := s.loadAudit(ctx, s.Pool, p, id)
	if err != nil {
		return out, err
	}
	if out.ResultArtifactID != nil {
		artifact, e := s.loadAuditArtifact(ctx, p, id, "RESULT")
		if e != nil {
			return out, e
		}
		var result auditStoredResult
		if err := auditJSON(artifact.Original, &result); err != nil {
			return out, err
		}
		if artifact.ID != *out.ResultArtifactID || artifact.ProtocolVersion != "zhiyu-audit-run-result-v1" || result.ProtocolVersion != artifact.ProtocolVersion || result.Mode != out.Mode || result.Verification.ManifestDigest != artifact.ManifestDigest || out.VerificationStatus == nil || string(result.Verification.Status) != *out.VerificationStatus || out.Assurance == nil || result.Verification.Assurance != *out.Assurance || result.Verification.Scope.EnvironmentID != p.EnvironmentID.String() || result.Verification.Scope.UserID != p.UserID.String() || result.Verification.Scope.Namespace != s.Namespace || !auditSameID(result.CaptureRunID, out.Request.CaptureRunID) {
			return out, reject("AUDIT_ARTIFACT_INVALID", nil)
		}
		out.Verification = &result.Verification
	}
	return out, nil
}

func auditSameID(a, b *funds.ID) bool {
	return a == nil && b == nil || a != nil && b != nil && *a == *b
}

func (s *Service) loadAuditArtifact(ctx context.Context, p Principal, runID funds.ID, kind string) (AuditArtifact, error) {
	var out AuditArtifact
	var id, rid string
	err := s.Pool.QueryRow(ctx, `SELECT id::text,run_id::text,kind,protocol_version,manifest_digest::text,original_hash::text,original FROM audit_artifacts WHERE environment_id=$1 AND user_id=$2 AND run_id=$3 AND kind=$4`, p.EnvironmentID.String(), p.UserID.String(), runID.String(), kind).Scan(&id, &rid, &out.Kind, &out.ProtocolVersion, &out.ManifestDigest, &out.OriginalHash, &out.Original)
	if errors.Is(err, pgx.ErrNoRows) {
		return out, reject("NOT_FOUND", err)
	}
	if err != nil {
		return out, err
	}
	out.ID, err = funds.ParseID(id)
	if err != nil {
		return out, err
	}
	out.RunID, err = funds.ParseID(rid)
	if err != nil {
		return out, err
	}
	if Hash(out.Original) != out.OriginalHash {
		return out, reject("AUDIT_ARTIFACT_INVALID", nil)
	}
	return out, nil
}

func (s *Service) AuditArtifact(ctx context.Context, p Principal, runID funds.ID, kind string) (AuditArtifact, error) {
	if kind != "CAPTURE" && kind != "RESULT" {
		return AuditArtifact{}, reject("INVALID_COMMAND", nil)
	}
	if err := s.auditHuman(ctx, p); err != nil {
		return AuditArtifact{}, err
	}
	return s.loadAuditArtifact(ctx, p, runID, kind)
}

// auditJSON accepts only our exact saved compact encoding. Re-encoding also
// rejects duplicate fields, whitespace variants and alternate byte lexemes.
func auditJSON(raw []byte, value any) error {
	if len(raw) == 0 || len(raw) > 32*1024*1024 {
		return reject("AUDIT_ARTIFACT_INVALID", nil)
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if err := d.Decode(value); err != nil {
		return reject("AUDIT_ARTIFACT_INVALID", err)
	}
	var extra any
	if d.Decode(&extra) != io.EOF {
		return reject("AUDIT_ARTIFACT_INVALID", nil)
	}
	encoded, err := encode(value)
	if err != nil || !bytes.Equal(raw, encoded) {
		return reject("AUDIT_ARTIFACT_INVALID", err)
	}
	return nil
}

func (s *Service) loadAuditCapture(ctx context.Context, p Principal, id funds.ID) (evidence.CapturedBundle, AuditArtifact, error) {
	artifact, err := s.loadAuditArtifact(ctx, p, id, "CAPTURE")
	if err != nil {
		return evidence.CapturedBundle{}, artifact, err
	}
	var capture evidence.CapturedBundle
	if artifact.ProtocolVersion != evidence.CaptureProtocol || auditJSON(artifact.Original, &capture) != nil {
		return capture, artifact, reject("AUDIT_ARTIFACT_INVALID", nil)
	}
	digest, err := capture.Manifest.Digest()
	if err != nil || digest != artifact.ManifestDigest || capture.Manifest.Scope.EnvironmentID != p.EnvironmentID.String() || capture.Manifest.Scope.UserID != p.UserID.String() || capture.Manifest.Scope.Namespace != s.Namespace {
		return capture, artifact, reject("AUDIT_ARTIFACT_INVALID", err)
	}
	return capture, artifact, nil
}

func (s *Service) loadAuditAnchor(ctx context.Context, p Principal, id funds.ID) (evidence.Anchor, error) {
	var raw []byte
	var hash, manifest, key, protocol, algorithm string
	var out evidence.Anchor
	err := s.Pool.QueryRow(ctx, `SELECT original,original_hash::text,manifest_digest::text,key_id,protocol_version,algorithm FROM audit_anchors WHERE environment_id=$1 AND user_id=$2 AND id=$3`, p.EnvironmentID.String(), p.UserID.String(), id.String()).Scan(&raw, &hash, &manifest, &key, &protocol, &algorithm)
	if errors.Is(err, pgx.ErrNoRows) {
		return out, reject("NOT_FOUND", err)
	}
	if err != nil {
		return out, err
	}
	if Hash(raw) != hash || auditJSON(raw, &out) != nil || out.ManifestDigest != manifest || out.KeyID != key || out.ProtocolVersion != protocol || out.Algorithm != algorithm {
		return out, reject("AUDIT_ARTIFACT_INVALID", nil)
	}
	return out, nil
}

func (s *Service) ImportAuditAnchor(ctx context.Context, p Principal, in AuditAnchorRequest) (AuditAnchor, error) {
	if err := s.auditHuman(ctx, p); err != nil {
		return AuditAnchor{}, err
	}
	capture, _, err := s.loadAuditCapture(ctx, p, in.CaptureRunID)
	if err != nil {
		return AuditAnchor{}, err
	}
	if err = evidence.VerifyAnchor(capture.Manifest, in.Anchor, s.AuditTrust.TrustedKeys); err != nil {
		return AuditAnchor{}, reject("AUDIT_ANCHOR_REJECTED", err)
	}
	raw, err := encode(in.Anchor)
	if err != nil {
		return AuditAnchor{}, err
	}
	id, err := newID()
	if err != nil {
		return AuditAnchor{}, err
	}
	_, err = s.Pool.Exec(ctx, `INSERT INTO audit_anchors(environment_id,user_id,id,key_id,protocol_version,algorithm,manifest_digest,original,original_hash) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9) ON CONFLICT(environment_id,user_id,manifest_digest,key_id) DO NOTHING`, p.EnvironmentID.String(), p.UserID.String(), id.String(), in.Anchor.KeyID, in.Anchor.ProtocolVersion, in.Anchor.Algorithm, in.Anchor.ManifestDigest, raw, Hash(raw))
	if err != nil {
		return AuditAnchor{}, err
	}
	var stored, storedHash string
	err = s.Pool.QueryRow(ctx, `SELECT id::text,original_hash::text FROM audit_anchors WHERE environment_id=$1 AND user_id=$2 AND manifest_digest=$3 AND key_id=$4`, p.EnvironmentID.String(), p.UserID.String(), in.Anchor.ManifestDigest, in.Anchor.KeyID).Scan(&stored, &storedHash)
	if err != nil {
		return AuditAnchor{}, err
	}
	if storedHash != Hash(raw) {
		return AuditAnchor{}, reject("IDEMPOTENCY_CONFLICT", nil)
	}
	id, err = funds.ParseID(stored)
	return AuditAnchor{id, in.Anchor.KeyID, in.Anchor.ManifestDigest}, err
}

type auditTable struct {
	name string
	keys []string
}

// V2 has an explicit 19-object selector. V1 captured bytes retain their exact
// original 17-table contract; re-verification never recollects or upgrades them.
var auditCaptureTables = []auditTable{
	{"accounts", []string{"id"}}, {"audit_session_subjects", []string{"id"}},
	{"bank_observations", []string{"id"}}, {"confirmations", []string{"id"}},
	{"evidence_blobs", []string{"id"}}, {"goals", []string{"id"}},
	{"grants", []string{"id", "version"}}, {"income_claims", []string{"action_id", "fragment_id"}},
	{"income_locations", []string{"id"}}, {"income_origins", []string{"id"}},
	{"income_reservations", []string{"action_id"}}, {"journals", []string{"id"}},
	{"operations", []string{"id"}}, {"plans", []string{"id"}},
	{"policies", []string{"id", "version"}}, {"postings", []string{"journal_id", "leg_ref"}},
	{"receipts", []string{"id"}}, {"submission_permits", []string{"operation_id"}},
	{"users", []string{"id"}},
}

type auditRawRow struct {
	table, key string
	raw        []byte
}

// Business v2 has a closed selector. New financial families must not silently
// disappear from an otherwise VALID current capture. Reverification of pinned
// older captures retains its original scope and does not pass through this gate.
func requireSupportedAuditScope(ctx context.Context, q queryRow, p Principal) error {
	for _, table := range []string{"template_policies", "template_obligations", "template_protection_publications", "goal_configuration_events", "native_operations", "native_positions", "native_principal_returns"} {
		var installed bool
		if err := q.QueryRow(ctx, `SELECT to_regclass($1) IS NOT NULL`, "public."+table).Scan(&installed); err != nil {
			return err
		}
		if !installed {
			continue
		}
		var exists bool
		// Identifiers come only from the closed source-code list above.
		if err := q.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM `+table+` WHERE environment_id=$1 AND user_id=$2)`, p.EnvironmentID.String(), p.UserID.String()).Scan(&exists); err != nil {
			return err
		}
		if exists {
			return reject("UNSUPPORTED_AUDIT_SCOPE", nil)
		}
	}
	return nil
}

func (s *Service) captureAudit(ctx context.Context, p Principal, runID funds.ID) (evidence.CapturedBundle, error) {
	tx, err := s.Pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	if err != nil {
		return evidence.CapturedBundle{}, err
	}
	defer rollback(ctx, tx)
	env, err := s.environment(ctx, tx, false)
	if err != nil {
		return evidence.CapturedBundle{}, err
	}
	if err = sameUser(p, env.ID); err != nil {
		return evidence.CapturedBundle{}, err
	}
	if err = requireSupportedAuditScope(ctx, tx, p); err != nil {
		return evidence.CapturedBundle{}, err
	}
	var fv, sv int64
	if err = tx.QueryRow(ctx, `SELECT funds_version,source_version FROM users WHERE environment_id=$1 AND id=$2`, env.ID.String(), p.UserID.String()).Scan(&fv, &sv); err != nil {
		return evidence.CapturedBundle{}, err
	}
	scope := evidence.Scope{EnvironmentID: env.ID.String(), Namespace: env.Namespace, UserID: p.UserID.String(), Epoch: fmt.Sprintf("writer:%d", env.WriterGeneration)}
	source := evidence.SourceMetadata{CapturedAt: s.now(), Watermarks: map[string]int64{"funds_version": fv, "source_version": sv, "writer_generation": int64(env.WriterGeneration), "control_version": int64(env.ControlVersion)}, SourceManifestSHA256: s.AuditTrust.SourceManifestSHA256, ConfigSHA256: s.AuditTrust.ConfigSHA256}
	var captured []auditRawRow
	sourceBytes := 0
	for _, table := range auditCaptureTables {
		keys, order := []string{}, []string{}
		for _, key := range table.keys {
			keys = append(keys, "t."+key+"::text")
			order = append(order, "t."+key)
		}
		filter := "t.user_id=$2"
		if table.name == "users" {
			filter = "t.id=$2"
		}
		remaining := evidence.DefaultBounds().MaxNodes - 1 - len(captured)
		// An oversized stored row is counted, but its bytes never cross the
		// collector connection. A bad row cannot defeat the bounded capture by
		// forcing a huge client-side Scan before we reject it.
		query := `SELECT json_build_array(` + strings.Join(keys, ",") + `)::text,octet_length(to_jsonb(t)::text),CASE WHEN octet_length(to_jsonb(t)::text)<=$4 THEN to_jsonb(t)::text END FROM ` + table.name + ` t WHERE t.environment_id=$1 AND ` + filter + ` ORDER BY ` + strings.Join(order, ",") + ` LIMIT $3`
		rows, e := tx.Query(ctx, query, env.ID.String(), p.UserID.String(), remaining+1, evidence.DefaultBounds().MaxBytes-sourceBytes)
		if e != nil {
			return evidence.CapturedBundle{}, e
		}
		for rows.Next() {
			if len(captured) >= evidence.DefaultBounds().MaxNodes-1 {
				rows.Close()
				return evidence.CapturedBundle{}, reject("AUDIT_CAPTURE_LIMIT", nil)
			}
			var key string
			var raw *string
			var rawBytes int64
			if e = rows.Scan(&key, &rawBytes, &raw); e != nil {
				rows.Close()
				return evidence.CapturedBundle{}, e
			}
			var parts []string
			if json.Unmarshal([]byte(key), &parts) != nil {
				rows.Close()
				return evidence.CapturedBundle{}, reject("AUDIT_ARTIFACT_INVALID", nil)
			}
			compact, _ := json.Marshal(parts)
			if raw == nil || rawBytes < 0 || rawBytes > int64(evidence.DefaultBounds().MaxBytes-sourceBytes) {
				rows.Close()
				return evidence.CapturedBundle{}, reject("AUDIT_CAPTURE_LIMIT", nil)
			}
			sourceBytes += int(rawBytes)
			captured = append(captured, auditRawRow{table.name, string(compact), []byte(*raw)})
		}
		e = rows.Err()
		rows.Close()
		if e != nil {
			return evidence.CapturedBundle{}, e
		}
	}
	if err = tx.Commit(ctx); err != nil {
		return evidence.CapturedBundle{}, err
	}
	// All canonical construction and semantic replay run after releasing RR.
	originals := map[string]evidence.Original{}
	tables := map[string][]string{}
	refs := []evidence.Reference{}
	total := 0
	for _, row := range captured {
		original, e := executionaudit.SealRowV2(executionaudit.BusinessRow{Scope: scope, Table: row.table, RowKey: row.key, Raw: row.raw})
		if e != nil {
			return evidence.CapturedBundle{}, reject("AUDIT_CAPTURE_LIMIT", e)
		}
		id := executionaudit.RowID(row.table, row.key)
		originals[id] = original
		tables[row.table] = append(tables[row.table], id)
		refs = append(refs, evidence.Reference{ID: id, Digest: original.Digest})
		total += len(original.Canonical)
		if total > evidence.DefaultBounds().MaxBytes {
			return evidence.CapturedBundle{}, reject("AUDIT_CAPTURE_LIMIT", nil)
		}
	}
	sort.Slice(refs, func(i, j int) bool { return refs[i].ID < refs[j].ID })
	counts := []executionaudit.BusinessTable{}
	for _, table := range auditCaptureTables {
		ids := tables[table.name]
		if ids == nil {
			ids = []string{}
		}
		sort.Strings(ids)
		counts = append(counts, executionaudit.BusinessTable{Table: table.name, Count: int64(len(ids)), IDs: ids})
	}
	rootID := "snapshot:" + runID.String()
	root, err := executionaudit.SealSnapshotV2(executionaudit.BusinessSnapshot{ID: rootID, Scope: scope, Tables: counts, Watermarks: source.Watermarks, References: refs})
	if err != nil {
		return evidence.CapturedBundle{}, reject("AUDIT_CAPTURE_LIMIT", err)
	}
	originals[rootID] = root
	bundle, err := evidence.BuildCapture(scope, source, []string{rootID}, originals)
	if err != nil {
		return bundle, reject("AUDIT_CAPTURE_LIMIT", err)
	}
	return bundle, nil
}

var ErrAuditClaimLost = errors.New("audit lease claim lost")

type auditClaim struct {
	Principal             Principal
	ID                    funds.ID
	Owner                 string
	Generation            uint64
	Attempts, MaxAttempts int
}

func (s *Service) claimAudit(ctx context.Context, owner string, lease time.Duration) (*auditClaim, error) {
	if owner == "" || len(owner) > 128 || lease < time.Millisecond || lease > time.Minute {
		return nil, reject("INVALID_WORKER_CONFIGURATION", nil)
	}
	_, err := s.Pool.Exec(ctx, `UPDATE audit_runs r SET state='EXHAUSTED',last_error='LEASE_EXPIRED_AT_RETRY_LIMIT',lease_owner=NULL,lease_until=NULL,finished_at=clock_timestamp() FROM environments e WHERE e.id=r.environment_id AND e.namespace=$1 AND r.state='RUNNING' AND r.lease_until<=clock_timestamp() AND r.attempts>=r.max_attempts`, s.Namespace)
	if err != nil {
		return nil, err
	}
	var env, user, id string
	var c auditClaim
	err = s.Pool.QueryRow(ctx, `WITH picked AS(SELECT r.environment_id,r.user_id,r.id FROM audit_runs r JOIN environments e ON(e.id=r.environment_id) WHERE e.namespace=$1 AND r.state IN('QUEUED','RUNNING') AND r.attempts<r.max_attempts AND r.next_attempt_at<=clock_timestamp() AND (r.lease_until IS NULL OR r.lease_until<=clock_timestamp()) ORDER BY r.next_attempt_at,r.id FOR UPDATE OF r SKIP LOCKED LIMIT 1) UPDATE audit_runs r SET state='RUNNING',claim_generation=r.claim_generation+1,lease_owner=$2,lease_until=clock_timestamp()+$3::bigint*interval '1 millisecond',attempts=r.attempts+1 FROM picked p WHERE r.environment_id=p.environment_id AND r.user_id=p.user_id AND r.id=p.id RETURNING r.environment_id::text,r.user_id::text,r.id::text,r.claim_generation,r.attempts,r.max_attempts`, s.Namespace, owner, lease.Milliseconds()).Scan(&env, &user, &id, &c.Generation, &c.Attempts, &c.MaxAttempts)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if c.Principal.EnvironmentID, err = funds.ParseID(env); err != nil {
		return nil, err
	}
	if c.Principal.UserID, err = funds.ParseID(user); err != nil {
		return nil, err
	}
	if c.ID, err = funds.ParseID(id); err != nil {
		return nil, err
	}
	c.Principal.Kind = "SYSTEM"
	c.Owner = owner
	return &c, nil
}

// auditCurrent locks only this audit task. No business row lock is held while
// collecting the RR snapshot, replaying business rules or verifying signatures.
func (s *Service) auditCurrent(ctx context.Context, tx pgx.Tx, c auditClaim) (AuditRun, error) {
	var live bool
	err := tx.QueryRow(ctx, `SELECT claim_generation=$4 AND lease_owner=$5 AND lease_until>clock_timestamp() AND state='RUNNING' FROM audit_runs WHERE environment_id=$1 AND user_id=$2 AND id=$3 FOR UPDATE`, c.Principal.EnvironmentID.String(), c.Principal.UserID.String(), c.ID.String(), c.Generation, c.Owner).Scan(&live)
	if err != nil {
		return AuditRun{}, err
	}
	if !live {
		return AuditRun{}, ErrAuditClaimLost
	}
	return s.loadAudit(ctx, tx, c.Principal, c.ID)
}

func (s *Service) pinAuditCapture(ctx context.Context, c auditClaim, capture evidence.CapturedBundle, raw []byte) error {
	digest, err := capture.Manifest.Digest()
	if err != nil || len(raw) > 32*1024*1024 {
		return reject("AUDIT_CAPTURE_LIMIT", err)
	}
	tx, err := s.begin(ctx)
	if err != nil {
		return err
	}
	defer rollback(ctx, tx)
	run, err := s.auditCurrent(ctx, tx, c)
	if err != nil {
		return err
	}
	if run.CaptureArtifactID != nil {
		return tx.Commit(ctx)
	}
	id, err := newID()
	if err != nil {
		return err
	}
	_, err = tx.Exec(ctx, `INSERT INTO audit_artifacts(environment_id,user_id,id,run_id,kind,protocol_version,manifest_digest,original,original_hash) VALUES($1,$2,$3,$4,'CAPTURE',$5,$6,$7,$8)`, c.Principal.EnvironmentID.String(), c.Principal.UserID.String(), id.String(), c.ID.String(), evidence.CaptureProtocol, digest, raw, Hash(raw))
	if err != nil {
		return err
	}
	tag, err := tx.Exec(ctx, `UPDATE audit_runs SET capture_artifact_id=$6 WHERE environment_id=$1 AND user_id=$2 AND id=$3 AND claim_generation=$4 AND lease_owner=$5 AND lease_until>clock_timestamp() AND state='RUNNING' AND capture_artifact_id IS NULL`, c.Principal.EnvironmentID.String(), c.Principal.UserID.String(), c.ID.String(), c.Generation, c.Owner, id.String())
	if err != nil {
		return err
	}
	if tag.RowsAffected() != 1 {
		return ErrAuditClaimLost
	}
	return tx.Commit(ctx)
}

func auditTrustedKeys(keys map[string]ed25519.PublicKey) map[string]ed25519.PublicKey {
	copy := make(map[string]ed25519.PublicKey, len(keys))
	for id, key := range keys {
		copy[id] = append(ed25519.PublicKey(nil), key...)
	}
	return copy
}

func (s *Service) processAudit(ctx context.Context, c auditClaim) error {
	if !s.auditConfigured() {
		return reject("AUDIT_NOT_CONFIGURED", nil)
	}
	run, err := s.loadAudit(ctx, s.Pool, c.Principal, c.ID)
	if err != nil {
		return err
	}
	if run.CaptureArtifactID == nil {
		var capture evidence.CapturedBundle
		var raw []byte
		if run.Request.CaptureRunID != nil {
			var artifact AuditArtifact
			capture, artifact, err = s.loadAuditCapture(ctx, c.Principal, *run.Request.CaptureRunID)
			raw = artifact.Original // preserve old scope, capture time and exact bytes
		} else {
			if run.Request.ProtocolVersion == executionaudit.NativeAuditProtocolV3 {
				capture, err = s.captureNativeAuditV3(ctx, c.Principal, c.ID)
			} else {
				capture, err = s.captureAudit(ctx, c.Principal, c.ID)
			}
			if err == nil {
				raw, err = encode(capture)
			}
		}
		if err != nil {
			return err
		}
		if err = s.pinAuditCapture(ctx, c, capture, raw); err != nil {
			return err
		}
		if s.Failpoint != nil {
			if err = s.Failpoint("after_audit_capture_pin"); err != nil {
				return err
			}
		}
	}
	// Always reload the winning pin. A stale collector can never replace it.
	capture, _, err := s.loadAuditCapture(ctx, c.Principal, c.ID)
	if err != nil {
		return err
	}
	registry := evidence.NewRegistry()
	if err = executionaudit.RegisterBusiness(registry); err != nil {
		return err
	}
	if err = executionaudit.RegisterNativeBusinessV3WithTrust(registry, executionaudit.NativeVerifierTrustV3{HistoryAuthorityProfileHashes: s.AuditTrust.HistoryAuthorityProfileHashes}); err != nil {
		return err
	}
	options := evidence.CaptureOptions{RequireAnchor: run.Request.RequireAnchor || s.AuditTrust.RequireAnchor, TrustedKeys: auditTrustedKeys(s.AuditTrust.TrustedKeys)}
	if run.Request.AnchorID != nil {
		anchor, e := s.loadAuditAnchor(ctx, c.Principal, *run.Request.AnchorID)
		if e != nil {
			return e
		}
		options.Anchor = &anchor
	}
	verification := evidence.VerifyCaptured(capture, registry, options)
	result := auditStoredResult{ProtocolVersion: "zhiyu-audit-run-result-v1", Mode: run.Mode, CaptureRunID: run.Request.CaptureRunID, VerifiedAt: s.now(), VerifierSourceManifestSHA256: s.AuditTrust.SourceManifestSHA256, VerifierConfigSHA256: s.AuditTrust.ConfigSHA256, Verification: verification}
	raw, err := encode(result)
	if err != nil {
		return err
	}
	if len(raw) > 1024*1024 {
		return reject("AUDIT_CAPTURE_LIMIT", nil)
	}
	if s.Failpoint != nil {
		if err = s.Failpoint("before_audit_result_pin"); err != nil {
			return err
		}
	}
	return s.finishAudit(ctx, c, run.Request.AnchorID, verification, raw)
}

func (s *Service) finishAudit(ctx context.Context, c auditClaim, anchor *funds.ID, verification evidence.CaptureVerification, raw []byte) error {
	tx, err := s.begin(ctx)
	if err != nil {
		return err
	}
	defer rollback(ctx, tx)
	run, err := s.auditCurrent(ctx, tx, c)
	if err != nil {
		return err
	}
	if run.CaptureArtifactID == nil {
		return reject("AUDIT_ARTIFACT_INVALID", nil)
	}
	id, err := newID()
	if err != nil {
		return err
	}
	var anchorID any
	if anchor != nil {
		anchorID = anchor.String()
	}
	_, err = tx.Exec(ctx, `INSERT INTO audit_artifacts(environment_id,user_id,id,run_id,kind,protocol_version,manifest_digest,original,original_hash,verification_status,assurance,anchor_id) VALUES($1,$2,$3,$4,'RESULT','zhiyu-audit-run-result-v1',$5,$6,$7,$8,$9,$10)`, c.Principal.EnvironmentID.String(), c.Principal.UserID.String(), id.String(), c.ID.String(), verification.ManifestDigest, raw, Hash(raw), string(verification.Status), verification.Assurance, anchorID)
	if err != nil {
		return err
	}
	tag, err := tx.Exec(ctx, `UPDATE audit_runs SET state='COMPLETED',result_artifact_id=$6,verification_status=$7,assurance=$8,anchor_id=$9,lease_owner=NULL,lease_until=NULL,finished_at=clock_timestamp(),last_error='' WHERE environment_id=$1 AND user_id=$2 AND id=$3 AND claim_generation=$4 AND lease_owner=$5 AND lease_until>clock_timestamp() AND state='RUNNING' AND result_artifact_id IS NULL`, c.Principal.EnvironmentID.String(), c.Principal.UserID.String(), c.ID.String(), c.Generation, c.Owner, id.String(), string(verification.Status), verification.Assurance, anchorID)
	if err != nil {
		return err
	}
	if tag.RowsAffected() != 1 {
		return ErrAuditClaimLost
	}
	return tx.Commit(ctx)
}

func (s *Service) retryAudit(ctx context.Context, c auditClaim, cause error) error {
	state := "QUEUED"
	reason := Code(cause)
	switch reason {
	case "AUDIT_CAPTURE_LIMIT", "AUDIT_ARTIFACT_INVALID", "AUDIT_NOT_CONFIGURED", "UNSUPPORTED_AUDIT_SCOPE", "NOT_FOUND", "FORBIDDEN":
		state = "EXHAUSTED"
	}
	if c.Attempts >= c.MaxAttempts {
		state = "EXHAUSTED"
	}
	delay := 100 * time.Millisecond
	for n := 1; n < c.Attempts && delay < 5*time.Second; n++ {
		delay *= 2
	}
	if delay > 5*time.Second {
		delay = 5 * time.Second
	}
	tag, err := s.Pool.Exec(ctx, `UPDATE audit_runs SET state=$6,last_error=$7,lease_owner=NULL,lease_until=NULL,next_attempt_at=clock_timestamp()+$8::bigint*interval '1 millisecond',finished_at=CASE WHEN $6='EXHAUSTED' THEN clock_timestamp() ELSE NULL END WHERE environment_id=$1 AND user_id=$2 AND id=$3 AND claim_generation=$4 AND lease_owner=$5 AND lease_until>clock_timestamp() AND state='RUNNING'`, c.Principal.EnvironmentID.String(), c.Principal.UserID.String(), c.ID.String(), c.Generation, c.Owner, state, reason, delay.Milliseconds())
	if err != nil {
		return err
	}
	if tag.RowsAffected() != 1 {
		return ErrAuditClaimLost
	}
	return nil
}

// AuditStep performs bounded read-only business capture and verification. It
// neither calls the bank nor shares the financial or standing worker queues.
func (s *Service) AuditStep(ctx context.Context, owner string, lease time.Duration) (bool, error) {
	claim, err := s.claimAudit(ctx, owner, lease)
	if err != nil || claim == nil {
		return false, err
	}
	err = s.processAudit(ctx, *claim)
	if errors.Is(err, ErrAuditClaimLost) {
		return true, err
	}
	if err != nil {
		if retryErr := s.retryAudit(ctx, *claim, err); retryErr != nil {
			return true, retryErr
		}
	}
	return true, nil
}

func (s *Service) RunAuditWorker(ctx context.Context, owner string) error {
	var databaseFailures uint
	for {
		if ctx.Err() != nil {
			return nil
		}
		worked, err := s.AuditStep(ctx, owner, 30*time.Second)
		if retryBackgroundDatabase(ctx, err, &databaseFailures) {
			continue
		}
		if err != nil && !errors.Is(err, ErrAuditClaimLost) {
			return err
		}
		if !worked || err != nil {
			timer := time.NewTimer(250 * time.Millisecond)
			select {
			case <-ctx.Done():
				timer.Stop()
				return nil
			case <-timer.C:
			}
		}
	}
}
