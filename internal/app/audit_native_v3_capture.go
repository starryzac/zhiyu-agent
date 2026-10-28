package app

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/jackc/pgx/v5"
	evidence "zhiyu.local/zhiyu-go/internal/audit"
	executionaudit "zhiyu.local/zhiyu-go/internal/execution/audit"
	funds "zhiyu.local/zhiyu-go/internal/funds/domain"
)

type nativeAuditBasisV3 struct{ FV, SV, WG, CV int64 }

// The app role cannot read Goose's owner-only version table. Select the
// registered schema features, then let the complete catalog inventory expose
// every missing table. Never silently downgrade a partial witness schema.
func nativeAuditSchemaCatalogRevisionV3(recovery, fundsWitness, sourceWitness, terminalDecision bool) (int, error) {
	if terminalDecision {
		return 26, nil
	}
	if fundsWitness != sourceWitness {
		return 0, reject("AUDIT_SCHEMA_INCOMPLETE", nil)
	}
	if fundsWitness {
		return 25, nil
	}
	if recovery {
		return 23, nil
	}
	return executionaudit.NativeCatalogRevisionV3, nil
}

func nativeAuditCaptureIsV3(capture evidence.CapturedBundle) bool {
	if len(capture.Manifest.Roots) != 1 {
		return false
	}
	original, ok := capture.Originals[capture.Manifest.Roots[0].ID]
	if !ok {
		return false
	}
	var header struct {
		Kind    string `json:"kind"`
		Version string `json:"semantic_version"`
	}
	return json.Unmarshal(original.Canonical, &header) == nil && header.Kind == executionaudit.NativeSnapshotKindV3 && header.Version == executionaudit.NativeSnapshotVersionV3
}

func readNativeAuditBasisV3(ctx context.Context, q queryRow, p Principal) (nativeAuditBasisV3, error) {
	var out nativeAuditBasisV3
	err := q.QueryRow(ctx, `SELECT u.funds_version,u.source_version,e.writer_generation,e.control_version FROM users u JOIN environments e ON(e.id=u.environment_id) WHERE u.environment_id=$1 AND u.id=$2`, p.EnvironmentID.String(), p.UserID.String()).Scan(&out.FV, &out.SV, &out.WG, &out.CV)
	return out, err
}

// captureNativeAuditV3 is a new protocol collector. Reverification of any old
// pinned capture never invokes it and never upgrades old v1/v2 source bytes.
func (s *Service) captureNativeAuditV3(ctx context.Context, p Principal, runID funds.ID) (evidence.CapturedBundle, error) {
	var empty evidence.CapturedBundle
	before, err := readNativeAuditBasisV3(ctx, s.Pool, p)
	if err != nil {
		return empty, err
	}
	bank := s.captureIndependentNativeAuditBankV3(ctx, p)
	tx, err := s.Pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	if err != nil {
		return empty, err
	}
	defer rollback(ctx, tx)
	env, err := s.environment(ctx, tx, false)
	if err != nil {
		return empty, err
	}
	if err = sameUser(p, env.ID); err != nil {
		return empty, err
	}
	after, err := readNativeAuditBasisV3(ctx, tx, p)
	if err != nil {
		return empty, err
	}
	if before != after {
		bank.Complete = false
		bank.Problems = append(bank.Problems, "APPLICATION_BASIS_CHANGED_DURING_INDEPENDENT_READ")
	}
	scope := evidence.Scope{EnvironmentID: env.ID.String(), Namespace: env.Namespace, UserID: p.UserID.String(), Epoch: fmt.Sprintf("writer:%d", env.WriterGeneration)}
	var recoverySchema, fundsWitness, sourceWitness, terminalDecision bool
	if err = tx.QueryRow(ctx, `SELECT to_regclass('public.writer_controls') IS NOT NULL OR to_regclass('public.writer_control_events') IS NOT NULL OR to_regclass('public.recovery_runs') IS NOT NULL OR to_regclass('public.recovery_bank_scans') IS NOT NULL OR to_regclass('public.recovery_bank_observations') IS NOT NULL,
 to_regclass('public.funds_commit_witnesses') IS NOT NULL,to_regclass('public.template_source_witnesses') IS NOT NULL,to_regclass('public.funds_terminal_decisions') IS NOT NULL`).Scan(&recoverySchema, &fundsWitness, &sourceWitness, &terminalDecision); err != nil {
		return empty, err
	}
	revision, err := nativeAuditSchemaCatalogRevisionV3(recoverySchema, fundsWitness, sourceWitness, terminalDecision)
	if err != nil {
		return empty, err
	}
	catalog := executionaudit.NativeAuditTablesV3Revision(revision)
	source := evidence.SourceMetadata{CapturedAt: s.now(), Watermarks: map[string]int64{"funds_version": after.FV, "source_version": after.SV, "writer_generation": after.WG, "control_version": after.CV}, SourceManifestSHA256: s.AuditTrust.SourceManifestSHA256, ConfigSHA256: s.AuditTrust.ConfigSHA256}
	bankRaw, err := encode(bank)
	if err != nil {
		return empty, err
	}
	sourceBytes := len(bankRaw)
	var rowsCaptured []auditRawRow
	missing := []string{}
	for _, table := range catalog {
		var installed bool
		if err = tx.QueryRow(ctx, `SELECT to_regclass($1) IS NOT NULL`, "public."+table.Name).Scan(&installed); err != nil {
			return empty, err
		}
		if !installed {
			missing = append(missing, table.Name)
			continue
		}
		keys, order := []string{}, []string{}
		for _, column := range table.PrimaryKey {
			keys = append(keys, "t."+column+"::text")
			order = append(order, "t."+column)
		}
		if len(order) == 0 {
			order = []string{"t.environment_id", "t.user_id"}
			if table.Name == "writer_controls" {
				order = []string{"t.environment_id"}
			}
		}
		filter := `t.environment_id=$1 AND t.user_id=$2`
		if table.Name == "users" {
			filter = `t.environment_id=$1 AND t.id=$2`
		}
		if table.Name == "environments" {
			filter = `t.id=$1 AND $2::uuid IS NOT NULL`
		}
		if table.Name == "writer_controls" || table.Name == "writer_control_events" || table.Name == "recovery_runs" {
			filter = `t.environment_id=$1 AND $2::uuid IS NOT NULL`
		}
		remaining := evidence.DefaultBounds().MaxNodes - 2 - len(rowsCaptured)
		if remaining < 0 || sourceBytes > executionaudit.NativeMaximumRawCaptureBytesV3 {
			return empty, reject("AUDIT_CAPTURE_LIMIT", nil)
		}
		maxRow := min(executionaudit.NativeMaximumRawRowBytesV3, executionaudit.NativeMaximumRawCaptureBytesV3-sourceBytes)
		query := `SELECT json_build_array(` + strings.Join(keys, ",") + `)::text,octet_length(to_jsonb(t)::text),CASE WHEN octet_length(to_jsonb(t)::text)<=$4 THEN to_jsonb(t)::text END FROM ` + table.Name + ` t WHERE ` + filter + ` ORDER BY ` + strings.Join(order, ",") + ` LIMIT $3`
		rows, e := tx.Query(ctx, query, env.ID.String(), p.UserID.String(), remaining+1, maxRow)
		if e != nil {
			return empty, e
		}
		for rows.Next() {
			if len(rowsCaptured) >= evidence.DefaultBounds().MaxNodes-2 {
				rows.Close()
				return empty, reject("AUDIT_CAPTURE_LIMIT", nil)
			}
			var key string
			var raw *string
			var rawSize int64
			if e = rows.Scan(&key, &rawSize, &raw); e != nil {
				rows.Close()
				return empty, e
			}
			var parts []string
			if json.Unmarshal([]byte(key), &parts) != nil || parts == nil {
				rows.Close()
				return empty, reject("AUDIT_ARTIFACT_INVALID", nil)
			}
			compact, _ := json.Marshal(parts)
			if raw == nil || rawSize < 1 || rawSize > int64(executionaudit.NativeMaximumRawRowBytesV3) || rawSize > int64(executionaudit.NativeMaximumRawCaptureBytesV3-sourceBytes) {
				rows.Close()
				return empty, reject("AUDIT_CAPTURE_LIMIT", nil)
			}
			if table.Name == "recovery_runs" && !nativeAuditRecoveryRunOwnedV3([]byte(*raw), p, s.Namespace) {
				bank.Complete = false
				bank.Problems = append(bank.Problems, "RECOVERY_RUN_SCOPE_NOT_EXPORTABLE")
				continue
			}
			sourceBytes += int(rawSize)
			rowsCaptured = append(rowsCaptured, auditRawRow{table: table.Name, key: string(compact), raw: []byte(*raw)})
		}
		e = rows.Err()
		rows.Close()
		if e != nil {
			return empty, e
		}
	}
	updatedBankRaw, e := encode(bank)
	if e != nil {
		return empty, e
	}
	sourceBytes += len(updatedBankRaw) - len(bankRaw)
	if sourceBytes > executionaudit.NativeMaximumRawCaptureBytesV3 {
		return empty, reject("AUDIT_CAPTURE_LIMIT", nil)
	}
	if err = tx.Commit(ctx); err != nil {
		return empty, err
	}
	// Exact source membership is now pinned in memory. Compression/canonical
	// construction and all pure semantic replay execute after releasing RR.
	originals := map[string]evidence.Original{}
	refs := []evidence.Reference{}
	tableIDs := map[string][]string{}
	var encodedBytes int64
	memberBytes := 0
	add := func(id string, original evidence.Original) error {
		var header struct {
			Data struct {
				RawHex string `json:"raw_hex"`
			} `json:"data"`
		}
		if json.Unmarshal(original.Canonical, &header) != nil {
			return reject("AUDIT_ARTIFACT_INVALID", nil)
		}
		encodedBytes += int64(len(header.Data.RawHex) / 2)
		memberBytes += len(original.Canonical)
		if memberBytes > evidence.DefaultBounds().MaxBytes {
			return reject("AUDIT_CAPTURE_LIMIT", nil)
		}
		originals[id] = original
		refs = append(refs, evidence.Reference{ID: id, Digest: original.Digest})
		return nil
	}
	bankID := "independent-bank:" + runID.String()
	bankOriginal, err := executionaudit.SealNativeIndependentBankV3(bankID, scope, bank)
	if err != nil {
		return empty, reject("AUDIT_CAPTURE_LIMIT", err)
	}
	if err = add(bankID, bankOriginal); err != nil {
		return empty, err
	}
	for _, row := range rowsCaptured {
		original, e := executionaudit.SealNativeRowV3(executionaudit.BusinessRow{Scope: scope, Table: row.table, RowKey: row.key, Raw: row.raw})
		if e != nil {
			return empty, reject("AUDIT_ARTIFACT_INVALID", e)
		}
		id := executionaudit.RowID(row.table, row.key)
		if err = add(id, original); err != nil {
			return empty, err
		}
		tableIDs[row.table] = append(tableIDs[row.table], id)
	}
	sort.Slice(refs, func(i, j int) bool { return refs[i].ID < refs[j].ID })
	tables := []executionaudit.BusinessTable{}
	for _, table := range catalog {
		ids := tableIDs[table.Name]
		if ids == nil {
			ids = []string{}
		}
		sort.Strings(ids)
		tables = append(tables, executionaudit.BusinessTable{Table: table.Name, Count: int64(len(ids)), IDs: ids})
	}
	rootID := "native-snapshot:" + runID.String()
	root, err := executionaudit.SealNativeSnapshotV3(executionaudit.NativeSnapshotV3{BusinessSnapshot: executionaudit.BusinessSnapshot{ID: rootID, Scope: scope, Tables: tables, Watermarks: source.Watermarks, References: refs}, CatalogRevision: revision, MissingTables: missing, BankReference: bankID, RawSourceBytes: int64(sourceBytes), CompressedSourceBytes: encodedBytes})
	if err != nil {
		return empty, reject("AUDIT_ARTIFACT_INVALID", err)
	}
	originals[rootID] = root
	if memberBytes+len(root.Canonical) > evidence.DefaultBounds().MaxBytes {
		return empty, reject("AUDIT_CAPTURE_LIMIT", nil)
	}
	bundle, err := evidence.BuildCapture(scope, source, []string{rootID}, originals)
	if err != nil {
		return empty, reject("AUDIT_CAPTURE_LIMIT", err)
	}
	return bundle, nil
}
