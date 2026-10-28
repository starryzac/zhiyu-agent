package banksim

import (
	"context"
	_ "embed"
	"encoding/json"

	"github.com/jackc/pgx/v5"
)

//go:embed observation_schema_projection.sql
var observationSchemaProjection string

// Root-authorized metadata-only formal bank1/2/3 baseline: catalog.json
// baseline-20261025-03, 322241B, 604 unique entries. Never learn an expected
// baseline from the bank being checked or treat migration rows as DDL proof.
const frozenObservationSchemaSHA256 = "8db4eeab9131be48fc3e874f19bfde5bf897a10a3ef05e5cb0dfd48ae9405845"

func observationSchema(ctx context.Context, tx pgx.Tx, _ []observationTable) (string, error) {
	if len(frozenObservationSchemaSHA256) != 64 {
		return "", errObservationUnavailable
	}
	if _, err := tx.Exec(ctx, `SET LOCAL search_path=pg_catalog`); err != nil {
		return "", err
	}
	var n int64
	var catalog *string
	if err := tx.QueryRow(ctx, observationSchemaProjection).Scan(&n, &catalog); err != nil {
		return "", err
	}
	if catalog == nil || n < 1 || n > 4<<20 || int64(len(*catalog)) != n || observationSHA(*catalog) != frozenObservationSchemaSHA256 {
		return "", errObservationUnavailable
	}
	// Field tags are explicit because the projection deliberately uses snake
	// case and its exact PG jsonb text is hashed without Go reserialization.
	var envelope struct {
		Protocol   string            `json:"protocol"`
		Schema     string            `json:"schema"`
		SearchPath string            `json:"search_path"`
		Status     string            `json:"status"`
		EntryCount int               `json:"entry_count"`
		Entries    []json.RawMessage `json:"entries"`
	}
	if json.Unmarshal([]byte(*catalog), &envelope) != nil {
		return "", errObservationUnavailable
	}
	if envelope.Protocol != "zhiyu-bank-schema-catalog-v2" || envelope.Schema != "bank" || envelope.SearchPath != "pg_catalog" || envelope.Status != "OK" || envelope.EntryCount < 1 || envelope.EntryCount > 10000 || len(envelope.Entries) != envelope.EntryCount {
		return "", errObservationUnavailable
	}
	rows, err := tx.Query(ctx, `SELECT version,sha256 FROM bank.protocol_migrations ORDER BY version LIMIT 4`)
	if err != nil {
		return "", err
	}
	versions := map[int]string{}
	for rows.Next() {
		var version int
		var value string
		if err = rows.Scan(&version, &value); err != nil {
			break
		}
		if _, duplicate := versions[version]; duplicate {
			err = errObservationUnavailable
			break
		}
		versions[version] = value
	}
	if end := rows.Err(); err == nil {
		err = end
	}
	rows.Close()
	if err != nil {
		return "", err
	}
	if len(versions) != 2 || versions[2] != frozenBankV2Migration || versions[3] != frozenBankCreditMigration {
		return "", errObservationUnavailable
	}
	return frozenObservationSchemaSHA256, nil
}
