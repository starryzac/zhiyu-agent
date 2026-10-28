package app

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"sort"
	"time"

	"github.com/jackc/pgx/v5"
	executionaudit "zhiyu.local/zhiyu-go/internal/execution/audit"
	funds "zhiyu.local/zhiyu-go/internal/funds/domain"
	planning "zhiyu.local/zhiyu-go/internal/planning/domain"
	policy "zhiyu.local/zhiyu-go/internal/policy/domain"
)

// TemplateSourceWitness is an actual read prefix, before any proposed policy
// or counterfactual action. Its basis descriptor retains only nonfinancial
// originals; all economic/authority rows are reconstructed from the sealed
// funds-version delta chain. No current ledger or cache is audit authority.
type TemplateSourceWitness struct {
	Protocol               string                     `json:"protocol"`
	ID                     funds.ID                   `json:"id"`
	Scope                  policy.TemplateOwnerScope  `json:"scope"`
	Namespace              string                     `json:"namespace"`
	AsOf                   time.Time                  `json:"as_of"`
	Timezone               string                     `json:"timezone"`
	FundsVersion           uint64                     `json:"funds_version"`
	SnapshotSourceVersion  uint64                     `json:"snapshot_source_version"`
	WriterGeneration       uint64                     `json:"writer_generation"`
	ControlVersion         uint64                     `json:"control_version"`
	FundsCommitHash        string                     `json:"funds_commit_hash"`
	SourceHash             string                     `json:"source_hash"`
	SourceBasisOriginal    []byte                     `json:"source_basis_original"`
	SourceBasisHash        string                     `json:"source_basis_hash"`
	SourceTables           []string                   `json:"source_tables"`
	FundsStateHash         string                     `json:"funds_state_hash"`
	DatedConfirmationInput *datedConfirmationSourceV1 `json:"dated_confirmation_input,omitempty"`
}

var templateWitnessFinancialTables = []string{"accounts", "goals", "income_origins", "income_locations", "income_reservations", "income_claims", "native_income_reservations", "native_income_claims", "native_goal_balances", "native_goal_lots", "native_holds", "native_positions", "native_position_states", "native_principal_returns", "native_return_locations", "native_return_claims", "receipts", "native_receipts", "native_payment_sources", "native_obligation_payments", "template_obligation_payments", "template_policies", "template_policy_versions", "template_policy_confirmations", "template_policy_status_events"}

// Same field order and spelling as the established full source-hash basis.
type templateWitnessSourceBasis struct {
	Scope                         policy.TemplateOwnerScope
	Inventory                     templateInventory
	FundsVersion, Writer, Control uint64
	Rows                          map[string][]string
}

func templateSourceWitnessEnabled(ctx context.Context, tx pgx.Tx) (bool, error) {
	var enabled bool
	err := tx.QueryRow(ctx, `SELECT to_regclass('public.template_source_witnesses') IS NOT NULL`).Scan(&enabled)
	return enabled, err
}

func (s *Service) saveTemplateSourceWitness(ctx context.Context, tx pgx.Tx, p Principal, snapshot templateSnapshot) (*funds.ID, string, error) {
	return s.saveTemplateSourceWitnessWithDated(ctx, tx, p, snapshot, nil)
}

func (s *Service) saveTemplateSourceWitnessWithDated(ctx context.Context, tx pgx.Tx, p Principal, snapshot templateSnapshot, dated *datedConfirmationSourceV1) (*funds.ID, string, error) {
	if !snapshot.SourceWitnessEnabled {
		return nil, "", nil // Old schema retains its original protocol and gaps.
	}
	if snapshot.Native == nil || len(snapshot.SourceBasisOriginal) == 0 || Hash(snapshot.SourceBasisOriginal) != snapshot.Facts.SourceHash {
		return nil, "", reject("TEMPLATE_SOURCE_WITNESS_INCOMPLETE", nil)
	}
	var commitHash string
	var sealedStateHash string
	if err := tx.QueryRow(ctx, `SELECT original_hash::text,convert_from(original,'UTF8')::jsonb->>'state_hash' FROM funds_commit_witnesses WHERE environment_id=$1 AND user_id=$2 AND funds_version=$3`, p.EnvironmentID.String(), p.UserID.String(), snapshot.FundsVersion).Scan(&commitHash, &sealedStateHash); err != nil {
		return nil, "", reject("TEMPLATE_FUNDS_PREFIX_MISSING", err)
	}
	var stateHash string
	var stateRaw []byte
	if err := tx.QueryRow(ctx, `SELECT financial_rows,state_hash::text FROM funds_commit_projection_cache WHERE environment_id=$1 AND user_id=$2 AND funds_version=$3`, p.EnvironmentID.String(), p.UserID.String(), snapshot.FundsVersion).Scan(&stateRaw, &stateHash); err != nil {
		return nil, "", reject("TEMPLATE_FUNDS_PREFIX_MISSING", err)
	}
	if stateHash != sealedStateHash {
		return nil, "", reject("TEMPLATE_FUNDS_PREFIX_CACHE_DIFFERS", nil)
	}
	var retained map[string]map[string]string
	if json.Unmarshal(stateRaw, &retained) != nil {
		return nil, "", reject("TEMPLATE_FUNDS_PREFIX_INVALID", nil)
	}
	var basis templateWitnessSourceBasis
	if json.Unmarshal(snapshot.SourceBasisOriginal, &basis) != nil {
		return nil, "", reject("TEMPLATE_SOURCE_WITNESS_INCOMPLETE", nil)
	}
	tables := make([]string, 0, len(basis.Rows))
	for table := range basis.Rows {
		tables = append(tables, table)
	}
	sort.Strings(tables)
	for _, table := range templateWitnessFinancialTables {
		actual, exists := basis.Rows[table]
		prefix, found := retained[table]
		if !exists || !found || len(actual) != len(prefix) {
			return nil, "", reject("TEMPLATE_FUNDS_PREFIX_DIFFERS", nil)
		}
		project := func(raw string) string {
			return raw
		}
		seen := map[string]bool{}
		for _, raw := range prefix {
			seen[project(raw)] = true
		}
		for _, raw := range actual {
			if !seen[project(raw)] {
				return nil, "", reject("TEMPLATE_FUNDS_PREFIX_DIFFERS", nil)
			}
		}
		delete(basis.Rows, table)
	}
	partial, err := encode(basis)
	if err != nil {
		return nil, "", err
	}
	id, err := newID()
	if err != nil {
		return nil, "", err
	}
	witness := TemplateSourceWitness{Protocol: "template-source-witness-v1", ID: id, Scope: snapshot.Facts.Scope, Namespace: s.Namespace, AsOf: snapshot.AsOf, Timezone: snapshot.Timezone, FundsVersion: snapshot.FundsVersion, SnapshotSourceVersion: snapshot.SourceVersion, WriterGeneration: snapshot.WriterGeneration, ControlVersion: snapshot.ControlVersion, FundsCommitHash: commitHash, SourceHash: snapshot.Facts.SourceHash, SourceBasisOriginal: partial, SourceBasisHash: Hash(partial), SourceTables: tables, FundsStateHash: stateHash}
	if dated != nil {
		if dated.Protocol != "dated-protected-confirmation-source-v1" || dated.PreviewID == (funds.ID{}) {
			return nil, "", reject("TEMPLATE_SOURCE_WITNESS_INCOMPLETE", nil)
		}
		actual, e := encode(snapshot.forecastInput(365))
		supplied, f := encode(dated.BeforeInput)
		if e != nil || f != nil || string(actual) != string(supplied) {
			return nil, "", reject("TEMPLATE_SOURCE_WITNESS_INCOMPLETE", nil)
		}
		copy, e := planning.CloneForecastInput(dated.BeforeInput)
		if e != nil {
			return nil, "", e
		}
		witness.DatedConfirmationInput = &datedConfirmationSourceV1{Protocol: dated.Protocol, PreviewID: dated.PreviewID, BeforeInput: copy}
	}
	raw, err := encode(witness)
	if err != nil {
		return nil, "", err
	}
	if dated != nil {
		if len(raw) > planning.MaxDatedConfirmationSourceBytesV1 {
			return nil, "", reject("TEMPLATE_PROTECTED_REFERENCE_CAPACITY", nil)
		}
		// Same retained bytea/physical fields as to_jsonb(row). The unchanged
		// native encoder reserves 8KiB for outer metadata (including harmless
		// PostgreSQL JSON spacing). This performs no database or bank action.
		row, e := encode(map[string]any{"environment_id": p.EnvironmentID.String(), "user_id": p.UserID.String(), "id": id.String(), "funds_version": snapshot.FundsVersion, "source_version": snapshot.SourceVersion, "source_hash": witness.SourceHash, "original": `\x` + hex.EncodeToString(raw), "original_hash": Hash(raw), "created_at": snapshot.AsOf.Format(time.RFC3339Nano)})
		if e != nil {
			return nil, "", e
		}
		if e = executionaudit.ValidateDatedSourceRowCapacityV1(row); e != nil {
			return nil, "", reject("TEMPLATE_PROTECTED_REFERENCE_CAPACITY", e)
		}
	}
	hash := Hash(raw)
	_, err = tx.Exec(ctx, `INSERT INTO template_source_witnesses(environment_id,user_id,id,funds_version,source_version,source_hash,original,original_hash,created_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9)`, p.EnvironmentID.String(), p.UserID.String(), id.String(), snapshot.FundsVersion, snapshot.SourceVersion, witness.SourceHash, raw, hash, snapshot.AsOf)
	if err != nil {
		return nil, "", err
	}
	return &id, hash, nil
}
