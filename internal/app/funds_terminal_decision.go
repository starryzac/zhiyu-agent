package app

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"zhiyu.local/zhiyu-go/internal/execution/bankv2"
	execution "zhiyu.local/zhiyu-go/internal/execution/domain"
	"zhiyu.local/zhiyu-go/internal/execution/fundswitness"
	funds "zhiyu.local/zhiyu-go/internal/funds/domain"
)

func terminalDecisionEnabled(ctx context.Context, tx pgx.Tx) (bool, error) {
	var enabled bool
	err := tx.QueryRow(ctx, `SELECT to_regclass('public.funds_terminal_decisions') IS NOT NULL`).Scan(&enabled)
	return enabled, err
}

// The mutable projection is useful only after its full hash has been anchored
// to the immutable commit at this exact, locked user version.
func terminalFundsPrefix(ctx context.Context, tx pgx.Tx, p Principal) (fundswitness.Boundary, map[string]map[string]string, error) {
	var b fundswitness.Boundary
	var raw []byte
	var anchored bool
	err := tx.QueryRow(ctx, `SELECT u.funds_version,u.source_version,e.writer_generation,e.control_version,
 w.original_hash::text,convert_from(w.original,'UTF8')::jsonb->>'state_hash',c.financial_rows,
 funds_witness_state_hash(c.financial_rows)=c.state_hash AND c.state_hash::text=convert_from(w.original,'UTF8')::jsonb->>'state_hash'
 FROM users u JOIN environments e ON e.id=u.environment_id
 JOIN funds_commit_witnesses w ON(w.environment_id=u.environment_id AND w.user_id=u.id AND w.funds_version=u.funds_version)
 JOIN funds_commit_projection_cache c ON(c.environment_id=w.environment_id AND c.user_id=w.user_id AND c.funds_version=w.funds_version)
 WHERE u.environment_id=$1 AND u.id=$2`, p.EnvironmentID.String(), p.UserID.String()).Scan(&b.FundsVersion, &b.SourceVersion, &b.WriterGeneration, &b.ControlVersion, &b.CommitHash, &b.StateHash, &raw, &anchored)
	if err != nil {
		return b, nil, err
	}
	var rows map[string]map[string]string
	if !anchored || json.Unmarshal(raw, &rows) != nil {
		return b, nil, reject("TERMINAL_FUNDS_PREFIX_INVALID", nil)
	}
	return b, rows, nil
}

// Call after writing the terminal operation status, before the same existing
// funds-version increment. Older schemas retain their original protocol. An
// operation with no RESERVED resource in the before prefix has no release
// decision to seal (for example an unmaterialized bridge suffix).
func (s *Service) recordFundsTerminalDecision(ctx context.Context, tx pgx.Tx, p Principal, kind string, operation funds.ID, terminal string, cause fundswitness.Cause) error {
	enabled, err := terminalDecisionEnabled(ctx, tx)
	if err != nil || !enabled {
		return err
	}
	before, _, err := terminalFundsPrefix(ctx, tx, p)
	if err != nil {
		return err
	}
	var resources string
	var count int
	err = tx.QueryRow(ctx, `WITH r AS(SELECT funds_witness_operation_resources(financial_rows,$4,$3) v
 FROM funds_commit_projection_cache WHERE environment_id=$1 AND user_id=$2 AND funds_version=$5)
 SELECT funds_witness_state_hash(v),(SELECT count(*) FROM jsonb_each(v)t CROSS JOIN LATERAL jsonb_each(t.value)x) FROM r`, p.EnvironmentID.String(), p.UserID.String(), operation.String(), kind, before.FundsVersion).Scan(&resources, &count)
	if err != nil || count == 0 {
		return err
	}
	var query string
	switch kind {
	case "LEGACY":
		query = `SELECT reserved_funds_version,bank_request_hash::text,permit_signature,status,updated_at FROM operations WHERE environment_id=$1 AND user_id=$2 AND id=$3`
	case "NATIVE":
		query = `SELECT reserved_funds_version,bank_request_hash::text,permit_signature,status,updated_at FROM native_operations WHERE environment_id=$1 AND user_id=$2 AND id=$3`
	default:
		return reject("TERMINAL_LEDGER_KIND_INVALID", nil)
	}
	var reserved uint64
	var requestHash, state string
	var signature *string
	var decisionAt time.Time
	if err = tx.QueryRow(ctx, query, p.EnvironmentID.String(), p.UserID.String(), operation.String()).Scan(&reserved, &requestHash, &signature, &state, &decisionAt); err != nil {
		return err
	}
	if state != terminal || (terminal != "CANCELLED" && terminal != "REJECTED") || (terminal == "CANCELLED" && signature != nil) || (terminal == "REJECTED" && (signature == nil || *signature == "")) {
		return reject("TERMINAL_DECISION_STATE_INVALID", nil)
	}
	id, err := newID()
	if err != nil {
		return err
	}
	d := fundswitness.TerminalDecision{Protocol: fundswitness.TerminalProtocol, ID: id, Scope: nativeAutomationScope(p), Namespace: s.Namespace, LedgerKind: kind, OperationID: operation, ReservedFundsVersion: reserved, Before: before, TerminalFundsVersion: before.FundsVersion + 1, TerminalState: terminal, BankRequestHash: requestHash, ResourceVectorHash: resources, ResourceRowCount: count, DecisionAt: decisionAt, Cause: cause}
	if signature != nil {
		d.PermitSignatureHash = Hash([]byte(*signature))
	}
	raw, err := encode(d)
	if err != nil {
		return err
	}
	_, err = tx.Exec(ctx, `INSERT INTO funds_terminal_decisions(environment_id,user_id,id,ledger_kind,operation_id,previous_funds_version,terminal_funds_version,original,original_hash,recorded_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`, p.EnvironmentID.String(), p.UserID.String(), id.String(), kind, operation.String(), before.FundsVersion, d.TerminalFundsVersion, raw, Hash(raw), d.DecisionAt)
	return err
}

func bankRejectionCause(ctx context.Context, tx pgx.Tx, p Principal, operation funds.ID, kind, code string, raw []byte) (fundswitness.Cause, error) {
	cause := fundswitness.Cause{Kind: fundswitness.BankRejectedFinal, Code: code}
	enabled, err := terminalDecisionEnabled(ctx, tx)
	if err != nil || !enabled {
		return cause, err
	}
	var query string
	if kind == "NATIVE" {
		query = `SELECT id::text FROM native_bank_observations WHERE environment_id=$1 AND user_id=$2 AND operation_id=$3 AND status='REJECTED' AND original=$4 ORDER BY id LIMIT 1`
	} else if kind == "LEGACY" {
		query = `SELECT id::text FROM bank_observations WHERE environment_id=$1 AND user_id=$2 AND operation_id=$3 AND status='REJECTED' AND original=$4 ORDER BY id LIMIT 1`
	} else {
		return cause, reject("TERMINAL_LEDGER_KIND_INVALID", nil)
	}
	var text string
	if err = tx.QueryRow(ctx, query, p.EnvironmentID.String(), p.UserID.String(), operation.String(), raw).Scan(&text); err != nil {
		return cause, err
	}
	id, err := funds.ParseID(text)
	if err != nil {
		return cause, err
	}
	cause.BankObservationID, cause.BankObservationHash = &id, Hash(raw)
	return cause, nil
}

func (s *Service) nativeBankRejectionCause(ctx context.Context, tx pgx.Tx, p Principal, operation funds.ID, result bankv2.Result) (fundswitness.Cause, error) {
	if result.Status != bankv2.Rejected || !result.AbsenceIsFinal {
		return fundswitness.Cause{}, reject("EVIDENCE_INVALID", nil)
	}
	raw, err := encode(result)
	if err != nil {
		return fundswitness.Cause{}, err
	}
	return bankRejectionCause(ctx, tx, p, operation, "NATIVE", result.RejectionCode, raw)
}

func (s *Service) legacyBankRejectionCause(ctx context.Context, tx pgx.Tx, p Principal, operation funds.ID, result execution.BankResult) (fundswitness.Cause, error) {
	if result.Status != execution.BankRejected || !result.AbsenceIsFinal {
		return fundswitness.Cause{}, reject("EVIDENCE_INVALID", nil)
	}
	raw, err := encode(result)
	if err != nil {
		return fundswitness.Cause{}, err
	}
	return bankRejectionCause(ctx, tx, p, operation, "LEGACY", result.RejectionCode, raw)
}

func (s *Service) recordNativeCancellation(ctx context.Context, tx pgx.Tx, p Principal, operation funds.ID, reason string) error {
	cause, err := s.nativeTerminalCancellationCause(ctx, tx, p, operation, reason)
	if err != nil {
		return err
	}
	return s.recordFundsTerminalDecision(ctx, tx, p, "NATIVE", operation, "CANCELLED", cause)
}

func (s *Service) recordNativeRejection(ctx context.Context, tx pgx.Tx, p Principal, operation funds.ID, result bankv2.Result) error {
	cause, err := s.nativeBankRejectionCause(ctx, tx, p, operation, result)
	if err != nil {
		return err
	}
	return s.recordFundsTerminalDecision(ctx, tx, p, "NATIVE", operation, "REJECTED", cause)
}

// Joint suffix handling receives an already verified rejection through its
// existing caller. Reopen that retained observation under the original key;
// never manufacture a bank result from an operation's mutable status.
func (s *Service) recordNativeObservedRejection(ctx context.Context, tx pgx.Tx, p Principal, operation funds.ID) error {
	enabled, err := terminalDecisionEnabled(ctx, tx)
	if err != nil || !enabled {
		return err
	}
	var requestRaw, observationRaw []byte
	if err = tx.QueryRow(ctx, `SELECT o.bank_request,b.original FROM native_operations o JOIN native_bank_observations b ON(b.environment_id=o.environment_id AND b.user_id=o.user_id AND b.operation_id=o.id AND b.status='REJECTED') WHERE o.environment_id=$1 AND o.user_id=$2 AND o.id=$3 ORDER BY b.observed_at DESC,b.id LIMIT 1`, p.EnvironmentID.String(), p.UserID.String(), operation.String()).Scan(&requestRaw, &observationRaw); err != nil {
		return err
	}
	var request bankv2.Request
	var result bankv2.Result
	if decode(requestRaw, &request) != nil || decode(observationRaw, &result) != nil || bankv2.VerifyResult(request, result) != nil {
		return reject("EVIDENCE_INVALID", nil)
	}
	return s.recordNativeRejection(ctx, tx, p, operation, result)
}

// Unsupported causes are retained explicitly. A later auditor must return
// precise INCOMPLETE for them, rather than infer a cause from today's state.
func (s *Service) nativeTerminalCancellationCause(ctx context.Context, tx pgx.Tx, p Principal, operation funds.ID, reason string) (fundswitness.Cause, error) {
	cause := fundswitness.Cause{Kind: fundswitness.UnsupportedCause, Code: reason}
	enabled, err := terminalDecisionEnabled(ctx, tx)
	if err != nil || !enabled {
		return cause, err
	}
	before, prefix, err := terminalFundsPrefix(ctx, tx, p)
	if err != nil {
		return cause, err
	}
	var requestRaw []byte
	var dependenciesRaw []byte
	var grantText *string
	var grantVersion *uint64
	err = tx.QueryRow(ctx, `SELECT bank_request,dependencies,grant_id::text,grant_version FROM native_operations WHERE environment_id=$1 AND user_id=$2 AND id=$3`, p.EnvironmentID.String(), p.UserID.String(), operation.String()).Scan(&requestRaw, &dependenciesRaw, &grantText, &grantVersion)
	if err != nil {
		return cause, err
	}
	if reason == fundswitness.NativeGrantNotActive && grantText != nil && grantVersion != nil {
		for _, raw := range prefix["native_grant_state_events"] {
			var row struct {
				GrantID      string   `json:"grant_id"`
				GrantVersion uint64   `json:"grant_version"`
				ID           funds.ID `json:"id"`
				Sequence     uint64   `json:"sequence"`
				NewState     string   `json:"new_state"`
				OriginalHash string   `json:"original_hash"`
			}
			if json.Unmarshal([]byte(raw), &row) != nil || row.GrantID != *grantText || row.GrantVersion != *grantVersion || row.NewState == "ACTIVE" {
				continue
			}
			for _, stateRaw := range prefix["native_grant_states"] {
				var state struct {
					GrantID      string   `json:"grant_id"`
					GrantVersion uint64   `json:"grant_version"`
					EventID      funds.ID `json:"event_id"`
					Sequence     uint64   `json:"sequence"`
				}
				if json.Unmarshal([]byte(stateRaw), &state) == nil && state.GrantID == row.GrantID && state.GrantVersion == row.GrantVersion && state.EventID == row.ID && state.Sequence == row.Sequence {
					id, parseErr := funds.ParseID(row.GrantID)
					if parseErr != nil {
						return cause, parseErr
					}
					return fundswitness.Cause{Kind: fundswitness.NativeGrantNotActive, Code: reason, GrantID: &id, GrantVersion: row.GrantVersion, EventID: &row.ID, EventSequence: row.Sequence, EventOriginalHash: row.OriginalHash}, nil
				}
			}
		}
		return cause, nil
	}
	switch reason {
	case "TEMPLATE_POLICY_INACTIVE", "PAYMENT_POLICY_NOT_ACTIVE", "ASSET_POLICY_NOT_ACTIVE":
	case "SOURCE_CHANGED":
		// Some workers reject the changed source watermark before reading the
		// paused rule. Prove that mismatch and the related lifecycle below.
		var dependencies struct {
			SourceVersion uint64 `json:"source_evidence_version"`
		}
		if json.Unmarshal(dependenciesRaw, &dependencies) != nil || dependencies.SourceVersion == 0 || dependencies.SourceVersion == before.SourceVersion {
			return cause, nil
		}
	default:
		return cause, nil
	}
	var request bankv2.Request
	if json.Unmarshal(requestRaw, &request) != nil {
		return cause, reject("EVIDENCE_INVALID", nil)
	}
	for _, authority := range request.Authorities {
		for _, raw := range prefix["template_policy_versions"] {
			var version struct {
				ID       funds.ID `json:"id"`
				PolicyID string   `json:"policy_id"`
				Version  int64    `json:"version"`
				State    string   `json:"state"`
				EventID  funds.ID `json:"status_event_id"`
				Sequence uint64   `json:"status_sequence"`
			}
			if json.Unmarshal([]byte(raw), &version) != nil || version.PolicyID != authority.PolicyID || version.Version != authority.PolicyVersion || version.State == "ACTIVE" {
				continue
			}
			for _, eventRaw := range prefix["template_policy_status_events"] {
				var event struct {
					ID           funds.ID `json:"id"`
					VersionID    funds.ID `json:"version_id"`
					Sequence     uint64   `json:"sequence"`
					NewState     string   `json:"new_state"`
					OriginalHash string   `json:"original_hash"`
				}
				if json.Unmarshal([]byte(eventRaw), &event) == nil && event.ID == version.EventID && event.VersionID == version.ID && event.Sequence == version.Sequence && event.NewState == version.State {
					return fundswitness.Cause{Kind: fundswitness.TemplatePolicyInactive, Code: reason, VersionID: &version.ID, EventID: &event.ID, EventSequence: event.Sequence, EventOriginalHash: event.OriginalHash}, nil
				}
			}
		}
	}
	return cause, nil
}

func (s *Service) sealNativeGrantAuthority(ctx context.Context, tx pgx.Tx, p Principal) error {
	enabled, err := terminalDecisionEnabled(ctx, tx)
	if err != nil || !enabled {
		return err
	}
	tag, err := tx.Exec(ctx, `UPDATE users SET funds_version=funds_version+1 WHERE environment_id=$1 AND id=$2`, p.EnvironmentID.String(), p.UserID.String())
	if err = assertOne(tag, err); err != nil {
		return fmt.Errorf("seal native grant authority: %w", err)
	}
	return nil
}

// Bind the USER original itself to its actual admission boundary. Moving a
// lifecycle delta together with a later cancellation must not reassign when
// that original permission event became available.
func fundsAuthorityAdmission(ctx context.Context, tx pgx.Tx, p Principal) (*fundswitness.Boundary, error) {
	enabled, err := terminalDecisionEnabled(ctx, tx)
	if err != nil || !enabled {
		return nil, err
	}
	before, _, err := terminalFundsPrefix(ctx, tx, p)
	if err != nil {
		return nil, err
	}
	return &before, nil
}
