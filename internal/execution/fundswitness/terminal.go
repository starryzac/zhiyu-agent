// Package fundswitness defines forward immutable evidence contracts shared by
// deterministic writers and the independent audit interpreter. It performs no
// database, clock, permission or bank action.
package fundswitness

import (
	"time"

	funds "zhiyu.local/zhiyu-go/internal/funds/domain"
	policy "zhiyu.local/zhiyu-go/internal/policy/domain"
)

const TerminalProtocol = "funds-terminal-decision-v1"

const (
	BankRejectedFinal      = "BANK_REJECTED_FINAL"
	TemplatePolicyInactive = "TEMPLATE_POLICY_INACTIVE"
	NativeGrantNotActive   = "NATIVE_GRANT_NOT_ACTIVE"
	UnsupportedCause       = "UNSUPPORTED"
)

type Boundary struct {
	FundsVersion     uint64 `json:"funds_version"`
	SourceVersion    uint64 `json:"source_version"`
	WriterGeneration uint64 `json:"writer_generation"`
	ControlVersion   uint64 `json:"control_version"`
	CommitHash       string `json:"commit_hash"`
	StateHash        string `json:"state_hash"`
}

// Cause references immutable originals already checked independently. A grant
// event must be present in Before's actual FV; its final state is insufficient.
// A rejected bank observation must be in the terminal FV and match the exact
// independently read original-key result and retained signed T2.
type Cause struct {
	Kind                string    `json:"kind"`
	Code                string    `json:"code"`
	VersionID           *funds.ID `json:"version_id,omitempty"`
	GrantID             *funds.ID `json:"grant_id,omitempty"`
	GrantVersion        uint64    `json:"grant_version,omitempty"`
	EventID             *funds.ID `json:"event_id,omitempty"`
	EventSequence       uint64    `json:"event_sequence,omitempty"`
	EventOriginalHash   string    `json:"event_original_hash,omitempty"`
	BankObservationID   *funds.ID `json:"bank_observation_id,omitempty"`
	BankObservationHash string    `json:"bank_observation_hash,omitempty"`
}

type TerminalDecision struct {
	Protocol             string                    `json:"protocol"`
	ID                   funds.ID                  `json:"id"`
	Scope                policy.TemplateOwnerScope `json:"scope"`
	Namespace            string                    `json:"namespace"`
	LedgerKind           string                    `json:"ledger_kind"`
	OperationID          funds.ID                  `json:"operation_id"`
	ReservedFundsVersion uint64                    `json:"reserved_funds_version"`
	Before               Boundary                  `json:"before"`
	TerminalFundsVersion uint64                    `json:"terminal_funds_version"`
	TerminalState        string                    `json:"terminal_state"`
	BankRequestHash      string                    `json:"bank_request_hash"`
	PermitSignatureHash  string                    `json:"permit_signature_hash,omitempty"`
	ResourceVectorHash   string                    `json:"resource_vector_hash"`
	ResourceRowCount     int                       `json:"resource_row_count"`
	DecisionAt           time.Time                 `json:"decision_at"`
	Cause                Cause                     `json:"cause"`
}
