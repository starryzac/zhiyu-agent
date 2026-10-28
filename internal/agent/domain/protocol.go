// Package domain defines the finite Agent protocol. It has no model, storage,
// HTTP or wall-clock dependency and cannot create financial authority.
package domain

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"time"
	"unicode/utf8"

	"zhiyu.local/zhiyu-go/internal/audit"
	funds "zhiyu.local/zhiyu-go/internal/funds/domain"
)

var (
	ErrInvalid   = errors.New("AGENT_INVALID_INPUT")
	ErrTool      = errors.New("AGENT_TOOL_REJECTED")
	ErrReference = errors.New("AGENT_REFERENCE_REJECTED")
	ErrStale     = errors.New("AGENT_STALE_REFERENCE")
	ErrBudget    = errors.New("AGENT_BUDGET_EXCEEDED")
)

const MaxJSONBytes = 8192

type Scope struct {
	EnvironmentID funds.ID
	UserID        funds.ID
}
type Account struct {
	ID        string      `json:"id"`
	Name      string      `json:"name"`
	Balance   funds.Money `json:"balance_cents"`
	GoalOwned funds.Money `json:"goal_owned_cents"`
}
type Goal struct {
	ID        string      `json:"id"`
	Name      string      `json:"name"`
	AccountID string      `json:"account_id"`
	Target    funds.Money `json:"target_cents"`
	Assigned  funds.Money `json:"assigned_cents"`
}
type Policy struct {
	ID         string      `json:"id"`
	GoalID     string      `json:"goal_id"`
	Version    uint64      `json:"version"`
	Status     string      `json:"status"`
	MaxAmount  funds.Money `json:"max_amount"`
	ValidUntil time.Time   `json:"valid_until"`
}
type Grant struct {
	ID         string      `json:"id"`
	PolicyID   string      `json:"policy_id"`
	Status     string      `json:"status"`
	MaxAmount  funds.Money `json:"max_amount"`
	ValidUntil time.Time   `json:"valid_until"`
}
type Operation struct {
	ID                 string      `json:"id"`
	PlanID             string      `json:"plan_id"`
	State              string      `json:"state"`
	Amount             funds.Money `json:"amount_cents"`
	Version            uint64      `json:"version"`
	ReceiptID          string      `json:"receipt_id,omitempty"`
	BankObservedStatus string      `json:"bank_observed_status,omitempty"`
	ProcessingHealth   string      `json:"processing_health"`
}

// Snapshot must come from a server-owned, scoped, consistent current read. It
// is a display projection, never an execution bound or an authorization proof.
type Snapshot struct {
	Scope      Scope          `json:"-"`
	AsOf       time.Time      `json:"as_of"`
	Accounts   []Account      `json:"accounts"`
	Goals      []Goal         `json:"goals"`
	Policies   []Policy       `json:"policies"`
	Grants     []Grant        `json:"grants"`
	Operations []Operation    `json:"operations"`
	Native     *NativeContext `json:"-"`
}
type Reference struct {
	Kind   string `json:"kind"`
	ID     string `json:"id"`
	Digest string `json:"digest"`
}
type Candidate struct {
	Template           string    `json:"template"`
	GoalID             string    `json:"goal_id"`
	Reference          Reference `json:"reference"`
	RequiresUserFields bool      `json:"requires_user_fields"`
	BankAuthority      bool      `json:"bank_authority"`
}
type ToolCall struct {
	Name      string          `json:"name"`
	Arguments json.RawMessage `json:"arguments"`
}
type Turn struct {
	Mode string    `json:"mode"`
	Text string    `json:"text,omitempty"`
	Tool *ToolCall `json:"tool,omitempty"`
}

func (turn *Turn) UnmarshalJSON(raw []byte) error {
	parsed, err := DecodeTurn(raw)
	if err == nil {
		*turn = parsed
	}
	return err
}

type Observation struct {
	Tool              string                 `json:"tool"`
	AsOf              time.Time              `json:"as_of"`
	Summary           string                 `json:"summary"`
	VerificationScope string                 `json:"verification_scope"`
	References        []Reference            `json:"references"`
	Accounts          []Account              `json:"accounts,omitempty"`
	Goals             []Goal                 `json:"goals,omitempty"`
	Policies          []Policy               `json:"policies,omitempty"`
	Grants            []Grant                `json:"grants,omitempty"`
	Operations        []Operation            `json:"operations,omitempty"`
	Candidate         *Candidate             `json:"candidate,omitempty"`
	NativeCandidate   *TemplateCandidate     `json:"native_candidate,omitempty"`
	NativeRules       []NativeRule           `json:"native_rules,omitempty"`
	NativeGrants      *NativeGrantCollection `json:"native_grants,omitempty"`
	NativeGrant       *NativeGrantDisplay    `json:"native_grant,omitempty"`
	Catalog           []TemplateDescriptor   `json:"catalog,omitempty"`
	Forecast          *ForecastObservation   `json:"forecast,omitempty"`
	Joint             *JointObservation      `json:"joint,omitempty"`
	Object            *ObjectObservation     `json:"object,omitempty"`
	Objects           []ObjectObservation    `json:"objects,omitempty"`
}
type ToolSchema struct {
	Name        string          `json:"name"`
	Description string          `json:"description"`
	Parameters  json.RawMessage `json:"parameters"`
}

// Registry is rebuilt on every call so a provider cannot mutate future tools.
func Registry() []ToolSchema {
	empty := json.RawMessage(`{"type":"object","additionalProperties":false,"properties":{},"required":[]}`)
	goal := json.RawMessage(`{"type":"object","additionalProperties":false,"properties":{"goal_id":{"type":"string","format":"uuid"}},"required":["goal_id"]}`)
	operation := json.RawMessage(`{"type":"object","additionalProperties":false,"properties":{"operation_id":{"type":"string","format":"uuid"}},"required":["operation_id"]}`)
	legacy := []ToolSchema{
		{"funds_summary", "Read owned current account display values; no safe execution amount is inferred.", append(json.RawMessage(nil), empty...)},
		{"current_rules", "Read only current simple single-goal policy and grant display values. Native template rules use native_rules. Native standing grants are not fully read here; check the rules page. Never grant or restore authority.", append(json.RawMessage(nil), empty...)},
		{"goal_status", "Read one existing owned goal by exact reference.", append(json.RawMessage(nil), goal...)},
		{"operation_status", "Read one existing owned original operation; UNKNOWN remains unresolved.", operation},
		{"policy_candidate", "Suggest an existing single goal form; user must supply fields and confirm separately.", append(json.RawMessage(nil), goal...)},
	}
	return append(legacy, nativeRegistry()...)
}

func exactObject(raw []byte, allowed ...string) (map[string]any, error) {
	if len(raw) == 0 || len(raw) > MaxJSONBytes || !utf8.Valid(raw) {
		return nil, ErrInvalid
	}
	object, err := audit.ParseRawObject(raw)
	if err != nil {
		return nil, ErrInvalid
	}
	for key := range object {
		found := false
		for _, name := range allowed {
			if key == name {
				found = true
				break
			}
		}
		if !found {
			return nil, ErrInvalid
		}
	}
	return object, nil
}
func exactID(value string) bool {
	id, err := funds.ParseID(value)
	return err == nil && id != (funds.ID{}) && id.String() == value
}
func decodeCall(raw []byte) (ToolCall, error) {
	object, err := exactObject(raw, "name", "arguments")
	if err != nil || len(object) != 2 {
		return ToolCall{}, ErrTool
	}
	var call ToolCall
	if err = json.Unmarshal(raw, &call); err != nil {
		return call, ErrTool
	}
	if _, err = argumentID(call); err != nil {
		return call, err
	}
	return call, nil
}
func DecodeTurn(raw []byte) (Turn, error) {
	object, err := exactObject(raw, "mode", "text", "tool")
	if err != nil {
		return Turn{}, err
	}
	var turn Turn
	type wireTurn Turn
	if json.Unmarshal(raw, (*wireTurn)(&turn)) != nil {
		return turn, ErrInvalid
	}
	switch turn.Mode {
	case "OFFLINE":
		if len(object) != 2 || object["tool"] == nil || turn.Text != "" {
			return turn, ErrInvalid
		}
		var pieces map[string]json.RawMessage
		if json.Unmarshal(raw, &pieces) != nil {
			return turn, ErrInvalid
		}
		call, err := decodeCall(pieces["tool"])
		if err != nil {
			return turn, err
		}
		turn.Tool = &call
	case "MODEL":
		if len(object) != 2 || turn.Tool != nil || object["text"] == nil || turn.Text == "" || len(turn.Text) > 4096 {
			return turn, ErrInvalid
		}
	default:
		return turn, ErrInvalid
	}
	return turn, nil
}

// Model replies select a registered tool or finish. Free prose, authority,
// amounts, URLs, multiple tools and invented reference digests are rejected.
func DecodeReply(raw []byte) (*ToolCall, bool, error) {
	object, err := exactObject(raw, "done", "tool")
	if err != nil || len(object) != 1 {
		return nil, false, ErrTool
	}
	if done, ok := object["done"]; ok {
		if done != true {
			return nil, false, ErrTool
		}
		return nil, true, nil
	}
	var pieces map[string]json.RawMessage
	if json.Unmarshal(raw, &pieces) != nil {
		return nil, false, ErrTool
	}
	call, err := decodeCall(pieces["tool"])
	return &call, false, err
}

func argumentID(call ToolCall) (string, error) {
	var key string
	switch call.Name {
	case "funds_summary", "current_rules":
		object, err := exactObject(call.Arguments)
		if err != nil || len(object) != 0 {
			return "", ErrTool
		}
		return "", nil
	case "goal_status", "policy_candidate":
		key = "goal_id"
	case "operation_status":
		key = "operation_id"
	default:
		return nativeArguments(call)
	}
	object, err := exactObject(call.Arguments, key)
	if err != nil || len(object) != 1 {
		return "", ErrTool
	}
	id, ok := object[key].(string)
	if !ok || !exactID(id) {
		return "", ErrTool
	}
	return id, nil
}
func makeRef(kind, id string, value any) Reference {
	raw, _ := json.Marshal(value) // Only validated closed structs enter this helper.
	digest := sha256.Sum256(raw)
	return Reference{kind, id, hex.EncodeToString(digest[:])}
}
func (s Snapshot) References() []Reference {
	refs := make([]Reference, 0, len(s.Accounts)+len(s.Goals)+len(s.Policies)+len(s.Grants)+len(s.Operations))
	for _, v := range s.Accounts {
		refs = append(refs, makeRef("ACCOUNT", v.ID, v))
	}
	for _, v := range s.Goals {
		refs = append(refs, makeRef("GOAL", v.ID, v))
	}
	for _, v := range s.Policies {
		refs = append(refs, makeRef("POLICY", v.ID, v))
	}
	for _, v := range s.Grants {
		refs = append(refs, makeRef("GRANT", v.ID, v))
	}
	for _, v := range s.Operations {
		refs = append(refs, makeRef("OPERATION", v.ID, v))
	}
	refs = append(refs, makeRef("ACCOUNTS", s.Scope.UserID.String(), s.Accounts), makeRef("RULES", s.Scope.UserID.String(), struct {
		Policies []Policy
		Grants   []Grant
	}{s.Policies, s.Grants}))
	return append(refs, s.nativeReferences()...)
}
func (s Snapshot) Validate(scope Scope) error {
	if scope.EnvironmentID == (funds.ID{}) || scope.UserID == (funds.ID{}) || scope != s.Scope || s.AsOf.IsZero() || len(s.Accounts) > 100 || len(s.Goals) > 100 || len(s.Policies) > 100 || len(s.Grants) > 100 || len(s.Operations) > 20 {
		return ErrReference
	}
	seen := map[string]bool{}
	for _, ref := range s.References() {
		if !exactID(ref.ID) || seen[ref.Kind+ref.ID] {
			return ErrReference
		}
		seen[ref.Kind+ref.ID] = true
	}
	name := func(v string) bool { return utf8.ValidString(v) && len(v) <= 256 }
	for _, v := range s.Accounts {
		if !name(v.Name) || v.GoalOwned.Cents() > v.Balance.Cents() {
			return ErrReference
		}
	}
	for _, v := range s.Goals {
		if !name(v.Name) || !seen["ACCOUNT"+v.AccountID] {
			return ErrReference
		}
	}
	status := func(v string) bool { return v == "ACTIVE" || v == "PAUSED" || v == "REVOKED" || v == "EXPIRED" }
	for _, v := range s.Policies {
		if v.Version == 0 || !status(v.Status) || !seen["GOAL"+v.GoalID] || v.ValidUntil.IsZero() {
			return ErrReference
		}
	}
	for _, v := range s.Grants {
		if !status(v.Status) || !seen["POLICY"+v.PolicyID] || v.ValidUntil.IsZero() {
			return ErrReference
		}
	}
	for _, v := range s.Operations {
		if !exactID(v.PlanID) || v.Version == 0 {
			return ErrReference
		}
		switch v.State {
		case "QUEUED", "SUBMITTING", "PENDING_SETTLEMENT", "UNKNOWN", "RECONCILING", "SETTLED", "REJECTED", "CANCELLED":
		default:
			return ErrReference
		}
		if v.ReceiptID != "" && !exactID(v.ReceiptID) {
			return ErrReference
		}
		if v.State == "SETTLED" && v.ReceiptID == "" {
			return ErrReference
		}
		if len(v.BankObservedStatus) > 64 || len(v.ProcessingHealth) > 64 {
			return ErrReference
		}
	}
	return s.validateNative()
}

func Observe(s Snapshot, call ToolCall) (Observation, error) {
	if err := s.Validate(s.Scope); err != nil {
		return Observation{}, err
	}
	id, err := argumentID(call)
	if err != nil {
		return Observation{}, err
	}
	if nativeTool(call.Name) {
		return observeNative(s, call)
	}
	v := Observation{Tool: call.Name, AsOf: s.AsOf, VerificationScope: "DISPLAY_SNAPSHOT", References: []Reference{}}
	switch call.Name {
	case "funds_summary":
		v.Accounts = append([]Account(nil), s.Accounts...)
		v.Summary = fmt.Sprintf("已读取 %d 个本人账户的当前账面显示。账面余额不代表本次可执行上限；资金保护与执行须另行确定性核验。", len(s.Accounts))
		for _, x := range s.Accounts {
			v.References = append(v.References, makeRef("ACCOUNT", x.ID, x))
		}
		v.References = append(v.References, makeRef("ACCOUNTS", s.Scope.UserID.String(), s.Accounts))
	case "current_rules":
		v.Policies, v.Grants = append([]Policy(nil), s.Policies...), append([]Grant(nil), s.Grants...)
		v.Summary = fmt.Sprintf("简式单目标规则与授权范围：已读取 %d 条规则与 %d 条持续授权的显示状态。原生模板规则请使用“读取现行原生规则”；原生持续授权未在此完整读取，请到规则页核对。此读取不新增或恢复授权，撤销后的在途原操作仍须核对。", len(s.Policies), len(s.Grants))
		for _, x := range s.Policies {
			v.References = append(v.References, makeRef("POLICY", x.ID, x))
		}
		for _, x := range s.Grants {
			v.References = append(v.References, makeRef("GRANT", x.ID, x))
		}
		v.References = append(v.References, makeRef("RULES", s.Scope.UserID.String(), struct {
			Policies []Policy
			Grants   []Grant
		}{s.Policies, s.Grants}))
	case "goal_status", "policy_candidate":
		for _, x := range s.Goals {
			if x.ID == id {
				ref := makeRef("GOAL", x.ID, x)
				v.Goals, v.References = []Goal{x}, []Reference{ref}
				v.Summary = "已读取所选目标的当前归属与进度。未来收入不会因此变为今日可用资金。"
				if call.Name == "policy_candidate" {
					v.Candidate = &Candidate{"SINGLE_GOAL", x.ID, ref, true, false}
					v.Summary = "已整理单目标规则草稿入口。请本人填写单次上限并在规则表单明确确认；此草稿尚未生效，也未授予执行权限。"
				}
				return v, nil
			}
		}
		return Observation{}, ErrReference
	case "operation_status":
		for _, x := range s.Operations {
			if x.ID == id {
				v.Operations, v.References = []Operation{x}, []Reference{makeRef("OPERATION", x.ID, x)}
				v.Summary = "已读取这笔原操作的当前状态。未结清时继续保留原键；NOT_FOUND、超时或撤销均不证明无效果。"
				if x.State == "SETTLED" {
					v.Summary = "这笔原操作已结清并具有回执引用，目标进度以最新服务端读数为准。"
				}
				return v, nil
			}
		}
		return Observation{}, ErrReference
	}
	return v, nil
}

func CheckReferences(scope Scope, fresh Snapshot, observations []Observation) error {
	if fresh.Validate(scope) != nil {
		return ErrReference
	}
	refs := fresh.References()
	for _, observation := range observations {
		if fresh.AsOf.Before(observation.AsOf) {
			return ErrStale
		}
		for _, original := range observation.References {
			found := false
			for _, current := range refs {
				if current == original {
					found = true
					break
				}
			}
			if !found {
				return ErrStale
			}
		}
	}
	return nil
}

// CloneSnapshot severs mutable slice aliases supplied by adapters/providers.
func CloneSnapshot(s Snapshot) Snapshot {
	s.Accounts = slices.Clone(s.Accounts)
	s.Goals = slices.Clone(s.Goals)
	s.Policies = slices.Clone(s.Policies)
	s.Grants = slices.Clone(s.Grants)
	s.Operations = slices.Clone(s.Operations)
	s.Native = cloneNative(s.Native)
	return s
}
