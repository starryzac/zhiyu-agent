// Package agent coordinates read-only current observations and an optional
// provider. It owns no financial write, USER confirmation or payment interface.
package agent

import (
	"context"
	"encoding/json"
	"errors"

	"zhiyu.local/zhiyu-go/internal/agent/domain"
)

var ErrProviderNotConfigured = errors.New("AGENT_PROVIDER_NOT_CONFIGURED")
var ErrProvider = errors.New("AGENT_PROVIDER_FAILED")

type Reader interface {
	Snapshot(context.Context, domain.Scope) (domain.Snapshot, error)
}
type ReaderFunc func(context.Context, domain.Scope) (domain.Snapshot, error)

func (f ReaderFunc) Snapshot(ctx context.Context, scope domain.Scope) (domain.Snapshot, error) {
	return f(ctx, scope)
}

// Provider receives only a finite server-built JSON payload, never session
// tokens, bank keys, receipt originals, credentials or connection settings.
// Native tools may receive opaque owned account IDs required by typed fields.
// Real adapters must enforce the supplied output and input reservation bounds.
type Provider interface {
	Generate(context.Context, ProviderRequest) (ProviderReply, error)
}
type ProviderRequest struct {
	Payload         json.RawMessage
	InputTokenBound int64
	MaxOutputTokens int64
}
type ProviderReply struct {
	JSON         json.RawMessage
	InputTokens  int64
	OutputTokens int64
}
type Service struct {
	reader       Reader
	provider     Provider
	limits       domain.Limits
	providerSlot chan struct{}
}

func New(reader Reader, provider Provider, limits domain.Limits) (*Service, error) {
	if reader == nil || limits.Validate() != nil {
		return nil, domain.ErrInvalid
	}
	return &Service{reader, provider, limits, make(chan struct{}, 1)}, nil
}

type Status struct {
	Mode               string `json:"mode"`
	ProviderStatus     string `json:"provider_status"`
	ProviderConfigured bool   `json:"provider_configured"`
	Authority          bool   `json:"authority"`
}

func (s *Service) Status() Status {
	if s.provider == nil {
		return Status{"OFFLINE", "NOT_RUN", false, false}
	}
	return Status{"MODEL_AVAILABLE", "CONFIGURED_NOT_VERIFIED", true, false}
}

type Result struct {
	Mode            string                    `json:"mode"`
	ProviderStatus  string                    `json:"provider_status"`
	ModelUsed       bool                      `json:"model_used"`
	Observations    []domain.Observation      `json:"observations"`
	Candidate       *domain.Candidate         `json:"candidate,omitempty"`
	NativeCandidate *domain.TemplateCandidate `json:"native_candidate,omitempty"`
	References      []domain.Reference        `json:"references"`
	Budget          domain.Budget             `json:"budget"`
	ProviderUsage   ProviderUsage             `json:"provider_usage"`
	Authority       bool                      `json:"authority"`
}
type ProviderUsage struct {
	InputTokens   int64 `json:"input_tokens"`
	OutputTokens  int64 `json:"output_tokens"`
	ReportedCalls int   `json:"reported_calls"`
}
type modelInput struct {
	Protocol string              `json:"protocol"`
	Text     string              `json:"text"`
	Tools    []domain.ToolSchema `json:"tools"`
	// Only IDs/kinds/digests are supplied as available references. Names and
	// arbitrary database prose cannot inject tool instructions through this list.
	References     []domain.Reference        `json:"references"`
	Observations   []modelObservation        `json:"observations"`
	ReferenceScope string                    `json:"reference_scope,omitempty"`
	KnownPayees    []domain.KnownPayeeSignal `json:"known_payees,omitempty"`
}
type modelObservation struct {
	Tool        string                      `json:"tool"`
	References  []domain.Reference          `json:"references"`
	Catalog     []domain.TemplateDescriptor `json:"catalog,omitempty"`
	Outcome     *modelOutcome               `json:"outcome,omitempty"`
	NativeRules []modelRuleSignal           `json:"native_rules,omitempty"`
}
type modelRuleSignal struct {
	PolicyID          string `json:"policy_id"`
	VersionID         string `json:"version_id"`
	Version           uint64 `json:"version"`
	Template          string `json:"template_name"`
	State             string `json:"state"`
	EffectiveState    string `json:"effective_state"`
	ConfigurationHash string `json:"configuration_hash"`
}

// Only closed deterministic signals enter the model context. No arbitrary
// database prose, raw bank originals, session or connection data is forwarded.
type modelOutcome struct {
	State             string `json:"state"`
	CurrentSafe       string `json:"current_safe_cents,omitempty"`
	MaximumDeficit    string `json:"maximum_deficit_cents,omitempty"`
	PointCount        int    `json:"point_count,omitempty"`
	ConfigurationHash string `json:"configuration_hash,omitempty"`
	Mode              string `json:"mode,omitempty"`
	BankAuthority     bool   `json:"bank_authority"`
}

func modelObserved(o domain.Observation, native bool) modelObservation {
	v := modelObservation{Tool: o.Tool, References: modelReferences(o.References, native), Catalog: o.Catalog}
	for _, r := range o.NativeRules {
		allowed := false
		for _, ref := range v.References {
			if ref.Kind == "NATIVE_POLICY" && ref.ID == r.Version.PolicyID.String() {
				allowed = true
			}
		}
		if allowed {
			v.NativeRules = append(v.NativeRules, modelRuleSignal{r.Version.PolicyID.String(), r.Version.VersionID.String(), r.Version.Version, string(r.Version.Compiled.Name), r.Version.State, r.EffectiveState, r.Version.Compiled.Hash})
		}
	}
	if o.Forecast != nil {
		v.Outcome = &modelOutcome{State: o.Forecast.State}
		if r := o.Forecast.Result; r != nil {
			v.Outcome.CurrentSafe = r.CurrentSafe.String()
			v.Outcome.MaximumDeficit = r.MaximumDeficit.String()
			v.Outcome.PointCount = len(r.Points)
		}
	}
	if o.Joint != nil {
		v.Outcome = &modelOutcome{State: o.Joint.State, Mode: o.Joint.Mode}
	}
	if o.NativeCandidate != nil {
		v.Outcome = &modelOutcome{State: o.NativeCandidate.State, Mode: o.NativeCandidate.Mode, ConfigurationHash: o.NativeCandidate.Compiled.Hash}
	}
	return v
}

// A provider that ignores context cannot hold an HTTP request past its budget
// or accumulate unbounded abandoned calls: the single slot remains occupied
// until that call actually returns. A real transport must still cancel its I/O.
func (s *Service) generate(ctx context.Context, request ProviderRequest) (ProviderReply, error) {
	select {
	case s.providerSlot <- struct{}{}:
	case <-ctx.Done():
		return ProviderReply{}, ctx.Err()
	}
	type outcome struct {
		reply ProviderReply
		err   error
	}
	finished := make(chan outcome, 1)
	go func() {
		defer func() { <-s.providerSlot }()
		reply, err := s.provider.Generate(ctx, request)
		finished <- outcome{reply, err}
	}()
	select {
	case value := <-finished:
		return value.reply, value.err
	case <-ctx.Done():
		return ProviderReply{}, ctx.Err()
	}
}
func modelRefs(refs []domain.Reference) []domain.Reference {
	filtered := []domain.Reference{}
	for _, ref := range refs {
		if ref.Kind == "GOAL" || ref.Kind == "OPERATION" {
			filtered = append(filtered, ref)
		}
	}
	return filtered
}
func modelReferences(refs []domain.Reference, native bool) []domain.Reference {
	if !native {
		return modelRefs(refs)
	}
	out := []domain.Reference{}
	counts := map[string]int{}
	for _, r := range refs {
		switch r.Kind {
		case "ACCOUNT", "GOAL", "OPERATION", "NATIVE_POLICY", "NATIVE_CONTEXT", "NATIVE_PLAN", "NATIVE_OPERATION", "NATIVE_POSITION", "NATIVE_PAYEE", "NATIVE_QUESTION":
			cap := 8
			if r.Kind == "NATIVE_POLICY" {
				cap = 20
			}
			if r.Kind == "OPERATION" {
				cap = 4
			}
			family := r.Kind
			if r.Kind == "NATIVE_PLAN" || r.Kind == "NATIVE_OPERATION" || r.Kind == "NATIVE_POSITION" || r.Kind == "NATIVE_QUESTION" {
				family = "RETAINED"
			}
			if counts[family] >= cap {
				continue
			}
			counts[family]++
			out = append(out, r)
		}
	}
	return out
}

// Native grant tools are local OFFLINE reads and never enter a provider payload.
func modelRegistry() []domain.ToolSchema {
	tools := []domain.ToolSchema{}
	for _, tool := range domain.Registry() {
		if tool.Name != "native_grants" {
			tools = append(tools, tool)
		}
	}
	return tools
}

func DecodeTurn(raw []byte) (domain.Turn, error) { return domain.DecodeTurn(raw) }

func (s *Service) Run(ctx context.Context, scope domain.Scope, turn domain.Turn) (result Result, err error) {
	stage := "TURN_DECODE"
	defer func() {
		if err != nil {
			result.Observations = []domain.Observation{}
			result.References = []domain.Reference{}
			result.Candidate = nil
			result.NativeCandidate = nil
			err = turnFailure(stage, err, result.Budget, result.ProviderUsage)
		}
	}()
	result = Result{Mode: turn.Mode, ProviderStatus: "NOT_RUN", Observations: []domain.Observation{}, References: []domain.Reference{}}
	// Validate even in-process callers through the same closed transport contract.
	raw, err := json.Marshal(turn)
	if err != nil {
		return result, domain.ErrInvalid
	}
	turn, err = domain.DecodeTurn(raw)
	if err != nil {
		return result, err
	}
	if turn.Mode == "MODEL" && s.provider == nil {
		stage = "PROVIDER_CONFIGURATION"
		return result, ErrProviderNotConfigured
	}
	ctx, cancel := context.WithTimeout(ctx, s.limits.Timeout)
	defer cancel()
	stage = "SNAPSHOT_READ"
	snapshot, err := s.reader.Snapshot(ctx, scope)
	if err != nil {
		return result, err
	}
	snapshot = domain.CloneSnapshot(snapshot)
	stage = "SNAPSHOT_VALIDATE"
	if err = snapshot.Validate(scope); err != nil {
		return result, err
	}
	observe := func(call domain.ToolCall) error {
		stage = "TOOL_LIMIT"
		if err := result.Budget.Tool(s.limits); err != nil {
			return err
		}
		stage = "OBSERVE"
		observation, err := domain.Observe(snapshot, call)
		if err != nil {
			return err
		}
		result.Observations = append(result.Observations, observation)
		result.References = append(result.References, observation.References...)
		if observation.Candidate != nil {
			result.Candidate = observation.Candidate
		}
		if observation.NativeCandidate != nil {
			result.NativeCandidate = observation.NativeCandidate
		}
		stage = "OBSERVATION_SIZE"
		bounded, encodeErr := json.Marshal(result.Observations)
		if encodeErr != nil || len(bounded) > 2*1024*1024 {
			return domain.ErrBudget
		}
		return nil
	}
	if turn.Mode == "OFFLINE" {
		err = observe(*turn.Tool)
	} else {
		result.ModelUsed = true
		result.ProviderStatus = "CALLED"
		input := modelInput{Protocol: "zhiyu-agent-tools-v1", Text: turn.Text, Tools: modelRegistry(), References: snapshot.References(), Observations: []modelObservation{}}
		if snapshot.Native != nil {
			input.ReferenceScope = "BOUNDED_CURRENT_8_ACCOUNTS_8_GOALS_20_NATIVE_POLICIES_4_LEGACY_OPERATIONS_8_RETAINED_OBJECTS_8_KNOWN_BILL_PAYEES; NOT_COMPLETE_INVENTORY"
		}
		// Account/receipt/bank identifiers are unnecessary for tool selection.
		input.References = modelReferences(input.References, snapshot.Native != nil)
		input.KnownPayees = snapshot.KnownPayeeSignals(input.References)
		seen := map[string]bool{}
		for {
			stage = "CONTEXT"
			if err = ctx.Err(); err != nil {
				break
			}
			stage = "INPUT_ENCODE"
			payload, encodeErr := json.Marshal(input)
			if encodeErr != nil {
				err = domain.ErrInvalid
				break
			}
			stage = "RESERVE"
			reservation, reserveErr := result.Budget.Reserve(s.limits, len(payload))
			if reserveErr != nil {
				err = reserveErr
				break
			}
			stage = "PROVIDER"
			reply, providerErr := s.generate(ctx, ProviderRequest{append(json.RawMessage(nil), payload...), reservation.InputTokens, reservation.OutputTokens})
			if providerErr != nil {
				if ctx.Err() != nil {
					stage = "CONTEXT"
					err = ctx.Err()
				} else {
					stage = providerFailureStage(providerErr)
					if input, output, ok := rejectedReplyUsage(providerErr, reservation); ok {
						result.ProviderUsage.InputTokens += input
						result.ProviderUsage.OutputTokens += output
						result.ProviderUsage.ReportedCalls++
					}
					err = ErrProvider
				}
				break
			}
			stage = "CONTEXT"
			if err = ctx.Err(); err != nil {
				break
			}
			stage = "USAGE"
			if err = reservation.CheckUsage(reply.InputTokens, reply.OutputTokens); err != nil {
				break
			}
			result.ProviderUsage.InputTokens += reply.InputTokens
			result.ProviderUsage.OutputTokens += reply.OutputTokens
			result.ProviderUsage.ReportedCalls++
			stage = "REPLY_DECODE"
			call, done, decodeErr := domain.DecodeReply(reply.JSON)
			if decodeErr != nil {
				err = decodeErr
				break
			}
			if done {
				stage = "DONE_WITHOUT_OBSERVATION"
				if len(result.Observations) == 0 {
					err = domain.ErrTool
				}
				break
			}
			stage = "MODEL_TOOL_SCOPE"
			if call.Name == "native_grants" {
				err = domain.ErrTool
				break
			}
			fingerprint := call.Name
			if call.Name == "object_status" || call.Name == "template_candidate" {
				fingerprint += string(call.Arguments)
			}
			stage = "REPEAT_TOOL"
			if seen[fingerprint] {
				err = domain.ErrTool
				break
			}
			seen[fingerprint] = true
			available := append([]domain.Reference(nil), input.References...)
			for _, o := range input.Observations {
				available = append(available, o.References...)
			}
			stage = "TOOL_REFERENCE"
			if err = domain.CheckToolReferences(*call, available, snapshot); err != nil {
				break
			}
			if err = observe(*call); err != nil {
				break
			}
			latest := result.Observations[len(result.Observations)-1]
			if call.Name == "template_candidate" && latest.NativeCandidate != nil {
				// Server-compiled conditional candidate ends only the model loop.
				// The shared context/fresh-reference/final-size gates still follow.
				break
			}
			input.Observations = append(input.Observations, modelObserved(latest, snapshot.Native != nil))
		}
	}
	if err == nil {
		stage = "CONTEXT"
		err = ctx.Err()
	}
	if err == nil {
		var fresh domain.Snapshot
		stage = "FRESH_SNAPSHOT"
		fresh, err = s.reader.Snapshot(ctx, scope)
		if err == nil {
			stage = "CONTEXT"
			err = ctx.Err()
		}
		if err == nil {
			stage = "FRESH_REFERENCES"
			err = domain.CheckReferences(scope, domain.CloneSnapshot(fresh), result.Observations)
		}
	}
	if err == nil {
		stage = "FINAL_SIZE"
		raw, encodeErr := json.Marshal(result)
		if encodeErr != nil || len(raw) > 2*1024*1024 {
			err = domain.ErrBudget
		}
	}
	if err == nil {
		stage = "CONTEXT"
		err = ctx.Err()
	}
	if err != nil {
		// The deferred failure wrapper clears all observations/references/candidates.
		return result, err
	}
	return result, nil
}
