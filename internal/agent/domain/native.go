package domain

import (
	"encoding/json"
	"fmt"
	"reflect"
	"sort"
	"strings"
	"zhiyu.local/zhiyu-go/internal/audit"

	funds "zhiyu.local/zhiyu-go/internal/funds/domain"
	planning "zhiyu.local/zhiyu-go/internal/planning/domain"
	policy "zhiyu.local/zhiyu-go/internal/policy/domain"
)

// NativeContext is an internal trusted read, never an HTTP/model argument.
// Missing inventory is represented explicitly; it is never an empty world.
type NativeContext struct {
	Timezone         string
	BankNamespace    string
	SourceHash       string
	InventoryHash    string
	Unavailable      string
	Rules            []NativeRule
	Forecast         *planning.ForecastInput
	Joint            *planning.JointInput `json:"-"`
	JointUnavailable string
	Objects          []ObjectObservation
	NativeGrants     *NativeGrantCollection `json:"-"`
}
type NativeRule struct {
	Version        policy.TemplateVersion `json:"version"`
	GoalID         *funds.ID              `json:"goal_id,omitempty"`
	Timezone       string                 `json:"timezone"`
	EffectiveState string                 `json:"effective_state"`
}
type TemplateDescriptor struct {
	Name    policy.TemplateName `json:"template_name"`
	Fields  []string            `json:"fields"`
	Example json.RawMessage     `json:"example_configuration,omitempty"`
}
type TemplateCandidate struct {
	Mode                     string                   `json:"mode"`
	Compiled                 policy.CompiledTemplate  `json:"compiled"`
	GoalID                   *funds.ID                `json:"goal_id,omitempty"`
	PolicyID                 *funds.ID                `json:"policy_id,omitempty"`
	Reference                Reference                `json:"reference"`
	State                    string                   `json:"state"`
	Preview                  *policy.TemplatePreview  `json:"preview,omitempty"`
	Forecast                 *planning.ForecastResult `json:"forecast,omitempty"`
	Reasons                  []string                 `json:"reasons"`
	RequiresUserConfirmation bool                     `json:"requires_user_confirmation"`
	BankAuthority            bool                     `json:"bank_authority"`
}
type ForecastObservation struct {
	State         string                   `json:"state"`
	Result        *planning.ForecastResult `json:"result,omitempty"`
	Reasons       []string                 `json:"reasons"`
	BankAuthority bool                     `json:"bank_authority"`
}
type JointObservation struct {
	Mode          string              `json:"mode"`
	State         string              `json:"state"`
	Result        *planning.JointPlan `json:"result,omitempty"`
	Reasons       []string            `json:"reasons"`
	BankAuthority bool                `json:"bank_authority"`
}

// Data is a server-curated original object's display metadata, not credentials,
// bank keys, raw request bytes or an executable command.
type ObjectObservation struct {
	Kind string          `json:"kind"`
	ID   string          `json:"id"`
	Data json.RawMessage `json:"data"`
}

func nativeTool(name string) bool {
	switch name {
	case "template_catalog", "template_candidate", "native_rules", "native_grants", "forecast365", "joint_preview", "object_status", "original_objects":
		return true
	}
	return false
}
func nativeRegistry() []ToolSchema {
	empty := json.RawMessage(`{"type":"object","additionalProperties":false,"properties":{},"required":[]}`)
	return []ToolSchema{
		{"native_grants", "OFFLINE only: read complete bounded owned native grant originals and lifecycle display. Never establish, restore or execute authority.", append(json.RawMessage(nil), empty...)},
		{"original_objects", "Read owned retained plan/operation/position/question metadata, known verified-BILL payee identities and exact references; never answer, accept or recover an operation.", append(json.RawMessage(nil), empty...)},
		{"template_catalog", "Read the twelve exact template names and closed configuration field names. Configuration is compiled by the server, not authority.", append(json.RawMessage(nil), empty...)},
		{"native_rules", "Read the actual current native rule versions and lifecycle; never confirm, resume or grant.", append(json.RawMessage(nil), empty...)},
		{"forecast365", "Compute a 365-day forecast from current complete server facts; future income cannot increase current safe cash.", append(json.RawMessage(nil), empty...)},
		{"joint_preview", "Read-only deterministic joint solve for all 2..8 native long-term goals. No persisted executable plan or authority.", append(json.RawMessage(nil), empty...)},
		{"object_status", "Read one exact current supplied reference including its digest. No invented or foreign reference is accepted.", json.RawMessage(`{"type":"object","additionalProperties":false,"properties":{"reference":{"type":"object","additionalProperties":false,"properties":{"kind":{"type":"string"},"id":{"type":"string","format":"uuid"},"digest":{"type":"string","pattern":"^[0-9a-f]{64}$"}},"required":["kind","id","digest"]}},"required":["reference"]}`)},
		{"template_candidate", "Propose one of twelve typed templates. Money is an integer-cent STRING in configuration only. Nested fields are checked by that exact template compiler. This is IF_USER_CONFIRMED only; no approval, grant, acceptance or bank call.", json.RawMessage(`{"type":"object","additionalProperties":false,"properties":{"template_name":{"type":"string"},"configuration":{"type":"object"},"goal_id":{"type":"string","format":"uuid"},"policy_id":{"type":"string","format":"uuid"}},"required":["template_name","configuration"]}`)},
	}
}

type templateArguments struct {
	Name          policy.TemplateName `json:"template_name"`
	Configuration json.RawMessage     `json:"configuration"`
	GoalID        *funds.ID           `json:"goal_id,omitempty"`
	PolicyID      *funds.ID           `json:"policy_id,omitempty"`
}

func nativeArguments(call ToolCall) (string, error) {
	switch call.Name {
	case "template_catalog", "native_rules", "native_grants", "forecast365", "joint_preview", "original_objects":
		o, e := exactObject(call.Arguments)
		if e != nil || len(o) != 0 {
			return "", ErrTool
		}
		return "", nil
	case "object_status":
		o, e := exactObject(call.Arguments, "reference")
		if e != nil || len(o) != 1 {
			return "", ErrTool
		}
		raw, _ := json.Marshal(o["reference"])
		r, e := exactObject(raw, "kind", "id", "digest")
		if e != nil || len(r) != 3 {
			return "", ErrTool
		}
		var v struct {
			Reference Reference `json:"reference"`
		}
		if json.Unmarshal(call.Arguments, &v) != nil || !exactID(v.Reference.ID) || !hash64(v.Reference.Digest) || len(v.Reference.Kind) > 32 {
			return "", ErrTool
		}
		return v.Reference.ID, nil
	case "template_candidate":
		o, e := exactObject(call.Arguments, "template_name", "configuration", "goal_id", "policy_id")
		if e != nil || o["template_name"] == nil || o["configuration"] == nil {
			return "", ErrTool
		}
		for _, k := range []string{"goal_id", "policy_id"} {
			if id, present := o[k]; present {
				s, ok := id.(string)
				if !ok || !exactID(s) {
					return "", ErrTool
				}
			}
		}
		var a templateArguments
		if json.Unmarshal(call.Arguments, &a) != nil {
			return "", ErrTool
		}
		if _, e = policy.CompileTemplate(a.Name, a.Configuration); e != nil {
			return "", ErrTool
		}
		return "", nil
	}
	return "", ErrTool
}
func hash64(s string) bool {
	if len(s) != 64 {
		return false
	}
	for _, c := range s {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}
func (s Snapshot) contextRef() Reference {
	n := s.Native
	// AsOf changes on each read. Bind its natural day and every validity/status
	// transition instead of rejecting two otherwise identical current reads.
	day := ""
	if z, e := policy.TemplateLocation(n.Timezone); e == nil {
		day = s.AsOf.In(z).Format("2006-01-02")
	}
	states := []string{}
	states = append(states, makeRef("BASE", s.Scope.UserID.String(), struct {
		Accounts []Account
		Goals    []Goal
		Policies []Policy
		Grants   []Grant
	}{s.Accounts, s.Goals, s.Policies, s.Grants}).Digest)
	for _, r := range n.Rules {
		state, _ := r.Version.EffectiveState(s.AsOf, r.Timezone)
		states = append(states, r.Version.VersionID.String()+":"+state)
	}
	return makeRef("NATIVE_CONTEXT", s.Scope.UserID.String(), struct {
		Source, Inventory, Day, Unavailable, JointUnavailable string
		States                                                []string
	}{n.SourceHash, n.InventoryHash, day, n.Unavailable, n.JointUnavailable, states})
}
func (s Snapshot) nativeReferences() []Reference {
	if s.Native == nil {
		return nil
	}
	refs := []Reference{s.contextRef()}
	for _, r := range s.Native.Rules {
		refs = append(refs, makeRef("NATIVE_POLICY", r.Version.PolicyID.String(), r), makeRef("NATIVE_VERSION", r.Version.VersionID.String(), r))
	}
	for _, o := range s.Native.Objects {
		refs = append(refs, makeRef(o.Kind, o.ID, o))
	}
	return append(refs, s.nativeGrantReferences()...)
}
func (s Snapshot) validateNative() error {
	n := s.Native
	if n == nil {
		return nil
	}
	if _, e := policy.TemplateLocation(n.Timezone); e != nil || len(n.Rules) > 100 || len(n.Objects) > 100 {
		return ErrReference
	}
	if err := s.nativeGrantCollection().Validate(s.Scope, s.AsOf); err != nil {
		return err
	}
	if err := s.validateNativeGrantOwnership(); err != nil {
		return err
	}
	scope := policy.TemplateOwnerScope{EnvironmentID: s.Scope.EnvironmentID, UserID: s.Scope.UserID}
	for _, r := range n.Rules {
		v := r.Version
		if v.Scope != scope || !v.Current || !v.ConfirmationVerified || v.ConfirmedConfigurationHash != v.Compiled.Hash || v.Version == 0 {
			return ErrReference
		}
		if _, e := v.Compiled.Decode(); e != nil {
			return ErrReference
		}
		state, e := v.EffectiveState(s.AsOf, r.Timezone)
		if e != nil || state != r.EffectiveState {
			return ErrReference
		}
		if r.GoalID != nil && !s.hasRef("GOAL", r.GoalID.String()) {
			return ErrReference
		}
	}
	for _, o := range n.Objects {
		if !strings.HasPrefix(o.Kind, "NATIVE_") || o.Kind == "NATIVE_CONTEXT" || o.Kind == "NATIVE_POLICY" || o.Kind == "NATIVE_VERSION" || o.Kind == "NATIVE_GRANT" || o.Kind == "NATIVE_GRANTS" || !json.Valid(o.Data) || len(o.Data) > 32768 {
			return ErrReference
		}
		if o.Kind == "NATIVE_PAYEE" {
			if _, ok := s.knownPayeeObject(o); !ok {
				return ErrReference
			}
		}
	}
	if n.Forecast != nil {
		f := n.Forecast
		if n.Unavailable != "" || !f.Complete || !f.Facts.Complete || f.Scope != scope || f.Facts.Scope != scope || !f.AsOf.Equal(s.AsOf) || f.Timezone != n.Timezone || f.InventoryHash != n.InventoryHash || f.Facts.SourceHash != n.SourceHash || !hash64(n.SourceHash) || !hash64(n.InventoryHash) || len(f.Versions) != len(n.Rules) {
			return ErrReference
		}
		balances := []funds.Money{}
		for _, a := range s.Accounts {
			balances = append(balances, a.Balance)
		}
		total, e := funds.SumMoney(balances...)
		if e != nil || total != f.Facts.CurrentCash {
			return ErrReference
		}
		for _, v := range f.Versions {
			matched := false
			for _, r := range n.Rules {
				if makeRef("VERSION", v.VersionID.String(), v) == makeRef("VERSION", r.Version.VersionID.String(), r.Version) {
					matched = true
				}
			}
			if !matched {
				return ErrReference
			}
		}
	}
	if n.Joint != nil {
		j := n.Joint
		if n.Forecast == nil || j.Scope != scope || !j.Now.Equal(s.AsOf) || j.InventoryHash != n.InventoryHash || j.ProtectionInput == nil || j.Timezone != n.Timezone || len(j.Protection) != 0 {
			return ErrReference
		}
		if j.Ledger.Validate() != nil || j.Ledger.Snapshot().UserID != scope.UserID || !j.Ledger.Snapshot().AsOf.Equal(s.AsOf) || makeRef("FORECAST", scope.UserID.String(), j.ProtectionInput) != makeRef("FORECAST", scope.UserID.String(), n.Forecast) {
			return ErrReference
		}
	}
	return nil
}
func (s Snapshot) hasRef(kind, id string) bool {
	for _, r := range s.References() {
		if r.Kind == kind && r.ID == id {
			return true
		}
	}
	return false
}
func cloneNative(n *NativeContext) *NativeContext {
	if n == nil {
		return nil
	}
	raw, e := json.Marshal(n)
	if e != nil {
		return &NativeContext{Timezone: "INVALID"}
	}
	var out NativeContext
	if json.Unmarshal(raw, &out) != nil {
		return &NativeContext{Timezone: "INVALID"}
	}
	out.NativeGrants = CloneNativeGrantCollection(n.NativeGrants)
	if n.Joint != nil {
		raw, _ = json.Marshal(n.Joint)
		var j planning.JointInput
		if json.Unmarshal(raw, &j) != nil {
			return &NativeContext{Timezone: "INVALID"}
		}
		j.Ledger, _ = funds.NewIncomeLedger(n.Joint.Ledger.Snapshot())
		out.Joint = &j
	}
	return &out
}

func configurationTypes() map[policy.TemplateName]reflect.Type {
	return map[policy.TemplateName]reflect.Type{
		policy.RecurringObligationTemplate: reflect.TypeOf(policy.RecurringObligationConfig{}), policy.LivingReserveTemplate: reflect.TypeOf(policy.LivingReserveConfig{}), policy.EmergencyBufferTemplate: reflect.TypeOf(policy.EmergencyBufferConfig{}), policy.DatedExpenseTemplate: reflect.TypeOf(policy.DatedExpenseConfig{}), policy.LongTermGoalTemplate: reflect.TypeOf(policy.LongTermGoalConfig{}), policy.PeriodicTransferTemplate: reflect.TypeOf(policy.PeriodicTransferConfig{}), policy.AssetAuthorizationTemplate: reflect.TypeOf(policy.AssetAuthorizationConfig{}), policy.RecoveryTemplate: reflect.TypeOf(policy.RecoveryConfig{}), policy.GoalAllocationTemplate: reflect.TypeOf(policy.GoalAllocationConfig{}), policy.CrossGoalReallocationTemplate: reflect.TypeOf(policy.CrossGoalReallocationConfig{}), policy.SeasonalReserveTemplate: reflect.TypeOf(policy.SeasonalReserveConfig{}), policy.InterventionTemplate: reflect.TypeOf(policy.InterventionConfig{}),
	}
}
func TemplateCatalog() []TemplateDescriptor {
	out := []TemplateDescriptor{}
	for _, name := range policy.TemplateNames() {
		fields := []string{}
		var add func(reflect.Type)
		add = func(t reflect.Type) {
			for i := 0; i < t.NumField(); i++ {
				f := t.Field(i)
				if f.Anonymous {
					add(f.Type)
					continue
				}
				key := strings.Split(f.Tag.Get("json"), ",")[0]
				if key != "" && key != "-" {
					fields = append(fields, key)
				}
			}
		}
		add(configurationTypes()[name])
		sort.Strings(fields)
		descriptor := TemplateDescriptor{Name: name, Fields: fields}
		if name == policy.EmergencyBufferTemplate {
			descriptor.Example = json.RawMessage(`{"type":"emergency_buffer","amount_cents":"3000"}`)
		}
		out = append(out, descriptor)
	}
	return out
}

func observeNative(s Snapshot, call ToolCall) (Observation, error) {
	out := Observation{Tool: call.Name, AsOf: s.AsOf, VerificationScope: "DISPLAY_SNAPSHOT", References: []Reference{}}
	if call.Name == "template_catalog" {
		out.Catalog = TemplateCatalog()
		out.Summary = "已读取十二类规则的准确名称和配置字段。候选只有经本人在规则页重新预览、明确确认后才可能生效。"
		if s.Native != nil {
			out.References = []Reference{s.contextRef()}
		}
		return out, nil
	}
	if s.Native == nil {
		return out, ErrReference
	}
	n := s.Native
	out.References = []Reference{s.contextRef()}
	switch call.Name {
	case "native_grants":
		return observeNativeGrants(s, call, out)
	case "original_objects":
		out.Objects = append([]ObjectObservation(nil), n.Objects...)
		for _, o := range n.Objects {
			out.References = append(out.References, makeRef(o.Kind, o.ID, o))
		}
		out.Summary = "已读取本人近期保留的计划、操作、仓位、原问题及已核实账单中的收款对象。已知收款对象不代表当前可付款或已经授权；原问题是否仍可回答须由原问题页面重新核验。"
	case "native_rules":
		out.NativeRules = append([]NativeRule(nil), n.Rules...)
		for _, r := range n.Rules {
			out.References = append(out.References, makeRef("NATIVE_POLICY", r.Version.PolicyID.String(), r))
		}
		out.Summary = fmt.Sprintf("已核对 %d 条本人现行原生规则的真实版本、配置和生命周期；读取不会新增或恢复授权。", len(n.Rules))
	case "forecast365":
		out.Forecast = &ForecastObservation{State: "INCOMPLETE", Reasons: []string{n.Unavailable}}
		if n.Forecast != nil {
			f := *n.Forecast
			f.HorizonDays = 365
			r, e := planning.Forecast365(f)
			if e != nil {
				return Observation{}, ErrReference
			}
			out.Forecast = &ForecastObservation{State: r.State, Result: &r, Reasons: r.Reasons}
		}
		out.Summary = "365 天预测使用当前服务端完整库存；未到账收入只影响预测，不扩大今日现金边界。缺少完整证明时不返回可用金额。"
	case "joint_preview":
		out.Joint = &JointObservation{Mode: "READ_ONLY_NOT_EXECUTABLE", State: "INCOMPLETE", Reasons: []string{n.JointUnavailable}}
		if n.Joint != nil {
			r, e := planning.SolveJoint(*n.Joint)
			if e != nil {
				return Observation{}, ErrReference
			}
			out.Joint = &JointObservation{Mode: "READ_ONLY_NOT_EXECUTABLE", State: r.Status, Result: &r, Reasons: r.Reasons}
		}
		out.Summary = "只读联合规划按全部当前目标、原收入资格、今日现金与全年硬保护计算；没有登记可执行计划、用户授权或资金操作。"
	case "template_candidate":
		return observeTemplateCandidate(s, call, out)
	case "object_status":
		var a struct {
			Reference Reference `json:"reference"`
		}
		_ = json.Unmarshal(call.Arguments, &a)
		if a.Reference.Kind == "NATIVE_GRANT" || a.Reference.Kind == "NATIVE_GRANTS" {
			return observeNativeGrants(s, call, out)
		}
		found := false
		for _, r := range s.References() {
			if r == a.Reference {
				found = true
			}
		}
		if !found {
			return Observation{}, ErrReference
		}
		out.References = append(out.References, a.Reference)
		var value any
		for _, r := range n.Rules {
			if a.Reference.Kind == "NATIVE_POLICY" && r.Version.PolicyID.String() == a.Reference.ID || a.Reference.Kind == "NATIVE_VERSION" && r.Version.VersionID.String() == a.Reference.ID {
				value = r
			}
		}
		for _, o := range n.Objects {
			if o.Kind == a.Reference.Kind && o.ID == a.Reference.ID {
				out.Object = &o
			}
		}
		if value == nil && out.Object == nil {
			value = s.referenceValue(a.Reference)
		}
		if out.Object == nil {
			if value == nil {
				return Observation{}, ErrReference
			}
			raw, _ := json.Marshal(value)
			out.Object = &ObjectObservation{a.Reference.Kind, a.Reference.ID, raw}
		}
		out.Summary = "已按原对象身份与当前摘要读取本人记录。历史原件读取不会受理、重试或更换银行键。"
	}
	return out, nil
}
func (s Snapshot) referenceValue(r Reference) any {
	switch r.Kind {
	case "ACCOUNT":
		for _, v := range s.Accounts {
			if v.ID == r.ID {
				return v
			}
		}
	case "GOAL":
		for _, v := range s.Goals {
			if v.ID == r.ID {
				return v
			}
		}
	case "POLICY":
		for _, v := range s.Policies {
			if v.ID == r.ID {
				return v
			}
		}
	case "GRANT":
		for _, v := range s.Grants {
			if v.ID == r.ID {
				return v
			}
		}
	case "OPERATION":
		for _, v := range s.Operations {
			if v.ID == r.ID {
				return v
			}
		}
	}
	return nil
}

func observeTemplateCandidate(s Snapshot, call ToolCall, out Observation) (Observation, error) {
	var a templateArguments
	_ = json.Unmarshal(call.Arguments, &a)
	compiled, e := policy.CompileTemplate(a.Name, a.Configuration)
	if e != nil {
		return Observation{}, ErrTool
	}
	if a.Name == policy.LongTermGoalTemplate && a.GoalID == nil || a.Name != policy.LongTermGoalTemplate && a.GoalID != nil {
		return Observation{}, ErrReference
	}
	if a.GoalID != nil && !s.hasRef("GOAL", a.GoalID.String()) {
		return Observation{}, ErrReference
	}
	var previous *NativeRule
	if a.PolicyID != nil {
		for i, r := range s.Native.Rules {
			if r.Version.PolicyID == *a.PolicyID {
				previous = &s.Native.Rules[i]
			}
		}
		if previous == nil || previous.Version.Compiled.Name != a.Name || !sameOptionalID(previous.GoalID, a.GoalID) {
			return Observation{}, ErrReference
		}
	}
	if a.GoalID != nil && a.PolicyID == nil {
		for _, r := range s.Native.Rules {
			if sameOptionalID(r.GoalID, a.GoalID) {
				return Observation{}, ErrReference
			}
		}
	}
	// Enforce closed current object references throughout every typed config.
	obj, parseErr := audit.ParseRawObject(compiled.Configuration)
	if parseErr != nil || !candidateReferences(s, obj, "") {
		return Observation{}, ErrReference
	}
	if payee, ok := obj["payee_id"].(string); ok {
		ref, ok := s.knownPayeeReference(payee)
		if !ok {
			return Observation{}, ErrReference
		}
		out.References = append(out.References, ref)
	}
	draft := &TemplateCandidate{Mode: "IF_USER_CONFIRMED", Compiled: compiled, GoalID: a.GoalID, PolicyID: a.PolicyID, Reference: s.contextRef(), State: "INCOMPLETE", Reasons: []string{s.Native.Unavailable}, RequiresUserConfirmation: true}
	out.NativeCandidate = draft
	out.Summary = "这是确定性编译的条件候选，尚未确认或生效。请到规则页由本人重新预览完整影响并明确确认；候选不是授权或可执行计划。"
	if s.Native.Forecast == nil {
		return out, nil
	}
	f, cloneErr := planning.CloneForecastInput(*s.Native.Forecast)
	if cloneErr != nil {
		draft.Reasons = []string{"CURRENT_FACTS_INSUFFICIENT_FOR_COUNTERFACTUAL"}
		return out, nil
	}
	var protectedBefore *planning.ForecastInput
	var protectedIDs []funds.ID
	if compiled.Name == policy.DatedExpenseTemplate {
		config, _ := compiled.Decode()
		protectedIDs = config.(*policy.DatedExpenseConfig).MustNotReducePolicyIDs
		if len(protectedIDs) != 0 {
			before, err := planning.CloneForecastInput(f)
			if err != nil {
				draft.Reasons = []string{"CURRENT_FACTS_INSUFFICIENT_FOR_COUNTERFACTUAL"}
				return out, nil
			}
			protectedBefore = &before
		}
	}
	// These IDs and verification flags exist only inside this explicit
	// counterfactual. They are never persisted or returned as USER evidence.
	pid := draftID(s.Scope, compiled.Hash, "policy")
	if a.PolicyID != nil {
		pid = *a.PolicyID
	}
	vid := draftID(s.Scope, compiled.Hash, "version")
	version := uint64(1)
	if previous != nil {
		version = previous.Version.Version + 1
	}
	proposed := policy.TemplateVersion{PolicyID: pid, VersionID: vid, Version: version, Scope: f.Scope, Compiled: compiled, State: "ACTIVE", ConfirmedAt: s.AsOf, Current: true, ConfirmationVerified: true, ConfirmedConfigurationHash: compiled.Hash}
	versions := []policy.TemplateVersion{}
	for _, v := range f.Versions {
		if v.PolicyID != pid {
			versions = append(versions, v)
		}
	}
	f.Versions = append(versions, proposed)
	f.Facts.Goals = append([]policy.TemplateGoalFact(nil), f.Facts.Goals...)
	if a.GoalID != nil {
		for i, g := range f.Facts.Goals {
			if g.ID == *a.GoalID {
				conf, _ := compiled.Decode()
				if conf.(*policy.LongTermGoalConfig).Target.Cents() < g.Owned.Cents() {
					return Observation{}, ErrReference
				}
				f.Facts.Goals[i].PolicyID = pid
				f.Facts.Goals[i].VersionID = vid
				f.Facts.Goals[i].GoalVersion = &proposed
			}
		}
	}
	forecast, e := planning.Forecast365(f)
	if e != nil {
		draft.Reasons = []string{"CURRENT_FACTS_INSUFFICIENT_FOR_COUNTERFACTUAL"}
		return out, nil
	}
	if protectedBefore != nil {
		refs, err := planning.CompareProtectedPolicyReferencesV1(*protectedBefore, f, pid, protectedIDs)
		if err != nil {
			draft.Reasons = []string{"CURRENT_FACTS_INSUFFICIENT_FOR_COUNTERFACTUAL"}
			return out, nil
		}
		f.Facts.ProtectedReferences = refs
	}
	f.Facts.CurrentSafe = forecast.CurrentSafe
	f.Facts.CurrentSafeVerified = true
	preview, e := policy.PreviewTemplate(proposed, f.Facts, s.AsOf, f.Timezone)
	if e != nil {
		draft.Reasons = []string{"CURRENT_FACTS_INSUFFICIENT_FOR_COUNTERFACTUAL"}
		return out, nil
	}
	draft.State = preview.State
	draft.Preview = &preview
	draft.Forecast = &forecast
	draft.Reasons = preview.Reasons
	return out, nil
}
func sameOptionalID(a, b *funds.ID) bool {
	return a == nil && b == nil || a != nil && b != nil && *a == *b
}
func draftID(scope Scope, hash, kind string) funds.ID {
	r := makeRef("DRAFT", scope.UserID.String(), []string{scope.EnvironmentID.String(), hash, kind})
	var id funds.ID
	for i := range id {
		fmt.Sscanf(r.Digest[i*2:i*2+2], "%02x", &id[i])
	}
	id[6] = (id[6] & 15) | 64
	id[8] = (id[8] & 63) | 128
	return id
}
func candidateReferences(s Snapshot, value any, key string) bool {
	return configurationReferences(value, key, func(kind, id string) bool {
		if kind == "NATIVE_PAYEE" {
			_, ok := s.knownPayeeReference(id)
			return ok
		}
		return s.hasRef(kind, id)
	})
}
func configurationReferences(value any, key string, has func(string, string) bool) bool {
	switch v := value.(type) {
	case map[string]any:
		for k, x := range v {
			if !configurationReferences(x, k, has) {
				return false
			}
		}
	case []any:
		for _, x := range v {
			if !configurationReferences(x, key, has) {
				return false
			}
		}
	case string:
		kind := ""
		switch key {
		case "account_id", "source_account_id":
			kind = "ACCOUNT"
		case "goal_id", "goal_ids", "source_goal_ids", "target_goal_ids":
			kind = "GOAL"
		case "asset_policy_id", "cross_goal_reallocation_policy_id", "must_not_reduce_policy_ids":
			kind = "NATIVE_POLICY"
		case "payee_id":
			kind = "NATIVE_PAYEE"
		}
		if kind != "" && !has(kind, v) {
			return false
		}
	}
	return true
}

// CheckToolReferences restricts MODEL selections to exactly the finite
// references actually advertised in this turn, in addition to the independent
// current/scope checks performed by Observe. Offline reads use the full scope.
func CheckToolReferences(call ToolCall, refs []Reference, snapshot Snapshot) error {
	if _, e := argumentID(call); e != nil {
		return e
	}
	has := func(kind, id string) bool {
		if kind == "NATIVE_PAYEE" {
			mapped, ok := snapshot.knownPayeeReference(id)
			if !ok {
				return false
			}
			for _, r := range refs {
				if r == mapped {
					return true
				}
			}
			return false
		}
		for _, r := range refs {
			if r.Kind == kind && r.ID == id {
				return true
			}
		}
		return false
	}
	switch call.Name {
	case "native_grants":
		return ErrTool // MODEL only; OFFLINE Observe does not use this gate.
	case "goal_status", "policy_candidate":
		id, e := argumentID(call)
		if e != nil || !has("GOAL", id) {
			return ErrReference
		}
	case "operation_status":
		id, e := argumentID(call)
		if e != nil || !has("OPERATION", id) {
			return ErrReference
		}
	case "object_status":
		var a struct {
			Reference Reference `json:"reference"`
		}
		if json.Unmarshal(call.Arguments, &a) != nil {
			return ErrReference
		}
		if a.Reference.Kind == "NATIVE_GRANT" || a.Reference.Kind == "NATIVE_GRANTS" {
			return ErrTool
		}
		for _, r := range refs {
			if r == a.Reference {
				return nil
			}
		}
		return ErrReference
	case "template_candidate":
		var a templateArguments
		if json.Unmarshal(call.Arguments, &a) != nil || a.GoalID != nil && !has("GOAL", a.GoalID.String()) || a.PolicyID != nil && !has("NATIVE_POLICY", a.PolicyID.String()) {
			return ErrReference
		}
		obj, e := audit.ParseRawObject(a.Configuration)
		if e != nil || !configurationReferences(obj, "", has) {
			return ErrReference
		}
	}
	return nil
}
