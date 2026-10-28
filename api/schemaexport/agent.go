package main

import (
	"encoding/json"
	"reflect"

	assistant "zhiyu.local/zhiyu-go/internal/agent"
	agent "zhiyu.local/zhiyu-go/internal/agent/domain"
)

func agentEnum(values ...string) schema     { return schema{"type": "string", "enum": values} }
func agentProps(n string) map[string]schema { return schemas[n]["properties"].(map[string]schema) }
func agentCopy(s schema) schema {
	out := schema{}
	for k, v := range s {
		out[k] = v
	}
	return out
}
func agentObject(props map[string]schema, required ...string) schema {
	return schema{"type": "object", "additionalProperties": false, "properties": props, "required": required}
}

// Export the actual transport structs. The internal Snapshot/NativeContext and
// provider payload are deliberately not roots of the public HTTP contract.
func agentContracts(templateNames []string) {
	for _, v := range []any{assistant.Status{}, assistant.Result{}} {
		shape(reflect.TypeOf(v))
	}
	refKinds := []string{"ACCOUNT", "GOAL", "POLICY", "GRANT", "OPERATION", "ACCOUNTS", "RULES", "NATIVE_CONTEXT", "NATIVE_POLICY", "NATIVE_VERSION", "NATIVE_PLAN", "NATIVE_OPERATION", "NATIVE_POSITION", "NATIVE_QUESTION", "NATIVE_PAYEE", "NATIVE_GRANT", "NATIVE_GRANTS"}
	modelKinds := refKinds[:len(refKinds)-2]
	rp := agentProps("NativeAgentReference")
	rp["kind"], rp["id"], rp["digest"] = agentEnum(refKinds...), ref("ID"), ref("Digest")
	schemas["NativeAgentModelReference"] = agentObject(map[string]schema{"kind": agentEnum(modelKinds...), "id": ref("ID"), "digest": ref("Digest")}, "kind", "id", "digest")
	for _, n := range []string{"NativeAgentStatus", "NativeAgentResult", "NativeAgentNativeGrantDisplay", "NativeAgentNativeGrantCollection"} {
		agentProps(n)["authority"] = schema{"type": "boolean", "enum": []bool{false}}
	}
	sp := agentProps("NativeAgentStatus")
	sp["mode"], sp["provider_status"] = agentEnum("OFFLINE", "MODEL_AVAILABLE"), agentEnum("NOT_RUN", "CONFIGURED_NOT_VERIFIED")
	schemas["NativeAgentStatus"]["oneOf"] = []schema{
		{"properties": map[string]schema{"mode": agentEnum("OFFLINE"), "provider_status": agentEnum("NOT_RUN"), "provider_configured": {"type": "boolean", "enum": []bool{false}}}},
		{"properties": map[string]schema{"mode": agentEnum("MODEL_AVAILABLE"), "provider_status": agentEnum("CONFIGURED_NOT_VERIFIED"), "provider_configured": {"type": "boolean", "enum": []bool{true}}}},
	}
	for n, fields := range map[string][]string{"NativeAgentAccount": {"id"}, "NativeAgentGoal": {"id", "account_id"}, "NativeAgentPolicy": {"id", "goal_id"}, "NativeAgentGrant": {"id", "policy_id"}, "NativeAgentOperation": {"id", "plan_id", "receipt_id"}, "NativeAgentCandidate": {"goal_id"}} {
		for _, field := range fields {
			agentProps(n)[field] = ref("ID")
		}
	}
	for _, n := range []string{"NativeAgentAccount", "NativeAgentGoal"} {
		agentProps(n)["name"] = schema{"type": "string", "maxLength": 256, "x-max-utf8-bytes": 256}
	}
	for _, n := range []string{"NativeAgentPolicy", "NativeAgentGrant"} {
		agentProps(n)["status"] = agentEnum("ACTIVE", "PAUSED", "REVOKED", "EXPIRED")
	}
	for _, n := range []string{"NativeAgentPolicy", "NativeAgentOperation"} {
		agentProps(n)["version"] = ref("Version")
	}
	for _, n := range []string{"bank_observed_status", "processing_health"} {
		agentProps("NativeAgentOperation")[n] = schema{"type": "string", "maxLength": 64}
	}
	agentProps("NativeAgentOperation")["state"] = ref("OperationState")
	agentProps("NativeAgentCandidate")["template"] = agentEnum("SINGLE_GOAL")
	agentProps("NativeAgentCandidate")["requires_user_fields"] = schema{"type": "boolean", "enum": []bool{true}}
	cp := agentProps("NativeAgentTemplateCandidate")
	cp["mode"] = agentEnum("IF_USER_CONFIRMED")
	cp["requires_user_confirmation"] = schema{"type": "boolean", "enum": []bool{true}}
	cp["state"] = agentEnum("INCOMPLETE", "CONFIRMED", "READY", "OUT_OF_AUTHORIZATION", "NO_ACTION", "MINIMUM_SHORTFALL", "CONSTRAINTS_READY", "FLOOR_RELEASED", "ADVICE_ONLY", "SILENT_STABLE_OR_DEDUPLICATED", "USER_QUESTION_REQUIRED", "COMPLETE", "MONTHLY_MAX_ALREADY_EXCEEDED", "HARD_GUARANTEE_SHORTFALL", "DEADLINE_BLOCKED", "PARTIAL", "OVERDUE_READY")
	agentProps("NativeAgentForecastObservation")["state"] = agentEnum("INCOMPLETE", "READY", "PROTECTION_DEFICIT")
	agentProps("NativeAgentJointObservation")["mode"] = agentEnum("READ_ONLY_NOT_EXECUTABLE")
	agentProps("NativeAgentJointObservation")["state"] = agentEnum("INCOMPLETE", "UNKNOWN", "INFEASIBLE", "OPTIMAL")
	agentProps("NativeAgentNativeRule")["effective_state"] = agentEnum("ACTIVE", "CONFIRMED", "CONFIRMATION_IN_FUTURE", "SUSPENDED", "REVOKED", "EXPIRED")
	agentProps("NativeAgentTemplateDescriptor")["template_name"] = agentEnum(templateNames...)
	agentProps("NativeAgentTemplateDescriptor")["example_configuration"] = ref("NativeTemplateConfiguration")
	agentProps("NativeAgentObjectObservation")["kind"] = agentEnum("ACCOUNT", "GOAL", "POLICY", "GRANT", "OPERATION", "NATIVE_POLICY", "NATIVE_VERSION", "NATIVE_PLAN", "NATIVE_OPERATION", "NATIVE_POSITION", "NATIVE_QUESTION", "NATIVE_PAYEE")
	agentProps("NativeAgentObjectObservation")["id"] = ref("ID")
	// Native grant records have a separate bounded display protocol. They are
	// never a generic original object or a provider argument/observation.
	reasons := []string{"CAPACITY", "SCHEMA_UNAVAILABLE", "EVIDENCE_INVALID", "SUBJECT_UNAVAILABLE", "SESSION_EXPIRED_AT_EVENT", "SESSION_REVOCATION_HISTORY_UNAVAILABLE", "POLICY_CHANGED", "POLICY_UNAVAILABLE", "NOT_YET_EFFECTIVE", "EXPIRED", "PAUSED", "REVOKED"}
	schemas["NativeAgentGrantReason"] = agentEnum(reasons...)
	schemas["NativeAgentGrantCap"] = schema{"type": "string", "pattern": "^([1-8][0-9]{0,15}|[1-9][0-9]{0,14}|9000000000000000)$", "description": "Positive integer cents at most funds.MaxMoneyCents (9000000000000000); reviewed limit, never executable cash."}
	gp := agentProps("NativeAgentNativeGrantDisplay")
	gp["id"], gp["version"] = ref("ID"), schema{"type": "integer", "enum": []int{1}}
	gp["family"] = agentEnum("SINGLE_GOAL", "JOINT_GOALS", "ASSET_ALLOCATION", "MATURITY_REINVEST", "PERIODIC_PAYMENT")
	gp["recorded_state"] = agentEnum("ACTIVE", "PAUSED", "REVOKED")
	gp["effective_state"] = agentEnum("REVOKED", "EXPIRED", "PAUSED", "NOT_YET_EFFECTIVE", "POLICY_CHANGED", "UNAVAILABLE", "CURRENT_DISPLAY_ONLY")
	gp["state_sequence"] = schema{"type": "integer", "minimum": 1, "maximum": 256}
	gp["evaluated_local_date"] = schema{"type": "string", "format": "date"}
	for _, n := range []string{"original_digest", "terms_digest", "chain_digest"} {
		gp[n] = ref("Digest")
	}
	for _, n := range []string{"single_cap_cents", "lifetime_cap_cents", "monthly_cap_cents"} {
		gp[n] = ref("NativeAgentGrantCap")
	}
	for n, max := range map[string]int{"policy_references": 16, "account_ids": 16, "goal_ids": 8, "product_ids": 100, "payee_ids": 1, "reason_codes": 13} {
		gp[n]["maxItems"] = max
	}
	gp["policy_references"]["minItems"], gp["account_ids"]["minItems"] = 1, 1
	gp["reason_codes"]["items"] = ref("NativeAgentGrantReason")
	for _, n := range []string{"account_ids", "goal_ids", "product_ids", "payee_ids", "reason_codes"} {
		gp[n]["uniqueItems"] = true
	}
	for _, n := range []string{"product_ids", "payee_ids"} {
		gp[n]["items"] = schema{"type": "string", "pattern": "^[A-Za-z0-9_.:-]{1,128}$"}
	}
	schemas["NativeAgentNativeGrantDisplay"]["x-max-json-bytes"] = 32 * 1024
	schemas["NativeAgentNativeGrantDisplay"]["description"] = "OFFLINE only. Original caps and complete lifecycle display, not authority. Sorted unique lists, family policy/scope, cap ordering, same-state reasons, expiry/day and original chain are checked by the domain; schema validation does not replace those checks. No session, grant raw bytes, signature or executable budget is exposed."
	gc := agentProps("NativeAgentNativeGrantCollection")
	gc["protocol"] = agentEnum(agent.NativeGrantDisplayProtocol)
	gc["status"] = agentEnum("COMPLETE", "UNAVAILABLE")
	gc["count"] = schema{"type": "integer", "minimum": 0, "maximum": 100}
	gc["items"]["maxItems"], gc["reason_codes"]["maxItems"] = 100, 13
	gc["reason_codes"]["items"], gc["collection_digest"] = ref("NativeAgentGrantReason"), ref("Digest")
	gc["verification_scope"] = agentEnum(agent.NativeGrantVerificationScope, "NOT_VERIFIED")
	gc["session_verification"] = agentEnum(agent.NativeGrantSessionScope, "HISTORY_INCOMPLETE", "NOT_VERIFIED")
	schemas["NativeAgentNativeGrantCollection"]["oneOf"] = []schema{
		{"required": []string{"count"}, "properties": map[string]schema{"status": agentEnum("COMPLETE"), "reason_codes": {"maxItems": 0}, "verification_scope": agentEnum(agent.NativeGrantVerificationScope), "session_verification": agentEnum(agent.NativeGrantSessionScope, "HISTORY_INCOMPLETE")}},
		{"not": schema{"required": []string{"count"}}, "properties": map[string]schema{"status": agentEnum("UNAVAILABLE"), "items": {"maxItems": 0}, "reason_codes": {"minItems": 1}, "verification_scope": agentEnum("NOT_VERIFIED"), "session_verification": agentEnum("NOT_VERIFIED")}},
	}
	schemas["NativeAgentNativeGrantCollection"]["x-max-json-bytes"] = 512 * 1024
	schemas["NativeAgentNativeGrantCollection"]["description"] = "OFFLINE only. COMPLETE count equals all sorted owned items; UNAVAILABLE omits count, never reports unknown as zero. Historical session scope is explicit and is not current execution authority."
	// Registry is the authoritative finite tool list. Preserve closed argument
	// objects and enrich only the typed template config/reference wire shapes.
	tools, names, modelNames := []schema{}, []string{}, []string{}
	legacyGroups := map[string][]schema{}
	for _, tool := range agent.Registry() {
		var args schema
		if json.Unmarshal(tool.Parameters, &args) != nil {
			panic("invalid Agent registry schema")
		}
		if tool.Name == "object_status" {
			args = agentObject(map[string]schema{"reference": ref("NativeAgentReference")}, "reference")
		}
		if tool.Name == "template_candidate" {
			args = agentObject(map[string]schema{"template_name": agentEnum(templateNames...), "configuration": ref("NativeTemplateConfiguration"), "goal_id": ref("ID"), "policy_id": ref("ID")}, "template_name", "configuration")
		}
		call := agentObject(map[string]schema{"name": agentEnum(tool.Name), "arguments": args}, "name", "arguments")
		tools = append(tools, call)
		switch tool.Name {
		case "funds_summary", "current_rules":
			legacyGroups["Empty"] = append(legacyGroups["Empty"], call)
		case "goal_status", "policy_candidate":
			legacyGroups["Goal"] = append(legacyGroups["Goal"], call)
		case "operation_status":
			legacyGroups["Operation"] = append(legacyGroups["Operation"], call)
		}
		names = append(names, tool.Name)
		if tool.Name != "native_grants" {
			modelNames = append(modelNames, tool.Name)
		}
	}
	for group, calls := range legacyGroups {
		schemas["NativeAgent"+group+"Tool"] = schema{"x-go-type": "json.RawMessage", "oneOf": calls}
	}
	schemas["NativeAgentToolCall"] = schema{"x-go-type": "json.RawMessage", "oneOf": tools}
	schemas["NativeAgentOfflineTurn"] = agentObject(map[string]schema{"mode": agentEnum("OFFLINE"), "tool": ref("NativeAgentToolCall")}, "mode", "tool")
	schemas["NativeAgentModelTurn"] = agentObject(map[string]schema{"mode": agentEnum("MODEL"), "text": {"type": "string", "minLength": 1, "maxLength": 4096, "x-max-utf8-bytes": 4096}}, "mode", "text")
	schemas["NativeAgentTurn"] = schema{"x-go-type": "json.RawMessage", "oneOf": []schema{ref("NativeAgentOfflineTurn"), ref("NativeAgentModelTurn")}, "x-max-utf8-bytes": agent.MaxJSONBytes, "description": "Authenticated scope only. OFFLINE has exactly one registered closed tool; MODEL has only bounded text. No USER authority is accepted. Native grant tools/references/data are OFFLINE-only and never sent to a provider."}
	op := agentProps("NativeAgentObservation")
	op["tool"], op["verification_scope"] = agentEnum(names...), agentEnum("DISPLAY_SNAPSHOT")
	for n, max := range map[string]int{"accounts": 100, "goals": 100, "policies": 100, "grants": 100, "operations": 20, "native_rules": 100, "catalog": 12, "objects": 100, "references": 1000} {
		op[n]["maxItems"] = max
	}
	// OFFLINE has one tool. MODEL forbids repeated names except exact-reference
	// object_status and terminal template_candidate: largest four are 201/101/
	// 101/101, all others <=2. At most eight tools therefore return <=612 refs.
	r := agentProps("NativeAgentResult")
	r["mode"], r["provider_status"] = agentEnum("OFFLINE", "MODEL"), agentEnum("NOT_RUN", "CALLED")
	r["observations"]["maxItems"], r["references"]["maxItems"] = 8, 1000
	schemas["NativeAgentResult"]["x-max-json-bytes"] = 2 * 1024 * 1024
	modelObs := agentCopy(schemas["NativeAgentObservation"])
	modelProps := map[string]schema{}
	for k, v := range op {
		if k != "native_grant" && k != "native_grants" {
			modelProps[k] = v
		}
	}
	modelProps["tool"] = agentEnum(modelNames...)
	modelProps["references"] = schema{"type": "array", "maxItems": 1000, "items": ref("NativeAgentModelReference")}
	for _, n := range []string{"Candidate", "TemplateCandidate"} {
		original := schemas["NativeAgent"+n]
		model := agentCopy(original)
		props := map[string]schema{}
		for k, v := range agentProps("NativeAgent" + n) {
			props[k] = v
		}
		props["reference"] = ref("NativeAgentModelReference")
		model["properties"] = props
		schemas["NativeAgentModel"+n] = model
	}
	modelProps["candidate"] = ref("NativeAgentModelCandidate")
	modelProps["native_candidate"] = ref("NativeAgentModelTemplateCandidate")
	modelObs["properties"] = modelProps
	schemas["NativeAgentModelObservation"] = modelObs
	schemas["NativeAgentResult"]["oneOf"] = []schema{
		{"properties": map[string]schema{"mode": agentEnum("OFFLINE"), "provider_status": agentEnum("NOT_RUN"), "model_used": {"type": "boolean", "enum": []bool{false}}, "observations": {"minItems": 1, "maxItems": 1}}},
		{"properties": map[string]schema{"mode": agentEnum("MODEL"), "provider_status": agentEnum("CALLED"), "model_used": {"type": "boolean", "enum": []bool{true}}, "observations": {"type": "array", "minItems": 1, "maxItems": 8, "items": ref("NativeAgentModelObservation")}, "references": {"type": "array", "maxItems": 1000, "items": ref("NativeAgentModelReference")}, "candidate": ref("NativeAgentModelCandidate"), "native_candidate": ref("NativeAgentModelTemplateCandidate")}},
	}
	for _, n := range []string{"provider_calls", "tool_calls"} {
		agentProps("NativeAgentBudget")[n] = schema{"type": "integer", "minimum": 0, "maximum": 8}
	}
	for _, n := range []string{"reserved_tokens", "reserved_cost_micros"} {
		agentProps("NativeAgentBudget")[n]["minimum"] = 0
	}
	agentProps("NativeAgentBudget")["reserved_tokens"]["maximum"] = 1000000
	agentProps("NativeAgentBudget")["reserved_cost_micros"]["maximum"] = 1000000000
	for _, n := range []string{"input_tokens", "output_tokens", "reported_calls"} {
		agentProps("NativeAgentProviderUsage")[n]["minimum"] = 0
	}
	for _, n := range []string{"input_tokens", "output_tokens"} {
		agentProps("NativeAgentProviderUsage")[n]["maximum"] = 1000000
	}
	agentProps("NativeAgentProviderUsage")["reported_calls"]["maximum"] = 8
	schemas["NativeAgentProviderUsage"]["description"] = "Validated returned replies only, never independent invoice verification. Reserved calls/cost are not refunded for unknown failed attempts."
	agentFailureContract()
}

func agentFailureContract() {
	stages := []string{"BODY_DECODE", "TURN_DECODE", "SNAPSHOT_READ", "SNAPSHOT_VALIDATE", "INPUT_ENCODE", "RESERVE", "PROVIDER_CONFIGURATION", "PROVIDER", "PROVIDER_REPLY_SCHEMA", "PROVIDER_USAGE", "PROVIDER_ENVELOPE", "PROVIDER_HTTP_STATUS", "PROVIDER_RESPONSE", "USAGE", "REPLY_DECODE", "MODEL_TOOL_SCOPE", "DONE_WITHOUT_OBSERVATION", "REPEAT_TOOL", "TOOL_REFERENCE", "TOOL_LIMIT", "OBSERVE", "OBSERVATION_SIZE", "CONTEXT", "FRESH_SNAPSHOT", "FRESH_REFERENCES", "FINAL_SIZE", "UNKNOWN"}
	props := map[string]schema{
		"failure_protocol": agentEnum("zhiyu-agent-failure-v1"), "failure_stage": agentEnum(stages...),
		"failure_reason": agentEnum("REJECTED", "RESERVE_CONFIGURATION", "RESERVE_INPUT_BYTES", "RESERVE_CALLS", "RESERVE_TOKENS", "RESERVE_COST", "TOOL_CALLS", "REPORTED_USAGE"),
		"usage_scope":    agentEnum("PARTIAL_UNKNOWN_ATTEMPTS_NOT_INVOICE", "NO_PROVIDER_RESERVATIONS", "VALIDATED_RETURNED_REPLIES_ONLY_NOT_INVOICE"),
	}
	required := []string{"failure_protocol", "failure_stage", "failure_reason", "provider_calls_reserved", "tool_calls_consumed", "reserved_tokens", "reserved_cost_micros", "validated_input_tokens", "validated_output_tokens", "validated_reported_calls", "usage_scope"}
	for _, n := range required[3:10] {
		props[n] = schema{"type": "string", "pattern": "^(0|[1-9][0-9]*)$", "maxLength": 19}
	}
	schemas["NativeAgentFailureDetails"] = agentObject(props, required...)
	schemas["NativeAgentFailureDetails"]["description"] = "Finite safe failure stage and validated counters only. No raw error, SQL, provider body, object IDs, connection values or secret. Reserved calls do not prove requests arrived; missing usage remains unknown, not free."
	schemas["NativeAgentError"] = schema{"allOf": []schema{ref("ApiError"), {"properties": map[string]schema{"code": agentEnum("AGENT_UNAVAILABLE", "AGENT_INVALID_INPUT", "AGENT_STALE_REFERENCE", "AGENT_BUDGET_EXCEEDED", "AGENT_PROVIDER_NOT_CONFIGURED", "AGENT_TIMEOUT"), "retry_class": agentEnum("USE_OFFLINE", "NEVER", "AFTER_REFRESH"), "details": ref("NativeAgentFailureDetails")}}}}
}
