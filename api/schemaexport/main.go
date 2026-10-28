// schemaexport emits the native transport DTO shapes without accessing runtime
// configuration, a database, credentials, or a provider. Domain validation is
// still authoritative; generated shapes do not convey financial permission.
package main

import (
	"encoding/json"
	"fmt"
	"os"
	"reflect"
	"strings"
	"time"

	"zhiyu.local/zhiyu-go/internal/app"
	funds "zhiyu.local/zhiyu-go/internal/funds/domain"
	history "zhiyu.local/zhiyu-go/internal/history/domain"
	policy "zhiyu.local/zhiyu-go/internal/policy/domain"
	"zhiyu.local/zhiyu-go/internal/transport/httpapi"
)

type schema map[string]any

var schemas = map[string]schema{}

func ref(name string) schema { return schema{"$ref": "#/components/schemas/" + name} }
func name(t reflect.Type) string {
	p := strings.TrimPrefix(t.PkgPath(), "zhiyu.local/zhiyu-go/internal/")
	p = strings.TrimSuffix(p, "/domain")
	p = strings.ReplaceAll(p, "/", "_")
	return "Native" + strings.ToUpper(p[:1]) + p[1:] + t.Name()
}
func shape(t reflect.Type) schema {
	if t.Kind() == reflect.Pointer {
		value := shape(t.Elem())
		if _, ok := value["$ref"]; ok {
			return schema{"allOf": []schema{value}, "nullable": true}
		}
		value["nullable"] = true
		return value
	}
	if t == reflect.TypeOf(funds.ID{}) {
		return ref("ID")
	}
	if t == reflect.TypeOf(funds.Money{}) {
		return ref("Money")
	}
	if t == reflect.TypeOf(time.Time{}) {
		return ref("Timestamp")
	}
	if t == reflect.TypeOf(json.RawMessage{}) {
		return schema{"type": "object", "additionalProperties": true}
	}
	if t.Kind() == reflect.Slice && t.Elem().Kind() == reflect.Uint8 {
		return schema{"type": "string", "format": "byte"}
	}
	if t.Kind() == reflect.Struct {
		n := name(t)
		if _, ok := schemas[n]; ok {
			return ref(n)
		}
		schemas[n] = schema{}
		props, required := map[string]schema{}, []string{}
		var fields func(reflect.Type)
		fields = func(v reflect.Type) {
			for i := 0; i < v.NumField(); i++ {
				f := v.Field(i)
				if !f.IsExported() {
					continue
				}
				tag := f.Tag.Get("json")
				if tag == "-" {
					continue
				}
				parts := strings.Split(tag, ",")
				key := parts[0]
				if f.Anonymous && key == "" {
					fields(f.Type)
					continue
				}
				if key == "" {
					key = f.Name
				}
				props[key] = shape(f.Type)
				if f.Name == "BankAuthority" {
					props[key] = schema{"type": "boolean", "enum": []bool{false}}
				}
				if !strings.Contains(tag, ",omitempty") {
					required = append(required, key)
				}
			}
		}
		fields(t)
		schemas[n] = schema{"type": "object", "additionalProperties": false, "properties": props, "required": required}
		return ref(n)
	}
	switch t.Kind() {
	case reflect.String:
		return schema{"type": "string"}
	case reflect.Bool:
		return schema{"type": "boolean"}
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		return schema{"type": "integer", "format": "int64"}
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		return schema{"type": "integer", "format": "int64", "minimum": 0}
	case reflect.Slice, reflect.Array:
		return schema{"type": "array", "items": shape(t.Elem())}
	case reflect.Map:
		return schema{"type": "object", "additionalProperties": shape(t.Elem())}
	default:
		panic("unsupported native transport type: " + t.String())
	}
}
func main() {
	for _, v := range []any{app.GoalConfigurationRequest{}, app.GoalDetail{}, app.TemplatePolicyRequest{}, app.TemplatePolicyConfirmation{}, app.TemplatePolicyPreview{}, app.TemplatePolicyView{}, app.ForecastView{}, app.AuditRequest{}, app.AuditRun{}, app.AuditAnchorRequest{}, app.AuditAnchor{}, app.JointPlanRequest{}, app.NativeJointView{}, app.NativeJointCommand{}, app.NativeOperationGroup{}, app.NativeReceipt{}, app.NativeBridgePreviewRequest{}, app.NativeBridgePreview{}, app.NativeBridgeCommand{}, app.NativeBridgeGroup{}, app.NativePriorityRequest{}, app.NativePriorityAnalysis{}, app.NativePriorityAnswerRequest{}, app.NativePriorityAnswer{}, app.NativeGoalTransferPreviewRequest{}, app.NativeGoalTransferPreview{}, app.NativeGoalTransferCommand{}, app.NativeOperation{}, app.NativeAssetRequest{}, app.NativeAssetPreview{}, app.NativeAssetCommand{}, app.NativePaymentRequest{}, app.NativePaymentPreview{}, app.NativePaymentCommand{}, app.NativeIncomeImportResult{}, app.NativeFinancialOptions{}, app.NativeActivityOriginal{}, app.NativeDashboardView{}} {
		shape(reflect.TypeOf(v))
	}
	for _, v := range []any{app.NativeStandingGrantRequest{}, app.NativeStandingGrantPreview{}, app.NativeStandingGrantConfirmation{}, app.NativeStandingGrantView{}, app.NativeGrantStateRequest{}, app.NativeFamilyCapability{}, app.NativeBillImportRequest{}, app.NativeBillSourcesView{}, app.NativeBillIntakeView{}, app.HistoryArchive{}, app.HistoryArchiveList{}, app.HistoryMappingPreview{}, app.HistoryImportRequest{}, app.HistoryImport{}, app.HistoryImportList{}, history.Bundle{}} {
		shape(reflect.TypeOf(v))
	}
	for _, v := range []any{httpapi.ForecastHistorySourceRequest{}, app.ForecastHistorySourceView{}, app.ForecastHistoryImport{}} {
		shape(reflect.TypeOf(v))
	}
	configs := []struct {
		value    any
		kind     string
		required []string
	}{
		{policy.RecurringObligationConfig{}, "recurring_obligation", []string{"payee_id", "amount_rule", "due_day"}},
		{policy.LivingReserveConfig{}, "living_reserve", []string{"horizon_days", "method"}},
		{policy.EmergencyBufferConfig{}, "emergency_buffer", []string{"amount_cents"}},
		{policy.DatedExpenseConfig{}, "dated_expense", []string{"window", "amount"}},
		{policy.LongTermGoalConfig{}, "long_term_goal", []string{"target_cents", "deadline", "monthly_contribution"}},
		{policy.PeriodicTransferConfig{}, "periodic_transfer", []string{"source_account_id", "payee_id", "amount_rule", "due_day", "single_action_cap_cents"}},
		{policy.AssetAuthorizationConfig{}, "asset_authorization", []string{"scope", "allowed_asset_classes", "max_auto_managed_cents", "single_action_cap_cents", "max_redemption_delay_days", "max_lock_days"}},
		{policy.RecoveryConfig{}, "recovery", []string{"scope", "asset_policy_id", "triggers", "single_action_cap_cents", "max_redemption_delay_days"}},
		{policy.GoalAllocationConfig{}, "goal_allocation", []string{"goal_ids", "max_single_allocation_cents"}},
		{policy.CrossGoalReallocationConfig{}, "cross_goal_reallocation", []string{}},
		{policy.SeasonalReserveConfig{}, "seasonal_reserve", []string{"holiday_code", "window", "lookback_days", "minimum_historical_windows", "quantile", "essential_categories", "adjustment_cap_cents"}},
		{policy.InterventionConfig{}, "intervention", []string{}},
	}
	choices := []schema{}
	for _, c := range configs {
		t := reflect.TypeOf(c.value)
		r := shape(t)
		s := schemas[name(t)]
		props := s["properties"].(map[string]schema)
		props["type"] = schema{"type": "string", "enum": []string{c.kind}}
		s["required"] = append([]string{"type"}, c.required...)
		choices = append(choices, r)
	}
	schemas["NativeTemplateConfiguration"] = schema{"oneOf": choices, "description": "Closed twelve-template configuration. Missing documented default fields are compiled by the server; cross-field and current-fact checks are authoritative domain rules."}
	for _, n := range []string{"NativeAppTemplatePolicyRequest", "NativePolicyCompiledTemplate"} {
		schemas[n]["properties"].(map[string]schema)["configuration"] = ref("NativeTemplateConfiguration")
	}
	names := []string{}
	for _, n := range policy.TemplateNames() {
		names = append(names, string(n))
	}
	schemas["NativeAppTemplatePolicyRequest"]["properties"].(map[string]schema)["template_name"] = schema{"type": "string", "enum": names}
	// AmountRule has a kind-dependent custom JSON encoder, not a bag of optional
	// fields. Reflecting the Go storage struct alone would misstate its wire form.
	rule := name(reflect.TypeOf(policy.TemplateAmountRule{}))
	schemas[rule] = schema{"oneOf": []schema{
		{"type": "object", "additionalProperties": false, "required": []string{"kind", "amount_cents"}, "properties": schema{"kind": schema{"type": "string", "enum": []string{"exact"}}, "amount_cents": ref("Money")}},
		{"type": "object", "additionalProperties": false, "required": []string{"kind", "min_cents", "max_cents"}, "properties": schema{"kind": schema{"type": "string", "enum": []string{"range"}}, "min_cents": ref("Money"), "max_cents": ref("Money")}},
		{"type": "object", "additionalProperties": false, "required": []string{"kind", "account_id"}, "properties": schema{"kind": schema{"type": "string", "enum": []string{"bill_balance"}}, "account_id": ref("ID")}},
	}}
	agentContracts(names)
	if err := json.NewEncoder(os.Stdout).Encode(schemas); err != nil {
		fmt.Fprintln(os.Stderr, "native schema export failed")
		os.Exit(1)
	}
}
