package executionaudit

import (
	"encoding/json"
	"fmt"
	"strconv"
	"time"

	evidence "zhiyu.local/zhiyu-go/internal/audit"
	"zhiyu.local/zhiyu-go/internal/execution/bankv2"
	funds "zhiyu.local/zhiyu-go/internal/funds/domain"
	policy "zhiyu.local/zhiyu-go/internal/policy/domain"
)

func (g *nativeGraphV3) allocationTimezoneV3(id string) (string, error) {
	op := g.row("native_operations", id)
	if op == nil {
		return "", businessInvalid("goal counter allocation action absent")
	}
	if grantID := op.optional("grant_id"); grantID != "" {
		row := g.row("native_grants", grantID, strconv.FormatInt(op.positive("grant_version"), 10))
		var grant nativeGrantV3
		if row == nil || nativeHashFieldV3(row, "original", "original_hash") != nil || json.Unmarshal(nativeRawV3(row, "original"), &grant) != nil || grant.ID.String() != grantID {
			return "", businessInvalid("goal counter original standing timezone authority")
		}
		return grant.Terms.Timezone, nil
	}
	row := g.row("native_joint_plans", op.text("plan_id"))
	var plan wireNativeJointPlan
	if row == nil || nativeHashFieldV3(row, "original", "original_hash") != nil || json.Unmarshal(nativeRawV3(row, "original"), &plan) != nil || plan.ID.String() != op.text("plan_id") {
		return "", fmt.Errorf("%w: goal counter actual reviewed allocation timezone missing", evidence.ErrIncomplete)
	}
	return plan.Input.ProtectionForecast.Timezone, nil
}

// Raw goal month counters are persistent financial projections, even when a
// particular forecast independently derives its own monthly contribution.
// A version with no consumer must not alter and later restore these counters.
func (g *nativeGraphV3) checkFundsGoalCountersV3(before nativeFinancialRowSetV3, commit nativeFundsCommitV3) error {
	type allocation struct {
		amount funds.Money
		period string
	}
	allocations := map[string][]allocation{}
	economicVersions := map[string]int64{}
	after := map[string]string{}
	for key, raw := range before["goals"] {
		after[key] = raw
	}
	for _, change := range commit.Changes {
		if change.AfterOriginal == nil {
			continue
		}
		value, err := nativeFundsObjectV3(*change.AfterOriginal)
		if err != nil {
			return err
		}
		row := &ledgerRow{values: value}
		if change.Table == "goals" {
			after[change.RowKey] = *change.AfterOriginal
		}
		if change.BeforeHash != nil || change.Table != "receipts" && change.Table != "native_receipts" {
			continue
		}
		id := row.text("operation_id")
		if change.Table == "receipts" {
			request, ok := g.legacy.requests[id]
			var receipt businessReceipt
			if !ok || json.Unmarshal(nativeRawV3(row, "original"), &receipt) != nil || request.Kind != "ALLOCATE_GOAL" {
				return businessInvalid("goal counter original legacy receipt")
			}
			allocations[request.GoalID] = append(allocations[request.GoalID], allocation{request.Amount, receipt.SettledAt.In(time.FixedZone("Asia/Shanghai", 8*3600)).Format("2006-01")})
			economicVersions[request.GoalID]++
			continue
		}
		request, ok := g.nativeRequests[id]
		receipt, known := g.nativeReceipts[id]
		if !ok || !known || receipt.BankResult.SettledAt == nil {
			return businessInvalid("goal counter original native receipt")
		}
		e := request.Effect
		switch e.Kind {
		case bankv2.Allocate:
			timezone, err := g.allocationTimezoneV3(id)
			if err != nil {
				return err
			}
			zone, err := policy.TemplateLocation(timezone)
			if err != nil {
				return err
			}
			allocations[e.DestinationGoalID] = append(allocations[e.DestinationGoalID], allocation{e.Amount, receipt.BankResult.SettledAt.In(zone).Format("2006-01")})
			economicVersions[e.DestinationGoalID]++
		case bankv2.Purchase, bankv2.Redeem, bankv2.Mature:
			if e.SourceGoalID != "" {
				economicVersions[e.SourceGoalID]++
			}
		case bankv2.MoveGoal:
			economicVersions[e.SourceGoalID]++
			economicVersions[e.DestinationGoalID]++
		}
	}
	for key, raw := range after {
		value, _ := nativeFundsObjectV3(raw)
		goal := &ledgerRow{values: value}
		id := goal.text("id")
		old, exists := before["goals"][key]
		if !exists {
			period := goal.text("month_period")
			date, err := time.Parse("2006-01", period)
			if err != nil || date.Format("2006-01") != period || !goal.money("month_contributed_cents").IsZero() || !goal.money("assigned_cents").IsZero() || goal.positive("version") != 1 || economicVersions[id] != 0 {
				return businessInvalid("new goal starts with exact zero financial counters and version one")
			}
			continue
		}
		prior, _ := nativeFundsObjectV3(old)
		previous := &ledgerRow{values: prior}
		period, amount := previous.text("month_period"), previous.money("month_contributed_cents")
		for _, a := range allocations[id] {
			if period != a.period {
				period, amount = a.period, funds.Money{}
			}
			var err error
			amount, err = amount.Add(a.amount)
			if err != nil {
				return err
			}
		}
		if goal.text("month_period") != period || goal.money("month_contributed_cents") != amount {
			return businessInvalid("funds prefix raw goal natural-month counters differ from exact same-FV allocation receipts")
		}
		metadata, err := g.goalMetadataVersionChangesV3(previous, goal, commit)
		if err != nil {
			return err
		}
		if goal.positive("version") != previous.positive("version")+economicVersions[id]+metadata {
			return businessInvalid("funds prefix goal version lacks exact same-FV economic or USER metadata source")
		}
		if goal.err != nil || previous.err != nil {
			return businessInvalid("funds prefix raw goal counter fields")
		}
	}
	return nil
}

func (g *nativeGraphV3) goalMetadataVersionChangesV3(before, after *ledgerRow, commit nativeFundsCommitV3) (int64, error) {
	nameChanged := before.text("name") != after.text("name")
	targetChanged := before.money("target_cents") != after.money("target_cents")
	policyChanged := before.optional("policy_id") != after.optional("policy_id") || before.values["policy_version"] != after.values["policy_version"]
	var count int64
	if nameChanged || targetChanged {
		matched := false
		for _, row := range g.rows["goal_configuration_events"] {
			var c nativeGoalConfigurationV3
			if json.Unmarshal(nativeRawV3(row, "original"), &c) == nil && c.Action == "UPDATE" && c.Before != nil && c.After.ID.String() == after.text("id") && c.Before.Version == uint64(before.positive("version")) && c.After.Version == uint64(after.positive("version")) && c.Before.Name == before.text("name") && c.After.Name == after.text("name") && c.Before.Target == before.money("target_cents") && c.After.Target == after.money("target_cents") {
				matched = true
			}
		}
		for _, change := range commit.Changes {
			if !nameChanged && change.Table == "template_policy_confirmations" && change.BeforeHash == nil && change.AfterOriginal != nil {
				v, _ := nativeFundsObjectV3(*change.AfterOriginal)
				var c nativeTemplateConfirmationV3
				if json.Unmarshal(nativeRawV3(&ledgerRow{values: v}, "original"), &c) == nil && c.TargetMutation != nil && c.TargetMutation.GoalID.String() == after.text("id") && c.TargetMutation.Before == before.money("target_cents") && c.TargetMutation.After == after.money("target_cents") {
					matched = true
				}
			}
		}
		if !matched {
			return 0, businessInvalid("funds prefix goal metadata changed without exact original USER transition")
		}
		count++
	}
	if policyChanged {
		p, found := g.legacy.policies[versionKey(after.optional("policy_id"), uint64(after.positive("policy_version")))]
		if before.optional("policy_id") != "" || !found || p.Version != 1 || p.Scope.GoalID.String() != after.text("id") {
			return 0, businessInvalid("funds prefix legacy policy binding lacks exact first USER installation")
		}
		count++
	}
	return count, nil
}
