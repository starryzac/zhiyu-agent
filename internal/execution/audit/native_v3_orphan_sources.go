package executionaudit

import (
	"bytes"
	"fmt"

	evidence "zhiyu.local/zhiyu-go/internal/audit"
	"zhiyu.local/zhiyu-go/internal/execution/bankv2"
	funds "zhiyu.local/zhiyu-go/internal/funds/domain"
	planning "zhiyu.local/zhiyu-go/internal/planning/domain"
)

type nativeJointExecutionOriginalV3 struct {
	Protocol           string              `json:"protocol"`
	PlanID             funds.ID            `json:"plan_id"`
	ReviewedBundleHash string              `json:"reviewed_bundle_hash"`
	Child              planning.JointChild `json:"child"`
	Request            bankv2.Request      `json:"bank_request"`
}
type nativeStandingExecutionOriginalV3 struct {
	Protocol string         `json:"protocol"`
	PlanID   funds.ID       `json:"plan_id"`
	PlanHash string         `json:"plan_hash"`
	Request  bankv2.Request `json:"request"`
}

// Typed candidate tables may retain previews never accepted by a USER. These
// execution previews instead freeze T1 commands, except the explicit whole
// BRIDGE_GROUP draft. Do not confuse absence of execution with missing proof.
func (g *nativeGraphV3) checkOrphanSourcesV3() error {
	confirmations := map[string]int{}
	versions := map[string]bool{}
	for _, row := range g.rows["template_policy_versions"] {
		versions[row.text("id")] = true
		confirmations[row.text("confirmation_id")]++
	}
	for _, row := range g.rows["template_policy_confirmations"] {
		if confirmations[row.id("id").String()] != 1 {
			return businessInvalid("template confirmation must belong to exactly one verified version")
		}
	}
	for _, row := range g.rows["template_policy_status_events"] {
		if !versions[row.text("version_id")] {
			return businessInvalid("template lifecycle original has no verified historical version")
		}
	}
	for _, row := range g.rows["native_previews"] {
		kind := row.text("kind")
		switch kind {
		case "BRIDGE_GROUP":
			// onceBridgeOriginalsV3 also accepts the real pre-T1 draft without
			// fabricating a batch, confirmation, operation or financial effect.
			if _, _, _, err := g.onceBridgeOriginalsV3(row.id("id").String()); err != nil {
				return err
			}
			continue
		case "JOINT_ALLOCATE", "STANDING_ALLOCATE", "STANDING_BRIDGE_TRANSFER", "STANDING_BRIDGE_ALLOCATE", string(bankv2.Purchase), string(bankv2.Redeem), string(bankv2.Mature), string(bankv2.Payment), string(bankv2.MoveGoal):
		default:
			return fmt.Errorf("%w: native execution preview kind %s", evidence.ErrUnsupportedVersion, kind)
		}
		id := row.id("id").String()
		var dependencies planning.DependencyVector
		row.object("dependencies", &dependencies)
		var request bankv2.Request
		nativeOriginalV3(row, "bank_request", &request)
		raw, canonicalErr := request.CanonicalBytes()
		hash, hashErr := request.Digest()
		effect, effectErr := request.Effect.Digest()
		if nativeHashFieldV3(row, "original", "original_hash") != nil || canonicalErr != nil || hashErr != nil || effectErr != nil || !bytes.Equal(raw, nativeRawV3(row, "bank_request")) || hash != row.text("bank_request_hash") || effect != row.text("effect_hash") || request.Namespace != g.manifest.Scope.Namespace || request.UserID != g.manifest.Scope.UserID || nakedHash(mustJSONV3(dependencies)) != row.text("dependencies_hash") {
			return businessInvalid("native execution preview original bank request/effect/dependency")
		}
		var operation *ledgerRow
		for _, op := range g.rows["native_operations"] {
			if op.text("preview_id") == id {
				if operation != nil {
					return businessInvalid("native execution preview reused by multiple operations")
				}
				operation = op
			}
		}
		if operation == nil {
			return fmt.Errorf("%w: execution preview has no retained T1 consumer; typed candidate drafts remain separate", evidence.ErrIncomplete)
		}
		opID := operation.text("id")
		actual, ok := g.nativeRequests[opID]
		if !ok || operation.text("command_kind") != kind || !exactJSON(actual, request) || !exactJSON(operation.values["dependencies"], row.values["dependencies"]) {
			return businessInvalid("native execution preview differs from original T1 consumer")
		}
		if operation.text("mode") == "ONCE" {
			if kind == "JOINT_ALLOCATE" {
				var original nativeJointExecutionOriginalV3
				nativeOriginalV3(row, "original", &original)
				plan, found := g.jointPlans[original.PlanID.String()]
				number := int(operation.positive("child_number"))
				if !found || original.Protocol != "native-joint-execution-preview-v1" || original.PlanID.String() != operation.text("plan_id") || original.ReviewedBundleHash != nakedHash(mustJSONV3(plan)) || number < 1 || number > len(plan.Result.Children) || !exactJSON(original.Child, plan.Result.Children[number-1]) || !exactJSON(original.Request, request) {
					return businessInvalid("joint execution preview exact validated plan/child/request")
				}
			} else {
				candidate := g.row("native_action_previews", id)
				if candidate == nil || !bytes.Equal(nativeRawV3(row, "original"), nativeRawV3(candidate, "original")) {
					return businessInvalid("ONCE execution preview differs from validated typed candidate")
				}
			}
		} else if operation.text("mode") == "STANDING" {
			if kind == string(bankv2.Payment) {
				plan := g.row("native_standing_plans", operation.text("plan_id"))
				if plan == nil || g.standingPlans[operation.text("plan_id")].payment == nil || !bytes.Equal(nativeRawV3(row, "original"), nativeRawV3(plan, "original")) {
					return businessInvalid("standing payment execution preview exact typed plan")
				}
			} else {
				var original nativeStandingExecutionOriginalV3
				nativeOriginalV3(row, "original", &original)
				protocol, planHash := "native-automation-v1/allocation-execution", g.standingPlans[operation.text("plan_id")].hash
				if kind == string(bankv2.Purchase) {
					protocol = "native-standing-asset-v1/execution"
				}
				if kind == "STANDING_BRIDGE_TRANSFER" || kind == "STANDING_BRIDGE_ALLOCATE" {
					protocol = "native-standing-bridge-v1/execution"
					group := g.row("native_standing_bridge_groups", operation.text("group_id"))
					if group == nil {
						return businessInvalid("standing bridge execution source missing")
					}
					planHash = group.text("original_hash")
				}
				if original.Protocol != protocol || original.PlanID.String() != operation.text("plan_id") || original.PlanHash != planHash || planHash == "" || !exactJSON(original.Request, request) {
					return businessInvalid("standing execution preview exact protocol/plan/request")
				}
			}
		} else {
			return businessInvalid("native execution preview unknown permission mode")
		}
	}
	return g.checkedRowsV3()
}
