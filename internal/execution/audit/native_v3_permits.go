package executionaudit

import (
	"encoding/json"
	"fmt"
	"time"
	evidence "zhiyu.local/zhiyu-go/internal/audit"
	"zhiyu.local/zhiyu-go/internal/execution/bankv2"
	funds "zhiyu.local/zhiyu-go/internal/funds/domain"
	planning "zhiyu.local/zhiyu-go/internal/planning/domain"
	policy "zhiyu.local/zhiyu-go/internal/policy/domain"
)

func (g *nativeGraphV3) permitHeaderV3(row *ledgerRow, request bankv2.Request, id funds.ID, permit, rh, eh, sh string, at time.Time) error {
	op := g.row("native_operations", request.OperationID)
	expectedRequest, _ := request.Digest()
	expectedEffect, _ := request.Effect.Digest()
	if op == nil || id.String() != request.OperationID || row.text("operation_id") != request.OperationID || permit != request.PermitID || row.text("permit_id") != permit || rh != expectedRequest || row.text("bank_request_hash") != rh || eh != expectedEffect || row.text("effect_hash") != eh || op.optional("permit_signature") == "" || sh != nakedHash([]byte(op.optional("permit_signature"))) || sh != row.text("signature_hash") || !at.Equal(row.instant("decision_at")) || at.Before(request.RequestedAt) || !at.Before(request.ExpiresAt) || nativeHashFieldV3(row, "original", "original_hash") != nil {
		return businessInvalid("native historical T2 original request/effect/signature/time binding")
	}
	for _, result := range g.bank.Native {
		if result.Key == request.Key && result.AcceptedAt != nil && result.AcceptedAt.Before(at) {
			return businessInvalid("native actual bank acceptance precedes historical T2")
		}
	}
	return nil
}

func (g *nativeGraphV3) exactPrefixV3(group string, count int, prefix []wirenativePrefixReceipt, at time.Time) error {
	if count < 0 || count > 16 || len(prefix) != count {
		return businessInvalid("native exact historical settled prefix length")
	}
	for i := 0; i < count; i++ {
		var operation *ledgerRow
		for _, op := range g.rows["native_operations"] {
			if op.optional("group_id") == group && int(op.positive("child_number")) == i+1 {
				if operation != nil {
					return businessInvalid("native duplicate prefix child")
				}
				operation = op
			}
		}
		if operation == nil || operation.text("status") != "SETTLED" {
			return businessInvalid("native historical prefix lacks a real settled operation")
		}
		receipt := g.row("native_receipts", operation.text("receipt_id"))
		if receipt == nil || receipt.text("operation_id") != operation.text("id") || prefix[i].OperationID != operation.text("id") || prefix[i].ReceiptID != receipt.text("id") || prefix[i].ReceiptHash != receipt.text("original_hash") || receipt.instant("created_at").After(at) {
			return businessInvalid("native historical prefix exact independent receipt original")
		}
	}
	return nil
}

func (g *nativeGraphV3) jointWitnessV3(op *ledgerRow, plan wireNativeJointPlan, w wirenativeJointPermitWitness, at time.Time, bridge bool) error {
	number := int(op.positive("child_number"))
	algorithm := "frozen-joint-exact-owned-prefix-v1"
	if bridge {
		algorithm = "frozen-bridge-arrival-prefix-v1"
	}
	if w.Algorithm != algorithm || w.PrefixSettled != number-1 || w.ReservedFundsVersion != uint64(op.positive("reserved_funds_version")) || w.FundsVersion != w.ReservedFundsVersion+uint64(number-1) || w.SourceVersion != plan.Dependencies.SourceEvidenceVersion+uint64(number-1) || w.WriterGeneration != plan.Dependencies.WriterGeneration || w.ControlVersion != plan.Dependencies.ControlVersion || w.SourceHash != w.ForecastInput.Facts.SourceHash || w.InventoryHash != plan.InventoryHash || w.InventoryHash != w.ForecastInput.InventoryHash || !w.ForecastInput.AsOf.Equal(at) || w.ForecastInput.Scope != g.ownerScopeV3() || len(w.PolicyReferences) != len(plan.PolicyReferences) {
		return businessInvalid("native historical T2 exact owned-prefix dependency witness")
	}
	if err := g.exactPrefixV3(op.text("group_id"), number-1, w.PrefixReceipts, at); err != nil {
		return err
	}
	for i, ref := range w.PolicyReferences {
		expected := plan.PolicyReferences[i]
		for _, p := range w.PrefixReceipts {
			request := g.nativeRequests[p.OperationID]
			if request.Effect.Kind == bankv2.Allocate && request.Effect.DestinationGoalID == ref.GoalID.String() {
				expected.GoalVersion++
			}
		}
		if ref != expected {
			return businessInvalid("native historical T2 current versions include exactly owned settled prefix")
		}
	}
	for _, view := range w.PolicyViews {
		if err := g.frozenVersionV3(view.Version); err != nil {
			return err
		}
	}
	result, err := planning.Forecast365(w.ForecastInput)
	if err != nil || !result.MaximumDeficit.IsZero() {
		return businessInvalid("native historical T2 complete current protection")
	}
	if err = g.frozenForecastV3(w.ForecastInput, result, w.SourceVersion); err != nil {
		return err
	}
	dependencies := plan.Dependencies
	dependencies.FundsVersion, dependencies.SourceEvidenceVersion = w.FundsVersion, w.SourceVersion
	dependencies.WriterGeneration, dependencies.ControlVersion = w.WriterGeneration, w.ControlVersion
	if err := g.queueForecastEconomyV3(w.ForecastInput, dependencies, nil); err != nil {
		return err
	}
	return nil
}

func (g *nativeGraphV3) checkPermitsV3() error {
	for _, row := range g.rows["native_submission_permits"] {
		id := row.text("operation_id")
		request, ok := g.nativeRequests[id]
		op := g.row("native_operations", id)
		if !ok || op == nil || op.optional("permit_signature") == "" {
			return businessInvalid("native orphan historical T2 original")
		}
		var declared struct {
			Protocol string `json:"protocol"`
		}
		if json.Unmarshal(nativeRawV3(row, "original"), &declared) != nil {
			return businessInvalid("native historical T2 declared protocol")
		}
		switch declared.Protocol {
		case "native-standing-submission-permit-v1", "native-standing-submission-permit-v2":
			var p wirenativeStandingSubmissionProof
			nativeOriginalV3(row, "original", &p)
			plan := g.standingPlans[id]
			if plan.allocation == nil {
				return businessInvalid("native standing allocation T2 original plan")
			}
			f := plan.allocation
			if err := g.permitHeaderV3(row, request, p.OperationID, p.PermitID, p.BankRequestHash, p.EffectHash, p.SignatureHash, p.DecisionAt); err != nil {
				return err
			}
			if op.text("mode") != "STANDING" || p.Scope != g.ownerScopeV3() || p.PlanHash != plan.hash || !exactJSON(p.Grant, f.Grant) || p.OccurrenceKey != f.Occurrence.Key || p.GrantStateSequence < f.GrantStateSequence || p.WriterGeneration != f.Dependencies.WriterGeneration || p.ControlVersion != f.Dependencies.ControlVersion {
				return businessInvalid("native standing historical T2 grant/occurrence/dependency")
			}
			if err := g.grantActiveAtV3(p.Grant.ID.String(), p.GrantStateSequence, p.DecisionAt); err != nil {
				return err
			}
			number := 1
			if f.Joint != nil {
				number = f.JointChild
			}
			if p.FundsVersion != f.Dependencies.FundsVersion+uint64(number) || p.SourceVersion != f.Dependencies.SourceEvidenceVersion+uint64(number-1) || f.Joint == nil && (p.Protocol != "native-standing-submission-permit-v1" || len(p.PrefixReceipts) != 0) || f.Joint != nil && p.Protocol != "native-standing-submission-permit-v2" {
				return businessInvalid("native standing historical exact version prefix")
			}
			if f.Joint != nil {
				if err := g.exactPrefixV3(f.Occurrence.ID.String(), number-1, p.PrefixReceipts, p.DecisionAt); err != nil {
					return err
				}
			}
		case "native-standing-asset-v1/permit":
			if raw := nativeRawV3(row, "original"); len(raw) < 1 || len(raw) > nativeStandingAssetPermitStoredLimitV3 {
				return businessInvalid("native standing asset v1 stored capacity")
			}
			var p wirenativeStandingAssetProof
			nativeOriginalV3(row, "original", &p)
			plan := g.standingPlans[id]
			if plan.asset == nil {
				return businessInvalid("native standing asset T2 original plan")
			}
			f := plan.asset
			if err := g.permitHeaderV3(row, request, p.OperationID, p.PermitID, p.RequestHash, p.EffectHash, p.SignatureHash, p.DecisionAt); err != nil {
				return err
			}
			if op.text("mode") != "STANDING" || p.PlanHash != plan.hash || !exactJSON(p.Grant, f.Grant) || p.GrantStateSequence < f.GrantStateSequence {
				return businessInvalid("native standing asset original grant T2")
			}
			if err := g.grantActiveAtV3(p.Grant.ID.String(), p.GrantStateSequence, p.DecisionAt); err != nil {
				return err
			}
			if err := mirrorstandingAssetReplayCurrentV3(*f, p.Current); err != nil {
				return nativeMirrorCheckV3("standing asset T2 current", err)
			}
			expected := mirrorstandingAssetRequestV3(*f, g.manifest.Scope.Namespace, plan.hash)
			if !exactJSON(expected, request) || policy.AuthorizeNativeStanding(p.Grant.Terms, "ACTIVE", f.Authority, f.Usage, p.DecisionAt) != nil {
				return businessInvalid("native standing asset exact T2 request/source/budget")
			}
			ledger, err := g.frozenLedgerV3(p.Current.Ledger, p.DecisionAt, mustBusinessID(id))
			if err != nil {
				return err
			}
			if err := g.frozenForecastEconomyV3(p.Current.ForecastInput, p.Current.ForecastBefore, ledger, p.Current.Dependencies, mustBusinessID(id)); err != nil {
				return err
			}
		case "native-standing-asset-v2/permit":
			if raw := nativeRawV3(row, "original"); len(raw) < 1 || len(raw) > nativeStandingAssetPermitStoredLimitV3 {
				return businessInvalid("native standing asset v2 stored capacity")
			}
			if err := g.checkStandingAssetPermitV2V3(row, request, id, op); err != nil {
				return err
			}
		case "native-automation-v1/payment-submission-permit":
			var p wirenativeStandingPaymentProof
			nativeOriginalV3(row, "original", &p)
			plan := g.standingPlans[id]
			if plan.payment == nil {
				return businessInvalid("native standing payment T2 original plan")
			}
			f := plan.payment
			if err := g.permitHeaderV3(row, request, p.OperationID, p.PermitID.String(), p.BankRequestHash, p.EffectHash, p.SignatureHash, p.DecisionAt); err != nil {
				return err
			}
			if op.text("mode") != "STANDING" || p.GrantStateSequence < f.GrantStateSequence {
				return businessInvalid("native standing payment historical mode/state")
			}
			if err := g.grantActiveAtV3(p.Grant.ID.String(), p.GrantStateSequence, p.DecisionAt); err != nil {
				return err
			}
			if err := mirrorvalidateStandingPaymentProofV3(*f, plan.hash, p, request); err != nil {
				return nativeMirrorCheckV3("standing payment T2", err)
			}
			ledger, err := g.frozenLedgerV3(p.Current.Ledger, p.DecisionAt, mustBusinessID(id))
			if err != nil {
				return err
			}
			if err := g.frozenForecastEconomyV3(p.Current.ForecastInput, p.Current.ForecastBefore, ledger, p.Current.Dependencies, mustBusinessID(id)); err != nil {
				return err
			}
		case "native-submission-permit-v1":
			return &evidence.ReferenceError{ID: "native-v3:historical-joint-t2-witness", Cause: fmt.Errorf("%w: historical v1 native T2 lacks its complete owned-prefix witness", evidence.ErrIncomplete)}
		case "native-submission-permit-v2":
			var p wirenativeSubmissionProof
			nativeOriginalV3(row, "original", &p)
			plan, ok := g.jointPlans[op.text("plan_id")]
			approval, approved := g.onceApprovals[id].(wirenativeJointApproval)
			if !ok || !approved || op.text("mode") != "ONCE" || p.Witness == nil || !exactJSON(p.Approval, approval) || p.DecisionAt.Before(approval.ConfirmedAt) {
				return businessInvalid("native joint historical T2 full USER original")
			}
			if err := g.permitHeaderV3(row, request, p.OperationID, p.PermitID, p.BankRequestHash, p.EffectHash, p.SignatureHash, p.DecisionAt); err != nil {
				return err
			}
			if err := g.jointWitnessV3(op, plan, *p.Witness, p.DecisionAt, false); err != nil {
				return err
			}
		case "native-asset-submission-permit-v1":
			var p wirenativeAssetSubmissionProof
			nativeOriginalV3(row, "original", &p)
			preview, ok := g.nativeActions[op.text("preview_id")].(wireNativeAssetPreview)
			approval, approved := g.onceApprovals[id].(wirenativeAssetApproval)
			if !ok || !approved || op.text("mode") != "ONCE" || p.PreviewID != preview.ID || !exactJSON(p.Approval, approval) || p.DecisionAt.Before(approval.ConfirmedAt) {
				return businessInvalid("native asset historical T2 full USER original")
			}
			if err := g.permitHeaderV3(row, request, p.OperationID, p.PermitID, p.BankRequestHash, p.EffectHash, p.SignatureHash, p.DecisionAt); err != nil {
				return err
			}
			if err := mirrorassetValidateWitnessV3(preview, approval, p.Witness, p.DecisionAt); err != nil {
				return nativeMirrorCheckV3("asset T2", err)
			}
			ledger, err := g.frozenLedgerV3(p.Witness.Current.Ledger, p.DecisionAt, mustBusinessID(id))
			if err != nil {
				return err
			}
			if err := g.frozenForecastEconomyV3(p.Witness.Current.ForecastInput, p.Witness.Current.ForecastBefore, ledger, p.Witness.Current.Dependencies, mustBusinessID(id)); err != nil {
				return err
			}
		case "native-payment-submission-permit-v1":
			var p wirenativePaymentSubmissionProof
			nativeOriginalV3(row, "original", &p)
			preview, ok := g.nativeActions[op.text("preview_id")].(wireNativePaymentPreview)
			approval, approved := g.onceApprovals[id].(wirenativePaymentApproval)
			if !ok || !approved || op.text("mode") != "ONCE" || !exactJSON(p.Approval, approval) {
				return businessInvalid("native payment historical T2 full USER original")
			}
			if err := g.permitHeaderV3(row, request, p.OperationID, p.PermitID, p.BankRequestHash, p.EffectHash, p.SignatureHash, p.DecisionAt); err != nil {
				return err
			}
			if err := mirrorvalidatePaymentProofV3(preview, p, request); err != nil {
				return nativeMirrorCheckV3("payment T2", err)
			}
			ledger, err := g.frozenLedgerV3(p.Current.Ledger, p.DecisionAt, mustBusinessID(id))
			if err != nil {
				return err
			}
			if err := g.frozenForecastEconomyV3(p.Current.ForecastInput, p.Current.ForecastBefore, ledger, p.Current.Dependencies, mustBusinessID(id)); err != nil {
				return err
			}
		case "native-goal-transfer-submission-permit-v1":
			var p wirenativeGoalTransferSubmissionProof
			nativeOriginalV3(row, "original", &p)
			preview, ok := g.nativeActions[op.text("preview_id")].(wireNativeGoalTransferPreview)
			approval, approved := g.onceApprovals[id].(wirenativeGoalTransferApproval)
			if !ok || !approved || op.text("mode") != "ONCE" || p.PreviewID != preview.ID || !exactJSON(p.Approval, approval) {
				return businessInvalid("native paired historical T2 full independent USER originals")
			}
			if err := g.permitHeaderV3(row, request, p.OperationID, p.PermitID, p.BankRequestHash, p.EffectHash, p.SignatureHash, p.DecisionAt); err != nil {
				return err
			}
			if err := mirrorgoalTransferValidateWitnessV3(preview, approval, p.Witness, p.DecisionAt); err != nil {
				return nativeMirrorCheckV3("paired transfer T2", err)
			}
			dependencies := preview.Dependencies
			dependencies.FundsVersion, dependencies.SourceEvidenceVersion = p.Witness.FundsVersion, p.Witness.SourceVersion
			dependencies.WriterGeneration, dependencies.ControlVersion = p.Witness.WriterGeneration, p.Witness.ControlVersion
			if err := g.queueForecastEconomyV3(p.Witness.ForecastInput, dependencies, nil, mustBusinessID(id)); err != nil {
				return err
			}
			if err := g.frozenForecastV3(p.Witness.ForecastInput, p.Witness.ForecastBefore, p.Witness.SourceVersion); err != nil {
				return err
			}
		case "native-bridge-submission-permit-v1", "native-standing-bridge-permit-v1":
			if err := g.bridgePermitV3(row, op, request, declared.Protocol); err != nil {
				return err
			}
		default:
			return fmt.Errorf("%w: native historical T2 protocol", evidence.ErrUnsupportedVersion)
		}
	}
	return g.checkedRowsV3()
}
