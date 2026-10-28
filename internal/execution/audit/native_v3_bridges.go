package executionaudit

import (
	"bytes"
	"fmt"
	"time"
	evidence "zhiyu.local/zhiyu-go/internal/audit"

	"zhiyu.local/zhiyu-go/internal/execution/bankv2"
	funds "zhiyu.local/zhiyu-go/internal/funds/domain"
	policy "zhiyu.local/zhiyu-go/internal/policy/domain"
)

type nativeBridgeCommandV3 struct {
	PreviewID    funds.ID `json:"preview_id"`
	ReviewedHash string   `json:"reviewed_hash"`
}

func (g *nativeGraphV3) onceBridgeOriginalsV3(id string) (wireNativeBridgePreview, wireNativeJointPlan, wirenativeBridgeApproval, error) {
	var p wireNativeBridgePreview
	var a wirenativeBridgeApproval
	row := g.row("native_previews", id)
	if row == nil || row.text("kind") != "BRIDGE_GROUP" {
		return p, wireNativeJointPlan{}, a, businessInvalid("native whole bridge preview missing")
	}
	nativeOriginalV3(row, "original", &p)
	plan, ok := g.jointPlans[p.PlanID.String()]
	review, err := mirrornativeBridgeReviewHashV3(p)
	if !ok || nativeHashFieldV3(row, "original", "original_hash") != nil || p.Protocol != "native-bridge-group-v1" || p.ID.String() != id || p.EnvironmentID.String() != g.manifest.Scope.EnvironmentID || p.UserID.String() != g.manifest.Scope.UserID || p.PlanHash != nakedHash(mustJSONV3(plan)) || review != p.ReviewHash || err != nil || p.ReviewHash != row.text("effect_hash") || p.CreatedAt.Before(plan.CreatedAt) || !p.CreatedAt.Before(p.ExpiresAt) || !p.ExpiresAt.Equal(plan.ExpiresAt) || !p.CreatedAt.Equal(row.instant("created_at")) || !p.ExpiresAt.Equal(row.instant("expires_at")) || plan.Result.Status != "OPTIMAL" || len(plan.Result.Children) < 1 || len(plan.Result.Children) > 8 || len(p.Steps) < 1 || len(p.Steps) > 16 {
		return p, plan, a, businessInvalid("native whole bridge scope/review/complete optimal plan")
	}
	if err = g.humanAtV3(p.SessionID, p.CreatedAt); err != nil {
		return p, plan, a, err
	}
	var refs []wireNativeJointPolicyReference
	row.object("policy_refs", &refs)
	if !exactJSON(refs, plan.PolicyReferences) || row.text("source_hash") != plan.SourceHash || !exactJSON(row.values["dependencies"], mustObjectV3(plan.Dependencies)) {
		return p, plan, a, businessInvalid("native whole bridge complete frozen dependency set")
	}
	number := 0
	ids := map[funds.ID]bool{}
	permits := map[string]bool{}
	confirmations := map[funds.ID]bool{}
	for _, child := range plan.Result.Children {
		var version uint64
		for _, ref := range plan.PolicyReferences {
			if ref.PolicyID == child.PolicyID && ref.VersionID == child.VersionID {
				version = ref.Version
			}
		}
		phases := []bankv2.Kind{bankv2.Allocate}
		if child.SourceAccountID != child.DestinationAccountID {
			phases = []bankv2.Kind{bankv2.Transfer, bankv2.Allocate}
		}
		for phaseIndex, phase := range phases {
			if number >= len(p.Steps) {
				return p, plan, a, businessInvalid("native whole bridge omitted economic step")
			}
			step := p.Steps[number]
			number++
			if step.Number != number || step.ChildNumber != child.Number || step.GoalID != child.GoalID || step.InitialSource != (phaseIndex == 0) || step.OperationID == (funds.ID{}) || step.ConfirmationID == (funds.ID{}) || ids[step.OperationID] || permits[step.Request.PermitID] || confirmations[step.ConfirmationID] {
				return p, plan, a, businessInvalid("native whole bridge step identities")
			}
			ids[step.OperationID] = true
			permits[step.Request.PermitID] = true
			confirmations[step.ConfirmationID] = true
			if number == 1 && step.PreviousOperationID != nil || number > 1 && (step.PreviousOperationID == nil || *step.PreviousOperationID != p.Steps[number-2].OperationID) {
				return p, plan, a, businessInvalid("native whole bridge complete ordered predecessor set")
			}
			account := child.DestinationAccountID
			kind := "BRIDGE_ALLOCATE"
			operation := funds.AllocateGoal
			var destination *funds.ID
			if phase == bankv2.Transfer {
				account = child.SourceAccountID
				kind = "BRIDGE_TRANSFER"
				operation = funds.TransferInternal
				v := child.DestinationAccountID
				destination = &v
			}
			uses := make([]funds.IncomeUse, len(child.Uses))
			bankUses := make([]bankv2.OriginUse, len(child.Uses))
			for i, use := range child.Uses {
				if phase == bankv2.Allocate {
					use.AccountID = account
					use.FragmentID = funds.LocationID(use.OriginID, account)
				}
				uses[i] = use
				bankUses[i] = bankv2.OriginUse{OriginID: use.OriginID.String(), AccountID: account.String(), Amount: use.Amount, Bucket: "AVAILABLE"}
			}
			resources := wireNativeBridgeResources{IncomeUses: uses, IncomeOperation: operation, DestinationAccountID: destination, CashAccountID: account, Amount: child.Amount}
			effect := bankv2.Effect{Kind: phase, BusinessKey: fmt.Sprintf("bridge:%s:%d", p.ID.String(), number), Amount: child.Amount, CashUses: []bankv2.CashUse{{AccountID: account.String(), Amount: child.Amount}}, OriginUses: bankUses, ReturnUses: []bankv2.ReturnUse{}, LatestArrivalAt: p.ExpiresAt}
			if phase == bankv2.Transfer {
				effect.DestinationAccountID = child.DestinationAccountID.String()
			} else {
				effect.DestinationGoalID = child.GoalID.String()
			}
			wanted := bankv2.Request{Protocol: bankv2.Protocol, Namespace: g.manifest.Scope.Namespace, Key: step.OperationID.String(), OperationID: step.OperationID.String(), UserID: p.UserID.String(), PermitID: step.Request.PermitID, ReferenceHash: p.PlanHash, RequestedAt: p.CreatedAt, ExpiresAt: p.ExpiresAt, Effect: effect, Authorities: []bankv2.Authority{{Role: "EXECUTE", SourceID: step.ConfirmationID.String(), Version: 1, GoalID: child.GoalID.String(), PolicyID: child.PolicyID.String(), PolicyVersion: int64(version)}}}
			rh, re := wanted.Digest()
			actual, ae := step.Request.Digest()
			eh, ee := effect.Digest()
			if re != nil || ae != nil || ee != nil || rh != actual || rh != step.RequestHash || eh != step.EffectHash || step.CommandKind != kind || !exactJSON(step.Resources, resources) {
				return p, plan, a, businessInvalid("native whole bridge exact transfer and allocation effects/resources")
			}
		}
	}
	if number != len(p.Steps) {
		return p, plan, a, businessInvalid("native whole bridge extra economic step")
	}
	first, _ := p.Steps[0].Request.CanonicalBytes()
	if !bytes.Equal(first, nativeRawV3(row, "bank_request")) || row.text("bank_request_hash") != p.Steps[0].RequestHash {
		return p, plan, a, businessInvalid("native bridge preview retained first request")
	}
	batch := g.row("native_group_batches", id)
	if batch == nil {
		return p, plan, a, nil
	}
	nativeOriginalV3(batch, "original", &a)
	effects := make([]string, len(p.Steps))
	for i, step := range p.Steps {
		effects[i] = step.EffectHash
	}
	var command nativeBridgeCommandV3
	nativeOriginalV3(batch, "request", &command)
	if nativeHashFieldV3(batch, "original", "original_hash") != nil || nativeHashFieldV3(batch, "request", "request_hash") != nil || a.Protocol != "native-bridge-group-v1/USER" || a.PrincipalKind != "USER" || a.EnvironmentID != p.EnvironmentID || a.UserID != p.UserID || a.GroupID != p.ID || a.PlanID != p.PlanID || a.ReviewedHash != p.ReviewHash || !exactJSON(a.StepEffectHashes, effects) || a.SessionID.String() != batch.text("session_id") || !a.ConfirmedAt.Equal(batch.instant("created_at")) || !a.ExpiresAt.Equal(batch.instant("expires_at")) || a.ConfirmedAt.Before(p.CreatedAt) || !a.ConfirmedAt.Before(p.ExpiresAt) || !a.ExpiresAt.Equal(p.ExpiresAt) || batch.text("preview_id") != id || batch.text("plan_id") != plan.ID.String() || command.PreviewID != p.ID || command.ReviewedHash != p.ReviewHash || uint64(batch.positive("reserved_funds_version")) != plan.Dependencies.FundsVersion+1 || uint64(batch.positive("source_version")) != plan.Dependencies.SourceEvidenceVersion || uint64(batch.positive("writer_generation")) != plan.Dependencies.WriterGeneration || uint64(batch.positive("control_version")) != plan.Dependencies.ControlVersion {
		return p, plan, a, businessInvalid("native whole bridge actual USER command/full review/dependencies")
	}
	if err = g.humanAtV3(a.SessionID, a.ConfirmedAt); err != nil {
		return p, plan, a, err
	}
	return p, plan, a, g.checkedRowsV3()
}

// mustObjectV3 compares a typed exact DTO with a PG jsonb object after numeric
// lexemes are parsed by the same strict raw-object parser used for source rows.
func mustObjectV3(value any) map[string]any {
	out, _ := evidence.ParseRawObject(mustJSONV3(value))
	return out
}

func (g *nativeGraphV3) bridgeStepRowV3(row *ledgerRow, group string, step wireNativeBridgeStep, standing bool) error {
	if row == nil || row.text("group_id") != group || int(row.positive("number")) != step.Number || int(row.positive("child_number")) != step.ChildNumber || row.text("operation_id") != step.OperationID.String() || row.optional("previous_operation_id") != nativeOptionalIDV3(step.PreviousOperationID) || row.boolean("initial_source") != step.InitialSource || row.text("command_kind") != step.CommandKind || row.text("goal_id") != step.GoalID.String() || row.text("bank_request_hash") != step.RequestHash || row.text("effect_hash") != step.EffectHash || nativeHashFieldV3(row, "resources", "resources_hash") != nil || !bytes.Equal(nativeRawV3(row, "resources"), mustJSONV3(step.Resources)) {
		return businessInvalid("native complete staged bridge row original binding")
	}
	raw, err := step.Request.CanonicalBytes()
	if err != nil || !bytes.Equal(raw, nativeRawV3(row, "bank_request")) {
		return businessInvalid("native staged bridge exact bank request bytes")
	}
	if !standing && row.text("confirmation_id") != step.ConfirmationID.String() {
		return businessInvalid("native staged bridge distinct USER confirmation identity")
	}
	return nil
}
func nativeOptionalIDV3(id *funds.ID) string {
	if id == nil {
		return ""
	}
	return id.String()
}

func (g *nativeGraphV3) standingBridgeOriginalV3(id string) (wirenativeStandingBridgeGroup, error) {
	var group wirenativeStandingBridgeGroup
	row := g.row("native_standing_bridge_groups", id)
	if row == nil {
		return group, businessInvalid("native whole standing bridge original missing")
	}
	nativeOriginalV3(row, "original", &group)
	grant, ok := g.nativeGrants[row.text("grant_id")]
	occurrence, sourceOK := g.occurrences[id]
	if !ok || !sourceOK || nativeHashFieldV3(row, "original", "original_hash") != nil || group.Scope != g.ownerScopeV3() || group.Occurrence.ID.String() != id || !exactJSON(group.Grant, grant) || !exactJSON(group.Occurrence, occurrence) || group.Grant.Version != uint64(row.positive("grant_version")) || !group.CreatedAt.Equal(row.instant("created_at")) || !group.ExpiresAt.Equal(row.instant("expires_at")) || uint64(row.positive("reserved_funds_version")) != group.Dependencies.FundsVersion+1 {
		return group, businessInvalid("native standing whole bridge source/grant/header")
	}
	if err := mirrorreplayStandingBridgeV3(group, g.manifest.Scope.Namespace); err != nil {
		return group, nativeMirrorCheckV3("standing bridge whole candidate", err)
	}
	if err := g.grantActiveAtV3(grant.ID.String(), group.GrantStateSequence, group.CreatedAt); err != nil {
		return group, err
	}
	ledger, err := g.frozenLedgerV3(group.Candidate.Ledger, group.CreatedAt)
	if err != nil {
		return group, err
	}
	if err := g.frozenForecastEconomyV3(group.Candidate.ForecastInput, group.Candidate.ForecastBefore, ledger, group.Dependencies); err != nil {
		return group, err
	}
	claim := g.row("native_grant_budget_claims", id)
	if claim == nil {
		return group, businessInvalid("native whole standing bridge budget absent")
	}
	var budget struct {
		Protocol  string `json:"protocol"`
		GroupHash string `json:"group_hash"`
	}
	nativeOriginalV3(claim, "original", &budget)
	if budget.Protocol != "native-standing-bridge-v1/budget" || budget.GroupHash != row.text("original_hash") || claim.money("amount_cents") != group.Candidate.Authority.Amount {
		return group, businessInvalid("native standing whole group exact budget commitment")
	}
	return group, g.checkedRowsV3()
}

func (g *nativeGraphV3) checkBridgeGroupsV3() error {
	if g.usedNativeConfirmations == nil {
		g.usedNativeConfirmations = map[string]bool{}
	}
	onceRows, standingRows := map[*ledgerRow]bool{}, map[*ledgerRow]bool{}
	declaredOps := map[string]bool{}
	for _, previewRow := range g.rows["native_previews"] {
		if previewRow.text("kind") != "BRIDGE_GROUP" {
			continue
		}
		p, plan, a, err := g.onceBridgeOriginalsV3(previewRow.text("id"))
		if err != nil {
			return err
		}
		batch := g.row("native_group_batches", p.ID.String())
		if batch == nil {
			continue
		}
		for _, step := range p.Steps {
			id := step.OperationID.String()
			if declaredOps[id] {
				return businessInvalid("native bridge key reused across groups")
			}
			declaredOps[id] = true
			row := g.row("native_next_steps", p.ID.String(), fmt.Sprint(step.Number))
			if err = g.bridgeStepRowV3(row, p.ID.String(), step, false); err != nil {
				return err
			}
			onceRows[row] = true
			confirmation, err := g.confirmationV3(step.Request, p.ID.String(), step.Request.Authorities[0], "EXECUTE", a.SessionID, a.ConfirmedAt, a.ExpiresAt, a.StepEffectHashes)
			if err != nil {
				return err
			}
			if !bytes.Equal(nativeRawV3(confirmation, "original"), mustJSONV3(a)) {
				return businessInvalid("native future staged USER original must match whole consent")
			}
			op := g.row("native_operations", id)
			if op == nil {
				if step.InitialSource {
					return businessInvalid("native initial bridge source operation omitted")
				}
				continue
			}
			if op.text("mode") != "ONCE" || op.text("command_kind") != step.CommandKind || op.text("plan_id") != plan.ID.String() || op.text("preview_id") != p.ID.String() || op.text("group_id") != p.ID.String() || int(op.positive("child_number")) != step.Number || op.text("confirmation_id") != step.ConfirmationID.String() || op.text("idempotency_key") != fmt.Sprintf("%s_%d", batch.text("idempotency_key"), step.Number) || op.positive("reserved_funds_version") != batch.positive("reserved_funds_version") || !bytes.Equal(nativeRawV3(op, "request"), nativeRawV3(batch, "request")) {
				return businessInvalid("native born bridge operation differs from whole accepted command")
			}
			if err = g.bridgeBirthV3(op, step, p.Steps, a.ConfirmedAt, batch.text("accepted_xid"), nil); err != nil {
				return err
			}
		}
	}
	for id, row := range g.rows["native_group_batches"] {
		if g.row("native_previews", row.text("id")) == nil || id == "" {
			return businessInvalid("native orphan whole USER bridge group")
		}
	}
	for _, row := range g.rows["native_standing_bridge_groups"] {
		group, err := g.standingBridgeOriginalV3(row.text("id"))
		if err != nil {
			return err
		}
		closure := g.row("native_standing_bridge_closures", group.Occurrence.ID.String())
		if closure != nil && (closure.instant("closed_at").Before(group.CreatedAt) || closure.instant("closed_at").After(g.manifest.Source.CapturedAt) || len(closure.text("reason")) > 256) {
			return businessInvalid("native standing bridge immutable closure time/reason")
		}
		for _, step := range group.Steps {
			id := step.OperationID.String()
			if declaredOps[id] {
				return businessInvalid("native bridge operation key shared across groups")
			}
			declaredOps[id] = true
			stepRow := g.row("native_standing_bridge_steps", row.text("id"), fmt.Sprint(step.Number))
			if err = g.bridgeStepRowV3(stepRow, row.text("id"), step, true); err != nil {
				return err
			}
			standingRows[stepRow] = true
			op := g.row("native_operations", id)
			if op == nil {
				if step.InitialSource {
					return businessInvalid("native initial standing bridge operation omitted")
				}
				continue
			}
			if op.text("mode") != "STANDING" || op.text("command_kind") != step.CommandKind || op.text("group_id") != row.text("id") || op.text("plan_id") != row.text("id") || int(op.positive("child_number")) != step.Number || op.text("grant_id") != group.Grant.ID.String() || uint64(op.positive("grant_version")) != group.Grant.Version || op.positive("reserved_funds_version") != row.positive("reserved_funds_version") || op.text("idempotency_key") != fmt.Sprintf("standing_bridge_%s_%d", group.Occurrence.Key, step.Number) {
				return businessInvalid("native standing bridge operation exact original key/grant/budget")
			}
			if err = g.bridgeBirthV3(op, step, group.Steps, group.CreatedAt, row.text("accepted_xid"), closure); err != nil {
				return err
			}
			if closure != nil && nativeExpectedReservationStateV3(op.text("status")) == "RESERVED" {
				return businessInvalid("native closed bridge cannot erase unresolved signed operation")
			}
		}
	}
	for _, row := range g.rows["native_next_steps"] {
		if !onceRows[row] {
			return businessInvalid("native orphan or extra declared USER bridge step")
		}
	}
	for _, row := range g.rows["native_standing_bridge_steps"] {
		if !standingRows[row] {
			return businessInvalid("native orphan or extra declared standing bridge step")
		}
	}
	for _, row := range g.rows["native_standing_bridge_closures"] {
		if g.row("native_standing_bridge_groups", row.text("group_id")) == nil {
			return businessInvalid("native orphan standing bridge closure")
		}
	}
	for _, op := range g.rows["native_operations"] {
		kind := op.text("command_kind")
		if (kind == "BRIDGE_TRANSFER" || kind == "BRIDGE_ALLOCATE" || kind == "STANDING_BRIDGE_TRANSFER" || kind == "STANDING_BRIDGE_ALLOCATE") && !declaredOps[op.text("id")] {
			return businessInvalid("native bridge financial operation omitted whole group")
		}
	}
	return g.checkedRowsV3()
}

func (g *nativeGraphV3) bridgeBirthV3(op *ledgerRow, step wireNativeBridgeStep, steps []wireNativeBridgeStep, created time.Time, xid string, closure *ledgerRow) error {
	request, ok := g.nativeRequests[step.OperationID.String()]
	hash, err := request.Digest()
	if !ok || err != nil || hash != step.RequestHash || op.text("bank_request_hash") != hash || op.text("effect_hash") != step.EffectHash || op.instant("created_at").Before(created) {
		return businessInvalid("native bridge original request/time at operation birth")
	}
	if step.InitialSource {
		previous := ""
		if step.Number > 1 && steps[step.Number-2].InitialSource {
			previous = steps[step.Number-2].OperationID.String()
		}
		if !op.instant("created_at").Equal(created) || op.text("accepted_xid") != xid || op.optional("previous_operation_id") != previous {
			return businessInvalid("native initial bridge source must be in whole creation T1")
		}
	} else {
		if step.PreviousOperationID == nil || op.optional("previous_operation_id") != step.PreviousOperationID.String() || op.text("accepted_xid") == xid {
			return businessInvalid("native future allocation is a separate arrival T1")
		}
		receipt, ok := g.nativeReceipts[step.PreviousOperationID.String()]
		previous := g.nativeRequests[step.PreviousOperationID.String()]
		if !ok || previous.Effect.Kind != bankv2.Transfer || receipt.RecordedAt.After(op.instant("created_at")) || previous.Effect.DestinationAccountID != step.Resources.CashAccountID.String() {
			return businessInvalid("native future allocation requires actual exact transfer receipt")
		}
	}
	if closure != nil && op.instant("created_at").After(closure.instant("closed_at")) {
		return businessInvalid("native bridge operation created after immutable suffix closure")
	}
	return nil
}

func (g *nativeGraphV3) bridgePermitV3(row, op *ledgerRow, request bankv2.Request, protocol string) error {
	if protocol == "native-bridge-submission-permit-v1" {
		var p wirenativeBridgeSubmissionProof
		nativeOriginalV3(row, "original", &p)
		preview, plan, approval, err := g.onceBridgeOriginalsV3(op.text("group_id"))
		if err != nil {
			return err
		}
		if p.EnvironmentID != preview.EnvironmentID || p.UserID != preview.UserID || !exactJSON(p.Approval, approval) || p.StepNumber != int(op.positive("child_number")) || p.StepNumber < 1 || p.StepNumber > len(preview.Steps) || p.DecisionAt.Before(approval.ConfirmedAt) {
			return businessInvalid("native bridge historical whole USER approval")
		}
		if err = g.permitHeaderV3(row, request, p.OperationID, p.PermitID, p.BankRequestHash, p.EffectHash, p.SignatureHash, p.DecisionAt); err != nil {
			return err
		}
		if err = g.humanAtV3(approval.SessionID, p.DecisionAt); err != nil {
			return err
		}
		return g.jointWitnessV3(op, plan, p.Witness, p.DecisionAt, true)
	}
	var p wirenativeStandingBridgeProof
	nativeOriginalV3(row, "original", &p)
	group, err := g.standingBridgeOriginalV3(op.text("group_id"))
	if err != nil {
		return err
	}
	groupRow := g.row("native_standing_bridge_groups", op.text("group_id"))
	number := int(op.positive("child_number"))
	if p.Protocol != "native-standing-bridge-permit-v1" || p.Scope != group.Scope || p.GroupHash != groupRow.text("original_hash") || p.StepNumber != number || number < 1 || number > len(group.Steps) || p.GrantStateSequence < group.GrantStateSequence || p.FundsVersion != group.Dependencies.FundsVersion+uint64(number) || p.SourceVersion != group.Dependencies.SourceEvidenceVersion+uint64(number-1) || p.WriterGeneration != group.Dependencies.WriterGeneration || p.ControlVersion != group.Dependencies.ControlVersion || p.DecisionAt.Before(group.CreatedAt) {
		return businessInvalid("native standing bridge historical exact prefix/dependencies/grant")
	}
	if err = g.permitHeaderV3(row, request, p.OperationID, p.PermitID, p.BankRequestHash, p.EffectHash, p.SignatureHash, p.DecisionAt); err != nil {
		return err
	}
	if err = g.grantActiveAtV3(group.Grant.ID.String(), p.GrantStateSequence, p.DecisionAt); err != nil {
		return err
	}
	if err = policy.AuthorizeNativeStanding(group.Grant.Terms, "ACTIVE", group.Candidate.Authority, group.Candidate.Usage, p.DecisionAt); err != nil {
		return businessInvalid("native standing bridge historical deterministic source/budget authority")
	}
	return g.exactPrefixV3(op.text("group_id"), number-1, p.PrefixReceipts, p.DecisionAt)
}
