package executionaudit

import (
	"bytes"
	"encoding/json"
	"fmt"
	"time"

	evidence "zhiyu.local/zhiyu-go/internal/audit"
	"zhiyu.local/zhiyu-go/internal/execution/bankv2"
	funds "zhiyu.local/zhiyu-go/internal/funds/domain"
	planning "zhiyu.local/zhiyu-go/internal/planning/domain"
	policy "zhiyu.local/zhiyu-go/internal/policy/domain"
)

type nativeStandingPlanV3 struct {
	protocol   string
	hash       string
	allocation *wirenativeStandingAllocationPlan
	asset      *wirenativeStandingAssetPlan
	payment    *wirenativeStandingPaymentPlan
}

func (g *nativeGraphV3) frozenVersionV3(version policy.TemplateVersion) error {
	original, ok := g.templates[version.VersionID.String()]
	if !ok || original.PolicyID != version.PolicyID || original.Version != version.Version || original.Scope != version.Scope || !original.ConfirmedAt.Equal(version.ConfirmedAt) || !exactJSON(original.Compiled, version.Compiled) || version.ConfirmedConfigurationHash != original.ConfirmedConfigurationHash || version.ConfirmationVerified != original.ConfirmationVerified {
		return businessInvalid("native frozen exact historical policy version")
	}
	return nil
}

func (g *nativeGraphV3) frozenForecastV3(input planning.ForecastInput, result planning.ForecastResult, sourceVersions ...uint64) error {
	var sourceVersion uint64
	if len(sourceVersions) > 0 {
		sourceVersion = sourceVersions[0]
	}
	if err := g.checkHistoryFactsV3(input.Facts, input.AsOf, input.Timezone, sourceVersion); err != nil {
		return err
	}
	if err := g.checkBillForecastV3(input, sourceVersion); err != nil {
		return err
	}
	if input.Scope != g.ownerScopeV3() || len(input.FutureIncome) != 0 || len(input.PrincipalReturns) != 0 {
		return businessInvalid("native protection cannot execute forecast income or unarrived principal")
	}
	for _, version := range input.Versions {
		if err := g.frozenVersionV3(version); err != nil {
			return err
		}
	}
	expected, err := planning.Forecast365(input)
	if err != nil || !exactJSON(expected, result) || result.BankAuthority {
		return businessInvalid("native full per-point protection deterministic replay")
	}
	return nil
}

func (g *nativeGraphV3) frozenLedgerV3(capture wireNativeAssetLedgerCapture, at time.Time, neutralized ...funds.ID) (nativeFrozenLedgerV3, error) {
	ledger, err := capture.DomainLedger()
	if err != nil || ledger.Namespace != g.manifest.Scope.Namespace || ledger.Income.Snapshot().UserID.String() != g.manifest.Scope.UserID || !ledger.Income.Snapshot().AsOf.Equal(at) || ledger.validate(g.ownerScopeV3().UserID) != nil {
		return ledger, businessInvalid("native full frozen resource ledger")
	}
	for _, origin := range ledger.Income.Snapshot().Origins {
		fact := origin.Fact()
		row := g.row("income_origins", origin.ID().String())
		if row == nil || row.text("evidence_hash") != fact.EvidenceHash.String() || row.text("evidence_id") != fact.EvidenceID.String() || row.text("original_account_id") != fact.AccountID.String() || row.money("amount_cents") != fact.Amount || !row.instant("occurred_at").Equal(fact.OccurredAt) || !row.instant("observed_at").Equal(fact.ObservedAt) || !row.instant("recorded_at").Equal(fact.RecordedAt) {
			return ledger, businessInvalid("native frozen income cannot invent/re-time/relabel a source")
		}
	}
	for _, account := range ledger.Accounts {
		if g.row("accounts", account.ID.String()) == nil {
			return ledger, businessInvalid("native frozen account scope")
		}
	}
	for _, position := range ledger.Positions {
		row := g.row("native_positions", position.ID)
		if row == nil || !bytes.Equal(nativeRawV3(row, "original"), position.Original) || row.text("original_hash") != position.OriginalHash {
			return ledger, businessInvalid("native frozen immutable position source")
		}
	}
	for _, returned := range ledger.PrincipalReturns {
		row := g.row("native_principal_returns", returned.BankKey)
		if row == nil || !bytes.Equal(nativeRawV3(row, "original"), returned.Original) || row.text("original_hash") != returned.OriginalHash {
			return ledger, businessInvalid("native frozen actual principal return source")
		}
	}
	if err := g.checkFrozenLedgerProjectionV3(ledger, at, neutralized...); err != nil {
		return ledger, err
	}
	return ledger, g.checkedRowsV3()
}

func (g *nativeGraphV3) checkActionHeaderV3(row *ledgerRow, header wireNativeActionPreviewHeader) error {
	var deps planning.DependencyVector
	row.object("dependencies", &deps)
	if header.ID.String() != row.text("id") || header.Scope != g.ownerScopeV3() || header.SessionID.String() != row.text("session_id") || string(header.Kind) != row.text("kind") || header.EffectHash != row.text("effect_hash") || header.Dependencies != deps || header.SourceHash != row.text("source_hash") || header.InventoryHash != row.text("inventory_hash") || !header.CreatedAt.Equal(row.instant("created_at")) || !header.ExpiresAt.Equal(row.instant("expires_at")) || !header.ExpiresAt.After(header.CreatedAt) || header.ExpiresAt.Sub(header.CreatedAt) > 2*time.Minute || header.BankAuthority {
		return businessInvalid("native pre-confirmation candidate header has no bank authority")
	}
	return g.humanAtV3(header.SessionID, header.CreatedAt)
}

func (g *nativeGraphV3) checkCandidatesV3() error {
	g.jointPlans = map[string]wireNativeJointPlan{}
	g.nativeActions = map[string]any{}
	g.standingPlans = map[string]nativeStandingPlanV3{}
	for _, row := range g.rows["template_protection_publications"] {
		var input planning.ForecastInput
		var result planning.ForecastResult
		nativeOriginalV3(row, "input_original", &input)
		nativeOriginalV3(row, "result_original", &result)
		if nativeHashFieldV3(row, "input_original", "input_hash") != nil || nativeHashFieldV3(row, "result_original", "result_hash") != nil {
			return businessInvalid("native forecast publication full raw input/result")
		}
		if err := g.frozenForecastV3(input, result, uint64(row.positive("source_version"))); err != nil {
			return err
		}
	}
	for _, row := range g.rows["native_joint_plans"] {
		var plan wireNativeJointPlan
		nativeOriginalV3(row, "original", &plan)
		if nativeHashFieldV3(row, "original", "original_hash") != nil || nativeHashFieldV3(row, "input", "input_hash") != nil || nativeHashFieldV3(row, "result", "result_hash") != nil || nativeHashFieldV3(row, "dependencies", "dependencies_hash") != nil || plan.ID.String() != row.text("id") || plan.Scope != g.ownerScopeV3() || plan.SessionID.String() != row.text("session_id") || plan.Protocol != row.text("protocol_version") || !plan.CreatedAt.Equal(row.instant("created_at")) || !plan.ExpiresAt.Equal(row.instant("expires_at")) || plan.SourceHash != row.text("source_hash") || plan.InventoryHash != row.text("inventory_hash") || plan.Result.Status != row.text("status") || plan.Result.EffectHash != nativeStringV3(row, "effect_hash") || !bytes.Equal(mustJSONV3(plan.Input), nativeRawV3(row, "input")) || !bytes.Equal(mustJSONV3(plan.Result), nativeRawV3(row, "result")) || !bytes.Equal(mustJSONV3(plan.Dependencies), nativeRawV3(row, "dependencies")) {
			return businessInvalid("native joint original complete column binding")
		}
		if _, err := mirrorReplayNativeJointPlanV3(plan); err != nil {
			return nativeMirrorCheckV3("joint plan", err)
		}
		for _, version := range plan.Input.ProtectionForecast.Versions {
			if err := g.frozenVersionV3(version); err != nil {
				return err
			}
		}
		if err := g.humanAtV3(plan.SessionID, plan.CreatedAt); err != nil {
			return err
		}
		if err := g.queueForecastConsumerV3(nativeForecastEconomicConsumerV3{input: plan.Input.ProtectionForecast, dependencies: plan.Dependencies, income: &plan.Input.Ledger}); err != nil {
			return err
		}
		g.jointPlans[plan.ID.String()] = plan
	}
	for _, row := range g.rows["native_action_previews"] {
		if nativeHashFieldV3(row, "original", "original_hash") != nil {
			return businessInvalid("native action full original hash")
		}
		switch bankv2.Kind(row.text("kind")) {
		case bankv2.Purchase, bankv2.Redeem, bankv2.Mature:
			var p wireNativeAssetPreview
			nativeOriginalV3(row, "original", &p)
			if err := g.checkActionHeaderV3(row, p.wireNativeActionPreviewHeader); err != nil {
				return err
			}
			if err := mirrorreplayNativeAssetPreviewV3(p); err != nil {
				return nativeMirrorCheckV3("asset preview", err)
			}
			ledger, err := g.frozenLedgerV3(p.Ledger, p.CreatedAt)
			if err != nil {
				return err
			}
			if err := g.frozenForecastEconomyV3(p.ForecastInput, p.ForecastBefore, ledger, p.Dependencies); err != nil {
				return err
			}
			g.nativeActions[p.ID.String()] = p
		case bankv2.Payment:
			var p wireNativePaymentPreview
			nativeOriginalV3(row, "original", &p)
			if err := g.checkActionHeaderV3(row, p.wireNativeActionPreviewHeader); err != nil {
				return err
			}
			if err := mirrorreplayNativePaymentPreviewV3(p); err != nil {
				return nativeMirrorCheckV3("payment preview", err)
			}
			ledger, err := g.frozenLedgerV3(p.Ledger, p.CreatedAt)
			if err != nil {
				return err
			}
			if err := g.frozenForecastEconomyV3(p.ForecastInput, p.ForecastBefore, ledger, p.Dependencies); err != nil {
				return err
			}
			g.nativeActions[p.ID.String()] = p
		case bankv2.MoveGoal:
			var p wireNativeGoalTransferPreview
			nativeOriginalV3(row, "original", &p)
			if err := g.checkActionHeaderV3(row, p.wireNativeActionPreviewHeader); err != nil {
				return err
			}
			if err := mirrorreplayGoalTransferPreviewV3(p); err != nil {
				return nativeMirrorCheckV3("paired goal preview", err)
			}
			if err := g.queueForecastEconomyV3(p.ForecastInput, p.Dependencies, nil); err != nil {
				return err
			}
			if err := g.frozenForecastV3(p.ForecastInput, p.ForecastBefore, p.Dependencies.SourceEvidenceVersion); err != nil {
				return err
			}
			g.nativeActions[p.ID.String()] = p
		default:
			return fmt.Errorf("%w: native action preview kind", evidence.ErrUnsupportedVersion)
		}
	}
	for _, row := range g.rows["native_standing_plans"] {
		if nativeHashFieldV3(row, "original", "original_hash") != nil {
			return businessInvalid("native standing full immutable plan hash")
		}
		var declared struct {
			Protocol string `json:"protocol"`
		}
		if json.Unmarshal(nativeRawV3(row, "original"), &declared) != nil {
			return businessInvalid("native standing plan protocol")
		}
		id := row.text("id")
		occurrence, ok := g.occurrences[row.text("occurrence_id")]
		grant, grantOK := g.nativeGrants[row.text("grant_id")]
		if !ok || !grantOK || occurrence.GrantID != grant.ID || occurrence.GrantVersion != uint64(row.positive("grant_version")) {
			return businessInvalid("native standing plan original grant/occurrence")
		}
		plan := nativeStandingPlanV3{protocol: declared.Protocol, hash: row.text("original_hash")}
		switch declared.Protocol {
		case "native-automation-v1/allocation-plan":
			var p wirenativeStandingAllocationPlan
			nativeOriginalV3(row, "original", &p)
			if p.ID.String() != id || p.Scope != g.ownerScopeV3() || !exactJSON(p.Occurrence, occurrence) || !exactJSON(p.Grant, grant) || !p.CreatedAt.Equal(row.instant("created_at")) || !p.ExpiresAt.Equal(row.instant("expires_at")) {
				return businessInvalid("native standing allocation full identity")
			}
			ledger, err := g.frozenLedgerV3(p.Candidate.Ledger, p.CreatedAt)
			if err != nil {
				return err
			}
			if p.Joint != nil {
				if err := mirrorreplayStandingJointAllocationV3(p, g.manifest.Scope.Namespace); err != nil {
					return nativeMirrorCheckV3("standing joint", err)
				}
			} else {
				f, d := p.Candidate.ForecastInput, p.Dependencies
				snapshot := mirrortemplateSnapshotV3{Facts: f.Facts, Versions: f.Versions, Views: p.Candidate.Policies, Retained: f.RetainedObligations, Held: f.HeldCash, UnassignedGoalCash: f.UnassignedGoalCash, ExternalLiabilities: f.ExternalLiabilities, InventoryRaw: p.Candidate.InventoryOriginal, FundsVersion: d.FundsVersion, SourceVersion: d.SourceEvidenceVersion, WriterGeneration: d.WriterGeneration, ControlVersion: d.ControlVersion, AsOf: p.CreatedAt, Timezone: p.Grant.Terms.Timezone, Native: &ledger}
				expected, err := mirrorstandingAllocationCandidateV3(snapshot, ledger, p.Grant, p.Occurrence.Source, p.Candidate.Usage, p.Candidate.GoalVersion, p.CreatedAt)
				if err != nil || !exactJSON(expected, p.Candidate) {
					return businessInvalid("native standing single complete candidate replay")
				}
			}
			if err := g.grantActiveAtV3(grant.ID.String(), p.GrantStateSequence, p.CreatedAt); err != nil {
				return err
			}
			if err := g.frozenForecastEconomyV3(p.Candidate.ForecastInput, p.Candidate.ForecastBefore, ledger, p.Dependencies); err != nil {
				return err
			}
			if err := g.frozenForecastV3(p.Candidate.ForecastAfterInput, p.Candidate.ForecastAfter, p.Dependencies.SourceEvidenceVersion); err != nil {
				return err
			}
			expected := mirrorstandingAllocationExpectedRequestV3(p, g.manifest.Scope.Namespace, plan.hash)
			if request, ok := g.nativeRequests[id]; !ok || !exactJSON(request, expected) {
				return businessInvalid("native standing allocation exact expected request")
			}
			plan.allocation = &p
		case "native-standing-asset-v1/plan":
			var p wirenativeStandingAssetPlan
			nativeOriginalV3(row, "original", &p)
			if p.ID.String() != id || p.Scope != g.ownerScopeV3() || !exactJSON(p.Occurrence, occurrence) || !exactJSON(p.Grant, grant) || p.Source.Family != occurrence.Family || p.Source.Source != occurrence.Source || p.Preview.ID != p.ID || p.Preview.SessionID != (funds.ID{}) || !p.Preview.CreatedAt.Equal(row.instant("created_at")) || !p.Preview.ExpiresAt.Equal(row.instant("expires_at")) || policy.AuthorizeNativeStanding(grant.Terms, "ACTIVE", p.Authority, p.Usage, p.Preview.CreatedAt) != nil {
				return businessInvalid("native standing asset exact source/authority/plan")
			}
			if err := g.grantActiveAtV3(grant.ID.String(), p.GrantStateSequence, p.Preview.CreatedAt); err != nil {
				return err
			}
			if err := mirrorstandingAssetReplayCurrentV3(p, p.Preview); err != nil {
				return nativeMirrorCheckV3("standing asset", err)
			}
			ledger, err := g.frozenLedgerV3(p.Preview.Ledger, p.Preview.CreatedAt)
			if err != nil {
				return err
			}
			if err := g.frozenForecastEconomyV3(p.Preview.ForecastInput, p.Preview.ForecastBefore, ledger, p.Preview.Dependencies); err != nil {
				return err
			}
			plan.asset = &p
		case "native-automation-v1/payment-plan":
			var p wirenativeStandingPaymentPlan
			nativeOriginalV3(row, "original", &p)
			if p.ID.String() != id || p.Scope != g.ownerScopeV3() || !exactJSON(p.Occurrence, occurrence) || !exactJSON(p.Grant, grant) || p.Preview.ID != p.ID || p.Preview.SessionID != (funds.ID{}) || !p.Preview.CreatedAt.Equal(row.instant("created_at")) || !p.Preview.ExpiresAt.Equal(row.instant("expires_at")) || policy.AuthorizeNativeStanding(grant.Terms, "ACTIVE", p.Authority, p.Usage, p.Preview.CreatedAt) != nil {
				return businessInvalid("native standing payment exact source/authority/plan")
			}
			if err := g.grantActiveAtV3(grant.ID.String(), p.GrantStateSequence, p.Preview.CreatedAt); err != nil {
				return err
			}
			if err := mirrorreplayNativePaymentPreviewV3(p.Preview); err != nil {
				return nativeMirrorCheckV3("standing payment", err)
			}
			ledger, err := g.frozenLedgerV3(p.Preview.Ledger, p.Preview.CreatedAt)
			if err != nil {
				return err
			}
			if err := g.frozenForecastEconomyV3(p.Preview.ForecastInput, p.Preview.ForecastBefore, ledger, p.Preview.Dependencies); err != nil {
				return err
			}
			plan.payment = &p
		default:
			return fmt.Errorf("%w: native standing candidate protocol", evidence.ErrUnsupportedVersion)
		}
		g.standingPlans[id] = plan
	}
	return g.checkedRowsV3()
}
