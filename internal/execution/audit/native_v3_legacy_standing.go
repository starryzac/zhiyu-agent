package executionaudit

import (
	"bytes"
	"encoding/json"
	"fmt"
	"time"

	evidence "zhiyu.local/zhiyu-go/internal/audit"
	funds "zhiyu.local/zhiyu-go/internal/funds/domain"
	policy "zhiyu.local/zhiyu-go/internal/policy/domain"
)

const legacyStandingConsumerV3 = "standing-allocate-goal-v1"

type legacyStandingEventV3 struct {
	ID, EnvironmentID, UserID funds.ID
	Kind                      string
	Payload                   []byte
	CreatedAt                 time.Time
}

// These two tables describe discovery and acceptance of an original event.
// They confer no additional permission and are never used to infer a receipt.
func (g *nativeGraphV3) checkLegacyStandingV3() error {
	if g.legacy == nil && (len(g.rows["standing_event_receipts"]) > 0 || len(g.rows["standing_inbox"]) > 0) {
		return fmt.Errorf("%w: legacy standing authority graph absent", evidence.ErrIncomplete)
	}
	proofs := map[string]businessIncomeProof{}
	events := map[string]legacyStandingEventV3{}
	for _, row := range g.rows["standing_event_receipts"] {
		var event legacyStandingEventV3
		nativeOriginalV3(row, "event_original", &event)
		id := row.id("event_id").String()
		outbox := g.row("outbox", id)
		if row.text("consumer_name") != legacyStandingConsumerV3 || nativeHashFieldV3(row, "event_original", "event_hash") != nil || event.ID.String() != id || event.EnvironmentID.String() != g.manifest.Scope.EnvironmentID || event.UserID.String() != g.manifest.Scope.UserID || event.Kind != "INCOME_IMPORTED" || outbox == nil || outbox.text("kind") != event.Kind || !event.CreatedAt.Equal(outbox.instant("created_at")) || !bytes.Equal(event.Payload, outbox.raw("payload")) {
			return businessInvalid("legacy standing receipt must retain the exact independent outbox event")
		}
		proof, reason := g.legacyStandingSourceV3(event)
		expected := "REGISTERED"
		if reason != "" {
			expected = "INVALID"
			if reason == "UNSUPPORTED_SOURCE_PROOF" {
				expected = "UNSUPPORTED"
			}
		}
		storedReason, reasonOK := row.values["reason"].(string)
		if row.text("outcome") != expected || !reasonOK || storedReason != reason {
			return businessInvalid("legacy standing discovery outcome differs from its original source")
		}
		events[id] = event
		if reason == "" {
			proofs[id] = proof
		}
	}
	owners, consumed := map[string]int{}, map[string]string{}
	for _, row := range g.rows["standing_inbox"] {
		eventID := row.id("event_id").String()
		proof, found := proofs[eventID]
		event := events[eventID]
		if !found || row.text("consumer_name") != legacyStandingConsumerV3 || row.text("family") != "ALLOCATE_GOAL" || row.id("origin_id") != proof.OriginID || row.id("policy_id") != proof.Authority.PolicyID || uint64(row.positive("policy_version")) != proof.Authority.PolicyVersion || row.id("grant_id") != proof.Authority.GrantID || uint64(row.positive("grant_version")) != proof.Authority.GrantVersion {
			return businessInvalid("legacy standing inbox must bind the original registered authority")
		}
		key := legacyStandingKeyV3(event, proof)
		if row.text("accept_key") != key || consumed[key] != "" {
			return businessInvalid("legacy standing original acceptance key changed or duplicated")
		}
		consumed[key] = eventID
		occurrence := legacyStandingOccurrenceV3(proof)
		state := row.text("state")
		owner := row.boolean("occurrence_owner")
		if owner {
			owners[occurrence]++
		} else if !row.boolean("paused") || row.optional("lease_owner") != "" || row.optional("lease_until") != "" || state == "READY" || state == "RUNNING" {
			return businessInvalid("legacy duplicate occurrence must remain quarantined")
		}
		switch state {
		case "READY", "RUNNING", "ACCEPTED", "NO_ACTION", "BLOCKED", "EXHAUSTED":
		default:
			return fmt.Errorf("%w: legacy standing inbox state", evidence.ErrUnsupportedVersion)
		}
		planID, operationID := row.optional("plan_id"), row.optional("operation_id")
		if planID != "" {
			candidate, ok := g.legacy.plans[planID]
			if !ok || candidate.Kind != funds.AllocateGoal || candidate.PolicyID != proof.Authority.PolicyID || candidate.PolicyVersion != proof.Authority.PolicyVersion || candidate.Dependencies.GrantVersion != proof.Authority.GrantVersion || candidate.Scope.EnvironmentID != proof.EnvironmentID || candidate.Scope.UserID != proof.UserID {
				return businessInvalid("legacy standing pinned candidate authority")
			}
			if candidate.Status == "READY" && !candidate.Amount.IsZero() && (len(candidate.Uses) != 1 || candidate.Uses[0].OriginID != proof.OriginID || !candidate.EarliestIncomeAt.Equal(proof.OccurredAt) || candidate.EarliestIncomeAt.After(event.CreatedAt)) {
				return businessInvalid("legacy standing candidate uses another income occurrence")
			}
			if state == "NO_ACTION" && (candidate.Status != "NO_ACTION" || !candidate.Amount.IsZero()) {
				return businessInvalid("legacy standing no-action contradicts its pinned candidate")
			}
		} else if state == "NO_ACTION" || operationID != "" || state == "ACCEPTED" {
			return businessInvalid("legacy standing result lacks its original pinned candidate")
		}
		var originalOperation *ledgerRow
		for _, op := range g.rows["operations"] {
			if op.text("idempotency_key") == key {
				if originalOperation != nil || operationID != "" && operationID != op.id("id").String() {
					return businessInvalid("legacy standing acceptance points to another original operation")
				}
				originalOperation = op
			}
		}
		if state == "ACCEPTED" && (operationID == "" || originalOperation == nil) || operationID != "" && originalOperation == nil {
			return businessInvalid("legacy standing accepted result has no original T1")
		}
		if originalOperation != nil {
			var command businessCommand
			nativeOriginalV3(originalOperation, "request", &command)
			if originalOperation.text("plan_id") != planID || originalOperation.text("policy_id") != proof.Authority.PolicyID.String() || uint64(originalOperation.positive("policy_version")) != proof.Authority.PolicyVersion || originalOperation.optional("grant_id") != proof.Authority.GrantID.String() || uint64(originalOperation.positive("grant_version")) != proof.Authority.GrantVersion || command.PlanID.String() != planID || command.GrantID == nil || *command.GrantID != proof.Authority.GrantID || command.Mode != "STANDING" {
				return businessInvalid("legacy standing T1 original command/authority disagrees")
			}
		}
	}
	// A second event for one original income may have a registered receipt but
	// no inbox because ON CONFLICT retained the first occurrence owner.
	for _, proof := range proofs {
		if owners[legacyStandingOccurrenceV3(proof)] != 1 {
			return businessInvalid("legacy standing registered income needs one immutable occurrence owner")
		}
	}
	return g.checkedRowsV3()
}

func legacyStandingOccurrenceV3(proof businessIncomeProof) string {
	return keyParts(proof.OriginID.String(), proof.Authority.PolicyID.String(), fmt.Sprint(proof.Authority.PolicyVersion), proof.Authority.GrantID.String(), fmt.Sprint(proof.Authority.GrantVersion))
}

func legacyStandingKeyV3(event legacyStandingEventV3, proof businessIncomeProof) string {
	raw, _ := json.Marshal(struct {
		Protocol                                 string
		EnvironmentID, UserID, EventID, OriginID funds.ID
		Authority                                any
		Family                                   string
	}{legacyStandingConsumerV3, event.EnvironmentID, event.UserID, event.ID, proof.OriginID, proof.Authority, "ALLOCATE_GOAL"})
	return "standing_" + nakedHash(raw)
}

func (g *nativeGraphV3) legacyStandingSourceV3(event legacyStandingEventV3) (businessIncomeProof, string) {
	var proof businessIncomeProof
	var payload struct {
		OriginID      funds.ID `json:"origin_id"`
		SourceVersion uint64   `json:"source_version"`
	}
	if nativeCompactOriginalV3(event.Payload, &payload) != nil || payload.OriginID == (funds.ID{}) || payload.SourceVersion == 0 || payload.SourceVersion > uint64(^uint64(0)>>1) {
		return proof, "INVALID_SOURCE_EVENT"
	}
	origin := g.row("income_origins", payload.OriginID.String())
	if origin == nil {
		return proof, "MISSING_SOURCE_ORIGINAL"
	}
	if origin.text("currency") != "CNY" || origin.instant("occurred_at").After(event.CreatedAt) || origin.instant("observed_at").After(event.CreatedAt) || origin.instant("recorded_at").After(event.CreatedAt) {
		return proof, "EVENT_SOURCE_TIME_CONFLICT"
	}
	blob := g.row("evidence_blobs", origin.id("evidence_id").String())
	if blob == nil || blob.text("kind") != "EXPLICIT_SIMULATED_BANK_INCOME" {
		return proof, "UNSUPPORTED_SOURCE_PROOF"
	}
	raw := blob.raw("canonical")
	if nakedHash(raw) != blob.text("digest") || blob.text("digest") != origin.text("evidence_hash") {
		return proof, "SOURCE_HASH_CONFLICT"
	}
	if nativeCompactOriginalV3(raw, &proof) != nil || proof.Protocol != "explicit-synthetic-bank-income-v1" {
		return proof, "UNSUPPORTED_SOURCE_PROOF"
	}
	if proof.Namespace != g.manifest.Scope.Namespace || proof.EnvironmentID != event.EnvironmentID || proof.UserID != event.UserID || proof.OriginID != payload.OriginID || proof.AccountID != origin.id("original_account_id") || proof.EvidenceID != origin.id("evidence_id") || proof.Amount != origin.money("amount_cents") || !proof.OccurredAt.Equal(origin.instant("occurred_at")) || proof.OccurredAt.Before(proof.Authority.EffectiveFrom) {
		return proof, "SOURCE_SCOPE_OR_IDENTITY_CONFLICT"
	}
	if g.row("protection_snapshots", fmt.Sprint(payload.SourceVersion)) == nil || uint64(g.row("users", event.UserID.String()).positive("source_version")) < payload.SourceVersion {
		return proof, "MISSING_SOURCE_EPOCH"
	}
	p, pok := g.legacy.policies[versionKey(proof.Authority.PolicyID.String(), proof.Authority.PolicyVersion)]
	grant, gok := g.legacy.grants[versionKey(proof.Authority.GrantID.String(), proof.Authority.GrantVersion)]
	if !pok || !gok {
		return proof, "MISSING_ORIGINAL_AUTHORITY"
	}
	window, err := policy.CheckGrant(p, grant, proof.OccurredAt)
	if err != nil || !window.EffectiveFrom.Equal(proof.Authority.EffectiveFrom) || p.Scope.GoalID != proof.GoalID || p.Scope.SourceAccountID != proof.AccountID || p.Scope.DestinationAccountID != proof.AccountID {
		return proof, "INVALID_ORIGINAL_AUTHORITY"
	}
	return proof, ""
}
