package executionaudit

import (
	"bytes"
	"encoding/hex"
	"fmt"

	evidence "zhiyu.local/zhiyu-go/internal/audit"
	"zhiyu.local/zhiyu-go/internal/execution/bankcredit"
	policy "zhiyu.local/zhiyu-go/internal/policy/domain"
)

type nativeAutomationIncomePayloadV3 struct {
	Protocol          string `json:"protocol"`
	OriginID          string `json:"origin_id"`
	EvidenceID        string `json:"evidence_id"`
	RecordHash        string `json:"record_hash"`
	ExternalAuthority string `json:"external_authority"`
	ExternalEventID   string `json:"external_event_id"`
	CreditSequence    int64  `json:"credit_sequence"`
	SourceVersion     uint64 `json:"source_version"`
	BankCaptureHash   string `json:"bank_capture_hash"`
}

type nativeAutomationIncomeSourceV3 struct {
	Protocol      string                  `json:"protocol"`
	Event         nativeAutomationEventV3 `json:"event"`
	BankRecordHex string                  `json:"bank_record_hex"`
}

func nativeAutomationHashV3(value string) bool {
	if len(value) != 64 {
		return false
	}
	for _, c := range value {
		if !(c >= '0' && c <= '9') && !(c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}

// Discovery is not authorization. Reproduce its retained quarantine outcomes,
// then bind REGISTERED/NOT_ELIGIBLE bank facts to the independent credit feed.
// Paused grants may discover events; their T1/T2 activity gate is separate.
func (g *nativeGraphV3) checkAutomationEventReceiptsV3() error {
	occurrences := map[string][]*ledgerRow{}
	for _, row := range g.rows["native_occurrences"] {
		if row.text("source_kind") == "INCOME_EVENT" {
			key := keyParts(row.text("grant_id"), fmt.Sprint(row.positive("grant_version")), row.text("event_id"))
			occurrences[key] = append(occurrences[key], row)
		}
	}
	seen := map[string]bool{}
	for _, row := range g.rows["native_automation_event_receipts"] {
		var event nativeAutomationEventV3
		nativeOriginalV3(row, "original", &event)
		key := keyParts(row.text("grant_id"), fmt.Sprint(row.positive("grant_version")), row.text("event_id"))
		grant, ok := g.nativeGrants[event.GrantID.String()]
		outbox := g.row("outbox", event.ID.String())
		if seen[key] || !ok || nativeHashFieldV3(row, "original", "original_hash") != nil || event.Protocol != "native-automation-v1/event" || event.Scope != g.ownerScopeV3() || event.GrantID.String() != row.text("grant_id") || event.GrantVersion != uint64(row.positive("grant_version")) || event.GrantVersion != grant.Version || event.ID.String() != row.text("event_id") || event.Kind != "INCOME_IMPORTED" || outbox == nil || outbox.text("kind") != event.Kind || outbox.text("aggregate_id") != event.AggregateID.String() || !outbox.instant("created_at").Equal(event.CreatedAt) || event.PayloadHex != hex.EncodeToString(nativeRawV3(outbox, "payload")) || event.CreatedAt.Before(grant.ConfirmedAt) || !event.CreatedAt.Before(grant.Terms.ExpiresAt) {
			return businessInvalid("native automation receipt exact outbox/grant/original/window")
		}
		switch string(grant.Terms.Family) {
		case "SINGLE_GOAL", "JOINT_GOALS", "ASSET_ALLOCATION":
		default:
			return businessInvalid("native automation income receipt belongs to unsupported discovery family")
		}
		// SQL created_at is a persistence timestamp, not the injected business
		// event time or a new permission. Require its type, not a fake ordering.
		row.instant("created_at")
		outcome, reason, source, record, err := g.automationIncomeSourceV3(event, grant)
		if err != nil {
			return err
		}
		storedReason, reasonOK := row.values["reason"].(string)
		if row.text("outcome") != outcome || !reasonOK || storedReason != reason {
			return businessInvalid("native automation receipt outcome differs from exact original source")
		}
		linked := occurrences[key]
		if outcome == "REGISTERED" {
			if len(linked) == 0 {
				return fmt.Errorf("%w: registered native automation event occurrence missing", evidence.ErrIncomplete)
			}
			if len(linked) != 1 {
				return businessInvalid("native automation event registered more than once")
			}
			occurrence, exists := g.occurrences[linked[0].text("id")]
			expected := nativeAutomationIncomeSourceV3{Protocol: "native-automation-v1/income-source", Event: event, BankRecordHex: hex.EncodeToString(record)}
			if !exists || occurrence.GrantID != grant.ID || occurrence.GrantVersion != grant.Version || occurrence.Family != grant.Terms.Family || occurrence.Source != source || occurrence.CreatedAt.Before(event.CreatedAt) || !bytes.Equal(nativeRawV3(linked[0], "source_original"), mustJSONV3(expected)) {
				return businessInvalid("native automation registered receipt exact occurrence/bank original")
			}
		} else if len(linked) != 0 {
			return businessInvalid("native automation quarantined event cannot create financial occurrence")
		}
		seen[key] = true
	}
	for key := range occurrences {
		if !seen[key] {
			return fmt.Errorf("%w: native income occurrence lacks its original discovery receipt", evidence.ErrIncomplete)
		}
	}
	return g.checkedRowsV3()
}

func (g *nativeGraphV3) automationIncomeSourceV3(event nativeAutomationEventV3, grant nativeGrantV3) (outcome, reason string, source policy.NativeOccurrenceSource, raw []byte, err error) {
	payloadRaw, decodeErr := hex.DecodeString(event.PayloadHex)
	if decodeErr != nil {
		return "INVALID", "EVENT_HEX_INVALID", source, nil, nil
	}
	var payload nativeAutomationIncomePayloadV3
	if nativeCompactOriginalV3(payloadRaw, &payload) != nil || payload.Protocol != "native-income-import-v1" {
		return "UNSUPPORTED", "INCOME_EVENT_PROTOCOL_UNSUPPORTED", source, nil, nil
	}
	if payload.OriginID != event.AggregateID.String() || payload.EvidenceID != event.ID.String() || !nativeAutomationHashV3(payload.RecordHash) || !nativeAutomationHashV3(payload.BankCaptureHash) || payload.SourceVersion == 0 {
		return "INVALID", "INCOME_EVENT_IDENTITY_DIFFERS", source, nil, nil
	}
	blob := g.row("evidence_blobs", payload.EvidenceID)
	if blob == nil {
		return "INVALID", "INCOME_ORIGINAL_MISSING", source, nil, nil
	}
	raw = nativeRawV3(blob, "canonical")
	var record bankcredit.Record
	if blob.text("kind") != "BANK_EXTERNAL_CREDIT_V1" || nakedHash(raw) != blob.text("digest") || blob.text("digest") != payload.RecordHash || nativeCompactOriginalV3(raw, &record) != nil || record.Validate() != nil {
		return "INVALID", "INCOME_ORIGINAL_INVALID", source, nil, nil
	}
	e := record.Event
	if e.Namespace != g.manifest.Scope.Namespace || e.UserID != event.Scope.UserID.String() || e.OriginID != payload.OriginID || e.EvidenceID != payload.EvidenceID || e.AuthorityID != payload.ExternalAuthority || e.EventID != payload.ExternalEventID || record.Sequence != payload.CreditSequence || record.CreditedAt.After(event.CreatedAt) {
		return "INVALID", "INCOME_EVENT_SCOPE_OR_TIME_DIFFERS", source, nil, nil
	}
	origin := g.row("income_origins", payload.OriginID)
	if origin == nil {
		return "INVALID", "INCOME_ORIGIN_MISSING", source, nil, nil
	}
	if origin.text("original_account_id") != e.AccountID || origin.money("amount_cents") != e.Amount || !origin.instant("occurred_at").Equal(e.OccurredAt) || origin.text("evidence_id") != e.EvidenceID || origin.text("evidence_hash") != blob.text("digest") {
		return "INVALID", "INCOME_ORIGIN_ORIGINAL_DIFFERS", source, nil, nil
	}
	if g.bank == nil {
		err = fmt.Errorf("%w: automation receipt independent bank source unavailable", evidence.ErrIncomplete)
		return
	}
	independent := false
	for _, entry := range g.bank.Credit.Credits {
		if entry.Record.Event.OriginID == e.OriginID {
			actual, e := entry.Record.CanonicalBytes()
			independent = e == nil && entry.RecordHash == blob.text("digest") && bytes.Equal(actual, raw)
			break
		}
	}
	if !independent {
		err = businessInvalid("native automation income receipt differs from independent bank credit")
		return
	}
	if e.OccurredAt.Before(grant.Terms.EffectiveFrom) || !e.OccurredAt.Before(grant.Terms.ExpiresAt) {
		return "NOT_ELIGIBLE", "ORIGINAL_INCOME_OUTSIDE_GRANT_WINDOW", source, raw, nil
	}
	source = policy.NativeOccurrenceSource{Kind: "INCOME_EVENT", ID: e.OriginID, OriginalHash: blob.text("digest"), OccurredAt: e.OccurredAt, AvailableAt: record.CreditedAt}
	if source.Validate(grant.Terms.Family) != nil {
		return "INVALID", "INCOME_SOURCE_INVALID", source, nil, nil
	}
	return "REGISTERED", "", source, raw, nil
}
