package executionaudit

import (
	"bytes"
	"fmt"
	"math/big"
	"time"

	evidence "zhiyu.local/zhiyu-go/internal/audit"
	"zhiyu.local/zhiyu-go/internal/execution/bankcredit"
	"zhiyu.local/zhiyu-go/internal/execution/bankv2"
	execution "zhiyu.local/zhiyu-go/internal/execution/domain"
	funds "zhiyu.local/zhiyu-go/internal/funds/domain"
	planning "zhiyu.local/zhiyu-go/internal/planning/domain"
	policy "zhiyu.local/zhiyu-go/internal/policy/domain"
)

type nativeControlledBridgeIncomeV3 struct {
	Protocol, Namespace                        string
	EnvironmentID, UserID, AccountID, OriginID funds.ID
	Amount                                     funds.Money
	OccurredAt                                 time.Time
	Source                                     string
}

func (g *nativeGraphV3) checkLegacyV3() error {
	legacy := &businessGraph{v2: true, manifest: g.manifest, rows: g.rows, policies: map[string]policy.Policy{}, grants: map[string]policy.Grant{}, confirmations: map[string]policy.ConfirmationSource{}, plans: map[string]planning.Candidate{}, inputs: map[string]frozenBusinessInput{}, requests: map[string]execution.BankRequest{}, results: map[string][]execution.BankResult{}, reservations: g.reservations, ledger: g.ledger}
	legacy.nativePlanPrefixes = g.snapshot.Revision >= 25
	// These existing pure validators retain their exact legacy semantics. V3
	// separately verifies current projections and mixed-family bank agreement.
	for _, check := range []func() error{legacy.checkPermissions, legacy.checkPlans, legacy.checkOperations, legacy.checkSubmissionPermits} {
		if err := check(); err != nil {
			return err
		}
	}
	g.legacy = legacy
	return g.checkedRowsV3()
}

// No bank result is inferred from an application journal. Every independently
// discovered bank key must have its original scoped application command.
func (g *nativeGraphV3) checkBankAgreementV3() error {
	if g.bank == nil {
		return fmt.Errorf("%w: independent bank full scope source absent", evidence.ErrIncomplete)
	}
	bank := g.bank
	results := map[string]bankv2.Result{}
	for _, result := range bank.Native {
		results[result.Key] = result
	}
	for id, request := range g.nativeRequests {
		op := g.row("native_operations", id)
		result, found := results[request.Key]
		state := op.text("status")
		if state == "CANCELLED" {
			if found {
				return businessInvalid("native cancelled command has a bank effect")
			}
			continue
		}
		if !found {
			if state == "SETTLED" || state == "REJECTED" {
				return businessInvalid("native terminal original absent from complete independent bank inventory")
			}
			// An unsigned or signed unknown original can remain unobserved; its
			// exact reservation is retained, never released from this absence.
			continue
		}
		if bankv2.VerifyResult(request, result) != nil || result.RequestHash != op.text("bank_request_hash") {
			return businessInvalid("native independent bank full request mismatch")
		}
		switch state {
		case "SETTLED":
			if !exactJSON(g.nativeReceipts[id].BankResult, result) {
				return businessInvalid("native independent receipt differs from retained settlement")
			}
		case "REJECTED":
			if result.Status != bankv2.Rejected || !result.AbsenceIsFinal {
				return businessInvalid("native rejected without actual bank no-effect proof")
			}
		default:
			if result.Status == bankv2.Settled || result.Status == bankv2.Rejected {
				return fmt.Errorf("%w: native bank terminal result awaits original-key reconciliation", evidence.ErrIncomplete)
			}
			if op.optional("permit_signature") == "" {
				return businessInvalid("native bank acceptance without historical T2")
			}
		}
		delete(results, request.Key)
	}
	if len(results) > 0 {
		return fmt.Errorf("%w: independent native bank key lacks application authority original", evidence.ErrIncomplete)
	}
	legacy := map[string]execution.BankResult{}
	for _, result := range bank.Legacy {
		legacy[result.Key] = result
	}
	usedReceipts, usedJournals, usedPostings := map[string]bool{}, map[string]bool{}, map[string]bool{}
	for id, request := range g.legacy.requests {
		op := g.row("operations", id)
		result, found := legacy[request.Key]
		state := op.text("status")
		if state == "CANCELLED" {
			if found {
				return businessInvalid("legacy cancelled bank effect")
			}
			continue
		}
		if !found {
			if state == "SETTLED" || state == "REJECTED" {
				return businessInvalid("legacy terminal independent original missing")
			}
			continue
		}
		if execution.VerifyBankResult(request, result) != nil || result.RequestHash != op.text("bank_request_hash") {
			return businessInvalid("legacy independent request mismatch")
		}
		if state == "REJECTED" {
			if result.Status != execution.BankRejected || !result.AbsenceIsFinal {
				return businessInvalid("legacy independent rejected proof")
			}
		} else if state == "SETTLED" {
			if result.Status != execution.BankSettled {
				return businessInvalid("legacy local/bank settlement disagreement")
			}
			r := g.row("receipts", op.text("receipt_id"))
			if r == nil {
				return businessInvalid("legacy settled receipt missing")
			}
			var receipt businessReceipt
			nativeOriginalV3(r, "original", &receipt)
			if receipt.ID.String() != r.text("id") || receipt.OperationID.String() != id || receipt.Environment != request.Namespace || receipt.UserID.String() != request.UserID || receipt.BankKey != request.Key || receipt.BankRequestHash != result.RequestHash || receipt.Amount != request.Amount || result.SettledAt == nil || !receipt.SettledAt.Equal(*result.SettledAt) || receipt.RecordedAt.Before(receipt.SettledAt) || receipt.RecordedAt.After(g.manifest.Source.CapturedAt) || len(receipt.PostingIDs) != len(result.Postings) {
				return businessInvalid("legacy retained receipt full binding")
			}
			journal := g.row("journals", receipt.JournalID.String())
			if journal == nil || journal.text("operation_id") != id || journal.text("status") != "POSTED" {
				return businessInvalid("legacy original posted journal")
			}
			for i, leg := range result.Postings {
				ref := fmt.Sprintf("bank:%d:%s", i+1, leg.ID)
				posting := g.row("postings", receipt.JournalID.String(), ref)
				dimension := "GOAL_OWNERSHIP"
				if leg.Dimension == "INCOME_LOCATION" {
					dimension = "INCOME_QUALIFICATION"
				}
				if posting == nil || receipt.PostingIDs[i] != leg.ID || posting.text("dimension") != dimension || posting.text("account_id") != request.SourceAccountID || posting.text("direction") != leg.Direction || posting.money("amount_cents") != leg.Amount || posting.text("currency") != "CNY" {
					return businessInvalid("legacy original exact posting legs")
				}
				usedPostings[keyParts(receipt.JournalID.String(), ref)] = true
			}
			usedReceipts[r.text("id")], usedJournals[receipt.JournalID.String()] = true, true
		} else if result.Status == execution.BankSettled || result.Status == execution.BankRejected {
			return fmt.Errorf("%w: legacy terminal result awaits original-key reconciliation", evidence.ErrIncomplete)
		}
		delete(legacy, request.Key)
	}
	if len(legacy) > 0 {
		return fmt.Errorf("%w: independent legacy bank key lacks application authority original", evidence.ErrIncomplete)
	}
	if len(usedReceipts) != len(g.rows["receipts"]) || len(usedJournals) != len(g.rows["journals"]) || len(usedPostings) != len(g.rows["postings"]) {
		return businessInvalid("legacy orphan receipt/journal/posting")
	}
	if err := g.checkIndependentIncomeV3(); err != nil {
		return err
	}
	if err := g.checkIndependentStockV3(); err != nil {
		return err
	}
	return g.checkedRowsV3()
}

func (g *nativeGraphV3) checkIndependentIncomeV3() error {
	bank := g.bank
	purchased, spent := map[string]*big.Int{}, map[string]*big.Int{}
	for _, result := range bank.Native {
		if result.Status != bankv2.Settled {
			continue
		}
		e := result.Request.Effect
		if e.Kind != bankv2.Payment && (e.Kind != bankv2.Purchase || e.SourceGoalID != "") {
			continue
		}
		for _, use := range e.OriginUses {
			if use.Bucket != "AVAILABLE" {
				return businessInvalid("native spent origin qualification bucket")
			}
			key := use.OriginID + "/" + use.AccountID
			addBusinessSum(spent, key, use.Amount.Cents())
			if e.Kind == bankv2.Purchase {
				addBusinessSum(purchased, key, use.Amount.Cents())
			}
		}
	}
	credits := map[string]bankcredit.Entry{}
	for _, entry := range bank.Credit.Credits {
		credits[entry.Record.Event.OriginID] = entry
	}
	seenOrigins, seenLocations := map[string]bool{}, map[string]bool{}
	for _, origin := range bank.Credit.Origins {
		row := g.row("income_origins", origin.ID)
		if row == nil {
			return fmt.Errorf("%w: independently credited income awaits trusted intake", evidence.ErrIncomplete)
		}
		if row.text("original_account_id") != origin.OriginalAccountID || row.money("amount_cents") != origin.Amount || !row.instant("occurred_at").Equal(origin.OccurredAt) || row.text("evidence_hash") != origin.EvidenceHash {
			return businessInvalid("native independent immutable income source mismatch")
		}
		evidenceRow := g.row("evidence_blobs", row.text("evidence_id"))
		if evidenceRow == nil {
			return fmt.Errorf("%w: original income evidence missing", evidence.ErrIncomplete)
		}
		if entry, ok := credits[origin.ID]; ok {
			want, _ := entry.Record.CanonicalBytes()
			if evidenceRow.text("kind") != "BANK_EXTERNAL_CREDIT_V1" || evidenceRow.text("digest") != entry.RecordHash || !bytes.Equal(nativeRawV3(evidenceRow, "canonical"), want) {
				return businessInvalid("native independent external credit original/hash")
			}
		} else {
			// Old explicit seed originals remain visibly old bank facts. They
			// never become a newly arrived standing income occurrence.
			switch evidenceRow.text("kind") {
			case "EXPLICIT_SIMULATED_BANK_INCOME":
				var proof businessIncomeProof
				raw := nativeOriginalV3(evidenceRow, "canonical", &proof)
				if nakedHash(raw) != origin.EvidenceHash || evidenceRow.text("digest") != origin.EvidenceHash || proof.Namespace != g.manifest.Scope.Namespace || proof.UserID.String() != g.manifest.Scope.UserID || proof.OriginID.String() != origin.ID || proof.AccountID.String() != origin.OriginalAccountID || proof.Amount != origin.Amount || !proof.OccurredAt.Equal(origin.OccurredAt) {
					return businessInvalid("native explicit simulated income differs from independent bank original")
				}
			case "CONTROLLED_BANK_BRIDGE_SOURCE":
				var proof nativeControlledBridgeIncomeV3
				raw := nativeOriginalV3(evidenceRow, "canonical", &proof)
				if nakedHash(raw) != origin.EvidenceHash || evidenceRow.text("digest") != origin.EvidenceHash || proof.Protocol != "controlled-bank-bridge-source-v1" || proof.Source != "explicit-new-namespace-bank-opening-and-income-after-USER-rules" || proof.EnvironmentID.String() != g.manifest.Scope.EnvironmentID || proof.Namespace != g.manifest.Scope.Namespace || proof.UserID.String() != g.manifest.Scope.UserID || proof.AccountID.String() != origin.OriginalAccountID || proof.OriginID.String() != origin.ID || proof.Amount != origin.Amount || !proof.OccurredAt.Equal(origin.OccurredAt) {
					return businessInvalid("native controlled bridge seed differs from independent bank origin")
				}
			default:
				return fmt.Errorf("%w: historical independent income source", evidence.ErrUnsupportedVersion)
			}
		}
		for _, location := range origin.Locations {
			id := funds.LocationID(mustBusinessID(origin.ID), mustBusinessID(location.AccountID)).String()
			row := g.row("income_locations", id)
			if row == nil {
				return businessInvalid("native bank origin location omitted")
			}
			key := origin.ID + "/" + location.AccountID
			assigned := new(big.Int).SetInt64(row.money("assigned_cents").Cents())
			if p := purchased[key]; p != nil {
				assigned.Add(assigned, p)
			}
			// Before T2, the application can already hold qualification that
			// the bank has not reserved yet. Both describe the same unspent pool.
			localUnspent, err := row.money("available_cents").Add(row.money("reserved_cents"))
			if err != nil || localUnspent != location.Available || assigned.Cmp(big.NewInt(location.Assigned.Cents())) != 0 || !businessSum(spent, key, row.money("spent_cents").Cents()) || location.Reserved.Cents() > row.money("reserved_cents").Cents() {
				return businessInvalid("native independent source disposition/reservation conservation")
			}
			seenLocations[id] = true
		}
		seenOrigins[origin.ID] = true
	}
	if len(seenOrigins) != len(g.rows["income_origins"]) || len(seenLocations) != len(g.rows["income_locations"]) {
		return businessInvalid("native application income absent from complete bank source inventory")
	}
	return nil
}

func (g *nativeGraphV3) checkIndependentStockV3() error {
	stock := g.bank.Stock
	if len(stock.Accounts) != len(g.rows["accounts"]) || len(stock.Positions) != len(g.rows["native_positions"]) {
		return businessInvalid("native independent account/position inventory")
	}
	seenAccounts := map[string]bool{}
	for _, bank := range stock.Accounts {
		row := g.row("accounts", bank.ID)
		if row == nil || seenAccounts[bank.ID] || row.money("balance_cents") != bank.Balance {
			return businessInvalid("native independent actual cash balance")
		}
		seenAccounts[bank.ID] = true
	}
	seenGoals := map[string]bool{}
	for _, bank := range stock.Goals {
		row := g.row("native_goal_balances", bank.ID)
		goal := g.row("goals", bank.ID)
		if row == nil || goal == nil || seenGoals[bank.ID] || goal.text("account_id") != bank.AccountID || row.money("cash_cents") != bank.Cash || row.money("principal_cents") != bank.Principal || row.money("loss_cents") != bank.Loss {
			return businessInvalid("native independent actual goal cash/principal/loss")
		}
		seenGoals[bank.ID] = true
	}
	for _, row := range g.rows["native_goal_balances"] {
		if !seenGoals[row.text("goal_id")] && (!row.money("cash_cents").IsZero() || !row.money("principal_cents").IsZero() || !row.money("loss_cents").IsZero()) {
			return businessInvalid("native unproved nonzero bank goal anchor")
		}
	}
	seenPositions := map[string]bool{}
	for _, bank := range stock.Positions {
		id := bank.Opening.PositionID
		row, state := g.row("native_positions", id), g.row("native_position_states", id)
		var opening bankv2.PositionOpening
		if row == nil || state == nil || seenPositions[id] {
			return businessInvalid("native independent position state missing/duplicate")
		}
		nativeOriginalV3(row, "original", &opening)
		hash, err := opening.Digest()
		if err != nil || !exactJSON(opening, bank.Opening) || hash != row.text("original_hash") || hash != bank.OpeningHash || row.text("bank_key") != opening.OpeningKey || row.money("principal_cents") != opening.Principal || row.text("return_account_id") != opening.ReturnAccountID || row.optional("goal_id") != opening.GoalID || !row.instant("purchased_at").Equal(opening.PurchasedAt) || state.boolean("closed") != bank.Closed {
			return businessInvalid("native independent full immutable position opening")
		}
		if operation := row.optional("opening_operation_id"); operation != "" {
			r, ok := g.nativeReceipts[operation]
			if !ok || r.BankResult.Position == nil || !exactJSON(*r.BankResult.Position, opening) {
				return businessInvalid("native position opening actual purchase receipt")
			}
		} else if opening.SourceKind != "TRUSTED_HISTORICAL_IMPORT" {
			return businessInvalid("native position missing purchase original")
		}
		closing := state.optional("closing_operation_id")
		if closing == "" {
			if bank.ClosingKey != "" {
				return businessInvalid("native bank position closed without original operation")
			}
		} else {
			request, ok := g.nativeRequests[closing]
			if !ok || request.Key != bank.ClosingKey || request.Effect.PositionID != id {
				return businessInvalid("native position closing original key")
			}
			if bank.Closed && g.nativeReceipts[closing].BankResult.PrincipalReturn == nil {
				return businessInvalid("native closed position lacks actual returned principal receipt")
			}
		}
		seenPositions[id] = true
	}
	return nil
}
