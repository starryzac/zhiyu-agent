package executionaudit

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strconv"
	"time"

	evidence "zhiyu.local/zhiyu-go/internal/audit"
	funds "zhiyu.local/zhiyu-go/internal/funds/domain"
)

// fundsPrefixCaptureV3 is the read-only causal index for candidate/T2 callers.
// It replays ONLY the retained FV1..version delta originals; neither today's
// ledger nor the mutable projection cache participates. Call after original
// income/native/legacy/bank prerequisites. This returns the ACTUAL prefix. T2
// callers must separately derive and compare their explicitly neutralized own
// reservation view; no hypothetical bank effect is applied here.
func (g *nativeGraphV3) fundsPrefixRowsV3(version uint64, at time.Time) (map[string][]string, nativeFundsCommitV3, error) {
	var last nativeFundsCommitV3
	if version == 0 || version > uint64(g.snapshot.Watermarks["funds_version"]) || at.IsZero() {
		return nil, last, fmt.Errorf("%w: exact candidate funds prefix unavailable", evidence.ErrIncomplete)
	}
	state := nativeFinancialRowSetV3{}
	previous, previousProtocol := "", ""
	var source, writer, control uint64
	for fv := uint64(1); fv <= version; fv++ {
		row := g.row("funds_commit_witnesses", strconv.FormatUint(fv, 10))
		if row == nil {
			return nil, last, fmt.Errorf("%w: candidate historical funds prefix missing FV%d", evidence.ErrIncomplete, fv)
		}
		var c nativeFundsCommitV3
		raw := nativeRawV3(row, "original")
		d := json.NewDecoder(bytes.NewReader(raw))
		d.DisallowUnknownFields()
		if _, e := evidence.ParseRawObject(raw); e != nil || d.Decode(&c) != nil || nativeHashFieldV3(row, "original", "original_hash") != nil || !g.fundsProtocolV3(c.Protocol) || c.Scope != g.ownerScopeV3() || c.Namespace != g.manifest.Scope.Namespace || c.FundsVersion != fv || fv == 1 && (c.PreviousFundsVersion != nil || c.PreviousHash != nil) || fv > 1 && (c.PreviousFundsVersion == nil || *c.PreviousFundsVersion != fv-1 || c.PreviousHash == nil || *c.PreviousHash != previous) || c.SourceVersion < source || c.WriterGeneration < writer || c.ControlVersion < control {
			return nil, last, businessInvalid("candidate exact funds causal index original/chain")
		}
		if previousProtocol == "funds-commit-witness-v2" && c.Protocol != previousProtocol {
			return nil, last, businessInvalid("candidate funds protocol cannot downgrade after terminal authority admission")
		}
		if err := g.checkFundsCommitEffectsV3(state, c); err != nil {
			return nil, last, err
		}
		if err := g.checkFundsGoalCountersV3(state, c); err != nil {
			return nil, last, err
		}
		before := state
		state = nativeCopyFundsStateV3(before)
		if err := nativeApplyFundsDeltaV3(state, c); err != nil {
			return nil, last, err
		}
		if err := g.checkFundsTemplateAuthorityV3(state, c); err != nil {
			return nil, last, err
		}
		if err := g.checkNativeGrantPrefixV3(state, c); err != nil {
			return nil, last, err
		}
		if err := g.checkFundsTerminalDecisionsV3(before, state, c); err != nil {
			return nil, last, err
		}
		if fv == version && (c.TransactionStartedAt == nil || at.Before(*c.TransactionStartedAt)) {
			return nil, last, businessInvalid("candidate prefix precedes actual transaction lower bound")
		}
		previous, source, writer, control = row.text("original_hash"), c.SourceVersion, c.WriterGeneration, c.ControlVersion
		previousProtocol = c.Protocol
		last = c
	}
	rows, err := nativeFactsRowsV3(state)
	return rows, last, err
}

func (g *nativeGraphV3) fundsPrefixCaptureV3(version uint64, at time.Time) (wireNativeAssetLedgerCapture, error) {
	var zero wireNativeAssetLedgerCapture
	rows, _, err := g.fundsPrefixRowsV3(version, at)
	if err != nil {
		return zero, err
	}
	capture, err := nativeFactsLedgerFromRowsV3(g.ownerScopeV3(), g.manifest.Scope.Namespace, at, rows)
	if err != nil {
		return zero, err
	}
	if _, err = g.frozenLedgerV3(capture, at); err != nil {
		return zero, err
	}
	return capture, nil
}

// checkPrefixSourceHashV3 binds a consumer's actual raw source hash to the
// exact published source-version nonfinancial originals and its actual FV
// rows. The published witness is never used as today's financial ledger.
func (g *nativeGraphV3) checkPrefixSourceHashV3(fundsVersion, sourceVersion, writer, control uint64, sourceHash, inventoryHash string, at time.Time, timezone string) error {
	rows, commit, err := g.fundsPrefixRowsV3(fundsVersion, at)
	if err != nil {
		return err
	}
	if sourceVersion < commit.SourceVersion || writer < commit.WriterGeneration || control < commit.ControlVersion || sourceVersion > uint64(g.snapshot.Watermarks["source_version"]) || writer > uint64(g.snapshot.Watermarks["writer_generation"]) || control > uint64(g.snapshot.Watermarks["control_version"]) {
		return businessInvalid("consumer source/funds/authority watermarks precede its actual prefix")
	}
	publication := g.row("template_protection_publications", strconv.FormatUint(sourceVersion, 10))
	if publication == nil {
		return fmt.Errorf("%w: consumer exact published source version absent", evidence.ErrIncomplete)
	}
	id := publication.optional("source_witness_id")
	witness := g.row("template_source_witnesses", id)
	if id == "" || witness == nil {
		return fmt.Errorf("%w: consumer published nonfinancial source witness absent", evidence.ErrIncomplete)
	}
	var w nativeTemplateSourceWitnessV3
	nativeOriginalV3(witness, "original", &w)
	if nativeHashFieldV3(witness, "original", "original_hash") != nil || publication.text("source_witness_hash") != witness.text("original_hash") || w.SnapshotSourceVersion+1 != sourceVersion || w.Timezone != timezone || w.AsOf.After(at) {
		return businessInvalid("consumer exact source publication ancestry/timezone")
	}
	var basis nativeTemplateSourceBasisV3
	if json.Unmarshal(w.SourceBasisOriginal, &basis) != nil || nakedHash(w.SourceBasisOriginal) != w.SourceBasisHash || basis.Scope != g.ownerScopeV3() || nakedHash(mustJSONV3(basis.Inventory)) != inventoryHash {
		return businessInvalid("consumer independently retained source-basis inventory")
	}
	basis.FundsVersion, basis.Writer, basis.Control = fundsVersion, writer, control
	for _, table := range w.SourceTables {
		if nativeFactsTableV3(table) {
			if _, exists := basis.Rows[table]; exists {
				return businessInvalid("consumer source duplicates financial prefix")
			}
			basis.Rows[table] = rows[table]
		}
	}
	if nakedHash(mustJSONV3(basis)) != sourceHash {
		return businessInvalid("consumer source hash differs from exact FV and published nonfinancial originals")
	}
	return nil
}

func (g *nativeGraphV3) fundsPrefixLedgerV3(version uint64, at time.Time, neutralized ...funds.ID) (nativeFrozenLedgerV3, error) {
	capture, err := g.fundsPrefixCaptureV3(version, at)
	if err != nil {
		return nativeFrozenLedgerV3{}, err
	}
	n, err := capture.DomainLedger()
	if err != nil {
		return n, err
	}
	for _, operation := range neutralized {
		found := false
		for _, r := range n.Income.Snapshot().Reservations {
			if r.ActionID != operation {
				continue
			}
			if r.State != funds.Reserved {
				return n, businessInvalid("T2 neutralization requires its exact still-reserved income prefix")
			}
			n.Income, err = n.Income.Release(operation, at, true)
			if err != nil {
				return n, err
			}
			found = true
		}
		for i := range n.ReturnClaims {
			claim := &n.ReturnClaims[i]
			if claim.OperationID != operation {
				continue
			}
			if claim.State != funds.Reserved {
				return n, businessInvalid("T2 neutralization cannot release committed principal")
			}
			located := false
			for j := range n.ReturnLocations {
				location := &n.ReturnLocations[j]
				if location.BankKey == claim.BankKey && location.AccountID == claim.AccountID {
					location.Reserved, err = location.Reserved.Sub(claim.Amount)
					if err != nil {
						return n, err
					}
					located = true
				}
			}
			if !located {
				return n, businessInvalid("T2 original principal-return location absent")
			}
			claim.State = funds.Released
			found = true
		}
		for i := range n.Holds {
			hold := &n.Holds[i]
			if hold.OperationID != operation {
				continue
			}
			if hold.State != funds.Reserved {
				return n, businessInvalid("T2 neutralization cannot release terminal resources")
			}
			if hold.ResourceKind == "GOAL_LOT" {
				var ref struct {
					AccountID  string `json:"account_id"`
					SourceKind string `json:"source_kind"`
					SourceID   string `json:"source_id"`
				}
				if json.Unmarshal([]byte(hold.ResourceDetail), &ref) != nil {
					return n, businessInvalid("T2 exact held goal-lot reference")
				}
				located := false
				for j := range n.GoalLots {
					lot := &n.GoalLots[j]
					if lot.GoalID.String() == hold.ResourceID && lot.AccountID.String() == ref.AccountID && lot.SourceKind == ref.SourceKind && lot.SourceID == ref.SourceID {
						lot.Reserved, err = lot.Reserved.Sub(hold.Amount)
						if err != nil {
							return n, err
						}
						located = true
					}
				}
				if !located {
					return n, businessInvalid("T2 exact held goal-lot absent")
				}
			}
			hold.State = funds.Released
			found = true
		}
		for i := range n.Positions {
			position := &n.Positions[i]
			if position.ClosingOperationID != nil && *position.ClosingOperationID == operation {
				if position.Closed {
					return n, businessInvalid("T2 cannot neutralize an already closed position")
				}
				position.ClosingOperationID = nil
				found = true
			}
		}
		if !found {
			return n, businessInvalid("T2 neutralization omitted actual reserved own operation")
		}
	}
	if n.validate(g.ownerScopeV3().UserID) != nil {
		return n, businessInvalid("neutralized exact funds prefix invariant")
	}
	if err = g.checkFrozenLedgerProjectionV3(n, at, neutralized...); err != nil {
		return n, err
	}
	return n, nil
}
