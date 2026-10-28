package app

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5"
	"zhiyu.local/zhiyu-go/internal/execution/bankv2"
	funds "zhiyu.local/zhiyu-go/internal/funds/domain"
)

func standingJointPrefix(ctx context.Context, q queryRow, p Principal, plan nativeStandingAllocationPlan) ([]nativePrefixReceipt, error) {
	if plan.Joint == nil {
		return nil, reject("EVIDENCE_INVALID", nil)
	}
	out := []nativePrefixReceipt{}
	for i := 0; i < plan.JointChild-1; i++ {
		slot := plan.Joint.Slots[i]
		child := plan.Joint.Result.Children[i]
		var raw, requestRaw, planRaw []byte
		var state, rid, hash, requestHash, planHash string
		err := q.QueryRow(ctx, `SELECT o.status,r.id::text,r.original,r.original_hash,o.bank_request,o.bank_request_hash,p.original,p.original_hash FROM native_operations o JOIN native_receipts r ON(r.environment_id=o.environment_id AND r.user_id=o.user_id AND r.operation_id=o.id AND r.id=o.receipt_id) JOIN native_standing_plans p ON(p.environment_id=o.environment_id AND p.user_id=o.user_id AND p.id=o.id) WHERE o.environment_id=$1 AND o.user_id=$2 AND o.id=$3 AND o.group_id=$4 AND o.child_number=$5`, p.EnvironmentID.String(), p.UserID.String(), slot.OperationID.String(), plan.Occurrence.ID.String(), i+1).Scan(&state, &rid, &raw, &hash, &requestRaw, &requestHash, &planRaw, &planHash)
		if err != nil {
			return nil, reject("SOURCE_CHANGED", err)
		}
		var receipt NativeReceipt
		var request bankv2.Request
		var prior nativeStandingAllocationPlan
		if state != "SETTLED" || Hash(raw) != hash || Hash(planRaw) != planHash || auditJSON(raw, &receipt) != nil || auditJSON(requestRaw, &request) != nil || auditJSON(planRaw, &prior) != nil {
			return nil, reject("EVIDENCE_INVALID", nil)
		}
		want, e := request.Digest()
		expected := standingAllocationExpectedRequest(prior, request.Namespace, planHash)
		eh, e2 := expected.Digest()
		j1, _ := encode(plan.Joint)
		j2, _ := encode(prior.Joint)
		if e != nil || e2 != nil || want != requestHash || eh != want || string(j1) != string(j2) || prior.ID != slot.OperationID || prior.JointChild != i+1 || receipt.Protocol != "native-receipt-v1" || receipt.ID.String() != rid || receipt.OperationID != slot.OperationID || receipt.GroupID != plan.Occurrence.ID || receipt.BankResult.Status != bankv2.Settled || request.Effect.DestinationGoalID != child.GoalID.String() || request.Effect.Amount != child.Amount || bankv2.VerifyResult(request, receipt.BankResult) != nil {
			return nil, reject("EVIDENCE_INVALID", nil)
		}
		out = append(out, nativePrefixReceipt{OperationID: slot.OperationID.String(), ReceiptID: rid, ReceiptHash: hash})
	}
	return out, nil
}

func verifyStandingJointWitness(ctx context.Context, q queryRow, p Principal, plan nativeStandingAllocationPlan, proof nativeStandingSubmissionProof) error {
	if proof.Protocol != nativeStandingJointPermitProtocol || len(proof.PrefixReceipts) != plan.JointChild-1 || proof.FundsVersion != plan.Dependencies.FundsVersion+uint64(plan.JointChild) || proof.SourceVersion != plan.Dependencies.SourceEvidenceVersion+uint64(plan.JointChild-1) {
		return reject("EVIDENCE_INVALID", nil)
	}
	prefix, e := standingJointPrefix(ctx, q, p, plan)
	if e != nil {
		return e
	}
	a, _ := encode(prefix)
	b, _ := encode(proof.PrefixReceipts)
	// omitempty means the first child is represented by nil in the wire.
	if len(prefix) == 0 && len(proof.PrefixReceipts) == 0 {
		return nil
	}
	if string(a) != string(b) {
		return reject("EVIDENCE_INVALID", nil)
	}
	return nil
}

func validateStandingJointGoalVersions(ctx context.Context, q queryRow, p Principal, plan nativeStandingAllocationPlan) error {
	counts := map[string]uint64{}
	for i := 0; i < plan.JointChild-1; i++ {
		counts[plan.Joint.Result.Children[i].GoalID.String()]++
	}
	for id, version := range plan.Joint.GoalVersions {
		var current uint64
		if e := q.QueryRow(ctx, `SELECT version FROM goals WHERE environment_id=$1 AND user_id=$2 AND id=$3`, p.EnvironmentID.String(), p.UserID.String(), id).Scan(&current); e != nil {
			return e
		}
		if current != version+counts[id] {
			return reject("SOURCE_CHANGED", nil)
		}
	}
	return nil
}

func finalizeStandingAllocationBudgetIfDone(ctx context.Context, tx pgx.Tx, p Principal, plan nativeStandingAllocationPlan, now time.Time) error {
	var pending int
	var spent int64
	if e := tx.QueryRow(ctx, `SELECT count(*) FILTER(WHERE o.status NOT IN ('SETTLED','REJECTED','CANCELLED')),coalesce(sum(x.economic_amount_cents) FILTER(WHERE o.status='SETTLED'),0)::bigint FROM native_occurrence_operations x JOIN native_operations o ON(o.environment_id=x.environment_id AND o.user_id=x.user_id AND o.id=x.operation_id) WHERE x.environment_id=$1 AND x.user_id=$2 AND x.occurrence_id=$3`, p.EnvironmentID.String(), p.UserID.String(), plan.Occurrence.ID.String()).Scan(&pending, &spent); e != nil {
		return e
	}
	if pending > 0 {
		return nil
	}
	var state string
	var recorded int64
	if e := tx.QueryRow(ctx, `SELECT state,spent_cents FROM native_grant_budget_claims WHERE environment_id=$1 AND user_id=$2 AND occurrence_id=$3`, p.EnvironmentID.String(), p.UserID.String(), plan.Occurrence.ID.String()).Scan(&state, &recorded); e != nil {
		return e
	}
	if state == "FINAL" {
		if recorded != spent {
			return reject("EVIDENCE_INVALID", nil)
		}
		return nil
	}
	amount, e := funds.NewMoney(spent)
	if e != nil {
		return e
	}
	return finalizeNativeStandingBudget(ctx, tx, p, plan.Occurrence.ID, amount, now)
}

// Only a verified bank REJECTED result may release the signed current child.
// Every other suffix child must still be unsigned QUEUED. Settled prefix facts
// and receipts stay intact and remain charged against the original budget.
func (s *Service) cancelStandingJointSuffix(ctx context.Context, tx pgx.Tx, c Claim, plan nativeStandingAllocationPlan, reason string, bankRejected bool) error {
	p := c.Principal
	ledger, e := s.Store.LoadNativeLedger(ctx, tx, p.EnvironmentID, p.UserID, s.now())
	if e != nil {
		return e
	}
	for i := plan.JointChild - 1; i < len(plan.Joint.Slots); i++ {
		slot := plan.Joint.Slots[i]
		var state string
		var signature *string
		if e = tx.QueryRow(ctx, `SELECT status,permit_signature FROM native_operations WHERE environment_id=$1 AND user_id=$2 AND id=$3 AND group_id=$4 FOR UPDATE`, p.EnvironmentID.String(), p.UserID.String(), slot.OperationID.String(), plan.Occurrence.ID.String()).Scan(&state, &signature); e != nil {
			return e
		}
		if i == plan.JointChild-1 && bankRejected {
			if signature == nil || state == "SETTLED" || state == "CANCELLED" {
				return reject("OPERATION_UNKNOWN", nil)
			}
		} else if state != "QUEUED" || signature != nil {
			return reject("OPERATION_UNKNOWN", nil)
		}
		ledger.Income, e = ledger.Income.Release(slot.OperationID, s.now(), true)
		if e != nil {
			return e
		}
		for k := range ledger.Holds {
			if ledger.Holds[k].OperationID == slot.OperationID {
				ledger.Holds[k].State = funds.Released
			}
		}
		status := "CANCELLED"
		if i == plan.JointChild-1 && bankRejected {
			status = "REJECTED"
		}
		_, e = tx.Exec(ctx, `UPDATE native_operations SET status=$4,bank_observed_status=CASE WHEN $4='REJECTED' THEN 'REJECTED' ELSE bank_observed_status END,processing_health=$5,version=version+1,updated_at=$6 WHERE environment_id=$1 AND user_id=$2 AND id=$3`, p.EnvironmentID.String(), p.UserID.String(), slot.OperationID.String(), status, reason, s.now())
		if e != nil {
			return e
		}
		if status == "REJECTED" {
			e = s.recordNativeObservedRejection(ctx, tx, p, slot.OperationID)
		} else {
			e = s.recordNativeCancellation(ctx, tx, p, slot.OperationID, reason)
		}
		if e != nil {
			return e
		}
		_, e = tx.Exec(ctx, `UPDATE native_jobs SET state='FINISHED',lease_owner=NULL,lease_until=NULL,last_error=$4 WHERE environment_id=$1 AND user_id=$2 AND operation_id=$3`, p.EnvironmentID.String(), p.UserID.String(), slot.OperationID.String(), reason)
		if e != nil {
			return e
		}
	}
	if e = s.Store.PersistNativeLedger(ctx, tx, p.EnvironmentID, p.UserID, ledger); e != nil {
		return e
	}
	if e = finalizeStandingAllocationBudgetIfDone(ctx, tx, p, plan, s.now()); e != nil {
		return e
	}
	if _, e = tx.Exec(ctx, `UPDATE users SET funds_version=funds_version+1 WHERE environment_id=$1 AND id=$2`, p.EnvironmentID.String(), p.UserID.String()); e != nil {
		return e
	}
	_, _, e = s.refreshTemplateProtectionAfterNativeEffect(ctx, tx, p, plan.Grant.Terms.Timezone)
	return e
}
