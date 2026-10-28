package app

import (
	"sort"

	agent "zhiyu.local/zhiyu-go/internal/agent/domain"
)

// agentKnownBillPayees consumes only the full, validated BILL snapshot from
// this RR read. It adds no bank query or persisted preview/authorization.
func agentKnownBillPayees(snapshot templateSnapshot, namespace string) ([]agent.ObjectObservation, error) {
	scope := agent.Scope{EnvironmentID: snapshot.Facts.Scope.EnvironmentID, UserID: snapshot.Facts.Scope.UserID}
	byPayee := map[string][]agent.KnownPayeeEvidence{}
	for key, proof := range snapshot.BillProofs {
		bill, err := nativeBillProofOriginal(proof, snapshot.Facts.Scope, snapshot.AsOf)
		if err != nil {
			return nil, err
		}
		if bill.BankNamespace != namespace || key != "bill:"+bill.ID.String() {
			return nil, reject("BILL_BANK_ORIGINAL_MISMATCH", nil)
		}
		byPayee[bill.PayeeID] = append(byPayee[bill.PayeeID], agent.KnownPayeeEvidence{BillID: bill.ID, StatementAccountID: bill.StatementAccountID, OriginalHash: proof.OriginalHash, BankReferenceHash: proof.BankReferenceHash})
	}
	keys := make([]string, 0, len(byPayee))
	for key := range byPayee {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	if len(keys) > 100 {
		return nil, reject("TEMPLATE_CAPACITY_EXCEEDED", nil)
	}
	out := []agent.ObjectObservation{}
	for _, key := range keys {
		if len(byPayee[key]) > 100 {
			return nil, reject("TEMPLATE_CAPACITY_EXCEEDED", nil)
		}
		o, err := agent.NewKnownPayeeObject(scope, namespace, key, snapshot.Facts.SourceHash, byPayee[key])
		if err != nil {
			return nil, reject("EVIDENCE_INVALID", err)
		}
		out = append(out, o)
	}
	return out, nil
}
