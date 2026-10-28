package main

import (
	"errors"

	"zhiyu.local/zhiyu-go/internal/execution/bankv2"
	funds "zhiyu.local/zhiyu-go/internal/funds/domain"
	policy "zhiyu.local/zhiyu-go/internal/policy/domain"
)

// This projection is not a new bank authority. The operator supplies retained
// independent bank Results; the application separately verifies its original
// local observation, permit, receipt, journal and legs when importing them.
func addBankPayments(statement *policy.HistoryStatement, raw []byte) error {
	var bundle struct {
		Protocol  string          `json:"protocol"`
		Namespace string          `json:"namespace"`
		UserID    string          `json:"user_id"`
		Results   []bankv2.Result `json:"results"`
	}
	if strict(raw, &bundle) != nil || bundle.Protocol != "historyseed-bank-payment-results-v1" || bundle.Namespace != statement.Namespace || bundle.UserID != statement.UserID.String() || bundle.Results == nil || len(bundle.Results) > 1000 {
		return errors.New("retained bank payment inventory scope invalid")
	}
	accounts := map[string]funds.ID{}
	for _, id := range statement.AccountIDs {
		accounts[id.String()] = id
	}
	zone, e := policy.TemplateLocation(statement.Timezone)
	if e != nil {
		return errors.New("statement timezone invalid")
	}
	seen := map[funds.ID]bool{}
	for _, row := range statement.Transactions {
		seen[row.ID] = true
	}
	for _, r := range bundle.Results {
		if r.Request == nil || r.Namespace != statement.Namespace || r.UserID != statement.UserID.String() || r.Status != bankv2.Settled || r.SettledAt == nil || r.Request.Effect.Kind != bankv2.Payment || bankv2.VerifyResult(*r.Request, r) != nil {
			return errors.New("retained original bank payment invalid")
		}
		request := r.Request
		id, e := funds.ParseID(request.OperationID)
		if e != nil || seen[id] || len(request.Effect.CashUses) != 1 {
			return errors.New("retained payment identity or account ambiguous")
		}
		seen[id] = true
		account, ok := accounts[request.Effect.CashUses[0].AccountID]
		if !ok {
			return errors.New("retained payment outside exact account scope")
		}
		date := r.SettledAt.In(zone).Format("2006-01-02")
		if date < statement.FromDate || date > statement.ThroughDate {
			continue
		}
		statement.Transactions = append(statement.Transactions, policy.TemplateHistoryTransaction{ID: id, AccountID: account, Date: date, Direction: "DEBIT", Amount: request.Effect.Amount, Category: "obligation", CategoryConfirmed: true, EconomicRole: "CONSUMPTION"})
	}
	return nil
}
