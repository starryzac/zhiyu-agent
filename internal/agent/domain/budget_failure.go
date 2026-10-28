package domain

import "errors"

// BudgetFailure exposes only a fixed local reason. No request/model values
// are retained, and errors.Is(err, ErrBudget) remains the caller contract.
type BudgetFailure struct{ reason string }

func (e *BudgetFailure) Error() string  { return ErrBudget.Error() }
func (e *BudgetFailure) Unwrap() error  { return ErrBudget }
func (e *BudgetFailure) Reason() string { return e.reason }

func budgetFailure(reason string) error { return &BudgetFailure{reason: reason} }

func BudgetFailureReason(err error) string {
	var failure *BudgetFailure
	if errors.As(err, &failure) {
		return failure.Reason()
	}
	return ""
}
