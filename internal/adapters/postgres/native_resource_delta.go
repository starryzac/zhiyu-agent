// Resource selection preserves the complete scoped history.
package postgres

import funds "zhiyu.local/zhiyu-go/internal/funds/domain"

// Only these history-growing resources are selected. Accounts, both goal
// projections, positions/state and principal returns retain their original
// complete write/check path. This is not a complete NativeLedger.
type nativeResourceWrites struct {
	GoalLots        []NativeGoalLot
	Holds           []NativeHold
	ReturnLocations []NativeReturnLocation
	ReturnClaims    []NativeReturnClaim
}

type nativeGoalLotIdentity struct {
	Goal, Account funds.ID
	Kind, Source  string
}

type nativeHoldIdentity struct {
	Operation              funds.ID
	Kind, Resource, Detail string
}

type nativeReturnLocationIdentity struct {
	BankKey string
	Account funds.ID
}

type nativeReturnClaimIdentity struct {
	Operation funds.ID
	BankKey   string
	Account   funds.ID
}

// The caller must hold the same user lock and obtain before by a fresh, full
// LoadNativeLedger in this transaction; after must first pass validate(user).
// No cached snapshot, subset or successful previous save can replace that read.
// Identity sets are complete: even a terminal zero-valued row may not disappear.
func nativeChangedResources(before, after NativeLedger) (nativeResourceWrites, error) {
	var out nativeResourceWrites
	if before.Namespace != after.Namespace {
		return out, ErrLedgerConflict
	}
	lots := make(map[nativeGoalLotIdentity]NativeGoalLot, len(before.GoalLots))
	for _, value := range before.GoalLots {
		key := nativeGoalLotIdentity{value.GoalID, value.AccountID, value.SourceKind, value.SourceID}
		if _, exists := lots[key]; exists {
			return nativeResourceWrites{}, ErrLedgerConflict
		}
		lots[key] = value
	}
	for _, value := range after.GoalLots {
		key := nativeGoalLotIdentity{value.GoalID, value.AccountID, value.SourceKind, value.SourceID}
		old, exists := lots[key]
		if !exists || old != value {
			out.GoalLots = append(out.GoalLots, value)
		}
		delete(lots, key)
	}
	if len(lots) != 0 {
		return nativeResourceWrites{}, ErrLedgerConflict
	}
	holds := make(map[nativeHoldIdentity]NativeHold, len(before.Holds))
	for _, value := range before.Holds {
		key := nativeHoldIdentity{value.OperationID, value.ResourceKind, value.ResourceID, value.ResourceDetail}
		if _, exists := holds[key]; exists {
			return nativeResourceWrites{}, ErrLedgerConflict
		}
		holds[key] = value
	}
	for _, value := range after.Holds {
		key := nativeHoldIdentity{value.OperationID, value.ResourceKind, value.ResourceID, value.ResourceDetail}
		old, exists := holds[key]
		if exists && old.Amount != value.Amount {
			return nativeResourceWrites{}, ErrLedgerConflict
		}
		if !exists || old.State != value.State {
			out.Holds = append(out.Holds, value)
		}
		delete(holds, key)
	}
	if len(holds) != 0 {
		return nativeResourceWrites{}, ErrLedgerConflict
	}
	locations := make(map[nativeReturnLocationIdentity]NativeReturnLocation, len(before.ReturnLocations))
	for _, value := range before.ReturnLocations {
		key := nativeReturnLocationIdentity{value.BankKey, value.AccountID}
		if _, exists := locations[key]; exists {
			return nativeResourceWrites{}, ErrLedgerConflict
		}
		locations[key] = value
	}
	for _, value := range after.ReturnLocations {
		key := nativeReturnLocationIdentity{value.BankKey, value.AccountID}
		old, exists := locations[key]
		if !exists || old != value {
			out.ReturnLocations = append(out.ReturnLocations, value)
		}
		delete(locations, key)
	}
	if len(locations) != 0 {
		return nativeResourceWrites{}, ErrLedgerConflict
	}
	claims := make(map[nativeReturnClaimIdentity]NativeReturnClaim, len(before.ReturnClaims))
	for _, value := range before.ReturnClaims {
		key := nativeReturnClaimIdentity{value.OperationID, value.BankKey, value.AccountID}
		if _, exists := claims[key]; exists {
			return nativeResourceWrites{}, ErrLedgerConflict
		}
		claims[key] = value
	}
	for _, value := range after.ReturnClaims {
		key := nativeReturnClaimIdentity{value.OperationID, value.BankKey, value.AccountID}
		old, exists := claims[key]
		if exists && old.Amount != value.Amount {
			return nativeResourceWrites{}, ErrLedgerConflict
		}
		if !exists || old.State != value.State {
			out.ReturnClaims = append(out.ReturnClaims, value)
		}
		delete(claims, key)
	}
	if len(claims) != 0 {
		return nativeResourceWrites{}, ErrLedgerConflict
	}
	return out, nil
}
