// Package domain plans candidates without I/O, clock reads, or permission
// creation. All current facts and their authenticity are adapter inputs.
package domain

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"sort"
	"time"

	funds "zhiyu.local/zhiyu-go/internal/funds/domain"
	policy "zhiyu.local/zhiyu-go/internal/policy/domain"
)

const AlgorithmVersion = "single-goal-go-v1"
const MaxProtectionCheckpoints = 1098

var (
	ErrInput           = errors.New("invalid or incomplete single-goal planning input")
	ErrFrozenCandidate = errors.New("candidate differs from its frozen complete effect")
	ErrAuthorization   = errors.New("candidate is not covered by exact current authorization")
)

// DependencyVector must be compared to locked authoritative versions at T1/T2.
// Product versions remain explicit even for a no-product chain (the caller
// uses its no-product catalog version). This is not a freshness signature.
type DependencyVector struct {
	FundsVersion               uint64 `json:"funds_version"`
	GrantVersion               uint64 `json:"grant_version"`
	PolicyVersion              uint64 `json:"policy_version"`
	ProductTermsVersion        uint64 `json:"product_terms_version"`
	ProductAvailabilityVersion uint64 `json:"product_availability_version"`
	SourceEvidenceVersion      uint64 `json:"source_evidence_version"`
	WriterGeneration           uint64 `json:"writer_generation"`
	ControlVersion             uint64 `json:"control_version"`
}

func (v DependencyVector) Validate() error {
	if v.FundsVersion == 0 || v.PolicyVersion == 0 || v.ProductTermsVersion == 0 || v.ProductAvailabilityVersion == 0 || v.SourceEvidenceVersion == 0 || v.WriterGeneration == 0 || v.ControlVersion == 0 {
		return ErrInput
	}
	return nil
}

// ProtectionCheckpoint is a conservative envelope over CURRENT confirmed cash.
// OtherProtected includes all other goals, obligations, living/emergency
// amounts and future minimums. Only this goal's proven remaining current-month
// minimum may shrink one-for-one after contribution. No future credit is used.
type ProtectionCheckpoint struct {
	ID                 string      `json:"id"`
	At                 time.Time   `json:"at"`
	OtherProtected     funds.Money `json:"other_protected"`
	CurrentGoalMinimum funds.Money `json:"current_goal_minimum"`
}

// Protection is supplied only after the application validates the complete
// current protection input. Completeness is a contract, not proof: HTTP must
// never accept this structure from a browser as authoritative protection.
type Protection struct {
	Complete     bool                   `json:"complete"`
	ObservedAt   time.Time              `json:"observed_at"`
	EvidenceHash string                 `json:"evidence_hash"`
	Checkpoints  []ProtectionCheckpoint `json:"checkpoints"`
}

type Input struct {
	Policy           policy.Policy
	Ledger           funds.IncomeLedger
	Cash             []funds.CashLocationFact
	GoalTarget       funds.Money
	GoalAssigned     funds.Money
	MonthContributed funds.Money
	MonthPeriod      string
	Protection       Protection
	Dependencies     DependencyVector
	Now              time.Time
}

type Candidate struct {
	ID               funds.ID              `json:"id"`
	Algorithm        string                `json:"algorithm"`
	Kind             funds.IncomeOperation `json:"kind"`
	PolicyID         funds.ID              `json:"policy_id"`
	PolicyVersion    uint64                `json:"policy_version"`
	PolicyHash       string                `json:"policy_hash"`
	Scope            policy.Scope          `json:"scope"`
	Status           string                `json:"status"`
	Amount           funds.Money           `json:"amount"`
	MaxSafe          funds.Money           `json:"max_safe"`
	MinimumShortfall funds.Money           `json:"minimum_shortfall"`
	EligibleIncome   funds.Money           `json:"eligible_income"`
	Uses             []funds.IncomeUse     `json:"uses"`
	EffectiveFrom    time.Time             `json:"effective_from"`
	EarliestIncomeAt time.Time             `json:"earliest_income_at"`
	PreparedAt       time.Time             `json:"prepared_at"`
	ValidUntil       time.Time             `json:"valid_until"`
	Dependencies     DependencyVector      `json:"dependencies"`
	InputHash        string                `json:"input_hash"`
	EffectHash       string                `json:"effect_hash"`
}

func hash(v any) string {
	b, err := json.Marshal(v)
	if err != nil {
		return ""
	}
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

func minimum(values ...funds.Money) funds.Money {
	m := values[0]
	for _, v := range values[1:] {
		if v.Cents() < m.Cents() {
			m = v
		}
	}
	return m
}

func remaining(limit, used funds.Money) funds.Money {
	if used.Cents() >= limit.Cents() {
		return funds.Money{}
	}
	v, _ := limit.Sub(used)
	return v
}

func validHash(s string) bool {
	if len(s) != 64 {
		return false
	}
	for _, c := range s {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}

func normalizedProtection(p Protection) Protection {
	p.ObservedAt = p.ObservedAt.UTC()
	p.Checkpoints = append([]ProtectionCheckpoint(nil), p.Checkpoints...)
	for i := range p.Checkpoints {
		p.Checkpoints[i].At = p.Checkpoints[i].At.UTC()
	}
	sort.Slice(p.Checkpoints, func(i, j int) bool {
		a, b := p.Checkpoints[i], p.Checkpoints[j]
		if a.At.Equal(b.At) {
			return a.ID < b.ID
		}
		return a.At.Before(b.At)
	})
	return p
}

// PlanSingleGoal returns a preview, never a permission or reservation. Its
// initial supported operation assigns cash already in the same account. It
// rejects cross-account effects rather than inventing an implicit transfer.
func PlanSingleGoal(in Input) (Candidate, error) {
	planSingleGoalAttempts.Add(1)
	start, err := in.Policy.EffectiveFrom(in.Now)
	if err != nil {
		return Candidate{}, err
	}
	if err := in.Dependencies.Validate(); err != nil {
		return Candidate{}, err
	}
	scope := in.Policy.Scope
	if scope.SourceAccountID != scope.DestinationAccountID || in.Dependencies.PolicyVersion != in.Policy.Version || in.GoalTarget.IsZero() || in.GoalAssigned.Cents() > in.GoalTarget.Cents() {
		return Candidate{}, ErrInput
	}
	snapshot := in.Ledger.Snapshot()
	if snapshot.UserID != scope.UserID || snapshot.Currency != scope.Currency || snapshot.AsOf.After(in.Now) {
		return Candidate{}, ErrInput
	}
	if err := in.Ledger.ValidateCashCoverage(in.Cash, in.Now); err != nil {
		return Candidate{}, err
	}
	var cash, owned, reserved funds.Money
	sourceFound := false
	for _, fact := range in.Cash {
		if fact.AccountID == scope.SourceAccountID {
			sourceFound = true
		}
		cash, err = cash.Add(fact.Balance)
		if err != nil {
			return Candidate{}, err
		}
		owned, err = owned.Add(fact.GoalOwned)
		if err != nil {
			return Candidate{}, err
		}
	}
	if !sourceFound || in.GoalAssigned.Cents() > owned.Cents() {
		return Candidate{}, ErrInput
	}
	for _, location := range snapshot.Locations {
		reserved, err = reserved.Add(location.Reserved)
		if err != nil {
			return Candidate{}, err
		}
	}
	unowned, err := cash.Sub(owned)
	if err != nil {
		return Candidate{}, err
	}
	unowned, err = unowned.Sub(reserved)
	if err != nil {
		return Candidate{}, ErrInput
	}
	gap := remaining(in.GoalTarget, in.GoalAssigned)
	monthlyMin, monthlyTarget, monthlyMax := in.Policy.MonthlyMin, in.Policy.MonthlyTarget, in.Policy.MonthlyMax
	// A zero monthly tuple is the explicit first-chain per-event cap mode.
	perEvent := monthlyMin.IsZero() && monthlyTarget.IsZero() && monthlyMax.IsZero()
	if perEvent {
		monthlyTarget, monthlyMax = in.Policy.MaxAmount, in.Policy.MaxAmount
	} else {
		zone, zoneErr := in.Policy.BusinessLocation()
		if zoneErr != nil || in.MonthPeriod != in.Now.In(zone).Format("2006-01") {
			return Candidate{}, ErrInput
		}
	}
	needMin := minimum(gap, remaining(monthlyMin, in.MonthContributed))
	target := minimum(gap, remaining(monthlyTarget, in.MonthContributed))
	maxMonth := minimum(gap, remaining(monthlyMax, in.MonthContributed))
	if perEvent {
		target, maxMonth = minimum(gap, in.Policy.MaxAmount), minimum(gap, in.Policy.MaxAmount)
	}
	protection := normalizedProtection(in.Protection)
	if !protection.Complete || protection.ObservedAt.IsZero() || protection.ObservedAt.After(snapshot.AsOf) || len(protection.Checkpoints) == 0 || len(protection.Checkpoints) > MaxProtectionCheckpoints || !validHash(protection.EvidenceHash) {
		return Candidate{}, ErrInput
	}
	protectedIDs := make(map[string]bool)
	safe := unowned
	liquidityRisk := false
	for _, point := range protection.Checkpoints {
		if point.ID == "" || len(point.ID) > 128 || protectedIDs[point.ID] || point.At.Before(protection.ObservedAt) || point.At.After(in.Now.AddDate(1, 0, 1)) || point.CurrentGoalMinimum.Cents() > needMin.Cents() {
			return Candidate{}, ErrInput
		}
		protectedIDs[point.ID] = true
		all, addErr := point.OtherProtected.Add(point.CurrentGoalMinimum)
		if addErr != nil {
			return Candidate{}, addErr
		}
		if all.Cents() > unowned.Cents() {
			liquidityRisk = true
		}
		// After contribution x, protection is other + x + max(min-x,0).
		// If the baseline is safe, its exact safe upper bound is cash-other.
		cap := remaining(unowned, point.OtherProtected)
		safe = minimum(safe, cap)
	}
	lots, err := in.Ledger.IncomeLots(in.Now)
	if err != nil {
		return Candidate{}, err
	}
	eligible := make([]funds.IncomeLot, 0, len(lots))
	var available funds.Money
	for _, lot := range lots {
		if lot.AccountID != scope.SourceAccountID || lot.Origin.Fact().OccurredAt.Before(start) {
			continue
		}
		eligible = append(eligible, lot)
		available, err = available.Add(lot.Available)
		if err != nil {
			return Candidate{}, err
		}
	}
	sort.Slice(eligible, func(i, j int) bool {
		a, b := eligible[i], eligible[j]
		if !a.Origin.Fact().OccurredAt.Equal(b.Origin.Fact().OccurredAt) {
			return a.Origin.Fact().OccurredAt.Before(b.Origin.Fact().OccurredAt)
		}
		if a.Origin.ID() != b.Origin.ID() {
			ai, bi := a.Origin.ID(), b.Origin.ID()
			return bytes.Compare(ai[:], bi[:]) < 0
		}
		return bytes.Compare(a.FragmentID[:], b.FragmentID[:]) < 0
	})
	amount := minimum(safe, available, target, maxMonth, gap, in.Policy.MaxAmount)
	result := Candidate{Algorithm: AlgorithmVersion, Kind: funds.AllocateGoal, PolicyID: in.Policy.ID, PolicyVersion: in.Policy.Version, PolicyHash: in.Policy.ConfigurationHash(), Scope: scope, Status: "READY", Amount: amount, MaxSafe: amount, EligibleIncome: available, EffectiveFrom: start.UTC(), PreparedAt: in.Now.UTC(), ValidUntil: in.Policy.ValidUntil.UTC(), Dependencies: in.Dependencies, Uses: []funds.IncomeUse{}}
	if liquidityRisk {
		result.Status = "LIQUIDITY_RISK"
		result.Amount, result.MaxSafe = funds.Money{}, funds.Money{}
	}
	if !liquidityRisk && amount.Cents() < needMin.Cents() {
		result.Status = "MINIMUM_SHORTFALL"
		result.MinimumShortfall, _ = needMin.Sub(amount)
		result.Amount = funds.Money{}
	}
	if result.Status == "READY" && result.Amount.IsZero() {
		result.Status = "NO_ACTION"
	}
	left := result.Amount
	for _, lot := range eligible {
		used := minimum(left, lot.Available)
		if used.IsZero() {
			continue
		}
		result.Uses = append(result.Uses, funds.IncomeUse{FragmentID: lot.FragmentID, OriginID: lot.Origin.ID(), AccountID: lot.AccountID, Amount: used})
		if result.EarliestIncomeAt.IsZero() {
			result.EarliestIncomeAt = lot.Origin.Fact().OccurredAt.UTC()
		}
		left, _ = left.Sub(used)
	}
	result.InputHash = inputHash(in, protection)
	result.EffectHash = result.effectHash()
	if !validHash(result.InputHash) || !validHash(result.EffectHash) {
		return Candidate{}, ErrInput
	}
	decoded, _ := hex.DecodeString(result.EffectHash)
	copy(result.ID[:], decoded[:16])
	result.ID[6] = (result.ID[6] & 0x0f) | 0x80 // UUIDv8: locally defined SHA-256-derived identity.
	result.ID[8] = (result.ID[8] & 0x3f) | 0x80
	return result, nil
}

func inputHash(in Input, p Protection) string {
	s := in.Ledger.Snapshot()
	facts := make([]funds.BankCreditFact, len(s.Origins))
	for i, origin := range s.Origins {
		f := origin.Fact()
		f.OccurredAt = f.OccurredAt.UTC()
		f.ObservedAt = f.ObservedAt.UTC()
		f.RecordedAt = f.RecordedAt.UTC()
		facts[i] = f
	}
	cash := append([]funds.CashLocationFact(nil), in.Cash...)
	for i := range cash {
		cash[i].ObservedAt = cash[i].ObservedAt.UTC()
	}
	sort.Slice(cash, func(i, j int) bool { return bytes.Compare(cash[i].AccountID[:], cash[j].AccountID[:]) < 0 })
	confirmation := in.Policy.Confirmation
	confirmation.ConfirmedAt = confirmation.ConfirmedAt.UTC()
	confirmation.ExpiresAt = confirmation.ExpiresAt.UTC()
	return hash(struct {
		Algorithm, Policy       string
		Confirmation            policy.ConfirmationSource
		AsOf, Now               time.Time
		User                    funds.ID
		Currency                funds.Currency
		Accounts                []funds.ID
		Origins                 []funds.BankCreditFact
		Locations               []funds.IncomeLocation
		Reservations            []funds.IncomeReservation
		Cash                    []funds.CashLocationFact
		Target, Assigned, Month funds.Money
		MonthPeriod             string
		Protection              Protection
		Dependencies            DependencyVector
	}{AlgorithmVersion, in.Policy.ConfigurationHash(), confirmation, s.AsOf.UTC(), in.Now.UTC(), s.UserID, s.Currency, s.ScopeAccountIDs, facts, s.Locations, s.Reservations, cash, in.GoalTarget, in.GoalAssigned, in.MonthContributed, in.MonthPeriod, p, in.Dependencies})
}

func (c Candidate) effectHash() string { c.ID = funds.ID{}; c.EffectHash = ""; return hash(c) }

// ValidateCandidate rejects accidental mutation and incomplete economic fields.
// A matching hash alone cannot attest server origin; T1 loads the saved input.
func (c Candidate) ValidateCandidate() error {
	if c.Algorithm != AlgorithmVersion || c.Kind != funds.AllocateGoal || c.Scope.SourceAccountID != c.Scope.DestinationAccountID || c.PolicyVersion == 0 || !validHash(c.InputHash) || !validHash(c.EffectHash) || c.EffectHash != c.effectHash() || c.PreparedAt.IsZero() || !c.ValidUntil.After(c.PreparedAt) {
		return ErrFrozenCandidate
	}
	if err := c.Scope.Validate(); err != nil {
		return err
	}
	if err := c.Dependencies.Validate(); err != nil {
		return err
	}
	if c.PolicyID == (funds.ID{}) || !validHash(c.PolicyHash) || c.Dependencies.PolicyVersion != c.PolicyVersion || c.Amount.Cents() > c.MaxSafe.Cents() || c.Amount.Cents() > c.EligibleIncome.Cents() || c.EffectiveFrom.IsZero() || c.EffectiveFrom.After(c.PreparedAt) {
		return ErrFrozenCandidate
	}
	switch c.Status {
	case "READY":
		if c.Amount.IsZero() || c.EarliestIncomeAt.Before(c.EffectiveFrom) || c.EarliestIncomeAt.After(c.PreparedAt) {
			return ErrFrozenCandidate
		}
	case "NO_ACTION", "MINIMUM_SHORTFALL", "LIQUIDITY_RISK":
		if !c.Amount.IsZero() || len(c.Uses) != 0 {
			return ErrFrozenCandidate
		}
	default:
		return ErrFrozenCandidate
	}
	decoded, _ := hex.DecodeString(c.EffectHash)
	var expectedID funds.ID
	copy(expectedID[:], decoded[:16])
	expectedID[6] = (expectedID[6] & 0x0f) | 0x80
	expectedID[8] = (expectedID[8] & 0x3f) | 0x80
	if c.ID != expectedID {
		return ErrFrozenCandidate
	}
	var total funds.Money
	seen := make(map[funds.ID]bool)
	for _, use := range c.Uses {
		if use.Amount.IsZero() || seen[use.FragmentID] || use.AccountID != c.Scope.SourceAccountID || use.FragmentID != funds.LocationID(use.OriginID, use.AccountID) {
			return ErrFrozenCandidate
		}
		seen[use.FragmentID] = true
		var err error
		total, err = total.Add(use.Amount)
		if err != nil {
			return err
		}
	}
	if total != c.Amount {
		return ErrFrozenCandidate
	}
	return nil
}

// Authorization is an immutable reference for T1, not a reusable T2 permit.
// A single-use source is consumed only by the atomic application transaction.
type Authorization struct {
	CandidateID   funds.ID  `json:"candidate_id"`
	EffectHash    string    `json:"effect_hash"`
	Kind          string    `json:"kind"`
	SourceID      funds.ID  `json:"source_id"`
	SourceVersion uint64    `json:"source_version"`
	ValidUntil    time.Time `json:"valid_until"`
	CheckedAt     time.Time `json:"checked_at"`
}

func checkCandidatePolicy(c Candidate, p policy.Policy, now time.Time) error {
	if err := c.ValidateCandidate(); err != nil {
		return err
	}
	if _, err := p.EffectiveFrom(now); err != nil {
		return err
	}
	if c.PolicyID != p.ID || c.PolicyVersion != p.Version || c.PolicyHash != p.ConfigurationHash() || c.Scope != p.Scope || c.Status != "READY" || c.Amount.IsZero() || c.Amount.Cents() > p.MaxAmount.Cents() || now.Before(c.PreparedAt) || !now.Before(c.ValidUntil) {
		return ErrAuthorization
	}
	return nil
}

func AuthorizeStanding(c Candidate, p policy.Policy, g policy.Grant, now time.Time) (Authorization, error) {
	if err := checkCandidatePolicy(c, p, now); err != nil {
		return Authorization{}, err
	}
	b, err := policy.CheckGrant(p, g, now)
	if err != nil {
		return Authorization{}, err
	}
	if c.Dependencies.GrantVersion != g.Version || c.Amount.Cents() > b.MaxAmount.Cents() || c.EarliestIncomeAt.Before(b.EffectiveFrom) {
		return Authorization{}, ErrAuthorization
	}
	return Authorization{c.ID, c.EffectHash, "STANDING_GRANT", g.ID, g.Version, b.ValidUntil.UTC(), now.UTC()}, nil
}

func AuthorizeOnce(c Candidate, p policy.Policy, source policy.ConfirmationSource, now time.Time) (Authorization, error) {
	if err := checkCandidatePolicy(c, p, now); err != nil {
		return Authorization{}, err
	}
	if err := source.Check(c.Scope, "PLAN", c.ID, 1, c.EffectHash, now); err != nil {
		return Authorization{}, err
	}
	if source.ExpiresAt.IsZero() || !source.ExpiresAt.After(source.ConfirmedAt) || !now.Before(source.ExpiresAt) || source.ConfirmedAt.Before(c.PreparedAt) {
		return Authorization{}, ErrAuthorization
	}
	end := c.ValidUntil
	if source.ExpiresAt.Before(end) {
		end = source.ExpiresAt
	}
	return Authorization{c.ID, c.EffectHash, "SINGLE_USE", source.ID, 1, end.UTC(), now.UTC()}, nil
}
