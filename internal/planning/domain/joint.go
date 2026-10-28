package domain

import (
	"errors"
	"sort"
	"time"

	funds "zhiyu.local/zhiyu-go/internal/funds/domain"
	policy "zhiyu.local/zhiyu-go/internal/policy/domain"
)

const JointAlgorithm = "joint-hall-affine-box-go-v1"
const JointProtectedAlgorithm = "joint-point-protection-go-v2"

var (
	ErrJointInput    = errors.New("JOINT_INPUT_INCOMPLETE")
	ErrJointProgress = errors.New("JOINT_ORIGINAL_RESULT_MISMATCH")
	errJointCapacity = errors.New("JOINT_SOLVER_CAPACITY")
)

type JointGoal struct {
	Version policy.TemplateVersion  `json:"version"`
	Goal    policy.TemplateGoalFact `json:"goal"`
}

// Available is a CURRENT-cash envelope after immutable non-contribution
// protections, never a future-income balance. Its scoped collector proves it.
type JointProtectionPoint struct {
	ID         string                `json:"id"`
	At         time.Time             `json:"at"`
	Available  funds.Money           `json:"available_cents"`
	Deficit    bool                  `json:"deficit"`
	SourceHash string                `json:"source_hash"`
	GoalTerms  []JointGoalProtection `json:"goal_terms,omitempty"`
}
type JointInput struct {
	Scope      policy.TemplateOwnerScope
	Now        time.Time
	Timezone   string
	Ledger     funds.IncomeLedger
	Cash       []funds.CashLocationFact
	Goals      []JointGoal
	Protection []JointProtectionPoint
	// V2 consumes the full same-read ForecastInput. It derives per-point
	// replacement floors itself; callers must not remove selected policies.
	ProtectionInput  *ForecastInput
	Complete         bool
	InventoryHash    string
	Dependencies     DependencyVector
	SolverNodeBudget int
	// BudgetCap is an additional authority envelope. It never changes the
	// original cash/source/protection facts. Nil preserves the old protocol.
	BudgetCap *funds.Money `json:",omitempty"`
}
type JointIncomeUse struct {
	GoalID funds.ID        `json:"goal_id"`
	Use    funds.IncomeUse `json:"use"`
}
type JointAllocation struct {
	GoalID              funds.ID    `json:"goal_id"`
	VersionID           funds.ID    `json:"version_id"`
	Amount              funds.Money `json:"amount_cents"`
	ProjectedOwned      funds.Money `json:"projected_owned_cents"`
	MinimumShortfall    funds.Money `json:"minimum_shortfall_cents"`
	DelayLowerBoundDays int64       `json:"delay_lower_bound_days"`
	DelayCensored       bool        `json:"delay_censored"`
	CompletionDate      *string     `json:"completion_date,omitempty"`
}
type JointChild struct {
	Number               int               `json:"number"`
	GoalID               funds.ID          `json:"goal_id"`
	PolicyID             funds.ID          `json:"policy_id"`
	VersionID            funds.ID          `json:"version_id"`
	SourceAccountID      funds.ID          `json:"source_account_id"`
	DestinationAccountID funds.ID          `json:"destination_account_id"`
	Amount               funds.Money       `json:"amount_cents"`
	Uses                 []funds.IncomeUse `json:"uses"`
	EffectHash           string            `json:"effect_hash"`
}
type JointPlan struct {
	Algorithm      string            `json:"algorithm"`
	InputHash      string            `json:"input_hash"`
	DependencyHash string            `json:"dependency_hash"`
	EffectHash     string            `json:"effect_hash"`
	Status         string            `json:"status"`
	Budget         funds.Money       `json:"budget_cents"`
	Objective      *[8]int64         `json:"objective,omitempty"`
	Allocations    []JointAllocation `json:"allocations"`
	Uses           []JointIncomeUse  `json:"uses"`
	Children       []JointChild      `json:"children"`
	VisitedNodes   int               `json:"visited_nodes"`
	Reasons        []string          `json:"reasons"`
	BankAuthority  bool              `json:"bank_authority"`
}
type jointGoal struct {
	input                                 JointGoal
	config                                *policy.LongTermGoalConfig
	active                                bool
	start                                 time.Time
	low, high, minimum, target, remaining int64
}
type jointEdge struct {
	account funds.ID
	goal    int
}
type jointCounter struct{ used, limit int }

func (c *jointCounter) visit() error {
	if c.used >= c.limit {
		return errJointCapacity
	}
	c.used++
	return nil
}
func jointMax(a, b int64) int64 {
	if a > b {
		return a
	}
	return b
}
func jointMin(a, b int64) int64 {
	if a < b {
		return a
	}
	return b
}
func jointCompare(a, b []int64) int {
	for i := range a {
		if a[i] < b[i] {
			return -1
		}
		if a[i] > b[i] {
			return 1
		}
	}
	return 0
}
func jointDelay(g jointGoal, amount int64, today string) (int64, bool, *string) {
	if g.remaining == 0 {
		return 0, false, nil
	}
	d, _ := policy.TemplateDate(today)
	deadline, _ := policy.TemplateDate(g.config.Deadline)
	if amount == g.remaining {
		days := (d.Unix() - deadline.Unix()) / 86400
		if days < 0 {
			days = 0
		}
		return days, false, &today
	}
	days := (d.AddDate(0, 0, 1).Unix() - deadline.Unix()) / 86400
	if days < 0 {
		days = 0
	}
	return days, true, nil
}
func jointScore(goals []jointGoal, values []int64, today string) [7]int64 {
	var score [7]int64
	for i, g := range goals {
		if !g.active {
			continue
		}
		short := jointMax(0, g.minimum-values[i])
		score[2] += short
		score[3] += int64(g.config.Importance) * short
		days, _, _ := jointDelay(g, values[i], today)
		score[4] += days
		delta := g.target - values[i]
		if delta < 0 {
			delta = -delta
		}
		score[5] += delta
	}
	return score
}
func jointFeasible(values, ranks []int64) bool {
	for mask, capacity := range ranks {
		var total int64
		for i, value := range values {
			if mask&(1<<i) != 0 {
				total += value
			}
		}
		if total > capacity {
			return false
		}
	}
	return true
}
func jointRanks(lots []funds.IncomeLot, goals []jointGoal, edges map[jointEdge]bool, budget int64, counter *jointCounter) ([]int64, error) {
	masks := make([]int, len(lots))
	for l, lot := range lots {
		for g, goal := range goals {
			if edges[jointEdge{lot.AccountID, g}] && !lot.Origin.Fact().OccurredAt.Before(goal.start) {
				masks[l] |= 1 << g
			}
		}
	}
	ranks := make([]int64, 1<<len(goals))
	for mask := 1; mask < len(ranks); mask++ {
		if e := counter.visit(); e != nil {
			return nil, e
		}
		var n int64
		for i, lot := range lots {
			if masks[i]&mask != 0 {
				n += lot.Available.Cents()
				if n >= budget {
					n = budget
					break
				}
			}
		}
		ranks[mask] = n
	}
	return ranks, nil
}

type jointRegion struct{ low, high int64 }

func jointRegions(g jointGoal) []jointRegion {
	if g.low > g.high {
		return nil
	}
	cuts := []int64{g.low, g.high}
	for _, cut := range []int64{g.minimum, g.target} {
		if cut > g.low && cut < g.high {
			cuts = append(cuts, cut)
		}
	}
	sort.Slice(cuts, func(i, j int) bool { return cuts[i] < cuts[j] })
	unique := cuts[:0]
	for _, cut := range cuts {
		if len(unique) == 0 || unique[len(unique)-1] != cut {
			unique = append(unique, cut)
		}
	}
	regions := []jointRegion{}
	if len(unique) == 1 {
		return []jointRegion{{unique[0], unique[0]}}
	}
	for i := 1; i < len(unique); i++ {
		regions = append(regions, jointRegion{unique[i-1], unique[i]})
	}
	if g.high == g.remaining && g.high > g.low {
		last := regions[len(regions)-1]
		regions = regions[:len(regions)-1]
		if last.low <= last.high-1 {
			regions = append(regions, jointRegion{last.low, last.high - 1})
		}
		regions = append(regions, jointRegion{g.high, g.high})
	}
	return regions
}

type jointOptimum struct {
	score  [7]int64
	values []int64
}

func jointBest(lots []funds.IncomeLot, goals []jointGoal, edges map[jointEdge]bool, budget int64, today string, counter *jointCounter) (*jointOptimum, error) {
	ranks, err := jointRanks(lots, goals, edges, budget, counter)
	if err != nil {
		return nil, err
	}
	lower := make([]int64, len(goals))
	targets := make([]int64, len(goals))
	targetValid := true
	for i, g := range goals {
		if g.low > g.high {
			return nil, nil
		}
		lower[i] = g.low
		targets[i] = g.target
		if targets[i] < g.low || targets[i] > g.high {
			targetValid = false
		}
	}
	if !jointFeasible(lower, ranks) {
		return nil, nil
	}
	if targetValid && jointFeasible(targets, ranks) && jointScore(goals, targets, today) == ([7]int64{}) {
		return &jointOptimum{values: targets}, nil
	}
	regions := make([][]jointRegion, len(goals))
	for i, g := range goals {
		regions[i] = jointRegions(g)
	}
	box := make([]jointRegion, len(goals))
	var best *jointOptimum
	var visit func(int) error
	visit = func(index int) error {
		if index < len(goals) {
			for _, r := range regions[index] {
				box[index] = r
				if e := visit(index + 1); e != nil {
					return e
				}
			}
			return nil
		}
		if e := counter.visit(); e != nil {
			return e
		}
		values := make([]int64, len(goals))
		for i, r := range box {
			values[i] = r.low
		}
		if !jointFeasible(values, ranks) {
			return nil
		}
		base := jointScore(goals, values, today)
		type marginal struct {
			delta [7]int64
			index int
		}
		costs := []marginal{}
		for i, r := range box {
			if r.low == r.high {
				continue
			}
			if e := counter.visit(); e != nil {
				return e
			}
			values[i]++
			next := jointScore(goals, values, today)
			values[i]--
			var delta [7]int64
			for k := range delta {
				delta[k] = next[k] - base[k]
			}
			if jointCompare(delta[:], make([]int64, 7)) < 0 {
				costs = append(costs, marginal{delta, i})
			}
		}
		sort.Slice(costs, func(i, j int) bool {
			cmp := jointCompare(costs[i].delta[:], costs[j].delta[:])
			if cmp != 0 {
				return cmp < 0
			}
			return costs[i].index > costs[j].index
		})
		for _, cost := range costs {
			if e := counter.visit(); e != nil {
				return e
			}
			i := cost.index
			cap := box[i].high
			for mask, rank := range ranks {
				if mask&(1<<i) == 0 {
					continue
				}
				var others int64
				for j, value := range values {
					if j != i && mask&(1<<j) != 0 {
						others += value
					}
				}
				cap = jointMin(cap, rank-others)
			}
			values[i] = cap
		}
		score := jointScore(goals, values, today)
		if best == nil || jointCompare(score[:], best.score[:]) < 0 || (score == best.score && jointCompare(values, best.values) < 0) {
			best = &jointOptimum{score, append([]int64(nil), values...)}
		}
		return nil
	}
	err = visit(0)
	return best, err
}

// jointMatching materializes Hall-feasible amounts with deterministic integer
// augmenting paths. A fragment's capacity is shared by every eligible goal.
func jointMatching(lots []funds.IncomeLot, goals []jointGoal, edges map[jointEdge]bool, values []int64, counter *jointCounter) ([]JointIncomeUse, error) {
	sink := 1 + len(lots) + len(goals)
	residual := make([][]int64, sink+1)
	for i := range residual {
		residual[i] = make([]int64, sink+1)
	}
	for l, lot := range lots {
		residual[0][l+1] = lot.Available.Cents()
		for g, goal := range goals {
			if edges[jointEdge{lot.AccountID, g}] && !lot.Origin.Fact().OccurredAt.Before(goal.start) {
				residual[l+1][1+len(lots)+g] = values[g]
			}
		}
	}
	var expected int64
	for g, value := range values {
		residual[1+len(lots)+g][sink] = value
		expected += value
	}
	var sent int64
	for {
		if e := counter.visit(); e != nil {
			return nil, e
		}
		parents := make([]int, sink+1)
		for i := range parents {
			parents[i] = -1
		}
		parents[0] = 0
		queue := []int{0}
		for len(queue) > 0 && parents[sink] < 0 {
			node := queue[0]
			queue = queue[1:]
			for next := 0; next <= sink; next++ {
				if parents[next] < 0 && residual[node][next] > 0 {
					parents[next] = node
					queue = append(queue, next)
				}
			}
		}
		if parents[sink] < 0 {
			break
		}
		amount := int64(funds.MaxMoneyCents)
		for node := sink; node != 0; node = parents[node] {
			amount = jointMin(amount, residual[parents[node]][node])
		}
		for node := sink; node != 0; node = parents[node] {
			prior := parents[node]
			residual[prior][node] -= amount
			residual[node][prior] += amount
		}
		sent += amount
	}
	if sent != expected {
		return nil, ErrJointInput
	}
	uses := []JointIncomeUse{}
	for l, lot := range lots {
		for g, goal := range goals {
			amount := residual[1+len(lots)+g][l+1]
			if amount > 0 {
				money, _ := funds.NewMoney(amount)
				uses = append(uses, JointIncomeUse{goal.input.Goal.ID, funds.IncomeUse{FragmentID: lot.FragmentID, OriginID: lot.Origin.ID(), AccountID: lot.AccountID, Amount: money}})
			}
		}
	}
	return uses, nil
}

// SolveJoint is exact within its declared finite capacity. Exhaustion returns
// UNKNOWN with no allocations/uses/children; it never returns a greedy fallback.
func SolveJoint(in JointInput) (JointPlan, error) {
	solveJointAttempts.Add(1)
	result := JointPlan{Algorithm: JointAlgorithm, Status: "UNKNOWN", Allocations: []JointAllocation{}, Uses: []JointIncomeUse{}, Children: []JointChild{}, Reasons: []string{}}
	zone, err := policy.TemplateLocation(in.Timezone)
	if err != nil || in.Now.IsZero() || !in.Complete || !validHash(in.InventoryHash) || in.Scope.EnvironmentID == (funds.ID{}) || in.Scope.UserID == (funds.ID{}) || in.Dependencies.Validate() != nil || in.Ledger.Validate() != nil || in.Ledger.Snapshot().UserID != in.Scope.UserID || in.Ledger.ValidateCashCoverage(in.Cash, in.Now) != nil {
		return result, ErrJointInput
	}
	if len(in.Goals) < 2 || len(in.Goals) > 8 {
		if in.ProtectionInput != nil {
			result.Algorithm = JointProtectedAlgorithm
		}
		result.Reasons = append(result.Reasons, "DECLARED_DOMAIN_CAPACITY_EXCEEDED")
		return result, nil
	}
	if in.ProtectionInput != nil {
		result.Algorithm = JointProtectedAlgorithm
		in.Protection, err = jointBindProtection(in)
		if err != nil {
			return result, err
		}
	} else {
		for _, point := range in.Protection {
			if len(point.GoalTerms) != 0 {
				return result, ErrJointInput
			}
		}
	}
	if len(in.Protection) < 1 || len(in.Protection) > 1098 {
		result.Reasons = append(result.Reasons, "DECLARED_DOMAIN_CAPACITY_EXCEEDED")
		return result, nil
	}
	if in.SolverNodeBudget == 0 {
		in.SolverNodeBudget = 200000
	}
	if in.SolverNodeBudget < 1 || in.SolverNodeBudget > 1000000 {
		return result, ErrJointInput
	}
	counter := &jointCounter{limit: in.SolverNodeBudget}
	lots, err := in.Ledger.IncomeLots(in.Now)
	if err != nil {
		return result, ErrJointInput
	}
	if len(lots) > 128 {
		result.Reasons = append(result.Reasons, "INCOME_FRAGMENT_CAPACITY_EXCEEDED")
		return result, nil
	}
	sort.Slice(lots, func(i, j int) bool { return lots[i].FragmentID.String() < lots[j].FragmentID.String() })
	var total funds.Money
	for _, lot := range lots {
		total, err = total.Add(lot.Available)
		if err != nil {
			return result, ErrJointInput
		}
	}
	budget := total.Cents()
	if in.BudgetCap != nil {
		budget = jointMin(budget, in.BudgetCap.Cents())
	}
	pointIDs := map[string]bool{}
	points := append([]JointProtectionPoint(nil), in.Protection...)
	for i, p := range points {
		if p.ID == "" || pointIDs[p.ID] || p.At.Before(in.Now) || p.At.After(in.Now.AddDate(1, 0, 1)) || !validHash(p.SourceHash) {
			return result, ErrJointInput
		}
		pointIDs[p.ID] = true
		points[i].At = p.At.UTC()
		if p.Deficit {
			result.Status = "INFEASIBLE"
			result.Reasons = append(result.Reasons, "IMMUTABLE_HARD_PROTECTION_DEFICIT")
			return result, nil
		}
		budget = jointMin(budget, p.Available.Cents())
	}
	sort.Slice(points, func(i, j int) bool { return points[i].ID < points[j].ID })
	result.Budget, _ = funds.NewMoney(budget)
	in.Goals = append([]JointGoal(nil), in.Goals...)
	sort.Slice(in.Goals, func(i, j int) bool { return in.Goals[i].Goal.ID.String() < in.Goals[j].Goal.ID.String() })
	goals := []jointGoal{}
	seenGoals := map[funds.ID]bool{}
	seenPolicies := map[funds.ID]bool{}
	selectedOwned := map[funds.ID]funds.Money{}
	today := in.Now.In(zone).Format("2006-01-02")
	if today == "9999-12-31" {
		return result, ErrJointInput
	}
	for i, raw := range in.Goals {
		v, g := raw.Version, raw.Goal
		if v.Scope != in.Scope || g.ID == (funds.ID{}) || seenGoals[g.ID] || seenPolicies[v.PolicyID] || !g.Verified || g.PolicyID != v.PolicyID || g.VersionID != v.VersionID || g.CashOwned.Cents() > g.Owned.Cents() {
			return result, ErrJointInput
		}
		seenGoals[g.ID] = true
		seenPolicies[v.PolicyID] = true
		state, e := v.EffectiveState(in.Now, in.Timezone)
		if e != nil || state == "CONFIRMATION_IN_FUTURE" {
			return result, ErrJointInput
		}
		decoded, e := v.Compiled.Decode()
		if e != nil {
			return result, ErrJointInput
		}
		config, ok := decoded.(*policy.LongTermGoalConfig)
		if !ok {
			return result, ErrJointInput
		}
		start, _, e := policy.TemplateValidity(v.Compiled, v.ConfirmedAt, in.Timezone)
		if e != nil {
			return result, ErrJointInput
		}
		if start.Before(v.ConfirmedAt) {
			start = v.ConfirmedAt
		}
		active := state == "ACTIVE"
		if active && g.MonthPeriod != in.Now.In(zone).Format("2006-01") {
			return result, ErrJointInput
		}
		accountKnown := false
		for _, cash := range in.Cash {
			if cash.AccountID == g.AccountID {
				accountKnown = true
			}
		}
		if !accountKnown {
			return result, ErrJointInput
		}
		selectedOwned[g.AccountID], err = selectedOwned[g.AccountID].Add(g.CashOwned)
		if err != nil {
			return result, ErrJointInput
		}
		for _, fact := range in.Cash {
			if fact.AccountID == g.AccountID && selectedOwned[g.AccountID].Cents() > fact.GoalOwned.Cents() {
				return result, ErrJointInput
			}
		}
		remaining := jointMax(0, config.Target.Cents()-g.Owned.Cents())
		g.GoalVersion = nil
		v.ConfirmedAt = v.ConfirmedAt.UTC()
		in.Goals[i] = JointGoal{v, g}
		goal := jointGoal{input: in.Goals[i], config: config, active: active, start: start, remaining: remaining}
		if active {
			goal.low = jointMax(0, config.MinimumGuarantee.Cents()-g.Owned.Cents())
			if config.Deadline <= today && !config.AllowPartial && !config.AllowDeferral {
				goal.low = jointMax(goal.low, remaining)
			}
			goal.high = jointMin(remaining, jointMax(0, config.Monthly.Max.Cents()-g.MonthContributed.Cents()))
			goal.minimum = jointMin(remaining, jointMax(0, config.Monthly.Min.Cents()-g.MonthContributed.Cents()))
			goal.target = jointMin(remaining, jointMax(0, config.Monthly.Target.Cents()-g.MonthContributed.Cents()))
		}
		goals = append(goals, goal)
	}
	snapshot := in.Ledger.Snapshot()
	facts := make([]funds.BankCreditFact, 0, len(snapshot.Origins))
	for _, origin := range snapshot.Origins {
		f := origin.Fact()
		f.OccurredAt = f.OccurredAt.UTC()
		f.ObservedAt = f.ObservedAt.UTC()
		f.RecordedAt = f.RecordedAt.UTC()
		facts = append(facts, f)
	}
	cash := append([]funds.CashLocationFact(nil), in.Cash...)
	for i := range cash {
		cash[i].ObservedAt = cash[i].ObservedAt.UTC()
	}
	sort.Slice(cash, func(i, j int) bool { return cash[i].AccountID.String() < cash[j].AccountID.String() })
	result.DependencyHash = hash(in.Dependencies)
	result.InputHash = hash(struct {
		Scope                   policy.TemplateOwnerScope
		Now                     time.Time
		Timezone, InventoryHash string
		Origins                 []funds.BankCreditFact
		LedgerAsOf              time.Time
		Locations               []funds.IncomeLocation
		Reservations            []funds.IncomeReservation
		Cash                    []funds.CashLocationFact
		Goals                   []JointGoal
		Protection              []JointProtectionPoint
		Dependencies            DependencyVector
		SolverNodeBudget        int
		BudgetCap               *funds.Money `json:",omitempty"`
	}{in.Scope, in.Now.UTC(), in.Timezone, in.InventoryHash, facts, snapshot.AsOf.UTC(), snapshot.Locations, snapshot.Reservations, cash, in.Goals, points, in.Dependencies, in.SolverNodeBudget, in.BudgetCap})
	edges := map[jointEdge]bool{}
	for _, lot := range lots {
		if lot.Available.IsZero() {
			continue
		}
		for g, goal := range goals {
			if goal.active && !lot.Origin.Fact().OccurredAt.Before(goal.start) {
				edges[jointEdge{lot.AccountID, g}] = true
			}
		}
	}
	best := func(allowed map[jointEdge]bool) (*jointOptimum, error) {
		if in.ProtectionInput != nil {
			return jointBestProtected(lots, goals, allowed, budget, today, points, counter)
		}
		return jointBest(lots, goals, allowed, budget, today, counter)
	}
	optimum, err := best(edges)
	finishUnknown := func() (JointPlan, error) {
		result.VisitedNodes = counter.used
		result.Reasons = append(result.Reasons, "EXACT_SOLVER_CAPACITY_EXCEEDED_NO_ACTIONABLE_AMOUNTS")
		return result, nil
	}
	if errors.Is(err, errJointCapacity) {
		return finishUnknown()
	}
	if err != nil {
		return result, err
	}
	if optimum == nil {
		result.Status = "INFEASIBLE"
		result.VisitedNodes = counter.used
		result.Reasons = append(result.Reasons, "NO_FEASIBLE_CURRENT_PERIOD_ALLOCATION")
		return result, nil
	}
	zero := map[jointEdge]bool{}
	paid := []jointEdge{}
	for edge := range edges {
		if edge.account == goals[edge.goal].input.Goal.AccountID {
			zero[edge] = true
		} else {
			paid = append(paid, edge)
		}
	}
	sort.Slice(paid, func(i, j int) bool {
		if paid[i].account != paid[j].account {
			return paid[i].account.String() < paid[j].account.String()
		}
		return paid[i].goal < paid[j].goal
	})
	var chosen *jointOptimum
	var chosenEdges map[jointEdge]bool
	for count := 0; count <= len(paid) && chosen == nil; count++ {
		selected := map[jointEdge]bool{}
		for edge := range zero {
			selected[edge] = true
		}
		var enumerate func(int, int) error
		enumerate = func(start, left int) error {
			if e := counter.visit(); e != nil {
				return e
			}
			if left == 0 {
				candidate, e := best(selected)
				if e != nil {
					return e
				}
				if candidate != nil && candidate.score == optimum.score {
					chosen = candidate
					chosenEdges = map[jointEdge]bool{}
					for edge := range selected {
						chosenEdges[edge] = true
					}
				}
				return nil
			}
			for i := start; i <= len(paid)-left; i++ {
				selected[paid[i]] = true
				if e := enumerate(i+1, left-1); e != nil {
					return e
				}
				delete(selected, paid[i])
				if chosen != nil {
					return nil
				}
			}
			return nil
		}
		err = enumerate(0, count)
		if errors.Is(err, errJointCapacity) {
			return finishUnknown()
		}
		if err != nil {
			return result, err
		}
	}
	if chosen == nil {
		return result, ErrJointInput
	}
	uses, err := jointMatching(lots, goals, chosenEdges, chosen.values, counter)
	if errors.Is(err, errJointCapacity) {
		return finishUnknown()
	}
	if err != nil {
		return result, err
	}
	result.Status = "OPTIMAL"
	result.VisitedNodes = counter.used
	result.Uses = uses
	objective := [8]int64{}
	copy(objective[:7], chosen.score[:])
	movement := map[jointEdge]bool{}
	for i, g := range goals {
		amount, _ := funds.NewMoney(chosen.values[i])
		owned, e := g.input.Goal.Owned.Add(amount)
		if e != nil {
			return JointPlan{}, ErrJointInput
		}
		short, _ := funds.NewMoney(jointMax(0, g.minimum-amount.Cents()))
		days, censored, completed := jointDelay(g, amount.Cents(), today)
		result.Allocations = append(result.Allocations, JointAllocation{g.input.Goal.ID, g.input.Version.VersionID, amount, owned, short, days, censored, completed})
		byAccount := map[funds.ID][]funds.IncomeUse{}
		for _, use := range uses {
			if use.GoalID == g.input.Goal.ID {
				byAccount[use.Use.AccountID] = append(byAccount[use.Use.AccountID], use.Use)
				if use.Use.AccountID != g.input.Goal.AccountID {
					movement[jointEdge{use.Use.AccountID, i}] = true
				}
			}
		}
		accounts := []funds.ID{}
		for account := range byAccount {
			accounts = append(accounts, account)
		}
		sort.Slice(accounts, func(i, j int) bool { return accounts[i].String() < accounts[j].String() })
		for _, account := range accounts {
			child := JointChild{Number: len(result.Children) + 1, GoalID: g.input.Goal.ID, PolicyID: g.input.Version.PolicyID, VersionID: g.input.Version.VersionID, SourceAccountID: account, DestinationAccountID: g.input.Goal.AccountID, Uses: byAccount[account]}
			for _, use := range child.Uses {
				child.Amount, _ = child.Amount.Add(use.Amount)
			}
			child.EffectHash = hash(child)
			result.Children = append(result.Children, child)
		}
	}
	objective[7] = int64(len(movement))
	result.Objective = &objective
	result.Reasons = append(result.Reasons, "EXACT_CURRENT_PERIOD_LEXICOGRAPHIC_OPTIMUM", "UNFINISHED_DELAY_IS_CENSORED", "CURRENT_ORIGIN_ONLY_NO_FORECAST_OR_NEW_INCOME", "SERIAL_CHILDREN_REQUIRE_SEPARATE_FINANCIAL_AUTHORITY")
	result.EffectHash = hash(result)
	return result, nil
}

type JointChildResult struct {
	Number      int         `json:"number"`
	OperationID funds.ID    `json:"operation_id"`
	BankKey     string      `json:"bank_key"`
	State       string      `json:"state"`
	EffectHash  string      `json:"effect_hash"`
	ReceiptID   *funds.ID   `json:"receipt_id,omitempty"`
	Amount      funds.Money `json:"amount_cents"`
}
type JointProgress struct {
	State               string      `json:"state"`
	SettledChildren     int         `json:"settled_children"`
	SettledAmount       funds.Money `json:"settled_amount_cents"`
	NextChild           *int        `json:"next_child,omitempty"`
	OriginalOperationID *funds.ID   `json:"original_operation_id,omitempty"`
	OriginalBankKey     string      `json:"original_bank_key,omitempty"`
	BankAuthority       bool        `json:"bank_authority"`
}

// AdvanceJoint never retries or replaces a bank key. A partially settled joint
// plan remains partial; UNKNOWN and every nonterminal state block its suffix.
func AdvanceJoint(plan JointPlan, originals []JointChildResult) (JointProgress, error) {
	r := JointProgress{State: "READY_NEXT"}
	if plan.Status != "OPTIMAL" || !validHash(plan.InputHash) || !validHash(plan.DependencyHash) || plan.BankAuthority || len(originals) > len(plan.Children) {
		return r, ErrJointProgress
	}
	frozenPlan := plan
	frozenPlan.EffectHash = ""
	if !validHash(plan.EffectHash) || hash(frozenPlan) != plan.EffectHash {
		return r, ErrJointProgress
	}
	byNumber := map[int]JointChildResult{}
	operations := map[funds.ID]bool{}
	keys := map[string]bool{}
	for _, o := range originals {
		if o.Number < 1 || o.Number > len(plan.Children) || byNumber[o.Number].Number != 0 || o.OperationID == (funds.ID{}) || operations[o.OperationID] || o.BankKey == "" || keys[o.BankKey] {
			return r, ErrJointProgress
		}
		byNumber[o.Number] = o
		operations[o.OperationID] = true
		keys[o.BankKey] = true
	}
	for i, child := range plan.Children {
		if child.Number != i+1 || child.Amount.IsZero() || !validHash(child.EffectHash) {
			return r, ErrJointProgress
		}
		frozen := child
		frozen.EffectHash = ""
		if hash(frozen) != child.EffectHash {
			return r, ErrJointProgress
		}
		o, found := byNumber[child.Number]
		if !found {
			for n := range byNumber {
				if n > child.Number {
					return r, ErrJointProgress
				}
			}
			next := child.Number
			r.NextChild = &next
			return r, nil
		}
		if o.EffectHash != child.EffectHash || o.Amount != child.Amount {
			return r, ErrJointProgress
		}
		switch o.State {
		case "SETTLED":
			if o.ReceiptID == nil || *o.ReceiptID == (funds.ID{}) {
				return r, ErrJointProgress
			}
			r.SettledChildren++
			var e error
			r.SettledAmount, e = r.SettledAmount.Add(child.Amount)
			if e != nil {
				return r, ErrJointProgress
			}
		case "QUEUED", "SUBMITTING", "PENDING_SETTLEMENT", "UNKNOWN", "RECONCILING", "REJECTED", "CANCELLED":
			for n := range byNumber {
				if n > child.Number {
					return r, ErrJointProgress
				}
			}
			id := o.OperationID
			r.OriginalOperationID = &id
			r.OriginalBankKey = o.BankKey
			r.State = "BLOCKED_" + o.State
			return r, nil
		default:
			return r, ErrJointProgress
		}
	}
	r.State = "SETTLED"
	return r, nil
}

type PairedGoalTransferInput struct {
	Policy              policy.TemplateVersion
	Source              policy.TemplateGoalFact
	Target              policy.TemplateGoalFact
	Amount              funds.Money
	AlreadyUsedAndHeld  funds.Money
	UsageVerified       bool
	ProtectedReferences []policy.TemplatePolicyReference
	Now                 time.Time
	Timezone            string
	DependencyHash      string
}
type PairedGoalTransfer struct {
	Protocol            string                    `json:"protocol"`
	Scope               policy.TemplateOwnerScope `json:"scope"`
	PolicyID            funds.ID                  `json:"policy_id"`
	PolicyVersionID     funds.ID                  `json:"policy_version_id"`
	SourceGoalID        funds.ID                  `json:"source_goal_id"`
	TargetGoalID        funds.ID                  `json:"target_goal_id"`
	SourceAccountID     funds.ID                  `json:"source_account_id"`
	TargetAccountID     funds.ID                  `json:"target_account_id"`
	SourceGoalVersionID funds.ID                  `json:"source_goal_version_id"`
	TargetGoalVersionID funds.ID                  `json:"target_goal_version_id"`
	Amount              funds.Money               `json:"amount_cents"`
	DependencyHash      string                    `json:"dependency_hash"`
	EffectHash          string                    `json:"effect_hash"`
	CreatesIncome       bool                      `json:"creates_income"`
	BankAuthority       bool                      `json:"bank_authority"`
}
type PairedGoalConsent struct {
	ID                 funds.ID
	Scope              policy.TemplateOwnerScope
	Role               string
	PrincipalKind      string
	PolicyID           funds.ID
	PolicyVersionID    funds.ID
	SourceGoalID       funds.ID
	TargetGoalID       funds.ID
	Amount             funds.Money
	ReviewedEffectHash string
	ConfirmedAt        time.Time
	ValidUntil         time.Time
	Current            bool
	Verified           bool
}

// PreviewPairedGoalTransfer requires the explicit paired scope; a Cash grant or
// a model preference cannot be promoted into either side of a goal release.
func PreviewPairedGoalTransfer(in PairedGoalTransferInput) (PairedGoalTransfer, error) {
	if !in.UsageVerified || !validHash(in.DependencyHash) || in.Amount.IsZero() || in.Source.GoalVersion == nil || in.Target.GoalVersion == nil {
		return PairedGoalTransfer{}, ErrAuthorization
	}
	decoded, err := in.Policy.Compiled.Decode()
	if err != nil {
		return PairedGoalTransfer{}, ErrAuthorization
	}
	config, ok := decoded.(*policy.CrossGoalReallocationConfig)
	if !ok || config.ScopeVersion != "GOAL_TRANSFER_V1" || config.DestinationScope != "GOAL" || !config.Enabled {
		return PairedGoalTransfer{}, ErrAuthorization
	}
	state, err := in.Policy.EffectiveState(in.Now, in.Timezone)
	if err != nil || state != "ACTIVE" || in.Source.ID == in.Target.ID || in.Source.AccountID == in.Target.AccountID || in.Source.AccountID == (funds.ID{}) || in.Target.AccountID == (funds.ID{}) {
		return PairedGoalTransfer{}, ErrAuthorization
	}
	allowed := func(ids []funds.ID, id funds.ID) bool {
		for _, v := range ids {
			if v == id {
				return true
			}
		}
		return false
	}
	if !allowed(config.SourceGoalIDs, in.Source.ID) || !allowed(config.TargetGoalIDs, in.Target.ID) || in.Amount.Cents() > config.SingleActionCap.Cents() || in.AlreadyUsedAndHeld.Cents() > config.TotalCap.Cents() || in.Amount.Cents() > config.TotalCap.Cents()-in.AlreadyUsedAndHeld.Cents() {
		return PairedGoalTransfer{}, ErrAuthorization
	}
	for _, goal := range []policy.TemplateGoalFact{in.Source, in.Target} {
		v := goal.GoalVersion
		if !goal.Verified || goal.ID == (funds.ID{}) || goal.CashOwned.Cents() > goal.Owned.Cents() || goal.ReleaseableCash.Cents() > goal.CashOwned.Cents() || v.Scope != in.Policy.Scope || goal.PolicyID != v.PolicyID || goal.VersionID != v.VersionID {
			return PairedGoalTransfer{}, ErrAuthorization
		}
		s, e := v.EffectiveState(in.Now, in.Timezone)
		if e != nil || s != "ACTIVE" {
			return PairedGoalTransfer{}, ErrAuthorization
		}
		c, e := v.Compiled.Decode()
		if e != nil {
			return PairedGoalTransfer{}, ErrAuthorization
		}
		if _, ok := c.(*policy.LongTermGoalConfig); !ok {
			return PairedGoalTransfer{}, ErrAuthorization
		}
	}
	targetConfig, _ := in.Target.GoalVersion.Compiled.Decode()
	target := targetConfig.(*policy.LongTermGoalConfig)
	if in.Amount.Cents() > in.Source.ReleaseableCash.Cents() || in.Amount.Cents() > jointMax(0, target.Target.Cents()-in.Target.Owned.Cents()) {
		return PairedGoalTransfer{}, ErrAuthorization
	}
	for _, id := range config.MustNotReducePolicyIDs {
		found := false
		for _, ref := range in.ProtectedReferences {
			if ref.PolicyID == id {
				if found || !ref.Current || !ref.ConfirmationVerified || !ref.ImpactVerified || ref.VersionID == (funds.ID{}) || !validHash(ref.ConfigurationHash) || ref.ProtectedAfter.Cents() < ref.ProtectedBefore.Cents() {
					return PairedGoalTransfer{}, ErrAuthorization
				}
				found = true
			}
		}
		if !found {
			return PairedGoalTransfer{}, ErrAuthorization
		}
	}
	effect := PairedGoalTransfer{Protocol: "paired-goal-transfer-go-v1", Scope: in.Policy.Scope, PolicyID: in.Policy.PolicyID, PolicyVersionID: in.Policy.VersionID, SourceGoalID: in.Source.ID, TargetGoalID: in.Target.ID, SourceAccountID: in.Source.AccountID, TargetAccountID: in.Target.AccountID, SourceGoalVersionID: in.Source.VersionID, TargetGoalVersionID: in.Target.VersionID, Amount: in.Amount, DependencyHash: in.DependencyHash}
	effect.EffectHash = hash(effect)
	return effect, nil
}

// CheckPairedGoalTransfer checks two independently persisted USER consent
// originals for this exact effect. It returns no executable bank permission.
func CheckPairedGoalTransfer(in PairedGoalTransferInput, release, receive PairedGoalConsent) (PairedGoalTransfer, error) {
	effect, err := PreviewPairedGoalTransfer(in)
	if err != nil {
		return PairedGoalTransfer{}, err
	}
	if release.ID == (funds.ID{}) || receive.ID == (funds.ID{}) || release.ID == receive.ID {
		return PairedGoalTransfer{}, ErrAuthorization
	}
	for i, consent := range []PairedGoalConsent{release, receive} {
		role := []string{"RELEASE_SOURCE", "RECEIVE_TARGET"}[i]
		if consent.Role != role || consent.PrincipalKind != "USER" || consent.Scope != effect.Scope || consent.PolicyID != effect.PolicyID || consent.PolicyVersionID != effect.PolicyVersionID || consent.SourceGoalID != effect.SourceGoalID || consent.TargetGoalID != effect.TargetGoalID || consent.Amount != effect.Amount || consent.ReviewedEffectHash != effect.EffectHash || !consent.Current || !consent.Verified || consent.ConfirmedAt.IsZero() || consent.ConfirmedAt.After(in.Now) || !in.Now.Before(consent.ValidUntil) || !consent.ConfirmedAt.Before(consent.ValidUntil) {
			return PairedGoalTransfer{}, ErrAuthorization
		}
	}
	return effect, nil
}
