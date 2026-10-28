package domain

import (
	"bytes"
	"encoding/json"
	"sort"

	funds "zhiyu.local/zhiyu-go/internal/funds/domain"
	policy "zhiyu.local/zhiyu-go/internal/policy/domain"
)

// V1 adds no larger audit/forecast boundary. Four MiB is the existing template
// facts ceiling; the separately encoded source row must also fit the audit's
// unchanged raw and compressed member budgets.
const MaxProtectedReferenceInputBytesV1 = 4 << 20
const MaxDatedConfirmationSourceBytesV1 = 4 << 20
const MaxProtectedReferencesV1 = 32
const ProtectedReferencePointsV1 = 1098

func protectedInputCapacityV1(in ForecastInput) error {
	raw, err := json.Marshal(in)
	if err != nil {
		return ErrForecastInput
	}
	if len(raw) > MaxProtectedReferenceInputBytesV1 {
		return ErrForecastCapacity
	}
	return nil
}

// CloneForecastInput preserves all consumer facts, unlike normalizedForecast.
// Callers must retain an independent before value before editing a version.
func CloneForecastInput(in ForecastInput) (ForecastInput, error) {
	var out ForecastInput
	raw, err := json.Marshal(in)
	if err != nil {
		return out, ErrForecastInput
	}
	if json.Unmarshal(raw, &out) != nil {
		return out, ErrForecastInput
	}
	return out, nil
}

func protectedExact(a, b any) bool {
	x, e := json.Marshal(a)
	y, f := json.Marshal(b)
	return e == nil && f == nil && bytes.Equal(x, y)
}

// ProtectedPolicyIDs returns only the typed protection edges, never arbitrary
// UUID-shaped fields such as payee, bill, goal or bank resource identities.
func ProtectedPolicyIDs(v policy.TemplateVersion) ([]funds.ID, error) {
	c, err := v.Compiled.Decode()
	if err != nil {
		return nil, ErrForecastInput
	}
	switch c := c.(type) {
	case *policy.DatedExpenseConfig:
		return append([]funds.ID(nil), c.MustNotReducePolicyIDs...), nil
	case *policy.CrossGoalReallocationConfig:
		return append([]funds.ID(nil), c.MustNotReducePolicyIDs...), nil
	default:
		return nil, nil
	}
}

// CompareProtectedPolicyReferencesV1 proves a narrow Dated configuration
// counterfactual. It never grants authority to a proposed version or changes
// actual cash/debt. Inputs must separately be tied to their actual source.
func CompareProtectedPolicyReferencesV1(before, after ForecastInput, proposedID funds.ID, required []funds.ID) ([]policy.TemplatePolicyReference, error) {
	if len(before.Versions) > 100 || len(after.Versions) > 100 || len(required) > MaxProtectedReferencesV1 {
		return nil, ErrForecastCapacity
	}
	if err := protectedInputCapacityV1(before); err != nil {
		return nil, err
	}
	if err := protectedInputCapacityV1(after); err != nil {
		return nil, err
	}
	if proposedID == (funds.ID{}) || before.HorizonDays != 365 || after.HorizonDays != 365 || len(before.Facts.ProtectedReferences) != 0 || len(after.Facts.ProtectedReferences) != 0 || before.Facts.CurrentSafeVerified || after.Facts.CurrentSafeVerified || !before.Facts.CurrentSafe.IsZero() || !after.Facts.CurrentSafe.IsZero() {
		return nil, ErrForecastInput
	}
	left, err := CloneForecastInput(before)
	if err != nil {
		return nil, err
	}
	right, err := CloneForecastInput(after)
	if err != nil {
		return nil, err
	}
	left.Versions, right.Versions = nil, nil
	if !protectedExact(left, right) {
		return nil, ErrForecastInput
	}
	index := func(in ForecastInput) (map[funds.ID]policy.TemplateVersion, error) {
		out := map[funds.ID]policy.TemplateVersion{}
		for _, v := range in.Versions {
			if _, ok := out[v.PolicyID]; ok || v.Scope != in.Scope {
				return nil, ErrForecastInput
			}
			if _, e := v.EffectiveState(in.AsOf, in.Timezone); e != nil {
				return nil, ErrForecastInput
			}
			out[v.PolicyID] = v
		}
		return out, nil
	}
	b, err := index(before)
	if err != nil {
		return nil, err
	}
	a, err := index(after)
	if err != nil {
		return nil, err
	}
	proposed, ok := a[proposedID]
	if !ok || proposed.Compiled.Name != policy.DatedExpenseTemplate || !proposed.ConfirmedAt.Equal(after.AsOf) || proposed.State != "ACTIVE" {
		return nil, ErrForecastInput
	}
	old, exists := b[proposedID]
	if exists && (old.Compiled.Name != proposed.Compiled.Name || proposed.Version != old.Version+1 || proposed.VersionID == old.VersionID) || !exists && proposed.Version != 1 {
		return nil, ErrForecastInput
	}
	expectedCount := len(b) + 1
	if exists {
		expectedCount = len(b)
	}
	if len(a) != expectedCount {
		return nil, ErrForecastInput
	}
	for id, v := range b {
		if id != proposedID && !protectedExact(v, a[id]) {
			return nil, ErrForecastInput
		}
	}
	edges, err := ProtectedPolicyIDs(proposed)
	if err != nil {
		return nil, err
	}
	ordered := func(ids []funds.ID) []funds.ID {
		out := append([]funds.ID(nil), ids...)
		sort.Slice(out, func(i, j int) bool { return out[i].String() < out[j].String() })
		return out
	}
	ids := ordered(required)
	if !protectedExact(ids, ordered(edges)) {
		return nil, ErrForecastInput
	}
	for i, id := range ids {
		if id == (funds.ID{}) || id == proposedID || i > 0 && id == ids[i-1] {
			return nil, ErrForecastInput
		}
	}
	// Validate every current protection edge and detect cycles in O(V+E).
	colors := map[funds.ID]uint8{}
	var visit func(funds.ID) error
	visit = func(id funds.ID) error {
		if colors[id] == 1 {
			return ErrForecastInput
		}
		if colors[id] == 2 {
			return nil
		}
		v, ok := a[id]
		if !ok {
			return ErrForecastInput
		}
		colors[id] = 1
		refs, e := ProtectedPolicyIDs(v)
		if e != nil {
			return e
		}
		if len(refs) > MaxProtectedReferencesV1 {
			return ErrForecastCapacity
		}
		seen := map[funds.ID]bool{}
		for _, ref := range refs {
			actual, found := b[ref]
			if ref == id || seen[ref] || !found || !protectedExact(actual, a[ref]) {
				return ErrForecastInput
			}
			seen[ref] = true
			state, e := actual.EffectiveState(before.AsOf, before.Timezone)
			if e != nil || state != "ACTIVE" && state != "CONFIRMED" {
				return ErrForecastInput
			}
			if e = visit(ref); e != nil {
				return e
			}
		}
		colors[id] = 2
		return nil
	}
	all := make([]funds.ID, 0, len(a))
	for id := range a {
		all = append(all, id)
	}
	all = ordered(all)
	for _, id := range all {
		if err = visit(id); err != nil {
			return nil, err
		}
	}
	// The full forecasts retain every obligation and encumbrance. Per-policy
	// attribution below is permitted only after exact background equality.
	if _, err = Forecast365(before); err != nil {
		return nil, err
	}
	if _, err = Forecast365(after); err != nil {
		return nil, err
	}
	refs := []policy.TemplatePolicyReference{}
	for _, id := range ids {
		v, found := b[id]
		if !found {
			return nil, ErrForecastInput
		}
		isolate := func(in ForecastInput) (ForecastResult, error) {
			x, e := CloneForecastInput(in)
			if e != nil {
				return ForecastResult{}, e
			}
			x.Versions = []policy.TemplateVersion{v}
			x.HeldCash, x.UnassignedGoalCash = funds.Money{}, funds.Money{}
			x.FutureIncome, x.PrincipalReturns = nil, nil
			for i := range x.Facts.Goals {
				if x.Facts.Goals[i].PolicyID != id {
					x.Facts.Goals[i].CashOwned = funds.Money{}
				}
			}
			x.RetainedObligations, x.RetainedFloors = nil, nil
			for _, o := range in.RetainedObligations {
				if o.PolicyID == id {
					x.RetainedObligations = append(x.RetainedObligations, o)
				}
			}
			for _, f := range in.RetainedFloors {
				if f.PolicyID == id {
					x.RetainedFloors = append(x.RetainedFloors, f)
				}
			}
			return Forecast365(x)
		}
		l, e := isolate(before)
		if e != nil {
			return nil, e
		}
		r, e := isolate(after)
		if e != nil {
			return nil, e
		}
		lm, rm, e := compareProtectedCurveV1(l, r)
		if e != nil {
			return nil, e
		}
		refs = append(refs, policy.TemplatePolicyReference{PolicyID: id, VersionID: v.VersionID, ConfigurationHash: v.Compiled.Hash, Current: true, ConfirmationVerified: true, ImpactVerified: true, ProtectedBefore: lm, ProtectedAfter: rm})
	}
	return refs, nil
}

// Summaries are emitted only after every aligned natural-day phase passes.
func compareProtectedCurveV1(left, right ForecastResult) (funds.Money, funds.Money, error) {
	var lm, rm funds.Money
	if left.HorizonDays != 365 || right.HorizonDays != 365 || len(left.Points) != ProtectedReferencePointsV1 || len(right.Points) != ProtectedReferencePointsV1 || !left.AsOf.Equal(right.AsOf) || left.Timezone != right.Timezone {
		return lm, rm, ErrForecastInput
	}
	for i, p := range left.Points {
		q := right.Points[i]
		if p.ID != q.ID || p.Date != q.Date || p.Phase != q.Phase || !p.At.Equal(q.At) || q.Protected.Cents() < p.Protected.Cents() {
			return funds.Money{}, funds.Money{}, ErrForecastInput
		}
		if p.Protected.Cents() > lm.Cents() {
			lm = p.Protected
		}
		if q.Protected.Cents() > rm.Cents() {
			rm = q.Protected
		}
	}
	return lm, rm, nil
}
