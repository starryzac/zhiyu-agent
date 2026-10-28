package domain

import (
	"encoding/json"
	"sort"
	"time"

	funds "zhiyu.local/zhiyu-go/internal/funds/domain"
	policy "zhiyu.local/zhiyu-go/internal/policy/domain"
)

const NativeGrantDisplayProtocol = "zhiyu-agent-native-grants-v1"
const NativeGrantVerificationScope = "OWNED_ORIGINALS_AND_COMPLETE_GRANT_STATE_CHAIN"
const NativeGrantSessionScope = "SCOPED_SUBJECT_AND_EVENT_EXPIRY_ONLY"

// NativeGrantDisplay is a closed, owned read. Caps are reviewed limits, not
// a safe amount or permission to execute. No original or session is retained.
type NativeGrantDisplay struct {
	ID                 string                         `json:"id"`
	Version            uint64                         `json:"version"`
	Family             policy.NativeFamily            `json:"family"`
	RecordedState      string                         `json:"recorded_state"`
	EffectiveState     string                         `json:"effective_state"`
	StateSequence      uint64                         `json:"state_sequence"`
	StateAt            time.Time                      `json:"state_at"`
	EffectiveFrom      time.Time                      `json:"effective_from"`
	ExpiresAt          time.Time                      `json:"expires_at"`
	EvaluatedLocalDate string                         `json:"evaluated_local_date"`
	Timezone           string                         `json:"timezone"`
	PolicyReferences   []policy.NativePolicyReference `json:"policy_references"`
	AccountIDs         []funds.ID                     `json:"account_ids"`
	GoalIDs            []funds.ID                     `json:"goal_ids"`
	ProductIDs         []string                       `json:"product_ids"`
	PayeeIDs           []string                       `json:"payee_ids"`
	SingleCap          funds.Money                    `json:"single_cap_cents"`
	LifetimeCap        funds.Money                    `json:"lifetime_cap_cents"`
	MonthlyCap         funds.Money                    `json:"monthly_cap_cents"`
	OriginalDigest     string                         `json:"original_digest"`
	TermsDigest        string                         `json:"terms_digest"`
	ChainDigest        string                         `json:"chain_digest"`
	ReasonCodes        []string                       `json:"reason_codes"`
	Authority          bool                           `json:"authority"`
	BankAuthority      bool                           `json:"bank_authority"`
}

type NativeGrantCollection struct {
	Protocol            string               `json:"protocol"`
	Status              string               `json:"status"`
	Count               *int                 `json:"count,omitempty"`
	Items               []NativeGrantDisplay `json:"items"`
	ReasonCodes         []string             `json:"reason_codes"`
	CollectionDigest    string               `json:"collection_digest"`
	VerificationScope   string               `json:"verification_scope"`
	SessionVerification string               `json:"session_verification"`
	Authority           bool                 `json:"authority"`
	BankAuthority       bool                 `json:"bank_authority"`
}

func nativeGrantReason(code string) bool {
	switch code {
	case "CAPACITY", "SCHEMA_UNAVAILABLE", "EVIDENCE_INVALID", "SUBJECT_UNAVAILABLE", "SESSION_EXPIRED_AT_EVENT", "SESSION_REVOCATION_HISTORY_UNAVAILABLE", "POLICY_CHANGED", "POLICY_UNAVAILABLE", "NOT_YET_EFFECTIVE", "EXPIRED", "PAUSED", "REVOKED":
		return true
	}
	return false
}

func validGrantReasons(codes []string) bool {
	if codes == nil || len(codes) > 13 {
		return false
	}
	last := ""
	for _, code := range codes {
		if !nativeGrantReason(code) || code <= last {
			return false
		}
		last = code
	}
	return true
}

func grantHasReason(codes []string, want string) bool {
	for _, code := range codes {
		if code == want {
			return true
		}
	}
	return false
}

func nativeGrantDisplayBounds(v NativeGrantDisplay) bool {
	return len(v.PolicyReferences) <= 16 && len(v.AccountIDs) <= 16 && len(v.GoalIDs) <= 8 && len(v.ProductIDs) <= 100 && len(v.PayeeIDs) <= 1 && len(v.ReasonCodes) <= 13
}

func cloneNativeGrant(v NativeGrantDisplay) NativeGrantDisplay {
	if !nativeGrantDisplayBounds(v) {
		return NativeGrantDisplay{}
	}
	v.PolicyReferences = append([]policy.NativePolicyReference{}, v.PolicyReferences...)
	for i, ref := range v.PolicyReferences {
		if ref.GoalID != nil {
			id := *ref.GoalID
			v.PolicyReferences[i].GoalID = &id
		}
	}
	v.AccountIDs = append([]funds.ID{}, v.AccountIDs...)
	v.GoalIDs = append([]funds.ID{}, v.GoalIDs...)
	v.ProductIDs = append([]string{}, v.ProductIDs...)
	v.PayeeIDs = append([]string{}, v.PayeeIDs...)
	v.ReasonCodes = append([]string{}, v.ReasonCodes...)
	return v
}

func CloneNativeGrantCollection(c *NativeGrantCollection) *NativeGrantCollection {
	if c == nil {
		return nil
	}
	if len(c.Items) > 100 || len(c.ReasonCodes) > 13 {
		return &NativeGrantCollection{Status: "INVALID", Items: []NativeGrantDisplay{}, ReasonCodes: []string{}}
	}
	out := *c
	if c.Count != nil {
		count := *c.Count
		out.Count = &count
	}
	out.Items = make([]NativeGrantDisplay, len(c.Items))
	for i, v := range c.Items {
		out.Items[i] = cloneNativeGrant(v)
	}
	out.ReasonCodes = append([]string{}, c.ReasonCodes...)
	return &out
}

func nativeGrantCollectionDigest(scope Scope, c NativeGrantCollection) string {
	c.CollectionDigest = ""
	return makeRef("NATIVE_GRANTS", scope.UserID.String(), struct {
		Scope      Scope
		Collection NativeGrantCollection
	}{scope, c}).Digest
}

// NewNativeGrantCollection copies and canonicalizes only already verified
// app-owned display fields. It does not validate originals or grant authority.
func NewNativeGrantCollection(scope Scope, items []NativeGrantDisplay, sessionVerification string) (*NativeGrantCollection, error) {
	if len(items) > 100 {
		return nil, ErrBudget
	}
	c := &NativeGrantCollection{Protocol: NativeGrantDisplayProtocol, Status: "COMPLETE", Items: []NativeGrantDisplay{}, ReasonCodes: []string{}, VerificationScope: NativeGrantVerificationScope, SessionVerification: sessionVerification}
	for _, item := range items {
		if !nativeGrantDisplayBounds(item) {
			return nil, ErrBudget
		}
		item = cloneNativeGrant(item)
		sort.Strings(item.ReasonCodes)
		c.Items = append(c.Items, item)
	}
	sort.Slice(c.Items, func(i, j int) bool { return c.Items[i].ID < c.Items[j].ID })
	count := len(c.Items)
	c.Count = &count
	c.CollectionDigest = nativeGrantCollectionDigest(scope, *c)
	if err := c.Validate(scope, time.Time{}); err != nil {
		return nil, err
	}
	return c, nil
}

// UnavailableNativeGrants keeps unknown inventory distinct from known empty.
// Scope binding is done by NativeGrantCollectionForScope before use.
func UnavailableNativeGrants(reason string) *NativeGrantCollection {
	if !nativeGrantReason(reason) {
		reason = "EVIDENCE_INVALID"
	}
	return &NativeGrantCollection{Protocol: NativeGrantDisplayProtocol, Status: "UNAVAILABLE", Items: []NativeGrantDisplay{}, ReasonCodes: []string{reason}, VerificationScope: "NOT_VERIFIED", SessionVerification: "NOT_VERIFIED"}
}

// NativeGrantCollectionForScope binds an unavailable placeholder to its owner.
// It rejects a forged COMPLETE digest rather than silently repairing it.
func NativeGrantCollectionForScope(scope Scope, c *NativeGrantCollection) *NativeGrantCollection {
	if c == nil {
		c = UnavailableNativeGrants("SCHEMA_UNAVAILABLE")
	}
	out := CloneNativeGrantCollection(c)
	if out.Status == "UNAVAILABLE" && out.CollectionDigest == "" {
		out.CollectionDigest = nativeGrantCollectionDigest(scope, *out)
	}
	return out
}

func (v NativeGrantDisplay) validate(scope Scope, asOf time.Time) error {
	if !nativeGrantDisplayBounds(v) {
		return ErrBudget
	}
	if !exactID(v.ID) || v.Version != 1 || !v.Family.Valid() || v.StateSequence < 1 || v.StateSequence > 256 || v.StateAt.IsZero() || v.StateAt.Before(v.EffectiveFrom) || v.Authority || v.BankAuthority || !hash64(v.OriginalDigest) || !hash64(v.TermsDigest) || !hash64(v.ChainDigest) || !validGrantReasons(v.ReasonCodes) {
		return ErrReference
	}
	if v.RecordedState != "ACTIVE" && v.RecordedState != "PAUSED" && v.RecordedState != "REVOKED" {
		return ErrReference
	}
	terms := policy.NativeStandingTerms{Protocol: policy.NativeStandingProtocol, Scope: policy.TemplateOwnerScope{EnvironmentID: scope.EnvironmentID, UserID: scope.UserID}, Family: v.Family, Policies: v.PolicyReferences, AccountIDs: v.AccountIDs, GoalIDs: v.GoalIDs, ProductIDs: v.ProductIDs, PayeeIDs: v.PayeeIDs, SingleCap: v.SingleCap, LifetimeCap: v.LifetimeCap, MonthlyCap: v.MonthlyCap, Timezone: v.Timezone, EffectiveFrom: v.EffectiveFrom, ExpiresAt: v.ExpiresAt}
	// TermsDigest is attested by the app's verified original. The display
	// normalizes nil lists to [] and must not pretend to reconstruct raw bytes.
	if terms.Validate() != nil {
		return ErrReference
	}
	z, err := policy.TemplateLocation(v.Timezone)
	if err != nil {
		return ErrReference
	}
	if day, err := time.Parse("2006-01-02", v.EvaluatedLocalDate); err != nil || len(v.EvaluatedLocalDate) != 10 || day.IsZero() {
		return ErrReference
	}
	switch v.EffectiveState {
	case "REVOKED":
		if v.RecordedState != "REVOKED" || !grantHasReason(v.ReasonCodes, "REVOKED") {
			return ErrReference
		}
	case "EXPIRED", "NOT_YET_EFFECTIVE", "POLICY_CHANGED":
		if !grantHasReason(v.ReasonCodes, v.EffectiveState) {
			return ErrReference
		}
	case "PAUSED":
		if v.RecordedState != "PAUSED" || !grantHasReason(v.ReasonCodes, "PAUSED") {
			return ErrReference
		}
	case "UNAVAILABLE":
		uncertain := false
		for _, code := range v.ReasonCodes {
			if code == "POLICY_UNAVAILABLE" || code == "EVIDENCE_INVALID" || code == "SUBJECT_UNAVAILABLE" || code == "SESSION_EXPIRED_AT_EVENT" || code == "SESSION_REVOCATION_HISTORY_UNAVAILABLE" {
				uncertain = true
			}
		}
		if !uncertain {
			return ErrReference
		}
	case "CURRENT_DISPLAY_ONLY":
		if len(v.ReasonCodes) != 0 {
			return ErrReference
		}
	default:
		return ErrReference
	}
	if !asOf.IsZero() {
		if v.StateAt.After(asOf) || v.EvaluatedLocalDate != asOf.In(z).Format("2006-01-02") {
			return ErrReference
		}
		if grantHasReason(v.ReasonCodes, "CAPACITY") || grantHasReason(v.ReasonCodes, "SCHEMA_UNAVAILABLE") || grantHasReason(v.ReasonCodes, "EXPIRED") && asOf.Before(v.ExpiresAt) || grantHasReason(v.ReasonCodes, "PAUSED") && v.RecordedState != "PAUSED" || grantHasReason(v.ReasonCodes, "REVOKED") && v.RecordedState != "REVOKED" || grantHasReason(v.ReasonCodes, "NOT_YET_EFFECTIVE") && !asOf.Before(v.EffectiveFrom) {
			return ErrReference
		}
		want := "CURRENT_DISPLAY_ONLY"
		switch {
		case v.RecordedState == "REVOKED":
			want = "REVOKED"
		case !asOf.Before(v.ExpiresAt):
			want = "EXPIRED"
		case v.RecordedState == "PAUSED":
			want = "PAUSED"
		case asOf.Before(v.EffectiveFrom):
			want = "NOT_YET_EFFECTIVE"
		case grantHasReason(v.ReasonCodes, "POLICY_CHANGED"):
			want = "POLICY_CHANGED"
		default:
			for _, code := range v.ReasonCodes {
				if code == "POLICY_UNAVAILABLE" || code == "EVIDENCE_INVALID" || code == "SUBJECT_UNAVAILABLE" || code == "SESSION_EXPIRED_AT_EVENT" || code == "SESSION_REVOCATION_HISTORY_UNAVAILABLE" {
					want = "UNAVAILABLE"
				}
			}
		}
		if v.EffectiveState != want {
			return ErrReference
		}
	}
	raw, err := json.Marshal(v)
	if err != nil || len(raw) > 32*1024 {
		return ErrBudget
	}
	return nil
}

func (c *NativeGrantCollection) Validate(scope Scope, asOf time.Time) error {
	if c == nil || scope.EnvironmentID == (funds.ID{}) || scope.UserID == (funds.ID{}) || c.Protocol != NativeGrantDisplayProtocol || c.Authority || c.BankAuthority || c.Items == nil || !validGrantReasons(c.ReasonCodes) {
		return ErrReference
	}
	if len(c.Items) > 100 {
		return ErrBudget
	}
	switch c.Status {
	case "COMPLETE":
		if c.Count == nil || *c.Count != len(c.Items) || len(c.ReasonCodes) != 0 || c.VerificationScope != NativeGrantVerificationScope || (c.SessionVerification != NativeGrantSessionScope && c.SessionVerification != "HISTORY_INCOMPLETE") {
			return ErrReference
		}
		last := ""
		for _, item := range c.Items {
			if item.ID <= last {
				return ErrReference
			}
			last = item.ID
			if err := item.validate(scope, asOf); err != nil {
				return err
			}
			if grantHasReason(item.ReasonCodes, "SESSION_REVOCATION_HISTORY_UNAVAILABLE") && c.SessionVerification != "HISTORY_INCOMPLETE" {
				return ErrReference
			}
		}
	case "UNAVAILABLE":
		if c.Count != nil || len(c.Items) != 0 || len(c.ReasonCodes) == 0 || c.VerificationScope != "NOT_VERIFIED" || c.SessionVerification != "NOT_VERIFIED" {
			return ErrReference
		}
	default:
		return ErrReference
	}
	if !hash64(c.CollectionDigest) || c.CollectionDigest != nativeGrantCollectionDigest(scope, *c) {
		return ErrReference
	}
	raw, err := json.Marshal(c)
	if err != nil || len(raw) > 512*1024 {
		return ErrBudget
	}
	return nil
}

func (s Snapshot) nativeGrantCollection() *NativeGrantCollection {
	if s.Native == nil {
		return NativeGrantCollectionForScope(s.Scope, nil)
	}
	return NativeGrantCollectionForScope(s.Scope, s.Native.NativeGrants)
}

func (s Snapshot) validateNativeGrantOwnership() error {
	accounts, goals := map[string]bool{}, map[string]bool{}
	for _, item := range s.Accounts {
		accounts[item.ID] = true
	}
	for _, item := range s.Goals {
		goals[item.ID] = true
	}
	for _, grant := range s.nativeGrantCollection().Items {
		for _, id := range grant.AccountIDs {
			if !accounts[id.String()] {
				return ErrReference
			}
		}
		for _, id := range grant.GoalIDs {
			if !goals[id.String()] {
				return ErrReference
			}
		}
		for _, ref := range grant.PolicyReferences {
			if ref.GoalID != nil && !goals[ref.GoalID.String()] {
				return ErrReference
			}
		}
	}
	return nil
}

func (s Snapshot) nativeGrantReferences() []Reference {
	c := s.nativeGrantCollection()
	refs := []Reference{{Kind: "NATIVE_GRANTS", ID: s.Scope.UserID.String(), Digest: c.CollectionDigest}}
	if c.Status == "COMPLETE" {
		for _, item := range c.Items {
			refs = append(refs, makeRef("NATIVE_GRANT", item.ID, struct {
				Protocol, VerificationScope, SessionVerification string
				Scope                                            Scope
				Grant                                            NativeGrantDisplay
			}{c.Protocol, c.VerificationScope, c.SessionVerification, s.Scope, item}))
		}
	}
	return refs
}

func observeNativeGrants(s Snapshot, call ToolCall, out Observation) (Observation, error) {
	c := s.nativeGrantCollection()
	if err := c.Validate(s.Scope, s.AsOf); err != nil {
		return Observation{}, err
	}
	refs := s.nativeGrantReferences()
	out.References = append(out.References, refs[0])
	if call.Name == "native_grants" {
		out.NativeGrants = c
		out.References = append(out.References, refs[1:]...)
		if c.Status == "COMPLETE" {
			out.Summary = "已读取原生持续授权的完整有界原件与状态链展示；不是执行授权或可用金额。"
		} else {
			out.Summary = "原生持续授权读取不可用，当前数量未知；不能按零条处理。"
		}
		return out, nil
	}
	var args struct {
		Reference Reference `json:"reference"`
	}
	if json.Unmarshal(call.Arguments, &args) != nil {
		return Observation{}, ErrReference
	}
	for i, ref := range refs {
		if ref == args.Reference {
			if i == 0 {
				out.NativeGrants = c
			} else {
				item := cloneNativeGrant(c.Items[i-1])
				out.NativeGrant = &item
				out.References = append(out.References, ref)
			}
			out.Summary = "已按原生持续授权原引用核对只读状态；没有建立、恢复或执行权限。"
			return out, nil
		}
	}
	return Observation{}, ErrReference
}
