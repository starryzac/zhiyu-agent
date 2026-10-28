package domain

import (
	"crypto/sha256"
	"encoding/json"
	"regexp"
	"sort"
	"strings"
	"unicode/utf8"

	funds "zhiyu.local/zhiyu-go/internal/funds/domain"
	policy "zhiyu.local/zhiyu-go/internal/policy/domain"
)

const KnownPayeeProtocol = "zhiyu-agent-known-bill-payee-v1"

var payeeNamespace = regexp.MustCompile(`^zygo_[a-z][a-z0-9_]{0,63}$`)

// KnownPayee is a read-only identity from verified BILL originals. It proves
// neither a payable balance nor USER permission, and is not a payee directory.
type KnownPayee struct {
	Protocol      string                    `json:"protocol"`
	Scope         policy.TemplateOwnerScope `json:"scope"`
	BankNamespace string                    `json:"bank_namespace"`
	PayeeID       string                    `json:"payee_id"`
	SourceHash    string                    `json:"source_hash"`
	Evidence      []KnownPayeeEvidence      `json:"evidence"`
	Authority     bool                      `json:"authority"`
	BankAuthority bool                      `json:"bank_authority"`
}

type KnownPayeeEvidence struct {
	BillID             funds.ID `json:"bill_id"`
	StatementAccountID funds.ID `json:"statement_account_id"`
	OriginalHash       string   `json:"original_hash"`
	BankReferenceHash  string   `json:"bank_reference_hash"`
}

// KnownPayeeID retains the UUID reference contract while configuration keeps
// the exact opaque bank recipient. The namespace is pinned in the object digest.
func KnownPayeeID(scope Scope, raw string) funds.ID {
	h := sha256.Sum256([]byte(scope.EnvironmentID.String() + "/" + scope.UserID.String() + "/NATIVE_PAYEE/" + raw))
	var id funds.ID
	copy(id[:], h[:16])
	id[6] = (id[6] & 15) | 64
	id[8] = (id[8] & 63) | 128
	return id
}

func (p KnownPayee) valid(scope Scope) bool {
	if p.Protocol != KnownPayeeProtocol || p.Scope != (policy.TemplateOwnerScope{EnvironmentID: scope.EnvironmentID, UserID: scope.UserID}) ||
		!payeeNamespace.MatchString(p.BankNamespace) || !hash64(p.SourceHash) || p.Authority || p.BankAuthority ||
		len(p.PayeeID) == 0 || len(p.PayeeID) > 128 || !utf8.ValidString(p.PayeeID) || strings.ContainsRune(p.PayeeID, 0) ||
		len(p.Evidence) == 0 || len(p.Evidence) > 100 {
		return false
	}
	previous := ""
	for _, e := range p.Evidence {
		if e.BillID == (funds.ID{}) || e.StatementAccountID == (funds.ID{}) || !hash64(e.OriginalHash) || !hash64(e.BankReferenceHash) || e.BillID.String() <= previous {
			return false
		}
		previous = e.BillID.String()
	}
	return true
}

// NewKnownPayeeObject accepts only server-verified evidence metadata. The app
// adapter must verify actual originals before calling it; no model route can.
func NewKnownPayeeObject(scope Scope, namespace, raw, source string, evidence []KnownPayeeEvidence) (ObjectObservation, error) {
	evidence = append([]KnownPayeeEvidence(nil), evidence...)
	sort.Slice(evidence, func(i, j int) bool { return evidence[i].BillID.String() < evidence[j].BillID.String() })
	p := KnownPayee{Protocol: KnownPayeeProtocol, Scope: policy.TemplateOwnerScope{EnvironmentID: scope.EnvironmentID, UserID: scope.UserID}, BankNamespace: namespace, PayeeID: raw, SourceHash: source, Evidence: evidence}
	if scope.EnvironmentID == (funds.ID{}) || scope.UserID == (funds.ID{}) || !p.valid(scope) {
		return ObjectObservation{}, ErrReference
	}
	data, err := json.Marshal(p)
	if err != nil || len(data) > 32768 {
		return ObjectObservation{}, ErrReference
	}
	return ObjectObservation{Kind: "NATIVE_PAYEE", ID: KnownPayeeID(scope, raw).String(), Data: data}, nil
}

func (s Snapshot) knownPayeeObject(o ObjectObservation) (KnownPayee, bool) {
	var p KnownPayee
	// exactObject detects duplicate keys as well as unknown/case-folded fields.
	fields := []string{"protocol", "scope", "bank_namespace", "payee_id", "source_hash", "evidence", "authority", "bank_authority"}
	obj, err := exactObject(o.Data, fields...)
	if err != nil || len(obj) != len(fields) || json.Unmarshal(o.Data, &p) != nil || !p.valid(s.Scope) || s.Native == nil ||
		p.BankNamespace != s.Native.BankNamespace || p.SourceHash != s.Native.SourceHash || o.ID != KnownPayeeID(s.Scope, p.PayeeID).String() {
		return KnownPayee{}, false
	}
	// Nested metadata is closed too; it cannot carry hidden model instructions.
	var wire struct {
		Scope    json.RawMessage   `json:"scope"`
		Evidence []json.RawMessage `json:"evidence"`
	}
	if json.Unmarshal(o.Data, &wire) != nil {
		return KnownPayee{}, false
	}
	if scope, e := exactObject(wire.Scope, "environment_id", "user_id"); e != nil || len(scope) != 2 {
		return KnownPayee{}, false
	}
	for _, raw := range wire.Evidence {
		if item, e := exactObject(raw, "bill_id", "statement_account_id", "original_hash", "bank_reference_hash"); e != nil || len(item) != 4 {
			return KnownPayee{}, false
		}
	}
	for _, e := range p.Evidence {
		if !s.hasRef("ACCOUNT", e.StatementAccountID.String()) {
			return KnownPayee{}, false
		}
	}
	return p, true
}

func (s Snapshot) knownPayeeReference(raw string) (Reference, bool) {
	if s.Native != nil {
		for _, o := range s.Native.Objects {
			if o.Kind == "NATIVE_PAYEE" {
				if p, ok := s.knownPayeeObject(o); ok && p.PayeeID == raw {
					return makeRef(o.Kind, o.ID, o), true
				}
			}
		}
	}
	return Reference{}, false
}

// KnownPayeeSignals exposes only an exact advertised UUID reference and its
// opaque bank identity. Raw BILL bytes, prose and financial requests stay out.
func (s Snapshot) KnownPayeeSignals(refs []Reference) []KnownPayeeSignal {
	out := []KnownPayeeSignal{}
	if s.Native == nil {
		return out
	}
	for _, r := range refs {
		if r.Kind != "NATIVE_PAYEE" {
			continue
		}
		for _, o := range s.Native.Objects {
			if o.Kind == r.Kind && o.ID == r.ID && makeRef(o.Kind, o.ID, o) == r {
				if p, ok := s.knownPayeeObject(o); ok {
					out = append(out, KnownPayeeSignal{Reference: r, PayeeID: p.PayeeID})
				}
			}
		}
	}
	return out
}

type KnownPayeeSignal struct {
	Reference Reference `json:"reference"`
	PayeeID   string    `json:"payee_id"`
}
