package audit

import (
	"errors"
	"fmt"
	"sort"
	"strings"
)

// VerifyCaptured checks one exact, bounded captured set. A collector assertion
// of DB coverage is not silently promoted to independently anchored integrity.
func VerifyCaptured(bundle CapturedBundle, registry *Registry, options CaptureOptions) CaptureVerification {
	verifyCapturedAttempts.Add(1)
	m := bundle.Manifest
	result := CaptureVerification{Status: Valid, Scope: m.Scope, Assurance: "INTERNAL_CONSISTENCY", AnchorStatus: "NOT_PROVIDED", CapturedAt: m.Source.CapturedAt.UTC(), Watermarks: map[string]int64{}, SourceManifestSHA256: m.Source.SourceManifestSHA256, ConfigSHA256: m.Source.ConfigSHA256, RootIDs: []string{}, CheckedIDs: []string{}, Versions: []CapturedVersion{}}
	for key, value := range m.Source.Watermarks {
		result.Watermarks[key] = value
	}
	versions := map[CapturedVersion]bool{}
	setVersions := func() {
		result.Versions = []CapturedVersion{}
		for version := range versions {
			result.Versions = append(result.Versions, version)
		}
		sort.Slice(result.Versions, func(i, j int) bool {
			a, _ := captureCanonical(result.Versions[i])
			b, _ := captureCanonical(result.Versions[j])
			return string(a) < string(b)
		})
	}
	fail := func(status Status, id, reason string) CaptureVerification {
		setVersions()
		result.Status, result.FailedID, result.Reason = status, id, reason
		return result
	}
	fromError := func(id string, err error) CaptureVerification {
		var reference *ReferenceError
		if errors.As(err, &reference) && label(reference.ID) {
			id = reference.ID
		}
		if errors.Is(err, ErrUnsupportedVersion) {
			return fail(UnsupportedVersion, id, "unregistered captured protocol or algorithm")
		}
		if errors.Is(err, ErrIncomplete) {
			return fail(Incomplete, id, "required captured business proof missing")
		}
		return fail(Invalid, id, "captured original or semantic validation failed")
	}
	bounds := options.Bounds
	if bounds == (Bounds{}) {
		bounds = DefaultBounds()
	}
	if bounds.validate() != nil || len(m.Members) > bounds.MaxNodes {
		return fail(Incomplete, "", "captured audit capacity exceeded")
	}
	digest, err := m.Digest()
	if err != nil {
		return fromError("", err)
	}
	result.ManifestDigest = digest
	for _, root := range m.Roots {
		result.RootIDs = append(result.RootIDs, root.ID)
	}
	if len(bundle.Originals) > len(m.Members) {
		return fail(Invalid, "", "undeclared captured originals")
	}
	docs := make(map[string]Document, len(m.Members))
	members := make(map[string]CapturedMember, len(m.Members))
	for _, member := range m.Members {
		original, ok := bundle.Originals[member.ID]
		if !ok {
			return fail(Incomplete, member.ID, "captured member original missing")
		}
		if len(original.Canonical) > bounds.MaxBytes-result.OriginalBytes {
			return fail(Incomplete, member.ID, "captured byte capacity exceeded")
		}
		if member.Digest != original.Digest || member.Bytes != int64(len(original.Canonical)) {
			return fail(Invalid, member.ID, "captured member identity or length differs")
		}
		doc, err := parseOriginal(original)
		if err != nil {
			return fromError(member.ID, err)
		}
		if doc.ID != member.ID || memberOf(member.ID, original, doc) != member {
			return fail(Invalid, member.ID, "captured member type or identity differs")
		}
		docs[member.ID], members[member.ID] = doc, member
		result.OriginalBytes += len(original.Canonical)
		versions[CapturedVersion{doc.SchemaVersion, doc.CanonicalVersion, doc.HashAlgorithm, doc.Kind, doc.SemanticVersion}] = true
	}
	if registry == nil {
		return fail(UnsupportedVersion, "", "captured semantic registry missing")
	}
	kinds := map[semanticKey]bool{}
	for _, member := range m.Members {
		doc := docs[member.ID]
		key := semanticKey{doc.Kind, doc.SemanticVersion}
		validator, scope := registry.validators[key], registry.scopeValidators[key]
		if validator == nil || scope == nil {
			return fail(UnsupportedVersion, member.ID, "captured semantic or scope validator missing")
		}
		if err := validator(doc); err != nil {
			return fromError(member.ID, err)
		}
		if err := scope(m.Scope, doc); err != nil {
			return fromError(member.ID, err)
		}
		kinds[key] = true
		for _, ref := range doc.References {
			if result.EdgeCount >= bounds.MaxEdges {
				return fail(Incomplete, member.ID, "captured edge capacity exceeded")
			}
			result.EdgeCount++
			child, ok := members[ref.ID]
			if !ok {
				return fail(Incomplete, ref.ID, "reference outside captured membership")
			}
			if child.Digest != ref.Digest {
				return fail(Invalid, ref.ID, "captured reference digest differs")
			}
			if link := registry.referenceValidators[key]; link != nil {
				if err := link(doc, docs[ref.ID], ref); err != nil {
					return fromError(ref.ID, err)
				}
			}
		}
		result.CheckedIDs = append(result.CheckedIDs, member.ID)
	}
	for _, root := range m.Roots {
		member, ok := members[root.ID]
		if !ok {
			return fail(Incomplete, root.ID, "captured root missing")
		}
		if member.Digest != root.Digest {
			return fail(Invalid, root.ID, "captured root digest differs")
		}
	}
	seen, failed, reason := capturedReachable(m.Roots, docs, bounds.MaxDepth)
	if reason != "" {
		status := Invalid
		if reason == "captured graph depth exceeded" {
			status = Incomplete
		}
		return fail(status, failed, reason)
	}
	if len(seen) != len(m.Members) {
		for _, member := range m.Members {
			if !seen[member.ID] {
				return fail(Incomplete, member.ID, "captured member omitted from root closure")
			}
		}
	}
	keys := make([]semanticKey, 0, len(kinds))
	for key := range kinds {
		keys = append(keys, key)
	}
	sort.Slice(keys, func(i, j int) bool {
		return keys[i].kind < keys[j].kind || keys[i].kind == keys[j].kind && keys[i].version < keys[j].version
	})
	for _, key := range keys {
		if graph := registry.graphValidators[key]; graph != nil {
			if err := graph(m, docs); err != nil {
				return fromError("", err)
			}
		}
	}
	var closure strings.Builder
	for _, id := range result.CheckedIDs {
		fmt.Fprintf(&closure, "%d:%s:%s\n", len(id), id, members[id].Digest)
	}
	result.ClosureDigest = digestBytes("zhiyu/evidence-closure/v1\x00", []byte(closure.String()))
	setVersions()
	if options.Anchor == nil {
		if options.RequireAnchor {
			return fail(Incomplete, "", "required independent audit anchor missing")
		}
		return result
	}
	if err := VerifyAnchor(m, *options.Anchor, options.TrustedKeys); err != nil {
		result.AnchorStatus = "REJECTED"
		if errors.Is(err, ErrAnchorTrustMissing) {
			result.AnchorStatus = "TRUST_KEY_MISSING"
			return fail(Incomplete, "", "independent audit anchor trust key missing")
		}
		return fromError("", err)
	}
	result.AnchorStatus, result.Assurance = "VERIFIED", "ANCHORED_INTEGRITY"
	return result
}

func capturedReachable(roots []Reference, docs map[string]Document, maxDepth int) (map[string]bool, string, string) {
	state := map[string]int{}
	seen := map[string]bool{}
	height := map[string]int{}
	var visit func(string, int) (string, string)
	visit = func(id string, depth int) (string, string) {
		if depth > maxDepth {
			return id, "captured graph depth exceeded"
		}
		if state[id] == 1 {
			return id, "captured reference cycle"
		}
		if state[id] == 2 {
			if depth+height[id]-1 > maxDepth {
				return id, "captured graph depth exceeded"
			}
			return "", ""
		}
		state[id] = 1
		height[id] = 1
		for _, ref := range docs[id].References {
			if failed, reason := visit(ref.ID, depth+1); reason != "" {
				return failed, reason
			}
			if height[ref.ID]+1 > height[id] {
				height[id] = height[ref.ID] + 1
			}
		}
		state[id], seen[id] = 2, true
		return "", ""
	}
	for _, root := range roots {
		if failed, reason := visit(root.ID, 1); reason != "" {
			return seen, failed, reason
		}
	}
	return seen, "", ""
}
