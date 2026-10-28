package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"reflect"
	"sort"

	"zhiyu.local/zhiyu-go/internal/audit"
	executionaudit "zhiyu.local/zhiyu-go/internal/execution/audit"
)

// Populated only by a corresponding source-manifest-pinned build. An ordinary
// development build cannot sign a native capture by adopting its source claim.
var auditSourceManifestSHA string

type nativePublicTrust struct {
	Protocol                      string            `json:"protocol"`
	Environment                   string            `json:"environment"`
	Namespace                     string            `json:"namespace"`
	SourceManifestSHA256          string            `json:"source_manifest_sha256"`
	ConfigSHA256                  string            `json:"config_sha256"`
	RequireAnchor                 bool              `json:"require_anchor"`
	TrustedKeys                   map[string]string `json:"trusted_keys"`
	NativeCatalogHashes           map[string]string `json:"native_catalog_hashes,omitempty"`
	HistoryAuthorityProfileHashes []string          `json:"history_authority_profile_hashes,omitempty"`
}

func trustRefusal(code string) error { return errors.New("native trust rejected: " + code) }

func validNativeHash(value string) bool {
	raw, err := hex.DecodeString(value)
	return err == nil && len(raw) == sha256.Size && hex.EncodeToString(raw) == value
}

func nativeCapture(bundle audit.CapturedBundle) bool {
	for _, member := range bundle.Manifest.Members {
		if member.Kind == executionaudit.NativeSnapshotKindV3 || member.Kind == executionaudit.NativeRowKindV3 {
			return true
		}
	}
	return false
}

func loadNativeTrust(path, expectedSHA, expectedConfig, keyID string, private ed25519.PrivateKey, bundle audit.CapturedBundle) (executionaudit.NativeVerifierTrustV3, error) {
	closed := executionaudit.NativeVerifierTrustV3{}
	if path == "" || !validNativeHash(expectedSHA) || !validNativeHash(expectedConfig) {
		return closed, trustRefusal("EXPLICIT_PROFILE_PINS_REQUIRED")
	}
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Size() < 1 || info.Size() > 64*1024 {
		return closed, trustRefusal("PROFILE_FILE_INVALID")
	}
	raw, err := os.ReadFile(path)
	if err != nil || len(raw) > 64*1024 {
		return closed, trustRefusal("PROFILE_FILE_INVALID")
	}
	digest := sha256.Sum256(raw)
	if hex.EncodeToString(digest[:]) != expectedSHA {
		return closed, trustRefusal("PROFILE_HASH_MISMATCH")
	}
	if _, err := audit.ParseRawObject(raw); err != nil {
		return closed, trustRefusal("PROFILE_JSON_INVALID")
	}
	var profile nativePublicTrust
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(&profile) != nil || d.Decode(new(any)) != io.EOF || profile.Protocol != "zhiyu-audit-trust-v2" || profile.Environment == "" || profile.Namespace != bundle.Manifest.Scope.Namespace {
		return closed, trustRefusal("PROFILE_PROTOCOL_OR_SCOPE_MISMATCH")
	}
	if !validNativeHash(auditSourceManifestSHA) || profile.SourceManifestSHA256 != auditSourceManifestSHA || bundle.Manifest.Source.SourceManifestSHA256 != auditSourceManifestSHA {
		return closed, trustRefusal("COMPILED_SOURCE_MISMATCH")
	}
	if profile.ConfigSHA256 != expectedConfig || bundle.Manifest.Source.ConfigSHA256 != expectedConfig {
		return closed, trustRefusal("CONFIGURATION_PIN_MISMATCH")
	}
	catalogs := map[string]string{"22": executionaudit.NativeAuditCatalogHashV3Revision(22), "23": executionaudit.NativeAuditCatalogHashV3Revision(23), "25": executionaudit.NativeAuditCatalogHashV3Revision(25), "26": executionaudit.NativeAuditCatalogHashV3Revision(26)}
	if !reflect.DeepEqual(profile.NativeCatalogHashes, catalogs) {
		return closed, trustRefusal("COMPILED_CATALOGS_MISMATCH")
	}
	if len(profile.HistoryAuthorityProfileHashes) > 64 || !sort.StringsAreSorted(profile.HistoryAuthorityProfileHashes) {
		return closed, trustRefusal("HISTORY_PROFILE_PINS_INVALID")
	}
	for i, hash := range profile.HistoryAuthorityProfileHashes {
		if !validNativeHash(hash) || i > 0 && hash == profile.HistoryAuthorityProfileHashes[i-1] {
			return closed, trustRefusal("HISTORY_PROFILE_PINS_INVALID")
		}
	}
	if len(profile.TrustedKeys) < 1 || len(profile.TrustedKeys) > 64 || len(private) != ed25519.PrivateKeySize {
		return closed, trustRefusal("SIGNER_NOT_IN_PUBLIC_PROFILE")
	}
	if !bytes.Equal(ed25519.NewKeyFromSeed(private[:ed25519.SeedSize]), private) {
		return closed, trustRefusal("SIGNER_KEY_INVALID")
	}
	for id, encoded := range profile.TrustedKeys {
		key, err := base64.StdEncoding.Strict().DecodeString(encoded)
		if !keyIDPattern.MatchString(id) || err != nil || len(key) != ed25519.PublicKeySize {
			return closed, trustRefusal("PUBLIC_KEYS_INVALID")
		}
	}
	public, err := base64.StdEncoding.Strict().DecodeString(profile.TrustedKeys[keyID])
	if err != nil || !bytes.Equal(public, private.Public().(ed25519.PublicKey)) {
		return closed, trustRefusal("SIGNER_NOT_IN_PUBLIC_PROFILE")
	}
	// Only independently pinned public configuration enters this trust root.
	// No history key/hash is discovered from the bundle or audited database.
	return executionaudit.NativeVerifierTrustV3{HistoryAuthorityProfileHashes: append([]string(nil), profile.HistoryAuthorityProfileHashes...)}, nil
}
