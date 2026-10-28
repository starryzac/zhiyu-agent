package main

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"sort"

	"zhiyu.local/zhiyu-go/internal/app"
	"zhiyu.local/zhiyu-go/internal/audit"
	executionaudit "zhiyu.local/zhiyu-go/internal/execution/audit"
	"zhiyu.local/zhiyu-go/internal/platform"
)

// Set only by a build made from the corresponding immutable source manifest.
// A default development build does not pretend to know its source provenance.
var auditSourceManifestSHA string

type auditTrustConfig struct {
	NativeCatalogHashes           map[string]string `json:"native_catalog_hashes,omitempty"`
	HistoryAuthorityProfileHashes []string          `json:"history_authority_profile_hashes,omitempty"`
	Protocol                      string            `json:"protocol"`
	Environment                   string            `json:"environment"`
	Namespace                     string            `json:"namespace"`
	SourceManifestSHA256          string            `json:"source_manifest_sha256"`
	ConfigSHA256                  string            `json:"config_sha256"`
	RequireAnchor                 bool              `json:"require_anchor"`
	TrustedKeys                   map[string]string `json:"trusted_keys"`
}

func auditNativeCatalogHashesV2() map[string]string {
	return map[string]string{"22": executionaudit.NativeAuditCatalogHashV3Revision(22), "23": executionaudit.NativeAuditCatalogHashV3Revision(23), "25": executionaudit.NativeAuditCatalogHashV3Revision(25), "26": executionaudit.NativeAuditCatalogHashV3Revision(26)}
}

// This separate public profile preserves trust-v1's runtime digest. Only
// approved PUBLIC profile hashes and compiled known catalogs are added; no
// credential, DSN, private issuer key or raw source is hashed here.
// Adding a compiled catalog requires a new v2 profile/configuration digest;
// the old three-catalog v2 map is rejected rather than silently upgraded.
func auditConfigurationDigestV2(c platform.Runtime, history []string) string {
	if history == nil {
		history = []string{}
	}
	raw, _ := json.Marshal(struct {
		Protocol string            `json:"protocol"`
		Runtime  string            `json:"runtime_configuration_sha256"`
		Catalogs map[string]string `json:"native_catalog_hashes"`
		History  []string          `json:"history_authority_profile_hashes"`
	}{"zhiyu-public-audit-profile-v2", auditConfigurationDigest(c), auditNativeCatalogHashesV2(), history})
	return app.Hash(raw)
}

func auditConfigurationDigest(c platform.Runtime) string {
	// All values here are intentionally public configuration facts. Never hash
	// a password/key/DSN into a public source or verification index.
	raw, _ := json.Marshal(map[string]string{"protocol": "zhiyu-public-runtime-v1", "environment": c.Environment, "namespace": c.Namespace, "role": c.Role, "application_role": "zygo_app", "application_database": c.Environment + "_app", "bank_url": c.BankURL, "web_origin": c.WebOrigin})
	return app.Hash(raw)
}

func validAuditHash(value string) bool {
	raw, err := hex.DecodeString(value)
	return err == nil && len(raw) == 32 && hex.EncodeToString(raw) == value
}

func configuredAudit(configPath string, c platform.Runtime, logger *slog.Logger) app.AuditTrustOptions {
	result := app.AuditTrustOptions{}
	fail := func() app.AuditTrustOptions {
		logger.Warn("audit_configuration", "status", "AUDIT_NOT_CONFIGURED")
		return result
	}
	if !validAuditHash(auditSourceManifestSHA) {
		return fail()
	}
	absolute, err := filepath.Abs(configPath)
	if err != nil {
		return fail()
	}
	raw, err := os.ReadFile(filepath.Join(filepath.Dir(absolute), "audit-trust.json"))
	if err != nil || len(raw) > 64*1024 {
		return fail()
	}
	if _, err = audit.ParseRawObject(raw); err != nil {
		return fail()
	}
	var cfg auditTrustConfig
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&cfg) != nil {
		return fail()
	}
	var extra any
	if decoder.Decode(&extra) != io.EOF {
		return fail()
	}
	if cfg.Environment != c.Environment || cfg.Namespace != c.Namespace || cfg.SourceManifestSHA256 != auditSourceManifestSHA || len(cfg.TrustedKeys) > 64 || (cfg.RequireAnchor && len(cfg.TrustedKeys) == 0) {
		return fail()
	}
	switch cfg.Protocol {
	case "zhiyu-audit-trust-v1":
		if cfg.ConfigSHA256 != auditConfigurationDigest(c) || len(cfg.NativeCatalogHashes) != 0 || len(cfg.HistoryAuthorityProfileHashes) != 0 {
			return fail()
		}
	case "zhiyu-audit-trust-v2":
		if len(cfg.HistoryAuthorityProfileHashes) > 64 || !sort.StringsAreSorted(cfg.HistoryAuthorityProfileHashes) || !reflect.DeepEqual(cfg.NativeCatalogHashes, auditNativeCatalogHashesV2()) || cfg.ConfigSHA256 != auditConfigurationDigestV2(c, cfg.HistoryAuthorityProfileHashes) {
			return fail()
		}
		for i, hash := range cfg.HistoryAuthorityProfileHashes {
			if !validAuditHash(hash) || i > 0 && hash == cfg.HistoryAuthorityProfileHashes[i-1] {
				return fail()
			}
		}
	default:
		return fail()
	}
	keys := map[string]ed25519.PublicKey{}
	pattern := regexp.MustCompile(`^[A-Za-z0-9_-]{1,64}$`)
	for id, encoded := range cfg.TrustedKeys {
		key, e := base64.StdEncoding.Strict().DecodeString(encoded)
		if e != nil || len(key) != ed25519.PublicKeySize || !pattern.MatchString(id) {
			return fail()
		}
		keys[id] = ed25519.PublicKey(append([]byte(nil), key...))
	}
	logger.Info("audit_configuration", "status", "CONFIGURED_NOT_VERIFIED")
	return app.AuditTrustOptions{TrustedKeys: keys, RequireAnchor: cfg.RequireAnchor, SourceManifestSHA256: cfg.SourceManifestSHA256, ConfigSHA256: cfg.ConfigSHA256, HistoryAuthorityProfileHashes: append([]string(nil), cfg.HistoryAuthorityProfileHashes...)}
}
