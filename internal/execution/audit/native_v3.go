package executionaudit

import (
	"bytes"
	"encoding/json"
	"fmt"
	"reflect"
	"sort"
	"strconv"

	evidence "zhiyu.local/zhiyu-go/internal/audit"
	"zhiyu.local/zhiyu-go/internal/execution/bankv2"
	funds "zhiyu.local/zhiyu-go/internal/funds/domain"
	policy "zhiyu.local/zhiyu-go/internal/policy/domain"
)

type NativeSnapshotV3 struct {
	BusinessSnapshot
	CatalogRevision       int
	MissingTables         []string
	BankReference         string
	RawSourceBytes        int64
	CompressedSourceBytes int64
}

type nativeRowDataV3 struct {
	businessRowData
	RawEncoding string `json:"raw_encoding"`
	RawBytes    int64  `json:"raw_bytes"`
}

type nativeSnapshotDataV3 struct {
	Environment           string           `json:"environment"`
	EnvironmentID         string           `json:"environment_id"`
	UserID                string           `json:"user_id"`
	Epoch                 string           `json:"epoch"`
	CatalogHash           string           `json:"catalog_hash"`
	Revision              int              `json:"catalog_revision"`
	Tables                []BusinessTable  `json:"tables"`
	Watermarks            map[string]int64 `json:"watermarks"`
	MissingTables         []string         `json:"missing_tables"`
	BankReference         string           `json:"independent_bank_id"`
	RawSourceBytes        int64            `json:"raw_source_bytes"`
	CompressedSourceBytes int64            `json:"compressed_source_bytes"`
}

func SealNativeRowV3(input BusinessRow) (evidence.Original, error) {
	if _, ok := nativeAuditTableV3(input.Table); !ok {
		return evidence.Original{}, fmt.Errorf("%w: native table outside v3 catalog", evidence.ErrUnsupportedVersion)
	}
	if _, err := evidence.ParseRawObject(input.Raw); err != nil {
		return evidence.Original{}, err
	}
	encoded, err := nativeEncodeBytesV3(input.Raw)
	if err != nil {
		return evidence.Original{}, err
	}
	data := businessData(input.Scope)
	data["table"], data["row_key"], data["raw_hex"], data["raw_sha256"] = input.Table, input.RowKey, encoded, nakedHash(input.Raw)
	data["raw_encoding"], data["raw_bytes"] = "GZIP", int64(len(input.Raw))
	doc := evidence.Document{SchemaVersion: evidence.SchemaVersion, CanonicalVersion: evidence.CanonicalVersion, HashAlgorithm: evidence.HashAlgorithm, Simulation: true, ID: RowID(input.Table, input.RowKey), Kind: NativeRowKindV3, SemanticVersion: NativeRowVersionV3, Outcome: "RETAINED", Data: data, References: []evidence.Reference{}}
	if _, _, err := readNativeRowV3(doc); err != nil {
		return evidence.Original{}, err
	}
	return evidence.Seal(doc)
}

func SealNativeSnapshotV3(input NativeSnapshotV3) (evidence.Original, error) {
	revision := input.CatalogRevision
	if revision == 0 {
		revision = NativeCatalogRevisionV3
	}
	data := nativeSnapshotDataV3{Environment: input.Scope.Namespace, EnvironmentID: input.Scope.EnvironmentID, UserID: input.Scope.UserID, Epoch: input.Scope.Epoch, CatalogHash: NativeAuditCatalogHashV3Revision(revision), Revision: revision, Tables: input.Tables, Watermarks: input.Watermarks, MissingTables: append([]string{}, input.MissingTables...), BankReference: input.BankReference, RawSourceBytes: input.RawSourceBytes, CompressedSourceBytes: input.CompressedSourceBytes}
	raw, err := json.Marshal(data)
	if err != nil {
		return evidence.Original{}, err
	}
	values, err := evidence.ParseObject(raw)
	if err != nil {
		return evidence.Original{}, err
	}
	refs := input.References
	if refs == nil {
		refs = []evidence.Reference{}
	}
	doc := evidence.Document{SchemaVersion: evidence.SchemaVersion, CanonicalVersion: evidence.CanonicalVersion, HashAlgorithm: evidence.HashAlgorithm, Simulation: true, ID: input.ID, Kind: NativeSnapshotKindV3, SemanticVersion: NativeSnapshotVersionV3, Outcome: "CAPTURED", Data: values, References: refs}
	if _, err = readNativeSnapshotV3(doc); err != nil {
		return evidence.Original{}, err
	}
	return evidence.Seal(doc)
}

func readNativeRowHeaderV3(doc evidence.Document) (nativeRowDataV3, NativeAuditTableV3, error) {
	var data nativeRowDataV3
	if doc.Kind != NativeRowKindV3 || doc.SemanticVersion != NativeRowVersionV3 || doc.Outcome != "RETAINED" || len(doc.Data) != 10 || len(doc.References) != 0 || decodeBusinessData(doc.Data, &data) != nil {
		return data, NativeAuditTableV3{}, businessInvalid("native v3 row envelope")
	}
	table, ok := nativeAuditTableV3(data.Table)
	if !ok {
		return data, table, fmt.Errorf("%w: native v3 table", evidence.ErrUnsupportedVersion)
	}
	if doc.ID != RowID(data.Table, data.RowKey) || len(data.RawHex) == 0 || len(data.RawHex) > evidence.MaxCanonicalBytes {
		return data, table, businessInvalid("native row identity or capacity")
	}
	if data.RawEncoding != "GZIP" {
		return data, table, fmt.Errorf("%w: native row encoding", evidence.ErrUnsupportedVersion)
	}
	if data.RawBytes < 1 || data.RawBytes > NativeMaximumRawRowBytesV3 {
		return data, table, fmt.Errorf("%w: native row decompression capacity", evidence.ErrIncomplete)
	}
	return data, table, nil
}

func readNativeRowV3(doc evidence.Document) (nativeRowDataV3, map[string]any, error) {
	data, table, err := readNativeRowHeaderV3(doc)
	if err != nil {
		return data, nil, err
	}
	raw, err := nativeDecodeBytesV3(data.RawHex, data.RawSHA256, data.RawEncoding, data.RawBytes)
	if err != nil {
		return data, nil, err
	}
	row, err := evidence.ParseRawObject(raw)
	if err != nil {
		return data, nil, err
	}
	keys := []string{}
	for _, name := range table.PrimaryKey {
		switch value := row[name].(type) {
		case string:
			keys = append(keys, value)
		case json.Number:
			n, err := value.Int64()
			if err != nil || n < 1 {
				return data, nil, businessInvalid("native numeric primary key")
			}
			keys = append(keys, strconv.FormatInt(n, 10))
		default:
			return data, nil, businessInvalid("native primary key field")
		}
	}
	if keyParts(keys...) != data.RowKey {
		return data, nil, businessInvalid("native primary key binding")
	}
	return data, row, nil
}

func nativeScopeV3(scope evidence.Scope, doc evidence.Document) error {
	for key, value := range businessData(scope) {
		if value == "" || doc.Data[key] != value {
			return businessInvalid("native captured scope")
		}
	}
	if doc.Kind != NativeRowKindV3 {
		return nil
	}
	// Defer decompression until the complete graph's raw-byte preflight.
	_, _, err := readNativeRowHeaderV3(doc)
	return err
}

func nativePhysicalScopeV3(scope evidence.Scope, data nativeRowDataV3, row map[string]any) error {
	if data.Table == "environments" {
		if row["id"] != scope.EnvironmentID || row["namespace"] != scope.Namespace {
			return businessInvalid("native environment row scope")
		}
	} else if row["environment_id"] != scope.EnvironmentID || data.Table == "users" && row["id"] != scope.UserID || data.Table != "users" && !nativeEnvironmentTableV3(data.Table) && row["user_id"] != scope.UserID {
		return businessInvalid("native physical row scope")
	}
	return nil
}

func readNativeSnapshotV3(doc evidence.Document) (nativeSnapshotDataV3, error) {
	var data nativeSnapshotDataV3
	if doc.Kind != NativeSnapshotKindV3 || doc.SemanticVersion != NativeSnapshotVersionV3 || doc.Outcome != "CAPTURED" || len(doc.Data) != 12 || decodeBusinessData(doc.Data, &data) != nil || data.CatalogHash != NativeAuditCatalogHashV3Revision(data.Revision) || data.CatalogHash == "" || data.RawSourceBytes < 1 || data.CompressedSourceBytes < 1 {
		return data, businessInvalid("native snapshot envelope or catalog")
	}
	catalog := NativeAuditTablesV3Revision(data.Revision)
	if len(data.Tables) != len(catalog) || data.MissingTables == nil || !sort.StringsAreSorted(data.MissingTables) {
		return data, businessInvalid("native complete declared catalog")
	}
	for i, table := range data.Tables {
		if table.Table != catalog[i].Name || table.IDs == nil || table.Count != int64(len(table.IDs)) || !sort.StringsAreSorted(table.IDs) {
			return data, businessInvalid("native exact table membership")
		}
		for j := range table.IDs {
			if j > 0 && table.IDs[j-1] == table.IDs[j] {
				return data, businessInvalid("native duplicate declared member")
			}
		}
	}
	for i, name := range data.MissingTables {
		if _, ok := nativeAuditTableV3(name); !ok || i > 0 && data.MissingTables[i-1] == name {
			return data, businessInvalid("native missing-table declaration")
		}
	}
	return data, nil
}

type nativeGraphV3 struct {
	verifierTrust           NativeVerifierTrustV3
	manifest                evidence.CaptureManifest
	snapshot                nativeSnapshotDataV3
	rows                    map[string]map[string]*ledgerRow
	bank                    *NativeIndependentBankV3
	ledger                  funds.IncomeLedger
	reservations            map[string]funds.IncomeReservation
	nativeRequests          map[string]bankv2.Request
	nativeReceipts          map[string]nativeReceiptV3
	legacy                  *businessGraph
	templates               map[string]policy.TemplateVersion
	nativeGrants            map[string]nativeGrantV3
	nativeGrantEvents       map[string][]nativeGrantStateV3
	occurrences             map[string]nativeOccurrenceV3
	jointPlans              map[string]wireNativeJointPlan
	nativeActions           map[string]any
	standingPlans           map[string]nativeStandingPlanV3
	onceApprovals           map[string]any
	usedNativeConfirmations map[string]bool
	forecastConsumers       []nativeForecastEconomicConsumerV3
}

func (g *nativeGraphV3) row(table string, keys ...string) *ledgerRow {
	if keys == nil {
		keys = []string{}
	}
	return g.rows[table][keyParts(keys...)]
}

func nativeGraphFromV3(manifest evidence.CaptureManifest, docs map[string]evidence.Document) (*nativeGraphV3, error) {
	if len(manifest.Roots) != 1 {
		return nil, businessInvalid("one complete native root required")
	}
	root := docs[manifest.Roots[0].ID]
	snapshot, err := readNativeSnapshotV3(root)
	if err != nil {
		return nil, err
	}
	if !reflect.DeepEqual(snapshot.Watermarks, manifest.Source.Watermarks) || len(snapshot.Watermarks) != 4 {
		return nil, businessInvalid("native source watermarks")
	}
	for _, key := range []string{"funds_version", "source_version", "writer_generation", "control_version"} {
		if snapshot.Watermarks[key] < 1 {
			return nil, businessInvalid("native positive source watermark")
		}
	}
	if manifest.Scope.Epoch != "writer:"+strconv.FormatInt(snapshot.Watermarks["writer_generation"], 10) {
		return nil, businessInvalid("native writer epoch")
	}
	var rawBytes, compressedBytes int64
	for _, doc := range docs {
		var size int64
		var compressed string
		switch doc.Kind {
		case NativeRowKindV3:
			header, _, err := readNativeRowHeaderV3(doc)
			if err != nil {
				return nil, err
			}
			size, compressed = header.RawBytes, header.RawHex
		case NativeBankKindV3:
			header, err := readNativeBankHeaderV3(doc)
			if err != nil {
				return nil, err
			}
			size, compressed = header.RawBytes, header.RawHex
		default:
			continue
		}
		if size > NativeMaximumRawCaptureBytesV3-rawBytes {
			return nil, fmt.Errorf("%w: native total decompressed capacity", evidence.ErrIncomplete)
		}
		rawBytes += size
		compressedBytes += int64(len(compressed) / 2)
	}
	if rawBytes != snapshot.RawSourceBytes || compressedBytes != snapshot.CompressedSourceBytes {
		return nil, businessInvalid("native raw/compressed source byte accounting")
	}
	g := &nativeGraphV3{manifest: manifest, snapshot: snapshot, rows: map[string]map[string]*ledgerRow{}}
	refs, members := map[string]string{}, map[string]string{}
	for _, ref := range root.References {
		if _, exists := refs[ref.ID]; exists {
			return nil, businessInvalid("native duplicate root reference")
		}
		refs[ref.ID] = ref.Digest
	}
	for _, member := range manifest.Members {
		members[member.ID] = member.Digest
	}
	count := 1
	if snapshot.BankReference != "" {
		doc, exists := docs[snapshot.BankReference]
		if !exists || refs[snapshot.BankReference] == "" || refs[snapshot.BankReference] != members[snapshot.BankReference] || nativeScopeV3(manifest.Scope, doc) != nil {
			return nil, businessInvalid("native independent bank member binding")
		}
		bank, err := readNativeBankV3(doc, manifest.Scope)
		if err != nil {
			return nil, err
		}
		g.bank = &bank
		delete(refs, snapshot.BankReference)
		count++
	}
	for _, table := range snapshot.Tables {
		g.rows[table.Table] = map[string]*ledgerRow{}
		for _, id := range table.IDs {
			doc, exists := docs[id]
			if !exists || refs[id] == "" || refs[id] != members[id] {
				return nil, businessInvalid("native missing root/member row agreement")
			}
			data, row, err := readNativeRowV3(doc)
			if err != nil {
				return nil, err
			}
			if data.Table != table.Table || nativeScopeV3(manifest.Scope, doc) != nil || nativePhysicalScopeV3(manifest.Scope, data, row) != nil {
				return nil, businessInvalid("native row table/scope")
			}
			if g.rows[table.Table][data.RowKey] != nil {
				return nil, businessInvalid("native duplicate physical row")
			}
			g.rows[table.Table][data.RowKey] = &ledgerRow{values: row}
			delete(refs, id)
			count++
		}
	}
	if len(refs) != 0 || len(docs) != count || len(g.rows["users"]) != 1 || len(g.rows["environments"]) != 1 {
		return nil, businessInvalid("native undeclared graph membership")
	}
	u, e := g.row("users", manifest.Scope.UserID), g.row("environments", manifest.Scope.EnvironmentID)
	if u == nil || e == nil || u.positive("funds_version") != snapshot.Watermarks["funds_version"] || u.positive("source_version") != snapshot.Watermarks["source_version"] || e.positive("writer_generation") != snapshot.Watermarks["writer_generation"] || e.positive("control_version") != snapshot.Watermarks["control_version"] {
		return nil, businessInvalid("native physical source watermark binding")
	}
	return g, nil
}

// RegisterNativeBusinessV3 never broadens the old v1/v2 registry. During
// incremental implementation a structurally complete capture remains
// INCOMPLETE until every financial family and independent source is checked.
func RegisterNativeBusinessV3(registry *evidence.Registry) error {
	return RegisterNativeBusinessV3WithTrust(registry, NativeVerifierTrustV3{})
}

func RegisterNativeBusinessV3WithTrust(registry *evidence.Registry, trust NativeVerifierTrustV3) error {
	trust.HistoryAuthorityProfileHashes = append([]string(nil), trust.HistoryAuthorityProfileHashes...)
	if len(trust.HistoryAuthorityProfileHashes) > 64 {
		return businessInvalid("native external history profile trust capacity")
	}
	for _, hash := range trust.HistoryAuthorityProfileHashes {
		if _, err := funds.ParseEvidenceHash(hash); err != nil {
			return businessInvalid("native external history profile hash")
		}
	}
	if err := registry.Register(NativeRowKindV3, NativeRowVersionV3, func(doc evidence.Document) error { _, _, err := readNativeRowHeaderV3(doc); return err }); err != nil {
		return err
	}
	if err := registry.Register(NativeSnapshotKindV3, NativeSnapshotVersionV3, func(doc evidence.Document) error { _, err := readNativeSnapshotV3(doc); return err }); err != nil {
		return err
	}
	if err := registry.Register(NativeBankKindV3, NativeBankVersionV3, func(doc evidence.Document) error { _, err := readNativeBankHeaderV3(doc); return err }); err != nil {
		return err
	}
	for _, pair := range [][2]string{{NativeRowKindV3, NativeRowVersionV3}, {NativeSnapshotKindV3, NativeSnapshotVersionV3}, {NativeBankKindV3, NativeBankVersionV3}} {
		if err := registry.RegisterScopeValidator(pair[0], pair[1], nativeScopeV3); err != nil {
			return err
		}
	}
	return registry.RegisterGraphValidator(NativeSnapshotKindV3, NativeSnapshotVersionV3, func(manifest evidence.CaptureManifest, docs map[string]evidence.Document) error {
		return ValidateNativeFinancialGraphV3WithTrust(manifest, docs, trust)
	})
}

// ValidateNativeFinancialGraphV3 checks an already captured graph without I/O.
// The returned error retains a deterministic semantic cause for local diagnostics;
// public verification results continue to apply the generic safe error policy.
func ValidateNativeFinancialGraphV3(manifest evidence.CaptureManifest, docs map[string]evidence.Document) error {
	return ValidateNativeFinancialGraphV3WithTrust(manifest, docs, NativeVerifierTrustV3{})
}

func ValidateNativeFinancialGraphV3WithTrust(manifest evidence.CaptureManifest, docs map[string]evidence.Document, trust NativeVerifierTrustV3) error {
	g, err := nativeGraphFromV3(manifest, docs)
	if err != nil {
		return err
	}
	g.verifierTrust = trust
	if len(g.snapshot.MissingTables) > 0 {
		return fmt.Errorf("%w: declared native catalog table unavailable", evidence.ErrIncomplete)
	}
	checks := []struct {
		name     string
		validate func() error
	}{{"income", g.checkIncomeV3}, {"goal-lots", g.checkGoalLotsV3}, {"native-operations", g.checkNativeOperationsV3}, {"legacy", g.checkLegacyV3}, {"legacy-standing", g.checkLegacyStandingV3}, {"independent-bank", g.checkBankAgreementV3}, {"income-snapshot-evidence", g.checkIncomeSnapshotEvidenceV3}, {"recovery", g.checkRecoveryV3}, {"history-sources", g.checkHistorySourcesV3}, {"inventory-protection", g.checkInventoryAndProtectionV3}, {"templates", g.checkTemplatesV3}, {"bills-obligations", g.billSourcesAndObligations}, {"native-grants", g.checkNativeGrantsV3}, {"occurrences", g.checkOccurrencesV3}, {"automation-event-receipts", g.checkAutomationEventReceiptsV3}, {"standing-budget", g.checkStandingBudgetV3}, {"candidates", g.checkCandidatesV3}, {"finite-questions", g.checkQuestionsV3}, {"bridge-groups", g.checkBridgeGroupsV3}, {"once-user", g.checkOnceV3}, {"orphan-sources", g.checkOrphanSourcesV3}, {"historical-t2", g.checkPermitsV3}, {"resources", g.checkResourcesV3}, {"goal-configuration", g.checkGoalConfigurationV3}, {"native-settlement-events", g.checkNativeSettlementEventsV3}, {"legacy-settlement-events", g.checkLegacySettlementEventsV3}, {"event-evidence-coverage", g.checkEventEvidenceCoverageV3}, {"template-source-witnesses", g.checkTemplateSourceWitnessesV3}, {"forecast-economic-prefixes", g.checkForecastEconomicPrefixesV3}}
	for _, check := range checks {
		if err := check.validate(); err != nil {
			return &evidence.ReferenceError{ID: "native-v3:" + check.name, Cause: err}
		}
	}
	if err := g.checkLegacyEconomicPrefixesV3(); err != nil {
		return &evidence.ReferenceError{ID: "native-v3:legacy-economic-prefixes", Cause: err}
	}
	// Revision 26 has all registered financial closures above. This conclusion
	// covers only the captured graph; product and release acceptance are separate.
	if g.snapshot.Revision == 26 {
		return nil
	}
	return &evidence.ReferenceError{ID: "native-v3:remaining-financial-closures", Cause: fmt.Errorf("%w: native independent-bank and financial closures are not yet registered", evidence.ErrIncomplete)}
}

// Compact originals use their exact bytes; PostgreSQL's to_jsonb(row)::text is
// retained separately and never silently re-encoded before its raw digest.
func nativeCompactOriginalV3(raw []byte, target any) error {
	if _, err := evidence.ParseRawObject(raw); err != nil {
		return err
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(target) != nil {
		return businessInvalid("native compact original schema")
	}
	encoded, err := json.Marshal(target)
	if err != nil || !bytes.Equal(raw, encoded) {
		return businessInvalid("native original compact bytes")
	}
	return nil
}
