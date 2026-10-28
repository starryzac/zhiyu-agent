package executionaudit

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"time"

	evidence "zhiyu.local/zhiyu-go/internal/audit"
	execution "zhiyu.local/zhiyu-go/internal/execution/domain"
	funds "zhiyu.local/zhiyu-go/internal/funds/domain"
	planning "zhiyu.local/zhiyu-go/internal/planning/domain"
	policy "zhiyu.local/zhiyu-go/internal/policy/domain"
)

const (
	BusinessRowKind           = "LEDGER_ROW"
	BusinessRowVersion        = "ledger-row-v1"
	BusinessSnapshotKind      = "USER_LEDGER_SNAPSHOT"
	BusinessSnapshotVersion   = "user-ledger-snapshot-v1"
	BusinessRowVersionV2      = "ledger-row-v2"
	BusinessSnapshotVersionV2 = "user-ledger-snapshot-v2"
)

// BusinessRow preserves the exact PostgreSQL to_jsonb(row)::text bytes. Sealing
// records a claim; it deliberately does not certify the financial contents.
type BusinessRow struct {
	Scope         evidence.Scope
	Table, RowKey string
	Raw           []byte
}

type BusinessTable struct {
	Table string   `json:"table"`
	Count int64    `json:"count"`
	IDs   []string `json:"ids"`
}

type BusinessSnapshot struct {
	ID         string
	Scope      evidence.Scope
	Tables     []BusinessTable
	Watermarks map[string]int64
	References []evidence.Reference
}

var businessPrimaryKeys = map[string][]string{
	"users": {"id"}, "accounts": {"id"}, "goals": {"id"},
	"income_origins": {"id"}, "income_locations": {"id"},
	"income_reservations": {"action_id"}, "income_claims": {"action_id", "fragment_id"},
	"policies": {"id", "version"}, "grants": {"id", "version"},
	"confirmations": {"id"}, "plans": {"id"}, "operations": {"id"},
	"journals": {"id"}, "postings": {"journal_id", "leg_ref"},
	"receipts": {"id"}, "bank_observations": {"id"}, "evidence_blobs": {"id"},
}

func RowID(table, rowKey string) string {
	digest := sha256.Sum256([]byte(table + "\x00" + rowKey))
	return "row:" + table + ":" + hex.EncodeToString(digest[:])
}

func businessData(scope evidence.Scope) map[string]any {
	return map[string]any{"environment": scope.Namespace, "environment_id": scope.EnvironmentID, "user_id": scope.UserID, "epoch": scope.Epoch}
}

func SealRow(input BusinessRow) (evidence.Original, error) {
	return sealBusinessRow(input, BusinessRowVersion)
}
func SealRowV2(input BusinessRow) (evidence.Original, error) {
	return sealBusinessRow(input, BusinessRowVersionV2)
}
func sealBusinessRow(input BusinessRow, version string) (evidence.Original, error) {
	if _, err := evidence.ParseRawObject(input.Raw); err != nil {
		return evidence.Original{}, err
	}
	var keys []string
	if json.Unmarshal([]byte(input.RowKey), &keys) != nil || keys == nil {
		return evidence.Original{}, businessInvalid("row key format")
	}
	compact, _ := json.Marshal(keys)
	if string(compact) != input.RowKey {
		return evidence.Original{}, businessInvalid("row key must be compact")
	}
	data := businessData(input.Scope)
	digest := sha256.Sum256(input.Raw)
	data["table"], data["row_key"] = input.Table, input.RowKey
	data["raw_hex"], data["raw_sha256"] = hex.EncodeToString(input.Raw), hex.EncodeToString(digest[:])
	return evidence.Seal(evidence.Document{SchemaVersion: evidence.SchemaVersion, CanonicalVersion: evidence.CanonicalVersion,
		HashAlgorithm: evidence.HashAlgorithm, Simulation: true, ID: RowID(input.Table, input.RowKey),
		Kind: BusinessRowKind, SemanticVersion: version, Outcome: "RETAINED", Data: data, References: []evidence.Reference{}})
}

func SealSnapshot(input BusinessSnapshot) (evidence.Original, error) {
	return sealBusinessSnapshot(input, BusinessSnapshotVersion)
}
func SealSnapshotV2(input BusinessSnapshot) (evidence.Original, error) {
	return sealBusinessSnapshot(input, BusinessSnapshotVersionV2)
}
func sealBusinessSnapshot(input BusinessSnapshot, version string) (evidence.Original, error) {
	data := businessData(input.Scope)
	tables := make([]any, len(input.Tables))
	for i, table := range input.Tables {
		ids := make([]any, len(table.IDs))
		for j, id := range table.IDs {
			ids[j] = id
		}
		tables[i] = map[string]any{"table": table.Table, "count": table.Count, "ids": ids}
	}
	watermarks := map[string]any{}
	for key, value := range input.Watermarks {
		watermarks[key] = value
	}
	data["tables"], data["watermarks"] = tables, watermarks
	refs := input.References
	if refs == nil {
		refs = []evidence.Reference{}
	}
	return evidence.Seal(evidence.Document{SchemaVersion: evidence.SchemaVersion, CanonicalVersion: evidence.CanonicalVersion,
		HashAlgorithm: evidence.HashAlgorithm, Simulation: true, ID: input.ID, Kind: BusinessSnapshotKind,
		SemanticVersion: version, Outcome: "CAPTURED", Data: data, References: refs})
}

func primaryKeys(version string) map[string][]string {
	if version == BusinessRowVersion || version == BusinessSnapshotVersion {
		return businessPrimaryKeys
	}
	if version != BusinessRowVersionV2 && version != BusinessSnapshotVersionV2 {
		return nil
	}
	keys := make(map[string][]string, len(businessPrimaryKeys)+2)
	for table, columns := range businessPrimaryKeys {
		keys[table] = columns
	}
	keys["submission_permits"] = []string{"operation_id"}
	keys["audit_session_subjects"] = []string{"id"}
	return keys
}

type businessRowData struct {
	Environment   string `json:"environment"`
	EnvironmentID string `json:"environment_id"`
	UserID        string `json:"user_id"`
	Epoch         string `json:"epoch"`
	Table         string `json:"table"`
	RowKey        string `json:"row_key"`
	RawHex        string `json:"raw_hex"`
	RawSHA256     string `json:"raw_sha256"`
}

type businessSnapshotData struct {
	Environment   string           `json:"environment"`
	EnvironmentID string           `json:"environment_id"`
	UserID        string           `json:"user_id"`
	Epoch         string           `json:"epoch"`
	Tables        []BusinessTable  `json:"tables"`
	Watermarks    map[string]int64 `json:"watermarks"`
}

func businessInvalid(reason string) error {
	return fmt.Errorf("%w: business closure: %s", evidence.ErrInvalid, reason)
}

func decodeBusinessData(data map[string]any, target any) error {
	raw, err := json.Marshal(data)
	if err != nil {
		return businessInvalid("data encoding")
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if err = d.Decode(target); err != nil {
		return businessInvalid("data shape")
	}
	return nil
}

func readBusinessRow(doc evidence.Document) (businessRowData, map[string]any, error) {
	var data businessRowData
	if doc.Kind != BusinessRowKind || (doc.SemanticVersion != BusinessRowVersion && doc.SemanticVersion != BusinessRowVersionV2) || doc.Outcome != "RETAINED" || len(doc.References) != 0 || len(doc.Data) != 8 || decodeBusinessData(doc.Data, &data) != nil {
		return data, nil, businessInvalid("row envelope")
	}
	primary := primaryKeys(doc.SemanticVersion)[data.Table]
	if primary == nil || doc.ID != RowID(data.Table, data.RowKey) || len(data.RawHex) > 2*evidence.MaxCanonicalBytes {
		return data, nil, businessInvalid("row identity or capacity")
	}
	raw, err := hex.DecodeString(data.RawHex)
	if err != nil {
		return data, nil, businessInvalid("raw row hex")
	}
	digest := sha256.Sum256(raw)
	if data.RawSHA256 != hex.EncodeToString(digest[:]) {
		return data, nil, businessInvalid("raw row digest")
	}
	row, err := evidence.ParseRawObject(raw)
	if err != nil {
		return data, nil, err
	}
	keys := make([]string, len(primary))
	for i, field := range primary {
		switch value := row[field].(type) {
		case string:
			keys[i] = value
		case json.Number:
			integer, err := value.Int64()
			if err != nil || integer <= 0 {
				return data, nil, businessInvalid("primary key integer")
			}
			keys[i] = strconv.FormatInt(integer, 10)
		default:
			return data, nil, businessInvalid("primary key fields")
		}
	}
	keyRaw, _ := json.Marshal(keys)
	if string(keyRaw) != data.RowKey {
		return data, nil, businessInvalid("primary key binding")
	}
	return data, row, nil
}

func businessScope(scope evidence.Scope, doc evidence.Document) error {
	for key, expected := range businessData(scope) {
		if doc.Data[key] != expected || expected == "" {
			return businessInvalid("captured scope")
		}
	}
	if doc.Kind == BusinessRowKind {
		data, row, err := readBusinessRow(doc)
		if err != nil {
			return err
		}
		if row["environment_id"] != scope.EnvironmentID || data.Table == "users" && row["id"] != scope.UserID || data.Table != "users" && row["user_id"] != scope.UserID {
			return businessInvalid("raw row scope")
		}
	}
	return nil
}

func validateBusinessSnapshot(doc evidence.Document) error {
	var data businessSnapshotData
	if doc.Kind != BusinessSnapshotKind || (doc.SemanticVersion != BusinessSnapshotVersion && doc.SemanticVersion != BusinessSnapshotVersionV2) || doc.Outcome != "CAPTURED" || len(doc.Data) != 6 || decodeBusinessData(doc.Data, &data) != nil || len(data.Tables) != len(primaryKeys(doc.SemanticVersion)) {
		return businessInvalid("snapshot envelope")
	}
	for i, table := range data.Tables {
		if primaryKeys(doc.SemanticVersion)[table.Table] == nil || i > 0 && data.Tables[i-1].Table >= table.Table || table.IDs == nil || table.Count != int64(len(table.IDs)) || !sort.StringsAreSorted(table.IDs) {
			return businessInvalid("table membership")
		}
	}
	tables, ok := doc.Data["tables"].([]any)
	if !ok {
		return businessInvalid("tables array shape")
	}
	for _, value := range tables {
		table, ok := value.(map[string]any)
		if !ok || len(table) != 3 || table["table"] == nil || table["count"] == nil || table["ids"] == nil {
			return businessInvalid("table exact protocol fields")
		}
	}
	return nil
}

func RegisterBusiness(registry *evidence.Registry) error {
	if err := registry.Register(BusinessRowKind, BusinessRowVersion, func(doc evidence.Document) error {
		_, _, err := readBusinessRow(doc)
		return err
	}); err != nil {
		return err
	}
	if err := registry.Register(BusinessSnapshotKind, BusinessSnapshotVersion, validateBusinessSnapshot); err != nil {
		return err
	}
	if err := registry.Register(BusinessRowKind, BusinessRowVersionV2, func(doc evidence.Document) error { _, _, err := readBusinessRow(doc); return err }); err != nil {
		return err
	}
	if err := registry.Register(BusinessSnapshotKind, BusinessSnapshotVersionV2, validateBusinessSnapshot); err != nil {
		return err
	}
	for _, kind := range []struct{ kind, version string }{{BusinessRowKind, BusinessRowVersion}, {BusinessSnapshotKind, BusinessSnapshotVersion}, {BusinessRowKind, BusinessRowVersionV2}, {BusinessSnapshotKind, BusinessSnapshotVersionV2}} {
		if err := registry.RegisterScopeValidator(kind.kind, kind.version, businessScope); err != nil {
			return err
		}
	}
	rowGraph := func(manifest evidence.CaptureManifest, decoded map[string]evidence.Document) error {
		for _, root := range manifest.Roots {
			if decoded[root.ID].Kind == BusinessSnapshotKind {
				return nil
			}
		}
		return businessInvalid("rows lack a declared complete snapshot root")
	}
	if err := registry.RegisterGraphValidator(BusinessRowKind, BusinessRowVersion, rowGraph); err != nil {
		return err
	}
	if err := registry.RegisterGraphValidator(BusinessRowKind, BusinessRowVersionV2, rowGraph); err != nil {
		return err
	}
	if err := registry.RegisterGraphValidator(BusinessSnapshotKind, BusinessSnapshotVersion, validateBusinessGraph); err != nil {
		return err
	}
	return registry.RegisterGraphValidator(BusinessSnapshotKind, BusinessSnapshotVersionV2, validateBusinessGraph)
}

// ledgerRow is a bounded, exact-integer view of a retained PostgreSQL row. All
// accessor failures are sticky and checked before the row can be accepted.
type ledgerRow struct {
	values map[string]any
	err    error
}

func (r *ledgerRow) fail(field string) {
	if r.err == nil {
		r.err = businessInvalid("row field " + field)
	}
}
func (r *ledgerRow) text(field string) string {
	v, ok := r.values[field].(string)
	if !ok || v == "" {
		r.fail(field)
	}
	return v
}
func (r *ledgerRow) optional(field string) string {
	if r.values[field] == nil {
		return ""
	}
	return r.text(field)
}
func (r *ledgerRow) integer(field string) int64 {
	v, ok := r.values[field].(json.Number)
	if !ok {
		r.fail(field)
		return 0
	}
	n, err := v.Int64()
	if err != nil || n < 0 {
		r.fail(field)
	}
	return n
}
func (r *ledgerRow) positive(field string) int64 {
	n := r.integer(field)
	if n == 0 {
		r.fail(field)
	}
	return n
}
func (r *ledgerRow) boolean(field string) bool {
	v, ok := r.values[field].(bool)
	if !ok {
		r.fail(field)
	}
	return v
}
func (r *ledgerRow) id(field string) funds.ID {
	id, err := funds.ParseID(r.text(field))
	if err != nil || id == (funds.ID{}) {
		r.fail(field)
	}
	return id
}
func (r *ledgerRow) money(field string) funds.Money {
	m, err := funds.NewMoney(r.integer(field))
	if err != nil {
		r.fail(field)
	}
	return m
}
func (r *ledgerRow) instant(field string) time.Time {
	t, err := time.Parse(time.RFC3339Nano, r.text(field))
	if err != nil || t.IsZero() {
		r.fail(field)
	}
	return t
}
func (r *ledgerRow) raw(field string) []byte {
	s := r.text(field)
	if !strings.HasPrefix(s, `\x`) || len(s) > 2*evidence.MaxCanonicalBytes+2 {
		r.fail(field)
		return nil
	}
	b, err := hex.DecodeString(s[2:])
	if err != nil {
		r.fail(field)
	}
	return b
}
func (r *ledgerRow) original(field string, target any) []byte {
	b := r.raw(field)
	if _, err := evidence.ParseRawObject(b); err != nil {
		r.fail(field)
		return b
	}
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if err := d.Decode(target); err != nil {
		r.fail(field)
	}
	return b
}
func (r *ledgerRow) object(field string, target any) {
	b, err := json.Marshal(r.values[field])
	if err != nil {
		r.fail(field)
		return
	}
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if err := d.Decode(target); err != nil {
		r.fail(field)
	}
}
func keyParts(parts ...string) string { b, _ := json.Marshal(parts); return string(b) }
func versionKey(id string, version uint64) string {
	return keyParts(id, strconv.FormatUint(version, 10))
}
func nakedHash(b []byte) string { h := sha256.Sum256(b); return hex.EncodeToString(h[:]) }
func exactJSON(a, b any) bool {
	x, e := json.Marshal(a)
	y, f := json.Marshal(b)
	return e == nil && f == nil && bytes.Equal(x, y)
}

type businessGraph struct {
	v2 bool
	// Only native v3 with causal originals defers the old allocation-only
	// current-row approximation to its mandatory exact historical FV check.
	nativePlanPrefixes bool
	manifest           evidence.CaptureManifest
	rows               map[string]map[string]*ledgerRow
	policies           map[string]policy.Policy
	grants             map[string]policy.Grant
	confirmations      map[string]policy.ConfirmationSource
	plans              map[string]planning.Candidate
	inputs             map[string]frozenBusinessInput
	requests           map[string]execution.BankRequest
	results            map[string][]execution.BankResult
	reservations       map[string]funds.IncomeReservation
	ledger             funds.IncomeLedger
}

// This wire contract mirrors the immutable single-goal input, not an app
// service. Replaying it never fills missing fields from today's ledger.
type frozenBusinessInput struct {
	Policy           policy.Policy             `json:"policy"`
	ScopeAccounts    []funds.ID                `json:"scope_accounts"`
	OriginFacts      []funds.BankCreditFact    `json:"origin_facts"`
	Locations        []funds.IncomeLocation    `json:"locations"`
	Reservations     []funds.IncomeReservation `json:"reservations"`
	Cash             []funds.CashLocationFact  `json:"cash"`
	GoalTarget       funds.Money               `json:"goal_target"`
	GoalAssigned     funds.Money               `json:"goal_assigned"`
	MonthContributed funds.Money               `json:"month_contributed"`
	MonthPeriod      string                    `json:"month_period"`
	Protection       planning.Protection       `json:"protection"`
	Dependencies     planning.DependencyVector `json:"dependencies"`
	Now              time.Time                 `json:"now"`
}

func (g *businessGraph) row(table string, parts ...string) *ledgerRow {
	return g.rows[table][keyParts(parts...)]
}
func (g *businessGraph) scope(s policy.Scope) bool {
	return s.Validate() == nil && s.EnvironmentID.String() == g.manifest.Scope.EnvironmentID && s.UserID.String() == g.manifest.Scope.UserID &&
		g.row("accounts", s.SourceAccountID.String()) != nil && g.row("accounts", s.DestinationAccountID.String()) != nil &&
		g.row("goals", s.GoalID.String()) != nil && g.row("goals", s.GoalID.String()).text("account_id") == s.SourceAccountID.String() && s.SourceAccountID == s.DestinationAccountID
}

func validateBusinessGraph(manifest evidence.CaptureManifest, decoded map[string]evidence.Document) error {
	for _, value := range []string{manifest.Scope.EnvironmentID, manifest.Scope.UserID} {
		id, err := funds.ParseID(value)
		if err != nil || id == (funds.ID{}) || id.String() != value {
			return businessInvalid("scope UUID")
		}
	}
	if len(manifest.Roots) != 1 {
		return businessInvalid("one complete snapshot root required")
	}
	root := decoded[manifest.Roots[0].ID]
	if validateBusinessSnapshot(root) != nil {
		return businessInvalid("snapshot root")
	}
	var snapshot businessSnapshotData
	if decodeBusinessData(root.Data, &snapshot) != nil || !reflect.DeepEqual(snapshot.Watermarks, manifest.Source.Watermarks) || len(snapshot.Watermarks) != 4 {
		return businessInvalid("snapshot watermarks")
	}
	for _, key := range []string{"funds_version", "source_version", "writer_generation", "control_version"} {
		if snapshot.Watermarks[key] < 1 {
			return businessInvalid("positive known watermarks required")
		}
	}
	if manifest.Scope.Epoch != "writer:"+strconv.FormatInt(snapshot.Watermarks["writer_generation"], 10) {
		return businessInvalid("writer epoch binding")
	}
	g := &businessGraph{manifest: manifest, rows: map[string]map[string]*ledgerRow{}, policies: map[string]policy.Policy{}, grants: map[string]policy.Grant{}, confirmations: map[string]policy.ConfirmationSource{}, plans: map[string]planning.Candidate{}, inputs: map[string]frozenBusinessInput{}, requests: map[string]execution.BankRequest{}, results: map[string][]execution.BankResult{}, reservations: map[string]funds.IncomeReservation{}}
	g.v2 = root.SemanticVersion == BusinessSnapshotVersionV2
	refs := map[string]string{}
	for _, ref := range root.References {
		if refs[ref.ID] != "" {
			return businessInvalid("duplicate snapshot reference")
		}
		refs[ref.ID] = ref.Digest
	}
	members := map[string]string{}
	for _, member := range manifest.Members {
		members[member.ID] = member.Digest
	}
	for _, table := range snapshot.Tables {
		g.rows[table.Table] = map[string]*ledgerRow{}
		for i, id := range table.IDs {
			if i > 0 && table.IDs[i-1] >= id {
				return businessInvalid("duplicate table row")
			}
			doc, ok := decoded[id]
			if !ok || refs[id] == "" || refs[id] != members[id] {
				return businessInvalid("snapshot row membership")
			}
			data, row, err := readBusinessRow(doc)
			if err != nil {
				return err
			}
			if data.Table != table.Table || businessScope(manifest.Scope, doc) != nil {
				return businessInvalid("snapshot table or scope")
			}
			if g.v2 != (doc.SemanticVersion == BusinessRowVersionV2) {
				return businessInvalid("mixed row and snapshot scope versions")
			}
			if _, exists := g.rows[table.Table][data.RowKey]; exists {
				return businessInvalid("duplicate primary key")
			}
			g.rows[table.Table][data.RowKey] = &ledgerRow{values: row}
			delete(refs, id)
		}
	}
	count := 1
	for _, rows := range g.rows {
		count += len(rows)
	}
	if len(refs) != 0 || len(decoded) != count || len(g.rows["users"]) != 1 {
		return businessInvalid("undeclared or omitted membership")
	}
	u := g.row("users", manifest.Scope.UserID)
	if u == nil || u.positive("funds_version") != snapshot.Watermarks["funds_version"] || u.positive("source_version") != snapshot.Watermarks["source_version"] {
		return businessInvalid("user watermark binding")
	}
	for _, verify := range []func() error{g.checkLedger, g.checkPermissions, g.checkPlans, g.checkOperations, g.checkSettlementProjection} {
		if err := verify(); err != nil {
			return err
		}
	}
	for _, rows := range g.rows {
		for _, row := range rows {
			if row.err != nil {
				return row.err
			}
		}
	}
	if !g.v2 {
		return fmt.Errorf("%w: v1 snapshot lacks immutable T2 permit and non-credential session subjects", evidence.ErrIncomplete)
	}
	return g.checkSubmissionPermits()
}

func (g *businessGraph) checkLedger() error {
	user, _ := funds.ParseID(g.manifest.Scope.UserID)
	s := funds.LedgerSnapshot{UserID: user, Currency: funds.CNY, AsOf: g.manifest.Source.CapturedAt}
	for _, row := range g.rows["accounts"] {
		s.ScopeAccountIDs = append(s.ScopeAccountIDs, row.id("id"))
		if row.text("currency") != "CNY" || row.money("goal_owned_cents").Cents() > row.money("balance_cents").Cents() {
			return businessInvalid("account cash ownership")
		}
		row.instant("observed_at")
	}
	for _, row := range g.rows["income_origins"] {
		eh, err := funds.ParseEvidenceHash(row.text("evidence_hash"))
		if err != nil {
			return businessInvalid("income evidence hash")
		}
		fact := funds.BankCreditFact{TransactionID: row.id("id"), AccountID: row.id("original_account_id"), Currency: funds.Currency(row.text("currency")), Amount: row.money("amount_cents"), Role: funds.RoleIncome, Source: funds.BankConfirmed, OccurredAt: row.instant("occurred_at"), ObservedAt: row.instant("observed_at"), RecordedAt: row.instant("recorded_at"), EvidenceID: row.id("evidence_id"), EvidenceHash: eh}
		origin, err := funds.NewIncomeOrigin(fact)
		if err != nil {
			return businessInvalid("income origin")
		}
		if fact.RecordedAt.After(s.AsOf) {
			s.AsOf = fact.RecordedAt
		} // explicit injected business clocks may lead wall capture time.
		s.Origins = append(s.Origins, origin)
	}
	for _, row := range g.rows["income_locations"] {
		location := funds.IncomeLocation{FragmentID: row.id("id"), OriginID: row.id("origin_id"), AccountID: row.id("account_id"), Spent: row.money("spent_cents"), Assigned: row.money("assigned_cents"), Reserved: row.money("reserved_cents"), LegacyReserved: row.money("legacy_reserved_cents"), Available: row.money("available_cents")}
		if !location.LegacyReserved.IsZero() || !location.Spent.IsZero() {
			return fmt.Errorf("%w: legacy holds or spending require their business family", evidence.ErrUnsupportedVersion)
		}
		s.Locations = append(s.Locations, location)
	}
	for _, row := range g.rows["income_reservations"] {
		r := funds.IncomeReservation{ActionID: row.id("action_id"), Operation: funds.IncomeOperation(row.text("operation")), State: funds.ReservationState(row.text("state"))}
		if r.Operation != funds.AllocateGoal || row.optional("destination_account_id") != "" {
			return fmt.Errorf("%w: reservation operation family", evidence.ErrUnsupportedVersion)
		}
		if g.row("operations", r.ActionID.String()) == nil {
			return businessInvalid("orphan reservation")
		}
		for _, claim := range g.rows["income_claims"] {
			if claim.text("action_id") != r.ActionID.String() {
				continue
			}
			location := g.row("income_locations", claim.text("fragment_id"))
			if location == nil {
				return businessInvalid("claim location missing")
			}
			r.Uses = append(r.Uses, funds.IncomeUse{FragmentID: claim.id("fragment_id"), OriginID: location.id("origin_id"), AccountID: location.id("account_id"), Amount: claim.money("amount_cents")})
		}
		g.reservations[r.ActionID.String()] = r
		s.Reservations = append(s.Reservations, r)
	}
	for _, row := range g.rows["income_claims"] {
		if g.row("income_reservations", row.text("action_id")) == nil {
			return businessInvalid("orphan income claim")
		}
	}
	if len(s.ScopeAccountIDs) == 0 {
		if len(s.Origins)+len(s.Locations)+len(s.Reservations)+len(g.rows["goals"])+len(g.rows["plans"])+len(g.rows["operations"]) != 0 {
			return businessInvalid("missing accounts")
		}
		return nil
	}
	var err error
	g.ledger, err = funds.NewIncomeLedger(s)
	if err != nil {
		return businessInvalid("income conservation or exact live claims")
	}
	return nil
}

func (g *businessGraph) checkPermissions() error {
	for _, row := range g.rows["confirmations"] {
		var c policy.ConfirmationSource
		row.original("original", &c)
		if c.ID.String() != row.text("id") || c.EnvironmentID.String() != g.manifest.Scope.EnvironmentID || c.UserID.String() != g.manifest.Scope.UserID || c.PrincipalKind != "USER" ||
			c.TargetKind != row.text("target_kind") || c.TargetID.String() != row.text("target_id") || c.TargetVersion != uint64(row.positive("target_version")) || c.ReviewedHash != row.text("reviewed_hash") || !c.ConfirmedAt.Equal(row.instant("confirmed_at")) {
			return businessInvalid("USER confirmation original binding")
		}
		row.id("session_id")
		if row.optional("expires_at") == "" {
			if !c.ExpiresAt.IsZero() {
				return businessInvalid("confirmation expiry")
			}
		} else if !c.ExpiresAt.Equal(row.instant("expires_at")) {
			return businessInvalid("confirmation expiry")
		}
		g.confirmations[c.ID.String()] = c
	}
	usedConfirmations := map[string]bool{}
	for _, row := range g.rows["policies"] {
		var p policy.Policy
		row.original("original", &p)
		if p.ID.String() != row.text("id") || p.Version != uint64(row.positive("version")) || !g.scope(p.Scope) || p.Status != policy.Active || !exactJSON(g.confirmations[row.text("confirmation_id")], p.Confirmation) {
			return businessInvalid("reviewed policy original")
		}
		at := p.ValidFrom
		if p.Confirmation.ConfirmedAt.After(at) {
			at = p.Confirmation.ConfirmedAt
		}
		if _, err := p.EffectiveFrom(at); err != nil {
			return businessInvalid("policy permission/configuration")
		}
		if !lifecycle(row.text("status")) {
			return businessInvalid("policy lifecycle")
		}
		if row.boolean("is_current") {
			goal := g.row("goals", p.Scope.GoalID.String())
			if goal.optional("policy_id") != p.ID.String() || goal.positive("policy_version") != int64(p.Version) {
				return businessInvalid("current goal policy version")
			}
		}
		g.policies[versionKey(p.ID.String(), p.Version)] = p
		usedConfirmations[p.Confirmation.ID.String()] = true
	}
	for _, row := range g.rows["grants"] {
		var grant policy.Grant
		row.original("original", &grant)
		p, ok := g.policies[versionKey(grant.PolicyID.String(), grant.PolicyVersion)]
		if !ok || grant.ID.String() != row.text("id") || grant.Version != uint64(row.positive("version")) || grant.PolicyID.String() != row.text("policy_id") || grant.PolicyVersion != uint64(row.positive("policy_version")) || grant.Status != policy.Active || !g.scope(grant.Scope) || !exactJSON(g.confirmations[row.text("confirmation_id")], grant.Confirmation) || !lifecycle(row.text("status")) {
			return businessInvalid("reviewed grant version")
		}
		at := grant.EffectiveFrom
		for _, t := range []time.Time{p.ValidFrom, p.Confirmation.ConfirmedAt, grant.Confirmation.ConfirmedAt} {
			if t.After(at) {
				at = t
			}
		}
		if _, err := policy.CheckGrant(p, grant, at); err != nil {
			return businessInvalid("grant permission/configuration")
		}
		row.boolean("is_current")
		g.grants[versionKey(grant.ID.String(), grant.Version)] = grant
		usedConfirmations[grant.Confirmation.ID.String()] = true
	}
	for id, c := range g.confirmations {
		if c.TargetKind == "PLAN" {
			continue
		} // Single-use PLAN sources are checked with their operation below.
		if !usedConfirmations[id] {
			return businessInvalid("orphan reviewed confirmation")
		}
	}
	for _, row := range g.rows["goals"] {
		row.id("id")
		if g.row("accounts", row.text("account_id")) == nil || row.money("assigned_cents").Cents() > row.money("target_cents").Cents() || row.positive("version") == 0 || row.money("target_cents").IsZero() {
			return businessInvalid("goal account or target")
		}
		if pID := row.optional("policy_id"); pID != "" {
			p, ok := g.policies[versionKey(pID, uint64(row.positive("policy_version")))]
			pr := g.row("policies", pID, strconv.FormatInt(row.positive("policy_version"), 10))
			if !ok || p.Scope.GoalID.String() != row.text("id") || pr == nil || !pr.boolean("is_current") {
				return businessInvalid("goal current policy")
			}
		} else if row.values["policy_version"] != nil {
			return businessInvalid("partial goal policy")
		}
		period := row.text("month_period")
		t, err := time.Parse("2006-01", period)
		if err != nil || t.Format("2006-01") != period {
			return businessInvalid("goal month period")
		}
		row.money("month_contributed_cents")
	}
	return nil
}
func lifecycle(s string) bool { return s == "ACTIVE" || s == "PAUSED" || s == "REVOKED" }

func replayBusinessPlan(in frozenBusinessInput) (planning.Candidate, error) {
	origins := make([]funds.IncomeOrigin, len(in.OriginFacts))
	for i, fact := range in.OriginFacts {
		var err error
		origins[i], err = funds.NewIncomeOrigin(fact)
		if err != nil {
			return planning.Candidate{}, err
		}
	}
	ledger, err := funds.NewIncomeLedger(funds.LedgerSnapshot{UserID: in.Policy.Scope.UserID, Currency: in.Policy.Scope.Currency, AsOf: in.Now, ScopeAccountIDs: in.ScopeAccounts, Origins: origins, Locations: in.Locations, Reservations: in.Reservations})
	if err != nil {
		return planning.Candidate{}, err
	}
	return planning.PlanSingleGoal(planning.Input{Policy: in.Policy, Ledger: ledger, Cash: in.Cash, GoalTarget: in.GoalTarget, GoalAssigned: in.GoalAssigned, MonthContributed: in.MonthContributed, MonthPeriod: in.MonthPeriod, Protection: in.Protection, Dependencies: in.Dependencies, Now: in.Now})
}

func (g *businessGraph) checkPlans() error {
	for _, row := range g.rows["plans"] {
		var c planning.Candidate
		var in frozenBusinessInput
		raw := row.original("candidate", &c)
		row.original("input", &in)
		var deps planning.DependencyVector
		row.object("dependencies", &deps)
		p, ok := g.policies[versionKey(row.text("policy_id"), uint64(row.positive("policy_version")))]
		replayed, err := replayBusinessPlan(in)
		expected, _ := json.Marshal(replayed)
		if !ok || err != nil || !bytes.Equal(raw, expected) || !exactJSON(in.Policy, p) || c.ID.String() != row.text("id") || c.PolicyID != p.ID || c.PolicyVersion != p.Version || !g.scope(c.Scope) || c.Scope.GoalID.String() != row.text("goal_id") || c.EffectHash != row.text("effect_hash") || c.InputHash != row.text("input_hash") || c.Dependencies != deps || !c.PreparedAt.Equal(row.instant("created_at")) || !c.ValidUntil.Equal(row.instant("expires_at")) {
			return businessInvalid("frozen plan replay or row binding")
		}
		if deps.FundsVersion > uint64(g.manifest.Source.Watermarks["funds_version"]) || deps.SourceEvidenceVersion > uint64(g.manifest.Source.Watermarks["source_version"]) || deps.WriterGeneration > uint64(g.manifest.Source.Watermarks["writer_generation"]) || deps.ControlVersion > uint64(g.manifest.Source.Watermarks["control_version"]) {
			return businessInvalid("future plan dependencies")
		}
		if gid := row.optional("grant_id"); gid != "" {
			grant, ok := g.grants[versionKey(gid, uint64(row.positive("grant_version")))]
			if !ok || grant.Version != deps.GrantVersion || grant.PolicyID != p.ID || grant.PolicyVersion != p.Version {
				return businessInvalid("plan grant dependency")
			}
		} else if deps.GrantVersion != 0 || row.values["grant_version"] != nil {
			return businessInvalid("missing plan grant version")
		}
		// Frozen income facts are immutable across later assignments and revocation.
		for _, fact := range in.OriginFacts {
			current := g.row("income_origins", fact.TransactionID.String())
			if current == nil || fact.AccountID.String() != current.text("original_account_id") || fact.Amount != current.money("amount_cents") || !fact.OccurredAt.Equal(current.instant("occurred_at")) || !fact.ObservedAt.Equal(current.instant("observed_at")) || !fact.RecordedAt.Equal(current.instant("recorded_at")) || fact.EvidenceID.String() != current.text("evidence_id") || fact.EvidenceHash.String() != current.text("evidence_hash") {
				return businessInvalid("frozen origin identity")
			}
		}
		if !g.nativePlanPrefixes {
			goal := g.row("goals", c.Scope.GoalID.String())
			if in.GoalTarget != goal.money("target_cents") || in.GoalAssigned.Cents() > goal.integer("assigned_cents") {
				return businessInvalid("frozen goal capacity is inconsistent with captured goal")
			}
			for _, cash := range in.Cash {
				current := g.row("accounts", cash.AccountID.String())
				if current == nil || cash.Currency != funds.CNY || cash.Balance != current.money("balance_cents") || cash.GoalOwned.Cents() > current.integer("goal_owned_cents") {
					return businessInvalid("frozen cash scope or allocation-only economic balance")
				}
			}
		}
		g.plans[c.ID.String()] = c
		g.inputs[c.ID.String()] = in
	}
	return nil
}

type businessCommand struct {
	PlanID  funds.ID  `json:"plan_id"`
	GrantID *funds.ID `json:"grant_id,omitempty"`
	Mode    string    `json:"mode"`
}

func (g *businessGraph) checkOperations() error {
	keys := map[string]bool{}
	permits := map[string]bool{}
	activeGoals := map[string]bool{}
	for _, row := range g.rows["operations"] {
		if row.text("command_kind") != "ALLOCATE_GOAL" {
			return fmt.Errorf("%w: operation business family", evidence.ErrUnsupportedVersion)
		}
		id := row.id("id").String()
		c, ok := g.plans[row.text("plan_id")]
		if !ok || c.Status != "READY" || len(c.Uses) != 1 {
			return businessInvalid("operation frozen candidate")
		}
		var request execution.BankRequest
		raw := row.original("bank_request", &request)
		canon, err := request.CanonicalBytes()
		digest, de := request.Digest()
		var command businessCommand
		commandRaw := row.original("request", &command)
		var dep planning.DependencyVector
		row.object("dependencies", &dep)
		p := g.policies[versionKey(c.PolicyID.String(), c.PolicyVersion)]
		if err != nil || de != nil || !bytes.Equal(raw, canon) || digest != row.text("bank_request_hash") || request.Namespace != g.manifest.Scope.Namespace || request.Namespace != row.text("bank_namespace") || request.Key != id || request.Key != row.text("bank_key") || request.OperationID != id || request.UserID != g.manifest.Scope.UserID || request.Kind != "ALLOCATE_GOAL" || request.Amount != c.Amount || request.SourceAccountID != c.Scope.SourceAccountID.String() || request.DestinationAccountID != c.Scope.DestinationAccountID.String() || request.GoalID != c.Scope.GoalID.String() || request.IncomeOriginID != c.Uses[0].OriginID.String() || request.ReferenceHash != c.EffectHash || request.PermitID != row.id("permit_id").String() || !request.RequestedAt.Equal(row.instant("created_at")) || request.SettlementDelayDays != 0 || !request.LatestArrivalAt.Equal(request.RequestedAt.Add(24*time.Hour)) || command.PlanID != c.ID || nakedHash(commandRaw) != row.text("request_hash") || row.text("policy_id") != p.ID.String() || uint64(row.positive("policy_version")) != p.Version || dep != c.Dependencies || uint64(row.positive("reserved_funds_version")) != dep.FundsVersion+1 || dep.FundsVersion+1 > uint64(g.manifest.Source.Watermarks["funds_version"]) {
			return businessInvalid("original operation request and dependencies")
		}
		var auth planning.Authorization
		if command.Mode == "STANDING" && command.GrantID != nil {
			gid := command.GrantID.String()
			gv := uint64(row.positive("grant_version"))
			grant, exists := g.grants[versionKey(gid, gv)]
			if !exists || row.optional("grant_id") != gid || row.optional("confirmation_id") != "" || row.text("authorization_kind") != "STANDING_GRANT" {
				return businessInvalid("standing authorization source")
			}
			auth, err = planning.AuthorizeStanding(c, p, grant, request.RequestedAt)
		} else if command.Mode == "ONCE" && command.GrantID == nil {
			confirmation, exists := g.confirmations[row.optional("confirmation_id")]
			if !exists || row.optional("grant_id") != "" || row.values["grant_version"] != nil || row.text("authorization_kind") != "SINGLE_USE" {
				return businessInvalid("single use authorization source")
			}
			auth, err = planning.AuthorizeOnce(c, p, confirmation, request.RequestedAt)
		} else {
			return businessInvalid("command permission mode")
		}
		if err != nil || request.AuthorizationID != auth.SourceID.String() || request.AuthorizationVersion != int64(auth.SourceVersion) {
			return businessInvalid("T1 authorization replay")
		}
		key := row.text("idempotency_key")
		if keys[key] || permits[request.PermitID] {
			return businessInvalid("duplicate original key or permit")
		}
		keys[key] = true
		permits[request.PermitID] = true
		r, exists := g.reservations[id]
		if !exists || len(r.Uses) != 1 || r.Uses[0] != c.Uses[0] {
			return businessInvalid("operation exact reservation")
		}
		state := row.text("status")
		signature := row.optional("permit_signature")
		if signature != "" {
			b, e := hex.DecodeString(signature)
			if e != nil || len(b) != 32 {
				return businessInvalid("permit signature encoding")
			}
		}
		switch state {
		case "SETTLED":
			if r.State != funds.Committed || signature == "" {
				return businessInvalid("settled claim state")
			}
		case "REJECTED":
			if r.State != funds.Released || signature == "" {
				return businessInvalid("rejected claim state")
			}
		case "CANCELLED":
			if r.State != funds.Released || signature != "" {
				return businessInvalid("pre permit cancellation")
			}
		case "QUEUED":
			if r.State != funds.Reserved || signature != "" {
				return businessInvalid("queued claim or premature permit")
			}
		case "SUBMITTING", "UNKNOWN", "PENDING_SETTLEMENT", "RECONCILING":
			if r.State != funds.Reserved || signature == "" {
				return businessInvalid("uncertain effect must retain claims and original permit")
			}
		default:
			return businessInvalid("operation state")
		}
		if state != "SETTLED" && state != "REJECTED" && state != "CANCELLED" {
			if activeGoals[request.GoalID] {
				return businessInvalid("overlapping pending goal effects")
			}
			activeGoals[request.GoalID] = true
		}
		row.positive("version")
		updated := row.instant("updated_at")
		if updated.Before(request.RequestedAt) {
			return businessInvalid("operation clock")
		}
		g.requests[id] = request
	}
	for _, row := range g.rows["bank_observations"] {
		id := row.text("operation_id")
		request, ok := g.requests[id]
		var result execution.BankResult
		row.original("original", &result)
		if !ok || execution.VerifyBankResult(request, result) != nil || string(result.Status) != row.text("status") {
			return businessInvalid("independent original bank observation")
		}
		row.id("id")
		row.instant("observed_at")
		g.results[id] = append(g.results[id], result)
	}
	return nil
}

type businessReceipt struct {
	ID              funds.ID    `json:"id"`
	OperationID     funds.ID    `json:"operation_id"`
	Environment     string      `json:"environment"`
	UserID          funds.ID    `json:"user_id"`
	BankKey         string      `json:"bank_key"`
	BankRequestHash string      `json:"bank_request_hash"`
	Amount          funds.Money `json:"amount_cents"`
	JournalID       funds.ID    `json:"journal_id"`
	PostingIDs      []string    `json:"bank_posting_ids"`
	SettledAt       time.Time   `json:"settled_at"`
	RecordedAt      time.Time   `json:"recorded_at"`
}

// The first chain's explicit simulated bank-income original is an existing
// immutable protocol. Keep its field spelling and hash domain unchanged.
type businessIncomeProof struct {
	Protocol, Namespace                                            string
	EnvironmentID, UserID, AccountID, GoalID, OriginID, EvidenceID funds.ID
	Amount                                                         funds.Money
	OccurredAt                                                     time.Time
	Authority                                                      struct {
		PolicyID      funds.ID  `json:"policy_id"`
		PolicyVersion uint64    `json:"policy_version"`
		GrantID       funds.ID  `json:"grant_id"`
		GrantVersion  uint64    `json:"grant_version"`
		EffectiveFrom time.Time `json:"effective_from"`
	}
}

// Sums use independent arbitrary precision arithmetic rather than trusting
// row hashes, a stored "balanced" flag, or the domain projection alone.
func addBusinessSum(sums map[string]*big.Int, key string, n int64) {
	if sums[key] == nil {
		sums[key] = new(big.Int)
	}
	sums[key].Add(sums[key], big.NewInt(n))
}
func businessSum(sums map[string]*big.Int, key string, n int64) bool {
	sum := sums[key]
	if sum == nil {
		return n == 0
	}
	return sum.Cmp(big.NewInt(n)) == 0
}

func (g *businessGraph) checkSettlementProjection() error {
	goalSums, monthSums, accountSums, fragmentSums := map[string]*big.Int{}, map[string]*big.Int{}, map[string]*big.Int{}, map[string]*big.Int{}
	confirmedCash := map[string]*big.Int{}
	usedJournals, usedReceipts, usedEvidence, usedPostings := map[string]bool{}, map[string]bool{}, map[string]bool{}, map[string]bool{}
	var missingSource error
	for _, origin := range g.rows["income_origins"] {
		addBusinessSum(confirmedCash, origin.text("original_account_id"), origin.integer("amount_cents"))
		id := origin.text("evidence_id")
		er := g.row("evidence_blobs", id)
		if er == nil {
			missingSource = &evidence.ReferenceError{ID: RowID("evidence_blobs", keyParts(id)), Cause: fmt.Errorf("%w: original bank income evidence", evidence.ErrIncomplete)}
			continue
		}
		if er.text("kind") != "EXPLICIT_SIMULATED_BANK_INCOME" {
			return fmt.Errorf("%w: income original evidence family", evidence.ErrUnsupportedVersion)
		}
		var proof businessIncomeProof
		raw := er.original("canonical", &proof)
		if er.err != nil {
			return er.err
		}
		if proof.Protocol == "" {
			return businessInvalid("income original declared protocol missing")
		}
		if proof.Protocol != "explicit-synthetic-bank-income-v1" {
			return fmt.Errorf("%w: income original protocol", evidence.ErrUnsupportedVersion)
		}
		if nakedHash(raw) != er.text("digest") || er.text("digest") != origin.text("evidence_hash") || proof.Namespace != g.manifest.Scope.Namespace || proof.EnvironmentID.String() != g.manifest.Scope.EnvironmentID || proof.UserID.String() != g.manifest.Scope.UserID || proof.OriginID.String() != origin.text("id") || proof.AccountID.String() != origin.text("original_account_id") || proof.EvidenceID.String() != id || proof.Amount != origin.money("amount_cents") || !proof.OccurredAt.Equal(origin.instant("occurred_at")) {
			return businessInvalid("immutable bank income original binding")
		}
		p, ok := g.policies[versionKey(proof.Authority.PolicyID.String(), proof.Authority.PolicyVersion)]
		grant, exists := g.grants[versionKey(proof.Authority.GrantID.String(), proof.Authority.GrantVersion)]
		boundary, err := policy.CheckGrant(p, grant, proof.OccurredAt)
		if !ok || !exists || err != nil || !boundary.EffectiveFrom.Equal(proof.Authority.EffectiveFrom) || p.Scope.GoalID != proof.GoalID || p.Scope.SourceAccountID != proof.AccountID {
			return businessInvalid("income original reviewed authority")
		}
		usedEvidence[id] = true
	}
	for id, request := range g.requests {
		op := g.row("operations", id)
		state := op.text("status")
		results := g.results[id]
		var settled *execution.BankResult
		rejected := false
		accepted := false
		var sequence int64
		for i := range results {
			r := &results[i]
			if r.Status != execution.BankNotFound {
				if sequence != 0 && sequence != r.Sequence {
					return businessInvalid("bank original key has conflicting sequence identities")
				}
				sequence = r.Sequence
			}
			switch r.Status {
			case execution.BankSettled:
				if settled != nil && !exactJSON(*settled, *r) || rejected {
					return businessInvalid("conflicting terminal observations")
				}
				settled = r
				accepted = true
			case execution.BankAccepted:
				if rejected {
					return businessInvalid("rejection conflicts with acceptance")
				}
				accepted = true
			case execution.BankRejected:
				if accepted || settled != nil || !r.AbsenceIsFinal {
					return businessInvalid("release requires final original absence")
				}
				rejected = true
			case execution.BankNotFound: // NOT_FOUND alone never proves no effect.
			default:
				return businessInvalid("bank observation status")
			}
		}
		observed := op.optional("bank_observed_status")
		if state == "QUEUED" || state == "CANCELLED" {
			if len(results) != 0 || observed != "" {
				return businessInvalid("bank observation before permit")
			}
		}
		if state == "SETTLED" || state == "RECONCILING" {
			if settled == nil || observed != "SETTLED" {
				return businessInvalid("settlement requires original bank result")
			}
		}
		if state == "REJECTED" {
			if !rejected || observed != "REJECTED" {
				return businessInvalid("released rejection has no final proof")
			}
		}
		if state == "PENDING_SETTLEMENT" && (!accepted || settled != nil || observed != "ACCEPTED") {
			return businessInvalid("pending bank acceptance")
		}
		if (state == "UNKNOWN" || state == "SUBMITTING") && (settled != nil || rejected || accepted || observed != "") {
			return businessInvalid("durable known bank fact erased")
		}
		if state != "SETTLED" {
			if op.optional("receipt_id") != "" {
				return businessInvalid("unsettled local receipt")
			}
			continue
		}
		receiptID := op.optional("receipt_id")
		rr := g.row("receipts", receiptID)
		if rr == nil {
			return businessInvalid("receipt missing")
		}
		var receipt businessReceipt
		rr.original("original", &receipt)
		if receipt.ID.String() != receiptID || receipt.OperationID.String() != id || rr.text("operation_id") != id || rr.text("bank_operation_id") != id || receipt.Environment != request.Namespace || receipt.UserID.String() != request.UserID || receipt.BankKey != request.Key || receipt.BankRequestHash != settled.RequestHash || receipt.Amount != request.Amount || !receipt.SettledAt.Equal(*settled.SettledAt) || !receipt.RecordedAt.Equal(rr.instant("created_at")) {
			return businessInvalid("receipt original binding")
		}
		jr := g.row("journals", receipt.JournalID.String())
		if jr == nil || usedJournals[receipt.JournalID.String()] || jr.text("operation_id") != id || jr.text("kind") != "ALLOCATION" || jr.text("status") != "POSTED" || !jr.instant("posted_at").Equal(receipt.RecordedAt) || !jr.instant("created_at").Equal(receipt.RecordedAt) {
			return businessInvalid("one posted allocation journal")
		}
		balances := map[string]*big.Int{}
		postingIDs := make([]string, len(settled.Postings))
		for i, leg := range settled.Postings {
			ref := fmt.Sprintf("bank:%d:%s", i+1, leg.ID)
			pr := g.row("postings", receipt.JournalID.String(), ref)
			dimension := "GOAL_OWNERSHIP"
			if leg.Dimension == "INCOME_LOCATION" {
				dimension = "INCOME_QUALIFICATION"
			}
			if pr == nil || pr.text("dimension") != dimension || pr.text("currency") != "CNY" || pr.text("account_id") != request.SourceAccountID || pr.text("direction") != leg.Direction || pr.money("amount_cents") != leg.Amount {
				return businessInvalid("journal leg differs from independent bank posting")
			}
			delta := leg.Amount.Cents()
			if leg.Direction == "CREDIT" {
				delta = -delta
			}
			addBusinessSum(balances, dimension, delta)
			postingIDs[i] = leg.ID
			usedPostings[keyParts(receipt.JournalID.String(), ref)] = true
		}
		if len(settled.Postings) != 4 || !reflect.DeepEqual(postingIDs, receipt.PostingIDs) {
			return businessInvalid("receipt posting identities")
		}
		for _, sum := range balances {
			if sum.Sign() != 0 {
				return businessInvalid("journal is not balanced in each dimension")
			}
		}
		er := g.row("evidence_blobs", "settlement:"+id)
		if er == nil || er.text("kind") != SettlementKind {
			return businessInvalid("settlement evidence missing")
		}
		original := evidence.Original{Canonical: er.raw("canonical"), Digest: er.text("digest")}
		registry := evidence.NewRegistry()
		if Register(registry) != nil {
			return businessInvalid("settlement registry")
		}
		verified := evidence.VerifyBundle([]string{"settlement:" + id}, map[string]evidence.Original{"settlement:" + id: original}, registry)
		if verified.Status != evidence.Valid {
			if verified.Status == evidence.UnsupportedVersion {
				return fmt.Errorf("%w: nested settlement protocol", evidence.ErrUnsupportedVersion)
			}
			return businessInvalid("nested settlement evidence")
		}
		var doc evidence.Document
		if json.Unmarshal(original.Canonical, &doc) != nil || doc.Data["receipt_id"] != receiptID || doc.Data["operation_id"] != id || doc.Data["environment"] != request.Namespace || doc.Data["user_id"] != request.UserID {
			return businessInvalid("settlement evidence links")
		}
		var evidenceRequest execution.BankRequest
		var evidenceResult execution.BankResult
		if decodeHex(doc.Data["bank_request_hex"].(string), &evidenceRequest) != nil || decodeHex(doc.Data["bank_result_hex"].(string), &evidenceResult) != nil || !exactJSON(evidenceRequest, request) || !exactJSON(evidenceResult, *settled) {
			return businessInvalid("settlement evidence differs from original request or result")
		}
		usedJournals[receipt.JournalID.String()] = true
		usedReceipts[receiptID] = true
		usedEvidence["settlement:"+id] = true
		addBusinessSum(goalSums, request.GoalID, request.Amount.Cents())
		addBusinessSum(accountSums, request.SourceAccountID, request.Amount.Cents())
		addBusinessSum(fragmentSums, funds.LocationID(mustBusinessID(request.IncomeOriginID), mustBusinessID(request.SourceAccountID)).String(), request.Amount.Cents())
		period := settled.SettledAt.In(time.FixedZone("Asia/Shanghai", 8*3600)).Format("2006-01")
		addBusinessSum(monthSums, request.GoalID+":"+period, request.Amount.Cents())
	}
	if len(usedJournals) != len(g.rows["journals"]) || len(usedReceipts) != len(g.rows["receipts"]) || len(usedEvidence) != len(g.rows["evidence_blobs"]) || len(usedPostings) != len(g.rows["postings"]) {
		return businessInvalid("orphan or duplicate settlement rows")
	}
	goalOwned := map[string]*big.Int{}
	for _, row := range g.rows["goals"] {
		if !businessSum(goalSums, row.text("id"), row.integer("assigned_cents")) || !businessSum(monthSums, row.text("id")+":"+row.text("month_period"), row.integer("month_contributed_cents")) {
			return businessInvalid("goal assignment or month arithmetic")
		}
		addBusinessSum(goalOwned, row.text("account_id"), row.integer("assigned_cents"))
	}
	availableReserved := map[string]*big.Int{}
	for _, row := range g.rows["income_locations"] {
		if !businessSum(fragmentSums, row.text("id"), row.integer("assigned_cents")) {
			return businessInvalid("income assignment differs from committed effects")
		}
		addBusinessSum(availableReserved, row.text("account_id"), row.integer("available_cents"))
		addBusinessSum(availableReserved, row.text("account_id"), row.integer("reserved_cents"))
	}
	for _, row := range g.rows["accounts"] {
		id := row.text("id")
		if !businessSum(confirmedCash, id, row.integer("balance_cents")) {
			if confirmedCash[id] == nil {
				return &evidence.ReferenceError{ID: RowID("accounts", keyParts(id)), Cause: fmt.Errorf("%w: account opening balance has no supported immutable source proof", evidence.ErrIncomplete)}
			}
			return businessInvalid("allocation-only cash differs from confirmed original income")
		}
		owned := row.integer("goal_owned_cents")
		if !businessSum(accountSums, id, owned) || !businessSum(goalOwned, id, owned) {
			return businessInvalid("account goal ownership arithmetic")
		}
		free := new(big.Int).Sub(big.NewInt(row.integer("balance_cents")), big.NewInt(owned))
		if sum := availableReserved[id]; sum != nil && sum.Cmp(free) > 0 {
			return businessInvalid("qualified available plus held exceeds free cash")
		}
	}
	if missingSource != nil {
		return missingSource
	}
	return nil
}
func mustBusinessID(s string) funds.ID { id, _ := funds.ParseID(s); return id }

func (g *businessGraph) checkSubmissionPermits() error {
	for _, subject := range g.rows["audit_session_subjects"] {
		if len(subject.values) != 5 {
			return businessInvalid("session subject must exclude all credential fields")
		}
		subject.id("id")
		subject.instant("expires_at")
		subject.boolean("revoked")
		if subject.err != nil {
			return subject.err
		}
	}
	for _, confirmation := range g.rows["confirmations"] {
		id := confirmation.text("session_id")
		subject := g.row("audit_session_subjects", id)
		if subject == nil {
			return &evidence.ReferenceError{ID: RowID("audit_session_subjects", keyParts(id)), Cause: fmt.Errorf("%w: USER confirmation session subject", evidence.ErrIncomplete)}
		}
		if !confirmation.instant("confirmed_at").Before(subject.instant("expires_at")) {
			return businessInvalid("USER confirmation outside recorded session validity")
		}
		// Today's revoked bit is not a historical revocation timestamp. The
		// authenticated collector and immutable confirmation remain trust inputs.
	}
	used := map[string]bool{}
	for id, request := range g.requests {
		op := g.row("operations", id)
		signature := op.optional("permit_signature")
		row := g.row("submission_permits", id)
		if signature == "" {
			if row != nil {
				return businessInvalid("submission evidence for unsigned operation")
			}
			continue
		}
		if row == nil {
			return &evidence.ReferenceError{ID: RowID("submission_permits", keyParts(id)), Cause: fmt.Errorf("%w: immutable historical T2 evidence was never captured", evidence.ErrIncomplete)}
		}
		var proof SubmissionPermitEvidence
		raw := row.original("original", &proof)
		if row.err != nil {
			return row.err
		}
		if proof.Protocol == "" {
			return businessInvalid("T2 declared protocol missing")
		}
		if proof.Protocol != SubmissionPermitProtocol || row.text("protocol_version") != SubmissionPermitProtocol {
			return fmt.Errorf("%w: submission permit protocol", evidence.ErrUnsupportedVersion)
		}
		c := g.plans[op.text("plan_id")]
		p := g.policies[versionKey(c.PolicyID.String(), c.PolicyVersion)]
		if nakedHash(raw) != row.text("original_hash") || proof.EnvironmentID.String() != g.manifest.Scope.EnvironmentID || proof.UserID.String() != g.manifest.Scope.UserID || proof.OperationID.String() != id || proof.Namespace != request.Namespace || proof.PermitID != request.PermitID || row.id("permit_id").String() != proof.PermitID || proof.BankRequestHash != op.text("bank_request_hash") || proof.EffectHash != c.EffectHash || proof.Dependencies != c.Dependencies || proof.ReservedFundsVersion != uint64(op.positive("reserved_funds_version")) || proof.SourceVersion != c.Dependencies.SourceEvidenceVersion || proof.SignatureHash != nakedHash([]byte(signature)) || !proof.DecisionAt.Equal(row.instant("decision_at")) || proof.DecisionAt.Before(request.RequestedAt) || !exactJSON(proof.Policy, p) {
			return businessInvalid("T2 original exact scope, version, request or signature binding")
		}
		var auth planning.Authorization
		var err error
		switch op.text("authorization_kind") {
		case "STANDING_GRANT":
			if proof.Grant == nil || proof.Confirmation != nil {
				return businessInvalid("T2 grant subject missing or ambiguous")
			}
			grant, exists := g.grants[versionKey(op.text("grant_id"), uint64(op.positive("grant_version")))]
			if !exists || !exactJSON(*proof.Grant, grant) {
				return businessInvalid("T2 exact reviewed grant version")
			}
			auth, err = planning.AuthorizeStanding(c, proof.Policy, *proof.Grant, proof.DecisionAt)
		case "SINGLE_USE":
			if proof.Confirmation == nil || proof.Grant != nil || !exactJSON(*proof.Confirmation, g.confirmations[op.text("confirmation_id")]) {
				return businessInvalid("T2 exact USER single-use confirmation")
			}
			auth, err = planning.AuthorizeOnce(c, proof.Policy, *proof.Confirmation, proof.DecisionAt)
		default:
			return businessInvalid("T2 permission family")
		}
		if err != nil || auth.SourceID.String() != request.AuthorizationID || int64(auth.SourceVersion) != request.AuthorizationVersion {
			return businessInvalid("T2 permission at immutable decision instant")
		}
		for _, result := range g.results[id] {
			if result.AcceptedAt != nil && result.AcceptedAt.Before(proof.DecisionAt) {
				return businessInvalid("bank acceptance precedes T2 decision")
			}
		}
		row.instant("recorded_at")
		if row.err != nil {
			return row.err
		}
		used[id] = true
	}
	if len(used) != len(g.rows["submission_permits"]) {
		return businessInvalid("orphan submission proof")
	}
	return nil
}
