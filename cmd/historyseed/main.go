// historyseed is an independent local simulation source. Its signing private
// key is never loaded by the application, bank, browser or model.
package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"zhiyu.local/zhiyu-go/internal/audit"
	funds "zhiyu.local/zhiyu-go/internal/funds/domain"
	policy "zhiyu.local/zhiyu-go/internal/policy/domain"
)

type publicAuthority struct {
	IssuerID     string     `json:"issuer_id"`
	Namespace    string     `json:"namespace"`
	UserID       funds.ID   `json:"user_id"`
	AccountIDs   []funds.ID `json:"account_ids"`
	PublicKeyHex string     `json:"public_key_hex"`
}

type privateIssuer struct {
	Protocol      string          `json:"protocol"`
	Simulation    bool            `json:"simulation"`
	Authority     publicAuthority `json:"authority"`
	PrivateKeyHex string          `json:"private_key_hex"`
}

func main() {
	if err := run(os.Args[1:], os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func strict(raw []byte, out any) error {
	if _, err := audit.ParseRawObject(raw); err != nil {
		return errors.New("invalid source input")
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(out) != nil {
		return errors.New("invalid source input")
	}
	return nil
}

func privatePath(path string) (string, error) {
	base, err := filepath.Abs(".runtime")
	if err != nil {
		return "", errors.New("private runtime unavailable")
	}
	out, err := filepath.Abs(path)
	if err != nil {
		return "", errors.New("invalid private path")
	}
	rel, err := filepath.Rel(base, out)
	if err != nil || rel == "." || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) || filepath.IsAbs(rel) {
		return "", errors.New("source files must remain inside project .runtime")
	}
	if os.MkdirAll(filepath.Dir(out), 0700) != nil {
		return "", errors.New("private directory unavailable")
	}
	base, err = filepath.EvalSymlinks(base)
	if err != nil {
		return "", errors.New("private runtime unavailable")
	}
	parent, err := filepath.EvalSymlinks(filepath.Dir(out))
	if err != nil {
		return "", errors.New("private directory unavailable")
	}
	rel, err = filepath.Rel(base, parent)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) || filepath.IsAbs(rel) {
		return "", errors.New("private path escapes project runtime")
	}
	if info, e := os.Lstat(out); e == nil && !info.Mode().IsRegular() {
		return "", errors.New("private input must be a regular file")
	}
	return out, nil
}

func writeNew(path string, raw []byte) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return errors.New("source original exists or cannot be created; do not overwrite")
	}
	defer f.Close()
	if _, err = f.Write(raw); err != nil {
		return errors.New("source write failed; retain partial original")
	}
	if f.Sync() != nil {
		return errors.New("source sync failed; retain original")
	}
	return nil
}

func readBounded(path string, limit int64) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, errors.New("private source input unavailable")
	}
	defer f.Close()
	raw, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil || int64(len(raw)) > limit {
		return nil, errors.New("private source capacity exceeded")
	}
	return raw, nil
}

func run(args []string, out io.Writer) error {
	f := flag.NewFlagSet("historyseed", flag.ContinueOnError)
	f.SetOutput(io.Discard)
	mode := f.String("mode", "controlled", "init-authority, controlled, seal, or verify")
	simulation := f.Bool("simulation", false, "explicit isolated historical simulation")
	issuerID := f.String("issuer-id", "", "fixed independent issuer ID")
	namespace := f.String("namespace", "", "exact owned namespace")
	userID := f.String("user-id", "", "exact owned user UUID")
	accountID := f.String("account-id", "", "exact owned account UUID")
	accountIDs := f.String("account-ids", "", "comma-separated exact owned account UUIDs; alternative to account-id")
	privateFile := f.String("private-file", ".runtime/history-producer/issuer-private.json", "producer-only key file")
	profileFile := f.String("public-file", ".runtime/history-public/issuer-public.json", "application public authority profile")
	rawFile := f.String("raw-file", ".runtime/history-producer/statement-raw.json", "exact statement original")
	envelopeFile := f.String("envelope-file", ".runtime/history-public/statement-envelope.json", "application-readable signed envelope")
	statementID := f.String("statement-id", "", "unique immutable statement ID")
	issuedAt := f.String("issued-at", "", "RFC3339 time; defaults to real now")
	days := f.Int("days", 366, "past complete natural days, 1..366")
	dailyCents := f.Int64("daily-consumption-cents", 1, "explicit simulated daily food consumption cents")
	holidayCode := f.String("holiday-code", "controlled-synthetic", "label for two controlled historical windows")
	bankPaymentsFile := f.String("bank-payments-file", "", "optional retained independent bank payment results; never a permit/private file")
	if f.Parse(args) != nil || f.NArg() != 0 || !*simulation {
		return errors.New("valid flags and explicit -simulation required")
	}
	paths := []*string{privateFile, profileFile, rawFile, envelopeFile}
	for _, p := range paths {
		value, err := privatePath(*p)
		if err != nil {
			return err
		}
		*p = value
	}
	if *privateFile == *profileFile || *privateFile == *envelopeFile || *privateFile == *rawFile || *rawFile == *envelopeFile || *profileFile == *envelopeFile {
		return errors.New("private key, public profile and source originals require separate paths")
	}
	if *mode == "init-authority" {
		user, ue := funds.ParseID(*userID)
		values := []string{*accountID}
		if *accountIDs != "" {
			if *accountID != "" {
				return errors.New("use account-id or account-ids")
			}
			values = strings.Split(*accountIDs, ",")
		}
		accounts := []funds.ID{}
		for _, v := range values {
			id, e := funds.ParseID(v)
			if e != nil || id == (funds.ID{}) {
				return errors.New("exact owned account UUID required")
			}
			accounts = append(accounts, id)
		}
		sort.Slice(accounts, func(i, j int) bool { return accounts[i].String() < accounts[j].String() })
		for i := 1; i < len(accounts); i++ {
			if accounts[i] == accounts[i-1] {
				return errors.New("duplicate account scope")
			}
		}
		if ue != nil || user == (funds.ID{}) || len(accounts) < 1 || len(accounts) > 32 {
			return errors.New("exact owned user/account UUID required")
		}
		public, private, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return errors.New("issuer key generation failed")
		}
		a := publicAuthority{*issuerID, *namespace, user, accounts, hex.EncodeToString(public)}
		now := time.Now().UTC()
		yesterday := now.AddDate(0, 0, -1).Format("2006-01-02")
		probe := policy.HistoryStatement{Protocol: policy.HistoryStatementProtocol, IssuerID: a.IssuerID, StatementID: "scope-validation", Namespace: a.Namespace, UserID: a.UserID, AccountIDs: a.AccountIDs, Currency: funds.CNY, Timezone: "UTC", FromDate: yesterday, ThroughDate: yesterday, Complete: true, SourceMode: "CONTROLLED_HISTORICAL_SIMULATION", IssuedAt: now, Transactions: []policy.TemplateHistoryTransaction{}, SeasonalWindows: []policy.HistoryStatementWindow{}}
		if probe.Validate() != nil {
			return errors.New("issuer scope invalid")
		}
		privateRaw, _ := json.MarshalIndent(privateIssuer{"zhiyu-forecast-history-issuer-private-v1", true, a, hex.EncodeToString(private)}, "", "  ")
		publicRaw, _ := json.MarshalIndent(a, "", "  ")
		if err = writeNew(*privateFile, privateRaw); err != nil {
			return err
		}
		if err = writeNew(*profileFile, publicRaw); err != nil {
			return err
		}
		fmt.Fprintln(out, "ISSUER_CREATED; private_key_printed=false; app_profile_public_only=true; financial_effects=0")
		return nil
	}
	if *mode == "verify" {
		profileRaw, err := readBounded(*profileFile, 65536)
		if err != nil {
			return err
		}
		var a publicAuthority
		if strict(profileRaw, &a) != nil {
			return errors.New("public authority invalid")
		}
		public, err := hex.DecodeString(a.PublicKeyHex)
		if err != nil {
			return errors.New("public authority invalid")
		}
		wire, err := readBounded(*envelopeFile, 2*policy.MaxHistoryStatementBytes+4096)
		if err != nil {
			return err
		}
		var envelope policy.HistoryStatementEnvelope
		if strict(wire, &envelope) != nil {
			return errors.New("envelope invalid")
		}
		s, _, err := policy.VerifyHistoryEnvelope(envelope, ed25519.PublicKey(public))
		if err != nil || !sameScope(s, a) {
			return errors.New("signature or exact scope invalid")
		}
		fmt.Fprintf(out, "VERIFIED; protocol=%s; raw_sha256=%s; source_mode=%s; financial_effects=0\n", envelope.Protocol, envelope.RawSHA256, s.SourceMode)
		return nil
	}
	if *mode != "controlled" && *mode != "seal" {
		return errors.New("unknown producer mode")
	}
	privateRaw, err := readBounded(*privateFile, 65536)
	if err != nil {
		return err
	}
	var issuer privateIssuer
	if strict(privateRaw, &issuer) != nil || issuer.Protocol != "zhiyu-forecast-history-issuer-private-v1" || !issuer.Simulation {
		return errors.New("private issuer invalid")
	}
	private, err := hex.DecodeString(issuer.PrivateKeyHex)
	if err != nil || len(private) != ed25519.PrivateKeySize || !bytes.Equal(ed25519.NewKeyFromSeed(private[:ed25519.SeedSize]), private) || hex.EncodeToString(ed25519.PrivateKey(private).Public().(ed25519.PublicKey)) != issuer.Authority.PublicKeyHex {
		return errors.New("private issuer key mismatch")
	}
	var raw []byte
	if *mode == "controlled" {
		if *days < 1 || *days > 366 {
			return errors.New("complete history days must be 1..366")
		}
		amount, err := funds.NewMoney(*dailyCents)
		if err != nil || amount.IsZero() {
			return errors.New("positive simulated consumption amount required")
		}
		now := time.Now().UTC().Truncate(time.Microsecond)
		if *issuedAt != "" {
			now, err = time.Parse(time.RFC3339Nano, *issuedAt)
			if err != nil {
				return errors.New("issued-at must be RFC3339")
			}
		}
		zone, _ := policy.TemplateLocation("Asia/Shanghai")
		local := now.In(zone)
		today := time.Date(local.Year(), local.Month(), local.Day(), 0, 0, 0, 0, zone)
		a := issuer.Authority
		s := policy.HistoryStatement{Protocol: policy.HistoryStatementProtocol, IssuerID: a.IssuerID, StatementID: *statementID, Namespace: a.Namespace, UserID: a.UserID, AccountIDs: a.AccountIDs, Currency: funds.CNY, Timezone: "Asia/Shanghai", FromDate: today.AddDate(0, 0, -*days).Format("2006-01-02"), ThroughDate: today.AddDate(0, 0, -1).Format("2006-01-02"), Complete: true, SourceMode: "CONTROLLED_HISTORICAL_SIMULATION", IssuedAt: now, Transactions: []policy.TemplateHistoryTransaction{}, SeasonalWindows: []policy.HistoryStatementWindow{}}
		for d := today.AddDate(0, 0, -*days); d.Before(today); d = d.AddDate(0, 0, 1) {
			date := d.Format("2006-01-02")
			for _, account := range a.AccountIDs {
				sum := sha256.Sum256([]byte("historyseed-controlled-transaction-v1\x00" + a.IssuerID + "\x00" + a.Namespace + "\x00" + a.UserID.String() + "\x00" + account.String() + "\x00" + date))
				var id funds.ID
				copy(id[:], sum[:16])
				id[6] = (id[6] & 15) | 64
				id[8] = (id[8] & 63) | 128
				s.Transactions = append(s.Transactions, policy.TemplateHistoryTransaction{ID: id, AccountID: account, Date: date, Direction: "DEBIT", Amount: amount, Category: "food", CategoryConfirmed: true, EconomicRole: "CONSUMPTION"})
			}
		}
		if *days >= 93 {
			for _, offset := range []int{-90, -60} {
				start := today.AddDate(0, 0, offset)
				s.SeasonalWindows = append(s.SeasonalWindows, policy.HistoryStatementWindow{HolidayCode: *holidayCode, Start: start.Format("2006-01-02"), End: start.AddDate(0, 0, 2).Format("2006-01-02")})
			}
		}
		if *bankPaymentsFile != "" {
			path, e := privatePath(*bankPaymentsFile)
			if e != nil {
				return e
			}
			originals, e := readBounded(path, 16<<20)
			if e != nil {
				return e
			}
			if e = addBankPayments(&s, originals); e != nil {
				return e
			}
		}
		sort.Slice(s.Transactions, func(i, j int) bool {
			return s.Transactions[i].Date+":"+s.Transactions[i].ID.String() < s.Transactions[j].Date+":"+s.Transactions[j].ID.String()
		})
		if s.Validate() != nil {
			return errors.New("controlled historical source invalid")
		}
		raw, _ = json.MarshalIndent(s, "", "  ")
		if err = writeNew(*rawFile, raw); err != nil {
			return err
		}
	} else {
		raw, err = readBounded(*rawFile, policy.MaxHistoryStatementBytes)
		if err != nil {
			return err
		}
	}
	s, err := policy.ParseHistoryStatement(raw)
	if err != nil || !sameScope(s, issuer.Authority) || s.SourceMode != "CONTROLLED_HISTORICAL_SIMULATION" {
		return errors.New("statement scope or simulation declaration invalid")
	}
	envelope, err := policy.SignHistoryRaw(raw, ed25519.PrivateKey(private))
	if err != nil {
		return errors.New("statement signing failed")
	}
	wire, _ := json.MarshalIndent(envelope, "", "  ")
	if err = writeNew(*envelopeFile, wire); err != nil {
		return err
	}
	fmt.Fprintf(out, "SEALED; raw_sha256=%s; source_mode=CONTROLLED_HISTORICAL_SIMULATION; historical_bank_postings_claimed=false; financial_effects=0\n", envelope.RawSHA256)
	return nil
}

func sameScope(s policy.HistoryStatement, a publicAuthority) bool {
	if s.IssuerID != a.IssuerID || s.Namespace != a.Namespace || s.UserID != a.UserID || len(s.AccountIDs) != len(a.AccountIDs) {
		return false
	}
	for i, id := range a.AccountIDs {
		if s.AccountIDs[i] != id {
			return false
		}
	}
	return true
}
