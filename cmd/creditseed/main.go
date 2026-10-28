// creditseed is a local simulated external-event producer. It is never loaded
// by the application, model or browser and carries no application authority.
package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"zhiyu.local/zhiyu-go/internal/adapters/banksim"
	"zhiyu.local/zhiyu-go/internal/execution/bankcredit"
	funds "zhiyu.local/zhiyu-go/internal/funds/domain"
)

const authorityProtocol = "zhiyu-external-credit-authorities-v1"
const bundleProtocol = "zhiyu-seed-only-credit-v1"

type authority struct {
	ID        string `json:"id"`
	Namespace string `json:"namespace"`
	UserID    string `json:"user_id"`
	AccountID string `json:"account_id"`
	Secret    string `json:"secret"`
}
type authorityFile struct {
	Protocol    string      `json:"protocol"`
	Simulation  bool        `json:"simulation"`
	Authorities []authority `json:"authorities"`
}
type bundle struct {
	Protocol   string           `json:"protocol"`
	Simulation bool             `json:"simulation"`
	BankURL    string           `json:"bank_url"`
	Event      bankcredit.Event `json:"event"`
	EventHash  string           `json:"event_hash"`
	Signature  string           `json:"signature"`
}

func main() {
	if e := run(os.Args[1:], os.Stdout); e != nil {
		fmt.Fprintln(os.Stderr, e)
		os.Exit(1)
	}
}

func strict(raw []byte, out any) error {
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	var extra any
	if d.Decode(out) != nil || d.Decode(&extra) != io.EOF {
		return errors.New("invalid private input")
	}
	return nil
}
func loopback(raw string) bool {
	u, e := url.Parse(raw)
	return e == nil && u.Scheme == "http" && net.ParseIP(u.Hostname()) != nil && net.ParseIP(u.Hostname()).IsLoopback() && u.Port() != "" && u.User == nil && (u.Path == "" || u.Path == "/") && u.RawQuery == "" && u.Fragment == ""
}
func uuid() (string, error) {
	var id funds.ID
	if _, e := rand.Read(id[:]); e != nil {
		return "", errors.New("random identity unavailable")
	}
	id[6] = (id[6] & 15) | 64
	id[8] = (id[8] & 63) | 128
	return id.String(), nil
}
func privatePath(path string) (string, error) {
	base, e := filepath.Abs(".runtime")
	if e != nil {
		return "", errors.New("private directory unavailable")
	}
	out, e := filepath.Abs(path)
	if e != nil {
		return "", errors.New("private path invalid")
	}
	rel, e := filepath.Rel(base, out)
	if e != nil || rel == "." || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) || filepath.IsAbs(rel) {
		return "", errors.New("private files must remain inside project .runtime")
	}
	if e = os.MkdirAll(filepath.Dir(out), 0700); e != nil {
		return "", errors.New("private directory creation failed")
	}
	resolvedBase, e := filepath.EvalSymlinks(base)
	if e != nil {
		return "", errors.New("private directory unavailable")
	}
	parent, e := filepath.EvalSymlinks(filepath.Dir(out))
	if e != nil {
		return "", errors.New("private directory unavailable")
	}
	rel, e = filepath.Rel(resolvedBase, parent)
	if e != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) || filepath.IsAbs(rel) {
		return "", errors.New("private path escapes project runtime")
	}
	return out, nil
}
func writeNew(path string, raw []byte) error {
	file, e := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if e != nil {
		return errors.New("private original already exists or cannot be created; do not overwrite")
	}
	defer file.Close()
	if _, e = file.Write(raw); e != nil {
		return errors.New("private original write failed; retain partial file")
	}
	if e = file.Sync(); e != nil {
		return errors.New("private original sync failed")
	}
	return nil
}
func readPrivate(path string) ([]byte, error) {
	file, e := os.Open(path)
	if e != nil {
		return nil, errors.New("private input unavailable")
	}
	defer file.Close()
	raw, e := io.ReadAll(io.LimitReader(file, 1<<20+1))
	if e != nil || len(raw) > 1<<20 {
		return nil, errors.New("private input capacity exceeded")
	}
	return raw, nil
}

func run(args []string, out io.Writer) error {
	f := flag.NewFlagSet("creditseed", flag.ContinueOnError)
	f.SetOutput(io.Discard)
	mode := f.String("mode", "seal", "init-authority, seal, submit or lookup")
	simulation := f.Bool("simulation", false, "explicit isolated simulated external credit")
	namespace := f.String("namespace", "", "exact expected owned namespace")
	authorityPath := f.String("authority-file", ".runtime/credentials/external-credit-authorities.json", "private bank-only authority file")
	authorityID := f.String("authority-id", "", "exact provisioned authority ID")
	seedPath := f.String("seed", ".runtime/demo-seed.json", "read only namespace/user/account metadata")
	bankURL := f.String("bank-url", "http://127.0.0.1:19311", "literal loopback bank")
	bundlePath := f.String("bundle", "", "private immutable event bundle")
	eventID := f.String("event-id", "", "new external event identity, never replace an uncertain key")
	amount := f.Int64("amount-cents", 0, "new controlled external income amount in CNY cents")
	if f.Parse(args) != nil || len(f.Args()) != 0 || !*simulation || !bankcredit.Identity(*authorityID) || !strings.HasPrefix(*namespace, "zygo_") {
		return errors.New("explicit simulation, namespace and authority identity required")
	}
	aPath, e := privatePath(*authorityPath)
	if e != nil {
		return e
	}
	if *mode == "init-authority" {
		raw, e := readPrivate(*seedPath)
		if e != nil {
			return e
		}
		var seed struct {
			Namespace string `json:"namespace"`
			UserID    string `json:"user_id"`
			AccountID string `json:"account_id"`
		}
		if json.Unmarshal(raw, &seed) != nil || seed.Namespace != *namespace || !bankcredit.Scope(seed.Namespace, seed.UserID) {
			return errors.New("seed scope differs from explicit owned namespace")
		}
		id, e := funds.ParseID(seed.AccountID)
		if e != nil || id == (funds.ID{}) {
			return errors.New("seed account identity invalid")
		}
		secret := make([]byte, 32)
		if _, e = rand.Read(secret); e != nil {
			return errors.New("authority random secret unavailable")
		}
		cfg := authorityFile{authorityProtocol, true, []authority{{*authorityID, seed.Namespace, seed.UserID, seed.AccountID, hex.EncodeToString(secret)}}}
		data, _ := json.Marshal(cfg)
		if e = writeNew(aPath, data); e != nil {
			return e
		}
		return json.NewEncoder(out).Encode(map[string]any{"status": "AUTHORITY_CREATED_NO_BANK_IO", "authority_id": *authorityID, "namespace": *namespace})
	}
	if *mode != "seal" && *mode != "submit" && *mode != "lookup" {
		return errors.New("unknown seed-only mode")
	}
	raw, e := readPrivate(aPath)
	if e != nil {
		return e
	}
	var cfg authorityFile
	if strict(raw, &cfg) != nil || cfg.Protocol != authorityProtocol || !cfg.Simulation || len(cfg.Authorities) == 0 || len(cfg.Authorities) > 1000 {
		return errors.New("invalid external authority file")
	}
	var selected *authority
	for i := range cfg.Authorities {
		a := &cfg.Authorities[i]
		if a.ID == *authorityID {
			if selected != nil {
				return errors.New("duplicate external authority identity")
			}
			selected = a
		}
	}
	if selected == nil || selected.Namespace != *namespace || len(selected.Secret) < 32 || !bankcredit.Scope(selected.Namespace, selected.UserID) {
		return errors.New("external authority scope rejected")
	}
	if *bundlePath == "" {
		return errors.New("explicit private immutable bundle path required")
	}
	path, e := privatePath(*bundlePath)
	if e != nil {
		return e
	}
	var b bundle
	if *mode == "seal" {
		money, e := funds.NewMoney(*amount)
		if e != nil || money.IsZero() || !bankcredit.Identity(*eventID) || !loopback(*bankURL) {
			return errors.New("invalid controlled credit amount, event identity or loopback URL")
		}
		origin, e := uuid()
		if e != nil {
			return e
		}
		evidence, e := uuid()
		if e != nil {
			return e
		}
		now := time.Now().UTC().Truncate(time.Microsecond)
		event := bankcredit.Event{Protocol: bankcredit.Protocol, Namespace: *namespace, AuthorityID: selected.ID, EventID: *eventID, UserID: selected.UserID, AccountID: selected.AccountID, OriginID: origin, EvidenceID: evidence, Role: "INCOME", Currency: "CNY", Amount: money, OccurredAt: now, IssuedAt: now, ExpiresAt: now.Add(time.Hour), ExternalReferenceHash: bankcredit.Hash([]byte(fmt.Sprintf("controlled-seed-only\x00%s\x00%s\x00%s\x00%d", *namespace, selected.AccountID, *eventID, *amount)))}
		signature, e := bankcredit.SignExternal(event, []byte(selected.Secret))
		if e != nil {
			return errors.New("external event signing failed")
		}
		hash, _ := event.Digest()
		b = bundle{bundleProtocol, true, strings.TrimRight(*bankURL, "/"), event, hash, signature}
		data, _ := json.Marshal(b)
		if e = writeNew(path, data); e != nil {
			return e
		}
		return json.NewEncoder(out).Encode(map[string]any{"status": "SEALED_NO_BANK_IO", "event_id": event.EventID, "event_hash": hash})
	}
	raw, e = readPrivate(path)
	if e != nil {
		return e
	}
	if strict(raw, &b) != nil || b.Protocol != bundleProtocol || !b.Simulation || !loopback(b.BankURL) || b.Event.Namespace != *namespace || b.Event.AuthorityID != selected.ID || b.Event.UserID != selected.UserID || b.Event.AccountID != selected.AccountID || !bankcredit.VerifyExternal(b.Event, b.Signature, []byte(selected.Secret)) {
		return errors.New("original bundle signature or authority scope differs")
	}
	hash, e := b.Event.Digest()
	if e != nil || hash != b.EventHash {
		return errors.New("original bundle hash differs")
	}
	client := &http.Client{Timeout: 10 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	var entry bankcredit.Entry
	if *mode == "lookup" {
		reader, e := banksim.NewExternalCreditClient(b.BankURL, client)
		if e != nil {
			return errors.New("invalid literal loopback reader")
		}
		found, e := reader.Lookup(ctx, b.Event.Namespace, b.Event.UserID, b.Event.AuthorityID, b.Event.EventID)
		if e != nil {
			return errors.New("original-key lookup unavailable; preserve bundle")
		}
		if !found.Found {
			return json.NewEncoder(out).Encode(map[string]any{"status": "NOT_FOUND_NOT_TERMINAL", "event_id": b.Event.EventID, "event_hash": hash})
		}
		entry = *found.Entry
	} else {
		eventRaw, _ := b.Event.CanonicalBytes()
		request, e := http.NewRequestWithContext(ctx, http.MethodPost, b.BankURL+"/v3/external-credits", bytes.NewReader(eventRaw))
		if e != nil {
			return errors.New("external request construction failed")
		}
		request.Header.Set("Content-Type", "application/json")
		request.Header.Set("X-Zhiyu-External-Credit", b.Signature)
		response, e := client.Do(request)
		if e != nil {
			return errors.New("external credit outcome unknown; preserve bundle and lookup original key")
		}
		defer response.Body.Close()
		data, e := io.ReadAll(io.LimitReader(response.Body, 1<<20+1))
		if e != nil || len(data) > 1<<20 {
			return errors.New("external response unavailable; preserve bundle and lookup original key")
		}
		if response.StatusCode != http.StatusOK {
			return fmt.Errorf("external writer returned HTTP %d; preserve bundle and lookup original key", response.StatusCode)
		}
		if strict(data, &entry) != nil {
			return errors.New("external bank result invalid; preserve bundle")
		}
	}
	got, e := entry.Record.Event.Digest()
	if e != nil || entry.Validate() != nil || got != hash || entry.Record.AuthoritySignatureHash != bankcredit.Hash([]byte(b.Signature)) {
		return errors.New("bank original differs from sealed event")
	}
	data, _ := json.Marshal(entry)
	receiptPath := path + ".receipt.json"
	if previous, e := os.ReadFile(receiptPath); e == nil {
		var prior bankcredit.Entry
		if strict(previous, &prior) != nil || prior.Validate() != nil || prior.RecordHash != entry.RecordHash {
			return errors.New("retained original bank receipt conflict")
		}
	} else if !errors.Is(e, os.ErrNotExist) {
		return errors.New("retained bank receipt unavailable")
	} else if e = writeNew(receiptPath, data); e != nil {
		return e
	}
	return json.NewEncoder(out).Encode(map[string]any{"status": "CREDITED_ORIGINAL_VERIFIED", "event_id": b.Event.EventID, "event_hash": hash, "record_hash": entry.RecordHash, "sequence": entry.Record.Sequence})
}
