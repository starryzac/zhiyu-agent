package app

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"reflect"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	funds "zhiyu.local/zhiyu-go/internal/funds/domain"
	policy "zhiyu.local/zhiyu-go/internal/policy/domain"
)

const forecastHistoryKind = "FORECAST_HISTORY_STATEMENT_V1"
const forecastHistoryCommandKind = "FORECAST_HISTORY_IMPORT_COMMAND_V1"
const forecastHistoryCaptureProtocol = "forecast-history-capture-v1"

type forecastHistoryCapture struct {
	Protocol      string                          `json:"protocol"`
	ID            string                          `json:"id"`
	SourceID      string                          `json:"source_id"`
	EnvironmentID funds.ID                        `json:"environment_id"`
	UserID        funds.ID                        `json:"user_id"`
	Namespace     string                          `json:"namespace"`
	Authority     ForecastHistoryAuthority        `json:"authority"`
	AuthorityHash string                          `json:"authority_hash"`
	Envelope      policy.HistoryStatementEnvelope `json:"envelope"`
	RecordedAt    time.Time                       `json:"recorded_at"`
	SessionID     funds.ID                        `json:"session_id"`
}

type forecastHistoryCommand struct {
	Protocol string                `json:"protocol"`
	SourceID string                `json:"source_id"`
	Result   ForecastHistoryImport `json:"result"`
}

func (s *Service) historySource(id string, p Principal, reader bool) (ForecastHistorySource, error) {
	if s.ForecastHistorySources == nil || len(id) < 1 || len(id) > 64 || strings.ContainsAny(id, "/\\\x00\r\n") {
		return ForecastHistorySource{}, reject("HISTORY_SOURCE_NOT_CONFIGURED", nil)
	}
	source, ok := s.ForecastHistorySources.Sources[id]
	a := source.Authority
	public, e := hex.DecodeString(a.PublicKeyHex)
	if !ok || a.Namespace != s.Namespace || a.UserID != p.UserID || a.IssuerID == "" || len(a.IssuerID) > 128 || len(a.AccountIDs) < 1 || len(a.AccountIDs) > 100 || e != nil || len(public) != ed25519.PublicKeySize || reader && source.Reader == nil {
		return ForecastHistorySource{}, reject("HISTORY_SOURCE_NOT_CONFIGURED", nil)
	}
	previous := ""
	for _, account := range a.AccountIDs {
		if account == (funds.ID{}) || account.String() <= previous {
			return ForecastHistorySource{}, reject("HISTORY_SOURCE_NOT_CONFIGURED", nil)
		}
		previous = account.String()
	}
	return source, nil
}

func historyStatementFor(authority ForecastHistoryAuthority, envelope policy.HistoryStatementEnvelope, now time.Time) (policy.HistoryStatement, error) {
	public, e := hex.DecodeString(authority.PublicKeyHex)
	if e != nil {
		return policy.HistoryStatement{}, reject("HISTORY_SIGNATURE_INVALID", nil)
	}
	statement, _, e := policy.VerifyHistoryEnvelope(envelope, ed25519.PublicKey(public))
	if e != nil || statement.IssuerID != authority.IssuerID || statement.Namespace != authority.Namespace || statement.UserID != authority.UserID || !reflect.DeepEqual(statement.AccountIDs, authority.AccountIDs) || statement.IssuedAt.After(now) {
		return policy.HistoryStatement{}, reject("HISTORY_SIGNATURE_OR_SCOPE_INVALID", e)
	}
	return statement, nil
}

func historyCommand(ctx context.Context, q queryRow, p Principal, key, source string) (ForecastHistoryImport, bool, error) {
	var raw []byte
	var hash string
	err := q.QueryRow(ctx, `SELECT canonical,digest FROM evidence_blobs WHERE environment_id=$1 AND user_id=$2 AND id=$3 AND kind=$4`, p.EnvironmentID.String(), p.UserID.String(), "forecast-history-command:"+key, forecastHistoryCommandKind).Scan(&raw, &hash)
	if errors.Is(err, pgx.ErrNoRows) {
		return ForecastHistoryImport{}, false, nil
	}
	if err != nil {
		return ForecastHistoryImport{}, false, err
	}
	var c forecastHistoryCommand
	if Hash(raw) != hash || auditJSON(raw, &c) != nil || c.Protocol != "forecast-history-import-command-v1" {
		return ForecastHistoryImport{}, false, reject("EVIDENCE_INVALID", nil)
	}
	if c.SourceID != source {
		return ForecastHistoryImport{}, false, reject("IDEMPOTENCY_CONFLICT", nil)
	}
	c.Result.Replayed = true
	return c.Result, true, nil
}

// ImportForecastHistory captures one separately signed source. USER identity
// proves who requested observation, not who may invent historical facts. Only
// configured issuer public keys can authenticate the bytes. It changes no
// cash, income, reservation, bank operation or financial authorization.
func (s *Service) ImportForecastHistory(ctx context.Context, p Principal, key, sourceID string) (ForecastHistoryImport, error) {
	var zero ForecastHistoryImport
	if err := validateKey(key); err != nil {
		return zero, err
	}
	if err := s.auditHuman(ctx, p); err != nil {
		return zero, err
	}
	if v, found, e := historyCommand(ctx, s.Pool, p, key, sourceID); e != nil || found {
		return v, e
	}
	source, err := s.historySource(sourceID, p, true)
	if err != nil {
		return zero, err
	}
	wire, err := source.Reader.ReadHistory(ctx)
	if err != nil {
		return zero, reject("HISTORY_SOURCE_UNAVAILABLE", nil)
	}
	envelope, err := parseForecastHistoryEnvelope(wire)
	if err != nil {
		return zero, err
	}
	statement, err := historyStatementFor(source.Authority, envelope, s.now())
	if err != nil {
		return zero, err
	}
	tx, err := s.begin(ctx)
	if err != nil {
		return zero, err
	}
	defer rollback(ctx, tx)
	env, err := s.environment(ctx, tx, true)
	if err != nil {
		return zero, err
	}
	if err = sameUser(p, env.ID); err != nil {
		return zero, err
	}
	if _, _, err = lockUser(ctx, tx, p); err != nil {
		return zero, err
	}
	if err = s.human(ctx, tx, p); err != nil {
		return zero, err
	}
	if v, found, e := historyCommand(ctx, tx, p, key, sourceID); e != nil || found {
		return v, e
	}
	for _, id := range statement.AccountIDs {
		var present bool
		if err = tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM accounts WHERE environment_id=$1 AND user_id=$2 AND id=$3)`, p.EnvironmentID.String(), p.UserID.String(), id.String()).Scan(&present); err != nil || !present {
			return zero, reject("HISTORY_ACCOUNT_SCOPE_INVALID", err)
		}
	}
	if err = s.verifyForecastHistoryPayments(ctx, tx, p, statement); err != nil {
		return zero, err
	}
	id := "forecast-history:" + sourceID + ":" + statement.StatementID
	var previousRaw []byte
	var previousHash string
	err = tx.QueryRow(ctx, `SELECT canonical,digest FROM evidence_blobs WHERE environment_id=$1 AND user_id=$2 AND id=$3 AND kind=$4`, p.EnvironmentID.String(), p.UserID.String(), id, forecastHistoryKind).Scan(&previousRaw, &previousHash)
	replay := err == nil
	now := s.now()
	if replay {
		var old forecastHistoryCapture
		if Hash(previousRaw) != previousHash || auditJSON(previousRaw, &old) != nil || old.Envelope.RawSHA256 != envelope.RawSHA256 || old.Envelope.SignatureHex != envelope.SignatureHex || old.SourceID != sourceID {
			return zero, reject("IDEMPOTENCY_CONFLICT", nil)
		}
		now = old.RecordedAt
	} else {
		if !errors.Is(err, pgx.ErrNoRows) {
			return zero, err
		}
		prior, _, e := s.forecastHistoryCaptures(ctx, tx, p, s.now())
		if e != nil {
			return zero, e
		}
		for _, old := range prior {
			if old.SourceID == sourceID {
				previous, e := historyStatementFor(source.Authority, old.Envelope, s.now())
				if e != nil {
					return zero, e
				}
				if e = historyAppendCompatible(previous, statement); e != nil {
					return zero, e
				}
			}
		}
		authorityRaw, _ := encode(source.Authority)
		capture := forecastHistoryCapture{Protocol: forecastHistoryCaptureProtocol, ID: id, SourceID: sourceID, EnvironmentID: p.EnvironmentID, UserID: p.UserID, Namespace: s.Namespace, Authority: source.Authority, AuthorityHash: Hash(authorityRaw), Envelope: envelope, RecordedAt: now, SessionID: p.SessionID}
		raw, e := encode(capture)
		if e != nil {
			return zero, e
		}
		if _, err = tx.Exec(ctx, `INSERT INTO evidence_blobs(environment_id,user_id,id,kind,canonical,digest,created_at) VALUES($1,$2,$3,$4,$5,$6,$7)`, p.EnvironmentID.String(), p.UserID.String(), id, forecastHistoryKind, raw, Hash(raw), now); err != nil {
			return zero, err
		}
		if _, err = s.refreshTemplateProtection(ctx, tx, p, statement.Timezone); err != nil {
			return zero, err
		}
	}
	result := ForecastHistoryImport{Protocol: "forecast-history-import-v1", ID: id, SourceID: sourceID, StatementID: statement.StatementID, StatementHash: envelope.RawSHA256, FromDate: statement.FromDate, ThroughDate: statement.ThroughDate, RecordedAt: now, Replayed: replay}
	if err = tx.QueryRow(ctx, `SELECT source_version FROM users WHERE environment_id=$1 AND id=$2`, p.EnvironmentID.String(), p.UserID.String()).Scan(&result.SourceVersion); err != nil {
		return zero, err
	}
	commandRaw, _ := encode(forecastHistoryCommand{Protocol: "forecast-history-import-command-v1", SourceID: sourceID, Result: result})
	if _, err = tx.Exec(ctx, `INSERT INTO evidence_blobs(environment_id,user_id,id,kind,canonical,digest,created_at) VALUES($1,$2,$3,$4,$5,$6,$7)`, p.EnvironmentID.String(), p.UserID.String(), "forecast-history-command:"+key, forecastHistoryCommandKind, commandRaw, Hash(commandRaw), s.now()); err != nil {
		return zero, err
	}
	return result, tx.Commit(ctx)
}

func historyAppendCompatible(old, next policy.HistoryStatement) error {
	if old.StatementID == next.StatementID || !next.IssuedAt.After(old.IssuedAt) || next.Timezone != old.Timezone || next.SourceMode != old.SourceMode || next.ThroughDate < old.ThroughDate || next.FromDate < old.FromDate {
		return reject("HISTORY_SOURCE_REVISION_CONFLICT", nil)
	}
	from, through := next.FromDate, old.ThroughDate
	for _, project := range []bool{false, true} {
		left, right := map[string]string{}, map[string]string{}
		for _, side := range []struct {
			s      policy.HistoryStatement
			target map[string]string
		}{{old, left}, {next, right}} {
			if project {
				for _, w := range side.s.SeasonalWindows {
					if w.Start >= from && w.End <= through {
						raw, _ := encode(w)
						side.target[w.HolidayCode+":"+w.Start] = Hash(raw)
					}
				}
			} else {
				for _, row := range side.s.Transactions {
					if row.Date >= from && row.Date <= through {
						raw, _ := encode(row)
						side.target[row.ID.String()] = Hash(raw)
					}
				}
			}
		}
		if !reflect.DeepEqual(left, right) {
			return reject("HISTORY_SOURCE_REVISION_CONFLICT", nil)
		}
	}
	return nil
}
