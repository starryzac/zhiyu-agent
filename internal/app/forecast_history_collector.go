package app

import (
	"context"
	"encoding/json"
	"reflect"
	"sort"
	"time"

	"github.com/jackc/pgx/v5"
	"zhiyu.local/zhiyu-go/internal/execution/bankv2"
	funds "zhiyu.local/zhiyu-go/internal/funds/domain"
	policy "zhiyu.local/zhiyu-go/internal/policy/domain"
)

func (s *Service) forecastHistoryCaptures(ctx context.Context, tx pgx.Tx, p Principal, now time.Time) ([]forecastHistoryCapture, map[string][]string, error) {
	rows, err := tx.Query(ctx, `SELECT canonical,digest,octet_length(canonical) FROM evidence_blobs WHERE environment_id=$1 AND user_id=$2 AND kind=$3 ORDER BY id LIMIT 101`, p.EnvironmentID.String(), p.UserID.String(), forecastHistoryKind)
	if err != nil {
		return nil, nil, err
	}
	defer rows.Close()
	all := []forecastHistoryCapture{}
	originals := map[string][]string{"forecast_history_sources": {}}
	total := 0
	for rows.Next() {
		var raw []byte
		var hash string
		var n int
		if err = rows.Scan(&raw, &hash, &n); err != nil {
			return nil, nil, err
		}
		total += n
		if total > 16<<20 || len(all) >= 100 {
			return nil, nil, reject("HISTORY_CAPACITY_EXCEEDED", nil)
		}
		var c forecastHistoryCapture
		if Hash(raw) != hash || auditJSON(raw, &c) != nil || c.Protocol != forecastHistoryCaptureProtocol || c.Namespace != s.Namespace || c.EnvironmentID != p.EnvironmentID || c.UserID != p.UserID || c.SessionID == (funds.ID{}) || c.RecordedAt.After(now) {
			return nil, nil, reject("HISTORY_CAPTURE_INVALID", nil)
		}
		source, e := s.historySource(c.SourceID, p, false)
		if e != nil {
			return nil, nil, e
		}
		profile, _ := encode(c.Authority)
		if !reflect.DeepEqual(source.Authority, c.Authority) || c.AuthorityHash != Hash(profile) {
			return nil, nil, reject("HISTORY_AUTHORITY_PROFILE_CHANGED", nil)
		}
		if _, e = historyStatementFor(source.Authority, c.Envelope, c.RecordedAt); e != nil {
			return nil, nil, e
		}
		originals["forecast_history_sources"] = append(originals["forecast_history_sources"], string(raw))
		all = append(all, c)
	}
	return all, originals, rows.Err()
}

func (s *Service) collectForecastHistory(ctx context.Context, tx pgx.Tx, p Principal, snapshot *templateSnapshot) error {
	collectForecastHistoryAttempts.Add(1)
	all, raw, err := s.forecastHistoryCaptures(ctx, tx, p, snapshot.AsOf)
	if err != nil {
		return err
	}
	if len(all) == 0 {
		return nil
	}
	for k, v := range raw {
		snapshot.Raw[k] = v
	}
	latest := map[string]forecastHistoryCapture{}
	statements := map[string]policy.HistoryStatement{}
	for _, capture := range all {
		statement, e := historyStatementFor(capture.Authority, capture.Envelope, snapshot.AsOf)
		if e != nil {
			return e
		}
		old, exists := statements[capture.SourceID]
		if exists && old.IssuedAt.Equal(statement.IssuedAt) && latest[capture.SourceID].Envelope.RawSHA256 != capture.Envelope.RawSHA256 {
			return reject("HISTORY_SOURCE_FORK", nil)
		}
		if !exists || statement.IssuedAt.After(old.IssuedAt) {
			latest[capture.SourceID], statements[capture.SourceID] = capture, statement
		}
	}
	accounts := map[funds.ID]bool{}
	for _, a := range snapshot.Facts.Accounts {
		accounts[a.ID] = true
		snapshot.Facts.HistoryAccounts = append(snapshot.Facts.HistoryAccounts, a.ID)
	}
	sort.Slice(snapshot.Facts.HistoryAccounts, func(i, j int) bool {
		return snapshot.Facts.HistoryAccounts[i].String() < snapshot.Facts.HistoryAccounts[j].String()
	})
	covered := map[funds.ID]bool{}
	seen := map[funds.ID]bool{}
	for sourceID, statement := range statements {
		if statement.Timezone != snapshot.Timezone {
			return reject("HISTORY_TIMEZONE_SCOPE_INVALID", nil)
		}
		if err = s.verifyForecastHistoryPayments(ctx, tx, p, statement); err != nil {
			return err
		}
		from, _ := policy.TemplateDate(statement.FromDate)
		through, _ := policy.TemplateDate(statement.ThroughDate)
		for _, id := range statement.AccountIDs {
			if !accounts[id] || covered[id] {
				return reject("HISTORY_ACCOUNT_SCOPE_INVALID", nil)
			}
			covered[id] = true
			dates := []string{}
			for d := from; !d.After(through); d = d.AddDate(0, 0, 1) {
				dates = append(dates, d.Format("2006-01-02"))
			}
			snapshot.Facts.Coverage = append(snapshot.Facts.Coverage, policy.TemplateHistoryCoverage{AccountID: id, Dates: dates})
		}
		for _, row := range statement.Transactions {
			if seen[row.ID] {
				return reject("HISTORY_TRANSACTION_DUPLICATE", nil)
			}
			seen[row.ID] = true
			snapshot.Facts.History = append(snapshot.Facts.History, row)
		}
		for _, w := range statement.SeasonalWindows {
			snapshot.Facts.SeasonalWindows = append(snapshot.Facts.SeasonalWindows, policy.TemplateSeasonalWindow{SourceProtocol: policy.HistoryStatementProtocol, HolidayCode: w.HolidayCode, Start: w.Start, End: w.End, Verified: true, EvidenceHash: latest[sourceID].Envelope.RawSHA256})
		}
	}
	sort.Slice(snapshot.Facts.Coverage, func(i, j int) bool {
		return snapshot.Facts.Coverage[i].AccountID.String() < snapshot.Facts.Coverage[j].AccountID.String()
	})
	sort.Slice(snapshot.Facts.History, func(i, j int) bool {
		a, b := snapshot.Facts.History[i], snapshot.Facts.History[j]
		if a.Date != b.Date {
			return a.Date < b.Date
		}
		return a.ID.String() < b.ID.String()
	})
	sort.Slice(snapshot.Facts.SeasonalWindows, func(i, j int) bool {
		a, b := snapshot.Facts.SeasonalWindows[i], snapshot.Facts.SeasonalWindows[j]
		if a.HolidayCode != b.HolidayCode {
			return a.HolidayCode < b.HolidayCode
		}
		return a.Start < b.Start
	})
	return nil
}

// Known local simulated payments within the statement's closed range cannot
// disappear or be classified as transfers. These checks use retained request,
// bank result, receipt, journal and exact legs; no bank I/O occurs in a read.
func (s *Service) verifyForecastHistoryPayments(ctx context.Context, tx pgx.Tx, p Principal, statement policy.HistoryStatement) error {
	rows, err := tx.Query(ctx, `SELECT o.id::text,o.bank_namespace,o.bank_key,o.bank_request_hash::text,o.bank_request,o.receipt_id::text,r.original,r.original_hash::text,o.permit_signature FROM native_operations o LEFT JOIN native_receipts r ON(r.environment_id=o.environment_id AND r.user_id=o.user_id AND r.operation_id=o.id AND r.id=o.receipt_id) WHERE o.environment_id=$1 AND o.user_id=$2 AND o.status='SETTLED' ORDER BY o.id LIMIT 1001`, p.EnvironmentID.String(), p.UserID.String())
	if err != nil {
		return err
	}
	type entry struct {
		o               nativeIncomeLocalOperation
		raw             []byte
		hash, signature string
	}
	entries := []entry{}
	for rows.Next() {
		var e entry
		e.o.State = "SETTLED"
		if err = rows.Scan(&e.o.ID, &e.o.Namespace, &e.o.Key, &e.o.RequestHash, &e.o.Request, &e.o.ReceiptID, &e.raw, &e.hash, &e.signature); err != nil {
			rows.Close()
			return reject("HISTORY_PAYMENT_ORIGINAL_INVALID", err)
		}
		entries = append(entries, e)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return err
	}
	if len(entries) > 1000 {
		return reject("HISTORY_CAPACITY_EXCEEDED", nil)
	}
	transactions := map[string]policy.TemplateHistoryTransaction{}
	for _, row := range statement.Transactions {
		transactions[row.ID.String()] = row
	}
	zone, _ := policy.TemplateLocation(statement.Timezone)
	accountSet := map[string]bool{}
	for _, id := range statement.AccountIDs {
		accountSet[id.String()] = true
	}
	for _, e := range entries {
		var receipt NativeReceipt
		var request bankv2.Request
		if Hash(e.raw) != e.hash || auditJSON(e.raw, &receipt) != nil || auditJSON(e.o.Request, &request) != nil {
			return reject("HISTORY_PAYMENT_ORIGINAL_INVALID", nil)
		}
		requestHash, digestErr := request.Digest()
		if digestErr != nil || requestHash != e.o.RequestHash || request.Namespace != s.Namespace || request.UserID != p.UserID.String() || request.OperationID != e.o.ID || request.Key != e.o.Key || e.o.Namespace != s.Namespace || receipt.OperationID.String() != e.o.ID || bankv2.VerifyResult(request, receipt.BankResult) != nil || receipt.BankResult.SettledAt == nil {
			return reject("HISTORY_PAYMENT_ORIGINAL_INVALID", nil)
		}
		date := receipt.BankResult.SettledAt.In(zone).Format("2006-01-02")
		covered := false
		sourceAccounts := map[string]bool{}
		for _, use := range request.Effect.CashUses {
			sourceAccounts[use.AccountID] = true
			covered = covered || accountSet[use.AccountID]
		}
		row, present := transactions[e.o.ID]
		if request.Effect.Kind != bankv2.Payment {
			if present && row.EconomicRole == "CONSUMPTION" {
				return reject("HISTORY_PAYMENT_CLASSIFICATION_INVALID", nil)
			}
			continue
		}
		if date < statement.FromDate || date > statement.ThroughDate || !covered {
			if present {
				return reject("HISTORY_PAYMENT_SCOPE_OR_DATE_INVALID", nil)
			}
			continue
		}
		if len(sourceAccounts) != 1 {
			return reject("HISTORY_PAYMENT_MULTI_ACCOUNT_UNSUPPORTED", nil)
		}
		if !present || row.Date != date || !sourceAccounts[row.AccountID.String()] || row.Amount != request.Effect.Amount || row.Direction != "DEBIT" || row.EconomicRole != "CONSUMPTION" {
			return reject("HISTORY_PAYMENT_MISSING_OR_CHANGED", nil)
		}
		if request.Namespace != s.Namespace || request.UserID != p.UserID.String() || request.OperationID != e.o.ID || request.Key != e.o.Key || bankv2.VerifyResult(request, receipt.BankResult) != nil {
			return reject("HISTORY_PAYMENT_ORIGINAL_INVALID", nil)
		}
		if err = nativeStoredPermit(ctx, tx, p, receipt.OperationID, request, e.signature); err != nil {
			return err
		}
		if err = verifyIncomeNativeReceipt(ctx, tx, p, e.o, request, receipt.BankResult, s.now()); err != nil {
			return err
		}
		resultRaw, _ := json.Marshal(receipt.BankResult)
		var observed bool
		if err = tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM native_bank_observations WHERE environment_id=$1 AND user_id=$2 AND operation_id=$3 AND status='SETTLED' AND original=$4 AND original_hash=$5)`, p.EnvironmentID.String(), p.UserID.String(), e.o.ID, resultRaw, Hash(resultRaw)).Scan(&observed); err != nil || !observed {
			return reject("HISTORY_PAYMENT_ORIGINAL_INVALID", err)
		}
	}
	return nil
}
