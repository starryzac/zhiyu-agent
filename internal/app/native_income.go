package app

import (
	"bytes"
	"context"
	"time"

	"github.com/jackc/pgx/v5"
	"zhiyu.local/zhiyu-go/internal/adapters/postgres"
	"zhiyu.local/zhiyu-go/internal/execution/bankcredit"
	funds "zhiyu.local/zhiyu-go/internal/funds/domain"
)

type NativeIncomeImportResult struct {
	Protocol             string      `json:"protocol"`
	Status               string      `json:"status"`
	ImportedOriginIDs    []funds.ID  `json:"imported_origin_ids"`
	Amount               funds.Money `json:"amount_cents"`
	CreditWatermark      int64       `json:"credit_watermark"`
	V1OperationWatermark int64       `json:"v1_operation_watermark"`
	V2OperationWatermark int64       `json:"v2_operation_watermark"`
	FundsVersion         uint64      `json:"funds_version"`
	SourceVersion        uint64      `json:"source_version"`
	BankCaptureHash      string      `json:"bank_capture_hash"`
	CapturedAt           time.Time   `json:"captured_at"`
}

// ImportNativeIncome imports independently credited facts; it neither accepts
// client financial payloads nor grants permission to use the newly observed
// income. All bank I/O precedes the environment/user lock.
func (s *Service) ImportNativeIncome(ctx context.Context, p Principal, sources NativeIncomeSources) (NativeIncomeImportResult, error) {
	return s.importNativeIncome(ctx, p, sources, false)
}

// observeNativeIncome is private to server-owned intake code. Its SYSTEM
// identity can record confirmed facts, never create execution permission.
func (s *Service) observeNativeIncome(ctx context.Context, p Principal, sources NativeIncomeSources) (NativeIncomeImportResult, error) {
	return s.importNativeIncome(ctx, p, sources, true)
}

func (s *Service) importNativeIncome(ctx context.Context, p Principal, sources NativeIncomeSources, trustedObservation bool) (NativeIncomeImportResult, error) {
	return s.importNativeIncomeClaimed(ctx, p, sources, trustedObservation, nil)
}

func (s *Service) importNativeIncomeClaimed(ctx context.Context, p Principal, sources NativeIncomeSources, trustedObservation bool, intake *nativeIncomeIntakeClaim) (NativeIncomeImportResult, error) {
	var zero NativeIncomeImportResult
	if trustedObservation {
		if p.Kind != "SYSTEM" || p.SessionID != (funds.ID{}) {
			return zero, reject("FORBIDDEN", nil)
		}
		env, err := s.environment(ctx, s.Pool, false)
		if err != nil {
			return zero, err
		}
		if err = sameUser(p, env.ID); err != nil {
			return zero, err
		}
	} else {
		if err := s.auditHuman(ctx, p); err != nil {
			return zero, err
		}
	}
	capture, raw, err := s.captureNativeIncome(ctx, p, sources)
	if err != nil {
		return zero, err
	}
	if s.Failpoint != nil {
		if err = s.Failpoint("native_income_after_bank_read"); err != nil {
			return zero, err
		}
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
	fv, sv, err := lockUser(ctx, tx, p)
	if err != nil {
		return zero, err
	}
	if !trustedObservation {
		if err = s.human(ctx, tx, p); err != nil {
			return zero, err
		}
	}
	if intake != nil {
		if !trustedObservation || intake.Principal != p {
			return zero, reject("FORBIDDEN", nil)
		}
		if err = currentNativeIncomeIntake(ctx, tx, *intake); err != nil {
			return zero, err
		}
	}
	var pending bool
	if err = tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM operations WHERE environment_id=$1 AND user_id=$2 AND status NOT IN ('SETTLED','REJECTED','CANCELLED')) OR EXISTS(SELECT 1 FROM native_operations WHERE environment_id=$1 AND user_id=$2 AND status NOT IN ('SETTLED','REJECTED','CANCELLED'))`, p.EnvironmentID.String(), p.UserID.String()).Scan(&pending); err != nil {
		return zero, err
	}
	if pending {
		return zero, reject("INCOME_OPERATION_PENDING", nil)
	}
	if fv != capture.LocalBasis.FundsVersion || sv != capture.LocalBasis.SourceVersion || env.WriterGeneration != capture.LocalBasis.WriterGeneration || env.ControlVersion != capture.LocalBasis.ControlVersion {
		return zero, reject("INCOME_SOURCE_CHANGED", nil)
	}
	if err = s.verifyIncomeOperations(ctx, tx, p, capture); err != nil {
		return zero, err
	}
	dispositions, err := verifiedNativeIncomeDispositions(capture)
	if err != nil {
		return zero, err
	}
	now := s.now()
	if capture.State.CapturedAt.After(now) || capture.State.CapturedAt.Before(now.Add(-30*time.Second)) {
		return zero, reject("INCOME_BANK_SNAPSHOT_INVALID", nil)
	}
	ledger, err := s.Store.LoadNativeLedger(ctx, tx, p.EnvironmentID, p.UserID, now)
	if err != nil {
		return zero, err
	}
	if err = verifyNativeIncomeStock(ledger, capture); err != nil {
		return zero, err
	}
	ledger, imported, err := verifyAndAddNativeIncome(ctx, tx, p, ledger, capture.State, dispositions, now)
	if err != nil {
		return zero, err
	}
	result := NativeIncomeImportResult{Protocol: nativeIncomeProtocol, Status: "NO_NEW_INCOME", ImportedOriginIDs: []funds.ID{}, CreditWatermark: capture.State.CreditWatermark, V1OperationWatermark: capture.State.V1OperationWatermark, V2OperationWatermark: capture.State.V2OperationWatermark, FundsVersion: fv, SourceVersion: sv, BankCaptureHash: Hash(raw), CapturedAt: capture.State.CapturedAt}
	if len(imported) == 0 {
		if intake != nil {
			if err = finishNativeIncomeIntake(ctx, tx, *intake, result); err != nil {
				return zero, err
			}
		}
		return result, tx.Commit(ctx)
	}
	for _, entry := range imported {
		e := entry.Record.Event
		id, _ := funds.ParseID(e.OriginID)
		result.ImportedOriginIDs = append(result.ImportedOriginIDs, id)
		result.Amount, err = result.Amount.Add(e.Amount)
		if err != nil {
			return zero, err
		}
		recordRaw, _ := entry.Record.CanonicalBytes()
		if _, err = tx.Exec(ctx, `INSERT INTO evidence_blobs(environment_id,user_id,id,kind,canonical,digest,created_at) VALUES($1,$2,$3,'BANK_EXTERNAL_CREDIT_V1',$4,$5,$6)`, p.EnvironmentID.String(), p.UserID.String(), e.EvidenceID, recordRaw, entry.RecordHash, now); err != nil {
			return zero, err
		}
	}
	if err = s.Store.PersistNativeLedger(ctx, tx, p.EnvironmentID, p.UserID, ledger); err != nil {
		return zero, err
	}
	if _, err = tx.Exec(ctx, `UPDATE users SET funds_version=funds_version+1 WHERE environment_id=$1 AND id=$2`, p.EnvironmentID.String(), p.UserID.String()); err != nil {
		return zero, err
	}
	timezone, err := templateScopedTimezone(ctx, tx, p, "")
	if err != nil {
		return zero, err
	}
	view, err := s.refreshTemplateProtection(ctx, tx, p, timezone)
	if err != nil {
		return zero, err
	}
	result.Status, result.FundsVersion, result.SourceVersion = "IMPORTED", fv+1, view.SourceVersion
	for _, entry := range imported {
		e := entry.Record.Event
		payload, err := encode(struct {
			Protocol          string `json:"protocol"`
			OriginID          string `json:"origin_id"`
			EvidenceID        string `json:"evidence_id"`
			RecordHash        string `json:"record_hash"`
			ExternalAuthority string `json:"external_authority"`
			ExternalEventID   string `json:"external_event_id"`
			CreditSequence    int64  `json:"credit_sequence"`
			SourceVersion     uint64 `json:"source_version"`
			BankCaptureHash   string `json:"bank_capture_hash"`
		}{nativeIncomeProtocol, e.OriginID, e.EvidenceID, entry.RecordHash, e.AuthorityID, e.EventID, entry.Record.Sequence, view.SourceVersion, result.BankCaptureHash})
		if err != nil {
			return zero, err
		}
		if _, err = tx.Exec(ctx, `INSERT INTO outbox(environment_id,user_id,id,aggregate_id,aggregate_version,kind,payload,created_at) VALUES($1,$2,$3,$4,1,'INCOME_IMPORTED',$5,$6)`, p.EnvironmentID.String(), p.UserID.String(), e.EvidenceID, e.OriginID, payload, now); err != nil {
			return zero, err
		}
	}
	if _, err = tx.Exec(ctx, `INSERT INTO evidence_blobs(environment_id,user_id,id,kind,canonical,digest,created_at) VALUES($1,$2,$3,'NATIVE_INCOME_SNAPSHOT_V1',$4,$5,$6)`, p.EnvironmentID.String(), p.UserID.String(), "native-income-capture:"+result.BankCaptureHash, raw, result.BankCaptureHash, now); err != nil {
		return zero, err
	}
	if s.Failpoint != nil {
		if err = s.Failpoint("native_income_before_commit"); err != nil {
			return zero, err
		}
	}
	if intake != nil {
		if err = finishNativeIncomeIntake(ctx, tx, *intake, result); err != nil {
			return zero, err
		}
	}
	return result, tx.Commit(ctx)
}

func verifyAndAddNativeIncome(ctx context.Context, tx pgx.Tx, p Principal, ledger postgres.NativeLedger, state bankcredit.CurrentState, dispositions map[string]nativeIncomeDisposition, now time.Time) (postgres.NativeLedger, []bankcredit.Entry, error) {
	fail := func() (postgres.NativeLedger, []bankcredit.Entry, error) {
		return ledger, nil, reject("INCOME_LEDGER_SNAPSHOT_MISMATCH", nil)
	}
	snapshot := ledger.Income.Snapshot()
	localOrigins := map[string]funds.BankCreditFact{}
	localLocations := map[string]funds.IncomeLocation{}
	for _, o := range snapshot.Origins {
		localOrigins[o.ID().String()] = o.Fact()
	}
	for _, l := range snapshot.Locations {
		key := l.OriginID.String() + "/" + l.AccountID.String()
		if l.Spent != dispositions[key].Spent {
			return fail()
		}
		localLocations[key] = l
	}
	bankOrigins := map[string]bankcredit.Origin{}
	for _, o := range state.Origins {
		bankOrigins[o.ID] = o
	}
	credits := map[string]bankcredit.Entry{}
	for _, entry := range state.Credits {
		credits[entry.Record.Event.OriginID] = entry
	}
	imported := []bankcredit.Entry{}
	delta := map[string]funds.Money{}
	evidence := nativeIncomeEvidenceReader{ctx: ctx, tx: tx, p: p, credits: state.Credits, known: localOrigins}
	for i, entry := range state.Credits {
		e := entry.Record.Event
		if fact, exists := localOrigins[e.OriginID]; exists {
			if fact.EvidenceID.String() != e.EvidenceID || fact.EvidenceHash.String() != entry.RecordHash {
				return fail()
			}
			stored, err := evidence.row(i, entry)
			if err != nil {
				return ledger, nil, reject("INCOME_ORIGINAL_CONFLICT", err)
			}
			want, _ := entry.Record.CanonicalBytes()
			if stored.bytes != int64(len(want)) || stored.kind != "BANK_EXTERNAL_CREDIT_V1" || stored.digest != entry.RecordHash || Hash(stored.canonical) != stored.digest || !bytes.Equal(stored.canonical, want) {
				return fail()
			}
			continue
		}
		o := bankOrigins[e.OriginID]
		if len(o.Locations) != 1 || o.Locations[0].AccountID != e.AccountID || o.Locations[0].Available != e.Amount || !o.Locations[0].Assigned.IsZero() || !o.Locations[0].Reserved.IsZero() {
			return ledger, nil, reject("INCOME_NEW_ORIGIN_ALREADY_USED", nil)
		}
		var err error
		delta[e.AccountID], err = delta[e.AccountID].Add(e.Amount)
		if err != nil {
			return ledger, nil, err
		}
		imported = append(imported, entry)
	}
	for _, o := range state.Origins {
		fact, exists := localOrigins[o.ID]
		if !exists {
			if _, proven := credits[o.ID]; !proven {
				return ledger, nil, reject("INCOME_UNPROVEN_BANK_ORIGIN", nil)
			}
			continue
		}
		if fact.AccountID.String() != o.OriginalAccountID || fact.Amount != o.Amount || !fact.OccurredAt.Equal(o.OccurredAt) || fact.EvidenceHash.String() != o.EvidenceHash || fact.Role != funds.RoleIncome || fact.Source != funds.BankConfirmed {
			return fail()
		}
		for _, b := range o.Locations {
			key := o.ID + "/" + b.AccountID
			l, exists := localLocations[key]
			if !exists {
				return fail()
			}
			available, err := b.Available.Sub(b.Reserved)
			assigned, assignmentErr := l.Assigned.Add(dispositions[key].PurchasedAssigned)
			if err != nil || assignmentErr != nil || available != l.Available || b.Assigned != assigned || b.Reserved != l.Reserved {
				return fail()
			}
			delete(dispositions, key)
			delete(localLocations, key)
		}
		delete(localOrigins, o.ID)
	}
	if len(localOrigins) != 0 || len(localLocations) != 0 || len(dispositions) != 0 || len(state.Accounts) != len(ledger.Accounts) {
		return fail()
	}
	bankAccounts := map[string]bankcredit.Account{}
	for _, a := range state.Accounts {
		bankAccounts[a.ID] = a
	}
	for i := range ledger.Accounts {
		a := &ledger.Accounts[i]
		b, exists := bankAccounts[a.ID.String()]
		expected, err := a.Balance.Add(delta[a.ID.String()])
		if !exists || err != nil || expected != b.Balance || !b.Reserved.IsZero() {
			return fail()
		}
		if !delta[a.ID.String()].IsZero() {
			a.Balance, a.ObservedAt = expected, state.CapturedAt
		}
		delete(bankAccounts, a.ID.String())
		delete(delta, a.ID.String())
	}
	if len(bankAccounts) != 0 || len(delta) != 0 {
		return fail()
	}
	for _, entry := range imported {
		e := entry.Record.Event
		originID, _ := funds.ParseID(e.OriginID)
		accountID, _ := funds.ParseID(e.AccountID)
		evidenceID, _ := funds.ParseID(e.EvidenceID)
		hash, err := funds.ParseEvidenceHash(entry.RecordHash)
		if err != nil {
			return ledger, nil, err
		}
		origin, err := funds.NewIncomeOrigin(funds.BankCreditFact{TransactionID: originID, AccountID: accountID, Currency: funds.CNY, Amount: e.Amount, Role: funds.RoleIncome, Source: funds.BankConfirmed, OccurredAt: e.OccurredAt, ObservedAt: state.CapturedAt, RecordedAt: now, EvidenceID: evidenceID, EvidenceHash: hash})
		if err != nil {
			return ledger, nil, err
		}
		snapshot.Origins = append(snapshot.Origins, origin)
		snapshot.Locations = append(snapshot.Locations, funds.IncomeLocation{FragmentID: funds.LocationID(originID, accountID), OriginID: originID, AccountID: accountID, Available: e.Amount})
	}
	snapshot.AsOf = now
	var err error
	ledger.Income, err = funds.NewIncomeLedger(snapshot)
	return ledger, imported, err
}
