package app

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	funds "zhiyu.local/zhiyu-go/internal/funds/domain"
	planning "zhiyu.local/zhiyu-go/internal/planning/domain"
	policy "zhiyu.local/zhiyu-go/internal/policy/domain"
)

const DemoSeedProtocol = "zhiyu-demo-seed-v1"

// SeedIdentity belongs only to the explicit local CLI. It is never accepted by
// a public HTTP handler and never grants a policy or standing permission.
type SeedIdentity struct {
	Protocol      string      `json:"protocol"`
	Namespace     string      `json:"namespace"`
	EnvironmentID funds.ID    `json:"environment_id"`
	UserID        funds.ID    `json:"user_id"`
	AccountID     funds.ID    `json:"account_id"`
	GoalID        funds.ID    `json:"goal_id"`
	LoginSecret   string      `json:"login_secret"`
	Target        funds.Money `json:"target_cents"`
	CreatedAt     time.Time   `json:"created_at"`
}

type BootstrapResult struct {
	Status        string   `json:"status"`
	Namespace     string   `json:"namespace"`
	EnvironmentID funds.ID `json:"environment_id"`
	UserID        funds.ID `json:"user_id"`
	AccountID     funds.ID `json:"account_id"`
	GoalID        funds.ID `json:"goal_id"`
}

func (seed SeedIdentity) validate(namespace string, now time.Time) error {
	if seed.Protocol != DemoSeedProtocol || seed.Namespace != namespace || seed.EnvironmentID == (funds.ID{}) || seed.UserID == (funds.ID{}) || seed.AccountID == (funds.ID{}) || seed.GoalID == (funds.ID{}) || len(seed.LoginSecret) < 32 || seed.Target.IsZero() || seed.CreatedAt.IsZero() || seed.CreatedAt.After(now) || !seed.CreatedAt.Equal(seed.CreatedAt.Truncate(time.Microsecond)) {
		return reject("INVALID_DEMO_SEED", nil)
	}
	return nil
}

func zeroDemoProtection(seed SeedIdentity, at time.Time) planning.Protection {
	// This is a narrowly stated synthetic closed-world contract. It is not a
	// fallback for missing obligations in an imported/existing financial user.
	proof := Hash([]byte(DemoSeedProtocol + "/synthetic-zero-obligations/" + seed.EnvironmentID.String() + "/" + seed.UserID.String()))
	return planning.Protection{Complete: true, ObservedAt: at.UTC(), EvidenceHash: proof, Checkpoints: []planning.ProtectionCheckpoint{{ID: "explicit-synthetic-zero-obligations", At: at.UTC()}}}
}

// Bootstrap inserts a NEW owned empty demo once and preserves every existing
// balance, version, goal contribution, confirmation, and operation on replay.
func (s *Service) Bootstrap(ctx context.Context, seed SeedIdentity) (BootstrapResult, error) {
	var result BootstrapResult
	if err := seed.validate(s.Namespace, s.now()); err != nil {
		return result, err
	}
	tx, err := s.begin(ctx)
	if err != nil {
		return result, err
	}
	defer rollback(ctx, tx)
	_, err = tx.Exec(ctx, `INSERT INTO environments(id,namespace) VALUES($1,$2) ON CONFLICT DO NOTHING`, seed.EnvironmentID.String(), seed.Namespace)
	if err != nil {
		return result, err
	}
	var envID string
	if err = tx.QueryRow(ctx, `SELECT id::text FROM environments WHERE namespace=$1 FOR UPDATE`, seed.Namespace).Scan(&envID); err != nil || envID != seed.EnvironmentID.String() {
		return result, reject("DEMO_SEED_IDENTITY_CONFLICT", err)
	}
	userInserted, err := tx.Exec(ctx, `INSERT INTO users(environment_id,id) VALUES($1,$2) ON CONFLICT DO NOTHING`, envID, seed.UserID.String())
	if err != nil {
		return result, err
	}
	p := Principal{EnvironmentID: seed.EnvironmentID, UserID: seed.UserID, Kind: "SYSTEM"}
	_, sourceVersion, err := lockUser(ctx, tx, p)
	if err != nil {
		return result, err
	}
	_, err = tx.Exec(ctx, `INSERT INTO accounts(environment_id,user_id,id,name,balance_cents,goal_owned_cents,observed_at) VALUES($1,$2,$3,'本地模拟现金',0,0,$4) ON CONFLICT DO NOTHING`, envID, seed.UserID.String(), seed.AccountID.String(), seed.CreatedAt)
	if err != nil {
		return result, err
	}
	var currency string
	if err = tx.QueryRow(ctx, `SELECT currency FROM accounts WHERE environment_id=$1 AND user_id=$2 AND id=$3`, envID, seed.UserID.String(), seed.AccountID.String()).Scan(&currency); err != nil || currency != "CNY" {
		return result, reject("DEMO_SEED_IDENTITY_CONFLICT", err)
	}
	_, err = tx.Exec(ctx, `INSERT INTO goals(environment_id,user_id,id,name,account_id,target_cents,month_period) VALUES($1,$2,$3,'我的单目标', $4,$5,$6) ON CONFLICT DO NOTHING`, envID, seed.UserID.String(), seed.GoalID.String(), seed.AccountID.String(), seed.Target.Cents(), seed.CreatedAt.In(time.FixedZone("Asia/Shanghai", 8*3600)).Format("2006-01"))
	if err != nil {
		return result, err
	}
	var account string
	if err = tx.QueryRow(ctx, `SELECT account_id::text FROM goals WHERE environment_id=$1 AND user_id=$2 AND id=$3`, envID, seed.UserID.String(), seed.GoalID.String()).Scan(&account); err != nil || account != seed.AccountID.String() {
		return result, reject("DEMO_SEED_IDENTITY_CONFLICT", err)
	}
	_, err = tx.Exec(ctx, `INSERT INTO login_credentials(environment_id,user_id,secret_hash) VALUES($1,$2,$3) ON CONFLICT DO NOTHING`, envID, seed.UserID.String(), Hash([]byte(seed.LoginSecret)))
	if err != nil {
		return result, err
	}
	var sameCredential bool
	if err = tx.QueryRow(ctx, `SELECT secret_hash=$3 FROM login_credentials WHERE environment_id=$1 AND user_id=$2`, envID, seed.UserID.String(), Hash([]byte(seed.LoginSecret))).Scan(&sameCredential); err != nil || !sameCredential {
		return result, reject("DEMO_SEED_CREDENTIAL_CONFLICT", err)
	}
	var hasProtection bool
	if err = tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM protection_snapshots WHERE environment_id=$1 AND user_id=$2 AND version=$3)`, envID, seed.UserID.String(), sourceVersion).Scan(&hasProtection); err != nil {
		return result, err
	}
	if !hasProtection {
		// Only a genuinely empty seed may establish this explicit contract.
		var empty bool
		if err = tx.QueryRow(ctx, `SELECT NOT EXISTS(SELECT 1 FROM income_origins WHERE environment_id=$1 AND user_id=$2) AND NOT EXISTS(SELECT 1 FROM policies WHERE environment_id=$1 AND user_id=$2) AND NOT EXISTS(SELECT 1 FROM operations WHERE environment_id=$1 AND user_id=$2) AND (SELECT COALESCE(sum(balance_cents),0)=0 FROM accounts WHERE environment_id=$1 AND user_id=$2)`, envID, seed.UserID.String()).Scan(&empty); err != nil {
			return result, err
		}
		if !empty || sourceVersion != 1 {
			return result, reject("DEMO_SEED_PROTECTION_MISSING", nil)
		}
		protection := zeroDemoProtection(seed, seed.CreatedAt)
		raw, e := encode(protection)
		if e != nil {
			return result, e
		}
		_, err = tx.Exec(ctx, `INSERT INTO protection_snapshots(environment_id,user_id,version,original,original_hash,observed_at) VALUES($1,$2,1,$3,$4,$5)`, envID, seed.UserID.String(), raw, Hash(raw), seed.CreatedAt)
		if err != nil {
			return result, err
		}
	}
	if userInserted.RowsAffected() == 1 {
		witnessEnabled, e := templateSourceWitnessEnabled(ctx, tx)
		if e != nil {
			return result, e
		}
		if witnessEnabled {
			// FV1 seals the actual empty user insertion. The newly inserted
			// account/zero-goal inventory forms the separate next prefix.
			if _, e = tx.Exec(ctx, `UPDATE users SET funds_version=funds_version+1 WHERE environment_id=$1 AND id=$2`, envID, seed.UserID.String()); e != nil {
				return result, e
			}
		}
	}
	if err = tx.Commit(ctx); err != nil {
		return result, err
	}
	return BootstrapResult{Status: "READY_EMPTY_DEMO", Namespace: seed.Namespace, EnvironmentID: seed.EnvironmentID, UserID: seed.UserID, AccountID: seed.AccountID, GoalID: seed.GoalID}, nil
}

type DemoAuthority struct {
	PolicyID      funds.ID  `json:"policy_id"`
	PolicyVersion uint64    `json:"policy_version"`
	GrantID       funds.ID  `json:"grant_id"`
	GrantVersion  uint64    `json:"grant_version"`
	EffectiveFrom time.Time `json:"effective_from"`
}

// PrepareDemoIncome is a local trusted-CLI precondition, not a financial action.
// A real service USER must already have confirmed both policy and grant.
func (s *Service) PrepareDemoIncome(ctx context.Context, seed SeedIdentity) (DemoAuthority, error) {
	var result DemoAuthority
	if err := seed.validate(s.Namespace, s.now()); err != nil {
		return result, err
	}
	tx, err := s.begin(ctx)
	if err != nil {
		return result, err
	}
	defer rollback(ctx, tx)
	env, err := s.environment(ctx, tx, true)
	if err != nil || env.ID != seed.EnvironmentID {
		return result, reject("DEMO_SEED_IDENTITY_CONFLICT", err)
	}
	p := Principal{EnvironmentID: env.ID, UserID: seed.UserID, Kind: "SYSTEM"}
	if _, _, err = lockUser(ctx, tx, p); err != nil {
		return result, err
	}
	var pid, gid string
	err = tx.QueryRow(ctx, `SELECT policy_id::text FROM goals WHERE environment_id=$1 AND user_id=$2 AND id=$3`, env.ID.String(), seed.UserID.String(), seed.GoalID.String()).Scan(&pid)
	if err != nil {
		return result, reject("USER_POLICY_AND_GRANT_REQUIRED", err)
	}
	policyID, err := funds.ParseID(pid)
	if err != nil {
		return result, reject("USER_POLICY_AND_GRANT_REQUIRED", err)
	}
	pol, err := loadPolicy(ctx, tx, p, policyID, true)
	if err != nil {
		return result, err
	}
	err = tx.QueryRow(ctx, `SELECT id::text FROM grants WHERE environment_id=$1 AND user_id=$2 AND policy_id=$3 AND policy_version=$4 AND is_current AND status='ACTIVE' ORDER BY id LIMIT 1`, env.ID.String(), seed.UserID.String(), pol.ID.String(), pol.Version).Scan(&gid)
	if err != nil {
		return result, reject("USER_POLICY_AND_GRANT_REQUIRED", err)
	}
	grantID, err := funds.ParseID(gid)
	if err != nil {
		return result, err
	}
	g, err := loadGrant(ctx, tx, p, grantID, true)
	if err != nil {
		return result, err
	}
	boundary, err := policy.CheckGrant(pol, g, s.now())
	if err != nil {
		return result, reject("USER_POLICY_AND_GRANT_REQUIRED", err)
	}
	if pol.Scope.SourceAccountID != seed.AccountID || pol.Scope.DestinationAccountID != seed.AccountID || pol.Scope.GoalID != seed.GoalID {
		return result, reject("DEMO_SEED_IDENTITY_CONFLICT", nil)
	}
	return DemoAuthority{pol.ID, pol.Version, g.ID, g.Version, boundary.EffectiveFrom.UTC()}, tx.Commit(ctx)
}

// DemoIncomePreparation is saved on disk BEFORE the first bank call. Retries
// retain exactly these fields even after response loss or process interruption.
type DemoIncomePreparation struct {
	OriginID     funds.ID      `json:"origin_id"`
	EvidenceID   funds.ID      `json:"evidence_id"`
	Amount       funds.Money   `json:"amount_cents"`
	OccurredAt   time.Time     `json:"occurred_at"`
	EvidenceHash string        `json:"evidence_hash"`
	Authority    DemoAuthority `json:"authority"`
}

func DemoIncomeOriginal(seed SeedIdentity, in DemoIncomePreparation) ([]byte, error) {
	return encode(struct {
		Protocol, Namespace                                            string
		EnvironmentID, UserID, AccountID, GoalID, OriginID, EvidenceID funds.ID
		Amount                                                         funds.Money
		OccurredAt                                                     time.Time
		Authority                                                      DemoAuthority
	}{"explicit-synthetic-bank-income-v1", seed.Namespace, seed.EnvironmentID, seed.UserID, seed.AccountID, seed.GoalID, in.OriginID, in.EvidenceID, in.Amount, in.OccurredAt.UTC(), in.Authority})
}
func DemoIncomeHash(seed SeedIdentity, in DemoIncomePreparation) (string, error) {
	raw, err := DemoIncomeOriginal(seed, in)
	if err != nil {
		return "", err
	}
	return Hash(raw), nil
}

// DemoBankFacts is read from the independent bank DB by the trusted CLI after
// OpenAccount/OpenIncome/OpenGoal. No public request may supply this structure.
type DemoBankFacts struct {
	Namespace       string      `json:"namespace"`
	UserID          funds.ID    `json:"user_id"`
	AccountID       funds.ID    `json:"account_id"`
	GoalID          funds.ID    `json:"goal_id"`
	OriginID        funds.ID    `json:"origin_id"`
	OpeningAmount   funds.Money `json:"opening_amount_cents"`
	Balance         funds.Money `json:"balance_cents"`
	AccountReserved funds.Money `json:"account_reserved_cents"`
	OriginalAmount  funds.Money `json:"original_amount_cents"`
	Available       funds.Money `json:"available_cents"`
	Assigned        funds.Money `json:"assigned_cents"`
	IncomeReserved  funds.Money `json:"income_reserved_cents"`
	GoalOwned       funds.Money `json:"goal_owned_cents"`
	OccurredAt      time.Time   `json:"occurred_at"`
	EvidenceHash    string      `json:"evidence_hash"`
	ObservedAt      time.Time   `json:"observed_at"`
	OperationCount  int64       `json:"operation_count"`
}

type DemoIncomeResult struct {
	Status     string      `json:"status"`
	OriginID   funds.ID    `json:"origin_id"`
	Amount     funds.Money `json:"amount_cents"`
	OccurredAt time.Time   `json:"occurred_at"`
}

// ImportDemoIncome records a verified independent simulated-bank fact exactly
// once. This is a CLI-only trusted import, not a general transaction endpoint.
// Existing bank facts remain importable after revocation: stopping future
// actions cannot erase an income that independently occurred under the seed.
func (s *Service) ImportDemoIncome(ctx context.Context, seed SeedIdentity, in DemoIncomePreparation, bank DemoBankFacts) (DemoIncomeResult, error) {
	var result DemoIncomeResult
	now := s.now()
	if err := seed.validate(s.Namespace, now); err != nil {
		return result, err
	}
	expectedHash, err := DemoIncomeHash(seed, in)
	if err != nil {
		return result, err
	}
	if in.OriginID == (funds.ID{}) || in.EvidenceID == (funds.ID{}) || in.Amount.IsZero() || in.OccurredAt.IsZero() || !in.OccurredAt.Equal(in.OccurredAt.Truncate(time.Microsecond)) || in.OccurredAt.Before(in.Authority.EffectiveFrom) || in.OccurredAt.After(now) || in.EvidenceHash != expectedHash || bank.Namespace != seed.Namespace || bank.UserID != seed.UserID || bank.AccountID != seed.AccountID || bank.GoalID != seed.GoalID || bank.OriginID != in.OriginID || bank.OpeningAmount != in.Amount || bank.OriginalAmount != in.Amount || bank.EvidenceHash != in.EvidenceHash || !bank.OccurredAt.Equal(in.OccurredAt) || bank.ObservedAt.Before(in.OccurredAt) || bank.ObservedAt.After(now) {
		return result, reject("DEMO_BANK_ORIGINAL_MISMATCH", nil)
	}
	tx, err := s.begin(ctx)
	if err != nil {
		return result, err
	}
	defer rollback(ctx, tx)
	env, err := s.environment(ctx, tx, true)
	if err != nil || env.ID != seed.EnvironmentID {
		return result, reject("DEMO_SEED_IDENTITY_CONFLICT", err)
	}
	p := Principal{EnvironmentID: env.ID, UserID: seed.UserID, Kind: "SYSTEM"}
	_, sourceVersion, err := lockUser(ctx, tx, p)
	if err != nil {
		return result, err
	}
	var originalAccount, hash, evidence string
	var amount int64
	var occurred time.Time
	err = tx.QueryRow(ctx, `SELECT original_account_id::text,amount_cents,occurred_at,evidence_id::text,evidence_hash::text FROM income_origins WHERE environment_id=$1 AND user_id=$2 AND id=$3`, env.ID.String(), seed.UserID.String(), in.OriginID.String()).Scan(&originalAccount, &amount, &occurred, &evidence, &hash)
	if err == nil {
		if originalAccount != seed.AccountID.String() || amount != in.Amount.Cents() || !occurred.Equal(in.OccurredAt) || evidence != in.EvidenceID.String() || hash != in.EvidenceHash {
			return result, reject("DEMO_INCOME_CONFLICT", nil)
		}
		return DemoIncomeResult{"ALREADY_IMPORTED", in.OriginID, in.Amount, in.OccurredAt.UTC()}, tx.Commit(ctx)
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return result, err
	}
	// Verify the historical USER confirmation sources at the original prepared
	// instant. Their current lifecycle may have stopped subsequent execution.
	var policyRaw, grantRaw []byte
	if err = tx.QueryRow(ctx, `SELECT original FROM policies WHERE environment_id=$1 AND user_id=$2 AND id=$3 AND version=$4`, env.ID.String(), seed.UserID.String(), in.Authority.PolicyID.String(), in.Authority.PolicyVersion).Scan(&policyRaw); err != nil {
		return result, reject("EVIDENCE_INVALID", err)
	}
	if err = tx.QueryRow(ctx, `SELECT original FROM grants WHERE environment_id=$1 AND user_id=$2 AND id=$3 AND version=$4`, env.ID.String(), seed.UserID.String(), in.Authority.GrantID.String(), in.Authority.GrantVersion).Scan(&grantRaw); err != nil {
		return result, reject("EVIDENCE_INVALID", err)
	}
	var pol policy.Policy
	var g policy.Grant
	if decode(policyRaw, &pol) != nil || decode(grantRaw, &g) != nil {
		return result, reject("EVIDENCE_INVALID", nil)
	}
	if err = checkConfirmation(ctx, tx, p, pol.Confirmation); err != nil {
		return result, err
	}
	if err = checkConfirmation(ctx, tx, p, g.Confirmation); err != nil {
		return result, err
	}
	boundary, err := policy.CheckGrant(pol, g, in.OccurredAt)
	if err != nil || !boundary.EffectiveFrom.Equal(in.Authority.EffectiveFrom) || pol.Scope.EnvironmentID != env.ID || pol.Scope.UserID != seed.UserID || pol.Scope.GoalID != seed.GoalID || pol.Scope.SourceAccountID != seed.AccountID || pol.Scope.DestinationAccountID != seed.AccountID {
		return result, reject("DEMO_AUTHORITY_ORIGINAL_MISMATCH", err)
	}
	if bank.Balance != in.Amount || !bank.AccountReserved.IsZero() || bank.Available != in.Amount || !bank.Assigned.IsZero() || !bank.IncomeReserved.IsZero() || !bank.GoalOwned.IsZero() || bank.OperationCount != 0 {
		return result, reject("DEMO_BANK_INITIAL_STATE_CONFLICT", nil)
	}
	var empty bool
	err = tx.QueryRow(ctx, `SELECT NOT EXISTS(SELECT 1 FROM income_origins WHERE environment_id=$1 AND user_id=$2) AND NOT EXISTS(SELECT 1 FROM operations WHERE environment_id=$1 AND user_id=$2) AND (SELECT count(*)=1 AND COALESCE(sum(balance_cents),0)=0 AND COALESCE(sum(goal_owned_cents),0)=0 FROM accounts WHERE environment_id=$1 AND user_id=$2)`, env.ID.String(), seed.UserID.String()).Scan(&empty)
	if err != nil {
		return result, err
	}
	if !empty {
		return result, reject("DEMO_INCOME_INITIAL_STATE_CONFLICT", nil)
	}
	nativeInitial := sourceVersion != 1
	if nativeInitial {
		if err = s.validateDemoNativeProtectionChain(ctx, tx, p, sourceVersion); err != nil {
			return result, err
		}
	}
	var protectionRaw []byte
	var protectionHash string
	if err = tx.QueryRow(ctx, `SELECT original,original_hash FROM protection_snapshots WHERE environment_id=$1 AND user_id=$2 AND version=1`, env.ID.String(), seed.UserID.String()).Scan(&protectionRaw, &protectionHash); err != nil {
		return result, err
	}
	expectedProtection, _ := encode(zeroDemoProtection(seed, seed.CreatedAt))
	if Hash(protectionRaw) != protectionHash || string(protectionRaw) != string(expectedProtection) {
		return result, reject("DEMO_PROTECTION_CONFLICT", nil)
	}
	_, err = tx.Exec(ctx, `UPDATE accounts SET balance_cents=$4,observed_at=$5 WHERE environment_id=$1 AND user_id=$2 AND id=$3`, env.ID.String(), seed.UserID.String(), seed.AccountID.String(), bank.Balance.Cents(), bank.ObservedAt)
	if err != nil {
		return result, err
	}
	ledger, err := s.Store.LoadLedger(ctx, tx, env.ID, seed.UserID, now)
	if err != nil {
		return result, err
	}
	snap := ledger.Snapshot()
	evidenceHash, err := funds.ParseEvidenceHash(in.EvidenceHash)
	if err != nil {
		return result, err
	}
	origin, err := funds.NewIncomeOrigin(funds.BankCreditFact{TransactionID: in.OriginID, AccountID: seed.AccountID, Currency: funds.CNY, Amount: in.Amount, Role: funds.RoleIncome, Source: funds.BankConfirmed, OccurredAt: in.OccurredAt, ObservedAt: bank.ObservedAt, RecordedAt: now, EvidenceID: in.EvidenceID, EvidenceHash: evidenceHash})
	if err != nil {
		return result, err
	}
	snap.Origins = append(snap.Origins, origin)
	snap.Locations = append(snap.Locations, funds.IncomeLocation{FragmentID: funds.LocationID(in.OriginID, seed.AccountID), OriginID: in.OriginID, AccountID: seed.AccountID, Available: in.Amount})
	ledger, err = funds.NewIncomeLedger(snap)
	if err != nil {
		return result, err
	}
	if err = s.Store.SaveLedger(ctx, tx, env.ID, seed.UserID, ledger); err != nil {
		return result, err
	}
	original, err := DemoIncomeOriginal(seed, in)
	if err != nil {
		return result, err
	}
	_, err = tx.Exec(ctx, `INSERT INTO evidence_blobs(environment_id,user_id,id,kind,canonical,digest,created_at) VALUES($1,$2,$3,'EXPLICIT_SIMULATED_BANK_INCOME',$4,$5,$6)`, env.ID.String(), seed.UserID.String(), in.EvidenceID.String(), original, in.EvidenceHash, now)
	if err != nil {
		return result, err
	}
	if nativeInitial {
		if _, err = tx.Exec(ctx, `UPDATE users SET funds_version=funds_version+1 WHERE environment_id=$1 AND id=$2`, env.ID.String(), seed.UserID.String()); err != nil {
			return result, err
		}
		timezone, e := templateScopedTimezone(ctx, tx, p, "")
		if e != nil {
			return result, e
		}
		view, e := s.refreshTemplateProtection(ctx, tx, p, timezone)
		if e != nil {
			return result, e
		}
		sourceVersion = view.SourceVersion
	} else {
		newProtection := zeroDemoProtection(seed, bank.ObservedAt)
		raw, e := encode(newProtection)
		if e != nil {
			return result, e
		}
		if _, err = tx.Exec(ctx, `INSERT INTO protection_snapshots(environment_id,user_id,version,original,original_hash,observed_at) VALUES($1,$2,$3,$4,$5,$6)`, env.ID.String(), seed.UserID.String(), sourceVersion+1, raw, Hash(raw), bank.ObservedAt); err != nil {
			return result, err
		}
		if _, err = tx.Exec(ctx, `UPDATE users SET funds_version=funds_version+1,source_version=source_version+1 WHERE environment_id=$1 AND id=$2`, env.ID.String(), seed.UserID.String()); err != nil {
			return result, err
		}
		sourceVersion++
	}
	payload, _ := encode(struct {
		OriginID      funds.ID `json:"origin_id"`
		SourceVersion uint64   `json:"source_version"`
	}{in.OriginID, sourceVersion})
	_, err = tx.Exec(ctx, `INSERT INTO outbox(environment_id,user_id,id,aggregate_id,aggregate_version,kind,payload,created_at) VALUES($1,$2,$3,$4,1,'INCOME_IMPORTED',$5,$6)`, env.ID.String(), seed.UserID.String(), in.EvidenceID.String(), in.OriginID.String(), payload, now)
	if err != nil {
		return result, err
	}
	if err = tx.Commit(ctx); err != nil {
		return result, err
	}
	return DemoIncomeResult{"IMPORTED_CONFIRMED_SIMULATION", in.OriginID, in.Amount, in.OccurredAt.UTC()}, nil
}
