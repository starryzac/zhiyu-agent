package app

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5"
	"zhiyu.local/zhiyu-go/internal/adapters/postgres"
	"zhiyu.local/zhiyu-go/internal/execution/bankv2"
	funds "zhiyu.local/zhiyu-go/internal/funds/domain"
	policy "zhiyu.local/zhiyu-go/internal/policy/domain"
)

const nativeStandingBridgePermitProtocol = "native-standing-bridge-permit-v1"

type nativeStandingBridgeProof struct {
	Protocol           string                    `json:"protocol"`
	Scope              policy.TemplateOwnerScope `json:"scope"`
	OperationID        funds.ID                  `json:"operation_id"`
	PermitID           string                    `json:"permit_id"`
	GroupHash          string                    `json:"group_hash"`
	StepNumber         int                       `json:"step_number"`
	BankRequestHash    string                    `json:"bank_request_hash"`
	EffectHash         string                    `json:"effect_hash"`
	SignatureHash      string                    `json:"signature_hash"`
	GrantStateSequence uint64                    `json:"grant_state_sequence"`
	FundsVersion       uint64                    `json:"funds_version"`
	SourceVersion      uint64                    `json:"source_version"`
	WriterGeneration   uint64                    `json:"writer_generation"`
	ControlVersion     uint64                    `json:"control_version"`
	DecisionAt         time.Time                 `json:"decision_at"`
	PrefixReceipts     []nativePrefixReceipt     `json:"prefix_receipts"`
}

func standingBridgePrefix(ctx context.Context, q queryRow, p Principal, g nativeStandingBridgeGroup, completed int) ([]nativePrefixReceipt, error) {
	if completed < 0 || completed > len(g.Steps) {
		return nil, reject("EVIDENCE_INVALID", nil)
	}
	list := []nativePrefixReceipt{}
	for i := 0; i < completed; i++ {
		step := g.Steps[i]
		var state, id, hash, requestHash string
		var raw, requestRaw []byte
		e := q.QueryRow(ctx, `SELECT o.status,r.id::text,r.original_hash,r.original,o.bank_request_hash,o.bank_request FROM native_operations o JOIN native_receipts r ON(r.environment_id=o.environment_id AND r.user_id=o.user_id AND r.operation_id=o.id AND r.id=o.receipt_id) WHERE o.environment_id=$1 AND o.user_id=$2 AND o.id=$3 AND o.group_id=$4 AND o.child_number=$5`, p.EnvironmentID.String(), p.UserID.String(), step.OperationID.String(), g.Occurrence.ID.String(), step.Number).Scan(&state, &id, &hash, &raw, &requestHash, &requestRaw)
		if e != nil {
			return nil, reject("PREVIOUS_OPERATION_UNSETTLED", e)
		}
		var receipt NativeReceipt
		var request bankv2.Request
		if state != "SETTLED" || Hash(raw) != hash || requestHash != step.RequestHash || auditJSON(raw, &receipt) != nil || auditJSON(requestRaw, &request) != nil {
			return nil, reject("EVIDENCE_INVALID", nil)
		}
		h, e := request.Digest()
		if e != nil || h != step.RequestHash || receipt.ID.String() != id || receipt.OperationID != step.OperationID || receipt.GroupID != g.Occurrence.ID || receipt.Protocol != "native-receipt-v1" || receipt.BankResult.Status != bankv2.Settled || bankv2.VerifyResult(step.Request, receipt.BankResult) != nil {
			return nil, reject("EVIDENCE_INVALID", nil)
		}
		list = append(list, nativePrefixReceipt{OperationID: step.OperationID.String(), ReceiptID: id, ReceiptHash: hash})
	}
	return list, nil
}

func standingBridgeStoredPermit(ctx context.Context, q queryRow, p Principal, operation funds.ID, request bankv2.Request, signature string) error {
	g, hash, number, e := loadStandingBridge(ctx, q, p, operation)
	if e != nil {
		return e
	}
	step := g.Steps[number-1]
	var raw []byte
	var digest, rh, eh, sh, permit string
	if e = q.QueryRow(ctx, `SELECT original,original_hash,bank_request_hash,effect_hash,signature_hash,permit_id::text FROM native_submission_permits WHERE environment_id=$1 AND user_id=$2 AND operation_id=$3`, p.EnvironmentID.String(), p.UserID.String(), operation.String()).Scan(&raw, &digest, &rh, &eh, &sh, &permit); e != nil {
		return reject("EVIDENCE_INVALID", e)
	}
	var proof nativeStandingBridgeProof
	want, e := request.Digest()
	effect, e2 := request.Effect.Digest()
	if e != nil || e2 != nil || Hash(raw) != digest || auditJSON(raw, &proof) != nil || proof.Protocol != nativeStandingBridgePermitProtocol || proof.Scope != g.Scope || proof.OperationID != operation || proof.PermitID != permit || permit != request.PermitID || rh != want || want != step.RequestHash || eh != effect || eh != step.EffectHash || sh != Hash([]byte(signature)) || proof.BankRequestHash != rh || proof.EffectHash != eh || proof.SignatureHash != sh || proof.GroupHash != hash || proof.StepNumber != number || proof.GrantStateSequence < g.GrantStateSequence || proof.DecisionAt.Before(g.CreatedAt) || !proof.DecisionAt.Before(g.ExpiresAt) || proof.FundsVersion != g.Dependencies.FundsVersion+uint64(number) || proof.SourceVersion != g.Dependencies.SourceEvidenceVersion+uint64(number-1) || proof.WriterGeneration != g.Dependencies.WriterGeneration || proof.ControlVersion != g.Dependencies.ControlVersion {
		return reject("EVIDENCE_INVALID", nil)
	}
	prefix, e := standingBridgePrefix(ctx, q, p, g, number-1)
	if e != nil {
		return e
	}
	a, _ := encode(prefix)
	b, _ := encode(proof.PrefixReceipts)
	if string(a) != string(b) {
		return reject("EVIDENCE_INVALID", nil)
	}
	// Recovery verifies the frozen T2 witness. It never reuses today's grant,
	// USER session or signing secret to manufacture historical permission.
	return nil
}

func (s *Service) standingBridgePermit(ctx context.Context, c Claim) (nativePermitted, error) {
	var out nativePermitted
	if c.Principal.Kind != "SYSTEM" || c.Principal.SessionID != (funds.ID{}) {
		return out, reject("FORBIDDEN", nil)
	}
	tx, e := s.begin(ctx)
	if e != nil {
		return out, e
	}
	defer rollback(ctx, tx)
	if e = s.lockNativeClaim(ctx, tx, c); e != nil {
		return out, e
	}
	g, hash, number, e := loadStandingBridge(ctx, tx, c.Principal, c.OperationID)
	if e != nil {
		return out, e
	}
	step := g.Steps[number-1]
	out.Request = step.Request
	var raw []byte
	var rh, eh, mode, gid, kind string
	var version, rv uint64
	var signature *string
	e = tx.QueryRow(ctx, `SELECT status,bank_request,bank_request_hash,effect_hash,mode,grant_id::text,grant_version,reserved_funds_version,permit_signature,command_kind FROM native_operations WHERE environment_id=$1 AND user_id=$2 AND id=$3`, c.Principal.EnvironmentID.String(), c.Principal.UserID.String(), c.OperationID.String()).Scan(&out.State, &raw, &rh, &eh, &mode, &gid, &version, &rv, &signature, &kind)
	if e != nil {
		return out, e
	}
	want, _ := step.Request.CanonicalBytes()
	if string(want) != string(raw) || rh != step.RequestHash || eh != step.EffectHash || mode != "STANDING" || gid != g.Grant.ID.String() || version != g.Grant.Version || rv != g.Dependencies.FundsVersion+1 || kind != step.CommandKind {
		return out, reject("EVIDENCE_INVALID", nil)
	}
	if out.State == "SETTLED" || out.State == "REJECTED" || out.State == "CANCELLED" {
		out.Cancelled = true
		return out, nil
	}
	if signature != nil {
		if e = standingBridgeStoredPermit(ctx, tx, c.Principal, c.OperationID, out.Request, *signature); e != nil {
			return out, e
		}
		out.Signature = *signature
		return out, tx.Commit(ctx)
	}
	if out.State != "QUEUED" {
		return out, reject("OPERATION_UNKNOWN", nil)
	}
	now := s.now()
	permissionErr := s.validateStandingBridge(ctx, tx, c.Principal, g, number, now, true)
	if permissionErr != nil {
		if Code(permissionErr) == "INTERNAL_ERROR" || Code(permissionErr) == "EVIDENCE_INVALID" || Code(permissionErr) == "PREVIOUS_OPERATION_UNSETTLED" {
			return out, permissionErr
		}
		ledger, e := s.Store.LoadNativeLedger(ctx, tx, c.Principal.EnvironmentID, c.Principal.UserID, now)
		if e != nil {
			return out, e
		}
		if e = s.cancelStandingBridgeSuffix(ctx, tx, c.Principal, g, &ledger, Code(permissionErr)); e != nil {
			return out, e
		}
		if e = s.Store.PersistNativeLedger(ctx, tx, c.Principal.EnvironmentID, c.Principal.UserID, ledger); e != nil {
			return out, e
		}
		if e = s.finalizeStandingBridgeBudget(ctx, tx, c.Principal, g, true); e != nil {
			return out, e
		}
		if _, e = tx.Exec(ctx, `UPDATE users SET funds_version=funds_version+1 WHERE environment_id=$1 AND id=$2`, c.Principal.EnvironmentID.String(), c.Principal.UserID.String()); e != nil {
			return out, e
		}
		if _, _, e = s.refreshTemplateProtectionAfterNativeEffect(ctx, tx, c.Principal, g.Grant.Terms.Timezone); e != nil {
			return out, e
		}
		out.Cancelled = true
		return out, tx.Commit(ctx)
	}
	out.Signature, e = bankv2.SignPermit(out.Request, s.PermitSecret)
	if e != nil {
		return out, e
	}
	prefix, e := standingBridgePrefix(ctx, tx, c.Principal, g, number-1)
	if e != nil {
		return out, e
	}
	var seq uint64
	if e = tx.QueryRow(ctx, `SELECT sequence FROM native_grant_states WHERE environment_id=$1 AND user_id=$2 AND grant_id=$3 AND grant_version=$4`, g.Scope.EnvironmentID.String(), g.Scope.UserID.String(), g.Grant.ID.String(), g.Grant.Version).Scan(&seq); e != nil {
		return out, e
	}
	proof := nativeStandingBridgeProof{Protocol: nativeStandingBridgePermitProtocol, Scope: g.Scope, OperationID: c.OperationID, PermitID: out.Request.PermitID, GroupHash: hash, StepNumber: number, BankRequestHash: rh, EffectHash: eh, SignatureHash: Hash([]byte(out.Signature)), GrantStateSequence: seq, FundsVersion: g.Dependencies.FundsVersion + uint64(number), SourceVersion: g.Dependencies.SourceEvidenceVersion + uint64(number-1), WriterGeneration: g.Dependencies.WriterGeneration, ControlVersion: g.Dependencies.ControlVersion, DecisionAt: now, PrefixReceipts: prefix}
	proofRaw, _ := encode(proof)
	_, e = tx.Exec(ctx, `INSERT INTO native_submission_permits(environment_id,user_id,operation_id,permit_id,bank_request_hash,effect_hash,signature_hash,original,original_hash,decision_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`, g.Scope.EnvironmentID.String(), g.Scope.UserID.String(), c.OperationID.String(), out.Request.PermitID, rh, eh, proof.SignatureHash, proofRaw, Hash(proofRaw), now)
	if e != nil {
		return out, e
	}
	_, e = tx.Exec(ctx, `UPDATE native_operations SET status='SUBMITTING',permit_signature=$4,version=version+1,updated_at=$5 WHERE environment_id=$1 AND user_id=$2 AND id=$3`, g.Scope.EnvironmentID.String(), g.Scope.UserID.String(), c.OperationID.String(), out.Signature, now)
	if e != nil {
		return out, e
	}
	out.State = "SUBMITTING"
	return out, tx.Commit(ctx)
}

// Used both by fresh T2 and the new post-arrival T1, always under the common
// user lock. Exact prefix receipt counts fence unrelated FV/SV publications.
func (s *Service) validateStandingBridge(ctx context.Context, tx pgx.Tx, p Principal, g nativeStandingBridgeGroup, number int, now time.Time, reserved bool) error {
	if e := ensureNativeBillsReady(ctx, tx, p); e != nil {
		return e
	}
	if number < 1 || number > len(g.Steps) || now.Before(g.CreatedAt) || !now.Before(g.ExpiresAt) {
		return reject("AUTHORIZATION_EXPIRED", nil)
	}
	grant, e := loadNativeStandingGrant(ctx, tx, p, g.Grant.ID)
	if e != nil {
		return e
	}
	a, _ := encode(grant.Grant)
	b, _ := encode(g.Grant)
	if string(a) != string(b) {
		return reject("EVIDENCE_INVALID", nil)
	}
	if grant.State != "ACTIVE" || now.Before(g.Grant.Terms.EffectiveFrom) || !now.Before(g.Grant.Terms.ExpiresAt) {
		return reject("NATIVE_GRANT_NOT_ACTIVE", nil)
	}
	ids := []funds.ID{}
	for _, r := range g.Grant.Terms.Policies {
		ids = append(ids, r.VersionID)
	}
	refs, _, _, e := nativeGrantReferences(ctx, tx, s, p, ids)
	if e != nil {
		return e
	}
	a, _ = encode(refs)
	b, _ = encode(g.Grant.Terms.Policies)
	if string(a) != string(b) {
		return reject("NATIVE_GRANT_POLICY_CHANGED", nil)
	}
	var fv, sv, wg, cv uint64
	e = tx.QueryRow(ctx, `SELECT u.funds_version,u.source_version,e.writer_generation,e.control_version FROM users u JOIN environments e ON e.id=u.environment_id WHERE u.environment_id=$1 AND u.id=$2`, p.EnvironmentID.String(), p.UserID.String()).Scan(&fv, &sv, &wg, &cv)
	if e != nil {
		return e
	}
	d := g.Dependencies
	expectedFV, expectedSV := d.FundsVersion+uint64(number), d.SourceEvidenceVersion+uint64(number-1)
	if !reserved {
		// The only unreserved caller continues the preceding T3 under the
		// same user lock. Its receipt is present; its FV/SV publication waits
		// until this exact next reservation (or cancellation) is persisted.
		if number < 2 {
			return reject("EVIDENCE_INVALID", nil)
		}
		expectedFV--
		expectedSV--
	}
	if fv != expectedFV || sv != expectedSV || wg != d.WriterGeneration || cv != d.ControlVersion {
		return reject("SOURCE_CHANGED", nil)
	}
	if _, e = standingBridgePrefix(ctx, tx, p, g, number-1); e != nil {
		return e
	}
	counts := map[string]uint64{}
	for i := 0; i < number-1; i++ {
		if g.Steps[i].Request.Effect.Kind == bankv2.Allocate {
			counts[g.Steps[i].GoalID.String()]++
		}
	}
	for id, version := range g.GoalVersions {
		var v uint64
		if e = tx.QueryRow(ctx, `SELECT version FROM goals WHERE environment_id=$1 AND user_id=$2 AND id=$3`, p.EnvironmentID.String(), p.UserID.String(), id).Scan(&v); e != nil {
			return e
		}
		if v != version+counts[id] {
			return reject("SOURCE_CHANGED", nil)
		}
	}
	usage, e := nativeStandingUsage(ctx, tx, p, g.Grant, now, &g.Occurrence.ID)
	if e != nil {
		return e
	}
	if e = policy.AuthorizeNativeStanding(g.Grant.Terms, grant.State, g.Candidate.Authority, usage, now); e != nil {
		return reject(e.Error(), e)
	}
	var budget bool
	e = tx.QueryRow(ctx, `SELECT b.state='RESERVED' AND b.amount_cents=$4 AND b.grant_id=$5::uuid AND b.grant_version=$6 AND NOT EXISTS(SELECT 1 FROM native_standing_bridge_closures c WHERE c.environment_id=b.environment_id AND c.user_id=b.user_id AND c.group_id=b.occurrence_id) FROM native_grant_budget_claims b WHERE b.environment_id=$1 AND b.user_id=$2 AND b.occurrence_id=$3`, p.EnvironmentID.String(), p.UserID.String(), g.Occurrence.ID.String(), g.Candidate.Authority.Amount.Cents(), g.Grant.ID.String(), g.Grant.Version).Scan(&budget)
	if e != nil {
		return e
	}
	if !budget {
		return reject("EVIDENCE_INVALID", nil)
	}
	if !reserved {
		return nil
	}
	step := g.Steps[number-1]
	ledger, e := s.Store.LoadNativeLedger(ctx, tx, p.EnvironmentID, p.UserID, now)
	if e != nil {
		return e
	}
	match, holds := false, 0
	for _, r := range ledger.Income.Snapshot().Reservations {
		if r.ActionID != step.OperationID {
			continue
		}
		x, _ := encode(r.Uses)
		y, _ := encode(step.Resources.IncomeUses)
		if r.State != funds.Reserved || r.Operation != step.Resources.IncomeOperation || string(x) != string(y) || (r.DestinationAccountID == nil) != (step.Resources.DestinationAccountID == nil) || r.DestinationAccountID != nil && *r.DestinationAccountID != *step.Resources.DestinationAccountID {
			return reject("EVIDENCE_INVALID", nil)
		}
		match = true
	}
	for _, h := range ledger.Holds {
		if h.OperationID == step.OperationID {
			if h.ResourceKind != "CASH" || h.ResourceID != step.Resources.CashAccountID.String() || h.Amount != step.Resources.Amount || h.State != funds.Reserved {
				return reject("EVIDENCE_INVALID", nil)
			}
			holds++
		}
	}
	if !match || holds != 1 {
		return reject("EVIDENCE_INVALID", nil)
	}
	return nil
}

func (s *Service) cancelStandingBridgeSuffix(ctx context.Context, tx pgx.Tx, p Principal, g nativeStandingBridgeGroup, ledger *postgres.NativeLedger, reason string) error {
	for _, step := range g.Steps {
		var state string
		var signature *string
		e := tx.QueryRow(ctx, `SELECT status,permit_signature FROM native_operations WHERE environment_id=$1 AND user_id=$2 AND id=$3 FOR UPDATE`, p.EnvironmentID.String(), p.UserID.String(), step.OperationID.String()).Scan(&state, &signature)
		if e == pgx.ErrNoRows {
			continue
		}
		if e != nil {
			return e
		}
		if state == "SETTLED" || state == "REJECTED" || state == "CANCELLED" {
			continue
		}
		if signature != nil {
			return reject("OPERATION_UNKNOWN", nil)
		}
		if state != "QUEUED" {
			return reject("EVIDENCE_INVALID", nil)
		}
		ledger.Income, e = ledger.Income.Release(step.OperationID, s.now(), true)
		if e != nil {
			return e
		}
		for i := range ledger.Holds {
			if ledger.Holds[i].OperationID == step.OperationID {
				ledger.Holds[i].State = funds.Released
			}
		}
		if _, e = tx.Exec(ctx, `UPDATE native_operations SET status='CANCELLED',processing_health=$4,version=version+1,updated_at=$5 WHERE environment_id=$1 AND user_id=$2 AND id=$3`, p.EnvironmentID.String(), p.UserID.String(), step.OperationID.String(), reason, s.now()); e != nil {
			return e
		}
		if e = s.recordNativeCancellation(ctx, tx, p, step.OperationID, reason); e != nil {
			return e
		}
		if _, e = tx.Exec(ctx, `UPDATE native_jobs SET state='FINISHED',lease_owner=NULL,lease_until=NULL,last_error=$4 WHERE environment_id=$1 AND user_id=$2 AND operation_id=$3`, p.EnvironmentID.String(), p.UserID.String(), step.OperationID.String(), reason); e != nil {
			return e
		}
	}
	_, e := tx.Exec(ctx, `INSERT INTO native_standing_bridge_closures(environment_id,user_id,group_id,reason,closed_at) VALUES($1,$2,$3,$4,$5) ON CONFLICT DO NOTHING`, p.EnvironmentID.String(), p.UserID.String(), g.Occurrence.ID.String(), reason, s.now())
	return e
}

func (s *Service) finalizeStandingBridgeBudget(ctx context.Context, tx pgx.Tx, p Principal, g nativeStandingBridgeGroup, closed bool) error {
	var pending int
	var spent int64
	if e := tx.QueryRow(ctx, `SELECT count(*) FILTER(WHERE o.status NOT IN ('SETTLED','REJECTED','CANCELLED')),coalesce(sum(x.economic_amount_cents) FILTER(WHERE o.status='SETTLED'),0)::bigint FROM native_occurrence_operations x JOIN native_operations o ON(o.environment_id=x.environment_id AND o.user_id=x.user_id AND o.id=x.operation_id) WHERE x.environment_id=$1 AND x.user_id=$2 AND x.occurrence_id=$3`, p.EnvironmentID.String(), p.UserID.String(), g.Occurrence.ID.String()).Scan(&pending, &spent); e != nil {
		return e
	}
	if pending > 0 || !closed {
		return nil
	}
	amount, e := funds.NewMoney(spent)
	if e != nil {
		return e
	}
	return finalizeNativeStandingBudget(ctx, tx, p, g.Occurrence.ID, amount, s.now())
}

func (s *Service) standingBridgeProtection(ctx context.Context, tx pgx.Tx, p Principal, id funds.ID) error {
	g, _, _, e := loadStandingBridge(ctx, tx, p, id)
	if e != nil {
		return e
	}
	_, _, e = s.refreshTemplateProtectionAfterNativeEffect(ctx, tx, p, g.Grant.Terms.Timezone)
	return e
}
