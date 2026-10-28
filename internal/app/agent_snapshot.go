package app

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"strings"

	"github.com/jackc/pgx/v5"
	agent "zhiyu.local/zhiyu-go/internal/agent/domain"
	funds "zhiyu.local/zhiyu-go/internal/funds/domain"
	planning "zhiyu.local/zhiyu-go/internal/planning/domain"
	policy "zhiyu.local/zhiyu-go/internal/policy/domain"
)

// AgentSnapshot is a bounded read of authoritative rows in one RR transaction.
// It owns no model, confirmation, admission, outbox or bank call. In particular
// it never substitutes the eventually consistent dashboard read model.
func (s *Service) AgentSnapshot(ctx context.Context, p Principal) (agent.Snapshot, error) {
	out := agent.Snapshot{Scope: agent.Scope{EnvironmentID: p.EnvironmentID, UserID: p.UserID}, AsOf: s.now(), Accounts: []agent.Account{}, Goals: []agent.Goal{}, Policies: []agent.Policy{}, Grants: []agent.Grant{}, Operations: []agent.Operation{}}
	tx, e := s.Pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	if e != nil {
		return out, e
	}
	defer rollback(ctx, tx)
	env, e := s.environment(ctx, tx, false)
	if e != nil {
		return out, e
	}
	if e = sameUser(p, env.ID); e != nil {
		return out, e
	}
	if e = s.human(ctx, tx, p); e != nil {
		return out, e
	}
	rows, e := tx.Query(ctx, `SELECT id::text,name,balance_cents,goal_owned_cents FROM accounts WHERE environment_id=$1 AND user_id=$2 ORDER BY id LIMIT 101`, p.EnvironmentID.String(), p.UserID.String())
	if e != nil {
		return out, e
	}
	for rows.Next() {
		var a agent.Account
		var b, g int64
		if e = rows.Scan(&a.ID, &a.Name, &b, &g); e != nil {
			rows.Close()
			return out, e
		}
		a.Balance, e = funds.NewMoney(b)
		if e != nil {
			rows.Close()
			return out, e
		}
		a.GoalOwned, e = funds.NewMoney(g)
		if e != nil {
			rows.Close()
			return out, e
		}
		out.Accounts = append(out.Accounts, a)
	}
	e = rows.Err()
	rows.Close()
	if e != nil {
		return out, e
	}
	rows, e = tx.Query(ctx, `SELECT id::text,name,account_id::text,target_cents,assigned_cents FROM goals WHERE environment_id=$1 AND user_id=$2 ORDER BY id LIMIT 101`, p.EnvironmentID.String(), p.UserID.String())
	if e != nil {
		return out, e
	}
	for rows.Next() {
		var g agent.Goal
		var a, b int64
		if e = rows.Scan(&g.ID, &g.Name, &g.AccountID, &a, &b); e != nil {
			rows.Close()
			return out, e
		}
		g.Target, e = funds.NewMoney(a)
		if e != nil {
			rows.Close()
			return out, e
		}
		g.Assigned, e = funds.NewMoney(b)
		if e != nil {
			rows.Close()
			return out, e
		}
		out.Goals = append(out.Goals, g)
	}
	e = rows.Err()
	rows.Close()
	if e != nil {
		return out, e
	}
	rows, e = tx.Query(ctx, `SELECT original,status,id::text,version FROM policies WHERE environment_id=$1 AND user_id=$2 AND is_current ORDER BY id LIMIT 101`, p.EnvironmentID.String(), p.UserID.String())
	if e != nil {
		return out, e
	}
	for rows.Next() {
		var raw []byte
		var status, id string
		var version uint64
		var v policy.Policy
		if e = rows.Scan(&raw, &status, &id, &version); e != nil {
			rows.Close()
			return out, e
		}
		if decode(raw, &v) != nil || v.ID.String() != id || v.Version != version || v.Scope.EnvironmentID != env.ID || v.Scope.UserID != p.UserID {
			rows.Close()
			return out, reject("EVIDENCE_INVALID", nil)
		}
		out.Policies = append(out.Policies, agent.Policy{ID: v.ID.String(), GoalID: v.Scope.GoalID.String(), Version: v.Version, Status: status, MaxAmount: v.MaxAmount, ValidUntil: v.ValidUntil})
	}
	e = rows.Err()
	rows.Close()
	if e != nil {
		return out, e
	}
	rows, e = tx.Query(ctx, `SELECT original,status,id::text,version FROM grants WHERE environment_id=$1 AND user_id=$2 AND is_current ORDER BY id LIMIT 101`, p.EnvironmentID.String(), p.UserID.String())
	if e != nil {
		return out, e
	}
	for rows.Next() {
		var raw []byte
		var status, id string
		var version uint64
		var v policy.Grant
		if e = rows.Scan(&raw, &status, &id, &version); e != nil {
			rows.Close()
			return out, e
		}
		if decode(raw, &v) != nil || v.ID.String() != id || v.Version != version || v.Scope.EnvironmentID != env.ID || v.Scope.UserID != p.UserID {
			rows.Close()
			return out, reject("EVIDENCE_INVALID", nil)
		}
		out.Grants = append(out.Grants, agent.Grant{ID: v.ID.String(), PolicyID: v.PolicyID.String(), Status: status, MaxAmount: v.MaxAmount, ValidUntil: v.ValidUntil})
	}
	e = rows.Err()
	rows.Close()
	if e != nil {
		return out, e
	}
	rows, e = tx.Query(ctx, `SELECT `+operationColumns+` FROM operations WHERE environment_id=$1 AND user_id=$2 ORDER BY created_at DESC,id DESC LIMIT 20`, p.EnvironmentID.String(), p.UserID.String())
	if e != nil {
		return out, e
	}
	for rows.Next() {
		v, err := scanOperation(rows)
		if err != nil {
			rows.Close()
			return out, err
		}
		o := agent.Operation{ID: v.ID.String(), PlanID: v.PlanID.String(), State: v.State, Amount: v.Amount, Version: v.Version, ProcessingHealth: v.ProcessingHealth}
		if v.ReceiptID != nil {
			o.ReceiptID = *v.ReceiptID
		}
		if v.BankObservedStatus != nil {
			o.BankObservedStatus = *v.BankObservedStatus
		}
		out.Operations = append(out.Operations, o)
	}
	e = rows.Err()
	rows.Close()
	if e != nil {
		return out, e
	}
	timezone, e := templateScopedTimezone(ctx, tx, p, "")
	if e != nil {
		return out, e
	}
	views, e := s.loadTemplatePolicies(ctx, tx, p)
	if e != nil {
		return out, e
	}
	n := &agent.NativeContext{Timezone: timezone, Rules: []agent.NativeRule{}, Objects: []agent.ObjectObservation{}, Unavailable: "TEMPLATE_INVENTORY_INCOMPLETE", JointUnavailable: "JOINT_GOAL_CAPACITY"}
	for _, v := range views {
		n.Rules = append(n.Rules, agent.NativeRule{Version: v.Version, GoalID: v.GoalID, Timezone: v.Timezone, EffectiveState: v.EffectiveState})
	}
	// No empty-inventory fallback: unsupported/missing proofs remain explicit.
	snapshot, err := s.loadTemplateSnapshot(ctx, tx, p, out.AsOf, timezone)
	if err != nil {
		code := Code(err)
		if !strings.HasPrefix(code, "TEMPLATE_") {
			return out, err
		}
		n.Unavailable = code
		n.JointUnavailable = code
	} else {
		f := snapshot.forecastInput(365)
		n.Forecast = &f
		n.BankNamespace = s.Namespace
		n.SourceHash = snapshot.Facts.SourceHash
		n.InventoryHash = Hash(snapshot.InventoryRaw)
		n.Unavailable = ""
		payees, err := agentKnownBillPayees(snapshot, s.Namespace)
		if err != nil {
			return out, err
		}
		n.Objects = append(n.Objects, payees...)
		goals, _, goalErr := nativeJointGoals(snapshot)
		if goalErr == nil {
			cash, err := nativeJointCash(snapshot)
			if err != nil {
				return out, err
			}
			ledger, err := s.Store.LoadLedger(ctx, tx, p.EnvironmentID, p.UserID, out.AsOf)
			if err != nil {
				return out, err
			}
			n.Joint = &planning.JointInput{Scope: f.Scope, Now: out.AsOf, Timezone: timezone, Ledger: ledger, Cash: cash, Goals: goals, ProtectionInput: &f, Complete: true, InventoryHash: n.InventoryHash, Dependencies: planning.DependencyVector{FundsVersion: snapshot.FundsVersion, PolicyVersion: 1, ProductTermsVersion: 1, ProductAvailabilityVersion: 1, SourceEvidenceVersion: snapshot.SourceVersion, WriterGeneration: snapshot.WriterGeneration, ControlVersion: snapshot.ControlVersion}, SolverNodeBudget: 200000}
			n.JointUnavailable = ""
		} else {
			n.JointUnavailable = Code(goalErr)
		}
	}
	// Original object metadata is selected explicitly; raw requests and bank keys
	// never enter this tool snapshot or the model context.
	objectQueries := []struct{ kind, sql string }{
		{"NATIVE_PLAN", `SELECT id::text,json_build_object('id',id,'status',status,'created_at',created_at,'expires_at',expires_at,'input_hash',input_hash,'result_hash',result_hash,'source_hash',source_hash,'effect_hash',effect_hash)::text FROM native_joint_plans WHERE environment_id=$1 AND user_id=$2 ORDER BY created_at DESC,id DESC LIMIT 20`},
		{"NATIVE_OPERATION", `SELECT id::text,json_build_object('id',id,'kind',command_kind,'status',status,'version',version,'receipt_id',receipt_id,'created_at',created_at,'updated_at',updated_at,'effect_hash',effect_hash)::text FROM native_operations WHERE environment_id=$1 AND user_id=$2 ORDER BY created_at DESC,id DESC LIMIT 20`},
		{"NATIVE_POSITION", `SELECT p.id,json_build_object('id',p.id,'principal_cents',p.principal_cents::text,'goal_id',p.goal_id,'return_account_id',p.return_account_id,'purchased_at',p.purchased_at,'maturity_at',p.maturity_at,'original_hash',p.original_hash,'closed',s.closed)::text FROM native_positions p JOIN native_position_states s ON(s.environment_id=p.environment_id AND s.user_id=p.user_id AND s.position_id=p.id) WHERE p.environment_id=$1 AND p.user_id=$2 ORDER BY p.id LIMIT 20`},
	}
	for _, q := range objectQueries {
		rows, e = tx.Query(ctx, q.sql, p.EnvironmentID.String(), p.UserID.String())
		if e != nil {
			return out, e
		}
		for rows.Next() {
			var id, raw string
			if e = rows.Scan(&id, &raw); e != nil {
				rows.Close()
				return out, e
			}
			if q.kind == "NATIVE_POSITION" {
				id = agentObjectID(p, q.kind, id).String()
			}
			n.Objects = append(n.Objects, agent.ObjectObservation{Kind: q.kind, ID: id, Data: json.RawMessage(raw)})
		}
		e = rows.Err()
		rows.Close()
		if e != nil {
			return out, e
		}
	}
	// RF024 is additive and may not be deployed yet. Absence produces no
	// invented question/reference. Present questions retain their original ID.
	var questionsPresent bool
	if e = tx.QueryRow(ctx, `SELECT to_regclass('native_priority_analyses') IS NOT NULL AND to_regclass('native_priority_answers') IS NOT NULL`).Scan(&questionsPresent); e != nil {
		return out, e
	}
	if questionsPresent {
		rows, e = tx.Query(ctx, `SELECT a.question_id::text,encode(sha256(a.original),'hex')=a.original_hash,json_build_object('analysis_id',a.id,'original_hash',a.original_hash,'question',convert_from(a.original,'UTF8')::jsonb#>'{result,question}','expires_at',a.expires_at,'answered',EXISTS(SELECT 1 FROM native_priority_answers b WHERE b.environment_id=a.environment_id AND b.user_id=a.user_id AND b.question_id=a.question_id),'bank_authority',false)::text FROM native_priority_analyses a WHERE a.environment_id=$1 AND a.user_id=$2 AND a.question_id IS NOT NULL ORDER BY a.created_at DESC,a.id DESC LIMIT 20`, p.EnvironmentID.String(), p.UserID.String())
		if e != nil {
			return out, e
		}
		for rows.Next() {
			var id, raw string
			var valid bool
			if e = rows.Scan(&id, &valid, &raw); e != nil {
				rows.Close()
				return out, e
			}
			var object struct {
				Question planning.FiniteQuestion `json:"question"`
			}
			if !valid || json.Unmarshal([]byte(raw), &object) != nil || object.Question.OriginalQuestionID.String() != id || object.Question.Scope != (policy.TemplateOwnerScope{EnvironmentID: p.EnvironmentID, UserID: p.UserID}) || object.Question.BankAuthority {
				rows.Close()
				return out, reject("EVIDENCE_INVALID", nil)
			}
			n.Objects = append(n.Objects, agent.ObjectObservation{Kind: "NATIVE_QUESTION", ID: id, Data: json.RawMessage(raw)})
		}
		e = rows.Err()
		rows.Close()
		if e != nil {
			return out, e
		}
	}
	n.NativeGrants, e = s.loadAgentNativeGrants(ctx, tx, p, out, views)
	if e != nil {
		return out, e
	}
	out.Native = n
	if e = out.Validate(out.Scope); e != nil {
		return out, e
	}
	return out, tx.Commit(ctx)
}
func agentObjectID(p Principal, kind, id string) funds.ID {
	h := sha256.Sum256([]byte(p.EnvironmentID.String() + "/" + p.UserID.String() + "/" + kind + "/" + id))
	var v funds.ID
	copy(v[:], h[:16])
	v[6] = (v[6] & 15) | 64
	v[8] = (v[8] & 63) | 128
	return v
}
