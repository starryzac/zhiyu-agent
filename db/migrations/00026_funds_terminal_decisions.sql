-- Forward terminal decisions. No historical decision or authority is backfilled.
-- +goose Up
CREATE TABLE funds_terminal_decisions (
 environment_id uuid NOT NULL,user_id uuid NOT NULL,id uuid NOT NULL,
 ledger_kind text NOT NULL CHECK(ledger_kind IN('LEGACY','NATIVE')),operation_id uuid NOT NULL,
 previous_funds_version bigint NOT NULL CHECK(previous_funds_version>0),
 terminal_funds_version bigint NOT NULL CHECK(terminal_funds_version=previous_funds_version+1),
 original bytea NOT NULL CHECK(octet_length(original) BETWEEN 1 AND 262144),original_hash hash256 NOT NULL,
 recorded_at timestamptz NOT NULL,
 PRIMARY KEY(environment_id,user_id,id),UNIQUE(environment_id,user_id,ledger_kind,operation_id),
 FOREIGN KEY(environment_id,user_id) REFERENCES users(environment_id,id),
 FOREIGN KEY(environment_id,user_id,previous_funds_version) REFERENCES funds_commit_witnesses(environment_id,user_id,funds_version),
 FOREIGN KEY(environment_id,user_id,terminal_funds_version) REFERENCES funds_commit_witnesses(environment_id,user_id,funds_version) DEFERRABLE INITIALLY DEFERRED
);

-- +goose StatementBegin
CREATE FUNCTION funds_terminal_decision_original_guard() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE body jsonb; cache jsonb; cache_hash text; resources jsonb; resource_count bigint;
 current_fv bigint; current_sv bigint; writer bigint; control bigint; ns text;
 commit_hash text; committed_hash text; op_state text; request_hash text; signature text; reserved_fv bigint;
BEGIN
 IF encode(sha256(NEW.original),'hex')<>NEW.original_hash THEN RAISE EXCEPTION 'terminal decision original hash' USING ERRCODE='23514';END IF;
 body:=convert_from(NEW.original,'UTF8')::jsonb;
 IF body->>'protocol' IS DISTINCT FROM 'funds-terminal-decision-v1' OR body->>'id' IS DISTINCT FROM NEW.id::text OR
 body->'scope' IS DISTINCT FROM jsonb_build_object('environment_id',NEW.environment_id::text,'user_id',NEW.user_id::text) OR
 body->>'ledger_kind' IS DISTINCT FROM NEW.ledger_kind OR body->>'operation_id' IS DISTINCT FROM NEW.operation_id::text OR
 (body->'before'->>'funds_version')::bigint IS DISTINCT FROM NEW.previous_funds_version OR (body->>'terminal_funds_version')::bigint IS DISTINCT FROM NEW.terminal_funds_version OR
 (body->>'decision_at')::timestamptz IS DISTINCT FROM NEW.recorded_at THEN
 RAISE EXCEPTION 'terminal decision exact header' USING ERRCODE='23514';END IF;
 SELECT u.funds_version,u.source_version,e.writer_generation,e.control_version,e.namespace INTO STRICT current_fv,current_sv,writer,control,ns
 FROM users u JOIN environments e ON e.id=u.environment_id WHERE u.environment_id=NEW.environment_id AND u.id=NEW.user_id;
 SELECT financial_rows,state_hash INTO STRICT cache,cache_hash FROM funds_commit_projection_cache WHERE environment_id=NEW.environment_id AND user_id=NEW.user_id AND funds_version=NEW.previous_funds_version;
 SELECT original_hash,(convert_from(original,'UTF8')::jsonb)->>'state_hash' INTO STRICT commit_hash,committed_hash FROM funds_commit_witnesses WHERE environment_id=NEW.environment_id AND user_id=NEW.user_id AND funds_version=NEW.previous_funds_version;
 resources:=funds_witness_operation_resources(cache,NEW.ledger_kind,NEW.operation_id::text);
 SELECT count(*) INTO resource_count FROM jsonb_each(resources) t CROSS JOIN LATERAL jsonb_each(t.value) r;
 IF NEW.ledger_kind='NATIVE' THEN
  SELECT status,bank_request_hash,permit_signature,reserved_funds_version INTO STRICT op_state,request_hash,signature,reserved_fv FROM native_operations WHERE environment_id=NEW.environment_id AND user_id=NEW.user_id AND id=NEW.operation_id;
 ELSE
  SELECT status,bank_request_hash,permit_signature,reserved_funds_version INTO STRICT op_state,request_hash,signature,reserved_fv FROM operations WHERE environment_id=NEW.environment_id AND user_id=NEW.user_id AND id=NEW.operation_id;
 END IF;
 IF current_fv<>NEW.previous_funds_version OR body->>'namespace' IS DISTINCT FROM ns OR
 (body->'before'->>'source_version')::bigint IS DISTINCT FROM current_sv OR (body->'before'->>'writer_generation')::bigint IS DISTINCT FROM writer OR (body->'before'->>'control_version')::bigint IS DISTINCT FROM control OR
 funds_witness_state_hash(cache) IS DISTINCT FROM cache_hash OR cache_hash IS DISTINCT FROM committed_hash OR body->'before'->>'commit_hash' IS DISTINCT FROM commit_hash OR body->'before'->>'state_hash' IS DISTINCT FROM committed_hash OR
 op_state NOT IN('CANCELLED','REJECTED') OR body->>'terminal_state' IS DISTINCT FROM op_state OR body->>'bank_request_hash' IS DISTINCT FROM request_hash OR (body->>'reserved_funds_version')::bigint IS DISTINCT FROM reserved_fv OR
 COALESCE(body->>'permit_signature_hash','') IS DISTINCT FROM (CASE WHEN signature IS NULL THEN '' ELSE encode(sha256(convert_to(signature,'UTF8')),'hex') END) OR
 resource_count<1 OR (body->>'resource_row_count')::bigint IS DISTINCT FROM resource_count OR body->>'resource_vector_hash' IS DISTINCT FROM funds_witness_state_hash(resources) THEN
 RAISE EXCEPTION 'terminal decision exact original request/before resources/boundary' USING ERRCODE='23514';END IF;
 RETURN NEW;
END $$;
-- +goose StatementEnd
CREATE TRIGGER funds_terminal_decision_original_guard BEFORE INSERT ON funds_terminal_decisions FOR EACH ROW EXECUTE FUNCTION funds_terminal_decision_original_guard();
CREATE TRIGGER funds_terminal_decision_immutable BEFORE UPDATE OR DELETE ON funds_terminal_decisions FOR EACH ROW EXECUTE FUNCTION reject_immutable_row();
REVOKE UPDATE,DELETE ON funds_terminal_decisions FROM zygo_app;
GRANT SELECT,INSERT ON funds_terminal_decisions TO zygo_app;

-- Same exact raw-row framing as the retained funds state. Pure input function;
-- callers must independently anchor their BEFORE cache to its immutable commit.
-- +goose StatementBegin
CREATE FUNCTION funds_witness_operation_resources(before_state jsonb,ledger_kind text,operation text) RETURNS jsonb LANGUAGE sql IMMUTABLE AS $$
 WITH selected AS (
  SELECT t.key AS table_name,r.key AS row_key,r.value AS original
  FROM jsonb_each(before_state) t CROSS JOIN LATERAL jsonb_each_text(t.value) r
  WHERE ((ledger_kind='LEGACY' AND t.key IN('income_reservations','income_claims')) OR
         (ledger_kind='NATIVE' AND t.key IN('native_income_reservations','native_income_claims','native_holds','native_return_claims')))
  AND COALESCE(r.value::jsonb->>'operation_id',r.value::jsonb->>'action_id')=operation
  AND (r.value::jsonb->>'state'='RESERVED' OR
   t.key IN('income_claims','native_income_claims') AND EXISTS(
    SELECT 1 FROM jsonb_each_text(COALESCE(before_state->CASE WHEN ledger_kind='LEGACY' THEN 'income_reservations' ELSE 'native_income_reservations' END,'{}'::jsonb)) h
    WHERE h.value::jsonb->>'action_id'=operation AND h.value::jsonb->>'state'='RESERVED'))
 ), grouped AS (SELECT table_name,jsonb_object_agg(row_key,original) AS rows FROM selected GROUP BY table_name)
 SELECT COALESCE(jsonb_object_agg(table_name,rows),'{}'::jsonb) FROM grouped
$$;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION seal_funds_commit_witness() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path=public,pg_temp AS $$
DECLARE financial jsonb:='{}'::jsonb; spec text[]; values_json jsonb; prior bigint; prior_hash text;
 prior_state jsonb:='{}'::jsonb; prior_state_hash text; sealed_state_hash text; after_hash text; changes jsonb:='[]'::jsonb;change record;
 ns text; writer bigint; control bigint; body jsonb; raw bytea; row_expression text;
BEGIN
 IF TG_OP='UPDATE' AND NEW.funds_version=OLD.funds_version THEN RETURN NEW;END IF;
 IF TG_OP='UPDATE' AND NEW.funds_version<>OLD.funds_version+1 THEN RAISE EXCEPTION 'funds witness requires one version per boundary' USING ERRCODE='23514';END IF;
 SELECT namespace,writer_generation,control_version INTO STRICT ns,writer,control FROM environments WHERE id=NEW.environment_id;
 SELECT funds_version,original_hash INTO prior,prior_hash FROM funds_commit_witnesses WHERE environment_id=NEW.environment_id AND user_id=NEW.id ORDER BY funds_version DESC LIMIT 1;
 IF prior IS NOT NULL AND prior<>NEW.funds_version-1 THEN RAISE EXCEPTION 'funds witness prefix gap' USING ERRCODE='23514';END IF;
 IF prior IS NOT NULL THEN
  SELECT financial_rows,state_hash INTO STRICT prior_state,prior_state_hash FROM funds_commit_projection_cache WHERE environment_id=NEW.environment_id AND user_id=NEW.id AND funds_version=prior;
  SELECT (convert_from(original,'UTF8')::jsonb)->>'state_hash' INTO STRICT sealed_state_hash FROM funds_commit_witnesses WHERE environment_id=NEW.environment_id AND user_id=NEW.id AND funds_version=prior;
  IF funds_witness_state_hash(prior_state)<>prior_state_hash OR prior_state_hash IS DISTINCT FROM sealed_state_hash THEN RAISE EXCEPTION 'funds witness cache differs from immutable commit' USING ERRCODE='23514';END IF;
 ELSE prior_state_hash:=funds_witness_state_hash(prior_state);END IF;
 FOREACH spec SLICE 1 IN ARRAY ARRAY[
  ['accounts','id'],['goals','id'],['income_origins','id'],['income_locations','id'],
  ['income_reservations','action_id'],['income_claims','action_id,fragment_id'],
  ['native_income_reservations','action_id'],['native_income_claims','action_id,fragment_id'],
  ['native_goal_balances','goal_id'],['native_goal_lots','goal_id,account_id,source_kind,source_id'],
  ['native_holds','operation_id,resource_kind,resource_id,resource_detail'],
  ['native_positions','id'],['native_position_states','position_id'],
  ['native_principal_returns','bank_key'],['native_return_locations','bank_key,account_id'],
  ['native_return_claims','operation_id,bank_key,account_id'],['receipts','id'],['native_receipts','id'],
  ['native_payment_sources','operation_id'],['native_obligation_payments','id'],['template_obligation_payments','id'],
  ['template_policies','id'],['template_policy_versions','policy_id,version'],['template_policy_confirmations','id'],['template_policy_status_events','id'],
  ['native_grants','id,version'],['native_grant_state_events','id'],['native_grant_states','grant_id,grant_version'],
  ['native_bank_observations','id'],['bank_observations','id'],['funds_terminal_decisions','id']
 ] LOOP
  row_expression:='to_jsonb(t)';
  EXECUTE format('SELECT COALESCE(jsonb_object_agg(funds_witness_row_key(to_jsonb(t),string_to_array(%L,'','')),(%s)::text),''{}''::jsonb) FROM %I t WHERE environment_id=$1 AND user_id=$2',spec[2],row_expression,spec[1]) INTO values_json USING NEW.environment_id,NEW.id;
  financial:=financial||jsonb_build_object(spec[1],values_json);
  FOR change IN SELECT COALESCE(n.key,o.key) AS key,n.value AS after_original,o.value AS before_original FROM jsonb_each_text(values_json) n FULL JOIN jsonb_each_text(COALESCE(prior_state->spec[1],'{}'::jsonb)) o USING(key) WHERE n.value IS DISTINCT FROM o.value ORDER BY COALESCE(n.key,o.key) COLLATE "C" LOOP
   changes:=changes||jsonb_build_array(jsonb_build_object('table',spec[1],'row_key',change.key,'before_hash',CASE WHEN change.before_original IS NULL THEN NULL ELSE encode(sha256(convert_to(change.before_original,'UTF8')),'hex') END,'after_original',change.after_original));
  END LOOP;
 END LOOP;
 IF EXISTS(
  WITH released AS (
   SELECT DISTINCT CASE WHEN c->>'table'='income_reservations' THEN 'LEGACY' ELSE 'NATIVE' END AS ledger_kind,
   COALESCE((c->>'after_original')::jsonb->>'operation_id',(c->>'after_original')::jsonb->>'action_id') AS operation_id
   FROM jsonb_array_elements(changes) c
   WHERE c->>'table' IN('income_reservations','native_income_reservations','native_holds','native_return_claims')
   AND (c->>'after_original')::jsonb->>'state'='RELEASED'
   AND (prior_state->(c->>'table')->>(c->>'row_key'))::jsonb->>'state'='RESERVED'
  ), decisions AS (
   SELECT ledger_kind,operation_id::text AS operation_id FROM funds_terminal_decisions
   WHERE environment_id=NEW.environment_id AND user_id=NEW.id AND terminal_funds_version=NEW.funds_version
  ) SELECT 1 FROM released r FULL JOIN decisions d USING(ledger_kind,operation_id)
  WHERE r.operation_id IS NULL OR d.operation_id IS NULL
 ) THEN RAISE EXCEPTION 'exact terminal decision/released resource set differs' USING ERRCODE='23514';END IF;
 after_hash:=funds_witness_state_hash(financial);
 body:=jsonb_build_object('protocol','funds-commit-witness-v2','scope',jsonb_build_object('environment_id',NEW.environment_id::text,'user_id',NEW.id::text),'namespace',ns,'funds_version',NEW.funds_version,'previous_funds_version',prior,'previous_hash',prior_hash,'source_version',NEW.source_version,'writer_generation',writer,'control_version',control,'transaction_started_at',NULLIF(current_setting('zhiyu.business_as_of',true),''),'previous_state_hash',prior_state_hash,'state_hash',after_hash,'changes',changes);
 raw:=convert_to(body::text,'UTF8');
 INSERT INTO funds_commit_witnesses(environment_id,user_id,funds_version,previous_funds_version,original,original_hash) VALUES(NEW.environment_id,NEW.id,NEW.funds_version,prior,raw,encode(sha256(raw),'hex'));
 INSERT INTO funds_commit_projection_cache(environment_id,user_id,funds_version,financial_rows,state_hash) VALUES(NEW.environment_id,NEW.id,NEW.funds_version,financial,after_hash) ON CONFLICT(environment_id,user_id) DO UPDATE SET funds_version=EXCLUDED.funds_version,financial_rows=EXCLUDED.financial_rows,state_hash=EXCLUDED.state_hash;
 RETURN NEW;
END $$;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DO $$ BEGIN RAISE EXCEPTION 'terminal decision originals are forward only';END $$;
-- +goose StatementEnd
