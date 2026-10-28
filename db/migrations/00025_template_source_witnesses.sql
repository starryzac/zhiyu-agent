-- Forward evidence only. No old source/funds prefix is backfilled.
-- +goose Up
CREATE TABLE funds_commit_witnesses (
 environment_id uuid NOT NULL, user_id uuid NOT NULL, funds_version bigint NOT NULL CHECK(funds_version>0),
 previous_funds_version bigint CHECK(previous_funds_version>0 AND previous_funds_version<funds_version),
 original bytea NOT NULL CHECK(octet_length(original)>0), original_hash hash256 NOT NULL,
 PRIMARY KEY(environment_id,user_id,funds_version),
 FOREIGN KEY(environment_id,user_id) REFERENCES users(environment_id,id)
);
-- Rebuildable trigger cache. Never exported or accepted as audit authority.
CREATE TABLE funds_commit_projection_cache (
 environment_id uuid NOT NULL, user_id uuid NOT NULL, funds_version bigint NOT NULL,
 financial_rows jsonb NOT NULL, state_hash hash256 NOT NULL,
 PRIMARY KEY(environment_id,user_id), FOREIGN KEY(environment_id,user_id) REFERENCES users(environment_id,id)
);
CREATE TABLE template_source_witnesses (
 environment_id uuid NOT NULL, user_id uuid NOT NULL, id uuid NOT NULL,
 funds_version bigint NOT NULL CHECK(funds_version>0), source_version bigint NOT NULL CHECK(source_version>0),
 source_hash hash256 NOT NULL, original bytea NOT NULL CHECK(octet_length(original)>0), original_hash hash256 NOT NULL,
 created_at timestamptz NOT NULL,
 PRIMARY KEY(environment_id,user_id,id),
 FOREIGN KEY(environment_id,user_id,funds_version) REFERENCES funds_commit_witnesses(environment_id,user_id,funds_version)
);
ALTER TABLE template_protection_publications ADD COLUMN source_witness_id uuid;
ALTER TABLE template_protection_publications ADD COLUMN source_witness_hash hash256;
ALTER TABLE template_protection_publications ADD CONSTRAINT template_publication_source_witness_fk FOREIGN KEY(environment_id,user_id,source_witness_id) REFERENCES template_source_witnesses(environment_id,user_id,id);
ALTER TABLE template_protection_publications ADD CONSTRAINT template_publication_source_witness_pair CHECK((source_witness_id IS NULL)=(source_witness_hash IS NULL));

-- +goose StatementBegin
CREATE FUNCTION funds_witness_row_key(value jsonb, fields text[]) RETURNS text LANGUAGE plpgsql IMMUTABLE AS $$
DECLARE key text:='';field text;part text;
BEGIN
 FOREACH field IN ARRAY fields LOOP
  part:=value->>field;
  IF part IS NULL THEN RAISE EXCEPTION 'funds witness row key missing' USING ERRCODE='23514';END IF;
  key:=key||octet_length(part)::text||':'||part;
 END LOOP;
 RETURN key;
END $$;
-- +goose StatementEnd
-- +goose StatementBegin
CREATE FUNCTION funds_witness_state_hash(state jsonb) RETURNS text LANGUAGE sql IMMUTABLE AS $$
 SELECT encode(sha256(convert_to(COALESCE(string_agg(t.key||E'\t'||r.key||E'\t'||encode(sha256(convert_to(r.value,'UTF8')),'hex')||E'\n','' ORDER BY t.key COLLATE "C",r.key COLLATE "C"),''),'UTF8')),'hex')
 FROM jsonb_each(state) t CROSS JOIN LATERAL jsonb_each_text(t.value) r
$$;
-- +goose StatementEnd
-- Capture synchronously, at EACH precise FV boundary. A deferred trigger must
-- never label several intermediate FVs with the transaction's final state.
-- Financial writers must complete their resource/receipt writes before bump.
-- +goose StatementBegin
CREATE FUNCTION seal_funds_commit_witness() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path=public,pg_temp AS $$
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
  ['template_policies','id'],['template_policy_versions','policy_id,version'],['template_policy_confirmations','id'],['template_policy_status_events','id']
 ] LOOP
  row_expression:='to_jsonb(t)';
  EXECUTE format('SELECT COALESCE(jsonb_object_agg(funds_witness_row_key(to_jsonb(t),string_to_array(%L,'','')),(%s)::text),''{}''::jsonb) FROM %I t WHERE environment_id=$1 AND user_id=$2',spec[2],row_expression,spec[1]) INTO values_json USING NEW.environment_id,NEW.id;
  financial:=financial||jsonb_build_object(spec[1],values_json);
  FOR change IN SELECT COALESCE(n.key,o.key) AS key,n.value AS after_original,o.value AS before_original FROM jsonb_each_text(values_json) n FULL JOIN jsonb_each_text(COALESCE(prior_state->spec[1],'{}'::jsonb)) o USING(key) WHERE n.value IS DISTINCT FROM o.value ORDER BY COALESCE(n.key,o.key) COLLATE "C" LOOP
   changes:=changes||jsonb_build_array(jsonb_build_object('table',spec[1],'row_key',change.key,'before_hash',CASE WHEN change.before_original IS NULL THEN NULL ELSE encode(sha256(convert_to(change.before_original,'UTF8')),'hex') END,'after_original',change.after_original));
  END LOOP;
 END LOOP;
 after_hash:=funds_witness_state_hash(financial);
 body:=jsonb_build_object('protocol','funds-commit-witness-v1','scope',jsonb_build_object('environment_id',NEW.environment_id::text,'user_id',NEW.id::text),'namespace',ns,'funds_version',NEW.funds_version,'previous_funds_version',prior,'previous_hash',prior_hash,'source_version',NEW.source_version,'writer_generation',writer,'control_version',control,'transaction_started_at',NULLIF(current_setting('zhiyu.business_as_of',true),''),'previous_state_hash',prior_state_hash,'state_hash',after_hash,'changes',changes);
 raw:=convert_to(body::text,'UTF8');
 INSERT INTO funds_commit_witnesses(environment_id,user_id,funds_version,previous_funds_version,original,original_hash) VALUES(NEW.environment_id,NEW.id,NEW.funds_version,prior,raw,encode(sha256(raw),'hex'));
 INSERT INTO funds_commit_projection_cache(environment_id,user_id,funds_version,financial_rows,state_hash) VALUES(NEW.environment_id,NEW.id,NEW.funds_version,financial,after_hash) ON CONFLICT(environment_id,user_id) DO UPDATE SET funds_version=EXCLUDED.funds_version,financial_rows=EXCLUDED.financial_rows,state_hash=EXCLUDED.state_hash;
 RETURN NEW;
END $$;
-- +goose StatementEnd
CREATE TRIGGER users_funds_commit_witness AFTER INSERT OR UPDATE OF funds_version ON users FOR EACH ROW EXECUTE FUNCTION seal_funds_commit_witness();

-- +goose StatementBegin
CREATE FUNCTION template_source_witness_guard() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE body jsonb; basis bytea;
BEGIN
 IF encode(sha256(NEW.original),'hex')<>NEW.original_hash THEN RAISE EXCEPTION 'source witness original hash' USING ERRCODE='23514';END IF;
 body:=convert_from(NEW.original,'UTF8')::jsonb;
 basis:=decode(body->>'source_basis_original','base64');
 IF body->>'protocol' IS DISTINCT FROM 'template-source-witness-v1' OR body->>'id' IS DISTINCT FROM NEW.id::text OR body->'scope' IS DISTINCT FROM jsonb_build_object('environment_id',NEW.environment_id::text,'user_id',NEW.user_id::text) OR
 (body->>'funds_version')::bigint IS DISTINCT FROM NEW.funds_version OR (body->>'snapshot_source_version')::bigint IS DISTINCT FROM NEW.source_version OR body->>'source_hash' IS DISTINCT FROM NEW.source_hash::text OR encode(sha256(basis),'hex') IS DISTINCT FROM body->>'source_basis_hash' OR (body->>'as_of')::timestamptz IS DISTINCT FROM NEW.created_at THEN
 RAISE EXCEPTION 'source witness exact header/basis' USING ERRCODE='23514';END IF;
 RETURN NEW;
END $$;
-- +goose StatementEnd
CREATE TRIGGER template_source_witness_original_guard BEFORE INSERT ON template_source_witnesses FOR EACH ROW EXECUTE FUNCTION template_source_witness_guard();
CREATE TRIGGER template_source_witness_immutable BEFORE UPDATE OR DELETE ON template_source_witnesses FOR EACH ROW EXECUTE FUNCTION reject_immutable_row();
CREATE TRIGGER funds_commit_witness_immutable BEFORE UPDATE OR DELETE ON funds_commit_witnesses FOR EACH ROW EXECUTE FUNCTION reject_immutable_row();
REVOKE INSERT,UPDATE,DELETE ON funds_commit_witnesses FROM zygo_app;
REVOKE ALL ON funds_commit_projection_cache FROM zygo_app;
GRANT SELECT ON funds_commit_projection_cache TO zygo_app;
REVOKE UPDATE,DELETE ON template_source_witnesses FROM zygo_app;
GRANT SELECT ON funds_commit_witnesses TO zygo_app;
GRANT SELECT,INSERT ON template_source_witnesses TO zygo_app;

-- +goose Down
-- +goose StatementBegin
DO $$ BEGIN RAISE EXCEPTION 'source and funds witness originals are forward only';END $$;
-- +goose StatementEnd
