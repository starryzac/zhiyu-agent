-- RF029: process-pinned ownership, durable recovery inventory and SQL fences.
-- Additive source frozen only after exact-source owned-database preflight.
-- +goose Up
CREATE TABLE writer_control_events (
 environment_id uuid NOT NULL REFERENCES environments(id),id uuid NOT NULL,
 original bytea NOT NULL CHECK(octet_length(original) BETWEEN 1 AND 32768),original_hash hash256 NOT NULL,recorded_at timestamptz NOT NULL,
 PRIMARY KEY(environment_id,id)
);
CREATE TABLE writer_controls (
 environment_id uuid PRIMARY KEY REFERENCES environments(id),owner_id uuid NOT NULL,generation bigint NOT NULL CHECK(generation>0),version bigint NOT NULL CHECK(version>0),
 mode text NOT NULL CHECK(mode IN('ACTIVE','RECOVERING','READ_ONLY','FENCED')),event_id uuid NOT NULL,updated_at timestamptz NOT NULL,
 FOREIGN KEY(environment_id,event_id) REFERENCES writer_control_events(environment_id,id)
);
CREATE TABLE recovery_runs (
 environment_id uuid NOT NULL REFERENCES environments(id),id uuid NOT NULL,owner_id uuid NOT NULL,generation bigint NOT NULL,
 original bytea NOT NULL CHECK(octet_length(original) BETWEEN 1 AND 4194304),original_hash hash256 NOT NULL,created_at timestamptz NOT NULL,
 state text NOT NULL CHECK(state IN('SCANNING','INCOMPLETE','READY','ACTIVATED')),version bigint NOT NULL DEFAULT 1 CHECK(version>0),
 PRIMARY KEY(environment_id,id)
);
CREATE TABLE recovery_bank_scans (
 environment_id uuid NOT NULL,run_id uuid NOT NULL,user_id uuid NOT NULL,protocol text NOT NULL CHECK(protocol IN('LEGACY','NATIVE')),
 watermark bigint NOT NULL CHECK(watermark>=0),next_after bigint NOT NULL CHECK(next_after>=0),complete boolean NOT NULL,
 original bytea NOT NULL CHECK(octet_length(original) BETWEEN 1 AND 4194304),original_hash hash256 NOT NULL,recorded_at timestamptz NOT NULL,
 PRIMARY KEY(environment_id,run_id,user_id,protocol),FOREIGN KEY(environment_id,run_id) REFERENCES recovery_runs(environment_id,id)
 -- user deliberately has no users FK: an entire subject may be absent in the backup.
);
CREATE TABLE recovery_bank_observations (
 environment_id uuid NOT NULL,run_id uuid NOT NULL,user_id uuid NOT NULL,protocol text NOT NULL CHECK(protocol IN('LEGACY','NATIVE')),
 bank_key text NOT NULL CHECK(length(bank_key) BETWEEN 1 AND 256),version bigint NOT NULL CHECK(version>0),
 classification text NOT NULL CHECK(classification IN('KNOWN_MATCH','ORPHAN','MISMATCH')),operation_id uuid,
 original bytea NOT NULL CHECK(octet_length(original) BETWEEN 1 AND 1048576),original_hash hash256 NOT NULL,recorded_at timestamptz NOT NULL,
 PRIMARY KEY(environment_id,run_id,user_id,protocol,bank_key,version),FOREIGN KEY(environment_id,run_id,user_id,protocol) REFERENCES recovery_bank_scans(environment_id,run_id,user_id,protocol) DEFERRABLE INITIALLY DEFERRED
);
-- +goose StatementBegin
CREATE FUNCTION recovery_original_guard() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF TG_OP<>'INSERT' THEN RAISE EXCEPTION 'recovery originals are immutable' USING ERRCODE='23514';END IF;
 IF encode(sha256(NEW.original),'hex')<>NEW.original_hash THEN RAISE EXCEPTION 'recovery original hash differs' USING ERRCODE='23514';END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER writer_event_original BEFORE INSERT OR UPDATE OR DELETE ON writer_control_events FOR EACH ROW EXECUTE FUNCTION recovery_original_guard();
CREATE TRIGGER recovery_scan_original BEFORE INSERT OR UPDATE OR DELETE ON recovery_bank_scans FOR EACH ROW EXECUTE FUNCTION recovery_original_guard();
CREATE TRIGGER recovery_observation_original BEFORE INSERT OR UPDATE OR DELETE ON recovery_bank_observations FOR EACH ROW EXECUTE FUNCTION recovery_original_guard();
CREATE FUNCTION writer_control_identity_guard() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE ev jsonb;g bigint;
BEGIN
 IF TG_OP='DELETE' THEN RAISE EXCEPTION 'writer control cannot be removed' USING ERRCODE='23514';END IF;
 IF TG_OP='UPDATE' AND (NEW.environment_id<>OLD.environment_id OR NEW.version<>OLD.version+1 OR NEW.generation<OLD.generation OR NEW.generation>OLD.generation+1 OR (NEW.owner_id<>OLD.owner_id AND NEW.generation<>OLD.generation+1) OR current_setting('zhiyu.writer_owner',true) IS DISTINCT FROM OLD.owner_id::text OR current_setting('zhiyu.writer_generation',true) IS DISTINCT FROM OLD.generation::text) THEN RAISE EXCEPTION 'writer control CAS differs' USING ERRCODE='23514';END IF;
 SELECT writer_generation INTO STRICT g FROM environments WHERE id=NEW.environment_id;
 SELECT convert_from(original,'UTF8')::jsonb INTO STRICT ev FROM writer_control_events WHERE environment_id=NEW.environment_id AND id=NEW.event_id;
 IF TG_OP='UPDATE' AND ev->'before' IS DISTINCT FROM jsonb_build_object('environment_id',OLD.environment_id::text,'owner_id',OLD.owner_id::text,'generation',OLD.generation,'version',OLD.version,'mode',OLD.mode) THEN RAISE EXCEPTION 'writer event before differs' USING ERRCODE='23514';END IF;
 IF TG_OP='INSERT' AND ev ? 'before' THEN RAISE EXCEPTION 'initial writer has no predecessor' USING ERRCODE='23514';END IF;
 IF g<>NEW.generation OR ev->>'protocol' IS DISTINCT FROM 'zhiyu-recovery-cutover-v1/control' OR ev->>'id' IS DISTINCT FROM NEW.event_id::text OR ev->>'environment_id' IS DISTINCT FROM NEW.environment_id::text OR ev->'after'->>'environment_id' IS DISTINCT FROM NEW.environment_id::text OR ev->'after'->>'owner_id' IS DISTINCT FROM NEW.owner_id::text OR (ev->'after'->>'generation')::bigint IS DISTINCT FROM NEW.generation OR (ev->'after'->>'version')::bigint IS DISTINCT FROM NEW.version OR ev->'after'->>'mode' IS DISTINCT FROM NEW.mode OR (ev->>'at')::timestamptz IS DISTINCT FROM NEW.updated_at THEN RAISE EXCEPTION 'writer event or environment differs' USING ERRCODE='23514';END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER writer_control_identity BEFORE INSERT OR UPDATE OR DELETE ON writer_controls FOR EACH ROW EXECUTE FUNCTION writer_control_identity_guard();
CREATE FUNCTION recovery_run_guard() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF TG_OP='DELETE' THEN RAISE EXCEPTION 'recovery run retained' USING ERRCODE='23514';END IF;
 IF TG_OP='INSERT' THEN
  IF encode(sha256(NEW.original),'hex')<>NEW.original_hash THEN RAISE EXCEPTION 'recovery run hash differs' USING ERRCODE='23514';END IF;
 ELSIF ROW(NEW.environment_id,NEW.id,NEW.owner_id,NEW.generation,NEW.original,NEW.original_hash,NEW.created_at) IS DISTINCT FROM ROW(OLD.environment_id,OLD.id,OLD.owner_id,OLD.generation,OLD.original,OLD.original_hash,OLD.created_at) OR NEW.version<>OLD.version+1 OR OLD.state<>'READY' OR NEW.state<>'ACTIVATED' THEN RAISE EXCEPTION 'recovery run identity or version differs' USING ERRCODE='23514';END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER recovery_run_identity BEFORE INSERT OR UPDATE OR DELETE ON recovery_runs FOR EACH ROW EXECUTE FUNCTION recovery_run_guard();

CREATE FUNCTION writer_recovery_metadata_fence() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE c writer_controls;e uuid;
BEGIN
 e:=CASE WHEN TG_OP='DELETE' THEN OLD.environment_id ELSE NEW.environment_id END;
 PERFORM 1 FROM environments WHERE id=e FOR SHARE;
 SELECT * INTO c FROM writer_controls WHERE environment_id=e FOR SHARE;
 IF FOUND AND (current_setting('zhiyu.writer_owner',true) IS DISTINCT FROM c.owner_id::text OR current_setting('zhiyu.writer_generation',true) IS DISTINCT FROM c.generation::text) THEN RAISE EXCEPTION 'WRITER_FENCED' USING ERRCODE='55000';END IF;
 RETURN CASE WHEN TG_OP='DELETE' THEN OLD ELSE NEW END;
END $$;
CREATE TRIGGER aa_recovery_owner BEFORE INSERT OR UPDATE OR DELETE ON recovery_runs FOR EACH ROW EXECUTE FUNCTION writer_recovery_metadata_fence();
CREATE TRIGGER aa_recovery_owner BEFORE INSERT OR UPDATE OR DELETE ON recovery_bank_scans FOR EACH ROW EXECUTE FUNCTION writer_recovery_metadata_fence();
CREATE TRIGGER aa_recovery_owner BEFORE INSERT OR UPDATE OR DELETE ON recovery_bank_observations FOR EACH ROW EXECUTE FUNCTION writer_recovery_metadata_fence();
CREATE TRIGGER aa_recovery_owner BEFORE INSERT OR UPDATE OR DELETE ON writer_control_events FOR EACH ROW EXECUTE FUNCTION writer_recovery_metadata_fence();

CREATE FUNCTION recovery_run_closure_guard() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE e uuid;i uuid;r recovery_runs;raw jsonb;s jsonb;o jsonb;stored recovery_bank_scans;observed recovery_bank_observations;ns text;expected_count integer;actual_count integer;
BEGIN
 e:=NEW.environment_id;i:=CASE WHEN TG_TABLE_NAME='recovery_runs' THEN (to_jsonb(NEW)->>'id')::uuid ELSE (to_jsonb(NEW)->>'run_id')::uuid END;
 SELECT * INTO STRICT r FROM recovery_runs WHERE environment_id=e AND id=i;
 raw:=convert_from(r.original,'UTF8')::jsonb;SELECT namespace INTO STRICT ns FROM environments WHERE id=e;
 IF raw->>'protocol' IS DISTINCT FROM 'zhiyu-recovery-cutover-v1/run' OR raw->>'id' IS DISTINCT FROM i::text OR raw->>'environment_id' IS DISTINCT FROM e::text OR raw->>'namespace' IS DISTINCT FROM ns OR raw->'writer'->>'owner_id' IS DISTINCT FROM r.owner_id::text OR (raw->'writer'->>'generation')::bigint IS DISTINCT FROM r.generation OR raw->'bank_authority' IS DISTINCT FROM 'false'::jsonb OR raw->'subjects'->>'namespace' IS DISTINCT FROM ns OR raw->'subjects'->>'protocol' IS DISTINCT FROM 'zhiyu-bank-recovery-subjects-v1' OR raw->'subjects'->'complete' IS DISTINCT FROM 'true'::jsonb OR jsonb_typeof(raw->'users') IS DISTINCT FROM 'array' OR jsonb_typeof(raw->'scans') IS DISTINCT FROM 'array' OR (raw->>'captured_at')::timestamptz IS DISTINCT FROM r.created_at THEN RAISE EXCEPTION 'recovery manifest scope differs' USING ERRCODE='23514';END IF;
 IF r.state<>'ACTIVATED' AND raw->>'state' IS DISTINCT FROM r.state THEN RAISE EXCEPTION 'recovery state differs from immutable result' USING ERRCODE='23514';END IF;
 SELECT count(DISTINCT uid) INTO expected_count FROM (SELECT x->>'id' uid FROM jsonb_array_elements(raw->'users') x UNION ALL SELECT jsonb_array_elements_text(raw->'subjects'->'user_ids')) u;
 SELECT count(*) INTO actual_count FROM recovery_bank_scans WHERE environment_id=e AND run_id=i;
 IF actual_count<>expected_count*2 OR actual_count<>jsonb_array_length(raw->'scans') THEN RAISE EXCEPTION 'recovery manifest scan members incomplete' USING ERRCODE='23514';END IF;
 FOR s IN SELECT value FROM jsonb_array_elements(raw->'scans') LOOP
  SELECT * INTO STRICT stored FROM recovery_bank_scans WHERE environment_id=e AND run_id=i AND user_id=(s->>'user_id')::uuid AND protocol=s->>'family';
  IF convert_from(stored.original,'UTF8')::jsonb IS DISTINCT FROM s OR NOT stored.complete OR stored.watermark<>(s->>'watermark')::bigint OR stored.next_after<>(s->>'next_after')::bigint THEN RAISE EXCEPTION 'recovery scan original differs' USING ERRCODE='23514';END IF;
  SELECT count(*) INTO actual_count FROM recovery_bank_observations WHERE environment_id=e AND run_id=i AND user_id=stored.user_id AND protocol=stored.protocol;
  IF actual_count<>jsonb_array_length(s->'results') THEN RAISE EXCEPTION 'recovery observation members incomplete' USING ERRCODE='23514';END IF;
  FOR o IN SELECT value FROM jsonb_array_elements(s->'results') LOOP
   SELECT * INTO STRICT observed FROM recovery_bank_observations WHERE environment_id=e AND run_id=i AND user_id=stored.user_id AND protocol=stored.protocol AND bank_key=o->>'key' AND version=(o->>'version')::bigint;
   IF observed.original<>decode(o->>'original','base64') OR observed.original_hash::text IS DISTINCT FROM o->>'original_hash' OR observed.classification IS DISTINCT FROM o->>'classification' OR observed.operation_id::text IS DISTINCT FROM o->>'operation_id' THEN RAISE EXCEPTION 'recovery bank original differs' USING ERRCODE='23514';END IF;
   IF convert_from(observed.original,'UTF8')::jsonb->>'namespace' IS DISTINCT FROM ns OR convert_from(observed.original,'UTF8')::jsonb->>'user_id' IS DISTINCT FROM stored.user_id::text OR convert_from(observed.original,'UTF8')::jsonb->>'key' IS DISTINCT FROM observed.bank_key THEN RAISE EXCEPTION 'recovery bank scope differs' USING ERRCODE='23514';END IF;
  END LOOP;
 END LOOP;
 IF r.state IN('READY','ACTIVATED') AND (coalesce((raw->>'missing_users')::integer,-1)<>0 OR coalesce((raw->>'orphans')::integer,-1)<>0 OR coalesce((raw->>'mismatches')::integer,-1)<>0 OR coalesce((raw->>'unresolved')::integer,-1)<>0 OR coalesce((raw->>'state_mismatches')::integer,-1)<>0 OR EXISTS(SELECT 1 FROM recovery_bank_observations WHERE environment_id=e AND run_id=i AND classification<>'KNOWN_MATCH')) THEN RAISE EXCEPTION 'incomplete recovery cannot be ready' USING ERRCODE='23514';END IF;
 RETURN NULL;
END $$;
CREATE CONSTRAINT TRIGGER recovery_run_members AFTER INSERT OR UPDATE ON recovery_runs DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION recovery_run_closure_guard();
CREATE CONSTRAINT TRIGGER recovery_scan_members AFTER INSERT ON recovery_bank_scans DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION recovery_run_closure_guard();
CREATE CONSTRAINT TRIGGER recovery_observation_members AFTER INSERT ON recovery_bank_observations DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION recovery_run_closure_guard();

CREATE FUNCTION writer_financial_fence() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE rowdata jsonb;olddata jsonb;e uuid;u text;c writer_controls;m text;op uuid;family text;signed boolean;dep jsonb;state text;
BEGIN
 rowdata:=CASE WHEN TG_OP='DELETE' THEN to_jsonb(OLD) ELSE to_jsonb(NEW) END;
 e:=CASE WHEN TG_TABLE_NAME='environments' THEN (rowdata->>'id')::uuid ELSE (rowdata->>'environment_id')::uuid END;
 -- Environment share lock gives the same linearization boundary even for an
 -- old binary issuing direct SQL without the new application check.
 PERFORM 1 FROM environments WHERE id=e FOR SHARE;
 SELECT * INTO c FROM writer_controls WHERE environment_id=e FOR SHARE;
 IF NOT FOUND THEN RETURN CASE WHEN TG_OP='DELETE' THEN OLD ELSE NEW END;END IF;
 IF current_setting('zhiyu.writer_owner',true) IS DISTINCT FROM c.owner_id::text OR current_setting('zhiyu.writer_generation',true) IS DISTINCT FROM c.generation::text THEN RAISE EXCEPTION 'WRITER_FENCED' USING ERRCODE='55000';END IF;
 m:=current_setting('zhiyu.recovery_mode',true);
 IF m='CONTROL' THEN
  IF TG_OP<>'UPDATE' OR TG_TABLE_NAME NOT IN('environments','jobs','native_jobs','standing_inbox','native_occurrences','native_income_intakes') THEN RAISE EXCEPTION 'invalid control mutation' USING ERRCODE='55000';END IF;
  olddata:=to_jsonb(OLD);
  IF TG_TABLE_NAME='environments' THEN
   IF (rowdata-'writer_generation'-'control_version') IS DISTINCT FROM (olddata-'writer_generation'-'control_version') OR ((rowdata->>'writer_generation')::bigint NOT IN(c.generation,c.generation+1) OR (rowdata->>'control_version')::bigint<>(olddata->>'control_version')::bigint+1) THEN RAISE EXCEPTION 'invalid generation transition' USING ERRCODE='55000';END IF;
  ELSIF (rowdata-'claim_generation'-'lease_owner'-'lease_until'-'state') IS DISTINCT FROM (olddata-'claim_generation'-'lease_owner'-'lease_until'-'state') THEN RAISE EXCEPTION 'control may only invalidate leases' USING ERRCODE='55000';END IF;
  RETURN NEW;
 END IF;
 IF c.mode='ACTIVE' THEN RETURN CASE WHEN TG_OP='DELETE' THEN OLD ELSE NEW END;END IF;
 IF c.mode<>'RECOVERING' OR m NOT IN('SIGNED','CANCEL_UNSIGNED') THEN RAISE EXCEPTION 'WRITER_RECOVERING' USING ERRCODE='55000';END IF;
 op:=nullif(current_setting('zhiyu.recovery_operation',true),'')::uuid;u:=current_setting('zhiyu.recovery_user',true);family:=current_setting('zhiyu.recovery_family',true);
 IF op IS NULL OR (rowdata ? 'user_id' AND rowdata->>'user_id' IS DISTINCT FROM u) THEN RAISE EXCEPTION 'recovery scope differs' USING ERRCODE='55000';END IF;
 IF family='LEGACY' THEN SELECT permit_signature IS NOT NULL,dependencies,status INTO signed,dep,state FROM operations WHERE environment_id=e AND user_id=u::uuid AND id=op;
 ELSIF family='NATIVE' THEN SELECT permit_signature IS NOT NULL,dependencies,status INTO signed,dep,state FROM native_operations WHERE environment_id=e AND user_id=u::uuid AND id=op;
 ELSE RAISE EXCEPTION 'recovery family differs' USING ERRCODE='55000';END IF;
 IF signed IS NULL OR (m='SIGNED' AND NOT signed) OR (m='CANCEL_UNSIGNED' AND (signed OR coalesce((dep->>'writer_generation')::bigint,c.generation)>=c.generation)) THEN RAISE EXCEPTION 'recovery original not admissible' USING ERRCODE='55000';END IF;
 IF TG_TABLE_NAME NOT IN('users','accounts','income_origins','income_locations','income_reservations','income_claims','goals','operations','jobs','journals','postings','receipts','bank_observations','outbox','protection_snapshots','evidence_blobs','native_operations','native_jobs','native_income_reservations','native_income_claims','native_goal_balances','native_goal_lots','native_holds','native_positions','native_position_states','native_principal_returns','native_return_locations','native_return_claims','native_bank_observations','native_journals','native_postings','native_receipts','native_grant_budget_claims','native_standing_bridge_closures','native_obligation_payments','template_inventory_contracts','template_obligations','template_obligation_payments','template_protection_publications') THEN RAISE EXCEPTION 'new authority or source prohibited during recovery on %',TG_TABLE_NAME USING ERRCODE='55000';END IF;
 IF TG_TABLE_NAME='users' AND (TG_OP<>'UPDATE' OR rowdata->>'id' IS DISTINCT FROM u) THEN RAISE EXCEPTION 'new user prohibited during recovery' USING ERRCODE='55000';END IF;
 IF TG_TABLE_NAME IN('accounts','goals') AND TG_OP<>'UPDATE' THEN RAISE EXCEPTION 'new account or goal prohibited during recovery' USING ERRCODE='55000';END IF;
 IF TG_TABLE_NAME='template_inventory_contracts' AND (TG_OP<>'INSERT' OR NOT EXISTS(SELECT 1 FROM template_inventory_contracts x WHERE x.environment_id=e AND x.user_id=u::uuid AND to_jsonb(x)-'created_at'=rowdata-'created_at')) THEN RAISE EXCEPTION 'new inventory authority prohibited during recovery' USING ERRCODE='55000';END IF;
 IF TG_TABLE_NAME='income_origins' AND (TG_OP<>'INSERT' OR NOT EXISTS(SELECT 1 FROM income_origins i WHERE i.environment_id=e AND i.user_id=u::uuid AND to_jsonb(i)=rowdata)) THEN RAISE EXCEPTION 'new income prohibited during recovery' USING ERRCODE='55000';END IF;
 IF TG_TABLE_NAME IN('operations','native_operations') THEN
  IF TG_OP<>'UPDATE' OR rowdata->'permit_signature' IS DISTINCT FROM to_jsonb(OLD)->'permit_signature' OR (m='CANCEL_UNSIGNED' AND rowdata->>'status'<>'CANCELLED') THEN RAISE EXCEPTION 'new operation or permit prohibited during recovery' USING ERRCODE='55000';END IF;
  IF rowdata->>'id'<>op::text AND NOT(TG_TABLE_NAME='native_operations' AND family='NATIVE' AND rowdata->>'status'='CANCELLED' AND to_jsonb(OLD)->>'status'='QUEUED' AND to_jsonb(OLD)->>'permit_signature' IS NULL AND EXISTS(SELECT 1 FROM native_operations prefix WHERE prefix.environment_id=e AND prefix.user_id=u::uuid AND prefix.id=op AND prefix.group_id IS NOT NULL AND prefix.group_id=(rowdata->>'group_id')::uuid AND prefix.child_number<(rowdata->>'child_number')::integer)) THEN RAISE EXCEPTION 'unrelated operation outside recovery capability' USING ERRCODE='55000';END IF;
 END IF;
 RETURN CASE WHEN TG_OP='DELETE' THEN OLD ELSE NEW END;
END $$;
-- Capture the actual frozen 1-22 financial relations. Authentication and
-- non-financial audit/history/projection metadata remain usable while fenced.
DO $$ DECLARE r record; BEGIN
 FOR r IN SELECT c.table_name FROM information_schema.columns c JOIN information_schema.tables t USING(table_schema,table_name) WHERE c.table_schema='public' AND t.table_type='BASE TABLE' AND c.column_name='environment_id' AND c.table_name NOT IN('writer_controls','writer_control_events','recovery_runs','recovery_bank_scans','recovery_bank_observations','login_credentials','sessions','operation_projection_events','operation_read_models','projection_offsets') AND c.table_name NOT LIKE 'audit_%' AND c.table_name NOT LIKE 'history_%' ORDER BY c.table_name LOOP
  EXECUTE format('CREATE TRIGGER zz_writer_financial_fence BEFORE INSERT OR UPDATE OR DELETE ON %I FOR EACH ROW EXECUTE FUNCTION writer_financial_fence()',r.table_name);
 END LOOP;
 CREATE TRIGGER zz_writer_financial_fence BEFORE INSERT OR UPDATE OR DELETE ON environments FOR EACH ROW EXECUTE FUNCTION writer_financial_fence();
END $$;
-- +goose StatementEnd
GRANT SELECT,INSERT,UPDATE ON writer_controls,writer_control_events,recovery_runs,recovery_bank_scans,recovery_bank_observations TO zygo_app;
-- +goose Down
-- +goose StatementBegin
DO $$ DECLARE r record;BEGIN FOR r IN SELECT c.relname FROM pg_trigger t JOIN pg_class c ON c.oid=t.tgrelid JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='public' AND t.tgname='zz_writer_financial_fence' LOOP EXECUTE format('DROP TRIGGER zz_writer_financial_fence ON %I',r.relname);END LOOP;END $$;
-- +goose StatementEnd
DROP FUNCTION writer_financial_fence();
DROP TABLE recovery_bank_observations,recovery_bank_scans,recovery_runs,writer_controls,writer_control_events;
DROP FUNCTION recovery_run_guard(),writer_control_identity_guard(),recovery_original_guard(),writer_recovery_metadata_fence(),recovery_run_closure_guard();
