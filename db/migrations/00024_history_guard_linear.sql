-- Forward-only history validation; 019 originals and limits remain unchanged.
-- +goose Up
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION history_archive_guard() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE raw jsonb;manifest jsonb;wire jsonb;member record;member_raw bytea;actual_bytes bigint:=0;
BEGIN
 IF encode(sha256(NEW.original),'hex')<>NEW.original_hash OR encode(sha256(NEW.manifest_original),'hex')<>NEW.manifest_hash OR encode(sha256(NEW.wire_original),'hex')<>NEW.wire_hash THEN RAISE EXCEPTION 'history archive raw hash differs' USING ERRCODE='23514';END IF;
 raw:=convert_from(NEW.original,'UTF8')::jsonb;manifest:=convert_from(NEW.manifest_original,'UTF8')::jsonb;wire:=convert_from(NEW.wire_original,'UTF8')::jsonb;
 IF raw->>'protocol' IS DISTINCT FROM 'zhiyu-history-record-v1' OR raw->>'id' IS DISTINCT FROM NEW.id::text OR raw->'scope' IS DISTINCT FROM jsonb_build_object('environment_id',NEW.environment_id::text,'user_id',NEW.user_id::text) OR
 raw->>'session_id' IS DISTINCT FROM NEW.session_id::text OR raw->>'idempotency_key' IS DISTINCT FROM NEW.idempotency_key OR raw->>'request_hash' IS DISTINCT FROM NEW.request_hash::text OR raw->>'mode' IS DISTINCT FROM NEW.mode OR
 raw->>'wire_hash' IS DISTINCT FROM NEW.wire_hash::text OR raw->'manifest' IS DISTINCT FROM manifest OR wire->'manifest' IS DISTINCT FROM manifest OR manifest->>'protocol' IS DISTINCT FROM 'zhiyu-history-archive-v1' OR
 manifest->>'root_hash' IS DISTINCT FROM NEW.root_hash::text OR jsonb_typeof(manifest->'objects') IS DISTINCT FROM 'array' OR jsonb_array_length(manifest->'objects') IS DISTINCT FROM NEW.object_count OR
 (manifest->>'total_bytes')::bigint IS DISTINCT FROM NEW.total_bytes OR (raw->>'stored_count')::integer IS DISTINCT FROM NEW.stored_count OR (raw->>'stored_bytes')::bigint IS DISTINCT FROM NEW.stored_bytes OR jsonb_array_length(wire->'objects') IS DISTINCT FROM NEW.stored_count OR raw->'verification'->>'status' IS DISTINCT FROM NEW.verification_status OR raw->'verification'->>'root_hash' IS DISTINCT FROM NEW.root_hash::text OR
 raw->'bank_authority' IS DISTINCT FROM 'false'::jsonb OR raw->'activated' IS DISTINCT FROM 'false'::jsonb OR raw->'verification'->'bank_authority' IS DISTINCT FROM 'false'::jsonb OR raw->'verification'->'activated' IS DISTINCT FROM 'false'::jsonb OR
 (raw->>'created_at')::timestamptz IS DISTINCT FROM NEW.created_at THEN RAISE EXCEPTION 'history archive header differs' USING ERRCODE='23514';END IF;
 IF (NEW.mode='SUPPLIED_HISTORY' AND (NEW.request_hash<>NEW.wire_hash OR raw->>'source_trust' IS DISTINCT FROM 'DECLARED_UNVERIFIED')) OR
 (NEW.mode='AUTHENTICATED_CURRENT_READSET' AND (raw->>'source_trust' IS DISTINCT FROM 'LOCAL_AUTHENTICATED_READSET' OR manifest->'source'->>'environment_id' IS DISTINCT FROM NEW.environment_id::text OR manifest->'source'->>'user_id' IS DISTINCT FROM NEW.user_id::text)) THEN
 RAISE EXCEPTION 'history archive source mode differs' USING ERRCODE='23514';END IF;
 -- Verify the immutable wire set once. Complete row guards can then bind
 -- their original/hash to this manifest without reparsing the full wire.
 IF jsonb_typeof(wire->'objects') IS DISTINCT FROM 'array' OR
 (SELECT count(DISTINCT value->>'id') FROM jsonb_array_elements(manifest->'objects'))<>NEW.object_count OR
 (SELECT count(DISTINCT value->>'id') FROM jsonb_array_elements(wire->'objects'))<>NEW.stored_count THEN
 RAISE EXCEPTION 'history wire member identity is ambiguous' USING ERRCODE='23514';END IF;
 FOR member IN
  SELECT w.value AS wire_member,m.value AS expected
  FROM jsonb_array_elements(wire->'objects') w(value)
  LEFT JOIN jsonb_array_elements(manifest->'objects') m(value) ON m.value->>'id'=w.value->>'id'
 LOOP
  IF member.expected IS NULL OR (member.wire_member-'original') IS DISTINCT FROM member.expected OR jsonb_typeof(member.wire_member->'original') IS DISTINCT FROM 'string' THEN
   RAISE EXCEPTION 'history wire descriptor differs' USING ERRCODE='23514';END IF;
  member_raw:=decode(member.wire_member->>'original','base64');
  IF octet_length(member_raw)<1 OR octet_length(member_raw)>16777216 OR octet_length(member_raw) IS DISTINCT FROM (member.expected->>'bytes')::bigint OR encode(sha256(member_raw),'hex') IS DISTINCT FROM member.expected->>'raw_hash' THEN
   RAISE EXCEPTION 'history wire original differs' USING ERRCODE='23514';END IF;
  actual_bytes:=actual_bytes+octet_length(member_raw);
 END LOOP;
 IF actual_bytes<>NEW.stored_bytes THEN RAISE EXCEPTION 'history wire stored bytes differ' USING ERRCODE='23514';END IF;
 RETURN NEW;
END $$;
CREATE OR REPLACE FUNCTION history_object_guard() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE metadata jsonb;manifest jsonb;expected jsonb;wire jsonb;wire_member jsonb;complete boolean;
BEGIN
 IF encode(sha256(NEW.original),'hex')<>NEW.original_hash OR encode(sha256(NEW.metadata_original),'hex')<>NEW.metadata_hash THEN RAISE EXCEPTION 'history original hash differs' USING ERRCODE='23514';END IF;
 metadata:=convert_from(NEW.metadata_original,'UTF8')::jsonb;
 -- Deliberately do not fetch/detoast wire_original in the complete branch.
 SELECT convert_from(manifest_original,'UTF8')::jsonb,stored_count=object_count AND stored_bytes=total_bytes INTO STRICT manifest,complete FROM history_archives WHERE environment_id=NEW.environment_id AND user_id=NEW.user_id AND id=NEW.archive_id;
 expected:=manifest->'objects'->(NEW.ordinal-1);
 IF metadata IS DISTINCT FROM expected OR metadata->>'id' IS DISTINCT FROM NEW.id::text OR metadata->>'table' IS DISTINCT FROM NEW.source_table OR metadata->>'row_key' IS DISTINCT FROM NEW.row_key OR
 metadata->>'representation' IS DISTINCT FROM NEW.representation OR metadata->>'protocol' IS DISTINCT FROM NEW.protocol OR metadata->>'raw_hash' IS DISTINCT FROM NEW.original_hash::text OR (metadata->>'bytes')::integer IS DISTINCT FROM octet_length(NEW.original) THEN
 RAISE EXCEPTION 'history member identity differs' USING ERRCODE='23514';END IF;
 IF NOT complete THEN
  -- Incomplete captures must still prove that this particular member really
  -- exists in the immutable wire; another missing ID with equal bytes is not
  -- interchangeable. Preserve the original strict per-member path.
  SELECT convert_from(wire_original,'UTF8')::jsonb INTO STRICT wire FROM history_archives WHERE environment_id=NEW.environment_id AND user_id=NEW.user_id AND id=NEW.archive_id;
  SELECT value INTO STRICT wire_member FROM jsonb_array_elements(wire->'objects') WHERE value->>'id'=NEW.id::text;
  IF (wire_member-'original') IS DISTINCT FROM metadata OR decode(wire_member->>'original','base64') IS DISTINCT FROM NEW.original THEN
   RAISE EXCEPTION 'history member identity differs' USING ERRCODE='23514';END IF;
 END IF;
 RETURN NEW;
END $$;
-- +goose StatementEnd
-- +goose Down
-- +goose StatementBegin
DO $$ BEGIN RAISE EXCEPTION 'history validation guards are forward only';END $$;
-- +goose StatementEnd
