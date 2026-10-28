-- Execute only inside BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY;
-- SET LOCAL search_path=pg_catalog; SELECT below; ROLLBACK.
-- No bank financial rows, OID values, database names, row statistics, sequence
-- current values, or application credentials are selected.
WITH
ns AS MATERIALIZED (SELECT oid,nspname,nspowner,nspacl FROM pg_namespace WHERE nspname='bank'),
relations AS MATERIALIZED (
 SELECT c.* FROM pg_class c JOIN ns n ON n.oid=c.relnamespace
 WHERE c.relkind IN ('r','p','S','v','m','f','i','I')
),
raw_entries(kind,identity,definition) AS (
 SELECT 'schema'::text COLLATE "C",(n.nspname)::text COLLATE "C",jsonb_build_object('name',n.nspname,'owner',pg_get_userbyid(n.nspowner),'acl',coalesce(n.nspacl::text,'')) FROM ns n
 UNION ALL
 SELECT 'relation'::text COLLATE "C",(c.relname)::text COLLATE "C",jsonb_build_object('name',c.relname,'kind',c.relkind,'persistence',c.relpersistence,'owner',pg_get_userbyid(c.relowner),'access_method',coalesce(am.amname,''),'row_security',c.relrowsecurity,'force_row_security',c.relforcerowsecurity,'replica_identity',c.relreplident,'is_partition',c.relispartition,'partition_bound',CASE WHEN c.relispartition THEN pg_get_expr(c.relpartbound,c.oid,false) ELSE NULL END,'options',ARRAY(SELECT v FROM unnest(coalesce(c.reloptions,ARRAY[]::text[])) v ORDER BY v),'tablespace',coalesce(ts.spcname,''),'acl',coalesce(c.relacl::text,''))
 FROM relations c LEFT JOIN pg_am am ON am.oid=c.relam LEFT JOIN pg_tablespace ts ON ts.oid=c.reltablespace
 UNION ALL
 SELECT 'column'::text COLLATE "C",(c.relname||'.'||a.attname)::text COLLATE "C",jsonb_build_object('relation',c.relname,'position',a.attnum,'name',a.attname,'type_schema',tn.nspname,'type_name',t.typname,'formatted_type',format_type(a.atttypid,a.atttypmod),'not_null',a.attnotnull,'identity',a.attidentity,'generated',a.attgenerated,'storage',a.attstorage,'compression',a.attcompression,'collation_schema',cn.nspname,'collation',co.collname,'default',pg_get_expr(d.adbin,d.adrelid,false),'acl',coalesce(a.attacl::text,''),'options',ARRAY(SELECT v FROM unnest(coalesce(a.attoptions,ARRAY[]::text[])) v ORDER BY v))
 FROM relations c JOIN pg_attribute a ON a.attrelid=c.oid JOIN pg_type t ON t.oid=a.atttypid JOIN pg_namespace tn ON tn.oid=t.typnamespace
 LEFT JOIN pg_attrdef d ON d.adrelid=c.oid AND d.adnum=a.attnum
 LEFT JOIN pg_collation co ON co.oid=a.attcollation LEFT JOIN pg_namespace cn ON cn.oid=co.collnamespace
 WHERE c.relkind IN ('r','p','v','m','f') AND a.attnum>0 AND NOT a.attisdropped
 UNION ALL
 SELECT 'constraint'::text COLLATE "C",(coalesce(c.relname,'<domain:'||t.typname||'>')||'.'||k.conname)::text COLLATE "C",jsonb_build_object('relation',c.relname,'domain',t.typname,'name',k.conname,'kind',k.contype,'definition',pg_get_constraintdef(k.oid,false),'validated',k.convalidated,'deferrable',k.condeferrable,'initially_deferred',k.condeferred,'no_inherit',k.connoinherit,'enforced',to_jsonb(k)->>'conenforced','period',to_jsonb(k)->>'conperiod','parent_constraint',parent.conname,'reference_schema',rn.nspname,'reference_relation',r.relname)
 FROM pg_constraint k JOIN ns n ON n.oid=k.connamespace LEFT JOIN pg_class c ON c.oid=k.conrelid
 LEFT JOIN pg_type t ON t.oid=k.contypid LEFT JOIN pg_class r ON r.oid=k.confrelid LEFT JOIN pg_namespace rn ON rn.oid=r.relnamespace LEFT JOIN pg_constraint parent ON parent.oid=k.conparentid
 UNION ALL
 SELECT 'index'::text COLLATE "C",(i.relname)::text COLLATE "C",jsonb_build_object('name',i.relname,'relation',c.relname,'definition',pg_get_indexdef(x.indexrelid,0,false),'unique',x.indisunique,'nulls_not_distinct',x.indnullsnotdistinct,'primary',x.indisprimary,'exclusion',x.indisexclusion,'immediate',x.indimmediate,'valid',x.indisvalid,'ready',x.indisready,'live',x.indislive,'replica_identity',x.indisreplident,'clustered',x.indisclustered,'key_columns',x.indnkeyatts,'all_columns',x.indnatts,'predicate',pg_get_expr(x.indpred,x.indrelid,false),'expressions',pg_get_expr(x.indexprs,x.indrelid,false))
 FROM pg_index x JOIN relations c ON c.oid=x.indrelid JOIN pg_class i ON i.oid=x.indexrelid
 UNION ALL
 SELECT 'trigger'::text COLLATE "C",(c.relname||'.'||t.tgname)::text COLLATE "C",jsonb_build_object('relation',c.relname,'name',t.tgname,'enabled',t.tgenabled,'definition',pg_get_triggerdef(t.oid,false),'function_schema',pn.nspname,'function',p.proname,'function_arguments',pg_get_function_identity_arguments(p.oid),'old_table',t.tgoldtable,'new_table',t.tgnewtable,'parent_trigger',parent.tgname)
 FROM pg_trigger t JOIN relations c ON c.oid=t.tgrelid JOIN pg_proc p ON p.oid=t.tgfoid JOIN pg_namespace pn ON pn.oid=p.pronamespace LEFT JOIN pg_trigger parent ON parent.oid=t.tgparentid
 WHERE NOT t.tgisinternal
 UNION ALL
 SELECT 'internal-trigger'::text COLLATE "C",(c.relname||'.'||coalesce(kn.nspname||'.'||kc.relname||'.'||k.conname,'<no-constraint>')||'.'||pn.nspname||'.'||p.proname||'('||pg_get_function_identity_arguments(p.oid)||'):'||t.tgtype::text)::text COLLATE "C",
 jsonb_build_object('relation',c.relname,'internal',true,'enabled',t.tgenabled,'trigger_type',t.tgtype,'deferrable',t.tgdeferrable,'initially_deferred',t.tginitdeferred,'columns',t.tgattr::text,'qual',pg_get_expr(t.tgqual,t.tgrelid,false),'arguments_hex',encode(t.tgargs,'hex'),'function_schema',pn.nspname,'function',p.proname,'function_arguments',pg_get_function_identity_arguments(p.oid),'constraint_schema',kn.nspname,'constraint_relation',kc.relname,'constraint_name',k.conname,'constraint_definition',pg_get_constraintdef(k.oid,false),'constraint_target_schema',rn.nspname,'constraint_target_relation',rc.relname,'constraint_index',ix.relname)
 FROM pg_trigger t JOIN relations c ON c.oid=t.tgrelid JOIN pg_proc p ON p.oid=t.tgfoid JOIN pg_namespace pn ON pn.oid=p.pronamespace
 LEFT JOIN pg_constraint k ON k.oid=t.tgconstraint LEFT JOIN pg_namespace kn ON kn.oid=k.connamespace LEFT JOIN pg_class kc ON kc.oid=k.conrelid
 LEFT JOIN pg_class rc ON rc.oid=t.tgconstrrelid LEFT JOIN pg_namespace rn ON rn.oid=rc.relnamespace LEFT JOIN pg_class ix ON ix.oid=t.tgconstrindid
 WHERE t.tgisinternal
 UNION ALL
 SELECT 'rewrite-rule'::text COLLATE "C",(c.relname||'.'||r.rulename)::text COLLATE "C",jsonb_build_object('relation',c.relname,'name',r.rulename,'event',r.ev_type,'enabled',r.ev_enabled,'instead',r.is_instead,'definition',pg_get_ruledef(r.oid,false)) FROM pg_rewrite r JOIN relations c ON c.oid=r.ev_class
 UNION ALL
 SELECT 'function'::text COLLATE "C",(p.proname||'('||pg_get_function_identity_arguments(p.oid)||')')::text COLLATE "C",jsonb_build_object('name',p.proname,'arguments',pg_get_function_identity_arguments(p.oid),'definition',pg_get_functiondef(p.oid),'owner',pg_get_userbyid(p.proowner),'language',l.lanname,'kind',p.prokind,'security_definer',p.prosecdef,'strict',p.proisstrict,'volatility',p.provolatile,'parallel',p.proparallel,'leakproof',p.proleakproof,'returns_set',p.proretset,'cost',p.procost,'rows',p.prorows,'config',ARRAY(SELECT v FROM unnest(coalesce(p.proconfig,ARRAY[]::text[])) v ORDER BY v),'acl',coalesce(p.proacl::text,''))
 FROM pg_proc p JOIN ns n ON n.oid=p.pronamespace JOIN pg_language l ON l.oid=p.prolang WHERE p.prokind<>'a'
 UNION ALL
 SELECT 'type'::text COLLATE "C",(t.typname)::text COLLATE "C",jsonb_build_object('name',t.typname,'owner',pg_get_userbyid(t.typowner),'kind',t.typtype,'category',t.typcategory,'preferred',t.typispreferred,'length',t.typlen,'by_value',t.typbyval,'alignment',t.typalign,'storage',t.typstorage,'delimiter',t.typdelim,'not_null',t.typnotnull,'default',t.typdefault,'base_schema',bn.nspname,'base_type',b.typname,'element_schema',en.nspname,'element_type',e.typname,'relation',c.relname,'collation_schema',cn.nspname,'collation',co.collname,'input',t.typinput::regprocedure::text,'output',t.typoutput::regprocedure::text,'receive',t.typreceive::regprocedure::text,'send',t.typsend::regprocedure::text,'acl',coalesce(t.typacl::text,''))
 FROM pg_type t JOIN ns n ON n.oid=t.typnamespace LEFT JOIN pg_type b ON b.oid=t.typbasetype LEFT JOIN pg_namespace bn ON bn.oid=b.typnamespace
 LEFT JOIN pg_type e ON e.oid=t.typelem LEFT JOIN pg_namespace en ON en.oid=e.typnamespace LEFT JOIN pg_class c ON c.oid=t.typrelid LEFT JOIN pg_collation co ON co.oid=t.typcollation LEFT JOIN pg_namespace cn ON cn.oid=co.collnamespace
 UNION ALL
 SELECT 'enum'::text COLLATE "C",(t.typname||'.'||e.enumlabel)::text COLLATE "C",jsonb_build_object('type',t.typname,'label',e.enumlabel,'sort_order',e.enumsortorder) FROM pg_enum e JOIN pg_type t ON t.oid=e.enumtypid JOIN ns n ON n.oid=t.typnamespace
 UNION ALL
 SELECT 'sequence'::text COLLATE "C",(c.relname)::text COLLATE "C",jsonb_build_object('name',c.relname,'data_type',format_type(s.seqtypid,NULL),'start',s.seqstart,'increment',s.seqincrement,'minimum',s.seqmin,'maximum',s.seqmax,'cache',s.seqcache,'cycle',s.seqcycle,'owned_by',ARRAY(SELECT pn.nspname||'.'||p.relname||'.'||a.attname||':'||d.deptype::text FROM pg_depend d JOIN pg_class p ON p.oid=d.refobjid JOIN pg_namespace pn ON pn.oid=p.relnamespace JOIN pg_attribute a ON a.attrelid=p.oid AND a.attnum=d.refobjsubid WHERE d.classid='pg_class'::regclass AND d.objid=c.oid AND d.refclassid='pg_class'::regclass AND d.deptype IN ('a','i') ORDER BY pn.nspname,p.relname,a.attname,d.deptype))
 FROM pg_sequence s JOIN relations c ON c.oid=s.seqrelid
 UNION ALL
 SELECT 'policy'::text COLLATE "C",(c.relname||'.'||p.polname)::text COLLATE "C",jsonb_build_object('relation',c.relname,'name',p.polname,'command',p.polcmd,'permissive',p.polpermissive,'roles',ARRAY(SELECT CASE WHEN v=0 THEN 'PUBLIC' ELSE coalesce(r.rolname,'<missing-role>') END FROM unnest(p.polroles) v LEFT JOIN pg_roles r ON r.oid=v ORDER BY CASE WHEN v=0 THEN 'PUBLIC' ELSE coalesce(r.rolname,'<missing-role>') END),'using',pg_get_expr(p.polqual,p.polrelid,false),'with_check',pg_get_expr(p.polwithcheck,p.polrelid,false))
 FROM pg_policy p JOIN relations c ON c.oid=p.polrelid
 UNION ALL
 SELECT 'view'::text COLLATE "C",(c.relname)::text COLLATE "C",jsonb_build_object('name',c.relname,'definition',pg_get_viewdef(c.oid,false)) FROM relations c WHERE c.relkind IN ('v','m')
 UNION ALL
 SELECT 'default-acl'::text COLLATE "C",(pg_get_userbyid(d.defaclrole)||'.'||d.defaclobjtype::text)::text COLLATE "C",jsonb_build_object('owner',pg_get_userbyid(d.defaclrole),'object_kind',d.defaclobjtype,'acl',d.defaclacl::text) FROM pg_default_acl d JOIN ns n ON n.oid=d.defaclnamespace
 UNION ALL
 SELECT 'unsupported-presence'::text COLLATE "C",('aggregate/'||p.proname||'('||pg_get_function_identity_arguments(p.oid)||')')::text COLLATE "C",jsonb_build_object('object_kind','aggregate','name',p.proname,'arguments',pg_get_function_identity_arguments(p.oid)) FROM pg_proc p JOIN ns n ON n.oid=p.pronamespace WHERE p.prokind='a'
 UNION ALL
 SELECT 'unsupported-presence'::text COLLATE "C",('operator/'||o.oprname||'('||CASE WHEN o.oprleft=0 THEN '<none>' ELSE format_type(o.oprleft,NULL) END||','||CASE WHEN o.oprright=0 THEN '<none>' ELSE format_type(o.oprright,NULL) END||')')::text COLLATE "C",jsonb_build_object('object_kind','operator','name',o.oprname) FROM pg_operator o JOIN ns n ON n.oid=o.oprnamespace
 UNION ALL
 SELECT 'unsupported-presence'::text COLLATE "C",('collation/'||c.collname||'/'||c.collencoding::text)::text COLLATE "C",jsonb_build_object('object_kind','collation','name',c.collname,'encoding',c.collencoding) FROM pg_collation c JOIN ns n ON n.oid=c.collnamespace
 UNION ALL
 SELECT 'unsupported-presence'::text COLLATE "C",('conversion/'||c.conname)::text COLLATE "C",jsonb_build_object('object_kind','conversion','name',c.conname,'from_encoding',c.conforencoding,'to_encoding',c.contoencoding) FROM pg_conversion c JOIN ns n ON n.oid=c.connamespace
 UNION ALL
 SELECT 'unsupported-presence'::text COLLATE "C",('operator-class/'||a.amname||'/'||c.opcname)::text COLLATE "C",jsonb_build_object('object_kind','operator-class','name',c.opcname,'access_method',a.amname) FROM pg_opclass c JOIN ns n ON n.oid=c.opcnamespace JOIN pg_am a ON a.oid=c.opcmethod
 UNION ALL
 SELECT 'unsupported-presence'::text COLLATE "C",('operator-family/'||a.amname||'/'||f.opfname)::text COLLATE "C",jsonb_build_object('object_kind','operator-family','name',f.opfname,'access_method',a.amname) FROM pg_opfamily f JOIN ns n ON n.oid=f.opfnamespace JOIN pg_am a ON a.oid=f.opfmethod
 UNION ALL
 SELECT 'unsupported-presence'::text COLLATE "C",('text-search-config/'||c.cfgname)::text COLLATE "C",jsonb_build_object('object_kind','text-search-config','name',c.cfgname) FROM pg_ts_config c JOIN ns n ON n.oid=c.cfgnamespace
 UNION ALL
 SELECT 'unsupported-presence'::text COLLATE "C",('text-search-dictionary/'||d.dictname)::text COLLATE "C",jsonb_build_object('object_kind','text-search-dictionary','name',d.dictname) FROM pg_ts_dict d JOIN ns n ON n.oid=d.dictnamespace
 UNION ALL
 SELECT 'unsupported-presence'::text COLLATE "C",('text-search-parser/'||p.prsname)::text COLLATE "C",jsonb_build_object('object_kind','text-search-parser','name',p.prsname) FROM pg_ts_parser p JOIN ns n ON n.oid=p.prsnamespace
 UNION ALL
 SELECT 'unsupported-presence'::text COLLATE "C",('text-search-template/'||t.tmplname)::text COLLATE "C",jsonb_build_object('object_kind','text-search-template','name',t.tmplname) FROM pg_ts_template t JOIN ns n ON n.oid=t.tmplnamespace
 UNION ALL
 SELECT 'unsupported-presence'::text COLLATE "C",('extension/'||e.extname)::text COLLATE "C",jsonb_build_object('object_kind','extension','name',e.extname,'version',e.extversion) FROM pg_extension e JOIN ns n ON n.oid=e.extnamespace
 UNION ALL
 SELECT 'unsupported-presence'::text COLLATE "C",('extended-statistics/'||s.stxname)::text COLLATE "C",jsonb_build_object('object_kind','extended-statistics','name',s.stxname) FROM pg_statistic_ext s JOIN ns n ON n.oid=s.stxnamespace
),
limited AS MATERIALIZED (
 SELECT kind,identity,definition,octet_length(definition::text) AS bytes
 FROM raw_entries ORDER BY kind COLLATE "C",identity COLLATE "C" LIMIT 10001
),
bounds AS (
 SELECT count(*) AS entry_count,coalesce(sum(bytes),0) AS definition_bytes,
 coalesce(bool_or(bytes>65536 OR kind IS NULL OR identity IS NULL OR definition IS NULL OR kind='unsupported-presence'),false) AS bad,
 count(*)<>count(DISTINCT (kind,identity)) AS duplicate_identity FROM limited
),
payload AS (
 SELECT coalesce(jsonb_agg(jsonb_build_object('kind',l.kind,'identity',l.identity,'definition',l.definition) ORDER BY l.kind COLLATE "C",l.identity COLLATE "C"),'[]'::jsonb) AS entries
 FROM limited l CROSS JOIN bounds b WHERE b.entry_count<=10000 AND b.definition_bytes<=4194304 AND NOT b.bad AND NOT b.duplicate_identity
),
envelope AS (
 SELECT jsonb_build_object('protocol','zhiyu-bank-schema-catalog-v2','schema','bank','search_path','pg_catalog','status',CASE WHEN b.entry_count<=10000 AND b.definition_bytes<=4194304 AND NOT b.bad AND NOT b.duplicate_identity THEN 'OK' ELSE 'UNSUPPORTED' END,'entry_count',b.entry_count,'entries',p.entries)::text AS body
 FROM bounds b CROSS JOIN payload p
)
SELECT octet_length(body) AS bytes,CASE WHEN octet_length(body)<=4194304 THEN body ELSE NULL END AS catalog FROM envelope;
