import { cents } from './money';
import { parseTemplateName } from './template-schema';
import type { TemplateName } from './template-schema';
import type { AgentReference } from './agent';

const protocol = 'zhiyu-agent-native-grants-v1';
const verification = 'OWNED_ORIGINALS_AND_COMPLETE_GRANT_STATE_CHAIN';
const sessionScopes = ['SCOPED_SUBJECT_AND_EVENT_EXPIRY_ONLY', 'HISTORY_INCOMPLETE'] as const;
const families = ['SINGLE_GOAL', 'JOINT_GOALS', 'ASSET_ALLOCATION', 'MATURITY_REINVEST', 'PERIODIC_PAYMENT'] as const;
const recorded = ['ACTIVE', 'PAUSED', 'REVOKED'] as const;
const effective = ['REVOKED', 'EXPIRED', 'PAUSED', 'NOT_YET_EFFECTIVE', 'POLICY_CHANGED', 'UNAVAILABLE', 'CURRENT_DISPLAY_ONLY'] as const;
const reasonNames = ['CAPACITY', 'SCHEMA_UNAVAILABLE', 'EVIDENCE_INVALID', 'SUBJECT_UNAVAILABLE', 'SESSION_EXPIRED_AT_EVENT', 'SESSION_REVOCATION_HISTORY_UNAVAILABLE', 'POLICY_CHANGED', 'POLICY_UNAVAILABLE', 'NOT_YET_EFFECTIVE', 'EXPIRED', 'PAUSED', 'REVOKED'] as const;
export type GrantReason = typeof reasonNames[number];
export interface AgentGrantPolicyRef { policy_id: string; version_id: string; version: number; template_name: TemplateName; configuration_hash: string; goal_id?: string }
export interface AgentNativeGrant {
  id: string; version: 1; family: typeof families[number]; recorded_state: typeof recorded[number]; effective_state: typeof effective[number]; state_sequence: number;
  state_at: string; effective_from: string; expires_at: string; evaluated_local_date: string; timezone: string;
  policy_references: AgentGrantPolicyRef[]; account_ids: string[]; goal_ids: string[]; product_ids: string[]; payee_ids: string[];
  single_cap_cents: string; lifetime_cap_cents: string; monthly_cap_cents: string; original_digest: string; terms_digest: string; chain_digest: string; reason_codes: GrantReason[];
  authority: false; bank_authority: false;
}
export type AgentNativeGrantCollection = {
  protocol: typeof protocol; collection_digest: string; authority: false; bank_authority: false;
} & ({ status: 'COMPLETE'; count: number; items: AgentNativeGrant[]; reason_codes: []; verification_scope: typeof verification; session_verification: typeof sessionScopes[number] }
  | { status: 'UNAVAILABLE'; items: []; reason_codes: GrantReason[]; verification_scope: 'NOT_VERIFIED'; session_verification: 'NOT_VERIFIED' });

function object(raw: unknown): Record<string, unknown> { if (!raw || typeof raw !== 'object' || Array.isArray(raw)) throw new Error('原生授权结构无法核实'); return raw as Record<string, unknown>; }
function closed(row: Record<string, unknown>, keys: string[]): void { if (Object.keys(row).some((key) => !keys.includes(key))) throw new Error('原生授权字段超出只读合同'); }
function text(raw: unknown): string { if (typeof raw !== 'string') throw new Error('原生授权字段类型不符'); return raw; }
function integer(raw: unknown, min: number, max: number): number { if (!Number.isSafeInteger(raw) || (raw as number) < min || (raw as number) > max) throw new Error('原生授权数量或序号越界'); return raw as number; }
function choice<T extends string>(raw: unknown, values: readonly T[]): T { const value = text(raw); if (!values.includes(value as T)) throw new Error('原生授权状态无法识别'); return value as T; }
function uuid(raw: unknown): string { const value = text(raw); if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/.test(value) || /^0{8}-0{4}-0{4}-0{4}-0{12}$/.test(value)) throw new Error('原生授权引用不符'); return value; }
function hash(raw: unknown): string { const value = text(raw); if (!/^[a-f0-9]{64}$/.test(value)) throw new Error('原生授权摘要不符'); return value; }
function list<T>(raw: unknown, parse: (item: unknown) => T, max: number): T[] { if (!Array.isArray(raw) || raw.length > max) throw new Error('原生授权列表越界'); return raw.map(parse); }
function sorted(values: string[]): string[] { if (values.some((value, index) => index > 0 && value <= values[index - 1]!)) throw new Error('原生授权列表重复或乱序'); return values; }
function ids(raw: unknown, max: number): string[] { return sorted(list(raw, uuid, max)); }
function names(raw: unknown, max: number): string[] { return sorted(list(raw, (item) => { const value = text(item); if (!/^[A-Za-z0-9_.:-]{1,128}$/.test(value)) throw new Error('原生授权范围标识不符'); return value; }, max)); }
function money(raw: unknown): string { const value = cents(raw); if (BigInt(value) <= 0n || BigInt(value) > 9000000000000000n) throw new Error('原生授权限额超出v1合同'); return value; }
function reasons(raw: unknown): GrantReason[] { return sorted(list(raw, (item) => choice(item, reasonNames), 13)) as GrantReason[]; }
function byteBound(raw: unknown, maximum: number): void { if (new TextEncoder().encode(JSON.stringify(raw)).length > maximum) throw new Error('原生授权显示超出大小合同'); }

// Preserve the server's sub-millisecond business boundary when comparing times.
function instant(raw: unknown): { value: string; ns: bigint; millis: number } {
  const value = text(raw); const match = /^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})(?:\.(\d{1,9}))?(Z|[+-]\d{2}:\d{2})$/.exec(value);
  if (!match) throw new Error('原生授权时间不符');
  const millis = Date.parse(match[1]! + match[3]!);
  if (!Number.isSafeInteger(millis)) throw new Error('原生授权时间越界');
  const offset = match[3] === 'Z' ? 0 : (match[3]![0] === '-' ? -1 : 1) * (Number(match[3]!.slice(1, 3)) * 60 + Number(match[3]!.slice(4, 6)));
  if (new Date(millis + offset * 60000).toISOString().slice(0, 19) !== match[1]) throw new Error('原生授权日期无效');
  return { value, ns: BigInt(millis) * 1000000n + BigInt((match[2] ?? '').padEnd(9, '0')), millis: Date.parse(value) };
}
function localDate(asOf: string, timezone: string): string {
  const parts = new Intl.DateTimeFormat('en', { timeZone: timezone, year: 'numeric', month: '2-digit', day: '2-digit' }).formatToParts(new Date(asOf));
  return ['year', 'month', 'day'].map((type) => parts.find((part) => part.type === type)!.value).join('-');
}
function policyRef(raw: unknown): AgentGrantPolicyRef {
  const row = object(raw); closed(row, ['policy_id', 'version_id', 'version', 'template_name', 'configuration_hash', 'goal_id']);
  if ('goal_id' in row && row.goal_id == null) throw new Error('原生授权可选目标引用不符');
  return { policy_id: uuid(row.policy_id), version_id: uuid(row.version_id), version: integer(row.version, 1, Number.MAX_SAFE_INTEGER), template_name: parseTemplateName(row.template_name), configuration_hash: hash(row.configuration_hash), ...(row.goal_id == null ? {} : { goal_id: uuid(row.goal_id) }) };
}

export function parseNativeGrant(raw: unknown, refs: AgentReference[], asOf: string): AgentNativeGrant {
  const row = object(raw);
  closed(row, ['id', 'version', 'family', 'recorded_state', 'effective_state', 'state_sequence', 'state_at', 'effective_from', 'expires_at', 'evaluated_local_date', 'timezone', 'policy_references', 'account_ids', 'goal_ids', 'product_ids', 'payee_ids', 'single_cap_cents', 'lifetime_cap_cents', 'monthly_cap_cents', 'original_digest', 'terms_digest', 'chain_digest', 'reason_codes', 'authority', 'bank_authority']);
  byteBound(row, 32 * 1024);
  if (row.authority !== false || row.bank_authority !== false || row.version !== 1) throw new Error('原生授权显示不能作为执行权限');
  const id = uuid(row.id);
  if (!refs.some((ref) => ref.kind === 'NATIVE_GRANT' && ref.id === id) || refs.filter((ref) => ref.kind === 'NATIVE_GRANTS').length !== 1) throw new Error('原生授权缺少本轮对象与集合引用');
  const family = choice(row.family, families), state = choice(row.recorded_state, recorded), availability = choice(row.effective_state, effective), codes = reasons(row.reason_codes);
  if (availability === 'REVOKED' && (state !== 'REVOKED' || !codes.includes('REVOKED')) || availability === 'PAUSED' && (state !== 'PAUSED' || !codes.includes('PAUSED')) || ['EXPIRED', 'NOT_YET_EFFECTIVE', 'POLICY_CHANGED'].includes(availability) && !codes.includes(availability as GrantReason) || availability === 'CURRENT_DISPLAY_ONLY' && codes.length !== 0 || availability === 'UNAVAILABLE' && !codes.some((code) => ['POLICY_UNAVAILABLE', 'EVIDENCE_INVALID', 'SUBJECT_UNAVAILABLE', 'SESSION_EXPIRED_AT_EVENT', 'SESSION_REVOCATION_HISTORY_UNAVAILABLE'].includes(code))) throw new Error('原生授权有效状态缺少同源原因');
  const now = instant(asOf), from = instant(row.effective_from), end = instant(row.expires_at), at = instant(row.state_at);
  if (at.ns < from.ns || at.ns > now.ns || end.ns <= from.ns || end.ns - from.ns > 366n * 86400n * 1000000000n) throw new Error('原生授权时间边界不符');
  const timezone = text(row.timezone), day = text(row.evaluated_local_date);
  if (timezone.length > 128 || !/^\d{4}-\d{2}-\d{2}$/.test(day) || day !== localDate(asOf, timezone)) throw new Error('原生授权评估日期不符');
  const policies = list(row.policy_references, policyRef, 16); sorted(policies.map((ref) => ref.policy_id));
  const accounts = ids(row.account_ids, 16), goals = ids(row.goal_ids, 8), products = names(row.product_ids, 100), payees = names(row.payee_ids, 1);
  if (!policies.length || !accounts.length || policies.some((ref) => ref.goal_id && !goals.includes(ref.goal_id))) throw new Error('原生授权范围不完整');
  const single = money(row.single_cap_cents), lifetime = money(row.lifetime_cap_cents), monthly = money(row.monthly_cap_cents);
  if (BigInt(single) === 0n || BigInt(lifetime) < BigInt(single) || BigInt(monthly) < BigInt(single) || BigInt(monthly) > BigInt(lifetime)) throw new Error('原生授权限额关系不符');
  if (family === 'SINGLE_GOAL' || family === 'JOINT_GOALS') {
    if (products.length || payees.length || policies.length !== goals.length || new Set(policies.map((ref) => ref.goal_id)).size !== goals.length || (family === 'SINGLE_GOAL' ? goals.length !== 1 : goals.length < 2) || policies.some((ref) => ref.template_name !== 'LongTermGoalPolicy' || !ref.goal_id)) throw new Error('原生目标授权范围不符');
  } else if (family === 'PERIODIC_PAYMENT') {
    if (policies.length !== 1 || accounts.length !== 1 || goals.length || products.length || payees.length !== 1 || policies.some((ref) => !['RecurringObligationPolicy', 'PeriodicTransferPolicy'].includes(ref.template_name) || ref.goal_id)) throw new Error('原生周期授权范围不符');
  } else if (!products.length || payees.length || !policies.some((ref) => ref.template_name === 'AssetAuthorizationPolicy') || policies.some((ref) => ref.template_name !== 'AssetAuthorizationPolicy' && (family !== 'MATURITY_REINVEST' || ref.template_name !== 'RecoveryPolicy'))) throw new Error('原生资产授权范围不符');
  if (codes.includes('CAPACITY') || codes.includes('SCHEMA_UNAVAILABLE') || codes.includes('EXPIRED') && now.ns < end.ns || codes.includes('PAUSED') && state !== 'PAUSED' || codes.includes('REVOKED') && state !== 'REVOKED' || codes.includes('NOT_YET_EFFECTIVE') && now.ns >= from.ns) throw new Error('原生授权原因与事实不符');
  const expected = state === 'REVOKED' ? 'REVOKED' : now.ns >= end.ns ? 'EXPIRED' : state === 'PAUSED' ? 'PAUSED' : now.ns < from.ns ? 'NOT_YET_EFFECTIVE' : codes.includes('POLICY_CHANGED') ? 'POLICY_CHANGED' : codes.some((code) => ['POLICY_UNAVAILABLE', 'EVIDENCE_INVALID', 'SUBJECT_UNAVAILABLE', 'SESSION_EXPIRED_AT_EVENT', 'SESSION_REVOCATION_HISTORY_UNAVAILABLE'].includes(code)) ? 'UNAVAILABLE' : 'CURRENT_DISPLAY_ONLY';
  if (availability !== expected) throw new Error('原生授权有效状态不符');
  return { id, version: 1, family, recorded_state: state, effective_state: availability, state_sequence: integer(row.state_sequence, 1, 256), state_at: at.value, effective_from: from.value, expires_at: end.value, evaluated_local_date: day, timezone, policy_references: policies, account_ids: accounts, goal_ids: goals, product_ids: products, payee_ids: payees, single_cap_cents: single, lifetime_cap_cents: lifetime, monthly_cap_cents: monthly, original_digest: hash(row.original_digest), terms_digest: hash(row.terms_digest), chain_digest: hash(row.chain_digest), reason_codes: codes, authority: false, bank_authority: false };
}

export function parseNativeGrantCollection(raw: unknown, refs: AgentReference[], asOf: string): AgentNativeGrantCollection {
  const row = object(raw); closed(row, ['protocol', 'status', 'count', 'items', 'reason_codes', 'collection_digest', 'verification_scope', 'session_verification', 'authority', 'bank_authority']); byteBound(row, 512 * 1024);
  if (row.protocol !== protocol || row.authority !== false || row.bank_authority !== false) throw new Error('原生授权集合协议或权限不符');
  const digest = hash(row.collection_digest);
  const collectionRefs = refs.filter((ref) => ref.kind === 'NATIVE_GRANTS');
  if (collectionRefs.length !== 1 || collectionRefs[0]!.digest !== digest) throw new Error('原生授权集合缺少唯一完整引用');
  const status = choice(row.status, ['COMPLETE', 'UNAVAILABLE'] as const), codes = reasons(row.reason_codes);
  if (status === 'UNAVAILABLE') {
    if ('count' in row || !Array.isArray(row.items) || row.items.length || !codes.length || row.verification_scope !== 'NOT_VERIFIED' || row.session_verification !== 'NOT_VERIFIED') throw new Error('未知原生授权数量不能按零条显示');
    return { protocol, status, items: [], reason_codes: codes, collection_digest: digest, verification_scope: 'NOT_VERIFIED', session_verification: 'NOT_VERIFIED', authority: false, bank_authority: false };
  }
  const items = list(row.items, (item) => parseNativeGrant(item, refs, asOf), 100); sorted(items.map((item) => item.id));
  const count = integer(row.count, 0, 100), session = choice(row.session_verification, sessionScopes);
  if (count !== items.length || codes.length || row.verification_scope !== verification || items.some((item) => item.reason_codes.includes('SESSION_REVOCATION_HISTORY_UNAVAILABLE')) && session !== 'HISTORY_INCOMPLETE') throw new Error('原生授权完整性或验证范围不符');
  return { protocol, status, count, items, reason_codes: [], collection_digest: digest, verification_scope: verification, session_verification: session, authority: false, bank_authority: false };
}
