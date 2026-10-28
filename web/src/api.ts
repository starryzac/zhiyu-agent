import { cents } from './money';

export interface Session { token: string; csrf_token: string; user_id: string; environment: string }
export interface Scope { environment_id: string; user_id: string; goal_id: string; source_account_id: string; destination_account_id: string }
export interface Policy { id: string; version: number; scope: Scope; max_amount: string; status: string; valid_until: string }
export interface Grant { id: string; policy_id: string; scope: Scope; max_amount: string; status: string; valid_until: string }
export interface Candidate { id: string; policy_id: string; amount: string; status: string; max_safe: string; valid_until: string; effect_hash: string }
export const states = ['QUEUED', 'SUBMITTING', 'PENDING_SETTLEMENT', 'UNKNOWN', 'RECONCILING', 'SETTLED', 'REJECTED', 'CANCELLED'] as const;
export type OperationState = typeof states[number];
export interface Operation { id: string; state: OperationState; amount_cents: string; plan_id: string; bank_key: string; bank_observed_status?: string; processing_health?: string; receipt_id?: string; created_at: string; updated_at: string; version: number }
export type NativeRuleSummary = { status: 'CURRENT_LOCAL'; current_policy_count: number; active_policy_count: number } | { status: 'MISSING' | 'UNAVAILABLE' };
export interface Dashboard {
  environment: string; as_of: string;
  accounts: { id: string; name: string; balance_cents: string; goal_owned_cents: string }[];
  goals: { id: string; name: string; account_id: string; target_cents: string; assigned_cents: string }[];
  policies: Policy[]; grants: Grant[]; operations: Operation[];
  native?: NativeRuleSummary;
  projection: { source_sequence: number; applied_sequence: number; projected_at?: string; status: 'CURRENT' | 'DELAYED' | 'INVALID' | 'MISSING' | 'UNAVAILABLE' };
}
export interface Activity { id: string; kind: string; aggregate_id: string; aggregate_version: number; created_at: string }
export interface ActivityPage { items: Activity[]; next_cursor?: string; as_of: string; total: number; returned: number; has_more: boolean; verification_scope: string }
export interface CommandBody { plan_id: string; grant_id?: string; mode: 'STANDING' | 'ONCE' }
export interface GoalConfiguration { name: string; account_id: string; target_cents: string; expected_version: number }
export interface GoalDetail { id: string; name: string; account_id: string; target_cents: string; assigned_cents: string; version: number }
function parseGoal(value: unknown): GoalDetail {
  const item = object(value);
  const result = { id: text(item.id), name: text(item.name), account_id: text(item.account_id), target_cents: cents(item.target_cents), assigned_cents: cents(item.assigned_cents), version: integer(item.version) };
  if (result.version < 1 || BigInt(result.target_cents) < BigInt(result.assigned_cents)) throw new Error('目标当前版本或归属金额不符');
  return result;
}
export class ApiError extends Error {
  constructor(readonly status: number, readonly code: string, message: string) { super(message); }
}

function object(value: unknown): Record<string, unknown> {
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw new Error('服务端返回了不支持的数据结构');
  return value as Record<string, unknown>;
}
function text(value: unknown): string {
  if (typeof value !== 'string') throw new Error('服务端字段类型不符');
  return value;
}
function integer(value: unknown): number {
  if (!Number.isSafeInteger(value)) throw new Error('服务端版本字段不符');
  return value as number;
}
function list<T>(value: unknown, parse: (item: unknown) => T): T[] {
  if (!Array.isArray(value)) throw new Error('服务端列表字段不符');
  return value.map(parse);
}
function nativeRuleSummary(value: unknown): NativeRuleSummary {
  if (value == null) return { status: 'MISSING' };
  const item = object(value), status = text(item.status);
  if (status === 'UNAVAILABLE') return { status };
  if (status !== 'CURRENT_LOCAL') throw new Error('无法识别模板规则的读取状态');
  const current = integer(item.current_policy_count), active = integer(item.active_policy_count);
  if (current < 0 || active < 0 || active > current) throw new Error('模板规则数量不符');
  return { status, current_policy_count: current, active_policy_count: active };
}
function scope(value: unknown): Scope {
  const item = object(value);
  return { environment_id: text(item.environment_id), user_id: text(item.user_id), goal_id: text(item.goal_id), source_account_id: text(item.source_account_id), destination_account_id: text(item.destination_account_id) };
}
function policy(value: unknown): Policy {
  const item = object(value);
  return { id: text(item.id), version: integer(item.version), scope: scope(item.scope), max_amount: cents(item.max_amount), status: text(item.status), valid_until: text(item.valid_until) };
}
function grant(value: unknown): Grant {
  const item = object(value);
  return { id: text(item.id), policy_id: text(item.policy_id), scope: scope(item.scope), max_amount: cents(item.max_amount), status: text(item.status), valid_until: text(item.valid_until) };
}
export function parseOperation(value: unknown): Operation {
  const item = object(value);
  const state = text(item.state);
  if (!(states as readonly string[]).includes(state)) throw new Error('无法识别这笔操作的状态，请继续核对原操作');
  if (state === 'SETTLED' && (typeof item.receipt_id !== 'string' || !item.receipt_id)) throw new Error('结清操作缺少回执引用，请继续核对原操作');
  return { id: text(item.id), state: state as OperationState, amount_cents: cents(item.amount_cents), plan_id: text(item.plan_id), bank_key: text(item.bank_key),
    bank_observed_status: item.bank_observed_status == null ? undefined : text(item.bank_observed_status),
    processing_health: item.processing_health == null ? undefined : text(item.processing_health),
    receipt_id: item.receipt_id == null ? undefined : text(item.receipt_id), created_at: text(item.created_at), updated_at: text(item.updated_at), version: integer(item.version) };
}
export function terminal(operation: Operation): boolean { return ['SETTLED', 'REJECTED', 'CANCELLED'].includes(operation.state); }
export const stateText: Record<OperationState, string> = { QUEUED: '已受理，等待处理', SUBMITTING: '正在提交银行', PENDING_SETTLEMENT: '银行已受理，等待结清', UNKNOWN: '结果待核实', RECONCILING: '正在对账', SETTLED: '已结清', REJECTED: '已拒绝', CANCELLED: '已取消' };

export class Client {
  constructor(readonly session: Session | null, readonly base = '/api/v2') {}
  async request(path: string, init: RequestInit = {}): Promise<unknown> {
    const method = init.method ?? 'GET';
    const headers = new Headers(init.headers);
    headers.set('Accept', 'application/json');
    if (init.body != null) headers.set('Content-Type', 'application/json');
    if (this.session) {
      headers.set('Authorization', `Bearer ${this.session.token}`);
      if (method !== 'GET') headers.set('X-CSRF-Token', this.session.csrf_token);
    }
    const response = await fetch(this.base + path, { ...init, headers, signal: init.signal ?? AbortSignal.timeout(15000), cache: 'no-store', credentials: 'omit' });
    if (response.status === 204) return null;
    let body: unknown;
    try { body = await response.json(); } catch { throw new ApiError(response.status, 'INVALID_RESPONSE', '服务端暂未返回可识别的数据，请保留原操作并稍后核对。'); }
    if (!response.ok) {
      const envelope = object(body);
      const error = typeof envelope.error === 'object' && envelope.error ? object(envelope.error) : envelope;
      throw new ApiError(response.status, typeof error.code === 'string' ? error.code : 'HTTP_ERROR', typeof error.message === 'string' ? error.message : `请求未完成（${response.status}）`);
    }
    return body;
  }
  async login(secret: string): Promise<Session> {
    const value = object(await this.request('/session', { method: 'POST', body: JSON.stringify({ secret }) }));
    return { token: text(value.token), csrf_token: text(value.csrf_token), user_id: text(value.user_id), environment: text(value.environment) };
  }
  async dashboard(signal?: AbortSignal): Promise<Dashboard> {
    const item = object(await this.request('/dashboard', { signal }));
    const environment = text(item.environment);
    if (environment !== this.session?.environment) throw new Error('当前环境与登录会话不一致');
    const projected = item.projection == null ? { source_sequence: 0, applied_sequence: 0, status: 'UNAVAILABLE' } : object(item.projection);
    const projectionStatus = text(projected.status);
    if (!['CURRENT', 'DELAYED', 'INVALID', 'MISSING', 'UNAVAILABLE'].includes(projectionStatus)) throw new Error('无法识别活动摘要的读取状态');
    return { environment, as_of: text(item.as_of), projection: { source_sequence: integer(projected.source_sequence), applied_sequence: integer(projected.applied_sequence), status: projectionStatus as Dashboard['projection']['status'], projected_at: projected.projected_at == null ? undefined : text(projected.projected_at) }, accounts: list(item.accounts, (raw) => { const row = object(raw); return { id: text(row.id), name: text(row.name), balance_cents: cents(row.balance_cents), goal_owned_cents: cents(row.goal_owned_cents) }; }),
      goals: list(item.goals, (raw) => { const row = object(raw); return { id: text(row.id), name: text(row.name), account_id: text(row.account_id), target_cents: cents(row.target_cents), assigned_cents: cents(row.assigned_cents) }; }),
      policies: list(item.policies, policy), grants: list(item.grants, grant), operations: list(item.operations, parseOperation), native: nativeRuleSummary(item.native) };
  }
  async activities(cursor = '', signal?: AbortSignal): Promise<ActivityPage> {
    const item = object(await this.request(`/activities?limit=20${cursor ? `&cursor=${encodeURIComponent(cursor)}` : ''}`, { signal }));
    if (typeof item.has_more !== 'boolean') throw new Error('活动分页状态不符');
    const items = list(item.items, (raw) => { const row = object(raw); return { id: text(row.id), kind: text(row.kind), aggregate_id: text(row.aggregate_id), aggregate_version: integer(row.aggregate_version), created_at: text(row.created_at) }; });
    const returned = integer(item.returned), total = integer(item.total);
    const next = item.next_cursor == null ? undefined : text(item.next_cursor);
    if (items.length > 20 || returned !== items.length || total < returned || (item.has_more && !next)) throw new Error('活动分页边界不符');
    return { items, returned, total, has_more: item.has_more, next_cursor: next, as_of: text(item.as_of), verification_scope: text(item.verification_scope) };
  }
  async createPolicy(goal_id: string, max_amount: string): Promise<Policy> { return policy(await this.request('/policies', { method: 'POST', body: JSON.stringify({ goal_id, max_amount }) })); }
  async goal(id: string): Promise<GoalDetail> { return parseGoal(await this.request(`/goals/${encodeURIComponent(id)}`)); }
  async configureGoal(key: string, body: GoalConfiguration, id?: string): Promise<GoalDetail> {
    return parseGoal(await this.request(`/goals${id ? `/${encodeURIComponent(id)}` : ''}`, { method: 'POST', headers: { 'Idempotency-Key': key }, body: JSON.stringify(body) }));
  }
  async rebuildProjection(): Promise<unknown> { return this.request('/projections/rebuild', { method: 'POST', body: '{}' }); }
  async createGrant(policy_id: string, max_amount: string): Promise<Grant> { return grant(await this.request('/grants', { method: 'POST', body: JSON.stringify({ policy_id, max_amount }) })); }
  async revoke(id: string): Promise<unknown> { return this.request(`/grants/${encodeURIComponent(id)}/revoke`, { method: 'POST', body: '{}' }); }
  async plan(policy_id: string): Promise<Candidate> {
    const item = object(await this.request('/plans', { method: 'POST', body: JSON.stringify({ policy_id }) }));
    return { id: text(item.id), policy_id: text(item.policy_id), amount: cents(item.amount), status: text(item.status), max_safe: cents(item.max_safe), valid_until: text(item.valid_until), effect_hash: text(item.effect_hash) };
  }
  async accept(key: string, body: CommandBody): Promise<Operation> { return parseOperation(await this.request('/operations', { method: 'POST', headers: { 'Idempotency-Key': key }, body: JSON.stringify(body) })); }
  async operation(id: string, signal?: AbortSignal): Promise<Operation> { return parseOperation(await this.request(`/operations/${encodeURIComponent(id)}`, { signal })); }
  async command(key: string, signal?: AbortSignal): Promise<Operation> { return parseOperation(await this.request(`/command-results/${encodeURIComponent(key)}`, { signal })); }
}
