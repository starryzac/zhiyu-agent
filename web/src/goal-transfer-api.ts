import { Client, states } from './api';
import type { Dashboard, OperationState } from './api';
import { cents } from './money';
import { parseConfiguration, templateID } from './template-schema';
import type { TemplateConfiguration } from './template-schema';
import { parseForecastResult } from './template-api';
import type { ForecastResult, TemplateScope } from './template-api';

export interface GoalTransferRequest { policy_version_id: string; source_goal_id: string; target_goal_id: string; amount_cents: string; timezone: 'UTC' | 'Asia/Shanghai' }
export interface GoalTransferCommand { preview_id: string; reviewed_hash: string; release_source: true; receive_target: true }
interface GoalSide { id: string; account_id: string; policy_id: string; version_id: string; owned_cents: string; cash_owned_cents: string; releaseable_cash_cents: string; month_contributed_cents: string }
export interface GoalTransferPreview {
  id: string; scope: TemplateScope; created_at: string; expires_at: string; reviewed_hash: string; effect_hash: string;
  request: GoalTransferRequest; source: GoalSide; target: GoalSide; policy_id: string; policy_version: number;
  already_used_and_held_cents: string; single_action_cap_cents: string; total_cap_cents: string;
  lot_uses: { source_kind: 'INCOME' | 'PRINCIPAL_RETURN'; source_id: string; position_id?: string; amount_cents: string }[];
  protected_policies: { policy_id: string; protected_before_cents: string; protected_after_cents: string }[];
  forecast_before: ForecastResult; forecast_after: ForecastResult; bank_authority: false;
  original: Record<string, unknown>;
}
export interface GoalTransferOperation { id: string; group_id: string; child_number: 1; kind: 'TRANSFER_GOAL'; state: OperationState; amount_cents: string; bank_key: string; bank_observed_status?: string; processing_health: string; receipt_id?: string; version: number; created_at: string; updated_at: string }
export interface GoalTransferLocator { environment: string; user_id: string; key: string; command: GoalTransferCommand; preview: GoalTransferPreview }

function obj(value: unknown): Record<string, unknown> { if (!value || typeof value !== 'object' || Array.isArray(value)) throw new Error('目标转移原件结构不完整'); return value as Record<string, unknown>; }
function closed(value: Record<string, unknown>, keys: string[]) { if (Object.keys(value).some((key) => !keys.includes(key))) throw new Error('目标转移原件包含范围外字段'); }
function text(value: unknown, max = 256): string { if (typeof value !== 'string' || !value || value.length > max) throw new Error('目标转移文字字段不完整'); return value; }
function instant(value: unknown): string { const result = text(value, 64); if (!Number.isFinite(Date.parse(result))) throw new Error('目标转移时间不完整'); return result; }
function hash(value: unknown): string { const result = text(value, 64); if (!/^[a-f0-9]{64}$/.test(result)) throw new Error('目标转移原件引用不完整'); return result; }
function integer(value: unknown, min = 1): number { if (!Number.isSafeInteger(value) || (value as number) < min) throw new Error('目标转移版本不完整'); return value as number; }
function amount(value: unknown, positive = false): string { const result = cents(value); if (BigInt(result) < (positive ? 1n : 0n)) throw new Error('目标转移金额范围不符'); return result; }
function list<T>(value: unknown, parse: (raw: unknown) => T, max = 128): T[] { if (!Array.isArray(value) || value.length > max) throw new Error('目标转移依据超出完整范围'); return value.map(parse); }
function owner(value: unknown): TemplateScope { const v = obj(value); closed(v, ['environment_id', 'user_id']); return { environment_id: templateID(v.environment_id), user_id: templateID(v.user_id) }; }
function sameOwner(scope: TemplateScope, raw: unknown) { const other = owner(raw); if (scope.environment_id !== other.environment_id || scope.user_id !== other.user_id) throw new Error('目标转移依据跨越本人环境'); }
function sum(values: string[]) { return values.reduce((total, value) => total + BigInt(value), 0n); }
function unique(values: string[]) { if (new Set(values).size !== values.length) throw new Error('目标转移原件来源重复'); }
function financialTree(value: unknown): void {
  if (Array.isArray(value)) { value.forEach(financialTree); return; }
  if (!value || typeof value !== 'object') return;
  for (const [key, child] of Object.entries(value)) {
    if ((key === 'bank_authority' || key === 'creates_income') && child !== false) throw new Error('候选不能创建资金权限或新收入');
    if ((key.endsWith('_cents') || ['Amount', 'AlreadyUsedAndHeld'].includes(key)) && child != null && typeof child !== 'object') cents(child);
    financialTree(child);
  }
}
function version(raw: unknown, scope: TemplateScope, name: 'LongTermGoalPolicy' | 'CrossGoalReallocationPolicy') {
  const v = obj(raw), c = obj(v.compiled); sameOwner(scope, v.scope);
  if (c.protocol !== 'policy-templates-go-v1' || c.template_name !== name || v.current !== true || v.confirmation_verified !== true || v.state !== 'ACTIVE' || hash(v.confirmed_configuration_hash) !== hash(c.configuration_hash)) throw new Error('目标转移缺少当前本人规则原件');
  instant(v.confirmed_at);
  return { policy_id: templateID(v.policy_id), version_id: templateID(v.version_id), version: integer(v.version), configuration: parseConfiguration(name, c.configuration) };
}
function goal(raw: unknown, scope: TemplateScope): GoalSide {
  const g = obj(raw), v = version(g.goal_version, scope, 'LongTermGoalPolicy');
  const result = { id: templateID(g.id), account_id: templateID(g.account_id), policy_id: templateID(g.policy_id), version_id: templateID(g.version_id), owned_cents: amount(g.owned_cents), cash_owned_cents: amount(g.cash_owned_cents), releaseable_cash_cents: amount(g.releaseable_cash_cents), month_contributed_cents: amount(g.month_contributed_cents) };
  if (g.verified !== true || result.policy_id !== v.policy_id || result.version_id !== v.version_id || BigInt(result.releaseable_cash_cents) > BigInt(result.cash_owned_cents) || BigInt(result.cash_owned_cents) > BigInt(result.owned_cents)) throw new Error('目标当前归属与可释放依据不符');
  return result;
}
function request(raw: unknown): GoalTransferRequest {
  const r = obj(raw); closed(r, ['policy_version_id', 'source_goal_id', 'target_goal_id', 'amount_cents', 'timezone']);
  if (r.timezone !== 'UTC' && r.timezone !== 'Asia/Shanghai') throw new Error('目标转移自然时区不受支持');
  return { policy_version_id: templateID(r.policy_version_id), source_goal_id: templateID(r.source_goal_id), target_goal_id: templateID(r.target_goal_id), amount_cents: amount(r.amount_cents, true), timezone: r.timezone };
}
export function parseGoalTransferPreview(raw: unknown, client: Client, dashboard?: Dashboard): GoalTransferPreview {
  financialTree(raw); const p = obj(raw);
  closed(p, ['id', 'scope', 'session_id', 'kind', 'effect_hash', 'dependencies', 'source_hash', 'inventory_hash', 'created_at', 'expires_at', 'bank_authority', 'protocol', 'timezone', 'request', 'paired_input', 'paired_effect', 'bank_effect', 'lot_uses', 'forecast_input', 'forecast_before', 'forecast_after', 'reviewed_hash']);
  if (p.protocol !== 'native-paired-goal-transfer-v1' || p.kind !== 'TRANSFER_GOAL' || p.bank_authority !== false || !client.session) throw new Error('目标转移审阅协议不受支持');
  const scope = owner(p.scope); if (scope.user_id !== client.session.user_id) throw new Error('目标转移不属于当前会话');
  const id = templateID(p.id), created = instant(p.created_at), expires = instant(p.expires_at), r = request(p.request); templateID(p.session_id);
  if (Date.parse(expires) <= Date.parse(created) || Date.parse(expires) - Date.parse(created) > 120000 || r.timezone !== p.timezone) throw new Error('目标转移审阅期限不完整');
  const dependency = obj(p.dependencies), dependencyKeys = ['funds_version', 'grant_version', 'policy_version', 'product_terms_version', 'product_availability_version', 'source_evidence_version', 'writer_generation', 'control_version']; closed(dependency, dependencyKeys);
  for (const key of dependencyKeys) integer(dependency[key], key === 'grant_version' ? 0 : 1);
  const input = obj(p.paired_input), effect = obj(p.paired_effect), bank = obj(p.bank_effect), forecast = obj(p.forecast_input), facts = obj(forecast.facts);
  const rule = version(input.Policy, scope, 'CrossGoalReallocationPolicy'), config = rule.configuration;
  if (!pairedRule(config)) throw new Error('现金范围规则不能代替目标配对范围');
  const source = goal(input.Source, scope), target = goal(input.Target, scope), used = amount(input.AlreadyUsedAndHeld);
  if (input.UsageVerified !== true || instant(input.Now) !== created || input.Timezone !== r.timezone || input.Amount !== r.amount_cents || source.id === target.id || source.account_id === target.account_id || source.id !== r.source_goal_id || target.id !== r.target_goal_id || rule.version_id !== r.policy_version_id || !config.source_goal_ids.includes(source.id) || !config.target_goal_ids.includes(target.id) || BigInt(r.amount_cents) > BigInt(source.releaseable_cash_cents) || BigInt(r.amount_cents) > BigInt(config.single_action_cap_cents) || BigInt(r.amount_cents) + BigInt(used) > BigInt(config.total_cap_cents)) throw new Error('目标转移金额、双向范围或当前来源不符');
  const targetConfig = version(obj(input.Target).goal_version, scope, 'LongTermGoalPolicy').configuration;
  if (targetConfig.type !== 'long_term_goal' || BigInt(target.owned_cents) + BigInt(r.amount_cents) > BigInt(targetConfig.target_cents)) throw new Error('接收金额超过当前目标空间');
  sameOwner(scope, effect.scope); sameOwner(scope, forecast.scope); sameOwner(scope, facts.scope);
  if (effect.protocol !== 'paired-goal-transfer-go-v1' || effect.bank_authority !== false || effect.creates_income !== false || effect.policy_id !== rule.policy_id || effect.policy_version_id !== rule.version_id || effect.source_goal_id !== source.id || effect.target_goal_id !== target.id || effect.source_account_id !== source.account_id || effect.target_account_id !== target.account_id || effect.source_goal_version_id !== source.version_id || effect.target_goal_version_id !== target.version_id || effect.amount_cents !== r.amount_cents || hash(effect.dependency_hash) !== hash(input.DependencyHash)) throw new Error('配对经济效果与完整审阅不一致');
  hash(effect.effect_hash); hash(p.source_hash); hash(p.inventory_hash); hash(p.effect_hash); hash(p.reviewed_hash);
  if (forecast.complete !== true || facts.complete !== true || forecast.horizon_days !== 365 || forecast.as_of !== created || forecast.timezone !== r.timezone || forecast.inventory_hash !== p.inventory_hash || facts.source_hash !== p.source_hash) throw new Error('当前完整年度保护依据不符');
  const before = parseForecastResult(p.forecast_before), after = parseForecastResult(p.forecast_after);
  if ([before, after].some((f) => f.as_of !== created || f.timezone !== r.timezone || f.horizon_days !== 365) || after.maximum_deficit_cents !== '0') throw new Error('目标转移后年度保护尚未满足');
  const uses = list<GoalTransferPreview['lot_uses'][number]>(p.lot_uses, (raw) => { const v = obj(raw); closed(v, ['source_kind', 'source_id', 'position_id', 'amount_cents']); if (v.source_kind !== 'INCOME' && v.source_kind !== 'PRINCIPAL_RETURN') throw new Error('目标转移包含未证明的新来源'); const position = v.source_kind === 'PRINCIPAL_RETURN' ? text(v.position_id) : undefined; if (v.source_kind === 'INCOME' && v.position_id != null) throw new Error('原收入不能携带本金位置'); return { source_kind: v.source_kind, source_id: v.source_kind === 'INCOME' ? templateID(v.source_id) : text(v.source_id), position_id: position, amount_cents: amount(v.amount_cents, true) }; });
  unique(uses.map((v) => `${v.source_kind}:${v.source_id}`)); if (!uses.length || sum(uses.map((v) => v.amount_cents)) !== BigInt(r.amount_cents)) throw new Error('目标转移真实 lot 用途不守恒');
  closed(bank, ['kind', 'business_key', 'amount_cents', 'cash_uses', 'origin_uses', 'return_uses', 'destination_account_id', 'source_goal_id', 'destination_goal_id', 'product', 'position_id', 'position_opening_hash', 'return_account_id', 'principal_available_by', 'planned_redeem_at', 'fee_cents', 'loss_cents', 'net_cents', 'quote_id', 'liability', 'latest_arrival_at']);
  if (bank.kind !== 'TRANSFER_GOAL' || bank.business_key !== `paired-goal:${id}` || bank.amount_cents !== r.amount_cents || bank.source_goal_id !== source.id || bank.destination_goal_id !== target.id || bank.destination_account_id !== target.account_id || bank.fee_cents !== '0' || bank.loss_cents !== '0' || bank.net_cents !== '0' || bank.product !== null || bank.liability !== null || ['position_id', 'position_opening_hash', 'return_account_id', 'quote_id'].some((key) => bank[key] !== '') || ['principal_available_by', 'planned_redeem_at'].some((key) => bank[key] !== '0001-01-01T00:00:00Z') || bank.latest_arrival_at !== expires) throw new Error('目标转移包含范围外资产或经济效果');
  const cash = list(bank.cash_uses, (raw) => { const v = obj(raw); closed(v, ['account_id', 'amount_cents']); return v; }, 1);
  const origins = list(bank.origin_uses, (raw) => { const v = obj(raw); closed(v, ['origin_id', 'account_id', 'amount_cents', 'bucket']); if (v.bucket !== 'ASSIGNED_GOAL' || v.account_id !== source.account_id) throw new Error('目标转移不能重用未归属收入资格'); return `${templateID(v.origin_id)}:${amount(v.amount_cents, true)}`; });
  const returns = list(bank.return_uses, (raw) => { const v = obj(raw); closed(v, ['operation_key', 'position_id', 'account_id', 'amount_cents']); if (v.account_id !== source.account_id) throw new Error('本金原位置不属于来源账户'); return `${text(v.operation_key)}:${text(v.position_id)}:${amount(v.amount_cents, true)}`; });
  if (cash.length !== 1 || cash[0]!.account_id !== source.account_id || cash[0]!.amount_cents !== r.amount_cents || origins.sort().join('|') !== uses.filter((u) => u.source_kind === 'INCOME').map((u) => `${u.source_id}:${u.amount_cents}`).sort().join('|') || returns.sort().join('|') !== uses.filter((u) => u.source_kind === 'PRINCIPAL_RETURN').map((u) => `${u.source_id}:${u.position_id}:${u.amount_cents}`).sort().join('|')) throw new Error('原 bank effect 与真实来源用途不一致');
  const protectedPolicies = list(input.ProtectedReferences, (raw) => { const v = obj(raw); if (v.current !== true || v.confirmation_verified !== true || v.impact_verified !== true || BigInt(amount(v.protected_after_cents)) < BigInt(amount(v.protected_before_cents))) throw new Error('被保护规则的完整引用尚未核实'); templateID(v.version_id); hash(v.configuration_hash); return { policy_id: templateID(v.policy_id), protected_before_cents: amount(v.protected_before_cents), protected_after_cents: amount(v.protected_after_cents) }; }, 100);
  unique(protectedPolicies.map((v) => v.policy_id)); if ((config.must_not_reduce_policy_ids ?? []).some((id) => !protectedPolicies.some((v) => v.policy_id === id))) throw new Error('被保护规则依据缺失');
  if (dashboard && (dashboard.environment !== client.session.environment || [source, target].some((side) => !dashboard.goals.some((g) => g.id === side.id && g.account_id === side.account_id)))) throw new Error('原预览引用当前范围外目标');
  return { id, scope, created_at: created, expires_at: expires, reviewed_hash: hash(p.reviewed_hash), effect_hash: hash(p.effect_hash), request: r, source, target, policy_id: rule.policy_id, policy_version: rule.version, already_used_and_held_cents: used, single_action_cap_cents: config.single_action_cap_cents, total_cap_cents: config.total_cap_cents, lot_uses: uses, protected_policies: protectedPolicies, forecast_before: before, forecast_after: after, bank_authority: false, original: p };
}

export function parseGoalTransferOperation(raw: unknown, original: GoalTransferLocator, prior?: GoalTransferOperation): GoalTransferOperation {
  const o = obj(raw); closed(o, ['id', 'group_id', 'child_number', 'kind', 'state', 'amount_cents', 'bank_key', 'bank_observed_status', 'processing_health', 'receipt_id', 'version', 'created_at', 'updated_at']);
  if (o.kind !== 'TRANSFER_GOAL' || o.child_number !== 1 || !(states as readonly unknown[]).includes(o.state)) throw new Error('目标转移原操作类型或状态不完整');
  const result: GoalTransferOperation = { id: templateID(o.id), group_id: templateID(o.group_id), child_number: 1, kind: 'TRANSFER_GOAL', state: o.state as OperationState, amount_cents: amount(o.amount_cents, true), bank_key: templateID(o.bank_key), bank_observed_status: o.bank_observed_status == null ? undefined : text(o.bank_observed_status), processing_health: typeof o.processing_health === 'string' ? o.processing_health : text(o.processing_health), receipt_id: o.receipt_id == null ? undefined : templateID(o.receipt_id), version: integer(o.version), created_at: instant(o.created_at), updated_at: instant(o.updated_at) };
  if (result.group_id !== original.command.preview_id || result.amount_cents !== original.preview.request.amount_cents || result.bank_key !== result.id || (result.state === 'SETTLED') !== !!result.receipt_id || Date.parse(result.updated_at) < Date.parse(result.created_at)) throw new Error('原目标转移结果与审阅不一致');
  if (prior && (result.id !== prior.id || result.bank_key !== prior.bank_key || result.created_at !== prior.created_at || result.version < prior.version || (result.version === prior.version && JSON.stringify(result) !== JSON.stringify(prior)) || (goalTransferTerminal(prior) && (result.state !== prior.state || result.receipt_id !== prior.receipt_id)))) throw new Error('原目标转移结果发生回退或换键');
  return result;
}
export function goalTransferTerminal(operation: GoalTransferOperation): boolean { return ['SETTLED', 'REJECTED', 'CANCELLED'].includes(operation.state); }
export class GoalTransferClient {
  constructor(readonly client: Client) {}
  async preview(body: GoalTransferRequest, dashboard: Dashboard) { const value = parseGoalTransferPreview(await this.client.request('/goal-transfer-previews', { method: 'POST', body: JSON.stringify(request(body)) }), this.client, dashboard); if (JSON.stringify(value.request) !== JSON.stringify(request(body))) throw new Error('服务端返回另一份目标转移审阅'); return value; }
  async original(id: string, signal?: AbortSignal) { return parseGoalTransferPreview(await this.client.request(`/goal-transfer-previews/${encodeURIComponent(templateID(id))}`, { signal }), this.client); }
  async accept(original: GoalTransferLocator) { validateLocator(this.client, original); return parseGoalTransferOperation(await this.client.request('/goal-transfers', { method: 'POST', headers: { 'Idempotency-Key': original.key }, body: JSON.stringify(original.command) }), original); }
  async byKey(original: GoalTransferLocator, signal?: AbortSignal) { return parseGoalTransferOperation(await this.client.request(`/goal-transfer-commands/${encodeURIComponent(original.key)}`, { signal }), original); }
  async operation(id: string, original: GoalTransferLocator, signal?: AbortSignal) { return parseGoalTransferOperation(await this.client.request(`/goal-transfers/${encodeURIComponent(templateID(id))}`, { signal }), original); }
}
function storageKey(client: Client) { if (!client.session) throw new Error('请先登录当前本人环境'); return `zhiyu-go:goal-transfer-originals:v1:${client.session.environment}:${client.session.user_id}`; }
function validateLocator(client: Client, original: GoalTransferLocator): void {
  const v = obj(original); closed(v, ['environment', 'user_id', 'key', 'command', 'preview']); const c = obj(original.command); closed(c, ['preview_id', 'reviewed_hash', 'release_source', 'receive_target']);
  if (original.environment !== client.session?.environment || original.user_id !== client.session.user_id || templateID(original.key) !== original.key || c.release_source !== true || c.receive_target !== true) throw new Error('保存的原目标转移不属于当前本人环境');
  const preview = parseGoalTransferPreview(original.preview.original, client);
  if (JSON.stringify(preview) !== JSON.stringify(original.preview) || c.preview_id !== preview.id || c.reviewed_hash !== preview.reviewed_hash) throw new Error('保存的原目标转移载荷与完整审阅不一致');
}
export function loadGoalTransferLocators(client: Client): GoalTransferLocator[] {
  const raw = localStorage.getItem(storageKey(client)); if (!raw) return [];
  try { const records = list(JSON.parse(raw), (value) => { const v = value as GoalTransferLocator; validateLocator(client, v); return v; }, 16); unique(records.map((v) => v.key)); return records; }
  catch { throw new Error('保存的原目标转移请求不完整，已保留原资料并停止新提交'); }
}
export function saveGoalTransferLocator(client: Client, original: GoalTransferLocator): GoalTransferLocator[] {
  validateLocator(client, original); const records = loadGoalTransferLocators(client);
  if (records.some((v) => v.key === original.key) || records.length >= 16) throw new Error('原目标转移键已保存或本机历史容量已满，请保留原件');
  const result = [...records, original], raw = JSON.stringify(result); localStorage.setItem(storageKey(client), raw);
  if (localStorage.getItem(storageKey(client)) !== raw) throw new Error('无法完整保存原目标转移，尚未发送'); return result;
}

export function pairedRule(config: TemplateConfiguration): config is Extract<TemplateConfiguration, { type: 'cross_goal_reallocation' }> & { target_goal_ids: string[] } { return config.type === 'cross_goal_reallocation' && config.scope_version === 'GOAL_TRANSFER_V1' && config.destination_scope === 'GOAL' && config.enabled && Array.isArray(config.target_goal_ids) && config.target_goal_ids.length > 0; }
