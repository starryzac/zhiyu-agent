import { Client, states } from './api';
import { parseNativeGrant, parseNativeGrantCollection } from './agent-native-grants';
import type { AgentNativeGrant, AgentNativeGrantCollection } from './agent-native-grants';
import type { Dashboard, OperationState } from './api';
import { cents } from './money';
import { parseConfiguration, parseTemplateName } from './template-schema';
import type { TemplateConfiguration, TemplateName } from './template-schema';
import { parseForecastResult } from './template-api';
import type { CompiledTemplate, ForecastResult } from './template-api';

export interface AgentReference { kind: 'ACCOUNT' | 'GOAL' | 'POLICY' | 'GRANT' | 'OPERATION' | 'ACCOUNTS' | 'RULES' | 'NATIVE_CONTEXT' | 'NATIVE_POLICY' | 'NATIVE_VERSION' | 'NATIVE_PLAN' | 'NATIVE_OPERATION' | 'NATIVE_POSITION' | 'NATIVE_PAYEE' | 'NATIVE_QUESTION' | 'NATIVE_GRANT' | 'NATIVE_GRANTS'; id: string; digest: string }
export interface AgentNativeRule { policy_id: string; version_id: string; version: number; compiled: CompiledTemplate; state: string; effective_state: string; goal_id?: string }
export interface AgentNativeCandidate { mode: 'IF_USER_CONFIRMED'; compiled: CompiledTemplate; goal_id?: string; policy_id?: string; reference: AgentReference; state: string; reasons: string[]; amount_cents?: string; forecast?: ForecastResult; requires_user_confirmation: true; bank_authority: false }
export interface AgentJoint { mode: 'READ_ONLY_NOT_EXECUTABLE'; state: string; reasons: string[]; allocations: { goal_id: string; amount_cents: string; minimum_shortfall_cents: string }[]; bank_authority: false }
export interface AgentCandidate { template: 'SINGLE_GOAL'; goal_id: string; reference: AgentReference; requires_user_fields: true; bank_authority: false }
export interface AgentObservation {
  tool: string; as_of: string; summary: string; references: AgentReference[];
  accounts: { id: string; name: string; balance_cents: string; goal_owned_cents: string }[];
  goals: { id: string; name: string; target_cents: string; assigned_cents: string }[];
  operations: { id: string; state: OperationState; amount_cents: string; receipt_id?: string }[];
  native_grants?: AgentNativeGrantCollection; native_grant?: AgentNativeGrant; catalog?: { template_name: TemplateName; fields: string[] }[]; native_rules?: AgentNativeRule[]; forecast?: { state: string; result?: ForecastResult; reasons: string[] }; joint?: AgentJoint; object?: { kind: string; id: string; data: Record<string, unknown> }; objects?: { kind: string; id: string; data: Record<string, unknown> }[];
}
export interface AgentResult {
  mode: 'OFFLINE' | 'MODEL'; provider_status: 'NOT_RUN' | 'CALLED'; model_used: boolean; authority: false;
  observations: AgentObservation[]; references: AgentReference[]; candidate?: AgentCandidate;
  native_candidate?: AgentNativeCandidate;
  budget: { provider_calls: number; tool_calls: number; reserved_tokens: number; reserved_cost_micros: number };
  provider_usage?: { input_tokens: number; output_tokens: number; reported_calls: number };
}
export interface AgentStatus { mode: string; provider_status: string; provider_configured: boolean; authority: false }
export type OfflineTool = 'funds_summary' | 'current_rules' | 'goal_status' | 'operation_status' | 'policy_candidate' | 'template_catalog' | 'template_candidate' | 'native_rules' | 'native_grants' | 'forecast365' | 'joint_preview' | 'object_status' | 'original_objects';
const tools: readonly string[] = ['funds_summary', 'current_rules', 'goal_status', 'operation_status', 'policy_candidate', 'template_catalog', 'template_candidate', 'native_rules', 'native_grants', 'forecast365', 'joint_preview', 'object_status', 'original_objects'];
function object(raw: unknown): Record<string, unknown> { if (!raw || typeof raw !== 'object' || Array.isArray(raw)) throw new Error('助手响应结构无法核实'); return raw as Record<string, unknown>; }
function text(raw: unknown): string { if (typeof raw !== 'string') throw new Error('助手字段类型无法核实'); return raw; }
function integer(raw: unknown): number { if (!Number.isSafeInteger(raw) || (raw as number) < 0) throw new Error('助手预算无法核实'); return raw as number; }
function amount(raw: unknown): string { const value = cents(raw); if (BigInt(value) < 0n || BigInt(value) > 9000000000000000n) throw new Error('助手金额超出合同'); return value; }
function list<T>(raw: unknown, parse: (raw: unknown) => T, cap = 100): T[] { if (!Array.isArray(raw) || raw.length > cap) throw new Error('助手列表超出合同'); return raw.map(parse); }
function uuid(raw: unknown): string { const value = text(raw); if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/.test(value) || /^0{8}-0{4}-0{4}-0{4}-0{12}$/.test(value)) throw new Error('助手引用无法核实'); return value; }
function reference(raw: unknown): AgentReference {
  const item = object(raw); const kind = text(item.kind); const digest = text(item.digest);
  if (kind === 'NATIVE_GRANT' || kind === 'NATIVE_GRANTS') closed(item, ['kind', 'id', 'digest']);
  if (!['ACCOUNT', 'GOAL', 'POLICY', 'GRANT', 'OPERATION', 'ACCOUNTS', 'RULES', 'NATIVE_CONTEXT', 'NATIVE_POLICY', 'NATIVE_VERSION', 'NATIVE_PLAN', 'NATIVE_OPERATION', 'NATIVE_POSITION', 'NATIVE_PAYEE', 'NATIVE_QUESTION', 'NATIVE_GRANT', 'NATIVE_GRANTS'].includes(kind) || !/^[0-9a-f]{64}$/.test(digest)) throw new Error('助手引用无法核实');
  return { kind: kind as AgentReference['kind'], id: uuid(item.id), digest };
}
function sameRef(a: AgentReference, b: AgentReference): boolean { return a.kind === b.kind && a.id === b.id && a.digest === b.digest; }
function asOf(raw: unknown): string { const value = text(raw); if (!Number.isFinite(Date.parse(value))) throw new Error('助手观察时间无法核实'); return value; }
function closed(row: Record<string, unknown>, keys: string[]): void { if (Object.keys(row).some((key) => !keys.includes(key))) throw new Error('助手字段超出只读合同'); }
function hash(raw: unknown): string { const value = text(raw); if (!/^[a-f0-9]{64}$/.test(value)) throw new Error('助手原件摘要无法核实'); return value; }
function reasons(raw: unknown): string[] { return list(raw ?? [], (value) => { const s = text(value); if (s.length > 256) throw new Error('助手原因超出合同'); return s; }, 100); }
function compiled(raw: unknown): CompiledTemplate { const row = object(raw); closed(row, ['protocol', 'template_name', 'configuration', 'configuration_hash']); if (row.protocol !== 'policy-templates-go-v1') throw new Error('候选编译协议不符'); const name = parseTemplateName(row.template_name); return { protocol: row.protocol, template_name: name, configuration: parseConfiguration(name, row.configuration), configuration_hash: hash(row.configuration_hash) }; }
function readOnlyTree(raw: unknown): void { if (Array.isArray(raw)) { for (const v of raw) readOnlyTree(v); return; } if (raw && typeof raw === 'object') for (const [key, value] of Object.entries(raw)) { if (['authority', 'bank_authority'].includes(key) && value !== false || ['token_hash', 'csrf_hash', 'permit_signature', 'bank_key', 'bank_request'].includes(key)) throw new Error('助手夹带权限或敏感原件'); if (key.endsWith('_cents') && value != null && typeof value !== 'object') { if (['cash_cents', 'margin_cents', 'forecast_cash_cents'].includes(key)) cents(value); else amount(value); } readOnlyTree(value); } }
function parseNativeCandidate(raw: unknown, refs: AgentReference[], data: Dashboard): AgentNativeCandidate { const row = object(raw); closed(row, ['mode', 'compiled', 'goal_id', 'policy_id', 'reference', 'state', 'preview', 'forecast', 'reasons', 'requires_user_confirmation', 'bank_authority']); readOnlyTree(row); if (row.mode !== 'IF_USER_CONFIRMED' || row.requires_user_confirmation !== true || row.bank_authority !== false) throw new Error('原生候选未经本人确认'); const ref = reference(row.reference); if (ref.kind !== 'NATIVE_CONTEXT' || !refs.some((r) => sameRef(r, ref))) throw new Error('原生候选缺少当前依据'); const goal = row.goal_id == null ? undefined : uuid(row.goal_id); if (goal && !data.goals.some((g) => g.id === goal)) throw new Error('原生候选引用了范围外目标'); const preview = row.preview == null ? undefined : object(row.preview); const configuration = compiled(row.compiled); if (preview && (preview.configuration_hash !== configuration.configuration_hash || preview.template_name !== configuration.template_name || preview.bank_authority !== false)) throw new Error('候选与确定性预览不一致'); return { mode: row.mode, compiled: configuration, goal_id: goal, policy_id: row.policy_id == null ? undefined : uuid(row.policy_id), reference: ref, state: text(row.state), reasons: reasons(row.reasons), amount_cents: preview ? amount(preview.amount_cents) : undefined, forecast: row.forecast == null ? undefined : parseForecastResult(row.forecast), requires_user_confirmation: true, bank_authority: false }; }
function parseNativeRule(raw: unknown, refs: AgentReference[]): AgentNativeRule { const row = object(raw), version = object(row.version), config = compiled(version.compiled); closed(row, ['version', 'goal_id', 'timezone', 'effective_state']); if (version.current !== true || version.confirmation_verified !== true || version.confirmed_configuration_hash !== config.configuration_hash) throw new Error('现行规则缺少原确认'); const id = uuid(version.policy_id); if (!refs.some((r) => r.kind === 'NATIVE_POLICY' && r.id === id)) throw new Error('现行规则缺少当前引用'); return { policy_id: id, version_id: uuid(version.version_id), version: integer(version.version), compiled: config, state: text(version.state), effective_state: text(row.effective_state), goal_id: row.goal_id == null ? undefined : uuid(row.goal_id) }; }
function parseJoint(raw: unknown, data: Dashboard): AgentJoint { const row = object(raw); closed(row, ['mode', 'state', 'result', 'reasons', 'bank_authority']); readOnlyTree(row); if (row.mode !== 'READ_ONLY_NOT_EXECUTABLE' || row.bank_authority !== false) throw new Error('助手联合观察不是只读结果'); const result = row.result == null ? undefined : object(row.result); const allocations = result ? list(result.allocations ?? [], (raw) => { const v = object(raw); const id = uuid(v.goal_id); if (!data.goals.some((g) => g.id === id)) throw new Error('联合观察使用了范围外目标'); uuid(v.version_id); return { goal_id: id, amount_cents: amount(v.amount_cents), minimum_shortfall_cents: amount(v.minimum_shortfall_cents) }; }, 8) : []; if (result && (result.algorithm !== 'joint-point-protection-go-v2' || result.bank_authority !== false || result.status !== row.state || !['OPTIMAL', 'INFEASIBLE', 'UNKNOWN'].includes(text(result.status)))) throw new Error('联合观察算法或状态无法核实'); if (result && result.status !== 'OPTIMAL' && (allocations.length || (result.children as unknown[])?.length || (result.uses as unknown[])?.length || result.effect_hash || result.objective != null)) throw new Error('未知联合结果不能包含金额'); return { mode: row.mode, state: text(row.state), reasons: reasons(row.reasons), allocations, bank_authority: false }; }

export function parseAgentResult(raw: unknown, data: Dashboard): AgentResult {
  const item = object(raw);
  closed(item, ['mode', 'provider_status', 'model_used', 'authority', 'observations', 'references', 'candidate', 'native_candidate', 'budget', 'provider_usage']);
  if (item.authority !== false || !['OFFLINE', 'MODEL'].includes(text(item.mode)) || !['NOT_RUN', 'CALLED'].includes(text(item.provider_status)) || typeof item.model_used !== 'boolean') throw new Error('助手响应越过只读边界');
  if (item.mode === 'OFFLINE' && (item.model_used || item.provider_status !== 'NOT_RUN')) throw new Error('离线助手混入了未核实的模型调用');
  if (item.mode === 'MODEL' && (!item.model_used || item.provider_status !== 'CALLED')) throw new Error('模型调用状态无法核实');
  const references = list(item.references, reference, 1000);
  if (item.mode === 'MODEL' && references.some((ref) => ref.kind === 'NATIVE_GRANT' || ref.kind === 'NATIVE_GRANTS')) throw new Error('模型响应混入未授权的原生授权引用');
  const observations = list(item.observations, (raw): AgentObservation => {
    const row = object(raw); const tool = text(row.tool); const summary = text(row.summary);
    closed(row, ['tool', 'as_of', 'summary', 'verification_scope', 'references', 'accounts', 'goals', 'policies', 'grants', 'operations', 'candidate', 'native_candidate', 'native_rules', 'native_grants', 'native_grant', 'catalog', 'forecast', 'joint', 'object', 'objects']);
    if (!tools.includes(tool) || row.verification_scope !== 'DISPLAY_SNAPSHOT' || summary.length > 2000) throw new Error('助手观察未通过合同');
    const refs = list(row.references, reference, 1000);
    if (refs.some((ref) => !references.some((current) => sameRef(ref, current)))) throw new Error('助手引用缺少当前观察');
    const native = tool === 'template_catalog' || tool === 'native_rules' || tool === 'native_grants' || tool === 'forecast365' || tool === 'joint_preview' || tool === 'template_candidate' || tool === 'object_status' || tool === 'original_objects';
    if (native && tool !== 'template_catalog' && !refs.some((r) => r.kind === 'NATIVE_CONTEXT')) throw new Error('原生观察缺少当前完整上下文');
    const hasGrants = row.native_grants != null || row.native_grant != null || refs.some((ref) => ref.kind === 'NATIVE_GRANT' || ref.kind === 'NATIVE_GRANTS');
    if (hasGrants && (item.mode !== 'OFFLINE' || !['native_grants', 'object_status'].includes(tool) || row.native_grants != null && row.native_grant != null || row.object != null || row.objects != null || row.candidate != null || row.native_candidate != null || row.native_rules != null || row.forecast != null || row.joint != null || ['accounts', 'goals', 'policies', 'grants', 'operations', 'catalog'].some((key) => row[key] != null) || item.candidate != null || item.native_candidate != null)) throw new Error('原生授权只能独立本地只读核对');
    if (hasGrants && row.native_grants == null && row.native_grant == null || tool === 'native_grants' && row.native_grants == null || row.native_grant != null && tool !== 'object_status') throw new Error('原生授权观察缺少闭合内容');
    const nativeGrants = row.native_grants == null ? undefined : parseNativeGrantCollection(row.native_grants, refs, asOf(row.as_of));
    const nativeGrant = row.native_grant == null ? undefined : parseNativeGrant(row.native_grant, refs, asOf(row.as_of));
    let forecast: AgentObservation['forecast']; if (row.forecast != null) { const f = object(row.forecast); closed(f, ['state', 'result', 'reasons', 'bank_authority']); if (f.bank_authority !== false || tool !== 'forecast365') throw new Error('预测观察夹带权限'); forecast = { state: text(f.state), reasons: reasons(f.reasons), result: f.result == null ? undefined : parseForecastResult(f.result) }; if (forecast.result && forecast.result.horizon_days !== 365 || !forecast.result && forecast.state !== 'INCOMPLETE') throw new Error('预测观察范围不完整'); }
    let original: AgentObservation['object']; if (row.object != null) { const o = object(row.object); if (tool !== 'object_status' || !refs.some((r) => r.kind === o.kind && r.id === o.id)) throw new Error('原对象缺少当前引用'); readOnlyTree(o.data); if (JSON.stringify(o.data).length > 32768) throw new Error('原对象超出范围'); original = { kind: text(o.kind), id: uuid(o.id), data: object(o.data) }; }
    return { tool, as_of: asOf(row.as_of), summary, references: refs, native_grants: nativeGrants, native_grant: nativeGrant,
      objects: row.objects == null ? undefined : list(row.objects, (raw) => { const o = object(raw); if (tool !== 'original_objects' || !refs.some((r) => r.kind === o.kind && r.id === o.id)) throw new Error('原对象列表缺少当前引用'); readOnlyTree(o.data); return { kind: text(o.kind), id: uuid(o.id), data: object(o.data) }; }, 100), catalog: row.catalog == null ? undefined : list(row.catalog, (raw) => { const v = object(raw); return { template_name: parseTemplateName(v.template_name), fields: list(v.fields, text, 40) }; }, 12),
      native_rules: row.native_rules == null ? undefined : list(row.native_rules, (raw) => parseNativeRule(raw, refs)), forecast, joint: row.joint == null ? undefined : parseJoint(row.joint, data), object: original,
      accounts: list(row.accounts ?? [], (raw) => { const account = object(raw); return { id: uuid(account.id), name: text(account.name), balance_cents: amount(account.balance_cents), goal_owned_cents: amount(account.goal_owned_cents) }; }),
      goals: list(row.goals ?? [], (raw) => { const goal = object(raw); return { id: uuid(goal.id), name: text(goal.name), target_cents: amount(goal.target_cents), assigned_cents: amount(goal.assigned_cents) }; }),
      operations: list(row.operations ?? [], (raw) => { const op = object(raw); const state = text(op.state); if (!(states as readonly string[]).includes(state) || (state === 'SETTLED' && !op.receipt_id)) throw new Error('助手操作状态无法核实'); return { id: uuid(op.id), state: state as OperationState, amount_cents: amount(op.amount_cents), receipt_id: op.receipt_id == null ? undefined : uuid(op.receipt_id) }; }, 20) };
  }, 8);
  let candidate: AgentCandidate | undefined;
  if (item.candidate != null) {
    const draft = object(item.candidate);
    if (Object.keys(draft).some((key) => !['template', 'goal_id', 'reference', 'requires_user_fields', 'bank_authority'].includes(key)) || draft.template !== 'SINGLE_GOAL' || draft.requires_user_fields !== true || draft.bank_authority !== false) throw new Error('草稿夹带了未确认权限');
    const ref = reference(draft.reference); const goalID = uuid(draft.goal_id);
    if (ref.kind !== 'GOAL' || ref.id !== goalID || !data.goals.some((goal) => goal.id === goalID) || !references.some((current) => sameRef(ref, current)) || !observations.some((observation) => observation.tool === 'policy_candidate' && observation.references.some((current) => sameRef(ref, current)))) throw new Error('草稿没有当前本人目标引用');
    candidate = { template: 'SINGLE_GOAL', goal_id: goalID, reference: ref, requires_user_fields: true, bank_authority: false };
  }
  const nativeCandidate = item.native_candidate == null ? undefined : parseNativeCandidate(item.native_candidate, references, data);
  if (nativeCandidate && !observations.some((o) => o.tool === 'template_candidate' && o.references.some((r) => sameRef(r, nativeCandidate.reference)))) throw new Error('原生候选没有本轮确定性观察');
  const budget = object(item.budget);
  const result: AgentResult = { mode: item.mode as AgentResult['mode'], provider_status: item.provider_status as AgentResult['provider_status'], model_used: item.model_used, authority: false, observations, references, candidate,
    native_candidate: nativeCandidate, budget: { provider_calls: integer(budget.provider_calls), tool_calls: integer(budget.tool_calls), reserved_tokens: integer(budget.reserved_tokens), reserved_cost_micros: integer(budget.reserved_cost_micros) } };
  if (result.mode === 'OFFLINE' && (result.budget.provider_calls !== 0 || result.budget.reserved_tokens !== 0 || result.budget.reserved_cost_micros !== 0)) throw new Error('离线调用预算无法核实');
  if (item.provider_usage != null) {
    const usage = object(item.provider_usage);
    result.provider_usage = { input_tokens: integer(usage.input_tokens), output_tokens: integer(usage.output_tokens), reported_calls: integer(usage.reported_calls) };
  }
  if (result.mode === 'MODEL' && (!result.provider_usage || result.provider_usage.reported_calls !== result.budget.provider_calls || result.provider_usage.input_tokens < 1 || result.provider_usage.output_tokens < 1 || result.budget.provider_calls < 1 || result.budget.provider_calls > 3 || result.budget.tool_calls > 3 || result.budget.reserved_cost_micros > 20000 || result.provider_usage.input_tokens + result.provider_usage.output_tokens > result.budget.reserved_tokens)) throw new Error('模型实际用量与本轮预算无法核实');
  if (result.mode === 'OFFLINE' && result.provider_usage && (result.provider_usage.reported_calls || result.provider_usage.input_tokens || result.provider_usage.output_tokens)) throw new Error('离线响应混入了模型用量');
  return result;
}
export class AgentClient {
  constructor(readonly client: Client) {}
  async status(): Promise<AgentStatus> {
    const item = object(await this.client.request('/agent/status'));
    if (item.authority !== false || typeof item.provider_configured !== 'boolean') throw new Error('助手配置状态无法核实');
    return { mode: text(item.mode), provider_status: text(item.provider_status), provider_configured: item.provider_configured, authority: false };
  }
  async offline(tool: OfflineTool, selectedID: string, data: Dashboard, nativeArgs?: { template_name: TemplateName; configuration: TemplateConfiguration; goal_id?: string; policy_id?: string } | { reference: AgentReference }): Promise<AgentResult> {
    const args = tool === 'template_candidate' || tool === 'object_status' ? nativeArgs : tool === 'goal_status' || tool === 'policy_candidate' ? { goal_id: selectedID } : tool === 'operation_status' ? { operation_id: selectedID } : {};
    if (args == null) throw new Error('请先填写候选或读取原对象引用');
    const result = parseAgentResult(await this.client.request('/agent/turn', { method: 'POST', body: JSON.stringify({ mode: 'OFFLINE', tool: { name: tool, arguments: args } }) }), data);
    if (result.mode !== 'OFFLINE') throw new Error('离线入口返回了模型调用，已停止展示');
    return result;
  }
  async model(text: string, data: Dashboard): Promise<AgentResult> {
    if (!text.trim() || text.length > 1024 || new TextEncoder().encode(text).length > 4096) throw new Error('请输入最多 1024 字的本次问题');
    const result = parseAgentResult(await this.client.request('/agent/turn', { method: 'POST', signal: AbortSignal.timeout(25000), body: JSON.stringify({ mode: 'MODEL', text }) }), data);
    if (result.mode !== 'MODEL') throw new Error('模型入口未返回可核实的模型调用');
    return result;
  }
}
