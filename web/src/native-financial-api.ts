import { Client, states } from './api';
import type { OperationState } from './api';
import { cents } from './money';
import { parseForecastResult, parseTemplateView } from './template-api';
import type { ForecastResult, TemplatePolicyView, TemplateScope } from './template-api';
import { templateDate, templateID } from './template-schema';

export type NativeActionKind = 'PAY_RECURRING' | 'PURCHASE_ASSET' | 'REDEEM_ASSET' | 'MATURE_ASSET';
export type AssetKind = Exclude<NativeActionKind, 'PAY_RECURRING'>;
export interface ProductTerms { protocol: 'zhiyu-bank-product-v2'; product_id: string; version: number; asset_class: 'CASH_MGMT_T0' | 'CASH_MGMT_T1' | 'FIXED_DEPOSIT'; minimum_purchase_cents: string; term_days: number; lock_days: number; redemption_delay_days: number; redemption_fee_bps: number; early_loss_bps: number; principal_guaranteed: true; auto_rollover: false }
export interface FinancialProduct { terms: ProductTerms; terms_hash: string; availability: { status: 'AVAILABLE' | 'UNAVAILABLE'; effective_from: string; effective_until: string }; original: Record<string, unknown> }
export interface FinancialPosition { id: string; principal_cents: string; goal_id?: string; return_account_id: string; purchased_at: string; maturity_at?: string; terms: ProductTerms; source_policy_id: string; opening_hash: string; closed: boolean; closing_key?: string; original: Record<string, unknown> }
export interface FinancialDebt { id: string; policy_id: string; version_id: string; due_date: string; amount_cents: string; source_hash: string }
export interface FinancialLiability { id: string; kind: 'BILL' | 'OCCURRENCE'; policy_id: string; period: string; final_total_cents: string; payee_id: string; evidence_hash: string; original_hash: string; paid_cents: string; reserved_cents: string; original: Record<string, unknown> }
export interface FinancialOptions { captured_at: string; source_hash: string; funds_version: number; source_version: number; policies: TemplatePolicyView[]; debts: FinancialDebt[]; liabilities: FinancialLiability[]; products: FinancialProduct[]; positions: FinancialPosition[]; namespace: string; user_id: string; original: Record<string, unknown> }
export interface ActionPreview { id: string; kind: NativeActionKind; scope: TemplateScope; created_at: string; expires_at: string; reviewed_hash: string; amount_cents: string; fee_cents: string; loss_cents: string; net_cents: string; forecast_before: ForecastResult; forecast_after: ForecastResult; original: Record<string, unknown> }
export interface ActionCommand { preview_id: string; reviewed_hash: string; cost_reviewed?: boolean }
export interface ActionFunding { cash_uses: { account_id: string; amount_cents: string }[]; income_uses: { origin_id: string; account_id: string; amount_cents: string; bucket: 'AVAILABLE' | 'ASSIGNED_GOAL' }[]; return_uses: { operation_key: string; position_id: string; account_id: string; amount_cents: string }[] }
export interface ActionLocator<P extends ActionPreview = ActionPreview> { environment: string; user_id: string; key: string; command: ActionCommand; preview: P }
export interface ActionOperation { id: string; group_id: string; child_number: 1; kind: NativeActionKind; state: OperationState; amount_cents: string; bank_key: string; bank_observed_status?: string; processing_health: string; receipt_id?: string; version: number; created_at: string; updated_at: string }
export interface ActionTransport<P extends ActionPreview> { client: Client; family: 'payments' | 'assets'; parsePreview(raw: unknown): P; original(preview: P, signal?: AbortSignal): Promise<P>; accept(original: ActionLocator<P>): Promise<ActionOperation>; byKey(original: ActionLocator<P>, signal?: AbortSignal): Promise<ActionOperation>; operation(id: string, original: ActionLocator<P>, signal?: AbortSignal): Promise<ActionOperation> }

export function nfObject(value: unknown): Record<string, unknown> { if (!value || typeof value !== 'object' || Array.isArray(value)) throw new Error('原生资金原件结构不完整'); return value as Record<string, unknown>; }
export function nfClosed(value: Record<string, unknown>, keys: string[]) { if (Object.keys(value).some((key) => !keys.includes(key))) throw new Error('原生资金原件包含未审阅字段'); }
export function nfText(value: unknown, max = 256): string { if (typeof value !== 'string' || !value || value.length > max) throw new Error('原生资金文字字段不完整'); return value; }
export function nfHash(value: unknown): string { const result = nfText(value, 64); if (!/^[a-f0-9]{64}$/.test(result)) throw new Error('原生资金原件引用不完整'); return result; }
export function nfTime(value: unknown): string { const result = nfText(value, 64); if (!Number.isFinite(Date.parse(result))) throw new Error('原生资金时间不完整'); return result; }
export function nfInt(value: unknown, min = 0, max = Number.MAX_SAFE_INTEGER): number { if (!Number.isSafeInteger(value) || (value as number) < min || (value as number) > max) throw new Error('原生资金整数范围不符'); return value as number; }
export function nfMoney(value: unknown, positive = false): string { const result = cents(value); if (BigInt(result) < (positive ? 1n : 0n)) throw new Error('原生资金金额范围不符'); return result; }
export function nfList<T>(value: unknown, parse: (raw: unknown) => T, max = 10000): T[] { if (!Array.isArray(value) || value.length > max) throw new Error('原生资金列表超出完整读取范围'); return value.map(parse); }
export function nfUnique(values: string[]) { if (new Set(values).size !== values.length) throw new Error('原生资金原件重复'); }
export function nfOwner(raw: unknown, client?: Client): TemplateScope { const v = nfObject(raw); nfClosed(v, ['environment_id', 'user_id']); const scope = { environment_id: templateID(v.environment_id), user_id: templateID(v.user_id) }; if (client && scope.user_id !== client.session?.user_id) throw new Error('原生资金原件不属于当前本人会话'); return scope; }
export function nfSameOwner(left: TemplateScope, raw: unknown) { const right = nfOwner(raw); if (left.environment_id !== right.environment_id || left.user_id !== right.user_id) throw new Error('原生资金原件跨越本人环境'); }
export function nfTree(raw: unknown): void {
  if (Array.isArray(raw)) { raw.forEach(nfTree); return; }
  if (!raw || typeof raw !== 'object') return;
  for (const [key, value] of Object.entries(raw)) { if (key === 'bank_authority' && value !== false) throw new Error('候选预览不能包含资金权限'); if (key.endsWith('_cents') && value != null && typeof value !== 'object') cents(value); nfTree(value); }
}
export function parseProductTerms(raw: unknown): ProductTerms {
  const t = nfObject(raw); nfClosed(t, ['protocol', 'product_id', 'version', 'asset_class', 'minimum_purchase_cents', 'term_days', 'lock_days', 'redemption_delay_days', 'redemption_fee_bps', 'early_loss_bps', 'principal_guaranteed', 'auto_rollover']);
  if (t.protocol !== 'zhiyu-bank-product-v2' || !['CASH_MGMT_T0', 'CASH_MGMT_T1', 'FIXED_DEPOSIT'].includes(String(t.asset_class)) || t.principal_guaranteed !== true || t.auto_rollover !== false) throw new Error('产品条款不符合当前本金保护范围');
  const terms: ProductTerms = { protocol: t.protocol, product_id: nfText(t.product_id), version: nfInt(t.version, 1), asset_class: t.asset_class as ProductTerms['asset_class'], minimum_purchase_cents: nfMoney(t.minimum_purchase_cents, true), term_days: nfInt(t.term_days, 0, 3660), lock_days: nfInt(t.lock_days, 0, 3660), redemption_delay_days: nfInt(t.redemption_delay_days, 0, 1), redemption_fee_bps: nfInt(t.redemption_fee_bps, 0, 10000), early_loss_bps: nfInt(t.early_loss_bps, 0, 10000), principal_guaranteed: true, auto_rollover: false };
  if (terms.redemption_fee_bps + terms.early_loss_bps > 10000 || (terms.asset_class === 'FIXED_DEPOSIT' ? terms.term_days < 1 || terms.lock_days > terms.term_days : terms.term_days !== 0 || terms.redemption_delay_days !== (terms.asset_class === 'CASH_MGMT_T0' ? 0 : 1))) throw new Error('产品期限与费用条款不一致'); return terms;
}
export function parseFinancialProduct(raw: unknown): FinancialProduct {
  const p = nfObject(raw), a = nfObject(p.availability), terms = parseProductTerms(p.terms); nfClosed(p, ['terms', 'terms_hash', 'availability', 'availability_hash']);
  nfClosed(a, ['protocol', 'product_id', 'version', 'terms_version', 'terms_hash', 'status', 'effective_from', 'effective_until']);
  if (a.protocol !== 'zhiyu-bank-availability-v2' || a.product_id !== terms.product_id || a.terms_version !== terms.version || nfHash(a.terms_hash) !== nfHash(p.terms_hash) || !['AVAILABLE', 'UNAVAILABLE'].includes(String(a.status))) throw new Error('产品供给与原条款版本不一致');
  nfInt(a.version, 1); nfHash(p.availability_hash); const from = nfTime(a.effective_from), until = nfTime(a.effective_until); if (Date.parse(until) <= Date.parse(from)) throw new Error('产品供给期限不完整');
  return { terms, terms_hash: nfHash(p.terms_hash), availability: { status: a.status as 'AVAILABLE' | 'UNAVAILABLE', effective_from: from, effective_until: until }, original: p };
}
export function parseFinancialPosition(raw: unknown, namespace: string, userID: string): FinancialPosition {
  const p = nfObject(raw), o = nfObject(p.opening), authority = nfObject(o.source_authority); nfClosed(p, ['opening', 'opening_hash', 'closing_key', 'closed']);
  if (o.protocol !== 'zhiyu-bank-v2/position' || o.namespace !== namespace || o.user_id !== userID || typeof p.closed !== 'boolean' || authority.role !== 'EXECUTE') throw new Error('持仓原件不属于当前范围');
  const terms = parseProductTerms(o.terms); nfHash(o.terms_hash); nfHash(o.opening_request_hash); if (o.source_kind === 'TRUSTED_HISTORICAL_IMPORT') nfHash(o.source_evidence_hash); else if (o.source_kind !== 'BANK_PURCHASE' || o.source_evidence_hash !== '') throw new Error('持仓缺少明确的原始来源'); nfInt(authority.version, 1); nfInt(authority.policy_version, 1);
  if (authority.goal_id !== o.goal_id) throw new Error('持仓来源规则与目标归属不一致');
  const maturity = nfTime(o.maturity_at); return { id: nfText(o.position_id), principal_cents: nfMoney(o.principal_cents, true), goal_id: o.goal_id === '' ? undefined : templateID(o.goal_id), return_account_id: templateID(o.return_account_id), purchased_at: nfTime(o.purchased_at), maturity_at: maturity === '0001-01-01T00:00:00Z' ? undefined : maturity, terms, source_policy_id: templateID(authority.policy_id), opening_hash: nfHash(p.opening_hash), closed: p.closed, closing_key: p.closing_key === '' ? undefined : nfText(p.closing_key), original: p };
}
export function parseLiability(raw: unknown): FinancialLiability {
  const l = nfObject(raw), o = nfObject(l.original); nfClosed(l, ['original', 'original_hash', 'paid_cents', 'reserved_cents']); nfClosed(o, ['id', 'kind', 'policy_id', 'period', 'final_total_cents', 'payee_id', 'evidence_hash']);
  if (o.kind !== 'BILL' && o.kind !== 'OCCURRENCE') throw new Error('最终账单类型不完整');
  const final = nfMoney(o.final_total_cents, true), paid = nfMoney(l.paid_cents), reserved = nfMoney(l.reserved_cents);
  if (BigInt(paid) + BigInt(reserved) > BigInt(final) || (o.kind === 'BILL' ? o.policy_id !== '' || o.period !== '' : templateID(o.policy_id) !== o.policy_id || !/^\d{4}-\d{2}$/.test(nfText(o.period)))) throw new Error('最终账单金额或周期不一致');
  return { id: nfText(o.id, 128), kind: o.kind, policy_id: o.policy_id as string, period: o.period as string, final_total_cents: final, payee_id: nfText(o.payee_id), evidence_hash: nfHash(o.evidence_hash), original_hash: nfHash(l.original_hash), paid_cents: paid, reserved_cents: reserved, original: o };
}
export function parseFinancialOptions(raw: unknown, client: Client): FinancialOptions {
  nfTree(raw); const v = nfObject(raw), bank = nfObject(v.bank_state); nfClosed(v, ['protocol', 'captured_at', 'source_hash', 'funds_version', 'source_version', 'policies', 'debts', 'liabilities', 'bank_state', 'bank_authority']);
  if (v.protocol !== 'native-financial-options-v1' || v.bank_authority !== false || bank.protocol !== 'zhiyu-bank-v2' || bank.user_id !== client.session?.user_id) throw new Error('资金选项不属于当前本人会话');
  const namespace = nfText(bank.namespace), user = templateID(bank.user_id); nfTime(bank.captured_at); nfInt(bank.operation_watermark); nfInt(bank.catalog_watermark);
  const policies = nfList(v.policies, (row) => parseTemplateView(row, client), 100);
  const debts = nfList(v.debts, (raw): FinancialDebt => { const d = nfObject(raw); nfClosed(d, ['id', 'policy_id', 'version_id', 'due_date', 'amount_cents', 'verified', 'source_hash']); if (d.verified !== true) throw new Error('债务尚无已采纳原件'); return { id: nfText(d.id, 128), policy_id: templateID(d.policy_id), version_id: templateID(d.version_id), due_date: templateDate(d.due_date), amount_cents: nfMoney(d.amount_cents), source_hash: nfHash(d.source_hash) }; });
  const liabilities = nfList(v.liabilities, parseLiability, 1000), products = nfList(bank.products, parseFinancialProduct, 100), positions = nfList(bank.positions, (row) => parseFinancialPosition(row, namespace, user));
  for (const values of [debts.map((d) => d.id), liabilities.map((l) => l.id), products.map((p) => p.terms.product_id), positions.map((p) => p.id)]) nfUnique(values);
  return { captured_at: nfTime(v.captured_at), source_hash: nfHash(v.source_hash), funds_version: nfInt(v.funds_version, 1), source_version: nfInt(v.source_version, 1), policies, debts, liabilities, products, positions, namespace, user_id: user, original: v };
}
export async function financialOptions(client: Client, signal?: AbortSignal) { return parseFinancialOptions(await client.request('/financial-options', { signal }), client); }
export function parseActionHeader(raw: unknown, client: Client, protocol: string, kinds: readonly NativeActionKind[]): ActionPreview {
  nfTree(raw); const p = nfObject(raw), scope = nfOwner(p.scope, client); if (p.protocol !== protocol || !kinds.includes(p.kind as NativeActionKind) || p.bank_authority !== false) throw new Error('原生安排预览协议不受支持');
  templateID(p.session_id); nfHash(p.effect_hash); nfHash(p.source_hash); nfHash(p.inventory_hash); const created = nfTime(p.created_at), expires = nfTime(p.expires_at);
  if (Date.parse(expires) <= Date.parse(created) || Date.parse(expires) - Date.parse(created) > 120000) throw new Error('原生安排审阅期限不完整');
  const input = nfObject(p.forecast_input), facts = nfObject(input.facts); nfSameOwner(scope, input.scope); nfSameOwner(scope, facts.scope);
  if (input.complete !== true || facts.complete !== true || input.as_of !== created || input.horizon_days !== 365 || input.inventory_hash !== p.inventory_hash || facts.source_hash !== p.source_hash) throw new Error('原生安排完整年度保护依据不符');
  const before = parseForecastResult(p.forecast_before), after = parseForecastResult(p.forecast_after), effect = nfObject(p.bank_effect);
  if (before.horizon_days !== 365 || after.horizon_days !== 365 || before.as_of !== created || after.as_of !== created || input.timezone !== p.timezone || before.timezone !== p.timezone || after.timezone !== p.timezone || effect.kind !== p.kind) throw new Error('原生安排时点或效果与原保护不符');
  const dependencies = nfObject(p.dependencies), keys = ['funds_version', 'grant_version', 'policy_version', 'product_terms_version', 'product_availability_version', 'source_evidence_version', 'writer_generation', 'control_version']; nfClosed(dependencies, keys); for (const key of keys) nfInt(dependencies[key], key === 'grant_version' ? 0 : 1);
  return { id: templateID(p.id), kind: p.kind as NativeActionKind, scope, created_at: created, expires_at: expires, reviewed_hash: nfHash(p.reviewed_hash), amount_cents: nfMoney(effect.amount_cents, true), fee_cents: nfMoney(effect.fee_cents), loss_cents: nfMoney(effect.loss_cents), net_cents: nfMoney(effect.net_cents), forecast_before: before, forecast_after: after, original: p };
}
export function parseActionFunding(raw: unknown): ActionFunding {
  const e = nfObject(raw);
  nfClosed(e, ['kind', 'business_key', 'amount_cents', 'cash_uses', 'origin_uses', 'return_uses', 'destination_account_id', 'source_goal_id', 'destination_goal_id', 'product', 'position_id', 'position_opening_hash', 'return_account_id', 'principal_available_by', 'planned_redeem_at', 'fee_cents', 'loss_cents', 'net_cents', 'quote_id', 'liability', 'latest_arrival_at']);
  const cash = nfList(e.cash_uses, (raw) => { const v = nfObject(raw); nfClosed(v, ['account_id', 'amount_cents']); return { account_id: templateID(v.account_id), amount_cents: nfMoney(v.amount_cents, true) }; }, 128);
  const income = nfList<ActionFunding['income_uses'][number]>(e.origin_uses, (raw) => { const v = nfObject(raw); nfClosed(v, ['origin_id', 'account_id', 'amount_cents', 'bucket']); if (v.bucket !== 'AVAILABLE' && v.bucket !== 'ASSIGNED_GOAL') throw new Error('原收入用途资格不完整'); return { origin_id: templateID(v.origin_id), account_id: templateID(v.account_id), amount_cents: nfMoney(v.amount_cents, true), bucket: v.bucket }; }, 128);
  const returns = nfList(e.return_uses, (raw) => { const v = nfObject(raw); nfClosed(v, ['operation_key', 'position_id', 'account_id', 'amount_cents']); return { operation_key: nfText(v.operation_key), position_id: nfText(v.position_id), account_id: templateID(v.account_id), amount_cents: nfMoney(v.amount_cents, true) }; }, 128);
  nfUnique(cash.map((v) => v.account_id)); nfUnique(income.map((v) => `${v.origin_id}:${v.account_id}`)); nfUnique(returns.map((v) => `${v.operation_key}:${v.account_id}`));
  for (const source of [...income, ...returns]) if (!cash.some((c) => c.account_id === source.account_id)) throw new Error('来源用途缺少对应真实现金位置');
  for (const c of cash) if ([...income, ...returns].filter((v) => v.account_id === c.account_id).reduce((sum, v) => sum + BigInt(v.amount_cents), 0n) > BigInt(c.amount_cents)) throw new Error('来源资格金额超过实际现金用途');
  return { cash_uses: cash, income_uses: income, return_uses: returns };
}
export function validateCashResources(raw: unknown, funding: ActionFunding, expected: string): void {
  const r = nfObject(raw); nfClosed(r, ['amount_cents', 'cash_uses', 'income_uses', 'return_uses', 'slack_uses']); if (nfMoney(r.amount_cents, true) !== expected || JSON.stringify(r.cash_uses) !== JSON.stringify(funding.cash_uses) || JSON.stringify(r.return_uses ?? []) !== JSON.stringify(funding.return_uses)) throw new Error('原未归属现金资源与经济效果不一致');
  const income = nfList(r.income_uses ?? [], (raw) => { const v = nfObject(raw); nfClosed(v, ['FragmentID', 'OriginID', 'AccountID', 'Amount']); templateID(v.FragmentID); return { origin_id: templateID(v.OriginID), account_id: templateID(v.AccountID), amount_cents: nfMoney(v.Amount, true), bucket: 'AVAILABLE' }; }, 128);
  const slack = nfList(r.slack_uses ?? [], (raw) => { const v = nfObject(raw); nfClosed(v, ['account_id', 'amount_cents']); return { account_id: templateID(v.account_id), amount_cents: nfMoney(v.amount_cents, true) }; }, 128);
  const identity = (v: { origin_id: string; account_id: string; amount_cents: string; bucket: string }) => `${v.origin_id}:${v.account_id}:${v.amount_cents}:${v.bucket}`;
  if (income.map(identity).sort().join('|') !== funding.income_uses.map(identity).sort().join('|') || [...income, ...funding.return_uses, ...slack].reduce((sum, v) => sum + BigInt(v.amount_cents), 0n) !== BigInt(expected) || funding.cash_uses.reduce((sum, v) => sum + BigInt(v.amount_cents), 0n) !== BigInt(expected)) throw new Error('实际收入、返本与剩余现金分类不守恒');
}
export function actionTerminal(operation: ActionOperation) { return ['SETTLED', 'REJECTED', 'CANCELLED'].includes(operation.state); }
export function parseActionOperation(raw: unknown, original: ActionLocator, previous?: ActionOperation): ActionOperation {
  const o = nfObject(raw); nfClosed(o, ['id', 'group_id', 'child_number', 'kind', 'state', 'amount_cents', 'bank_key', 'bank_observed_status', 'processing_health', 'receipt_id', 'version', 'created_at', 'updated_at']);
  if (o.kind !== original.preview.kind || o.child_number !== 1 || !(states as readonly unknown[]).includes(o.state) || typeof o.processing_health !== 'string') throw new Error('原生安排操作类型或状态不完整');
  const result: ActionOperation = { id: templateID(o.id), group_id: templateID(o.group_id), child_number: 1, kind: o.kind as NativeActionKind, state: o.state as OperationState, amount_cents: nfMoney(o.amount_cents, true), bank_key: templateID(o.bank_key), bank_observed_status: o.bank_observed_status == null ? undefined : nfText(o.bank_observed_status), processing_health: o.processing_health, receipt_id: o.receipt_id == null ? undefined : templateID(o.receipt_id), version: nfInt(o.version, 1), created_at: nfTime(o.created_at), updated_at: nfTime(o.updated_at) };
  if (result.group_id !== original.preview.id || result.amount_cents !== original.preview.amount_cents || result.bank_key !== result.id || (result.state === 'SETTLED') !== !!result.receipt_id || Date.parse(result.updated_at) < Date.parse(result.created_at) || (previous && (result.id !== previous.id || result.created_at !== previous.created_at || result.version < previous.version || (result.version === previous.version && JSON.stringify(result) !== JSON.stringify(previous)) || (actionTerminal(previous) && (result.state !== previous.state || result.receipt_id !== previous.receipt_id))))) throw new Error('原生安排原结果换键、缺回执或发生回退'); return result;
}
function actionStorageKey(api: ActionTransport<ActionPreview>) { if (!api.client.session) throw new Error('请先登录当前本人环境'); return `zhiyu-go:native-${api.family}-originals:v1:${api.client.session.environment}:${api.client.session.user_id}`; }
export function validateActionLocator<P extends ActionPreview>(api: ActionTransport<P>, raw: unknown): ActionLocator<P> {
  const o = nfObject(raw); nfClosed(o, ['environment', 'user_id', 'key', 'command', 'preview']); const preview = api.parsePreview(nfObject(o.preview).original), command = nfObject(o.command);
  nfClosed(command, api.family === 'assets' ? ['preview_id', 'reviewed_hash', 'cost_reviewed'] : ['preview_id', 'reviewed_hash']);
  if (o.environment !== api.client.session?.environment || o.user_id !== api.client.session?.user_id || command.preview_id !== preview.id || command.reviewed_hash !== preview.reviewed_hash || JSON.stringify(preview) !== JSON.stringify(o.preview) || (api.family === 'assets' && command.cost_reviewed !== (BigInt(preview.fee_cents) + BigInt(preview.loss_cents) > 0n))) throw new Error('原生安排本机原载荷不属于当前完整审阅');
  return { environment: o.environment as string, user_id: o.user_id as string, key: templateID(o.key), command: command as unknown as ActionCommand, preview };
}
function parseActionLocators<P extends ActionPreview>(api: ActionTransport<P>, raw: unknown): ActionLocator<P>[] {
  if (raw == null) return [];
  if (typeof raw !== 'string') throw new Error('保存的原生安排请求不完整，已保留原资料并停止新提交');
  try { const records = nfList(JSON.parse(raw), (row) => validateActionLocator(api, row), 16); nfUnique(records.map((r) => r.key)); return records; }
  catch { throw new Error('保存的原生安排请求不完整，已保留原资料并停止新提交'); }
}
function mergeActionLocators<P extends ActionPreview>(left: ActionLocator<P>[], right: ActionLocator<P>[]): ActionLocator<P>[] {
  const result = [...left];
  for (const value of right) {
    const old = result.find((r) => r.key === value.key);
    if (old && JSON.stringify(old) !== JSON.stringify(value)) throw new Error('原生安排同一原键存在不同完整资料，请保留全部原件并先核对');
    if (!old) result.push(value);
  }
  if (result.length > 16) throw new Error('原生安排本机历史容量已满，请保留全部原件');
  return result;
}
function actionDatabase(): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    const request = indexedDB.open('zhiyu-go-native-action-originals-v1', 1);
    let blocked = false;
    request.onupgradeneeded = () => { request.result.createObjectStore('originals'); };
    request.onblocked = () => { blocked = true; reject(new Error('本机原生安排资料正被其他页面占用，请保留原资料并关闭旧页面后核对')); };
    request.onsuccess = () => { const database = request.result; database.onversionchange = () => database.close(); if (blocked) database.close(); else resolve(database); };
    request.onerror = () => reject(new Error('无法读取本机原生安排完整资料，请保留原件'));
  });
}
async function actionRecords<P extends ActionPreview>(api: ActionTransport<P>, append?: ActionLocator<P>): Promise<ActionLocator<P>[]> {
  const key = actionStorageKey(api), database = await actionDatabase();
  try {
    return await new Promise((resolve, reject) => {
      const transaction = database.transaction('originals', append ? 'readwrite' : 'readonly'), store = transaction.objectStore('originals'), request = store.get(key);
      let result: ActionLocator<P>[] = [], failure: unknown;
      request.onsuccess = () => {
        try {
          // The old localStorage bytes are read-only. Complete new originals
          // live in IndexedDB; neither terminal nor failed records are evicted.
          const legacyRaw = localStorage.getItem(key), legacy = parseActionLocators(api, legacyRaw);
          let stored: ActionLocator<P>[] = [];
          if (request.result !== undefined) {
            try {
              if (typeof request.result !== 'string') throw new Error();
              const snapshot = nfObject(JSON.parse(request.result)); nfClosed(snapshot, ['protocol', 'legacy_raw', 'records']);
              if (snapshot.protocol !== 'zhiyu-native-action-originals-v1' || snapshot.legacy_raw !== legacyRaw || !Array.isArray(snapshot.records)) throw new Error();
              stored = parseActionLocators(api, JSON.stringify(snapshot.records));
            } catch { throw new Error('本机原生安排请求不完整或旧版恢复资料变化，已保留全部原件并停止新提交'); }
          }
          result = mergeActionLocators(legacy, stored);
          if (append) {
            if (result.length >= 16 || result.some((r) => r.key === append.key)) throw new Error('原生安排本机历史容量已满或原键已存在，请保留原件');
            store.put(JSON.stringify({ protocol: 'zhiyu-native-action-originals-v1', legacy_raw: legacyRaw, records: [...stored, append] }), key); result.push(append);
          }
        } catch (cause) { failure = cause; transaction.abort(); }
      };
      transaction.oncomplete = () => resolve(result);
      transaction.onerror = transaction.onabort = () => reject(failure ?? new Error('原生安排完整资料尚未可靠保存，未发送本笔请求；请保留原件'));
    });
  } finally { database.close(); }
}
export async function loadActionLocators<P extends ActionPreview>(api: ActionTransport<P>): Promise<ActionLocator<P>[]> { return actionRecords(api); }
export async function saveActionLocator<P extends ActionPreview>(api: ActionTransport<P>, original: ActionLocator<P>): Promise<ActionLocator<P>[]> {
  const value = validateActionLocator(api, original), committed = await actionRecords(api, value), verified = await loadActionLocators(api);
  if (!committed.every((r) => verified.some((v) => v.key === r.key && JSON.stringify(v) === JSON.stringify(r)))) throw new Error('无法完整回读原生安排，未发送本笔请求；请保留原件');
  return verified;
}
export const actionKindLabel: Record<NativeActionKind, string> = { PAY_RECURRING: '负债支付', PURCHASE_ASSET: '资产购买', REDEEM_ASSET: '资产赎回', MATURE_ASSET: '到期本金回收' };
export function productLabel(terms: ProductTerms): string { return terms.asset_class === 'FIXED_DEPOSIT' ? `定期存款 ${terms.term_days} 天` : terms.asset_class === 'CASH_MGMT_T0' ? '现金管理 T+0' : '现金管理 T+1'; }
