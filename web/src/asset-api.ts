import { Client } from './api';
import { parseTemplateView } from './template-api';
import type { TemplatePolicyView } from './template-api';
import { templateID } from './template-schema';
import { nfClosed, nfHash, nfList, nfMoney, nfObject, nfSameOwner, nfText, nfTime, parseActionFunding, parseActionHeader, parseActionOperation, parseFinancialPosition, parseFinancialProduct, validateActionLocator, validateCashResources } from './native-financial-api';
import type { ActionFunding, ActionLocator, ActionPreview, ActionTransport, AssetKind, FinancialPosition, FinancialProduct } from './native-financial-api';

export interface AssetRequest { kind: AssetKind; policy_version_id: string; product_id?: string; position_id?: string; amount_cents: string; timezone: 'UTC' | 'Asia/Shanghai' }
export interface AssetPreview extends ActionPreview { kind: AssetKind; request: AssetRequest; policy: TemplatePolicyView; product: FinancialProduct; position?: FinancialPosition; funding: ActionFunding; goal_id?: string; return_account_id: string; available_at: string; planned_redeem_at?: string; recovery_trigger?: string }
function assetRequest(raw: unknown): AssetRequest {
  const r = nfObject(raw); nfClosed(r, ['kind', 'policy_version_id', 'product_id', 'position_id', 'amount_cents', 'timezone']);
  if (!['PURCHASE_ASSET', 'REDEEM_ASSET', 'MATURE_ASSET'].includes(String(r.kind)) || (r.timezone !== 'UTC' && r.timezone !== 'Asia/Shanghai')) throw new Error('资产动作或自然时区不受支持');
  const purchase = r.kind === 'PURCHASE_ASSET'; if (purchase ? typeof r.product_id !== 'string' || !r.product_id || r.position_id != null : typeof r.position_id !== 'string' || !r.position_id || r.product_id != null) throw new Error('资产产品与原持仓范围不能混用');
  return { kind: r.kind as AssetKind, policy_version_id: templateID(r.policy_version_id), ...(purchase ? { product_id: nfText(r.product_id) } : { position_id: nfText(r.position_id) }), amount_cents: nfMoney(r.amount_cents, purchase), timezone: r.timezone };
}
export function parseAssetPreview(raw: unknown, client: Client): AssetPreview {
  const base = parseActionHeader(raw, client, 'native-asset-action-v1', ['PURCHASE_ASSET', 'REDEEM_ASSET', 'MATURE_ASSET']), p = base.original;
  nfClosed(p, ['id', 'scope', 'session_id', 'kind', 'effect_hash', 'dependencies', 'source_hash', 'inventory_hash', 'created_at', 'expires_at', 'bank_authority', 'protocol', 'timezone', 'request', 'policy', 'policies', 'ledger', 'inventory_original', 'bank_state', 'quote', 'position', 'cash_resources', 'goal_uses', 'pending_purchases', 'bank_effect', 'forecast_input', 'forecast_before', 'forecast_after', 'recovery_trigger', 'reviewed_hash']);
  const request = assetRequest(p.request), policy = parseTemplateView(p.policy, client), effect = nfObject(p.bank_effect), funding = parseActionFunding(effect), state = nfObject(p.bank_state), product = parseFinancialProduct(effect.product), config = policy.version.compiled.configuration;
  nfSameOwner(base.scope, policy.version.scope);
  if (request.kind !== base.kind || policy.version.version_id !== request.policy_version_id || policy.effective_state !== 'ACTIVE' || !['AssetAuthorizationPolicy', 'RecoveryPolicy'].includes(policy.version.compiled.template_name) || state.protocol !== 'zhiyu-bank-v2' || state.user_id !== base.scope.user_id || effect.business_key !== `asset:${base.id}` || effect.destination_goal_id !== '' || effect.liability !== null || (request.amount_cents !== '0' && BigInt(request.amount_cents) < BigInt(base.amount_cents))) throw new Error('资产原规则、动作与真实经济效果不一致');
  const namespace = nfText(state.namespace), goalID = effect.source_goal_id === '' ? undefined : templateID(effect.source_goal_id), returnAccount = templateID(effect.return_account_id);
  if ((config.type !== 'asset_authorization' && config.type !== 'recovery') || (config.scope === 'goal' ? config.goal_id !== goalID : goalID != null)) throw new Error('资产动作与本人规则的归属范围不一致');
  const policies = nfList(p.policies, (row) => parseTemplateView(row, client), 100); for (const view of policies) nfSameOwner(base.scope, view.version.scope);
  let position: FinancialPosition | undefined, available = '', planned: string | undefined;
  if (request.kind === 'PURCHASE_ASSET') {
    if (config.type !== 'asset_authorization' || product.terms.product_id !== request.product_id || product.availability.status !== 'AVAILABLE' || p.quote != null || p.position != null || base.fee_cents !== '0' || base.loss_cents !== '0' || base.net_cents !== '0' || effect.destination_account_id !== '' || effect.position_opening_hash !== '' || effect.quote_id !== '' || funding.cash_uses.reduce((sum, v) => sum + BigInt(v.amount_cents), 0n) !== BigInt(base.amount_cents) || BigInt(base.amount_cents) < BigInt(product.terms.minimum_purchase_cents) || base.forecast_after.maximum_deficit_cents !== '0') throw new Error('购买包含未审阅费用、返本或来源范围');
    const actual = nfList(state.products, parseFinancialProduct, 100).find((v) => v.terms.product_id === product.terms.product_id); if (!actual || JSON.stringify(actual.original) !== JSON.stringify(product.original)) throw new Error('购买条款不属于本次实际产品清单');
    nfText(effect.position_id); available = nfTime(effect.principal_available_by); const plannedAt = nfTime(effect.planned_redeem_at); planned = plannedAt === '0001-01-01T00:00:00Z' ? undefined : plannedAt;
    if (goalID) {
      if (funding.cash_uses.length !== 1 || funding.income_uses.some((v) => v.bucket !== 'ASSIGNED_GOAL')) throw new Error('目标本金购买不能消耗未归属资格');
      const uses = nfList(p.goal_uses, (raw) => { const u = nfObject(raw); if (u.source_kind !== 'INCOME' && u.source_kind !== 'PRINCIPAL_RETURN') throw new Error('目标购买缺少真实原来源'); return nfMoney(u.amount_cents, true); }, 128);
      if (uses.reduce((sum, v) => sum + BigInt(v), 0n) !== BigInt(base.amount_cents)) throw new Error('目标购买的原来源用途不守恒');
    } else { if (funding.income_uses.some((v) => v.bucket !== 'AVAILABLE')) throw new Error('闲置资产购买不能调用已归属收入'); validateCashResources(p.cash_resources, funding, base.amount_cents); }
  } else {
    const q = nfObject(p.quote);
    if (q.protocol !== 'zhiyu-bank-v2/quote' || q.namespace !== namespace || q.user_id !== base.scope.user_id || q.kind !== base.kind || q.position_id !== request.position_id || q.principal_cents !== base.amount_cents || q.net_cents !== base.net_cents || q.fee_cents !== base.fee_cents || q.loss_cents !== base.loss_cents || effect.position_id !== request.position_id || effect.quote_id !== q.id || effect.position_opening_hash !== nfHash(q.position_opening_hash) || effect.destination_account_id !== returnAccount || funding.cash_uses.length || funding.income_uses.length || funding.return_uses.length || BigInt(base.net_cents) + BigInt(base.fee_cents) + BigInt(base.loss_cents) !== BigInt(base.amount_cents) || JSON.stringify(q.product) !== JSON.stringify(product.original)) throw new Error('赎回报价与本金、费用、损失或原持仓不一致');
    position = parseFinancialPosition({ opening: p.position, opening_hash: q.position_opening_hash, closing_key: '', closed: false }, namespace, base.scope.user_id);
    if (position.id !== request.position_id || position.principal_cents !== base.amount_cents || position.goal_id !== goalID || position.return_account_id !== returnAccount || position.terms.product_id !== product.terms.product_id || (config.type === 'asset_authorization' ? position.source_policy_id !== policy.version.policy_id : position.source_policy_id !== config.asset_policy_id)) throw new Error('赎回范围不属于原购买授权与归属');
    available = nfTime(q.available_at); if (Date.parse(nfTime(q.expires_at)) < Date.parse(base.expires_at)) throw new Error('原报价先于完整审阅到期');
    if (BigInt(base.forecast_after.maximum_deficit_cents) > BigInt(base.forecast_before.maximum_deficit_cents)) throw new Error('回收后保护缺口扩大');
  }
  return { ...base, kind: request.kind, request, policy, product, position, funding, goal_id: goalID, return_account_id: returnAccount, available_at: available, planned_redeem_at: planned, recovery_trigger: p.recovery_trigger == null ? undefined : nfText(p.recovery_trigger) };
}
export class AssetClient implements ActionTransport<AssetPreview> {
  readonly family = 'assets' as const;
  constructor(readonly client: Client) {}
  parsePreview(raw: unknown) { return parseAssetPreview(raw, this.client); }
  async preview(body: AssetRequest) { const request = assetRequest(body), value = this.parsePreview(await this.client.request('/asset-previews', { method: 'POST', body: JSON.stringify(request) })); if (JSON.stringify(value.request) !== JSON.stringify(request)) throw new Error('服务端返回另一份资产预览'); return value; }
  async original(preview: AssetPreview, signal?: AbortSignal) { return this.parsePreview(await this.client.request(`/asset-previews/${encodeURIComponent(preview.kind)}/${encodeURIComponent(preview.id)}`, { signal })); }
  async accept(original: ActionLocator<AssetPreview>) { validateActionLocator(this, original); return parseActionOperation(await this.client.request('/assets', { method: 'POST', headers: { 'Idempotency-Key': original.key }, body: JSON.stringify(original.command) }), original); }
  async byKey(original: ActionLocator<AssetPreview>, signal?: AbortSignal) { return parseActionOperation(await this.client.request(`/asset-commands/${encodeURIComponent(original.preview.kind)}/${encodeURIComponent(original.key)}`, { signal }), original); }
  async operation(id: string, original: ActionLocator<AssetPreview>, signal?: AbortSignal) { return parseActionOperation(await this.client.request(`/assets/${encodeURIComponent(templateID(id))}`, { signal }), original); }
}
