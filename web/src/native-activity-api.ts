import type { Activity, ActivityPage, Client } from './api';
import { nfClosed, nfHash, nfInt, nfList, nfMoney, nfObject, nfText, nfTime, nfTree, nfUnique, parseActionFunding } from './native-financial-api';
import type { ActionFunding } from './native-financial-api';
import { templateID } from './template-schema';

const kinds = ['TRANSFER_INTERNAL', 'ALLOCATE_GOAL', 'TRANSFER_GOAL', 'PURCHASE_ASSET', 'REDEEM_ASSET', 'MATURE_ASSET', 'PAY_RECURRING'] as const;
export type NativeActivityKind = typeof kinds[number];
export interface NativeActivityItem extends Activity { operation_family?: 'NATIVE' | 'LEGACY'; operation_kind?: NativeActivityKind; receipt_id?: string }
export interface NativeActivityPage extends Omit<ActivityPage, 'items'> { items: NativeActivityItem[] }
export interface NativeActivityPosting { id: string; dimension: 'ECONOMIC' | 'GOAL_OWNERSHIP' | 'INCOME_LOCATION' | 'LIABILITY'; direction: 'DEBIT' | 'CREDIT'; amount_cents: string; occurred_at: string }
export interface NativeActivityOriginal {
  activity: NativeActivityItem; operation_id: string; receipt_id: string; kind: NativeActivityKind; amount_cents: string;
  fee_cents: string; loss_cents: string; net_cents: string; funding: ActionFunding; source_goal_id?: string; destination_goal_id?: string; destination_account_id?: string;
  accepted_at: string; available_at: string; settled_at: string; recorded_at: string; verified_at: string; postings: NativeActivityPosting[]; historical_cost_consent: boolean;
}
export const nativeActivityKindText: Record<NativeActivityKind, string> = { TRANSFER_INTERNAL: '账户转移', ALLOCATE_GOAL: '目标归属', TRANSFER_GOAL: '目标配对转移', PURCHASE_ASSET: '资产购买', REDEEM_ASSET: '资产赎回', MATURE_ASSET: '到期本金回收', PAY_RECURRING: '负债支付' };
function kind(raw: unknown): NativeActivityKind { if (!kinds.includes(raw as NativeActivityKind)) throw new Error('活动原件的资金类型不受支持'); return raw as NativeActivityKind; }
export function parseNativeActivity(raw: unknown): NativeActivityItem {
  const a = nfObject(raw); nfClosed(a, ['id', 'kind', 'aggregate_id', 'aggregate_version', 'created_at', 'operation_family', 'operation_kind', 'receipt_id']);
  if (a.operation_family != null && a.operation_family !== 'NATIVE' && a.operation_family !== 'LEGACY') throw new Error('活动所属协议不受支持');
  const result: NativeActivityItem = { id: templateID(a.id), kind: nfText(a.kind), aggregate_id: templateID(a.aggregate_id), aggregate_version: nfInt(a.aggregate_version, 1), created_at: nfTime(a.created_at), operation_family: a.operation_family as NativeActivityItem['operation_family'], operation_kind: a.operation_kind == null ? undefined : kind(a.operation_kind), receipt_id: a.receipt_id == null ? undefined : templateID(a.receipt_id) };
  if (result.receipt_id && (result.operation_family !== 'NATIVE' || result.kind !== 'NATIVE_OPERATION_SETTLED' || !result.operation_kind)) throw new Error('活动回执引用与结清事件不一致');
  return result;
}
export function parseNativeActivityPage(raw: unknown): NativeActivityPage {
  const p = nfObject(raw); nfClosed(p, ['items', 'next_cursor', 'as_of', 'total', 'returned', 'has_more', 'verification_scope']);
  const items = nfList(p.items, parseNativeActivity, 20), total = nfInt(p.total), returned = nfInt(p.returned, 0, 20), next = p.next_cursor == null ? undefined : nfText(p.next_cursor, 2048);
  nfUnique(items.map((a) => a.id));
  if (p.verification_scope !== 'ACTIVITY_MEMBERSHIP_SNAPSHOT' || typeof p.has_more !== 'boolean' || returned !== items.length || total < returned || (p.has_more && (!next || !returned)) || (!p.has_more && next)) throw new Error('活动分页快照边界不完整');
  return { items, total, returned, has_more: p.has_more, next_cursor: next, as_of: nfTime(p.as_of), verification_scope: p.verification_scope };
}
function sameEvent(left: NativeActivityItem, right: NativeActivityItem) { return left.id === right.id && left.kind === right.kind && left.aggregate_id === right.aggregate_id && left.aggregate_version === right.aggregate_version && Date.parse(left.created_at) === Date.parse(right.created_at) && left.operation_family === right.operation_family && left.operation_kind === right.operation_kind && left.receipt_id === right.receipt_id; }
function bankAuthorityID(raw: unknown) { const id = nfText(raw, 128); if (!/^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$/.test(id)) throw new Error('保留银行角色的对象引用不完整'); return id; }
export function parseNativeActivityOriginal(raw: unknown, client: Client, event: NativeActivityItem): NativeActivityOriginal {
  nfTree(raw); const v = nfObject(raw); nfClosed(v, ['protocol', 'verification_scope', 'verified_at', 'activity', 'operation', 'receipt', 'original_hash', 'bank_request_hash', 'bank_effect_hash', 'bank_authority']);
  if (v.protocol !== 'native-activity-original-v1' || v.verification_scope !== 'RETAINED_BANK_RESULT_AND_LOCAL_POSTINGS_VERIFIED_NOT_LIVE_BANK_QUERY' || v.bank_authority !== false) throw new Error('活动原件核对范围不受支持');
  const activity = parseNativeActivity(v.activity), op = nfObject(v.operation), receipt = nfObject(v.receipt), result = nfObject(receipt.bank_result), request = nfObject(result.request), effect = nfObject(request.effect);
  nfClosed(op, ['id', 'group_id', 'child_number', 'kind', 'state', 'amount_cents', 'bank_key', 'bank_observed_status', 'processing_health', 'receipt_id', 'version', 'created_at', 'updated_at']);
  nfClosed(receipt, ['protocol', 'id', 'operation_id', 'group_id', 'journal_id', 'bank_result', 'recorded_at']);
  nfClosed(result, ['protocol', 'status', 'namespace', 'key', 'user_id', 'request', 'request_hash', 'sequence', 'version', 'accepted_at', 'available_at', 'settled_at', 'rejection_code', 'absence_is_final', 'position', 'principal_return', 'postings']);
  nfClosed(request, ['protocol', 'namespace', 'key', 'operation_id', 'user_id', 'permit_id', 'reference_hash', 'requested_at', 'expires_at', 'effect', 'authorities', 'cost_consent']);
  const operationID = templateID(op.id), receiptID = templateID(receipt.id), operationKind = kind(op.kind), amount = nfMoney(op.amount_cents, true);
  templateID(op.group_id); templateID(receipt.journal_id); templateID(request.permit_id); nfHash(request.reference_hash); nfHash(v.original_hash); nfHash(v.bank_effect_hash); nfInt(op.child_number, 1, 16); nfInt(op.version, activity.aggregate_version); nfInt(result.sequence, 1); nfInt(result.version, 1);
  nfTime(op.created_at); nfTime(op.updated_at); nfTime(request.requested_at); nfTime(request.expires_at); nfText(op.processing_health);
  if (!sameEvent(activity, event) || activity.operation_family !== 'NATIVE' || !activity.receipt_id || activity.operation_kind !== operationKind || receipt.protocol !== 'native-receipt-v1' || op.state !== 'SETTLED' || op.bank_observed_status !== 'SETTLED' || activity.aggregate_id !== operationID || receipt.operation_id !== operationID || request.operation_id !== operationID || op.receipt_id !== receiptID || activity.receipt_id !== receiptID || op.group_id !== receipt.group_id || op.bank_key !== result.key || result.key !== request.key || result.protocol !== 'zhiyu-bank-v2' || request.protocol !== result.protocol || result.status !== 'SETTLED' || result.namespace !== request.namespace || result.user_id !== client.session?.user_id || request.user_id !== result.user_id || nfHash(result.request_hash) !== nfHash(v.bank_request_hash) || result.absence_is_final !== false || result.rejection_code !== '' || effect.kind !== operationKind || nfMoney(effect.amount_cents, true) !== amount) throw new Error('活动原件跨会话、换键或缺少匹配的结清回执');
  nfText(result.namespace); const funding = parseActionFunding(effect), fee = nfMoney(effect.fee_cents), loss = nfMoney(effect.loss_cents), net = nfMoney(effect.net_cents);
  // These are retained bank-v2 request roles, not current execution authorization.
  const authorities = nfList(request.authorities, (raw) => { const a = nfObject(raw); nfClosed(a, ['role', 'source_id', 'version', 'goal_id', 'policy_id', 'policy_version', 'allows_fee', 'allows_loss']); if (!['EXECUTE', 'GOAL_RELEASE', 'GOAL_RECEIVE', 'POSITION_ORIGINAL'].includes(nfText(a.role)) || typeof a.allows_fee !== 'boolean' || typeof a.allows_loss !== 'boolean') throw new Error('保留银行角色原件不完整'); bankAuthorityID(a.source_id); bankAuthorityID(a.policy_id); if (a.goal_id !== '') bankAuthorityID(a.goal_id); nfInt(a.version, 1); nfInt(a.policy_version, 1); return a; }, 8);
  nfUnique(authorities.map((a) => nfText(a.role)));
  const roles = new Map(authorities.map((a) => [a.role, a])), execute = roles.get('EXECUTE');
  if (!execute || (['REDEEM_ASSET', 'MATURE_ASSET'].includes(operationKind) && !roles.has('POSITION_ORIGINAL'))) throw new Error('缺少原银行角色证据');
  if (operationKind === 'TRANSFER_GOAL') {
    const source = templateID(effect.source_goal_id), destination = templateID(effect.destination_goal_id); templateID(effect.destination_account_id);
    if (source === destination || roles.get('GOAL_RELEASE')?.goal_id !== source || roles.get('GOAL_RECEIVE')?.goal_id !== destination) throw new Error('原目标释放、接收角色与配对目标不一致');
  } else if ((effect.source_goal_id !== '' && execute.goal_id !== effect.source_goal_id) || (effect.destination_goal_id !== '' && execute.goal_id !== effect.destination_goal_id)) throw new Error('原银行角色与目标归属不一致');
  if (request.cost_consent != null) { const c = nfObject(request.cost_consent); nfClosed(c, ['confirmation_id', 'reviewed_effect_hash', 'principal_kind', 'confirmed_at', 'expires_at']); templateID(c.confirmation_id); nfTime(c.confirmed_at); nfTime(c.expires_at); if (c.principal_kind !== 'USER' || nfHash(c.reviewed_effect_hash) !== v.bank_effect_hash) throw new Error('原费用本人确认不匹配'); }
  if (BigInt(fee) + BigInt(loss) > 0n && request.cost_consent == null) throw new Error('有费用或损失的原件缺少本人确认');
  const postings = nfList<NativeActivityPosting>(result.postings, (raw) => { const p = nfObject(raw); nfClosed(p, ['id', 'dimension', 'ledger_id', 'direction', 'amount_cents', 'occurred_at']); if (!['ECONOMIC', 'GOAL_OWNERSHIP', 'INCOME_LOCATION', 'LIABILITY'].includes(nfText(p.dimension)) || (p.direction !== 'DEBIT' && p.direction !== 'CREDIT')) throw new Error('原记账维度或方向不完整'); nfText(p.ledger_id); return { id: nfText(p.id), dimension: p.dimension as NativeActivityPosting['dimension'], direction: p.direction, amount_cents: nfMoney(p.amount_cents, true), occurred_at: nfTime(p.occurred_at) }; }, 1024);
  nfUnique(postings.map((p) => p.id)); if (!postings.length) throw new Error('结清回执缺少实际记账分录');
  for (const dimension of new Set(postings.map((p) => p.dimension))) if (postings.filter((p) => p.dimension === dimension).reduce((sum, p) => sum + (p.direction === 'DEBIT' ? -1n : 1n) * BigInt(p.amount_cents), 0n) !== 0n) throw new Error('原记账分录在同一维度不守恒');
  const settled = nfTime(result.settled_at), recorded = nfTime(receipt.recorded_at);
  if (Date.parse(recorded) !== Date.parse(activity.created_at) || postings.some((p) => Date.parse(p.occurred_at) !== Date.parse(settled))) throw new Error('原活动时间与结清记账时间不一致');
  const optionalID = (raw: unknown) => raw === '' ? undefined : templateID(raw);
  return { activity, operation_id: operationID, receipt_id: receiptID, kind: operationKind, amount_cents: amount, fee_cents: fee, loss_cents: loss, net_cents: net, funding, source_goal_id: optionalID(effect.source_goal_id), destination_goal_id: optionalID(effect.destination_goal_id), destination_account_id: optionalID(effect.destination_account_id), accepted_at: nfTime(result.accepted_at), available_at: nfTime(result.available_at), settled_at: settled, recorded_at: recorded, verified_at: nfTime(v.verified_at), postings, historical_cost_consent: request.cost_consent != null };
}
export class NativeActivityClient {
  constructor(readonly client: Client) {}
  async page(cursor = '', signal?: AbortSignal): Promise<NativeActivityPage> { return parseNativeActivityPage(await this.client.request(`/activities?limit=20${cursor ? `&cursor=${encodeURIComponent(cursor)}` : ''}`, { signal })); }
  async original(event: NativeActivityItem, signal?: AbortSignal): Promise<NativeActivityOriginal> { if (event.operation_family !== 'NATIVE' || !event.receipt_id) throw new Error('这条活动尚无可独立核对的原银行回执'); return parseNativeActivityOriginal(await this.client.request(`/activities/${encodeURIComponent(templateID(event.id))}/original`, { signal }), this.client, event); }
}
