import type { AgentReference } from './agent';
import type { AgentNativeGrant, AgentNativeGrantCollection, GrantReason } from './agent-native-grants';
import { money } from './money';
import { timestamp } from './display';

const familyNames = { SINGLE_GOAL: '单目标持续授权', JOINT_GOALS: '联合目标持续授权', ASSET_ALLOCATION: '资产安排持续授权', MATURITY_REINVEST: '到期再投持续授权', PERIODIC_PAYMENT: '周期付款持续授权' };
const states = { ACTIVE: '记录为启用', PAUSED: '记录为暂停', REVOKED: '记录为撤销' };
const effective = { REVOKED: '已撤销', EXPIRED: '已到期', PAUSED: '已暂停', NOT_YET_EFFECTIVE: '尚未到生效时间', POLICY_CHANGED: '原规则版本或状态已变化', UNAVAILABLE: '有效性资料不足', CURRENT_DISPLAY_ONLY: '当前记录可核对，仅供展示' };
const reasons: Record<GrantReason, string> = { CAPACITY: '读取超出当前容量', SCHEMA_UNAVAILABLE: '读取来源尚未具备', EVIDENCE_INVALID: '原件或状态链无法完整核实', SUBJECT_UNAVAILABLE: '历史会话主体资料不足', SESSION_EXPIRED_AT_EVENT: '历史事件不在会话有效期内', SESSION_REVOCATION_HISTORY_UNAVAILABLE: '无法还原历史会话撤销时间', POLICY_CHANGED: '原规则版本或状态已变化', POLICY_UNAVAILABLE: '原规则资料不足', NOT_YET_EFFECTIVE: '尚未到生效时间', EXPIRED: '已到期', PAUSED: '已暂停', REVOKED: '已撤销' };

function GrantCard({ grant, refs, onInspect, disabled }: { grant: AgentNativeGrant; refs: AgentReference[]; onInspect: (ref: AgentReference) => void; disabled: boolean }) {
  const ref = refs.find((value) => value.kind === 'NATIVE_GRANT' && value.id === grant.id);
  return <article className="zy-candidate" aria-label={`原生授权 ${grant.id}`}>
    <h4>{familyNames[grant.family]}</h4>
    <p>{states[grant.recorded_state]}；{effective[grant.effective_state]}。</p>
    <p className="zy-muted">这份只读记录不代表当前可执行权限或可支付金额。</p>
    <dl><dt>授权原对象</dt><dd><code>{grant.id}</code> · 版本 {grant.version} · 状态序号 {grant.state_sequence}</dd>
      <dt>有效时间范围</dt><dd>{timestamp(grant.effective_from)} 至 {timestamp(grant.expires_at)}</dd>
      <dt>本次评估日期</dt><dd>{grant.evaluated_local_date} · {grant.timezone}</dd>
      <dt>原约定限额</dt><dd>单次 {money(grant.single_cap_cents)}；累计 {money(grant.lifetime_cap_cents)}；每月 {money(grant.monthly_cap_cents)}</dd></dl>
    {grant.reason_codes.map((code) => <p key={code}>{reasons[code]}</p>)}
    <details><summary>查看原约定范围与摘要</summary>
      <p>账户：{grant.account_ids.join('、')}；目标：{grant.goal_ids.length ? grant.goal_ids.join('、') : '未绑定目标'}。</p>
      <p>产品：{grant.product_ids.length ? grant.product_ids.join('、') : '未绑定产品'}；收款对象：{grant.payee_ids.length ? grant.payee_ids.join('、') : '未绑定收款对象'}。</p>
      {grant.policy_references.map((policy) => <p key={policy.version_id}>原规则 {policy.policy_id} · 版本 {policy.version} · <code>{policy.configuration_hash}</code></p>)}
      <p>原件摘要：<code>{grant.original_digest}</code></p><p>条款摘要：<code>{grant.terms_digest}</code></p><p>完整状态链摘要：<code>{grant.chain_digest}</code></p>
    </details>
    {ref && <button type="button" className="zy-secondary" disabled={disabled} onClick={() => onInspect(ref)}>核对这份原生授权</button>}
  </article>;
}

export default function NativeGrantRead({ collection, grant, refs, onInspect, disabled }: { collection?: AgentNativeGrantCollection; grant?: AgentNativeGrant; refs: AgentReference[]; onInspect: (ref: AgentReference) => void; disabled: boolean }) {
  return <section aria-label="原生持续授权只读结果">
    <h3>{grant ? '原生持续授权原对象' : '原生持续授权'}</h3>
    <p className="zy-muted">仅在本地读取核对，本结果不发送给模型。</p>
    {collection?.status === 'UNAVAILABLE' && <div><p>原生持续授权读取不可用；当前数量未知。</p>{collection.reason_codes.map((code) => <p key={code}>{reasons[code]}</p>)}</div>}
    {collection?.status === 'COMPLETE' && <div><p>已完整读取 {collection.count} 条原生持续授权。</p><p className="zy-muted">已核对原件和完整授权状态链；历史会话仅核对已存主体与事件有效期，不能证明缺失的撤销时间窗口。</p>
      {collection.session_verification === 'HISTORY_INCOMPLETE' && <p>历史会话撤销时间资料不足，相关有效性保持未知。</p>}
      {collection.items.map((item) => <GrantCard key={item.id} grant={item} refs={refs} onInspect={onInspect} disabled={disabled} />)}</div>}
    {grant && <GrantCard grant={grant} refs={refs} onInspect={onInspect} disabled={disabled} />}
  </section>;
}
