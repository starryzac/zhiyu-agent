import { useEffect, useMemo, useState } from 'react';
import { AgentClient } from './agent';
import NativeGrantRead from './NativeGrantRead';
import type { AgentResult, AgentStatus, OfflineTool, AgentReference } from './agent';
import { Client, stateText } from './api';
import type { Dashboard } from './api';
import { money } from './money';
import { timestamp, userError } from './display';
import TemplateEditor, { defaultTemplate } from './TemplateEditor';
import { parseConfiguration, templateLabels, templateNames } from './template-schema';
import type { TemplateConfiguration, TemplateName } from './template-schema';

export default function AgentPanel({ client, data, onOpenPolicyForm }: { client: Client; data: Dashboard; onOpenPolicyForm: (goalID: string) => void }) {
  const agent = useMemo(() => new AgentClient(client), [client]);
  const [status, setStatus] = useState<AgentStatus | null>(null);
  const [tool, setTool] = useState<OfflineTool>('policy_candidate');
  const [goalID, setGoalID] = useState(data.goals[0]?.id ?? '');
  const [operationID, setOperationID] = useState(data.operations[0]?.id ?? '');
  const [question, setQuestion] = useState('');
  const [result, setResult] = useState<AgentResult | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const [templateName, setTemplateName] = useState<TemplateName>('EmergencyBufferPolicy');
  const [configuration, setConfiguration] = useState<TemplateConfiguration>(() => defaultTemplate('EmergencyBufferPolicy', data));
  const [originalRef, setOriginalRef] = useState<AgentReference | null>(null);
  useEffect(() => { let active = true; agent.status().then((value) => { if (active) setStatus(value); }).catch((cause: unknown) => { if (active) setError(userError(cause)); }); return () => { active = false; }; }, [agent]);
  const needsGoal = tool === 'policy_candidate' || tool === 'goal_status' || tool === 'template_candidate' && templateName === 'LongTermGoalPolicy';
  const selectedID = needsGoal ? goalID : tool === 'operation_status' ? operationID : '';
  const missing = (needsGoal && !data.goals.some((goal) => goal.id === goalID)) || (tool === 'operation_status' && !data.operations.some((operation) => operation.id === operationID)) || tool === 'object_status' && !originalRef;
  const localGrantRead = tool === 'native_grants' || tool === 'object_status' && (originalRef?.kind === 'NATIVE_GRANT' || originalRef?.kind === 'NATIVE_GRANTS');
  async function read(mode: 'OFFLINE' | 'MODEL' = 'OFFLINE') {
    if (busy || (mode === 'OFFLINE' ? missing : !status?.provider_configured || !question.trim())) return;
    setBusy(true); setError(''); setResult(null);
    try { const args = tool === 'template_candidate' ? { template_name: templateName, configuration: parseConfiguration(templateName, configuration), ...(templateName === 'LongTermGoalPolicy' ? { goal_id: goalID } : {}) } : tool === 'object_status' && originalRef ? { reference: originalRef } : undefined; setResult(mode === 'OFFLINE' ? await agent.offline(tool, selectedID, data, args) : await agent.model(question, data)); } catch (cause) { setError(userError(cause)); } finally { setBusy(false); }
  }
  return <section className="zy-card" aria-label="知余助手">
    <div className="zy-section-heading"><h2>知余助手</h2><span className="zy-status zy-status-plain">{result ? result.mode === 'MODEL' ? 'DeepSeek · MODEL' : '离线工具 · OFFLINE' : '只读工具与草稿'}</span></div>
    <p>读取当前事实、整理目标规则草稿。规则、持续授权和执行分别由你明确确认。</p>
    <p className="zy-muted">{!status ? '模型配置尚待读取核实。' : status.provider_configured ? 'DeepSeek 已配置，不会自动调用。每次由你明确提交问题。' : '当前未配置模型。'}真实 Provider：{status?.provider_status === 'NOT_RUN' ? '未运行 · NOT_RUN' : status ? '已配置，本次调用结果见下方记录' : '读取配置状态中…'}</p>
    <form onSubmit={(event) => { event.preventDefault(); void read(); }}>
      <label className="zy-field">想整理什么<select disabled={busy} value={tool} onChange={(event) => { setTool(event.target.value as OfflineTool); setResult(null); }}><option value="policy_candidate">整理单目标规则草稿</option><option value="template_candidate">整理十二类规则条件候选</option><option value="template_catalog">查看十二类规则字段</option><option value="native_rules">读取现行原生规则</option><option value="native_grants">读取原生持续授权（只读）</option><option value="forecast365">读取 365 天现金保护预测</option><option value="joint_preview">只读联合计算全部目标</option><option value="original_objects">读取近期原计划、操作与问题</option><option value="object_status">按原对象引用核对</option><option value="funds_summary">读取账户事实</option><option value="current_rules">读取简式单目标规则与授权</option><option value="goal_status">读取已有目标进度</option><option value="operation_status">核对近期原操作</option></select></label>
      {tool === 'template_candidate' && <fieldset disabled={busy}><legend>条件候选配置</legend><p>这里只整理 IF_USER_CONFIRMED 候选。现行目标规则变版、收款对象或资产范围的确认，请到规则页审阅。</p><label className="zy-field">规则类别<select value={templateName} onChange={(event) => { const name = event.target.value as TemplateName; setTemplateName(name); setConfiguration(defaultTemplate(name, data)); setResult(null); }}>{templateNames.map((name) => <option value={name} key={name}>{templateLabels[name]}</option>)}</select></label><TemplateEditor configuration={configuration} onChange={(value) => { setConfiguration(value); setResult(null); }} dashboard={data} policies={[]} disabled={busy} /></fieldset>}
      {localGrantRead && <p className="zy-muted">原生持续授权通过本地只读工具核对，本次不向模型发送授权资料。</p>}
      {tool === 'object_status' && <p className="zy-muted">{originalRef ? `已选择原引用 ${originalRef.kind} · ${originalRef.id}` : '先读取规则、目标或联合观察，再点击其“核对这个原对象”。'}此读取不会重试原操作。</p>}
      {needsGoal && <label className="zy-field">当前本人目标<select disabled={busy} value={goalID} onChange={(event) => { setGoalID(event.target.value); setResult(null); }}>{data.goals.map((goal) => <option value={goal.id} key={goal.id}>{goal.name}</option>)}</select></label>}
      {tool === 'operation_status' && <label className="zy-field">近期原操作<select disabled={busy} value={operationID} onChange={(event) => { setOperationID(event.target.value); setResult(null); }}>{data.operations.map((operation) => <option value={operation.id} key={operation.id}>{money(operation.amount_cents)} · {stateText[operation.state]} · {operation.id.slice(0, 8)}</option>)}</select></label>}
      {missing && <p className="zy-muted">当前没有可选的{needsGoal ? '目标' : '近期原操作'}。可在目标或活动页继续查看原记录。</p>}
      <button className="zy-secondary" disabled={busy || missing}>{busy ? '正在读取真实业务对象…' : '读取并整理'}</button>
    </form>
    {status?.provider_configured && !localGrantRead && <form aria-label="DeepSeek提问" onSubmit={(event) => { event.preventDefault(); void read('MODEL'); }}>
      <h3>向 DeepSeek 提问</h3><p className="zy-muted">本轮最多 3 次调用、20 秒，费用预留上限 USD 0.02。只整理已有对象与草稿，不代你确认或付款。</p>
      <label className="zy-field">本次问题<textarea rows={3} maxLength={1024} disabled={busy} value={question} onChange={(event) => { setQuestion(event.target.value); setResult(null); }} placeholder="例如：帮我整理这个目标的规则草稿" required /></label>
      <button className="zy-secondary" disabled={busy || !question.trim()}>提交本次 DeepSeek 问题</button>
    </form>}
    {error && <p className="zy-message zy-error" role="alert">{error} 你仍可使用四页中的结构化表单继续主链。</p>}
    {busy && <p role="status">正在按当前会话读取，尚未确认或提交任何资金安排。</p>}
    {result && <div aria-live="polite">
      <p className="zy-muted">{result.mode === 'OFFLINE' ? '本次模式：离线 · OFFLINE；Provider 未运行 · NOT_RUN' : '本次模式：DeepSeek · MODEL；Provider 已调用 · CALLED'}；模型调用 {result.budget.provider_calls} 次。</p>
      {result.mode === 'MODEL' && <p className="zy-muted">最坏预留：{result.budget.reserved_tokens} tokens / USD {`${BigInt(result.budget.reserved_cost_micros) / 1000000n}.${(BigInt(result.budget.reserved_cost_micros) % 1000000n).toString().padStart(6, '0')}`}；Provider 回报实际输入 {result.provider_usage!.input_tokens}、输出 {result.provider_usage!.output_tokens} tokens。预留不按自报用量退回，账单以提供方为准。</p>}
      {result.observations.map((observation, index) => <article className="zy-candidate" key={`${observation.tool}-${index}`}><p>{observation.summary}</p>
        {observation.accounts.map((account) => <p key={account.id}>{account.name}：账面余额 {money(account.balance_cents)}，目标归属 {money(account.goal_owned_cents)}</p>)}
        {observation.goals.map((goal) => <p key={goal.id}>{goal.name}：已归属 {money(goal.assigned_cents)} / 目标 {money(goal.target_cents)}</p>)}
        {observation.operations.map((operation) => <p key={operation.id}>{money(operation.amount_cents)} · {stateText[operation.state]} · 回执 {operation.receipt_id ?? '尚未生成'}</p>)}
        {observation.catalog?.map((entry) => <p key={entry.template_name}>{templateLabels[entry.template_name]} · {entry.fields.join('、')}</p>)}
        {observation.native_rules?.map((rule) => <p key={rule.version_id}>{templateLabels[rule.compiled.template_name]} · 版本 {rule.version} · {rule.effective_state}<br/><code>{rule.compiled.configuration_hash}</code></p>)}
        {(observation.native_grants || observation.native_grant) && <NativeGrantRead collection={observation.native_grants} grant={observation.native_grant} refs={observation.references} disabled={busy} onInspect={(ref) => { setOriginalRef(ref); setTool('object_status'); }} />}
        {observation.forecast && <div><p>当前预测：{observation.forecast.state}</p>{observation.forecast.result && <p>今日严格余量 {money(observation.forecast.result.current_safe_cents)}；最大保护缺口 {money(observation.forecast.result.maximum_deficit_cents)}；已核对 {observation.forecast.result.points.length} 个保护点。</p>}{!observation.forecast.result && <p>资料尚不完整，未返回可用金额。{observation.forecast.reasons.join('、')}</p>}</div>}
        {observation.joint && <div><p>联合只读结果：{observation.joint.state} · 未登记执行计划</p>{observation.joint.allocations.map((a) => <p key={a.goal_id}>{data.goals.find((g) => g.id === a.goal_id)?.name ?? a.goal_id}：条件投入 {money(a.amount_cents)}，最低要求缺口 {money(a.minimum_shortfall_cents)}</p>)}{observation.joint.reasons.map((reason) => <p key={reason}>{reason}</p>)}</div>}
        {observation.objects?.map((o) => <details key={`${o.kind}-${o.id}`}><summary>{o.kind} · {o.id.slice(0, 8)}</summary><pre className="zy-code">{JSON.stringify(o.data, null, 2)}</pre></details>)}
        {observation.object && <details><summary>原对象当前元数据</summary><pre className="zy-code">{JSON.stringify(observation.object.data, null, 2)}</pre></details>}
        <p className="zy-muted">当前显示快照：{timestamp(observation.as_of)}；提交时仍须重新核验。</p>
        <details><summary>查看当前对象引用</summary>{observation.references.map((ref, i) => <div className="zy-code" key={`${ref.kind}-${ref.id}-${i}`}><p>{ref.kind} · {ref.id}<br/>SHA-256：{ref.digest}</p>{!['ACCOUNTS', 'RULES', 'NATIVE_CONTEXT', 'NATIVE_GRANT', 'NATIVE_GRANTS'].includes(ref.kind) && <button className="zy-secondary" disabled={busy} onClick={() => { setOriginalRef(ref); setTool('object_status'); }}>核对这个原对象</button>}</div>)}</details>
      </article>)}
      {result.candidate && <button className="zy-primary" onClick={() => onOpenPolicyForm(result.candidate!.goal_id)}>前往规则表单，亲自填写并确认</button>}
      {result.native_candidate && <article className="zy-candidate"><h3>{templateLabels[result.native_candidate.compiled.template_name]} · 条件候选</h3><p>IF_USER_CONFIRMED · {result.native_candidate.state} · 尚未确认、生效或执行。</p>{result.native_candidate.amount_cents !== undefined && <p>确定性预览金额 {money(result.native_candidate.amount_cents)}</p>}<p>{result.native_candidate.reasons.join('、')}</p><details><summary>查看本次编译配置</summary><pre className="zy-code">{JSON.stringify(result.native_candidate.compiled.configuration, null, 2)}</pre></details><button className="zy-primary" onClick={() => onOpenPolicyForm(result.native_candidate!.goal_id ?? goalID)}>前往规则页，重新预览并亲自确认</button></article>}
    </div>}
  </section>;
}
