import { useEffect, useMemo, useRef, useState } from 'react';
import type { FormEvent } from 'react';
import { useQuery, useQueryClient } from '@tanstack/react-query';
import { Client, stateText, terminal } from './api';
import type { Candidate, Dashboard, Operation, Session } from './api';
import { bindOperation, nextPoll, restorePending, savePending } from './recovery';
import type { PendingCommand } from './recovery';
import { money, yuanToCents } from './money';
import { businessState, requiresLogin, timestamp, userError } from './display';
import AgentPanel from './AgentPanel';
import ActivityHistory from './ActivityHistory';
import { GoalManager } from './GoalManager';
import Forecast from './Forecast';
import TemplatePolicies from './TemplatePolicies';
import JointPlanner from './JointPlanner';
import GoalTransfer from './GoalTransfer';
import PaymentsPanel from './PaymentsPanel';
import AssetsPanel from './AssetsPanel';
import HistoryPanel from './HistoryPanel';
import BillSourcesPanel from './BillSourcesPanel';
import NativeGrantsPanel from './NativeGrantsPanel';
import ForecastHistoryPanel from './ForecastHistoryPanel';

const pages = [{ id: 'overview', name: '总览' }, { id: 'policies', name: '我的规则' }, { id: 'goals', name: '目标与执行' }, { id: 'activity', name: '活动记录' }, { id: 'history', name: '历史档案' }];
const SESSION_KEY = 'zhiyu-go:session:v1';
function readSession(): Session | null {
  try {
    const item = JSON.parse(sessionStorage.getItem(SESSION_KEY) ?? 'null') as Session | null;
    return item && ['token', 'csrf_token', 'user_id', 'environment'].every((key) => typeof item[key as keyof Session] === 'string' && item[key as keyof Session]) ? item : null;
  } catch { return null; }
}
function statusTone(state: string): string { return state === 'SETTLED' || state === 'ACTIVE' ? 'good' : ['REJECTED', 'CANCELLED', 'REVOKED'].includes(state) ? 'plain' : 'wait'; }
function Status({ operation }: { operation: Operation }) { return <span className={`zy-status zy-status-${statusTone(operation.state)}`}>{stateText[operation.state]}</span>; }

function OperationCard({ operation }: { operation: Operation }) {
  return <article className="zy-card" aria-label="原操作状态"><div className="zy-section-heading"><h2>{operation.state === 'SETTLED' ? '这笔安排已结清' : '这笔安排的当前状态'}</h2><Status operation={operation} /></div>
    <strong className="zy-amount zy-amount-small">{money(operation.amount_cents)}</strong>
    <p role="status">{operation.state === 'SETTLED' ? '银行结算与本地对账已完成，目标进度以最新服务端读数为准。' : terminal(operation) ? '该操作已终止，结果按原操作记录保留。' : '尚未确认结清，金额未显示为已到账。系统正沿原操作核对，请保留这笔记录。'}</p>
    <dl className="zy-facts"><div><dt>最后更新</dt><dd>{timestamp(operation.updated_at)}</dd></div><div><dt>银行观察</dt><dd>{businessState(operation.bank_observed_status)}</dd></div><div><dt>原回执</dt><dd>{operation.receipt_id ? '已保留，可独立核对' : '尚未生成'}</dd></div></dl>
    {operation.processing_health && <p className="zy-muted">处理情况：{businessState(operation.processing_health)}</p>}
  </article>;
}

export default function App() {
  const [session, setSession] = useState<Session | null>(readSession);
  const [secret, setSecret] = useState('');
  const [page, setPage] = useState(() => location.hash.slice(1).split('/')[0] || 'overview');
  const [pending, setPending] = useState<PendingCommand | null>(null);
  const [recoveryReady, setRecoveryReady] = useState(false);
  const [storageError, setStorageError] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const [notice, setNotice] = useState('');
  const [showAgent, setShowAgent] = useState(false);
  const [goalId, setGoalId] = useState('');
  const [policyId, setPolicyId] = useState('');
  const [policyAmount, setPolicyAmount] = useState('100.00');
  const [grantAmount, setGrantAmount] = useState('100.00');
  const [policyConsent, setPolicyConsent] = useState(false);
  const [grantConsent, setGrantConsent] = useState(false);
  const [executeConsent, setExecuteConsent] = useState(false);
  const [candidate, setCandidate] = useState<Candidate | null>(null);
  const [grantId, setGrantId] = useState('');
  const [mode, setMode] = useState<'ONCE' | 'STANDING'>('ONCE');
  const [selectedOperationId, setSelectedOperationId] = useState(() => location.hash.startsWith('#activity/') ? location.hash.slice('#activity/'.length) : '');
  const main = useRef<HTMLElement>(null);
  const mutationRunning = useRef(false);
  const queryClient = useQueryClient();
  const client = useMemo(() => new Client(session, import.meta.env.VITE_API_BASE ?? '/api/v2'), [session]);
  const scope = session ? `${session.environment}:${session.user_id}` : 'signed-out';
  const dashboard = useQuery({ queryKey: ['dashboard', scope], queryFn: ({ signal }) => client.dashboard(signal), enabled: !!session });
  const operation = useQuery({ queryKey: ['original-operation', scope, pending?.key], enabled: !!session && !!pending && pending.environment === session.environment && pending.user_id === session.user_id && recoveryReady,
    queryFn: async ({ signal }) => { const value = pending!.operation_id ? await client.operation(pending!.operation_id, signal) : await client.command(pending!.key, signal); bindOperation(pending!, value); return value; },
    refetchInterval: (query) => requiresLogin(query.state.error) || (query.state.data && terminal(query.state.data)) ? false : nextPoll(query.state.dataUpdateCount + query.state.fetchFailureCount), refetchIntervalInBackground: false });
  const historical = useQuery({ queryKey: ['historical-operation', scope, selectedOperationId], enabled: !!session && !!selectedOperationId,
    queryFn: ({ signal }) => client.operation(selectedOperationId, signal), refetchInterval: (query) => query.state.data && !terminal(query.state.data) ? nextPoll(query.state.dataUpdateCount) : false });
  const data: Dashboard | undefined = dashboard.data;
  const activePolicies = data?.policies.filter((item) => item.status === 'ACTIVE') ?? [];
  const nativeRules = data?.native?.status === 'CURRENT_LOCAL' ? data.native : null;
  const selectedPolicy = activePolicies.find((item) => item.id === policyId)?.id ?? activePolicies[0]?.id ?? '';
  const usableGrant = !!candidate && !!data?.grants.some((item) => item.id === grantId && item.status === 'ACTIVE' && item.policy_id === candidate.policy_id && BigInt(item.max_amount) >= BigInt(candidate.amount));
  const current = operation.data;
  const unresolved = !!pending && (!current || !terminal(current));
  const blocked = busy || !!storageError || !recoveryReady || unresolved || !data;

  useEffect(() => {
    const navigate = () => { setPage(location.hash.slice(1).split('/')[0] || 'overview'); setSelectedOperationId(location.hash.startsWith('#activity/') ? location.hash.slice('#activity/'.length) : ''); main.current?.focus(); };
    window.addEventListener('hashchange', navigate);
    return () => window.removeEventListener('hashchange', navigate);
  }, []);
  useEffect(() => {
    setRecoveryReady(false); setPending(null); setCandidate(null); setStorageError(''); setShowAgent(false);
    if (session) {
      try { setPending(restorePending(session)); } catch (cause) { setStorageError(userError(cause)); }
    }
    setRecoveryReady(true);
  }, [session]);
  useEffect(() => {
    if (!session || !pending || !current) return;
    try {
      const updated = bindOperation(pending, current);
      if (updated.operation_id !== pending.operation_id) { savePending(session, updated); setPending(updated); }
      if (terminal(current)) void queryClient.invalidateQueries({ queryKey: ['dashboard', scope] });
    } catch (cause) { setStorageError(userError(cause)); }
  }, [current, pending, session, queryClient, scope]);
  useEffect(() => {
    if (candidate && candidate.policy_id !== selectedPolicy) { setCandidate(null); setExecuteConsent(false); }
  }, [candidate, selectedPolicy]);


  async function act(work: () => Promise<void>) {
    if (mutationRunning.current) return;
    mutationRunning.current = true; setBusy(true); setError(''); setNotice('');
    try { await work(); } catch (cause) { setError(userError(cause)); }
    finally { mutationRunning.current = false; setBusy(false); }
  }
  async function refresh() { await queryClient.invalidateQueries({ queryKey: ['dashboard', scope] }); }
  function navigate(id: string) { location.hash = id; }
  function endSession() {
    sessionStorage.removeItem(SESSION_KEY); setSession(null); setPending(null); setCandidate(null);
    setError(''); setNotice('重新登录后，将按保存的原计划和原键继续核对。');
    queryClient.clear();
  }
  async function login(event: FormEvent) {
    event.preventDefault();
    await act(async () => { const value = await client.login(secret); sessionStorage.setItem(SESSION_KEY, JSON.stringify(value)); setSession(value); setSecret(''); setNotice('已进入当前模拟环境。'); });
  }
  async function submitOriginal(original: PendingCommand) {
    if (!session) return;
    savePending(session, original);
    setPending(original);
    try {
      const result = await client.accept(original.key, original.body);
      const updated = bindOperation(original, result);
      savePending(session, updated); setPending(updated);
      queryClient.setQueryData(['original-operation', scope, original.key], result);
      setNotice('已受理，正在核对原操作。');
    } catch (cause) {
      void queryClient.invalidateQueries({ queryKey: ['original-operation', scope, original.key] });
      throw new Error(`${userError(cause)} 原键已保存，将核对这笔原操作。`);
    }
  }
  async function execute() {
    if (!session || !candidate || candidate.policy_id !== selectedPolicy || candidate.status !== 'READY' || blocked || !executeConsent || (mode === 'STANDING' && !usableGrant)) return;
    const original: PendingCommand = { version: 1, environment: session.environment, user_id: session.user_id, key: crypto.randomUUID(), plan: candidate,
      body: { plan_id: candidate.id, mode, ...(mode === 'STANDING' ? { grant_id: grantId } : {}) }, recorded_at: new Date().toISOString() };
    setCandidate(null); setExecuteConsent(false);
    await act(async () => { await submitOriginal(original); });
  }

  return <div className="zy-shell">
    <a className="zy-skip" href="#main-content" onClick={(event) => { event.preventDefault(); main.current?.focus(); }}>跳到当前页面内容</a>
    <header className="zy-header"><a className="zy-brand" href="#overview"><span className="zy-mark" aria-hidden="true">知</span><span><strong>知余</strong><small>把每一笔余裕，留给重要的事</small></span></a><span className="zy-simulation">本地模拟环境</span></header>
    <nav className="zy-nav" aria-label="主导航">{pages.map((item) => <button key={item.id} aria-current={page === item.id ? 'page' : undefined} onClick={() => navigate(item.id)}>{item.name}</button>)}</nav>
    <div className="zy-toolbar"><span>{session ? '当前本人模拟账户' : '登录后读取你的模拟账户'}</span>{session && <button className="zy-link" disabled={busy} onClick={endSession}>退出会话</button>}</div>
    {error && <p className="zy-message zy-error" role="alert">{error}</p>}{notice && <p className="zy-message" role="status">{notice}</p>}
    {session && [dashboard.error, operation.error, historical.error].some(requiresLogin) && <aside className="zy-recovery"><div><h2>请重新核对会话</h2><p>原计划和原键继续保留。重新登录同一用户后恢复原操作查询。</p></div><button className="zy-secondary" disabled={busy} onClick={endSession}>重新登录</button></aside>}
    {storageError && <p className="zy-message zy-error" role="alert">{storageError} 为保留原操作，新的安排已暂停。</p>}
    <main className="zy-content" id="main-content" ref={main} tabIndex={-1}>
      {!session ? <section className="zy-card login-card"><div className="zy-kicker">欢迎来到知余</div><h1>给重要的目标，<br/>留一份安心的余裕。</h1><p>输入本地会话码，查看模拟资金与当前规则。</p><form onSubmit={(event) => { void login(event); }}><label className="zy-field">会话码<input type="password" autoComplete="off" value={secret} onChange={(event) => setSecret(event.target.value)} required /></label><button className="zy-primary" disabled={busy || !secret}>进入模拟环境</button></form></section>
        : dashboard.isPending ? <p className="zy-message" role="status">正在读取账户与规则…</p>
          : dashboard.isError ? <section className="zy-card"><h1>暂时无法读取当前账户</h1><p role="alert">{userError(dashboard.error)}</p><button className="zy-secondary" onClick={() => { void dashboard.refetch(); }}>重新读取</button></section>
            : data && <>
              {data.projection.status !== 'CURRENT' && <div className="zy-message" role="status">{data.projection.status === 'DELAYED' ? '活动摘要仍在更新，以下安排列表可能落后。' : '活动摘要尚未核对完成。'} 原操作仍可按保存的编号独立查询。<button className="zy-link" disabled={busy} onClick={() => void act(async () => { await client.rebuildProjection(); await refresh(); setNotice('活动摘要已重新核对。'); })}>重新核对活动摘要</button></div>}
              {unresolved && <aside className="zy-recovery"><div><h2>原操作仍在核对</h2><p>{pending.body.mode === 'STANDING' && data.grants.some((grant) => grant.id === pending.body.grant_id && grant.status === 'REVOKED') ? '持续授权已撤销，原操作仍需沿原键核对，不会因撤销被写成无效果。' : '保留原计划与原键，新的资金安排暂缓。'}</p><p className="zy-code">{pending.key}</p></div><button className="zy-secondary" disabled={operation.isFetching || requiresLogin(operation.error)} onClick={() => { void operation.refetch(); }}>核对原操作</button></aside>}
              {operation.isError && <section className="zy-card"><p role="alert">原操作查询尚未完成：{userError(operation.error)}</p><p>未查到结果不代表没有发生效果。继续查询同一原键，或明确重试这笔原提交。</p><button className="zy-secondary" disabled={busy || operation.isFetching || !!storageError || requiresLogin(operation.error)} onClick={() => { if (pending) void act(() => submitOriginal(pending)); }}>按保存的原键重试提交</button></section>}
              {current && !(page === 'activity' && historical.data?.id === current.id) && <OperationCard operation={current} />}
              {!pages.some((item) => item.id === page) && <section className="zy-card"><h1>找不到这个页面</h1><p>原操作记录仍保留，可以从总览或活动记录继续查看。</p><button className="zy-secondary" onClick={() => navigate('overview')}>返回总览</button></section>}
              {page === 'overview' && (showAgent ? <AgentPanel client={client} data={data} onOpenPolicyForm={(id) => { setGoalId(id); setPolicyConsent(false); setGrantConsent(false); setExecuteConsent(false); setCandidate(null); navigate('policies'); }} /> : <section className="zy-card"><h2>知余助手</h2><p>依据当前本人对象整理规则草稿，或核对目标与原操作。</p><button className="zy-secondary" onClick={() => setShowAgent(true)}>打开助手</button></section>)}
              {page === 'overview' && <><section className="zy-hero"><div className="zy-kicker">每一笔安排，都有来处</div><h1>照顾好现在，<br/>也慢慢靠近未来。</h1><p>从可信到账出发，按你确认的规则，为重要的目标留出空间。</p></section><section className="zy-boundary"><div><div className="zy-kicker">当前账户余额</div><strong className="zy-amount">{data.accounts.length ? money(data.accounts.reduce((sum, account) => sum + BigInt(account.balance_cents), 0n).toString()) : '等待账户事实'}</strong><p>这是账户余额，实际可安排金额由服务端按当前事实核定。</p></div><div className="zy-boundary-next"><span>{data.goals.length ? `${data.goals.length} 个目标正在这里` : '还没有可读取的目标'}</span><button className="zy-primary" onClick={() => navigate('goals')}>查看目标与安排</button></div></section><section className="zy-metrics"><article><span>目标已归属</span><strong>{money(data.goals.reduce((sum, goal) => sum + BigInt(goal.assigned_cents), 0n).toString())}</strong><p>目标归属是现有资产的分类</p></article><article><span>现行规则</span><strong>{nativeRules ? activePolicies.length + nativeRules.active_policy_count : '未确认'}</strong><p>{nativeRules ? `生效规则合计；单目标生效 ${activePolicies.length} 条，模板当前 ${nativeRules.current_policy_count} 条，其中生效 ${nativeRules.active_policy_count} 条。` : `单目标生效 ${activePolicies.length} 条；模板规则尚未读取完整。`}</p></article><article><span>待核对安排</span><strong>{data.operations.filter((item) => !terminal(item)).length}</strong><p>受理中的安排尚未计为到账</p></article></section>{data.accounts.map((account) => <article className="zy-card" key={account.id}><h2>{account.name}</h2><strong className="zy-event-amount">{money(account.balance_cents)}</strong><p className="zy-muted">其中目标归属 {money(account.goal_owned_cents)}</p></article>)}</>}
              {page === 'policies' && <>{!data.policies.length && nativeRules?.current_policy_count === 0 && <p className="zy-message">当前还没有规则。选择已有目标并明确确认后，才能生成计划。</p>}{!nativeRules && <p className="zy-message" role="status">模板规则尚未读取完整，暂不能确认当前规则总数。单目标规则已读取 {data.policies.length} 条。</p>}<section className="zy-page-title"><div className="zy-kicker">由你确认，按规则安排</div><h1>我的规则</h1><p>模型和文字建议不会替你确认规则或授予执行权限。</p></section><section className="zy-card"><h2>确认单目标规则</h2><form onSubmit={(event) => { event.preventDefault(); if (!policyConsent || blocked) return; void act(async () => { const amount = yuanToCents(policyAmount); setPolicyConsent(false); await client.createPolicy(goalId || data.goals[0]?.id || '', amount); await refresh(); setNotice('规则已确认，请独立读取当前状态。'); }); }}><label className="zy-field">目标<select value={goalId || data.goals[0]?.id || ''} onChange={(event) => { setGoalId(event.target.value); setPolicyConsent(false); }} required>{data.goals.map((goal) => <option key={goal.id} value={goal.id}>{goal.name}</option>)}</select></label><label className="zy-field">单次上限（元）<input inputMode="decimal" value={policyAmount} onChange={(event) => { setPolicyAmount(event.target.value); setPolicyConsent(false); }} required /></label><label className="zy-check"><input type="checkbox" checked={policyConsent} onChange={(event) => setPolicyConsent(event.target.checked)} />我确认这条目标规则及单次上限。</label><button className="zy-primary" disabled={blocked || !policyConsent || !data.goals.length}>确认规则</button></form></section>
                {data.policies.map((item) => <article className="zy-card" key={item.id}><div className="zy-section-heading"><h2>{data.goals.find((goal) => goal.id === item.scope.goal_id)?.name ?? '原目标'}的储备规则</h2><span className={`zy-status zy-status-${statusTone(item.status)}`}>{businessState(item.status)}</span></div><p>单次最多 {money(item.max_amount)}</p><p className="zy-muted">有效期至 {timestamp(item.valid_until)}</p></article>)}
                <ForecastHistoryPanel client={client} onChanged={refresh} />
                <TemplatePolicies client={client} dashboard={data} onChanged={refresh} />
                <NativeGrantsPanel client={client} dashboard={data} onChanged={refresh} />
                <section className="zy-card"><h2>明确持续授权</h2><form onSubmit={(event) => { event.preventDefault(); if (!grantConsent || blocked) return; void act(async () => { const amount = yuanToCents(grantAmount); setGrantConsent(false); await client.createGrant(selectedPolicy, amount); await refresh(); setNotice('持续授权已保存，可在下方回读或撤销。'); }); }}><label className="zy-field">规则<select value={selectedPolicy} onChange={(event) => { setPolicyId(event.target.value); setGrantConsent(false); setExecuteConsent(false); }} required>{activePolicies.map((item) => <option key={item.id} value={item.id}>{data.goals.find((goal) => goal.id === item.scope.goal_id)?.name ?? item.id}</option>)}</select></label><label className="zy-field">授权单次上限（元）<input inputMode="decimal" value={grantAmount} onChange={(event) => { setGrantAmount(event.target.value); setGrantConsent(false); }} required /></label><label className="zy-check"><input type="checkbox" checked={grantConsent} onChange={(event) => setGrantConsent(event.target.checked)} />我明确授权系统按这条规则安排符合条件的到账资金，且受上述单次上限约束。</label><button className="zy-primary" disabled={blocked || !grantConsent || !data.policies.some((item) => item.status === 'ACTIVE')}>确认持续授权</button></form></section>
                {data.grants.map((item) => <article className="zy-card" key={item.id}><h2>持续授权</h2><p>{businessState(item.status)} · 单次最多 {money(item.max_amount)}</p>{item.status === 'ACTIVE' && <button className="zy-secondary" disabled={busy} onClick={() => { void act(async () => { await client.revoke(item.id); await refresh(); setNotice('授权已撤销。已在途的原操作仍会沿原键核对。'); }); }}>撤销这条授权</button>}</article>)}</>}
              {page === 'goals' && <><section className="zy-page-title"><div className="zy-kicker">每一步，都向目标靠近</div><h1>目标与执行</h1><p>先读取当前可行计划，再明确确认这一笔安排。</p></section>{!data.goals.length && <section className="zy-card"><p>当前环境还没有目标，请先完成环境准备。</p></section>}{data.goals.map((goal) => <article className="zy-card" key={goal.id}><h2>{goal.name}</h2><strong className="zy-amount zy-amount-small">{money(goal.assigned_cents)}</strong><p>目标 {money(goal.target_cents)}</p><div className="progress-track" aria-label={`${goal.name}的进度`}><span style={{ width: `${BigInt(goal.target_cents) > 0n ? (BigInt(goal.assigned_cents) * 10000n / BigInt(goal.target_cents) > 10000n ? 100 : Number(BigInt(goal.assigned_cents) * 10000n / BigInt(goal.target_cents)) / 100) : 0}%` }} /></div></article>)}
                <GoalManager key={scope} client={client} scope={scope} data={data} onChanged={refresh} />
                <JointPlanner client={client} dashboard={data} onChanged={refresh} />
                <GoalTransfer client={client} dashboard={data} onChanged={refresh} />
                <BillSourcesPanel client={client} onChanged={refresh} />
                <PaymentsPanel client={client} dashboard={data} onChanged={refresh} />
                <AssetsPanel client={client} dashboard={data} onChanged={refresh} />
                <Forecast client={client} dashboard={data} onChanged={refresh} />
                <section className="zy-card"><h2>读取本次计划</h2><label className="zy-field">已确认的规则<select value={selectedPolicy} onChange={(event) => { setPolicyId(event.target.value); setCandidate(null); setExecuteConsent(false); }}>{activePolicies.map((item) => <option key={item.id} value={item.id}>{data.goals.find((goal) => goal.id === item.scope.goal_id)?.name ?? item.id}</option>)}</select></label><button className="zy-secondary" disabled={blocked || !data.policies.some((item) => item.status === 'ACTIVE')} onClick={() => { void act(async () => { setCandidate(await client.plan(selectedPolicy)); setExecuteConsent(false); }); }}>按当前事实生成计划</button>
                  {candidate && <div className="zy-candidate"><h3>本次可安排 {money(candidate.amount)}</h3><p>目标：{data.goals.find((goal) => goal.id === data.policies.find((item) => item.id === candidate.policy_id)?.scope.goal_id)?.name ?? '等待核对原目标'}</p><p>当前安全上限 {money(candidate.max_safe)} · 计划状态 {businessState(candidate.status)}</p><p className="zy-muted">有效期至 {timestamp(candidate.valid_until)}。提交时系统还会重新核对。</p><label className="zy-field">执行方式<select value={mode} onChange={(event) => { setMode(event.target.value as 'ONCE' | 'STANDING'); setExecuteConsent(false); }}><option value="ONCE">只确认这一次</option><option value="STANDING">使用现行持续授权</option></select></label>{mode === 'STANDING' && <label className="zy-field">持续授权<select value={grantId} onChange={(event) => { setGrantId(event.target.value); setExecuteConsent(false); }} required><option value="">选择原授权</option>{data.grants.filter((item) => item.status === 'ACTIVE' && item.policy_id === candidate.policy_id).map((item, index) => <option key={item.id} value={item.id}>第 {index + 1} 份 · 单次最多 {money(item.max_amount)}</option>)}</select></label>}<label className="zy-check"><input type="checkbox" checked={executeConsent} onChange={(event) => setExecuteConsent(event.target.checked)} />我确认按上述金额与目标提交这笔安排。</label><button className="zy-primary" disabled={blocked || candidate.status !== 'READY' || !executeConsent || BigInt(candidate.amount) <= 0n || (mode === 'STANDING' && !usableGrant)} onClick={() => { void execute(); }}>确认并提交安排</button></div>}</section></>}
              {page === 'history' && <><section className="zy-page-title"><div className="zy-kicker">原资料，始终可回看</div><h1>历史档案</h1><p>核对原记录、保留原文件，并按本人审阅建立被动副本。</p></section><HistoryPanel key={scope} client={client} /></>}
              {page === 'activity' && <><section className="zy-page-title"><div className="zy-kicker">每一笔，都能回头核对</div><h1>活动记录</h1><p>已受理与已结清分别呈现，刷新页面后仍查询同一原操作。</p></section>{historical.data && <OperationCard operation={historical.data} />}{historical.isError && <p className="zy-message zy-error" role="alert">{userError(historical.error)}</p>}{data.operations.map((item) => <article className="zy-card" key={item.id}><div className="zy-section-heading"><h2>{money(item.amount_cents)}</h2><Status operation={item} /></div><p>{timestamp(item.created_at)}</p><button className="zy-link" onClick={() => navigate(`activity/${item.id}`)}>独立读取这笔操作</button></article>)}<ActivityHistory key={scope} client={client} scope={scope} onRead={(id) => navigate(`activity/${id}`)} /></>}
              <p className="zy-muted">当前事实读取于 {timestamp(data.as_of)}。<button className="zy-link" disabled={dashboard.isFetching} onClick={() => { void refresh(); }}>重新读取</button></p>
            </>}
    </main><footer className="zy-footer"><span>知余 · 本地模拟资金</span><span>所有账户、银行与资金效果均为模拟</span></footer>
  </div>;
}
