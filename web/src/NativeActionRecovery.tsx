import { useEffect, useId, useRef, useState } from 'react';
import { ApiError, stateText } from './api';
import { timestamp, userError } from './display';
import { money } from './money';
import { nextPoll } from './recovery';
import { actionKindLabel, actionTerminal, loadActionLocators, parseActionOperation, saveActionLocator } from './native-financial-api';
import type { ActionLocator, ActionOperation, ActionPreview, ActionTransport } from './native-financial-api';

// Payment and asset commands share the same durable-original transport rule.
// Family adapters still validate their distinct economics and exact payloads.
export default function NativeActionRecovery<P extends ActionPreview>({ api, preview, onConsumed, onBlockedChange, onChanged }: { api: ActionTransport<P>; preview: P | null; onConsumed: () => void; onBlockedChange: (blocked: boolean) => void; onChanged: () => Promise<void> }) {
  const formID = useId(), session = api.client.session, scope = `${session?.environment}:${session?.user_id}`;
  const [records, setRecords] = useState<ActionLocator<P>[]>([]), [selectedKey, setSelectedKey] = useState(''), [ready, setReady] = useState(false), [storageError, setStorageError] = useState('');
  const [consent, setConsent] = useState(false), [costConsent, setCostConsent] = useState(false), [replayConsent, setReplayConsent] = useState(false);
  const [operation, setOperation] = useState<ActionOperation | null>(null), [frontierTerminal, setFrontierTerminal] = useState(false), [independent, setIndependent] = useState(false), [notFound, setNotFound] = useState(false);
  const [busy, setBusy] = useState(false), [checking, setChecking] = useState(false), [error, setError] = useState(''), [readError, setReadError] = useState(''), [batch, setBatch] = useState(0);
  const sending = useRef(false), prior = useRef<ActionOperation | null>(null), callbacks = useRef({ onConsumed, onBlockedChange, onChanged }); callbacks.current = { onConsumed, onBlockedChange, onChanged };
  const selected = records.find((r) => r.key === selectedKey), frontierKey = records.at(-1)?.key;
  const unresolved = records.length > 0 && !frontierTerminal, blocked = busy || !ready || !!storageError || unresolved;
  const title = api.family === 'payments' ? '负债支付' : '资产安排', hasCost = !!preview && BigInt(preview.fee_cents) + BigInt(preview.loss_cents) > 0n;
  useEffect(() => {
    setReady(false); setStorageError(''); setRecords([]); setSelectedKey(''); setFrontierTerminal(false);
    let cancelled = false;
    void (async () => {
      try { const saved = await loadActionLocators(api); if (!cancelled) { setRecords(saved); setSelectedKey(saved.at(-1)?.key ?? ''); } }
      catch (cause) { if (!cancelled) setStorageError(userError(cause)); }
      finally { if (!cancelled) setReady(true); }
    })();
    return () => { cancelled = true; };
  }, [api, scope]);
  useEffect(() => { setConsent(false); setCostConsent(false); }, [preview?.id, preview?.reviewed_hash]);
  useEffect(() => { callbacks.current.onBlockedChange(blocked); }, [blocked]);
  useEffect(() => {
    setOperation(null); prior.current = null; setIndependent(false); setNotFound(false); setReadError(''); setReplayConsent(false);
    if (!selected) return;
    const original = selected, controller = new AbortController(); let cancelled = false, verified = false, attempts = 0, signature = ''; let timer: ReturnType<typeof setTimeout> | undefined;
    async function poll() {
      if (cancelled) return;
      setChecking(true); let again = true;
      try {
        if (!verified) { const independent = await api.original(original.preview, controller.signal); if (cancelled) return; if (JSON.stringify(independent) !== JSON.stringify(original.preview)) throw new Error('独立读取的原安排与本机完整审阅不一致'); verified = true; setIndependent(true); }
        const keyed = await api.byKey(original, controller.signal); if (cancelled) return;
        const value = parseActionOperation(await api.operation(keyed.id, original, controller.signal), original, prior.current ?? keyed); if (cancelled) return;
        const next = `${value.version}:${value.state}:${value.receipt_id ?? ''}`; attempts = signature === next ? attempts + 1 : 0; signature = next;
        prior.current = value; setOperation(value); setReadError(''); setNotFound(false); again = !actionTerminal(value);
        if (original.key === frontierKey) setFrontierTerminal(!again);
        if (!again) await callbacks.current.onChanged();
      } catch (cause) {
        if (cancelled) return;
        attempts++;
        if (cause instanceof ApiError && cause.status === 404) { setNotFound(verified); setReadError('原安排暂未查到，不能判断没有效果；原键、原载荷和预留继续保留。'); }
        else { setReadError(userError(cause)); if (cause instanceof ApiError && [401, 403].includes(cause.status)) again = false; }
      } finally { if (!cancelled) { setChecking(false); if (again) timer = setTimeout(() => { void poll(); }, nextPoll(attempts)); } }
    }
    void poll(); return () => { cancelled = true; controller.abort(); if (timer) clearTimeout(timer); };
  }, [api, selected?.key, frontierKey, batch]);

  async function submit() {
    if (blocked || !preview || !consent || (hasCost && !costConsent) || sending.current) return;
    sending.current = true; setBusy(true); setError('');
    let saving = false, durable = false;
    try {
      if (!session) throw new Error('请先登录本人当前环境');
      if (Date.now() >= Date.parse(preview.expires_at)) { callbacks.current.onConsumed(); throw new Error('原审阅已到期，请重新读取当前完整事实；已发送的原操作继续沿原键核对'); }
      const original: ActionLocator<P> = { environment: session.environment, user_id: session.user_id, key: crypto.randomUUID(), command: { preview_id: preview.id, reviewed_hash: preview.reviewed_hash, ...(api.family === 'assets' ? { cost_reviewed: hasCost && costConsent } : {}) }, preview };
      saving = true; const saved = await saveActionLocator(api, original); durable = true; setRecords(saved); setSelectedKey(original.key); setFrontierTerminal(false); setConsent(false); setCostConsent(false); callbacks.current.onConsumed();
      await api.accept(original); setBatch((value) => value + 1);
    } catch (cause) {
      if (saving && !durable) setStorageError('本机完整恢复资料尚未可靠回读，已停止新提交；请保留原资料并重新打开后核对。');
      setError(`${userError(cause)} ${durable ? '已保存的原请求将沿原键核对；202 或断连都不表示付款或本金已结清。' : '本笔资金请求尚未发送，原资料保留。'}`);
    }
    finally { sending.current = false; setBusy(false); }
  }
  async function replay() {
    if (busy || checking || !selected || !independent || !notFound || !replayConsent || storageError || sending.current) return;
    sending.current = true; setBusy(true); setError(''); setReplayConsent(false);
    try { const original = (await loadActionLocators(api)).find((r) => r.key === selected.key); if (!original) throw new Error('本机原载荷缺失'); await api.accept(original); setBatch((value) => value + 1); }
    catch (cause) { setError(`${userError(cause)} 原键及完整原载荷保留，不创建另一笔安排。`); }
    finally { sending.current = false; setBusy(false); }
  }
  return <div aria-label={`${title}原键恢复与确认`}>
    {storageError && <p className="zy-message zy-error" role="alert">{storageError}</p>}
    {!!records.length && <label className="zy-field" htmlFor={`${formID}-history`}>已保存的原{title}<select id={`${formID}-history`} aria-label={`已保存的原${title}`} value={selectedKey} disabled={busy} onChange={(event) => setSelectedKey(event.target.value)}>{records.map((r, i) => <option value={r.key} key={r.key}>第{i + 1}笔 · {actionKindLabel[r.preview.kind]} · {money(r.preview.amount_cents)}</option>)}</select></label>}
    {selected && <div aria-label={`原${title}结果`}><button className="zy-secondary" disabled={busy || checking} onClick={() => setBatch((value) => value + 1)}>立即核对原{title}</button>{checking && <p role="status">正在独立读取原审阅、原键与原操作…</p>}{readError && <p className="zy-message zy-error" role="alert">{readError}</p>}
      {operation && <><h4>{actionKindLabel[operation.kind]}：{stateText[operation.state]}</h4>{operation.state === 'SETTLED' ? <p>这笔{actionKindLabel[operation.kind]}已按原银行回执结清 {money(operation.amount_cents)}。{operation.kind === 'REDEEM_ASSET' || operation.kind === 'MATURE_ASSET' ? `原审阅净返本 ${money(selected.preview.net_cents)}；返本不成为新收入。` : ''}</p> : ['REJECTED', 'CANCELLED'].includes(operation.state) ? <p>这笔原安排没有形成已确认的资金效果，原结果保留。</p> : <p>本笔尚未结清，继续保留原预留与原键。</p>}{['UNKNOWN', 'RECONCILING'].includes(operation.state) && <p>结果待核实；规则暂停、原审阅过期或自动重试停止都不能证明无效果。</p>}</>}
      {notFound && independent && !operation && <><label className="zy-check"><input type="checkbox" checked={replayConsent} disabled={busy || checking} onChange={(event) => setReplayConsent(event.target.checked)} />本人确认仅沿本笔原键和完整原载荷继续提交。</label><button className="zy-secondary" disabled={busy || checking || !replayConsent} onClick={() => { void replay(); }}>沿原键继续原{title}</button></>}
    </div>}
    {unresolved && <p>最新原{title}尚未核实为终态，不能用新候选替换。</p>}
    {preview && <><p>完整原审阅至 {timestamp(preview.expires_at)} 有效；首次发送前将先保存本机恢复资料。</p><label className="zy-check"><input type="checkbox" checked={consent} disabled={blocked} onChange={(event) => setConsent(event.target.checked)} />本人已核对本次{actionKindLabel[preview.kind]}的对象、金额、来源、到账时点与保护变化，明确确认这一笔。</label>
      {hasCost && <label className="zy-check"><input type="checkbox" checked={costConsent} disabled={blocked} onChange={(event) => setCostConsent(event.target.checked)} />本人另行明确确认本笔原报价费用 {money(preview.fee_cents)}、本金损失 {money(preview.loss_cents)}，净返本 {money(preview.net_cents)}。</label>}
      <button className="zy-primary" disabled={blocked || !consent || (hasCost && !costConsent)} onClick={() => { void submit(); }}>本人确认并提交{title}</button><p className="zy-muted">202 仅表示受理。到账或结清须等原银行回执，未到账本金不能提前使用。</p></>}
    {busy && <p role="status">正在持久保存或提交原{title}…</p>}{error && <p className="zy-message zy-error" role="alert">{error}</p>}
  </div>;
}
