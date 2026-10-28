import { useEffect, useMemo, useRef, useState } from 'react';
import { ApiError, Client } from './api';
import { timestamp, userError } from './display';
import { HistoryClient, HistoryUploadRejected, historyBlobHash, historyPendingKey, historyStatusText, loadHistoryPending, loadHistoryRejections, retainHistoryRejection, saveHistoryPending } from './history-api';
import type { HistoryArchive, HistoryImport, HistoryPreview, HistorySummary, PendingHistory } from './history-api';
import { loadHistoryUpload, saveHistoryUpload } from './history-upload';

export default function HistoryPanel({ client }: { client: Client }) {
  const api = useMemo(() => new HistoryClient(client), [client]);
  const [archives, setArchives] = useState<HistorySummary[]>([]), [imports, setImports] = useState<HistoryImport[]>([]), [hasMore, setHasMore] = useState(false);
  const [archive, setArchive] = useState<HistoryArchive | null>(null), [preview, setPreview] = useState<HistoryPreview | null>(null), [prefix, setPrefix] = useState('历史副本'), [consent, setConsent] = useState(false);
  const [pending, setPending] = useState<PendingHistory | null>(null), [ready, setReady] = useState(false), [busy, setBusy] = useState(false), [error, setError] = useState(''), [notice, setNotice] = useState(''), [file, setFile] = useState<File | null>(null);
  const [download, setDownload] = useState<{ archiveID: string; url: string } | null>(null);
  const [rejections, setRejections] = useState<PendingHistory[]>([]);
  const running = useRef(false), alive = useRef(true);
  const blocked = !ready || !!(pending && !pending.result_id);
  function putPending(value: PendingHistory) { const saved = saveHistoryPending(client, value); setPending(saved); return saved; }
  async function refresh() { const [a, i] = await Promise.all([api.archives(), api.imports()]); if (alive.current) { setArchives(a.items); setImports(i.items); setHasMore(a.has_more || i.has_more); } }
  function displayOriginal(value: HistoryArchive | HistoryImport) {
    if ('members' in value) setArchive(value);
    else setImports((old) => [value, ...old.filter((r) => r.id !== value.id)]);
  }
  async function recover(value: PendingHistory) { const original = await api.original(value); if (alive.current) { displayOriginal(original); putPending({ ...value, result_id: original.id }); } return original; }
  async function act(action: () => Promise<void>) {
    if (running.current) return; running.current = true; setBusy(true); setError(''); setNotice('');
    try { await action(); } catch (cause) { if (alive.current) setError(userError(cause)); } finally { running.current = false; if (alive.current) setBusy(false); }
  }
  useEffect(() => {
    alive.current = true;
    void act(async () => { const value = loadHistoryPending(client); setPending(value); setRejections(loadHistoryRejections(client)); setReady(true); if (value && !value.rejection) { try { await recover(value); } catch (cause) { if (!(cause instanceof ApiError && cause.code === 'NOT_FOUND')) throw cause; setNotice('原请求暂未查到；可继续按同一原请求核对或重试。'); } } await refresh(); });
    return () => { alive.current = false; };
  }, [api]);
  useEffect(() => { setDownload(null); }, [archive?.id]);
  useEffect(() => () => { if (download) URL.revokeObjectURL(download.url); }, [download]);
  function fresh(kind: PendingHistory['kind']): PendingHistory { if (!client.session) throw new Error('请先登录'); return { protocol: 'zhiyu-browser-passive-history-v1', environment: client.session.environment, user_id: client.session.user_id, key: crypto.randomUUID(), kind, command: null }; }
  async function submit(value: PendingHistory, blob?: Blob) {
    putPending(value); setPreview(null); setConsent(false);
    try { const original = await api.submit(value, blob); displayOriginal(original); putPending({ ...value, result_id: original.id }); await refresh(); setNotice('历史原请求已独立回读。档案及副本均未激活资金执行。'); }
    catch (cause) {
      if (cause instanceof HistoryUploadRejected && value.kind === 'UPLOAD' && cause.key === value.key && cause.upload_hash === value.upload_hash && cause.upload_size === value.upload_size) {
        putPending({ ...value, rejection: { code: 'INVALID_HISTORY_ARCHIVE', http_status: 409, original_http_status: 404, observed_at: cause.observed_at } });
        setNotice(cause.message); await refresh(); return;
      }
      try { await recover(value); await refresh(); } catch { throw cause; }
    }
  }
  return <section className="zy-card" aria-label="历史档案与被动副本"><h2>历史档案与被动副本</h2><p>保存并回看原资料，保留失败、未知结果和原身份。副本只用于查阅；核验通过的范围会明确列出。</p>
    <div className="zy-actions"><button className="zy-secondary" disabled={busy || blocked} onClick={() => { void act(() => submit(fresh('CAPTURE'))); }}>保存当前历史快照</button><button className="zy-secondary" disabled={busy} onClick={() => { void act(refresh); }}>重新读取档案与进度</button></div>
    <label className="zy-field">选择已有历史档案文件<input type="file" accept=".json,application/json" disabled={busy || blocked} onChange={(event) => { setFile(event.target.files?.[0] ?? null); setConsent(false); }} /></label>
    <button className="zy-secondary" disabled={busy || blocked || !file} onClick={() => { void act(async () => { if (!file || file.size < 1 || file.size > 96 << 20) throw new Error('请选择96 MiB以内的完整历史档案'); const value = { ...fresh('UPLOAD'), upload_hash: await historyBlobHash(file), upload_size: file.size }; const key = historyPendingKey(client) + ':' + value.key; await saveHistoryUpload(key, file); const saved = await loadHistoryUpload(key); await submit(value, saved); setFile(null); }); }}>保留原文件并保存档案</button>
    {pending && !pending.result_id && !pending.rejection && <div role="status"><p>这份历史原请求尚未独立回读，先保留原请求继续核对。</p><button disabled={busy} onClick={() => { void act(async () => { await recover(pending); await refresh(); }); }}>查询历史原请求</button><button disabled={busy} onClick={() => { void act(async () => { const saved = loadHistoryPending(client); if (!saved || saved.key !== pending.key) throw new Error('本机历史原请求已变化'); const blob = saved.kind === 'UPLOAD' ? await loadHistoryUpload(historyPendingKey(client) + ':' + saved.key) : undefined; await submit(saved, blob); }); }}>按保存的原请求重试</button></div>}
    {pending?.rejection && <div role="status"><p>本次上传已明确拒绝保存：原件结构校验不通过，原请求与原文件均已保留。</p><button disabled={busy} onClick={() => { void act(async () => { retainHistoryRejection(client, pending); setRejections(loadHistoryRejections(client)); setPending(null); setNotice('拒绝记录和原文件继续保留，可以选择另一份档案或保存当前快照。'); }); }}>保留拒绝记录并开始新档案请求</button></div>}
    {rejections.map((value, index) => <article key={value.key}><h3>已保留的上传拒绝 {index + 1}</h3><p>{timestamp(value.rejection!.observed_at)}：原件结构校验不通过；原请求、原文件及拒绝结果保留，未保存为服务端历史档案。</p></article>)}
    {!archives.length && ready && !busy && <p>还没有可读取的历史档案。</p>}
    {hasMore && <p>这里显示最近20份记录，仍有较早档案；已保存的原请求仍可独立回读。</p>}
    {archives.map((a, i) => <article key={a.id}><h3>历史档案 {i + 1} · {timestamp(a.created_at)}</h3><p>{historyStatusText[a.status]} · {a.stored_count}项原资料</p><button className="zy-link" disabled={busy} onClick={() => { setPreview(null); setConsent(false); void act(async () => { setArchive(await api.archive(a.id)); }); }}>读取这份原档案</button></article>)}
    {archive && <div aria-label="历史原档案审阅"><h3>原档案审阅</h3><p>{historyStatusText[archive.status]}。已保留 {archive.stored_count} 项，{archive.stored_bytes.toLocaleString()} 字节。</p><p>{archive.source.scope === 'REGISTERED_TABLE_SET' ? '本次核对覆盖已登记的来源表与原件结构；完整资金审计另行核对。' : '本次按来源声明的范围保留原资料。'}</p>
      <button className="zy-secondary" disabled={busy} onClick={() => { void act(async () => { const blob = await api.export(archive); if (!alive.current) return; setDownload({ archiveID: archive.id, url: URL.createObjectURL(blob) }); setNotice('原文件字节已核对，请点击下载并在浏览器中核对保存结果。'); }); }}>导出原文件</button>
      {download?.archiveID === archive.id && <a className="zy-secondary" href={download.url} download="知余历史档案.json" onClick={() => setNotice('已发起下载，请在浏览器中核对保存结果。')}>下载已核对的原文件</a>}
      <label className="zy-field">被动副本名称<input value={prefix} disabled={busy || blocked} onChange={(event) => { setPrefix(event.target.value); setPreview(null); setConsent(false); }} /></label>
      <button className="zy-secondary" disabled={busy || blocked} onClick={() => { void act(async () => { setPreview(await api.preview(archive, prefix)); setConsent(false); }); }}>预览副本命名</button>
      {preview && <div><p>按原顺序保存 {preview.mapping.entries.length} 项副本，名称为“{prefix.trim()}-1”起的连续编号。原件身份、金额、银行键与未知结果保持原样。</p><p>来源状态：{historyStatusText[preview.source_status]}。</p><label className="zy-check"><input type="checkbox" checked={consent} disabled={busy || blocked} onChange={(e) => setConsent(e.target.checked)} />我已核对副本命名，只保存被动历史副本。</label><button className="zy-primary" disabled={busy || blocked || !consent} onClick={() => { void act(async () => { const value = fresh('IMPORT'); value.command = { archive_id: archive.id, mapping: preview.mapping, reviewed_hash: preview.reviewed_hash, passive_only_reviewed: true }; await submit(value); }); }}>确认建立被动副本</button></div>}
    </div>}
    {imports.map((item) => <article key={item.id}><h3>{item.state === 'COMPLETED' ? '被动副本已复制完成' : item.paused ? '被动副本已暂停' : '被动副本等待继续'}</h3><p>已保存 {item.cursor} / {item.total} 项 · {historyStatusText[item.source_status]}。副本未激活资金执行。</p>{item.state !== 'COMPLETED' && <><button disabled={busy || item.paused} onClick={() => { void act(async () => { const next = await api.step(item.id); displayOriginal(next); await refresh(); }); }}>复制下一批（最多100项）</button><button disabled={busy} onClick={() => { void act(async () => { displayOriginal(await api.paused(item.id, !item.paused)); await refresh(); }); }}>{item.paused ? '继续复制' : '暂停复制'}</button></>}</article>)}
    {busy && <p role="status">正在核对历史原资料…</p>}{notice && <p role="status">{notice}</p>}{error && <p className="zy-message zy-error" role="alert">{error}</p>}
  </section>;
}
