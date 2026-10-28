import { ApiError, Client } from './api';
import { nfClosed, nfHash, nfInt, nfList, nfObject, nfOwner, nfText, nfTime, nfUnique } from './native-financial-api';
import { templateID } from './template-schema';

export type HistoryStatus = 'VALID' | 'INVALID' | 'INCOMPLETE' | 'UNSUPPORTED_VERSION';
export const historyStatusText: Record<HistoryStatus, string> = { VALID: '登记范围内的字节与结构核对通过', INVALID: '原件核对失败', INCOMPLETE: '原件或登记来源不完整', UNSUPPORTED_VERSION: '保留原件，协议尚不支持核验' };
export interface HistoryMember { id: string; raw_hash: string; table: string }
export interface HistorySummary { id: string; mode: string; status: HistoryStatus; assurance: string; root_hash: string; stored_count: number; stored_bytes: number; created_at: string }
export interface HistoryArchive extends HistorySummary { wire_hash: string; members: HistoryMember[]; source: { environment_id: string; user_id: string; namespace: string; scope: string }; original: Record<string, unknown> }
export interface HistoryMappingEntry { object_id: string; source_raw_hash: string; destination_id: string }
export interface HistoryMapping { protocol: 'zhiyu-passive-history-mapping-v1'; archive_root_hash: string; source_environment_id: string; source_user_id: string; source_namespace: string; destination_environment_id: string; destination_user_id: string; entries: HistoryMappingEntry[]; activated: false; bank_authority: false }
export interface HistoryPreview { mapping: HistoryMapping; reviewed_hash: string; source_status: HistoryStatus; assurance: string; passive_only: true; bank_authority: false; activated: false }
export interface HistoryImportRequest { archive_id: string; mapping: HistoryMapping; reviewed_hash: string; passive_only_reviewed: true }
export interface HistoryImport { id: string; archive_id: string; source_status: HistoryStatus; state: 'READY' | 'RUNNING' | 'COMPLETED'; paused: boolean; cursor: number; total: number; generation: number; updated_at: string; original: Record<string, unknown> }
export interface HistoryUploadRejection { code: 'INVALID_HISTORY_ARCHIVE'; http_status: 409; original_http_status: 404; observed_at: string }
export interface PendingHistory { protocol: 'zhiyu-browser-passive-history-v1'; environment: string; user_id: string; key: string; kind: 'CAPTURE' | 'UPLOAD' | 'IMPORT'; command: HistoryImportRequest | null; upload_hash?: string; upload_size?: number; result_id?: string; rejection?: HistoryUploadRejection }
export class HistoryUploadRejected extends Error {
  constructor(readonly key: string, readonly upload_hash: string, readonly upload_size: number, readonly observed_at = new Date().toISOString()) { super('这份上传档案未通过原件结构校验，服务端已拒绝保存；原请求和原文件继续保留。'); }
}

function inert(raw: Record<string, unknown>) { if (raw.bank_authority !== false || raw.activated !== false) throw new Error('历史档案出现未审阅的激活或资金权限，已停止'); }
function status(raw: unknown): HistoryStatus { const value = nfText(raw); if (!(value in historyStatusText)) throw new Error('历史核验状态不受支持'); return value as HistoryStatus; }
function bool(raw: unknown): boolean { if (typeof raw !== 'boolean') throw new Error('历史进度状态不完整'); return raw; }
function summary(raw: unknown): HistorySummary { const r = nfObject(raw); inert(r); return { id: templateID(r.id), mode: nfText(r.mode), status: status(r.status), assurance: nfText(r.assurance), root_hash: nfHash(r.root_hash), stored_count: nfInt(r.stored_count, 0, 10000), stored_bytes: nfInt(r.stored_bytes, 0, 64 << 20), created_at: nfTime(r.created_at) }; }
export function parseHistoryArchive(raw: unknown, client: Client): HistoryArchive {
  const r = nfObject(raw); inert(r); nfOwner(r.scope, client); templateID(r.session_id);
  if (r.protocol !== 'zhiyu-history-record-v1') throw new Error('历史档案记录协议不受支持');
  const m = nfObject(r.manifest), v = nfObject(r.verification), source = nfObject(m.source); inert(v);
  if (m.protocol !== 'zhiyu-history-archive-v1' || nfHash(m.root_hash) !== nfHash(v.root_hash) || nfInt(m.total_bytes, 0, 64 << 20) !== r.stored_bytes) throw new Error('历史档案总览和核验原件不一致');
  const members = nfList(m.objects, (raw): HistoryMember => { const o = nfObject(raw); return { id: nfHash(o.id), raw_hash: nfHash(o.raw_hash), table: nfText(o.table, 128) }; }, 10000); nfUnique(members.map((r) => r.id));
  if (members.length !== nfInt(r.stored_count, 0, 10000)) throw new Error('历史档案成员数量不一致');
  const s = summary({ ...r, status: v.status, assurance: v.assurance, root_hash: m.root_hash });
  return { ...s, wire_hash: nfHash(r.wire_hash), members, source: { environment_id: nfText(source.environment_id), user_id: nfText(source.user_id), namespace: nfText(source.namespace), scope: nfText(source.scope) }, original: r };
}
export function parseHistoryMapping(raw: unknown, client: Client): HistoryMapping {
  const m = nfObject(raw); inert(m); nfClosed(m, ['protocol', 'archive_root_hash', 'source_environment_id', 'source_user_id', 'source_namespace', 'destination_environment_id', 'destination_user_id', 'entries', 'activated', 'bank_authority']);
  if (m.protocol !== 'zhiyu-passive-history-mapping-v1' || templateID(m.destination_user_id) !== client.session?.user_id) throw new Error('历史副本不属于当前本人');
  const entries = nfList(m.entries, (raw): HistoryMappingEntry => { const e = nfObject(raw); nfClosed(e, ['object_id', 'source_raw_hash', 'destination_id']); return { object_id: nfHash(e.object_id), source_raw_hash: nfHash(e.source_raw_hash), destination_id: nfText(e.destination_id, 128) }; }, 10000);
  nfUnique(entries.map((e) => e.object_id)); nfUnique(entries.map((e) => e.destination_id));
  return { protocol: m.protocol, archive_root_hash: nfHash(m.archive_root_hash), source_environment_id: nfText(m.source_environment_id), source_user_id: nfText(m.source_user_id), source_namespace: nfText(m.source_namespace), destination_environment_id: templateID(m.destination_environment_id), destination_user_id: templateID(m.destination_user_id), entries, activated: false, bank_authority: false };
}
export function parseHistoryPreview(raw: unknown, archive: HistoryArchive, entries: HistoryMappingEntry[], client: Client): HistoryPreview {
  const r = nfObject(raw); inert(r); const mapping = parseHistoryMapping(r.mapping, client);
  if (r.passive_only !== true || mapping.archive_root_hash !== archive.root_hash || mapping.destination_environment_id !== nfOwner(archive.original.scope).environment_id || mapping.source_environment_id !== archive.source.environment_id || mapping.source_user_id !== archive.source.user_id || mapping.source_namespace !== archive.source.namespace || JSON.stringify(mapping.entries) !== JSON.stringify(entries) || mapping.entries.length !== archive.members.length || mapping.entries.some((e, i) => e.object_id !== archive.members[i]!.id || e.source_raw_hash !== archive.members[i]!.raw_hash) || status(r.source_status) !== archive.status) throw new Error('副本命名审阅和原档案不一致');
  return { mapping, reviewed_hash: nfHash(r.reviewed_hash), source_status: status(r.source_status), assurance: nfText(r.assurance), passive_only: true, activated: false, bank_authority: false };
}
export function parseHistoryImport(raw: unknown, client: Client): HistoryImport {
  const r = nfObject(raw), o = nfObject(r.original); inert(o); if (r.activated !== false || o.protocol !== 'zhiyu-passive-history-import-v1') throw new Error('历史副本出现激活状态');
  const owner = nfOwner(o.scope, client), mapping = parseHistoryMapping(r.mapping, client);
  if (owner.environment_id !== mapping.destination_environment_id || !['READY', 'RUNNING', 'COMPLETED'].includes(nfText(r.state))) throw new Error('历史副本目标或进度不受支持');
  const cursor = nfInt(r.cursor, 0, mapping.entries.length); if (r.state === 'COMPLETED' && cursor !== mapping.entries.length) throw new Error('历史副本缺少已完成成员');
  nfHash(o.reviewed_hash); nfHash(o.mapping_hash); nfHash(o.request_hash);
  return { id: templateID(o.id), archive_id: templateID(o.archive_id), source_status: status(o.source_status), state: r.state as HistoryImport['state'], paused: bool(r.paused), cursor, total: mapping.entries.length, generation: nfInt(r.generation), updated_at: nfTime(r.updated_at), original: r };
}
export function historyPendingKey(client: Client) { if (!client.session) throw new Error('请先登录'); return `zhiyu-go:passive-history:v1:${client.session.environment}:${client.session.user_id}`; }
function parseHistoryPending(client: Client, raw: unknown): PendingHistory {
  try {
    const p = nfObject(raw); nfClosed(p, ['protocol', 'environment', 'user_id', 'key', 'kind', 'command', 'upload_hash', 'upload_size', 'result_id', 'rejection']);
    if (p.protocol !== 'zhiyu-browser-passive-history-v1' || p.environment !== client.session?.environment || p.user_id !== client.session?.user_id || !['CAPTURE', 'UPLOAD', 'IMPORT'].includes(String(p.kind))) throw new Error('scope');
    templateID(p.key); if (p.result_id != null) templateID(p.result_id);
    if (p.kind === 'IMPORT') { const command = nfObject(p.command); nfClosed(command, ['archive_id', 'mapping', 'reviewed_hash', 'passive_only_reviewed']); templateID(command.archive_id); nfHash(command.reviewed_hash); parseHistoryMapping(command.mapping, client); if (command.passive_only_reviewed !== true) throw new Error('review'); }
    else if (p.command !== null) throw new Error('command');
    if (p.kind === 'UPLOAD') { nfHash(p.upload_hash); nfInt(p.upload_size, 1, 96 << 20); }
    if (p.rejection != null) { const r = nfObject(p.rejection); nfClosed(r, ['code', 'http_status', 'original_http_status', 'observed_at']); if (p.kind !== 'UPLOAD' || p.result_id != null || r.code !== 'INVALID_HISTORY_ARCHIVE' || r.http_status !== 409 || r.original_http_status !== 404) throw new Error('rejection'); nfTime(r.observed_at); }
    return p as unknown as PendingHistory;
  } catch { throw new Error('本机历史档案原请求不完整，已保留资料并停止新提交'); }
}
export function loadHistoryPending(client: Client): PendingHistory | null { const raw = localStorage.getItem(historyPendingKey(client)); if (!raw) return null; try { return parseHistoryPending(client, JSON.parse(raw)); } catch { throw new Error('本机历史档案原请求不完整，已保留资料并停止新提交'); } }
export function loadHistoryRejections(client: Client): PendingHistory[] {
  const prefix = historyPendingKey(client) + ':rejected:', values: PendingHistory[] = [];
  for (let i = 0; i < localStorage.length; i++) { const key = localStorage.key(i); if (!key?.startsWith(prefix)) continue; const value = parseHistoryPending(client, JSON.parse(localStorage.getItem(key)!)); if (!value.rejection || key !== prefix + value.key) throw new Error('已保留的历史拒绝记录不完整'); values.push(value); }
  return values;
}
export function retainHistoryRejection(client: Client, pending: PendingHistory): void {
  const current = loadHistoryPending(client), value = parseHistoryPending(client, pending), raw = JSON.stringify(value);
  if (!value.rejection || JSON.stringify(current) !== raw) throw new Error('不能替换本机历史拒绝的原请求');
  const key = historyPendingKey(client) + ':rejected:' + value.key, previous = localStorage.getItem(key);
  if (previous != null && previous !== raw) throw new Error('已保留的历史拒绝记录发生变化');
  localStorage.setItem(key, raw); if (localStorage.getItem(key) !== raw) throw new Error('历史拒绝记录尚未完整保留，不能开始新请求');
}
export function saveHistoryPending(client: Client, pending: PendingHistory) {
  const key = historyPendingKey(client), value = parseHistoryPending(client, pending), raw = JSON.stringify(value), previous = loadHistoryPending(client);
  if (previous && previous.key !== value.key && !previous.result_id && (!previous.rejection || localStorage.getItem(key + ':rejected:' + previous.key) !== JSON.stringify(previous))) throw new Error('原历史请求尚未核对或保留，不能替换原键');
  if (previous?.key === value.key) { const request = (p: PendingHistory) => { const original = { ...p }; delete original.result_id; delete original.rejection; return original; }; if (JSON.stringify(request(previous)) !== JSON.stringify(request(value)) || (previous.rejection && JSON.stringify(previous.rejection) !== JSON.stringify(value.rejection))) throw new Error('不能更换历史原键的完整请求或已观察拒绝'); }
  localStorage.setItem(key, raw); if (localStorage.getItem(key) !== raw) throw new Error('无法完整保存历史原请求，尚未提交'); return loadHistoryPending(client)!;
}
export class HistoryClient {
  constructor(readonly client: Client) {}
  async archives() { const r = nfObject(await this.client.request('/history-archives')); return { items: nfList(r.items, summary, 20), has_more: bool(r.has_more) }; }
  async imports() { const r = nfObject(await this.client.request('/history-imports')); return { items: nfList(r.items, (v) => parseHistoryImport(v, this.client), 20), has_more: bool(r.has_more) }; }
  async archive(id: string) { return parseHistoryArchive(await this.client.request(`/history-archives/${templateID(id)}`), this.client); }
  async original(p: PendingHistory) {
    const result = await this.client.request(`/${p.kind === 'IMPORT' ? 'history-import' : 'history-archive'}-commands/${encodeURIComponent(p.key)}`);
    const parsed = p.kind === 'IMPORT' ? parseHistoryImport(result, this.client) : parseHistoryArchive(result, this.client);
    const o = p.kind === 'IMPORT' ? nfObject((parsed as HistoryImport).original.original) : (parsed as HistoryArchive).original;
    if (o.idempotency_key !== p.key || (p.result_id && p.result_id !== parsed.id) || (p.kind === 'CAPTURE' && o.mode !== 'AUTHENTICATED_CURRENT_READSET') || (p.kind === 'UPLOAD' && (o.mode !== 'SUPPLIED_HISTORY' || o.wire_hash !== p.upload_hash || o.request_hash !== p.upload_hash)) || (p.kind === 'IMPORT' && (o.archive_id !== p.command!.archive_id || o.reviewed_hash !== p.command!.reviewed_hash || JSON.stringify(nfObject((parsed as HistoryImport).original).mapping) !== JSON.stringify(p.command!.mapping)))) throw new Error('服务器返回另一份历史原请求');
    return parsed;
  }
  async submit(p: PendingHistory, blob?: Blob) {
    if (p.rejection) throw new Error('这份原上传已经明确拒绝，不能自动重试或换键重送');
    if (p.kind === 'UPLOAD') {
      if (!blob || blob.size !== p.upload_size || await historyBlobHash(blob) !== p.upload_hash) throw new Error('本机上传原件不完整');
      try { await this.wire('/history-archives', { method: 'POST', headers: { 'Idempotency-Key': p.key, 'Content-Type': 'application/vnd.zhiyu.history+json' }, body: blob }); }
      catch (cause) {
        // This exact upload error is returned before any archive transaction.
        // A bare 409, conflict, response loss or later GET error proves nothing.
        if (cause instanceof ApiError && cause.status === 409 && cause.code === 'INVALID_HISTORY_ARCHIVE') {
          try { return await this.original(p); }
          catch (lookup) { if (lookup instanceof ApiError && lookup.status === 404 && lookup.code === 'NOT_FOUND') throw new HistoryUploadRejected(p.key, p.upload_hash!, p.upload_size!); }
        }
        throw cause;
      }
    }
    else await this.client.request(p.kind === 'CAPTURE' ? '/history-captures' : '/history-imports', { method: 'POST', headers: { 'Idempotency-Key': p.key }, body: JSON.stringify(p.kind === 'CAPTURE' ? {} : p.command), ...(p.kind === 'CAPTURE' ? { signal: AbortSignal.timeout(25000) } : {}) });
    return this.original(p);
  }
  async preview(archive: HistoryArchive, prefix: string) {
    if (!prefix.trim() || new TextEncoder().encode(prefix).length > 80) throw new Error('请填写不超过80字节的副本名称');
    const entries = archive.members.map((m, i) => ({ object_id: m.id, source_raw_hash: m.raw_hash, destination_id: `${prefix.trim()}-${i + 1}` }));
    return parseHistoryPreview(await this.client.request('/history-import-previews', { method: 'POST', body: JSON.stringify({ archive_id: archive.id, entries }) }), archive, entries, this.client);
  }
  async step(id: string) { return parseHistoryImport(await this.client.request(`/history-imports/${templateID(id)}/step`, { method: 'POST', body: '{"batch":100}' }), this.client); }
  async paused(id: string, paused: boolean) { return parseHistoryImport(await this.client.request(`/history-imports/${templateID(id)}/state`, { method: 'POST', body: JSON.stringify({ paused }) }), this.client); }
  async wire(path: string, init: RequestInit = {}) {
    const headers = new Headers(init.headers); headers.set('Authorization', `Bearer ${this.client.session?.token ?? ''}`); if (init.method === 'POST') headers.set('X-CSRF-Token', this.client.session?.csrf_token ?? '');
    const r = await fetch(this.client.base + path, { ...init, headers, credentials: 'omit', cache: 'no-store', signal: AbortSignal.timeout(120000) });
    if (!r.ok) { let code = 'HTTP_ERROR'; try { const body = nfObject(await r.json()); code = String(nfObject(body.error ?? body).code ?? code); } catch { /* Keep the HTTP status if the failure body is unreadable. */ } throw new ApiError(r.status, code, '历史档案请求尚未完成，请核对原请求'); }
    return r;
  }
  async export(archive: HistoryArchive) { const r = await this.wire(`/history-archives/${templateID(archive.id)}/export`), blob = await r.blob(); if (blob.size > 96 << 20 || await historyBlobHash(blob) !== archive.wire_hash) throw new Error('导出字节与保留原档案不一致'); return blob; }
}
export async function historyBlobHash(blob: Blob) { return Array.from(new Uint8Array(await crypto.subtle.digest('SHA-256', await blob.arrayBuffer())), (v) => v.toString(16).padStart(2, '0')).join(''); }
