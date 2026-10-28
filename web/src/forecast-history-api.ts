import { Client } from './api';
import { nfClosed, nfHash, nfInt, nfList, nfObject, nfText, nfTime, nfUnique } from './native-financial-api';
import { templateID } from './template-schema';

export interface ForecastHistorySource { source_id: string; state: 'REGISTERED' | 'IMPORTED' }
export interface ForecastHistoryImport { protocol: 'forecast-history-import-v1'; id: string; source_id: string; statement_id: string; statement_hash: string; from_date: string; through_date: string; recorded_at: string; source_version: number; replayed: boolean }
export interface PendingForecastHistory { protocol: 'zhiyu-browser-forecast-history-v1'; environment: string; user_id: string; key: string; source_id: string; result?: ForecastHistoryImport }
function sourceID(raw: unknown) { const id = nfText(raw, 64); if (/[\\/\r\n\0]/.test(id)) throw new Error('历史来源标识不完整'); return id; }
function date(raw: unknown) { const value = nfText(raw, 10); if (!/^\d{4}-\d{2}-\d{2}$/.test(value) || new Date(value).toISOString().slice(0, 10) !== value) throw new Error('历史覆盖日期不完整'); return value; }
export function parseForecastHistorySources(raw: unknown): ForecastHistorySource[] {
  const rows = nfList(raw, (v): ForecastHistorySource => { const s = nfObject(v); nfClosed(s, ['source_id', 'state']); if (s.state !== 'REGISTERED' && s.state !== 'IMPORTED') throw new Error('历史来源状态不受支持'); return { source_id: sourceID(s.source_id), state: s.state }; }, 100);
  nfUnique(rows.map((s) => s.source_id)); return rows;
}
export function parseForecastHistoryImport(raw: unknown, expectedSource: string): ForecastHistoryImport {
  const r = nfObject(raw); nfClosed(r, ['protocol', 'id', 'source_id', 'statement_id', 'statement_hash', 'from_date', 'through_date', 'recorded_at', 'source_version', 'replayed']);
  if (r.protocol !== 'forecast-history-import-v1' || sourceID(r.source_id) !== expectedSource || typeof r.replayed !== 'boolean') throw new Error('历史原结果与原请求不符');
  const from = date(r.from_date), through = date(r.through_date), days = (Date.parse(through) - Date.parse(from)) / 86400000 + 1;
  if (days < 1 || days > 366) throw new Error('历史覆盖范围不完整');
  const statement = nfText(r.statement_id, 128), id = nfText(r.id, 210);
  if (/[\\/\r\n\0]/.test(statement) || id !== `forecast-history:${expectedSource}:${statement}`) throw new Error('历史原件身份与来源不符');
  return { protocol: r.protocol, id, source_id: expectedSource, statement_id: statement, statement_hash: nfHash(r.statement_hash), from_date: from, through_date: through, recorded_at: nfTime(r.recorded_at), source_version: nfInt(r.source_version, 1), replayed: r.replayed };
}
export function forecastHistoryPendingKey(client: Client) { if (!client.session) throw new Error('请先登录'); return `zhiyu-go:forecast-history:v1:${client.session.environment}:${client.session.user_id}`; }
export function loadForecastHistoryPending(client: Client): PendingForecastHistory | null {
  const raw = localStorage.getItem(forecastHistoryPendingKey(client)); if (!raw) return null;
  try {
    const p = nfObject(JSON.parse(raw)); nfClosed(p, ['protocol', 'environment', 'user_id', 'key', 'source_id', 'result']);
    if (p.protocol !== 'zhiyu-browser-forecast-history-v1' || p.environment !== client.session?.environment || p.user_id !== client.session?.user_id) throw new Error('scope');
    templateID(p.key); const source = sourceID(p.source_id); if (p.result != null) parseForecastHistoryImport(p.result, source); return p as unknown as PendingForecastHistory;
  } catch { throw new Error('保存的历史来源原请求不完整，已保留资料并停止新导入'); }
}
export function saveForecastHistoryPending(client: Client, pending: PendingForecastHistory) {
  const key = forecastHistoryPendingKey(client), raw = JSON.stringify(pending); localStorage.setItem(key, raw);
  if (localStorage.getItem(key) !== raw) throw new Error('未能保留历史来源原请求，尚未发送'); return loadForecastHistoryPending(client)!;
}
export class ForecastHistoryClient {
  constructor(readonly client: Client) {}
  async sources() { return parseForecastHistorySources(await this.client.request('/forecast-history-sources')); }
  async original(p: PendingForecastHistory) {
    const value = parseForecastHistoryImport(await this.client.request(`/forecast-history-import-commands/${encodeURIComponent(p.key)}?source_id=${encodeURIComponent(p.source_id)}`), p.source_id);
    if (p.result && (value.id !== p.result.id || value.statement_hash !== p.result.statement_hash || value.statement_id !== p.result.statement_id || value.from_date !== p.result.from_date || value.through_date !== p.result.through_date || value.recorded_at !== p.result.recorded_at || value.source_version !== p.result.source_version)) throw new Error('历史来源原件发生替换');
    return value;
  }
  async observe(p: PendingForecastHistory) {
    await this.client.request('/forecast-history-imports', { method: 'POST', headers: { 'Idempotency-Key': p.key }, body: JSON.stringify({ source_id: p.source_id }), signal: AbortSignal.timeout(25000) });
    return this.original(p);
  }
}
