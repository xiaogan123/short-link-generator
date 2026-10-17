import type { ClickStatsTotals } from './types';

export type DedupCounts = { first: number; repeat: number; measured: number };

// Older reports have no dedup field. A malformed field must never become a zero.
export function validDedup(totals: ClickStatsTotals | undefined): DedupCounts | null {
  if (!totals || !Number.isSafeInteger(totals.total) || totals.total < 0 || !totals.dedup) return null;
  const { first, repeat } = totals.dedup;
  if (!Number.isSafeInteger(first) || first < 0 || !Number.isSafeInteger(repeat) || repeat < 0) return null;
  const measured = first + repeat;
  if (!Number.isSafeInteger(measured) || measured > totals.total) return null;
  if (totals.total > 0 && measured === 0) return null;
  return { first, repeat, measured };
}

export function sumDedup(values: ClickStatsTotals[]): DedupCounts | null {
  let first = 0;
  let repeat = 0;
  for (const value of values) {
    const counts = validDedup(value);
    if (!counts) continue;
    first += counts.first;
    repeat += counts.repeat;
    if (!Number.isSafeInteger(first) || !Number.isSafeInteger(repeat) || !Number.isSafeInteger(first + repeat)) return null;
  }
  return { first, repeat, measured: first + repeat };
}

export function dedupLabel(totals: ClickStatsTotals): string {
  const counts = validDedup(totals);
  if (!counts) return '首次 — · 重复 — · 覆盖 未覆盖';
  const number = (value: number) => value.toLocaleString('zh-CN');
  return `首次 ${number(counts.first)} · 重复 ${number(counts.repeat)} · 覆盖 ${number(counts.measured)} / ${number(totals.total)}`;
}

export const dedupNote = '约 30 分钟内同一 IP 与同一浏览器请求特征（User-Agent）访问同一短链接的估算，不等于独立人数。共享 IP 且请求特征相同可能合并不同访客；Worker 本地节点重启或跨节点访问可能让重复次数偏低。统计不保存访客身份。';
