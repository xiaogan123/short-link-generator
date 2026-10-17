import { expect, it } from 'vitest';
import { dedupNote, sumDedup, validDedup } from './clickDedup';
import type { ClickStatsTotals } from './types';

const totals = (total: number, dedup?: ClickStatsTotals['dedup']): ClickStatsTotals => ({total,likelyHuman:total,likelyBot:0,unknown:0,previews:0,prefetches:0,dedup});

it('keeps legacy, malformed, and unmeasured nonzero totals uncovered', () => {
  for (const value of [totals(10), totals(10,{first:0,repeat:0}), totals(10,{first:11,repeat:0}), totals(10,{first:2.5,repeat:1}), totals(10,{first:2,repeat:NaN})]) {
    expect(validDedup(value)).toBeNull();
  }
  expect(validDedup(totals(0,{first:0,repeat:0}))).toEqual({first:0,repeat:0,measured:0});
});

it('aggregates only accounts with valid measured coverage', () => {
  expect(sumDedup([totals(10,{first:5,repeat:2}),totals(20),totals(12,{first:20,repeat:0}),totals(8,{first:3,repeat:1})])).toEqual({first:8,repeat:3,measured:11});
  expect(dedupNote).toContain('同一 IP 与同一浏览器请求特征');
  expect(dedupNote).toContain('不等于独立人数');
});
