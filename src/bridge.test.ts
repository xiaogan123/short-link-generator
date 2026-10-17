import { beforeEach, describe, expect, it, vi } from 'vitest';

beforeEach(() => { vi.resetModules(); window.history.replaceState({}, '', '/?preview=1'); });

describe('explicit preview bridge', () => {
  it('keeps ASCII identity ordering consistent across preview statistics pages',async()=>{
    window.history.replaceState({}, '', '/?preview=1&clickStats=1&manyLinks=1');
    const {dispatch}=await import('./bridge');
    for (const slug of ['Zebra', '_sample', 'alpha']) {
      const plan=await dispatch<{id:string}>('prepare_change',{kind:'save_link',domainId:'demo-d1',slug,cnUrl:'https://example.com/zh',defaultUrl:'https://example.org/en',createOnly:true});
      await dispatch('apply_plan',{planId:plan.id});
    }
    const state=await dispatch<import('./types').State>('get_state');
    const expected=state.links.map(link=>`${link.domainId}\u0000${link.slug}`).sort();
    const actual:string[]=[];
    for (let page=1;page<=Math.ceil(expected.length/25);page++) {
      const report=await dispatch<import('./types').StatsCenterReport>('get_stats_center',{accountId:'demo-a',days:7,page,pageSize:25});
      actual.push(...(report.rows||[]).map(row=>`${row.domainId}\u0000${row.slug}`));
    }
    expect(actual).toEqual(expected);
  });
  it('returns one explicitly selected statistics-center scope with fixed pagination',async()=>{
    window.history.replaceState({}, '', '/?preview=1&clickStats=1&manyLinks=1');
    const {dispatch}=await import('./bridge');
    const report=await dispatch<import('./types').StatsCenterReport>('get_stats_center',{accountId:'demo-a',days:7,page:2,pageSize:25});
    expect(report).toMatchObject({status:'ready',accountId:'demo-a',domainId:null,days:7,page:2,pageSize:25,totalLinks:100,estimated:true});
    expect(report.rows).toHaveLength(25);
    expect(report.rows?.every(row=>['demo-d1','demo-d2'].includes(row.domainId))).toBe(true);
    expect(report.totals?.total).toBe(report.totals!.likelyHuman+report.totals!.likelyBot+report.totals!.unknown);
    const domain=await dispatch<import('./types').StatsCenterReport>('get_stats_center',{accountId:'demo-a',domainId:'demo-d1',days:1,page:1,pageSize:25});
    expect(domain.domainId).toBe('demo-d1');
    expect(domain.rows?.every(row=>row.domainId==='demo-d1')).toBe(true);
    expect(domain.totalLinks).toBe(50);
  });
  it('keeps disabled and no-local-link center states explicit without fabricated totals',async()=>{
    const {dispatch}=await import('./bridge');
    const disabled=await dispatch<import('./types').StatsCenterReport>('get_stats_center',{accountId:'demo-a',days:7,page:1,pageSize:25});
    expect(disabled.status).toBe('disabled');expect(disabled.totals).toBeUndefined();expect(disabled.rows).toBeUndefined();
    const empty=await dispatch<import('./types').StatsCenterReport>('get_stats_center',{accountId:'demo-b',days:7,page:1,pageSize:25});
    expect(empty.status).toBe('no_data');expect(empty.rows).toEqual([]);expect(empty.totals).toBeUndefined();
    expect(empty.message).toContain('不代表历史统计为零');
    for(const fields of [
      {accountId:'missing',days:7,page:1,pageSize:25},
      {accountId:'demo-a',domainId:'demo-zone-3',days:7,page:1,pageSize:25},
      {accountId:'demo-a',days:3,page:1,pageSize:25},
      {accountId:'demo-a',days:7,page:0,pageSize:25},
      {accountId:'demo-a',days:7,page:1,pageSize:10},
    ]) await expect(dispatch('get_stats_center',fields)).rejects.toThrow();
  });
  it('keeps click collection disabled until a confirmed account plan and preserves every existing link',async()=>{
    const {dispatch}=await import('./bridge');
    const state=await dispatch<import('./types').State>('get_state');
    const link=state.links[0];const fields={domainId:link.domainId,slug:link.slug,days:7};
    expect(await dispatch('get_link_stats',fields)).toMatchObject({status:'disabled',estimated:true});
    const plan=await dispatch<{id:string}>('prepare_change',{kind:'enable_click_stats',accountId:'demo-a'});
    expect(await dispatch('get_link_stats',fields)).toMatchObject({status:'disabled'});
    await dispatch('apply_plan',{planId:plan.id});
    expect(await dispatch('get_link_stats',fields)).toMatchObject({status:'ready',totals:{total:128,likelyHuman:84,likelyBot:17,unknown:27,previews:12,prefetches:8}});
    expect((await dispatch<import('./types').State>('get_state')).links).toEqual(state.links);
    const disable=await dispatch<{id:string}>('prepare_change',{kind:'disable_click_stats',accountId:'demo-a'});
    await dispatch('apply_plan',{planId:disable.id});
    const report=await dispatch<import('./types').ClickStats>('get_link_stats',fields);
    expect(report.status).toBe('disabled');expect(report.totals).toBeUndefined();
  });
  it('rejects invalid statistics identities or ranges instead of returning zero',async()=>{
    const {dispatch}=await import('./bridge');
    for(const fields of [{domainId:'missing',slug:'welcome',days:7},{domainId:'demo-d1',slug:'WELCOME',days:7},{domainId:'demo-d1',slug:'welcome',days:'7'},{domainId:'demo-d1',slug:'welcome',days:3}]){
      await expect(dispatch('get_link_stats',fields)).rejects.toThrow();
    }
  });
  it('creates a new name without changing the old link and rejects an occupied name', async () => {
    const {dispatch}=await import('./bridge');
    const before=await dispatch<import('./types').State>('get_state');
    const old=before.links[0];
    const fields={kind:'save_link',domainId:old.domainId,slug:'new-name',cnUrl:old.cnUrl,defaultUrl:old.defaultUrl,createOnly:true};
    await expect(dispatch('prepare_change',{...fields,slug:old.slug})).rejects.toThrow('名称已被使用');
    await expect(dispatch('prepare_change',{...fields,createOnly:'true'})).rejects.toThrow('格式无效');
    const plan=await dispatch<{id:string}>('prepare_change',fields);
    const after=await dispatch<import('./types').State>('apply_plan',{planId:plan.id});
    expect(after.links.find(l=>l.domainId===old.domainId&&l.slug===old.slug)).toEqual(old);
    expect(after.links.find(l=>l.slug==='new-name')).toMatchObject({cnUrl:old.cnUrl,defaultUrl:old.defaultUrl});
  });
  it('rejects a create-only plan if its new name becomes occupied before applying',async()=>{
    const {dispatch}=await import('./bridge');
    const before=await dispatch<import('./types').State>('get_state');
    const old=before.links[0];
    const fields={kind:'save_link',domainId:old.domainId,slug:'new-name',cnUrl:old.cnUrl,defaultUrl:old.defaultUrl,createOnly:true};
    const first=await dispatch<{id:string}>('prepare_change',fields);
    const second=await dispatch<{id:string}>('prepare_change',{...fields,cnUrl:'https://example.com/second'});
    await dispatch('apply_plan',{planId:second.id});
    const occupied=await dispatch<import('./types').State>('get_state');
    await expect(dispatch('apply_plan',{planId:first.id})).rejects.toThrow('名称已被使用');
    expect(await dispatch('get_state')).toEqual(occupied);
  });
  it('starts with labeled synthetic data and applies only prepared plans', async () => {
    const { dispatch, preview } = await import('./bridge');
    expect(preview).toBe(true);
    const state = await dispatch<{ domains: { id: string }[]; links: { slug: string }[] }>('get_state');
    expect(state.domains.length).toBeGreaterThan(0);
    const plan = await dispatch<{ id: string }>('prepare_change', { kind: 'save_link', domainId: state.domains[0].id, slug: 'new-link', cnUrl: 'https://example.com/zh', defaultUrl: 'https://example.org/en' });
    const before = await dispatch<{ links: { slug: string }[] }>('get_state');
    expect(before.links.some(link => link.slug === 'new-link')).toBe(false);
    const after = await dispatch<{ links: { slug: string }[] }>('apply_plan', { planId: plan.id });
    expect(after.links.some(link => link.slug === 'new-link')).toBe(true);
    await expect(dispatch('apply_plan', { planId: plan.id })).rejects.toThrow('计划已过期');
  });
  it('does not include credentials in exported preview configuration', async () => {
    const { dispatch } = await import('./bridge');
    const json = await dispatch<string>('export_config');
    expect(json).not.toMatch(/token|secret|credential/i);
  });
});

it('simulates only the explicit local-configuration recovery and leaves a separate key plan', async () => {
  window.history.replaceState({}, '', '/?preview=1&legacyRecovery=1');
  const {dispatch} = await import('./bridge');
  const before = await dispatch<import('./types').State>('get_state');
  expect(before.pendingActions).toEqual([{kind:'recover_selftest_resources',poolId:null,accountId:'demo-b',label:'找回检测服务配置'}]);
  const plan = await dispatch<import('./types').Plan>('prepare_change', {kind:'recover_selftest_resources',accountId:'demo-b'});
  expect(await dispatch('get_state')).toEqual(before);
  const after = await dispatch<import('./types').State>('apply_plan',{planId:plan.id});
  expect(after.accounts.find(a=>a.id==='demo-b')?.hasResources).toBe(true);
  expect(after.accounts.find(a=>a.id==='demo-b')?.needsSelftestKey).toBe(true);
  expect(after.pendingOperations).toEqual(before.pendingOperations);
  expect(after.pendingActions[0].kind).toBe('recover_selftest_rotation');
  expect(after.links).toEqual(before.links);
  await expect(dispatch('apply_plan',{planId:plan.id})).rejects.toThrow('计划已过期');
  await expect(dispatch('prepare_change',{kind:'recover_selftest_resources',accountId:'demo-b'})).rejects.toThrow('无需找回');
});

it('keeps public-DNS preview results unconfirmed and rejects unsupported modes',async()=>{
  const {dispatch}=await import('./bridge');
  const report=await dispatch<import('./types').TargetReport>('check_link_targets',{dnsMode:'public'});
  expect(report.dnsMode).toBe('public');
  expect(report.checks.every(check=>check.status==='unknown'&&check.message.includes('本地预览'))).toBe(true);
  for(const dnsMode of ['other',null,true,{}])await expect(dispatch('check_link_targets',{dnsMode})).rejects.toThrow('查询方式');
});

it('adds 100 neutral links across domains only with explicit preview manyLinks mode',async()=>{
  window.history.replaceState({}, '', '/?preview=1&manyLinks=1');
  const {dispatch}=await import('./bridge');
  const state=await dispatch<import('./types').State>('get_state');
  expect(state.links).toHaveLength(100);
  expect(new Set(state.links.map(link=>link.domainId)).size).toBeGreaterThan(1);
  expect(state.links.every(link=>link.cnUrl.startsWith('https://example.com/') || link.cnUrl.startsWith('https://example.org/'))).toBe(true);
  expect(state.pools).toEqual([]);
  vi.resetModules();
  window.history.replaceState({}, '', '/?manyLinks=1');
  const regular=await import('./bridge');
  expect(regular.preview).toBe(false);
  vi.resetModules();
  window.history.replaceState({}, '', '/?preview=1');
  const normal=await import('./bridge');
  expect((await normal.dispatch<import('./types').State>('get_state')).links).toHaveLength(3);
});
