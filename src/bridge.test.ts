import { beforeEach, describe, expect, it, vi } from 'vitest';

beforeEach(() => { vi.resetModules(); window.history.replaceState({}, '', '/?preview=1'); });

describe('explicit preview bridge', () => {
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
