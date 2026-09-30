import { beforeEach, describe, expect, it, vi } from 'vitest';

beforeEach(() => { vi.resetModules(); window.history.replaceState({}, '', '/?preview=1'); });

describe('explicit preview bridge', () => {
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
