import { beforeEach, expect, it, vi } from 'vitest';

beforeEach(() => { vi.resetModules(); window.history.replaceState({}, '', '/?preview=1&protectionUpgrade=1'); });

it('previews upgrade-required status and preserves an explicit opt-out across upgrade', async () => {
  const { dispatch } = await import('./bridge');
  expect(await dispatch('get_click_protection', {accountId:'demo-a'})).toMatchObject({status:'upgrade_required',limit:100,periodSeconds:10});
  await expect(dispatch('get_click_protection',{accountId:'demo-b'})).rejects.toThrow('尚无云端');
  const disable = await dispatch<{id:string}>('prepare_change',{kind:'disable_click_protection',accountId:'demo-a'});
  expect(await dispatch('get_click_protection',{accountId:'demo-a'})).toMatchObject({status:'upgrade_required'});
  await dispatch('apply_plan',{planId:disable.id});
  expect(await dispatch('get_click_protection',{accountId:'demo-a'})).toMatchObject({status:'disabled'});
  const upgrade = await dispatch<{id:string}>('prepare_change',{kind:'upgrade_worker',accountId:'demo-a'});
  await dispatch('apply_plan',{planId:upgrade.id});
  expect(await dispatch('get_click_protection',{accountId:'demo-a'})).toMatchObject({status:'disabled'});
  const stats = await dispatch<{id:string}>('prepare_change',{kind:'enable_click_stats',accountId:'demo-a'});
  await dispatch('apply_plan',{planId:stats.id});
  expect(await dispatch('get_click_protection',{accountId:'demo-a'})).toMatchObject({status:'disabled'});
  const enable = await dispatch<{id:string}>('prepare_change',{kind:'enable_click_protection',accountId:'demo-a'});
  await dispatch('apply_plan',{planId:enable.id});
  expect(await dispatch('get_click_protection',{accountId:'demo-a'})).toMatchObject({status:'enabled'});
});

it.each(['enable_click_protection', 'enable_click_stats', 'upgrade_worker'])(
  '%s installs a protection-capable worker in preview', async (kind) => {
    const { dispatch } = await import('./bridge');
    expect(await dispatch('get_click_protection',{accountId:'demo-a'})).toMatchObject({status:'upgrade_required'});
    const plan = await dispatch<{id:string}>('prepare_change',{kind,accountId:'demo-a'});
    await dispatch('apply_plan',{planId:plan.id});
    expect(await dispatch('get_click_protection',{accountId:'demo-a'})).toMatchObject({status:'enabled'});
  },
);

it('disabling statistics preserves the old Worker source until a later explicit upgrade', async () => {
  const { dispatch } = await import('./bridge');
  const disable = await dispatch<{id:string}>('prepare_change',{kind:'disable_click_stats',accountId:'demo-a'});
  await dispatch('apply_plan',{planId:disable.id});
  expect(await dispatch('get_click_protection',{accountId:'demo-a'})).toMatchObject({status:'upgrade_required'});
  const upgrade = await dispatch<{id:string}>('prepare_change',{kind:'upgrade_worker',accountId:'demo-a'});
  await dispatch('apply_plan',{planId:upgrade.id});
  expect(await dispatch('get_click_protection',{accountId:'demo-a'})).toMatchObject({status:'enabled'});
});

it('re-enabling protection after an opt-out installs the current Worker source', async () => {
  const { dispatch } = await import('./bridge');
  const disable = await dispatch<{id:string}>('prepare_change',{kind:'disable_click_protection',accountId:'demo-a'});
  await dispatch('apply_plan',{planId:disable.id});
  expect(await dispatch('get_click_protection',{accountId:'demo-a'})).toMatchObject({status:'disabled'});
  const enable = await dispatch<{id:string}>('prepare_change',{kind:'enable_click_protection',accountId:'demo-a'});
  await dispatch('apply_plan',{planId:enable.id});
  expect(await dispatch('get_click_protection',{accountId:'demo-a'})).toMatchObject({status:'enabled'});
});
