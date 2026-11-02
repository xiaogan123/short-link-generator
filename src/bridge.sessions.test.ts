import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import type { State, StatsCenterReport, UpdateCancellation } from './types';

beforeEach(()=>{vi.resetModules();window.history.replaceState({},'', '/?preview=1&clickStats=1&manyLinks=1');});
afterEach(()=>{vi.useRealTimers();});

it('reuses a bounded preview read session and rejects expiry and changed scope',async()=>{
  const {dispatch}=await import('./bridge');
  vi.useFakeTimers();
  const first=await dispatch<StatsCenterReport>('get_stats_center',{accountId:'demo-a',days:7,page:1,pageSize:25});
  expect(first.readSessionId).toBeTruthy();
  await vi.advanceTimersByTimeAsync(5000);
  const second=await dispatch<StatsCenterReport>('get_stats_center',{accountId:'demo-a',days:7,page:2,pageSize:25,readSessionId:first.readSessionId});
  expect(second.readSessionId).toBe(first.readSessionId);
  expect(second.queriedAt).toBe(first.queriedAt);
  await expect(dispatch('get_stats_center',{accountId:'demo-a',days:30,page:2,pageSize:25,readSessionId:first.readSessionId})).rejects.toThrow(/过期或范围/);
  await vi.advanceTimersByTimeAsync(55000);
  await expect(dispatch('get_stats_center',{accountId:'demo-a',days:7,page:2,pageSize:25,readSessionId:first.readSessionId})).rejects.toThrow(/过期/);
});

it('rejects a preview session after a local configuration change',async()=>{
  const {dispatch}=await import('./bridge');
  const first=await dispatch<StatsCenterReport>('get_stats_center',{accountId:'demo-a',days:7,page:1,pageSize:25});
  await dispatch('rename_account',{accountId:'demo-a',label:'新示例备注'});
  await expect(dispatch('get_stats_center',{accountId:'demo-a',days:7,page:2,pageSize:25,readSessionId:first.readSessionId})).rejects.toThrow(/范围已变化/);
});

it('exposes token recovery only as an explicit fixture and scopes its confirmed update',async()=>{
  window.history.replaceState({},'', '/?preview=1&tokenRecoveryPreview=1');
  const {dispatch}=await import('./bridge');
  const before=await dispatch<State>('get_state');
  expect(before.accounts[0].needsTokenRecovery).toBe(true);
  await expect(dispatch('import_token',{token:'example-test-value',expectedAccountId:'demo-a'})).rejects.toThrow(/明确确认/);
  const after=await dispatch<State>('import_token',{token:'example-test-value',expectedAccountId:'demo-a',replace:true});
  expect(after.accounts[0].needsTokenRecovery).toBe(false);
  expect(after.accounts[1]).toEqual(before.accounts[1]);
});

it.each(['check','download'])('offers a cancellable %s preview without installation',async mode=>{
  window.history.replaceState({},'', '/?preview=1&updateDelayPreview='+mode);
  const {dispatch}=await import('./bridge');
  vi.useFakeTimers();
  const pending=dispatch(mode==='check'?'check_update':'install_update').then(()=>null,error=>String(error));
  const result=await dispatch<UpdateCancellation>('cancel_update');
  expect(result.status).toBe('cancel_requested');
  expect(await pending).toContain('已取消');
  await expect(dispatch('cancel_update')).rejects.toThrow(/没有可取消/);
  await vi.advanceTimersByTimeAsync(15000);
});

it('delays only explicitly requested preview plan applications for modal keyboard validation',async()=>{
  window.history.replaceState({},'', '/?preview=1&applyDelayPreview=1');
  const {dispatch}=await import('./bridge');
  const plan=await dispatch<{id:string}>('prepare_change',{kind:'save_link',domainId:'demo-d1',slug:'keyboard-sample',cnUrl:'https://example.com/zh',defaultUrl:'https://example.org/en',createOnly:true});
  vi.useFakeTimers();
  let finished=false;
  const pending=dispatch<State>('apply_plan',{planId:plan.id}).then(state=>{finished=true;return state;});
  await vi.advanceTimersByTimeAsync(1000);
  expect(finished).toBe(false);
  const before=await dispatch<State>('get_state');
  expect(before.links.some(link=>link.slug==='keyboard-sample')).toBe(false);
  await vi.advanceTimersByTimeAsync(14000);
  expect((await pending).links.some(link=>link.slug==='keyboard-sample')).toBe(true);
});
