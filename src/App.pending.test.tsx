import {cleanup,fireEvent,render,screen,waitFor,within} from '@testing-library/react';
import {afterEach,expect,it,vi} from 'vitest';
import App from './App';

const calls=vi.hoisted(()=>[] as {action:string;payload:Record<string,unknown>}[]);
vi.mock('./bridge',()=>{
  let pending=true;
  const state=()=>({accounts:[{id:'a',label:'示例账户',zoneCount:1,checkedAt:null,hasResources:true,needsSelftestKey:false}],domains:[],links:[],pools:[{id:'p',name:'示例地址池',official:{prefix:'https://example.com/path/',suffix:''},candidates:[{id:'c',prefix:'https://example.org/path/',suffix:'',enabled:true}],updated:'',accountIds:['a']}],pendingOperations:['待处理变更需核对'],pendingActions:pending?[{kind:'resume_pool_sync',poolId:'p',accountId:null,label:'继续同步示例地址池'},{kind:'resume_monitor',poolId:null,accountId:'a',label:'继续启用检测服务'}]:[]});
  return {preview:true,errorMessage:(error:unknown)=>String(error),dispatch:async(action:string,payload:Record<string,unknown>={})=>{calls.push({action,payload});if(action==='get_state')return state();if(action==='prepare_change'||action==='resume_monitor')return {id:'plan',title:action==='resume_monitor'?'继续处理检测服务':'继续同步地址池',steps:['复核资源并继续'],warnings:[],expiresAt:new Date(Date.now()+300000).toISOString()};if(action==='apply_plan'){pending=false;return state();}throw new Error(`Unexpected action ${action}`);}};
});

afterEach(()=>{cleanup();calls.length=0;});

it('offers structured pending actions and requires a review plan before resuming',async()=>{
  render(<App/>);
  expect(await screen.findByRole('region',{name:'可继续的变更'})).toBeTruthy();
  fireEvent.click(screen.getByRole('button',{name:'继续同步'}));
  const poolPlan=await screen.findByRole('dialog',{name:'继续同步地址池'});
  expect(within(poolPlan).getByText('平台地址：示例地址池')).toBeTruthy();
  expect(calls.some(call=>call.action==='prepare_change'&&call.payload.kind==='resume_pool_sync'&&call.payload.poolId==='p')).toBe(true);
  fireEvent.click(within(poolPlan).getByRole('button',{name:'返回'}));
  fireEvent.click(screen.getByRole('button',{name:'继续处理监测'}));
  const monitorPlan=await screen.findByRole('dialog',{name:'继续处理检测服务'});
  expect(within(monitorPlan).getByText('账户：示例账户')).toBeTruthy();
  expect(calls.some(call=>call.action==='resume_monitor'&&call.payload.accountId==='a')).toBe(true);
  fireEvent.click(within(monitorPlan).getByRole('button',{name:'确认并执行'}));
  await waitFor(()=>expect(screen.queryByRole('region',{name:'可继续的变更'})).toBeNull());
});
