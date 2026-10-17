import { cleanup, fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import { afterEach, expect, it, vi } from 'vitest';
import App from './App';

const control = vi.hoisted(() => ({calls: [] as {action:string;payload:Record<string,unknown>}[],status:'enabled' as 'enabled'|'disabled'}));
vi.mock('./bridge', () => ({preview:false,errorMessage:(error:unknown)=>error instanceof Error?error.message:String(error),dispatch:async(action:string,payload:Record<string,unknown>={})=>{
  control.calls.push({action,payload});
  if(action==='get_state'||action==='apply_plan')return {accounts:[{id:'a',label:'示例账户',zoneCount:1,checkedAt:null,hasResources:true,needsSelftestKey:false}],domains:[{id:'d',accountId:'a',zoneId:'z',host:'go.example.com',prefix:'r',routeId:'route'}],links:[],pools:[],pendingActions:[],pendingOperations:[]};
  if(action==='get_click_protection')return {accountId:'a',status:control.status,limit:100,periodSeconds:10,checkedAt:'2026-10-15T00:00:00Z'};
  if(action==='prepare_change')return {id:'plan',title:payload.kind==='disable_click_protection'?'停用访问保护':'启用访问保护',steps:['核对云端服务'],warnings:[],expiresAt:new Date(Date.now()+300000).toISOString()};
  throw Error(`Unexpected action ${action}`);
}}));
afterEach(()=>{cleanup();control.calls=[];control.status='enabled';});

async function openManager(){
  render(<App/>);
  fireEvent.click(await screen.findByRole('button',{name:/^Cloudflare 账户$/}));
  fireEvent.click(screen.getByRole('button',{name:'管理 示例账户'}));
  return screen.getByRole('dialog',{name:'账户管理'});
}

it('reads protection only on request and prepares a scoped, cancellable plan',async()=>{
  const manager=await openManager();
  expect(control.calls.some(call=>call.action==='get_click_protection')).toBe(false);
  fireEvent.click(within(manager).getByRole('button',{name:'读取保护状态'}));
  await waitFor(()=>expect(within(manager).getByRole('status').textContent).toContain('已启用'));
  expect(control.calls.filter(call=>call.action==='get_click_protection').map(call=>call.payload)).toEqual([{accountId:'a'}]);
  fireEvent.click(within(manager).getByRole('button',{name:'停用访问保护'}));
  const review=await screen.findByRole('dialog',{name:'停用访问保护'});
  expect(review.textContent).toContain('go.example.com/r/');
  expect(control.calls.find(call=>call.action==='prepare_change')?.payload).toEqual({kind:'disable_click_protection',accountId:'a'});
  expect(control.calls.some(call=>call.action==='apply_plan')).toBe(false);
  fireEvent.click(within(review).getByRole('button',{name:'返回'}));
  expect(control.calls.some(call=>call.action==='apply_plan')).toBe(false);
});
