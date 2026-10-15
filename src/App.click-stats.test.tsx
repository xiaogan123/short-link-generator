import {act, cleanup, fireEvent, render, screen, waitFor, within} from '@testing-library/react';
import {afterEach, beforeEach, expect, it, vi} from 'vitest';
import App from './App';
import type {State} from './types';

const control = vi.hoisted(() => ({
  calls: [] as {action:string;payload:Record<string,unknown>}[],
  enabled:false, deferred:false, failPrepare:false, failApply:false,
  resolve:null as null | ((value:unknown)=>void),
}));
const initial:State = {
  accounts:[
    {id:'a',label:'示例账户',zoneCount:2,checkedAt:null,hasResources:true,needsSelftestKey:false},
    {id:'b',label:'其他账户',zoneCount:1,checkedAt:null,hasResources:true,needsSelftestKey:false},
  ],
  domains:[
    {id:'d',accountId:'a',zoneId:'z',host:'go.example.com',prefix:'r',routeId:'route'},
    {id:'d2',accountId:'a',zoneId:'z2',host:'links.example.org',prefix:'go',routeId:'route2'},
    {id:'d3',accountId:'b',zoneId:'z3',host:'other.example.net',prefix:'r',routeId:'route3'},
  ],
  links:[{domainId:'d',slug:'OK',cnUrl:'https://example.com/join/Code_A',defaultUrl:'https://example.org/join/Code_A',updated:''}],
  pools:[],pendingActions:[],pendingOperations:[],
};
const plan = (enabled=true) => ({id:enabled?'enable':'disable',title:enabled?'启用点击统计':'停用点击统计',steps:['访客保持直接跳转，不做访问验证'],warnings:[],expiresAt:new Date(Date.now()+300000).toISOString()});
vi.mock('./bridge',()=>({preview:false,errorMessage:(error:unknown)=>error instanceof Error?error.message:String(error),dispatch:async(action:string,payload:Record<string,unknown>={})=>{
  control.calls.push({action,payload});
  if(action==='get_state')return structuredClone(initial);
  if(action==='get_link_stats')return {
    status:control.enabled?'ready':'disabled',message:'仅统计请求特征',domainId:payload.domainId,slug:payload.slug,days:payload.days,queriedAt:new Date().toISOString(),estimated:true,
    ...(control.enabled?{totals:{total:12,likelyHuman:7,likelyBot:3,unknown:2,previews:4,prefetches:1}}:{}),
  };
  if(action==='prepare_change'){
    if(control.failPrepare)throw Error('统计读取权限不足，请编辑原有令牌。');
    if(control.deferred)return new Promise(resolve=>{control.resolve=resolve;});
    return plan(payload.kind==='enable_click_stats');
  }
  if(action==='apply_plan'){if(control.failApply)throw Error('统计变更未确认完成，请先核对当前状态。');control.enabled=payload.planId==='enable';return structuredClone(initial);}
  throw Error(`Unexpected action: ${action}`);
}}));
beforeEach(()=>{control.calls=[];control.enabled=false;control.deferred=false;control.failPrepare=false;control.failApply=false;control.resolve=null;});
afterEach(()=>{cleanup();vi.restoreAllMocks();});
const calls=(action:string)=>control.calls.filter(call=>call.action===action);
async function open(){render(<App/>);fireEvent.click(await screen.findByRole('button',{name:'点击统计 OK'}));return screen.findByRole('dialog',{name:'访问统计 · /OK'});}

it('does not read statistics or prepare cloud changes on startup',async()=>{
  render(<App/>);await screen.findByRole('button',{name:'点击统计 OK'});
  expect(calls('get_link_stats')).toHaveLength(0);expect(calls('prepare_change')).toHaveLength(0);expect(calls('apply_plan')).toHaveLength(0);
});
it('prepares only the selected account, lists all its domains and permits cancellation',async()=>{
  const stats=await open();fireEvent.click(await within(stats).findByRole('button',{name:'启用账户统计'}));
  const review=await screen.findByRole('dialog',{name:'启用点击统计'});
  expect(calls('prepare_change')[0].payload).toEqual({kind:'enable_click_stats',accountId:'a'});
  expect(review.textContent).toContain('go.example.com/r/');expect(review.textContent).toContain('links.example.org/go/');expect(review.textContent).not.toContain('other.example.net');
  expect(review.textContent).toContain('不做访问验证');expect(calls('apply_plan')).toHaveLength(0);
  fireEvent.click(within(review).getByRole('button',{name:'返回'}));
  const returned=await screen.findByRole('dialog',{name:'访问统计 · /OK'});
  expect(await within(returned).findByRole('button',{name:'启用账户统计'})).toBeTruthy();expect(calls('apply_plan')).toHaveLength(0);
});
it('applies only after confirmation and refreshes the original exact-case link report',async()=>{
  const stats=await open();fireEvent.click(await within(stats).findByRole('button',{name:'启用账户统计'}));
  const review=await screen.findByRole('dialog',{name:'启用点击统计'});expect(calls('apply_plan')).toHaveLength(0);
  fireEvent.click(within(review).getByRole('button',{name:'确认并执行'}));
  const returned=await screen.findByRole('dialog',{name:'访问统计 · /OK'});expect(await within(returned).findByText('12')).toBeTruthy();
  expect(calls('apply_plan')).toHaveLength(1);expect(calls('get_link_stats').every(call=>call.payload.domainId==='d'&&call.payload.slug==='OK')).toBe(true);
  fireEvent.keyDown(document,{key:'Escape'});
  expect(await screen.findByRole('button',{name:'编辑 OK'})).toBeTruthy();expect(screen.getByText('https://go.example.com/r/OK')).toBeTruthy();
});
it('disabling also requires confirmation and keeps the selected account scope',async()=>{
  control.enabled=true;const stats=await open();fireEvent.click(await within(stats).findByRole('button',{name:'停用账户统计'}));
  const review=await screen.findByRole('dialog',{name:'停用点击统计'});expect(calls('prepare_change')[0].payload).toEqual({kind:'disable_click_stats',accountId:'a'});expect(calls('apply_plan')).toHaveLength(0);
  fireEvent.click(within(review).getByRole('button',{name:'确认并执行'}));
  expect(await screen.findByRole('button',{name:'启用账户统计'})).toBeTruthy();expect(calls('apply_plan')).toHaveLength(1);
});
it('closing while preparing cannot reopen a late cloud plan or apply it',async()=>{
  control.deferred=true;const stats=await open();const enable=await within(stats).findByRole('button',{name:'启用账户统计'});
  fireEvent.click(enable);fireEvent.click(enable);expect(calls('prepare_change')).toHaveLength(1);
  fireEvent.keyDown(document,{key:'Escape'});expect(screen.queryByRole('dialog')).toBeNull();
  await act(async()=>{control.resolve?.(plan());});expect(screen.queryByRole('dialog')).toBeNull();expect(calls('apply_plan')).toHaveLength(0);
});
it('failed preparation stays actionable in the same statistics dialog',async()=>{
  control.failPrepare=true;const stats=await open();fireEvent.click(await within(stats).findByRole('button',{name:'启用账户统计'}));
  await waitFor(()=>expect(within(stats).getByRole('alert').textContent).toContain('编辑原有令牌'));
  expect(screen.getByRole('dialog',{name:'访问统计 · /OK'})).toBe(stats);expect(calls('apply_plan')).toHaveLength(0);
  control.failPrepare=false;fireEvent.click(within(stats).getByRole('button',{name:'启用账户统计'}));expect(await screen.findByRole('dialog',{name:'启用点击统计'})).toBeTruthy();
});
it.each([false,true])('shows failed cloud application inside the statistics dialog (enabled=%s)',async(enabled)=>{
  control.enabled=enabled;control.failApply=true;const stats=await open();
  fireEvent.click(await within(stats).findByRole('button',{name:enabled?'停用账户统计':'启用账户统计'}));
  const review=await screen.findByRole('dialog',{name:enabled?'停用点击统计':'启用点击统计'});
  fireEvent.click(within(review).getByRole('button',{name:'确认并执行'}));
  const returned=await screen.findByRole('dialog',{name:'访问统计 · /OK'});
  expect((await within(returned).findByRole('alert')).textContent).toContain('请先核对当前状态');
  expect(await within(returned).findByRole('button',{name:enabled?'停用账户统计':'启用账户统计'})).toBeTruthy();
  expect(calls('apply_plan')).toHaveLength(1);
});
