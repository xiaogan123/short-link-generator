import {act,cleanup,fireEvent,render,screen,waitFor,within} from '@testing-library/react';
import {afterEach,beforeEach,expect,it,vi} from 'vitest';
import App from './App';
import type {Plan,State} from './types';

const control=vi.hoisted(()=>({calls:[] as {action:string;payload:Record<string,unknown>}[],state:null as State|null,defer:'',resolve:null as ((value:unknown)=>void)|null,failPrepare:false,failApply:false}));
const initial:State={accounts:[
  {id:'first',label:'主要账户',cloudflareName:'First provider name',zoneCount:0,checkedAt:null,hasResources:true,needsSelftestKey:false},
  {id:'affected',label:'本机备注 · 备用账户',cloudflareName:'Second provider name',zoneCount:1,checkedAt:null,hasResources:false,needsSelftestKey:true},
],domains:[{id:'d',accountId:'first',zoneId:'z',host:'go.example.com',prefix:'r',routeId:'route'}],links:[{domainId:'d',slug:'saved',cnUrl:'https://example.com/a',defaultUrl:'https://example.org/b',updated:''}],pools:[],pendingOperations:['旧版检测密钥操作待核对'],pendingActions:[{kind:'recover_selftest_resources',poolId:null,accountId:'affected',label:'找回检测服务配置'}]};
const plan=(kind='recover_selftest_resources'):Plan=>({id:kind+'-plan',title:kind==='recover_selftest_resources'?'找回检测服务配置':'恢复检测密钥',steps:['只读核对服务归属并登记本机配置'],warnings:[],expiresAt:new Date(Date.now()+300000).toISOString()});
const found=():State=>({...control.state!,accounts:control.state!.accounts.map(a=>a.id==='affected'?{...a,hasResources:true}:a),pendingActions:[{kind:'recover_selftest_rotation',poolId:null,accountId:'affected',label:'恢复旧版自检密钥操作'}]});
vi.mock('./bridge',()=>({preview:true,errorMessage:(e:unknown)=>e instanceof Error?e.message:String(e),dispatch:async(action:string,payload:Record<string,unknown>={})=>{
  control.calls.push({action,payload});
  if(action===control.defer)return new Promise(resolve=>{control.resolve=resolve;});
  if(action==='get_state')return control.state;
  if(action==='prepare_change'){if(control.failPrepare)throw Error('无法准备找回配置计划');return plan(String(payload.kind));}
  if(action==='apply_plan'){if(control.failApply)throw Error('没有找到唯一匹配的检测服务');control.state=found();return control.state;}
  throw Error('Unexpected action '+action);
}}));
beforeEach(()=>{control.state=structuredClone(initial);control.calls=[];control.defer='';control.resolve=null;control.failPrepare=false;control.failApply=false;});
afterEach(cleanup);
const calls=(action:string)=>control.calls.filter(c=>c.action===action);
async function start(){render(<App/>);return screen.findByRole('region',{name:'可继续的变更'});}
async function open(){fireEvent.click(within(await start()).getByRole('button',{name:'找回本机检测配置'}));return screen.findByRole('dialog',{name:'找回检测服务配置'});}

it('identifies the exact account by its local remark and separates selftest recovery from API token validity',async()=>{
 const pending=await start();expect(within(pending).getByText('账户：本机备注 · 备用账户')).toBeTruthy();expect(within(pending).queryByText('Second provider name')).toBeNull();expect(within(pending).getByText(/不是 Cloudflare API 令牌/).textContent).toContain('不代表账户连接失效');
 expect(within(pending).getByText(/先只读核对云端/).textContent).toContain('另行确认恢复检测密钥');
 const details=screen.getByText('查看待处理记录（1 条）').closest('details')!;expect(details.open).toBe(false);expect(within(details).getByText('旧版检测密钥操作待核对')).toBeTruthy();expect(calls('prepare_change')).toHaveLength(0);
});
it('prepares the exact new kind and account only on explicit click; cancelling preserves recovery and saved links',async()=>{
 const review=await open();expect(calls('prepare_change')[0].payload).toEqual({kind:'recover_selftest_resources',accountId:'affected'});expect(within(review).getByText('账户：本机备注 · 备用账户')).toBeTruthy();expect(within(review).getByText(/本次只找回本机检测配置/)).toBeTruthy();
 fireEvent.click(within(review).getByRole('button',{name:'返回'}));expect(calls('apply_plan')).toHaveLength(0);expect(screen.getByRole('button',{name:'找回本机检测配置'})).toBeTruthy();expect(control.state?.links).toEqual(initial.links);expect(control.state?.pendingOperations).toEqual(initial.pendingOperations);
});
it('coalesces repeated preparation clicks and releases the guard after cancellation',async()=>{
 control.defer='prepare_change';const pending=await start();const button=within(pending).getByRole('button',{name:'找回本机检测配置'});fireEvent.click(button);fireEvent.click(button);expect(calls('prepare_change')).toHaveLength(1);
 await act(async()=>control.resolve?.(plan()));fireEvent.click(within(screen.getByRole('dialog',{name:'找回检测服务配置'})).getByRole('button',{name:'返回'}));control.defer='';fireEvent.click(button);await screen.findByRole('dialog',{name:'找回检测服务配置'});expect(calls('prepare_change')).toHaveLength(2);
});
it('success offers a separate key-recovery plan without automatically applying or preparing it',async()=>{
 const review=await open();fireEvent.click(within(review).getByRole('button',{name:'确认并执行'}));await screen.findByText('本机检测配置已找回。请查看新的修复计划，另行确认恢复检测密钥。');
 expect(calls('apply_plan')).toHaveLength(1);expect(calls('apply_plan')[0].payload).toEqual({planId:'recover_selftest_resources-plan'});expect(calls('prepare_change')).toHaveLength(1);expect(control.state?.accounts[1].needsSelftestKey).toBe(true);expect(control.state?.pendingOperations).toEqual(initial.pendingOperations);expect(control.state?.links).toEqual(initial.links);
 fireEvent.click(screen.getByRole('button',{name:'查看修复计划'}));await screen.findByRole('dialog',{name:'恢复检测密钥'});expect(calls('prepare_change')[1].payload).toEqual({kind:'recover_selftest_rotation',accountId:'affected'});expect(calls('apply_plan')).toHaveLength(1);
});
it('while applying, cannot fake cancellation or submit twice',async()=>{
 const review=await open();control.defer='apply_plan';fireEvent.click(within(review).getByRole('button',{name:'确认并执行'}));fireEvent.click(within(review).getByRole('button',{name:'正在提交…'}));expect(calls('apply_plan')).toHaveLength(1);expect((within(review).getByRole('button',{name:'返回'}) as HTMLButtonElement).disabled).toBe(true);
 fireEvent.keyDown(document,{key:'Escape'});fireEvent.click(within(review).getByRole('button',{name:'关闭'}));expect(screen.getByRole('dialog',{name:'找回检测服务配置'})).toBe(review);await act(async()=>control.resolve?.(found()));await screen.findByRole('button',{name:'查看修复计划'});expect(calls('prepare_change')).toHaveLength(1);
});
it.each(['prepare','apply'])('keeps the recovery entry and journal after %s failure, with no automatic retry',async(stage)=>{
 control.failPrepare=stage==='prepare';control.failApply=stage==='apply';const pending=await start();fireEvent.click(within(pending).getByRole('button',{name:'找回本机检测配置'}));if(stage==='apply')fireEvent.click(within(await screen.findByRole('dialog',{name:'找回检测服务配置'})).getByRole('button',{name:'确认并执行'}));
 await waitFor(()=>expect(screen.getByRole('alert').textContent).toContain(stage==='prepare'?'无法准备找回配置计划':'没有找到唯一匹配的检测服务'));
 expect(screen.getByRole('button',{name:'找回本机检测配置'})).toBeTruthy();expect(control.state).toEqual(initial);expect(calls('prepare_change')).toHaveLength(1);expect(calls('apply_plan')).toHaveLength(stage==='apply'?1:0);
});
it.each([null,'removed'])('disables recovery when the target account is unavailable: %s',async(accountId)=>{
 control.state!.pendingActions[0].accountId=accountId;expect((within(await start()).getByRole('button',{name:'找回本机检测配置'}) as HTMLButtonElement).disabled).toBe(true);expect(calls('prepare_change')).toHaveLength(0);
});
