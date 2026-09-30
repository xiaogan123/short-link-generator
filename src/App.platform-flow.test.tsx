import {cleanup,fireEvent,render,screen,waitFor,within} from '@testing-library/react';
import {afterEach,expect,it,vi} from 'vitest';
import App from './App';

const control=vi.hoisted(()=>({
  calls:[] as {action:string;payload:Record<string,unknown>}[],
  applyFails:false,
  deferLinkPlan:false,
  resolveLinkPlan:null as null|((value:unknown)=>void),
  deferPoolPlan:false,
  resolvePoolPlan:null as null|((value:unknown)=>void),
  rejectPoolPlan:null as null|((error:unknown)=>void),
}));

const pool={id:'pool-global',name:'全局示例平台',official:{prefix:'https://example.com/join/',suffix:''},candidates:[{id:'candidate',prefix:'https://example.org/join/',suffix:'',enabled:true}],updated:'2026-09-30T00:00:00Z',accountIds:[],syncStatus:[]};
const baseState={
  accounts:[
    {id:'account-a',label:'示例账户 A',zoneCount:1,checkedAt:null,hasResources:true,needsSelftestKey:false},
    {id:'account-b',label:'示例账户 B',zoneCount:1,checkedAt:null,hasResources:true,needsSelftestKey:false},
  ],
  domains:[
    {id:'domain-a',accountId:'account-a',zoneId:'zone-a',host:'go.example.com',prefix:'r',routeId:'route-a'},
    {id:'domain-b',accountId:'account-b',zoneId:'zone-b',host:'go.example.org',prefix:'r',routeId:'route-b'},
  ],
  links:[],pools:[pool],pendingOperations:[],pendingActions:[],
};
const plan=(title:string)=>({id:'plan',title,steps:['自动配置所选域名账户','保存短链接'],warnings:[],expiresAt:new Date(Date.now()+300000).toISOString()});

vi.mock('./bridge',()=>({
  preview:true,
  errorMessage:(error:unknown)=>String(error),
  dispatch:async(action:string,payload:Record<string,unknown>={})=>{
    control.calls.push({action,payload});
    if(action==='get_state')return baseState;
    if(action==='prepare_change'){
      if(payload.kind==='save_link'&&control.deferLinkPlan)return new Promise(resolve=>{control.resolveLinkPlan=resolve;});
      if(payload.kind==='save_pool'&&control.deferPoolPlan)return new Promise((resolve,reject)=>{control.resolvePoolPlan=resolve;control.rejectPoolPlan=reject;});
      return plan(payload.kind==='save_pool'?'保存平台地址':'保存短链接');
    }
    if(action==='apply_plan'){
      if(control.applyFails)throw new Error('同步当前账户失败');
      return baseState;
    }
    throw new Error(`Unexpected action ${action}`);
  },
}));

afterEach(()=>{
  cleanup();
  control.calls.length=0;
  control.applyFails=false;
  control.deferLinkPlan=false;
  control.resolveLinkPlan=null;
  control.deferPoolPlan=false;
  control.resolvePoolPlan=null;
  control.rejectPoolPlan=null;
});

function saveLinkCall(){return control.calls.find(call=>call.action==='prepare_change'&&call.payload.kind==='save_link');}

it('offers an unsynced global platform to every domain and keeps the selection when the domain changes',async()=>{
  render(<App/>);
  await screen.findByRole('heading',{name:'短链接'});
  fireEvent.click(screen.getAllByRole('button',{name:'新建链接'})[0]);
  const editor=screen.getByRole('dialog',{name:'创建短链接'});
  fireEvent.change(within(editor).getByPlaceholderText('例如 welcome'),{target:{value:'demo'}});
  fireEvent.click(within(editor).getByRole('button',{name:'平台地址'}));
  const platforms=within(editor).getByRole('combobox',{name:'平台地址'});
  expect((platforms as HTMLSelectElement).value).toBe('pool-global');
  expect(within(editor).getByText(/创建时会自动把所需平台配置同步到所选域名的账户/)).toBeTruthy();
  fireEvent.change(within(editor).getByPlaceholderText('例如 member_01'),{target:{value:'DEMO'}});
  fireEvent.change(within(editor).getByRole('combobox',{name:'所属域名'}),{target:{value:'domain-b'}});
  expect((platforms as HTMLSelectElement).value).toBe('pool-global');
  fireEvent.click(within(editor).getByRole('button',{name:'下一步，核对内容'}));
  const review=await screen.findByRole('dialog',{name:'保存短链接'});
  expect(within(review).getByText('跟随平台地址：全局示例平台')).toBeTruthy();
  expect(within(review).getByText('邀请码：DEMO')).toBeTruthy();
  expect(saveLinkCall()?.payload).toMatchObject({domainId:'domain-b',slug:'demo',poolId:'pool-global',code:'DEMO'});
  fireEvent.click(within(review).getByRole('button',{name:'返回'}));
  const restored=screen.getByRole('dialog',{name:'创建短链接'});
  expect((within(restored).getByRole('combobox',{name:'所属域名'}) as HTMLSelectElement).value).toBe('domain-b');
  expect((within(restored).getByRole('combobox',{name:'平台地址'}) as HTMLSelectElement).value).toBe('pool-global');
  expect((within(restored).getByPlaceholderText('例如 member_01') as HTMLInputElement).value).toBe('DEMO');
});

it('returns to the unchanged link draft when applying the confirmed save fails',async()=>{
  control.applyFails=true;
  render(<App/>);
  await screen.findByRole('heading',{name:'短链接'});
  fireEvent.click(screen.getAllByRole('button',{name:'新建链接'})[0]);
  let editor=screen.getByRole('dialog',{name:'创建短链接'});
  fireEvent.change(within(editor).getByPlaceholderText('例如 welcome'),{target:{value:'demo'}});
  fireEvent.click(within(editor).getByRole('button',{name:'平台地址'}));
  fireEvent.change(within(editor).getByPlaceholderText('例如 member_01'),{target:{value:'DEMO'}});
  fireEvent.click(within(editor).getByRole('button',{name:'下一步，核对内容'}));
  fireEvent.click(within(await screen.findByRole('dialog',{name:'保存短链接'})).getByRole('button',{name:'确认并执行'}));
  editor=await screen.findByRole('dialog',{name:'创建短链接'});
  expect((within(editor).getByPlaceholderText('例如 welcome') as HTMLInputElement).value).toBe('demo');
  expect((within(editor).getByPlaceholderText('例如 member_01') as HTMLInputElement).value).toBe('DEMO');
  expect(within(editor).getByRole('alert').textContent).toContain('同步当前账户失败');
});

it('does not reopen a cancelled link draft when a delayed plan arrives',async()=>{
  control.deferLinkPlan=true;
  render(<App/>);
  await screen.findByRole('heading',{name:'短链接'});
  fireEvent.click(screen.getAllByRole('button',{name:'新建链接'})[0]);
  const editor=screen.getByRole('dialog',{name:'创建短链接'});
  fireEvent.change(within(editor).getByPlaceholderText('例如 welcome'),{target:{value:'demo'}});
  fireEvent.click(within(editor).getByRole('button',{name:'平台地址'}));
  fireEvent.change(within(editor).getByPlaceholderText('例如 member_01'),{target:{value:'DEMO'}});
  fireEvent.click(within(editor).getByRole('button',{name:'下一步，核对内容'}));
  await waitFor(()=>expect(saveLinkCall()).toBeTruthy());
  fireEvent.click(within(editor).getByRole('button',{name:'取消'}));
  control.resolveLinkPlan?.(plan('保存短链接'));
  await waitFor(()=>expect(screen.queryByRole('dialog')).toBeNull());
});

it('creates a local platform without exposing account authorization controls',async()=>{
  render(<App/>);
  await screen.findByRole('heading',{name:'短链接'});
  fireEvent.click(screen.getByRole('button',{name:/^平台地址$/}));
  expect(screen.getByText('已用于 0 个账户 · 关联链接 0 条 · 已启用大陆访问地址 1 个')).toBeTruthy();
  fireEvent.click(screen.getByRole('button',{name:'添加平台地址'}));
  const editor=screen.getByRole('dialog',{name:'添加平台地址'});
  expect(within(editor).queryByText('同步到哪些账户')).toBeNull();
  fireEvent.change(within(editor).getByPlaceholderText('例如：常用平台 A'),{target:{value:'新平台'}});
  fireEvent.change(within(editor).getByPlaceholderText('https://example.com/join/'),{target:{value:'https://example.com/join/'}});
  fireEvent.change(within(editor).getByPlaceholderText('https://example.org/join/'),{target:{value:'https://example.org/join/'}});
  fireEvent.click(within(editor).getByRole('button',{name:'下一步，核对内容'}));
  const review=await screen.findByRole('dialog',{name:'保存平台地址'});
  const savePool=control.calls.find(call=>call.action==='prepare_change'&&call.payload.kind==='save_pool');
  expect((savePool?.payload.pool as {accountIds:string[]}).accountIds).toEqual([]);
  expect(within(review).getByText('已使用账户：尚无；创建链接时会自动配置到对应账户')).toBeTruthy();
  fireEvent.click(within(review).getByRole('button',{name:'返回'}));
  expect((within(screen.getByRole('dialog',{name:'添加平台地址'})).getByPlaceholderText('例如：常用平台 A') as HTMLInputElement).value).toBe('新平台');
});

async function submitPoolWhilePlanIsDeferred(){
  control.deferPoolPlan=true;
  render(<App/>);
  await screen.findByRole('heading',{name:'短链接'});
  fireEvent.click(screen.getByRole('button',{name:/^平台地址$/}));
  fireEvent.click(screen.getByRole('button',{name:'添加平台地址'}));
  const editor=screen.getByRole('dialog',{name:'添加平台地址'});
  fireEvent.change(within(editor).getByPlaceholderText('例如：常用平台 A'),{target:{value:'旧草稿'}});
  fireEvent.change(within(editor).getByPlaceholderText('https://example.com/join/'),{target:{value:'https://example.com/join/'}});
  fireEvent.change(within(editor).getByPlaceholderText('https://example.org/join/'),{target:{value:'https://example.org/join/'}});
  fireEvent.click(within(editor).getByRole('button',{name:'下一步，核对内容'}));
  await waitFor(()=>expect(control.resolvePoolPlan).toBeTruthy());
  fireEvent.click(within(editor).getByRole('button',{name:'取消'}));
  fireEvent.click(screen.getByRole('button',{name:'添加平台地址'}));
  return screen.getByRole('dialog',{name:'添加平台地址'});
}

it('ignores a delayed pool plan after cancel and does not replace a newly opened draft',async()=>{
  const current=await submitPoolWhilePlanIsDeferred();
  control.resolvePoolPlan?.(plan('保存平台地址'));
  await waitFor(()=>expect((within(current).getByRole('button',{name:'下一步，核对内容'}) as HTMLButtonElement).disabled).toBe(false));
  expect(screen.queryByRole('dialog',{name:'保存平台地址'})).toBeNull();
  expect((within(current).getByPlaceholderText('例如：常用平台 A') as HTMLInputElement).value).toBe('');
});

it('does not show a delayed pool-plan failure on the draft opened after cancellation',async()=>{
  const current=await submitPoolWhilePlanIsDeferred();
  control.rejectPoolPlan?.(new Error('旧草稿准备失败'));
  await waitFor(()=>expect((within(current).getByRole('button',{name:'下一步，核对内容'}) as HTMLButtonElement).disabled).toBe(false));
  expect(within(current).queryByRole('alert')).toBeNull();
  expect(screen.queryByText(/旧草稿准备失败/)).toBeNull();
});
