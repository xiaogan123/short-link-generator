import {cleanup,fireEvent,render,screen,waitFor,within} from '@testing-library/react';
import {afterEach,expect,it,vi} from 'vitest';
import App from './App';

const control=vi.hoisted(()=>({calls:[] as {action:string;payload:Record<string,unknown>}[],refreshFails:false,prepareFails:false,getStateCount:0,checkState:null as Record<string,unknown>|null}));
const initialState={accounts:[{id:'a',label:'示例账户',cloudflareName:'Example organization',zones:[{id:'z',name:'example.com',status:'active'}],zoneCount:1,checkedAt:null,hasResources:true,needsSelftestKey:false}],domains:[],links:[],pools:[],pendingOperations:[],pendingActions:[]};
const refreshedState={...initialState,accounts:[{...initialState.accounts[0],zones:[{id:'z',name:'new.example.com',status:'active'}],zoneCount:1}]};
vi.mock('./bridge',()=>({preview:false,errorMessage:(error:unknown)=>String(error),dispatch:async(action:string,payload:Record<string,unknown>={})=>{
  control.calls.push({action,payload});
  if(action==='get_state') { control.getStateCount += 1; return control.getStateCount > 1 && control.checkState ? control.checkState : initialState; }
  if(action==='prepare_domain') { if(control.prepareFails) throw new Error('无权读取此域名'); return {host:payload.input,prefix:payload.prefix,candidates:[{accountId:'a',label:'示例账户',zoneId:'z',status:'active'}],checks:[{label:'目录',ok:true,level:'pass',message:'可接入'}],canApply:true,plan:{id:'domain',title:'添加域名',steps:[],warnings:[],expiresAt:new Date(Date.now()+300000).toISOString()}}; }
  if(action==='refresh_accounts') { if(control.refreshFails) throw new Error('令牌无权读取域名'); return refreshedState; }
  throw new Error(`Unexpected ${action}`);
}}));

afterEach(()=>{cleanup();control.calls.length=0;control.refreshFails=false;control.prepareFails=false;control.getStateCount=0;control.checkState=null;});

async function openPreparedDomain() {
  render(<App/>); await screen.findByText('先连接一个域名');
  fireEvent.click(screen.getByRole('button',{name:/^域名管理$/}));
  fireEvent.click(screen.getAllByRole('button',{name:'添加域名'})[0]);
  const dialog=screen.getByRole('dialog',{name:'添加域名'});
  fireEvent.change(within(dialog).getByPlaceholderText('go.example.com'),{target:{value:'old.example.com'}});
  fireEvent.change(within(dialog).getByRole('combobox',{name:/优先使用账户/}),{target:{value:'a'}});
  fireEvent.click(within(dialog).getByRole('button',{name:'检查并接入'}));
  await within(dialog).findByRole('button',{name:'查看接入计划'});
  return dialog;
}

it('refreshes zones, keeps the draft, and invalidates the prepared domain plan',async()=>{
  const dialog=await openPreparedDomain();
  fireEvent.click(within(dialog).getByRole('button',{name:'刷新域名列表'}));
  await waitFor(()=>expect(control.calls.some(call=>call.action==='refresh_accounts')).toBe(true));
  expect((within(dialog).getByPlaceholderText('go.example.com') as HTMLInputElement).value).toBe('old.example.com');
  expect((within(dialog).getByRole('combobox',{name:/优先使用账户/}) as HTMLSelectElement).value).toBe('a');
  expect(within(dialog).queryByRole('button',{name:'查看接入计划'})).toBeNull();
  expect(dialog.querySelector('datalist option')?.getAttribute('value')).toBe('new.example.com');
});

it('syncs refreshed zone cache after a successful domain check',async()=>{
  control.checkState=refreshedState;
  const dialog=await openPreparedDomain();
  expect(control.calls.filter(call=>call.action==='get_state')).toHaveLength(2);
  expect(dialog.querySelector('datalist option')?.getAttribute('value')).toBe('new.example.com');
});

it('shows the refresh failure and does not claim the list was updated',async()=>{
  control.refreshFails=true;
  const dialog=await openPreparedDomain();
  fireEvent.click(within(dialog).getByRole('button',{name:'刷新域名列表'}));
  expect((await within(dialog).findByRole('alert')).textContent).toContain('无法刷新域名列表：Error: 令牌无权读取域名');
  expect(within(dialog).queryByRole('button',{name:'查看接入计划'})).toBeNull();
  expect((within(dialog).getByPlaceholderText('go.example.com') as HTMLInputElement).value).toBe('old.example.com');
  expect(screen.queryByText('账户状态已更新。')).toBeNull();
});


it('shows a direct domain-check failure without claiming the check completed',async()=>{
  control.prepareFails=true;
  render(<App/>); await screen.findByText('先连接一个域名');
  fireEvent.click(screen.getByRole('button',{name:/^域名管理$/}));
  fireEvent.click(screen.getAllByRole('button',{name:'添加域名'})[0]);
  const dialog=screen.getByRole('dialog',{name:'添加域名'});
  fireEvent.change(within(dialog).getByPlaceholderText('go.example.com'),{target:{value:'blocked.example.com'}});
  fireEvent.click(within(dialog).getByRole('button',{name:'检查并接入'}));
  const alert=await within(dialog).findByRole('alert');
  expect(alert.textContent).toContain('Error: 无权读取此域名');
  expect(alert.textContent).not.toContain('检查完成');
  expect(control.calls.filter(call=>call.action==='get_state')).toHaveLength(1);
});
