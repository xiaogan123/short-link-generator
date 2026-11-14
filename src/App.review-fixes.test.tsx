import {act, cleanup, fireEvent, render, screen, waitFor, within} from '@testing-library/react';
import {afterEach, beforeEach, expect, it, vi} from 'vitest';
import App from './App';
import type {ConfigImportReport, State} from './types';

const control = vi.hoisted(() => ({
  state: null as unknown,
  calls: [] as {action: string; payload: Record<string, unknown>}[],
  refresh: null as null | ((accountId: string) => unknown),
  importResult: null as unknown,
}));
const base: State = {
  appVersion:'0.1.27',
  accounts:[
    {id:'a',label:'账号甲',zoneCount:1,checkedAt:null,hasResources:true,needsSelftestKey:false},
    {id:'b',label:'账号乙',zoneCount:1,checkedAt:null,hasResources:true,needsSelftestKey:false,needsCredentialMigration:true},
    {id:'c',label:'账号丙',zoneCount:1,checkedAt:null,hasResources:true,needsSelftestKey:false},
  ],
  domains:[
    {id:'d1',accountId:'a',zoneId:'z1',host:'go.example.com',prefix:'r',routeId:'route-1'},
    {id:'d2',accountId:'a',zoneId:'z2',host:'links.example.org',prefix:'s',routeId:'route-2'},
  ],
  links:[
    {domainId:'d1',slug:'welcome',cnUrl:'https://example.com/cn',defaultUrl:'https://example.org/en',updated:''},
    {domainId:'d2',slug:'guide',cnUrl:'https://example.com/cn/guide',defaultUrl:'https://example.org/en/guide',updated:''},
  ],
  pools:[],pendingOperations:[],pendingActions:[],
};
vi.mock('@tauri-apps/plugin-opener',()=>({openUrl:async()=>{}}));
vi.mock('@tauri-apps/plugin-dialog',()=>({open:async()=>'/synthetic/backup.json',save:async()=>null}));
vi.mock('@tauri-apps/plugin-fs',()=>({readTextFile:async()=>'{"example":true}',writeTextFile:async()=>{}}));
vi.mock('./bridge', () => ({preview:false,errorMessage:(error:unknown)=>error instanceof Error?error.message:String(error),dispatch:async(action:string,payload:Record<string,unknown>={})=>{
  control.calls.push({action,payload});
  if(action==='get_state') return control.state;
  if(action==='refresh_accounts') return control.refresh ? control.refresh(String(payload.accountId)) : control.state;
  if(action==='import_config') return control.importResult;
  throw Error(`Unexpected action ${action}`);
}}));
beforeEach(()=>{control.state=structuredClone(base);control.calls=[];control.refresh=null;control.importResult=null;});
afterEach(()=>{vi.useRealTimers();cleanup();});
const calls=(action:string)=>control.calls.filter(call=>call.action===action);
async function start(){render(<App/>);await screen.findByText('/welcome');}
function accountsPage(){fireEvent.click(screen.getByRole('button',{name:'Cloudflare 账户'}));}
function manage(label:string){
  fireEvent.click(within(screen.getByRole('article',{name:`${label} 账户`})).getByRole('button',{name:`管理 ${label}`}));
  return screen.getByRole('dialog',{name:'账户管理'});
}

it('refreshes accounts one by one, skips one needing local authorization, and names the failures',async()=>{
  control.refresh=(accountId)=>{
    if(accountId==='c') throw Error('令牌已失效，请更换本机令牌。');
    const state=control.state as State;
    control.state={...state,accounts:state.accounts.map(account=>account.id===accountId?{...account,checkedAt:'2026-11-15T00:00:00Z'}:account)};
    return control.state;
  };
  await start();accountsPage();
  fireEvent.click(screen.getByRole('button',{name:'更新状态'}));
  const alert=await screen.findByRole('alert');
  expect(calls('refresh_accounts').map(call=>call.payload)).toEqual([{accountId:'a'},{accountId:'c'}]);
  expect(alert.textContent).toContain('已更新 1 个账户');
  expect(alert.textContent).toContain('「账号乙」需先使用“更新本机授权”');
  expect(alert.textContent).toContain('「账号丙」令牌已失效，请更换本机令牌');
  expect(alert.textContent).not.toContain('。；');
  expect(within(alert).getByRole('button',{name:'更新本机授权'})).toBeTruthy();
  expect(screen.queryByText('账户状态已更新。')).toBeNull();
  expect((screen.getByRole('button',{name:'更新状态'}) as HTMLButtonElement).disabled).toBe(false);
});

it('announces success only when every account was refreshed',async()=>{
  const state=control.state as State;
  control.state={...state,accounts:state.accounts.map(account=>({...account,needsCredentialMigration:false}))};
  await start();accountsPage();
  fireEvent.click(screen.getByRole('button',{name:'更新状态'}));
  expect(await screen.findByText('账户状态已更新。')).toBeTruthy();
  expect(calls('refresh_accounts').map(call=>call.payload)).toEqual([{accountId:'a'},{accountId:'b'},{accountId:'c'}]);
  expect(screen.queryByRole('alert')).toBeNull();
});

it('falls back to all domains when the filtered domain disappears',async()=>{
  await start();
  const select=screen.getByRole('combobox',{name:'筛选域名'}) as HTMLSelectElement;
  fireEvent.change(select,{target:{value:'d2'}});
  expect(screen.queryByText('/welcome')).toBeNull();
  expect(screen.getByText('/guide')).toBeTruthy();
  const state=control.state as State;
  control.refresh=()=>({...state,domains:state.domains.filter(domain=>domain.id!=='d2'),links:state.links.filter(link=>link.domainId!=='d2')});
  accountsPage();
  fireEvent.click(screen.getByRole('button',{name:'更新状态'}));
  await screen.findByRole('alert');
  fireEvent.click(screen.getByRole('button',{name:/^短链接\d*$/}));
  expect(screen.getByText('/welcome')).toBeTruthy();
  expect((screen.getByRole('combobox',{name:'筛选域名'}) as HTMLSelectElement).value).toBe('all');
  expect(screen.queryByText('还没有短链接')).toBeNull();
});

it('blocks deleting the cloud service while the account still has domains',async()=>{
  await start();accountsPage();
  let manager=manage('账号甲');
  expect((within(manager).getByRole('button',{name:'删除云端短链接服务'}) as HTMLButtonElement).disabled).toBe(true);
  expect(manager.textContent).toContain('此账户还有 2 个域名，请先在域名管理中逐个移除后，才能删除云端短链接服务。');
  expect(manager.textContent).not.toContain('个域名下的短链接会失效');
  fireEvent.click(within(manager).getByRole('button',{name:'关闭'}));
  manager=manage('账号丙');
  expect((within(manager).getByRole('button',{name:'删除云端短链接服务'}) as HTMLButtonElement).disabled).toBe(false);
  expect(manager.textContent).toContain('删除后无法通过刷新或导入备份恢复');
  expect(manager.textContent).not.toContain('请先在域名管理中逐个移除');
});

it('disables account cloud actions while another operation is running',async()=>{
  let finish!:(state:unknown)=>void;
  control.refresh=()=>new Promise(resolve=>{finish=resolve;});
  const state=control.state as State;
  control.state={...state,accounts:state.accounts.map(account=>account.id==='c'?{...account,monitorEnabled:true,monitorEndpoint:'https://monitor.example.com'}:account)};
  await start();accountsPage();
  fireEvent.click(screen.getByRole('button',{name:'更新状态'}));
  await waitFor(()=>expect(calls('refresh_accounts')).toHaveLength(1));
  let manager=manage('账号丙');
  for(const name of ['停用检测服务','从 Cloudflare 找回配置','重置检测密钥','删除云端短链接服务'])
    expect((within(manager).getByRole('button',{name}) as HTMLButtonElement).disabled).toBe(true);
  fireEvent.click(within(manager).getByRole('button',{name:'关闭'}));
  await act(async()=>{finish(control.state);});
  await waitFor(()=>expect(calls('refresh_accounts')).toHaveLength(2));
  await act(async()=>{finish(control.state);});
  await waitFor(()=>expect((screen.getByRole('button',{name:'更新状态'}) as HTMLButtonElement).disabled).toBe(false));
  manager=manage('账号丙');
  for(const name of ['停用检测服务','从 Cloudflare 找回配置','重置检测密钥','删除云端短链接服务'])
    expect((within(manager).getByRole('button',{name}) as HTMLButtonElement).disabled).toBe(false);
});

function importResult(configImportReport?: ConfigImportReport){
  const state=control.state as State;
  return {...state,links:[...state.links,{domainId:'d1',slug:'fresh',cnUrl:'https://example.com/fresh',defaultUrl:'https://example.org/fresh',updated:''}],...(configImportReport?{configImportReport}:{})};
}
async function importBackup(){
  await start();accountsPage();
  fireEvent.click(screen.getByRole('button',{name:'导入配置'}));
  await waitFor(()=>expect(calls('import_config')).toHaveLength(1));
}

it('keeps the plain confirmation when the backend sends no import report',async()=>{
  control.importResult=importResult();
  await importBackup();
  expect(await screen.findByText('备份已导入并验证。')).toBeTruthy();
});

it('says nothing was added when every backup item already exists locally',async()=>{
  control.importResult=importResult({domainsAdded:0,linksAdded:0,poolsAdded:0,linksExisting:2,linksDiffering:0});
  await importBackup();
  expect(await screen.findByText('备份里的内容本机都已存在，没有新增。')).toBeTruthy();
});

it('lists what was added, keeps the report out of the state, and lets the notice expire',async()=>{
  control.importResult=importResult({domainsAdded:1,linksAdded:3,poolsAdded:0,linksExisting:2,linksDiffering:0});
  render(<App/>);await screen.findByText('/welcome');
  vi.useFakeTimers({shouldAdvanceTime:true});
  accountsPage();
  fireEvent.click(screen.getByRole('button',{name:'导入配置'}));
  const notice=await screen.findByText(/^备份已导入并验证：/);
  expect(notice.textContent).toBe('备份已导入并验证：新增 1 个域名、3 条链接。本机已有的 2 条链接保持不变。');
  fireEvent.click(screen.getByRole('button',{name:/^短链接\d*$/}));
  expect(screen.getByText('/fresh')).toBeTruthy();
  await act(async()=>{await vi.advanceTimersByTimeAsync(6000);});
  expect(screen.queryByText(/^备份已导入并验证/)).toBeNull();
});

it('keeps a notice about links that differ from the cloud until it is dismissed',async()=>{
  control.importResult=importResult({domainsAdded:0,linksAdded:1,poolsAdded:1,linksExisting:4,linksDiffering:2});
  render(<App/>);await screen.findByText('/welcome');
  vi.useFakeTimers({shouldAdvanceTime:true});
  accountsPage();
  fireEvent.click(screen.getByRole('button',{name:'导入配置'}));
  const text=await screen.findByText(/有链接需要核对/);
  expect(text.textContent).toContain('新增 1 条链接、1 组平台地址。');
  expect(text.textContent).not.toContain('个域名');
  expect(text.textContent).toContain('本机已有的 4 条链接保持不变。');
  expect(text.textContent).toContain('其中 2 条本机内容与云端不同，没有改动');
  expect(text.textContent).toContain('从 Cloudflare 找回配置');
  await act(async()=>{await vi.advanceTimersByTimeAsync(6000);});
  expect(text.isConnected).toBe(true);
  fireEvent.click(within(text.closest('[role="status"]') as HTMLElement).getByRole('button',{name:'关闭通知'}));
  expect(screen.queryByText(/有链接需要核对/)).toBeNull();
});
