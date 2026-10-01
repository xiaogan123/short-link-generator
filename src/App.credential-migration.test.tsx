import {act, cleanup, fireEvent, render, screen, waitFor, within} from '@testing-library/react';
import {afterEach, beforeEach, expect, it, vi} from 'vitest';
import App from './App';
import type {State} from './types';

const control = vi.hoisted(() => ({
  state: null as State | null,
  calls: [] as {action: string; payload: Record<string, unknown>}[],
  defer: '', failApply: false, failPrepare: false,
  resolve: null as null | ((value: unknown) => void),
}));
const initial: State = {
  accounts: [
    {id:'a',label:'旧账户',zoneCount:1,checkedAt:null,hasResources:true,needsSelftestKey:false,needsCredentialMigration:true,zones:[{id:'z',name:'example.com',status:'active'}]},
    {id:'b',label:'新账户',zoneCount:1,checkedAt:null,hasResources:false,needsSelftestKey:false,needsCredentialMigration:false,zones:[{id:'z-b',name:'example.org',status:'active'}]},
  ],
  domains:[{id:'d',accountId:'a',zoneId:'z',host:'go.example.com',prefix:'r',routeId:'route'}],
  links:[],pools:[],pendingOperations:[],pendingActions:[],
};
const plan = () => ({id:'migration-plan',title:'更新本机授权',steps:['读取此账户的旧凭据','写入新的本机凭据存储'],warnings:[],expiresAt:new Date(Date.now()+300000).toISOString(),credentialMigrationConfirmation:'系统可能需要你授权访问已保存的令牌或检测密钥；已有记录会保留，云端配置不变。'});
const migrated = () => ({...control.state!,accounts:control.state!.accounts.map(a=>a.id==='a'?{...a,needsCredentialMigration:false}:a)});
vi.mock('./bridge', () => ({preview:false,errorMessage:(e:unknown)=>e instanceof Error?e.message:String(e),dispatch:async(action:string,payload:Record<string,unknown>={})=>{
  control.calls.push({action,payload});
  if(action===control.defer) return new Promise(resolve=>{control.resolve=resolve;});
  if(action==='get_state'||action==='refresh_domains'||action==='refresh_accounts'||action==='import_config') return control.state;
  if(action==='rename_account') {control.state={...control.state!,accounts:control.state!.accounts.map(a=>a.id===payload.accountId?{...a,label:String(payload.label)}:a)};return control.state;}
  if(action==='check_pool_health')return {poolId:payload.poolId,accounts:[]};
  if(action==='prepare_change') {if(control.failPrepare)throw Error('无法准备本机授权更新。');return plan();}
  if(action==='prepare_domain') return {host:payload.input,prefix:payload.prefix,candidates:[],checks:[],canApply:false};
  if(action==='apply_plan') {if(control.failApply)throw Error('本机授权未完成，请稍后重试。');control.state=migrated();return control.state;}
  throw Error(`Unexpected ${action}`);
}}));
vi.mock('@tauri-apps/plugin-dialog',()=>({open:async()=>{control.calls.push({action:'backup_open',payload:{}});return '/synthetic/current-account-backup.json';}}));
vi.mock('@tauri-apps/plugin-fs',()=>({readTextFile:async()=>'{"version":1,"domains":[{"host":"go.example.org","prefix":"r"}],"links":[]}'}));
beforeEach(()=>{control.state=structuredClone(initial);control.calls=[];control.defer='';control.failApply=false;control.failPrepare=false;control.resolve=null;});
afterEach(()=>{cleanup();vi.restoreAllMocks();window.history.replaceState({},'', '/');});
async function start(){render(<App/>);await waitFor(()=>expect(screen.queryByText('正在读取本机配置…')).toBeNull());}
async function manager(){fireEvent.click(screen.getByRole('button',{name:'Cloudflare 账户'}));fireEvent.click(screen.getByRole('button',{name:'管理 旧账户'}));return screen.getByRole('dialog',{name:'账户管理'});}
async function domainEditor(account='a'){
  fireEvent.click(screen.getByRole('button',{name:'域名管理'}));fireEvent.click(screen.getAllByRole('button',{name:'添加域名'})[0]);
  const editor=screen.getByRole('dialog',{name:'添加域名'});
  fireEvent.change(within(editor).getByRole('combobox',{name:'Cloudflare 账户'}),{target:{value:account}});
  fireEvent.change(within(editor).getByPlaceholderText('go.example.com'),{target:{value:'draft.example.com'}});
  fireEvent.change(within(editor).getByRole('textbox',{name:/链接目录/}),{target:{value:'saved'}});
  return editor;
}
async function confirmFrom(editor:HTMLElement){fireEvent.click(within(editor).getByRole('button',{name:'更新本机授权'}));return screen.findByRole('dialog',{name:'更新本机授权'});}
const calls=(action:string)=>control.calls.filter(call=>call.action===action);

it('local account display and rename do not trigger credential access or migration',async()=>{
  await start();const editor=await manager();expect(calls('prepare_change')).toHaveLength(0);expect(calls('refresh_accounts')).toHaveLength(0);
  fireEvent.click(within(editor).getByRole('button',{name:'修改本机备注'}));const rename=screen.getByRole('dialog',{name:'重命名账户'});
  fireEvent.change(within(rename).getByLabelText('账户名称'),{target:{value:'本机备注'}});fireEvent.click(within(rename).getByRole('button',{name:'保存名称'}));
  await waitFor(()=>expect(calls('rename_account')).toHaveLength(1));expect(calls('prepare_change')).toHaveLength(0);expect(calls('apply_plan')).toHaveLength(0);
});
it('requires explicit migration entry and confirmation; cancelling permits a fresh plan',async()=>{
  await start();const editor=await manager();const review=await confirmFrom(editor);
  expect(calls('prepare_change')[0].payload).toEqual({kind:'migrate_credentials',accountId:'a'});
  expect(within(review).getByText(/系统可能需要你授权/).textContent).toContain('已有记录会保留，云端配置不变');expect(calls('apply_plan')).toHaveLength(0);
  fireEvent.click(within(review).getByRole('button',{name:'返回'}));expect(screen.queryByRole('dialog')).toBeNull();
  await confirmFrom(await manager());expect(calls('prepare_change')).toHaveLength(2);expect(calls('apply_plan')).toHaveLength(0);
});
it('coalesces repeated migration preparation clicks under the mutation guard',async()=>{
  control.defer='prepare_change';await start();const editor=await manager();const entry=within(editor).getByRole('button',{name:'更新本机授权'});
  fireEvent.click(entry);fireEvent.click(entry);expect(calls('prepare_change')).toHaveLength(1);
  fireEvent.keyDown(document,{key:'Escape'});expect(screen.getByRole('dialog',{name:'账户管理'})).toBe(editor);
  await act(async()=>control.resolve?.(plan()));expect(screen.getByRole('dialog',{name:'更新本机授权'})).toBeTruthy();
});
it('sends an actual boolean acknowledgement once and cannot dismiss the running native operation',async()=>{
  control.defer='apply_plan';await start();const review=await confirmFrom(await manager());
  fireEvent.click(within(review).getByRole('button',{name:'确认更新本机授权'}));fireEvent.click(within(review).getByRole('button',{name:'正在提交…'}));
  expect(calls('apply_plan')).toHaveLength(1);expect(calls('apply_plan')[0].payload).toEqual({planId:'migration-plan',acknowledgeCredentialMigration:true});
  expect((within(review).getByRole('button',{name:'返回'}) as HTMLButtonElement).disabled).toBe(true);
  fireEvent.keyDown(document,{key:'Escape'});fireEvent.mouseDown(review.parentElement!);fireEvent.click(within(review).getByRole('button',{name:'关闭'}));
  expect(screen.getByRole('dialog',{name:'更新本机授权'})).toBe(review);
  await act(async()=>control.resolve?.(migrated()));await screen.findByText('本机授权已更新，请重试刚才的操作');
  expect(control.calls.map(c=>c.action)).toEqual(['get_state','prepare_change','apply_plan']);
});
it('blocks old selected-account refresh before dispatch and preserves its domain draft on migration failure',async()=>{
  control.failApply=true;await start();const editor=await domainEditor();fireEvent.click(within(editor).getByRole('button',{name:'刷新域名列表'}));
  expect(calls('refresh_domains')).toHaveLength(0);expect(calls('prepare_change')).toHaveLength(0);
  const review=await confirmFrom(editor);expect(calls('prepare_change')[0].payload.accountId).toBe('a');
  fireEvent.click(within(review).getByRole('button',{name:'确认更新本机授权'}));const restored=await screen.findByRole('dialog',{name:'添加域名'});
  await within(restored).findByText('本机授权未完成，请稍后重试。');
  expect((within(restored).getByPlaceholderText('go.example.com') as HTMLInputElement).value).toBe('draft.example.com');
  expect((within(restored).getByRole('textbox',{name:/链接目录/}) as HTMLInputElement).value).toBe('saved');
  expect((within(restored).getByRole('combobox',{name:'Cloudflare 账户'}) as HTMLSelectElement).value).toBe('a');
  expect(calls('apply_plan')).toHaveLength(1);expect(calls('refresh_domains')).toHaveLength(0);
  await confirmFrom(restored);expect(calls('prepare_change')).toHaveLength(2);expect(calls('apply_plan')).toHaveLength(1);
});
it('successful migration retains the domain draft and does not replay refresh until another explicit click',async()=>{
  await start();const editor=await domainEditor();fireEvent.click(within(editor).getByRole('button',{name:'刷新域名列表'}));
  const review=await confirmFrom(editor);fireEvent.click(within(review).getByRole('button',{name:'确认更新本机授权'}));
  const restored=await screen.findByRole('dialog',{name:'添加域名'});await within(restored).findByText('本机授权已更新，请重试刚才的操作');
  expect((within(restored).getByPlaceholderText('go.example.com') as HTMLInputElement).value).toBe('draft.example.com');
  expect(calls('refresh_domains')).toHaveLength(0);expect(calls('prepare_domain')).toHaveLength(0);
  fireEvent.click(within(restored).getByRole('button',{name:'刷新域名列表'}));await waitFor(()=>expect(calls('refresh_domains')).toHaveLength(1));
  expect(calls('refresh_domains')[0].payload).toEqual({accountId:'a'});
});
it('cancelling the migration review retains the open domain draft without applying anything',async()=>{
  await start();const review=await confirmFrom(await domainEditor());fireEvent.click(within(review).getByRole('button',{name:'返回'}));
  const restored=screen.getByRole('dialog',{name:'添加域名'});expect((within(restored).getByPlaceholderText('go.example.com') as HTMLInputElement).value).toBe('draft.example.com');expect(calls('apply_plan')).toHaveLength(0);
});
it('preserves an unsaved link draft after migration fails without preparing a cloud write',async()=>{
  control.failApply=true;await start();fireEvent.click(screen.getAllByRole('button',{name:'新建链接'})[0]);let editor=screen.getByRole('dialog',{name:'创建短链接'});
  fireEvent.change(within(editor).getByPlaceholderText('例如 welcome'),{target:{value:'draft-link'}});
  fireEvent.change(within(editor).getByPlaceholderText('https://example.com/zh'),{target:{value:'https://example.com/kept'}});
  fireEvent.change(within(editor).getByPlaceholderText('https://example.com/en'),{target:{value:'https://example.org/kept'}});
  fireEvent.click(within(editor).getByRole('button',{name:'下一步，核对内容'}));expect(calls('prepare_change')).toHaveLength(0);
  const review=await confirmFrom(editor);fireEvent.click(within(review).getByRole('button',{name:'确认更新本机授权'}));editor=await screen.findByRole('dialog',{name:'创建短链接'});
  await within(editor).findByText('本机授权未完成，请稍后重试。');
  expect((within(editor).getByPlaceholderText('例如 welcome') as HTMLInputElement).value).toBe('draft-link');
  expect((within(editor).getByPlaceholderText('https://example.com/zh') as HTMLInputElement).value).toBe('https://example.com/kept');
  expect((within(editor).getByPlaceholderText('https://example.com/en') as HTMLInputElement).value).toBe('https://example.org/kept');
  expect(calls('prepare_change').map(c=>c.payload.kind)).toEqual(['migrate_credentials']);
});
it('a current selected account can refresh despite a different legacy account; progress does not demand a password',async()=>{
  control.defer='refresh_domains';await start();const editor=await domainEditor('b');expect(within(editor).queryByRole('button',{name:'更新本机授权'})).toBeNull();
  fireEvent.click(within(editor).getByRole('button',{name:'刷新域名列表'}));expect(calls('refresh_domains')[0].payload).toEqual({accountId:'b'});
  expect(within(editor).getByRole('status').textContent).toBe('正在读取此账户的域名，请稍候。');
  await act(async()=>control.resolve?.(control.state));
});
it('preview can simulate a legacy account and requires true acknowledgement without native access',async()=>{
  window.history.replaceState({},'', '/?preview=1&legacyCredentials=1');
  const bridge=await vi.importActual<typeof import('./bridge')>('./bridge');
  const before=await bridge.dispatch<State>('get_state');expect(before.accounts[0].needsCredentialMigration).toBe(true);
  const prepared=await bridge.dispatch<{id:string;credentialMigrationConfirmation:string}>('prepare_change',{kind:'migrate_credentials',accountId:'demo-a'});
  expect(prepared.credentialMigrationConfirmation).toContain('已有记录会保留');expect((await bridge.dispatch<State>('get_state')).accounts[0].needsCredentialMigration).toBe(true);
  for(const ack of [undefined,false,'true']) await expect(bridge.dispatch('apply_plan',{planId:prepared.id,acknowledgeCredentialMigration:ack})).rejects.toThrow('请先确认');
  const next=await bridge.dispatch<State>('apply_plan',{planId:prepared.id,acknowledgeCredentialMigration:true});expect(next.accounts[0].needsCredentialMigration).toBe(false);
  expect(next.domains).toEqual(before.domains);expect(next.links).toEqual(before.links);
  await expect(bridge.dispatch('apply_plan',{planId:prepared.id,acknowledgeCredentialMigration:true})).rejects.toThrow('计划已过期');
});

it('allows explicit retry after migration preparation fails without starting apply',async()=>{
  control.failPrepare=true;await start();const editor=await manager();fireEvent.click(within(editor).getByRole('button',{name:'更新本机授权'}));
  await within(editor).findByText('无法准备本机授权更新。');expect(calls('prepare_change')).toHaveLength(1);expect(calls('apply_plan')).toHaveLength(0);
  control.failPrepare=false;await confirmFrom(editor);expect(calls('prepare_change')).toHaveLength(2);expect(calls('apply_plan')).toHaveLength(0);
});
it('local removal discloses retained legacy entries without attempting migration',async()=>{
  await start();const editor=await manager();fireEvent.click(within(editor).getByRole('button',{name:'从本机移除'}));
  expect(within(screen.getByRole('dialog',{name:'从本机移除账户'})).getByText(/旧版钥匙串条目不会自动删除/)).toBeTruthy();expect(calls('prepare_change')).toHaveLength(0);
});
it('cached domain matching does not block a current account because another account is legacy',async()=>{
  await start();const editor=await domainEditor('');fireEvent.change(within(editor).getByPlaceholderText('go.example.com'),{target:{value:'new.example.org'}});
  fireEvent.click(within(editor).getByRole('button',{name:'检查并继续'}));await waitFor(()=>expect(calls('prepare_domain')).toHaveLength(1));expect(calls('prepare_change')).toHaveLength(0);
});

it('changing domain account removes the old account migration entry',async()=>{
  await start();const editor=await domainEditor();fireEvent.click(within(editor).getByRole('button',{name:'刷新域名列表'}));
  expect(within(editor).getByRole('button',{name:'更新本机授权'})).toBeTruthy();
  fireEvent.change(within(editor).getByRole('combobox',{name:'Cloudflare 账户'}),{target:{value:'b'}});
  expect(within(editor).queryByRole('button',{name:'更新本机授权'})).toBeNull();
  fireEvent.click(within(editor).getByRole('button',{name:'刷新域名列表'}));await waitFor(()=>expect(calls('refresh_domains')).toHaveLength(1));expect(calls('refresh_domains')[0].payload).toEqual({accountId:'b'});
});

function addPool(){control.state={...control.state!,pools:[{id:'pool',name:'原平台',official:{prefix:'https://example.com/join/',suffix:''},candidates:[{id:'c',prefix:'https://example.org/join/',suffix:'',enabled:true}],updated:'2026-09-30',accountIds:['a','b']}]};}
it('unconfigured legacy monitoring does not block current-account pool health reads',async()=>{
  addPool();control.state!.accounts[0].monitorEnabled=false;control.state!.accounts[1].monitorEnabled=true;
  await start();fireEvent.click(screen.getByRole('button',{name:'平台地址'}));fireEvent.click(screen.getByRole('button',{name:'查看网址检测'}));
  await waitFor(()=>expect(calls('check_pool_health')).toHaveLength(1));expect(calls('prepare_change')).toHaveLength(0);
});
it('an enabled legacy monitor still requires migration before pool health reads',async()=>{
  addPool();control.state!.accounts[0].monitorEnabled=true;await start();fireEvent.click(screen.getByRole('button',{name:'平台地址'}));fireEvent.click(screen.getByRole('button',{name:'查看网址检测'}));
  expect(calls('check_pool_health')).toHaveLength(0);expect(screen.getByRole('button',{name:'更新本机授权'})).toBeTruthy();
});
it('an unrelated legacy account does not block backup selection and backend scope validation',async()=>{
  await start();fireEvent.click(screen.getByRole('button',{name:'Cloudflare 账户'}));fireEvent.click(screen.getByRole('button',{name:'导入配置'}));
  await waitFor(()=>expect(calls('import_config')).toHaveLength(1));expect(calls('backup_open')).toHaveLength(1);expect(calls('prepare_change')).toHaveLength(0);
  expect(JSON.parse(String(calls('import_config')[0].payload.json)).domains[0].host).toBe('go.example.org');
});
it.each(['cancel','failure','success'])('retains changed pool fields after migration %s without automatic save',async(outcome)=>{
  addPool();control.failApply=outcome==='failure';await start();fireEvent.click(screen.getByRole('button',{name:'平台地址'}));fireEvent.click(screen.getByRole('button',{name:'编辑地址'}));
  let editor=screen.getByRole('dialog',{name:'编辑平台地址'});fireEvent.change(within(editor).getByPlaceholderText('例如：常用平台 A'),{target:{value:'保留平台草稿'}});
  fireEvent.click(within(editor).getByRole('button',{name:'下一步，核对内容'}));expect(calls('prepare_change')).toHaveLength(0);
  const review=await confirmFrom(editor);expect(screen.queryByRole('dialog',{name:'编辑平台地址'})).toBeNull();
  fireEvent.click(within(review).getByRole('button',{name:outcome==='cancel'?'返回':'确认更新本机授权'}));
  editor=await screen.findByRole('dialog',{name:'编辑平台地址'});expect((within(editor).getByPlaceholderText('例如：常用平台 A') as HTMLInputElement).value).toBe('保留平台草稿');
  expect(calls('prepare_change').map(c=>c.payload.kind)).toEqual(['migrate_credentials']);
  if(outcome==='failure')expect(within(editor).getByRole('alert').textContent).toContain('本机授权未完成');
  if(outcome==='success'){
    expect(within(editor).queryByRole('alert')).toBeNull();fireEvent.click(within(editor).getByRole('button',{name:'下一步，核对内容'}));
    await waitFor(()=>expect(calls('prepare_change')).toHaveLength(2));expect(calls('prepare_change')[1].payload.kind).toBe('save_pool');
  }
});
it('does not dismiss the pool draft while its migration plan is being prepared',async()=>{
  addPool();await start();fireEvent.click(screen.getByRole('button',{name:'平台地址'}));fireEvent.click(screen.getByRole('button',{name:'编辑地址'}));
  const editor=screen.getByRole('dialog',{name:'编辑平台地址'});fireEvent.change(within(editor).getByPlaceholderText('例如：常用平台 A'),{target:{value:'等待期间的草稿'}});
  fireEvent.click(within(editor).getByRole('button',{name:'下一步，核对内容'}));control.defer='prepare_change';fireEvent.click(within(editor).getByRole('button',{name:'更新本机授权'}));
  expect((within(editor).getByRole('button',{name:'取消'}) as HTMLButtonElement).disabled).toBe(true);fireEvent.keyDown(document,{key:'Escape'});
  expect(screen.getByRole('dialog',{name:'编辑平台地址'})).toBe(editor);await act(async()=>control.resolve?.(plan()));
  const review=screen.getByRole('dialog',{name:'更新本机授权'});fireEvent.click(within(review).getByRole('button',{name:'返回'}));
  expect((within(screen.getByRole('dialog',{name:'编辑平台地址'})).getByPlaceholderText('例如：常用平台 A') as HTMLInputElement).value).toBe('等待期间的草稿');
});
it.each([false,true])('shows amber migration status while retaining selftest recovery status %s',async(needsSelftestKey)=>{
  control.state!.accounts[0].needsSelftestKey=needsSelftestKey;await start();fireEvent.click(screen.getByRole('button',{name:'Cloudflare 账户'}));
  const card=screen.getByRole('button',{name:'管理 旧账户'}).closest('.account-card') as HTMLElement;
  expect(within(card).getByText('需要更新本机授权').className).toContain('status-amber');expect(within(card).queryByText('已连接')).toBeNull();
  expect(Boolean(within(card).queryByText('检测密钥待恢复'))).toBe(needsSelftestKey);
  const review=await confirmFrom(card);fireEvent.click(within(review).getByRole('button',{name:'确认更新本机授权'}));
  await waitFor(()=>expect(within(card).queryByText('需要更新本机授权')).toBeNull());
  expect(within(card).getByText(needsSelftestKey?'检测密钥待恢复':'已连接')).toBeTruthy();
});
