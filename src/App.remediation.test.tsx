import {StrictMode} from 'react';
import {act, cleanup, fireEvent, render, screen, waitFor, within} from '@testing-library/react';
import {afterEach, beforeEach, expect, it, vi} from 'vitest';
import App from './App';
import type {State, UpdateStatus} from './types';

const control = vi.hoisted(() => ({
  state: null as State | null,
  calls: [] as {action: string; payload: Record<string, unknown>}[],
  failImport: false,
  deferredGets: false,
  gets: [] as {resolve: (state: State) => void; reject: (error: Error) => void}[],
  pendingImport: null as Promise<State> | null,
  pendingCheck: null as Promise<UpdateStatus> | null,
  pendingInstall: null as Promise<UpdateStatus> | null,
  pendingCancel: null as Promise<unknown> | null,
  progress: null as null | ((event: {payload: {phase: string}}) => void),
  unlisten: vi.fn(),
}));
const initial: State = {
  appVersion:'0.1.24',
  accounts:[{id:'a',label:'常用账户',cloudflareName:'Example Cloud',zoneCount:1,checkedAt:null,hasResources:true,needsSelftestKey:false}],
  domains:[{id:'d',accountId:'a',zoneId:'z',host:'go.example.com',prefix:'r',routeId:'route'}],
  links:[{domainId:'d',slug:'welcome',cnUrl:'https://example.com/cn',defaultUrl:'https://example.org/en',updated:''}],
  pools:[],pendingOperations:[],pendingActions:[],
};
vi.mock('@tauri-apps/plugin-opener',()=>({openUrl:async()=>{}}));
vi.mock('@tauri-apps/api/event', () => ({listen: async (_name: string, listener: typeof control.progress) => {control.progress=listener;return control.unlisten;}}));
vi.mock('./bridge', () => ({preview:false,errorMessage:(error:unknown)=>error instanceof Error?error.message:String(error),dispatch:async(action:string,payload:Record<string,unknown>={})=>{
  control.calls.push({action,payload});
  if(action==='get_state') {
    if(control.deferredGets) return new Promise<State>((resolve,reject)=>control.gets.push({resolve,reject}));
    return control.state;
  }
  if(action==='token_template') return 'https://example.com/token-template';
  if(action==='import_token') {
    if(control.pendingImport) return control.pendingImport;
    if(control.failImport) {
      control.state={...initial,accounts:initial.accounts.map(account=>({...account,needsTokenRecovery:true}))};
      throw Error('令牌保存未完成，请恢复账户令牌。');
    }
    control.state={...control.state!,accounts:control.state!.accounts.map(account=>({...account,needsTokenRecovery:false}))};
    return control.state;
  }
  if(action==='check_update') return control.pendingCheck || {status:'available',version:'0.1.25',currentVersion:'0.1.24'};
  if(action==='install_update') return control.pendingInstall || {status:'installed',version:'0.1.25',currentVersion:'0.1.24'};
  if(action==='cancel_update') return control.pendingCancel || {status:'cancel_requested',message:'取消请求已发送，正在等待当前操作返回。'};
  if(action==='prepare_change') return {id:'plan',title:'保存短链接',steps:[],warnings:[],expiresAt:new Date(Date.now()+300000).toISOString()};
  throw Error(`Unexpected action ${action}`);
}}));
beforeEach(()=>{control.state=structuredClone(initial);control.calls=[];control.failImport=false;control.deferredGets=false;control.gets=[];control.pendingImport=null;control.pendingCheck=null;control.pendingInstall=null;control.pendingCancel=null;control.progress=null;control.unlisten.mockClear();});
afterEach(()=>{cleanup();delete (window as unknown as Record<string,unknown>).__TAURI_INTERNALS__;});
const calls=(action:string)=>control.calls.filter(call=>call.action===action);
async function start(){render(<App/>);await screen.findByText('/welcome');}
async function accounts(){fireEvent.click(screen.getByRole('button',{name:'Cloudflare 账户'}));}
async function update(){fireEvent.click(screen.getByRole('button',{name:'检查更新'}));return screen.findByRole('dialog',{name:'应用更新'});}

it('uses Chinese field errors, identifies invalid inputs, and focuses the first link error before any prepare',async()=>{
  await start();fireEvent.click(screen.getByRole('button',{name:'新建链接'}));
  const editor=screen.getByRole('dialog',{name:'创建短链接'});
  fireEvent.click(within(editor).getByRole('button',{name:'下一步，核对内容'}));
  const slug=within(editor).getByPlaceholderText('例如 welcome');
  expect(document.activeElement).toBe(slug);
  expect(slug.getAttribute('aria-invalid')).toBe('true');
  expect(document.getElementById(slug.getAttribute('aria-describedby')!)?.textContent).toContain('短链接名称须为');
  expect((editor.querySelector('form') as HTMLFormElement).noValidate).toBe(true);
  expect(calls('prepare_change')).toHaveLength(0);
  fireEvent.change(slug,{target:{value:'fresh'}});
  fireEvent.change(within(editor).getByPlaceholderText('https://example.com/zh'),{target:{value:'https://example.com/new'}});
  fireEvent.change(within(editor).getByPlaceholderText('https://example.com/en'),{target:{value:'https://example.org/new'}});
  fireEvent.click(within(editor).getByRole('button',{name:'下一步，核对内容'}));
  await screen.findByRole('dialog',{name:'保存短链接'});
  expect(calls('prepare_change')).toHaveLength(1);
});
it('rejects an empty domain and empty token in their forms without a native required bubble',async()=>{
  await start();fireEvent.click(screen.getByRole('button',{name:'域名管理'}));fireEvent.click(screen.getByRole('button',{name:'添加域名'}));
  let editor=screen.getByRole('dialog',{name:'添加域名'});
  fireEvent.click(within(editor).getByRole('button',{name:'检查并继续'}));
  const host=within(editor).getByPlaceholderText('go.example.com');
  expect(document.activeElement).toBe(host);expect(host.getAttribute('aria-invalid')).toBe('true');
  expect(calls('prepare_domain')).toHaveLength(0);
  fireEvent.click(within(editor).getByRole('button',{name:'取消'}));await accounts();fireEvent.click(screen.getByRole('button',{name:'导入账户'}));
  editor=screen.getByRole('dialog',{name:'导入访问令牌'});fireEvent.click(await within(editor).findByRole('button',{name:'验证并导入'}));
  expect(document.activeElement).toBe(within(editor).getByPlaceholderText('在此粘贴令牌'));
  expect(within(editor).getByRole('alert').textContent).toBe('请先粘贴令牌。');expect(calls('import_token')).toHaveLength(0);
});
it('keeps recovery separate from credential migration and disables cloud operations until targeted recovery',async()=>{
  control.state!.accounts[0].needsTokenRecovery=true;
  await start();await accounts();
  const card=screen.getByRole('article',{name:'常用账户 账户'});
  expect(within(card).getByRole('heading').textContent).toBe('常用账户');
  expect(card.textContent).toContain('Example Cloud');expect(card.textContent).toContain('令牌待恢复');expect(card.textContent).not.toContain('已连接');
  fireEvent.click(within(card).getByRole('button',{name:'管理 常用账户'}));
  const manager=screen.getByRole('dialog',{name:'账户管理'});
  for(const name of ['配置检测服务','从 Cloudflare 找回配置','重置检测密钥','读取保护状态','启用访问保护','升级云端跳转服务','删除云端短链接服务']) expect((within(manager).getByRole('button',{name}) as HTMLButtonElement).disabled).toBe(true);
  expect((within(manager).getByRole('button',{name:'从本机移除'}) as HTMLButtonElement).disabled).toBe(false);
  expect(within(manager).queryByRole('button',{name:'更新本机授权'})).toBeNull();
  fireEvent.click(within(manager).getByRole('button',{name:'恢复账户令牌'}));
  const recovery=screen.getByRole('dialog',{name:'恢复账户令牌'});
  fireEvent.change(within(recovery).getByPlaceholderText('在此粘贴令牌'),{target:{value:'example-recovery-token'}});
  fireEvent.click(within(recovery).getByRole('button',{name:'验证并替换'}));
  await waitFor(()=>expect(calls('import_token')).toHaveLength(1));
  expect(calls('import_token')[0].payload).toEqual({token:'example-recovery-token',replace:true,expectedAccountId:'a'});
  await waitFor(()=>expect(screen.queryByRole('dialog',{name:'恢复账户令牌'})).toBeNull());
  expect(screen.getByRole('article',{name:'常用账户 账户'}).textContent).toContain('已连接');
});
it('refreshes after a failed first import and exposes the persisted recovery account',async()=>{
  control.state={...initial,accounts:[],domains:[],links:[]};control.failImport=true;
  render(<App/>);await waitFor(()=>expect(screen.queryByText('正在读取本机配置…')).toBeNull());await accounts();fireEvent.click(screen.getAllByRole('button',{name:'导入账户'})[0]);
  const editor=screen.getByRole('dialog',{name:'导入访问令牌'});
  fireEvent.change(within(editor).getByPlaceholderText('在此粘贴令牌'),{target:{value:'example-import-token'}});
  fireEvent.click(await within(editor).findByRole('button',{name:'验证并导入'}));
  const recover=await within(editor).findByRole('button',{name:'恢复 常用账户 的令牌'});
  expect(calls('get_state')).toHaveLength(2);expect(within(editor).getByRole('alert').textContent).toContain('保存未完成');
  fireEvent.click(recover);expect(screen.getByRole('dialog',{name:'恢复账户令牌'}).textContent).toContain('常用账户');
  expect(calls('import_token')[0].payload.replace).toBe(false);
});
it('marks the active navigation page and searches accounts by either local or provider name',async()=>{
  await start();expect(screen.getByRole('button',{name:/^短链接/}).getAttribute('aria-current')).toBe('page');await accounts();
  fireEvent.change(screen.getByRole('textbox',{name:'搜索账户'}),{target:{value:'Example Cloud'}});expect(screen.getByRole('article',{name:'常用账户 账户'})).toBeTruthy();
  fireEvent.change(screen.getByRole('textbox',{name:'搜索账户'}),{target:{value:'不存在'}});expect(screen.queryByRole('article')).toBeNull();
  fireEvent.click(screen.getByRole('button',{name:'清除搜索'}));expect(screen.getByRole('article',{name:'常用账户 账户'})).toBeTruthy();
});
it('does not let an older initial load overwrite a newer snapshot',async()=>{
  control.deferredGets=true;render(<StrictMode><App/></StrictMode>);expect(control.gets).toHaveLength(2);
  const newer={...initial,links:[{...initial.links[0],slug:'newest'}]};
  await act(async()=>control.gets[1].resolve(newer));await screen.findByText('/newest');
  await act(async()=>control.gets[0].resolve(initial));expect(screen.queryByText('/welcome')).toBeNull();expect(screen.getByText('/newest')).toBeTruthy();
});
it('does not let an obsolete load error clear the newer loading state',async()=>{
  control.deferredGets=true;render(<StrictMode><App/></StrictMode>);
  await act(async()=>control.gets[0].reject(Error('旧请求失败')));
  expect(screen.getByText('正在读取本机配置…')).toBeTruthy();expect(screen.queryByRole('alert')).toBeNull();
  await act(async()=>control.gets[1].resolve(initial));await screen.findByText('/welcome');
});
it('allows cancel during a pending metadata check and waits for its actual completion',async()=>{
  let reject!: (error:Error)=>void;control.pendingCheck=new Promise((_resolve,rejectPromise)=>{reject=rejectPromise;});
  await start();const editor=await update();fireEvent.click(within(editor).getByRole('button',{name:'取消本次更新'}));
  await within(editor).findByText('取消请求已发送，正在等待当前操作返回。');
  expect(within(editor).getAllByRole('button',{name:'关闭'}).every(button=>(button as HTMLButtonElement).disabled)).toBe(true);
  await act(async()=>reject(Error('更新检查已取消。')));
  expect(within(editor).getByRole('alert').textContent).toBe('更新检查已取消。');expect(within(editor).queryByRole('button',{name:'取消本次更新'})).toBeNull();
});
it('keeps download cancellation available under the mutation lock and never dismisses on request alone',async()=>{
  let reject!: (error:Error)=>void;control.pendingInstall=new Promise((_resolve,rejectPromise)=>{reject=rejectPromise;});
  await start();const editor=await update();await within(editor).findByRole('button',{name:'确认安装更新'});
  fireEvent.click(within(editor).getByRole('button',{name:'确认安装更新'}));
  const cancel=within(editor).getByRole('button',{name:'取消本次更新'});expect((cancel as HTMLButtonElement).disabled).toBe(false);
  fireEvent.click(cancel);await within(editor).findByText('取消请求已发送，正在等待当前操作返回。');
  expect((within(editor).getByRole('button',{name:'正在处理更新…'}) as HTMLButtonElement).disabled).toBe(true);
  fireEvent.keyDown(document,{key:'Escape'});expect(screen.getByRole('dialog',{name:'应用更新'})).toBe(editor);
  await act(async()=>reject(Error('更新下载已取消。')));expect(within(editor).getByRole('alert').textContent).toBe('更新下载已取消。');expect(calls('install_update')).toHaveLength(1);
});
it('uses the native installation phase to disable cancellation and removes its listener when settled',async()=>{
  (window as unknown as Record<string,unknown>).__TAURI_INTERNALS__={};
  let resolve!: (value:UpdateStatus)=>void;control.pendingInstall=new Promise(resolvePromise=>{resolve=resolvePromise;});
  await start();const editor=await update();await within(editor).findByRole('button',{name:'确认安装更新'});fireEvent.click(within(editor).getByRole('button',{name:'确认安装更新'}));
  await waitFor(()=>expect(control.progress).toBeTruthy());
  act(()=>control.progress?.({payload:{phase:'downloading'}}));expect(within(editor).getByRole('status').textContent).toContain('正在下载');
  act(()=>control.progress?.({payload:{phase:'installing'}}));expect((within(editor).getByRole('button',{name:'安装开始后无法取消'}) as HTMLButtonElement).disabled).toBe(true);
  expect(calls('cancel_update')).toHaveLength(0);
  await act(async()=>resolve({status:'installed',version:'0.1.25'}));expect(control.unlisten).toHaveBeenCalledTimes(1);
  act(()=>control.progress?.({payload:{phase:'downloading'}}));expect(editor.textContent).not.toContain('正在下载');
});
it('discards a cancellation acknowledgement that arrives after the operation has ended',async()=>{
  let reject!: (error:Error)=>void;let acknowledge!: (value:unknown)=>void;
  control.pendingInstall=new Promise((_resolve,rejectPromise)=>{reject=rejectPromise;});control.pendingCancel=new Promise(resolve=>{acknowledge=resolve;});
  await start();const editor=await update();await within(editor).findByRole('button',{name:'确认安装更新'});fireEvent.click(within(editor).getByRole('button',{name:'确认安装更新'}));fireEvent.click(within(editor).getByRole('button',{name:'取消本次更新'}));
  await act(async()=>reject(Error('下载已取消。')));await act(async()=>acknowledge({status:'cancel_requested',message:'过时的取消确认'}));
  expect(editor.textContent).not.toContain('过时的取消确认');expect(within(editor).getByRole('alert').textContent).toBe('下载已取消。');
});
it('blocks link cloud preparation for a recovery account while retaining the draft and offering targeted recovery',async()=>{
  control.state!.accounts[0].needsTokenRecovery=true;
  await start();fireEvent.click(screen.getByRole('button',{name:'新建链接'}));
  const editor=screen.getByRole('dialog',{name:'创建短链接'});
  fireEvent.change(within(editor).getByPlaceholderText('例如 welcome'),{target:{value:'saved-draft'}});
  fireEvent.change(within(editor).getByPlaceholderText('https://example.com/zh'),{target:{value:'https://example.com/new'}});
  fireEvent.change(within(editor).getByPlaceholderText('https://example.com/en'),{target:{value:'https://example.org/new'}});
  fireEvent.click(within(editor).getByRole('button',{name:'下一步，核对内容'}));
  expect(calls('prepare_change')).toHaveLength(0);
  expect(within(editor).getByRole('alert').textContent).toContain('令牌保存未完成');
  fireEvent.click(within(editor).getByRole('button',{name:'恢复账户令牌'}));
  const recovery=screen.getByRole('dialog',{name:'恢复账户令牌'});fireEvent.click(within(recovery).getByRole('button',{name:'取消'}));
  expect((within(screen.getByRole('dialog',{name:'创建短链接'})).getByPlaceholderText('例如 welcome') as HTMLInputElement).value).toBe('saved-draft');
});

it.each(['success','failure'] as const)('holds the generic import target until a deferred import settles with %s',async(outcome)=>{
  control.state!.accounts[0].needsTokenRecovery=true;
  let resolve!: (state:State)=>void;
  let reject!: (error:Error)=>void;
  control.pendingImport=new Promise<State>((resolvePromise,rejectPromise)=>{resolve=resolvePromise;reject=rejectPromise;});
  await start();await accounts();fireEvent.click(screen.getByRole('button',{name:'导入账户'}));
  const generic=screen.getByRole('dialog',{name:'导入访问令牌'});
  const submit=await within(generic).findByRole('button',{name:'验证并导入'});
  const token=within(generic).getByPlaceholderText('在此粘贴令牌') as HTMLInputElement;
  const recovery=within(generic).getByRole('button',{name:'恢复 常用账户 的令牌'}) as HTMLButtonElement;
  fireEvent.change(token,{target:{value:'example-generic-import-token'}});
  fireEvent.click(submit);
  expect(recovery.disabled).toBe(true);
  fireEvent.click(recovery);
  expect(screen.queryByRole('dialog',{name:'恢复账户令牌'})).toBeNull();
  expect(screen.getByRole('dialog',{name:'导入访问令牌'})).toBe(generic);
  expect(token.value).toBe('example-generic-import-token');
  expect(calls('import_token').map(call=>call.payload)).toEqual([{token:'example-generic-import-token',replace:false}]);
  if(outcome==='success') {
    const complete={...control.state!,accounts:[...control.state!.accounts,{...initial.accounts[0],id:'b',label:'新账户',needsTokenRecovery:false}]};
    await act(async()=>resolve(complete));
    await waitFor(()=>expect(screen.queryByRole('dialog',{name:'导入访问令牌'})).toBeNull());
    expect(screen.getByRole('article',{name:'常用账户 账户'}).textContent).toContain('令牌待恢复');
    fireEvent.click(within(screen.getByRole('article',{name:'常用账户 账户'})).getByRole('button',{name:'恢复账户令牌'}));
  } else {
    await act(async()=>reject(Error('通用导入失败，请重试。')));
    expect(within(generic).getByRole('alert').textContent).toBe('通用导入失败，请重试。');
    expect(recovery.disabled).toBe(false);
    fireEvent.click(recovery);
  }
  const targeted=screen.getByRole('dialog',{name:'恢复账户令牌'});
  expect(targeted.textContent).toContain('正在更新 常用账户');
  expect((within(targeted).getByPlaceholderText('在此粘贴令牌') as HTMLInputElement).value).toBe('');
  control.pendingImport=null;
  fireEvent.change(within(targeted).getByPlaceholderText('在此粘贴令牌'),{target:{value:'example-targeted-recovery-token'}});
  fireEvent.click(within(targeted).getByRole('button',{name:'验证并替换'}));
  await waitFor(()=>expect(calls('import_token')).toHaveLength(2));
  expect(calls('import_token')[1].payload).toEqual({token:'example-targeted-recovery-token',replace:true,expectedAccountId:'a'});
  await waitFor(()=>expect(screen.queryByRole('dialog',{name:'恢复账户令牌'})).toBeNull());
});
it('uses the synchronous mutation guard when recovery is clicked in the same render batch as import',async()=>{
  control.state!.accounts[0].needsTokenRecovery=true;
  let resolve!: (state:State)=>void;
  control.pendingImport=new Promise<State>(resolvePromise=>{resolve=resolvePromise;});
  await start();await accounts();fireEvent.click(screen.getByRole('button',{name:'导入账户'}));
  const generic=screen.getByRole('dialog',{name:'导入访问令牌'});
  await within(generic).findByRole('button',{name:'验证并导入'});
  const token=within(generic).getByPlaceholderText('在此粘贴令牌') as HTMLInputElement;
  const recovery=within(generic).getByRole('button',{name:'恢复 常用账户 的令牌'}) as HTMLButtonElement;
  fireEvent.change(token,{target:{value:'example-same-batch-token'}});
  act(()=>{
    fireEvent.submit(generic.querySelector('form')!);
    // State-based disabled has not rendered yet; the synchronous ref owns this boundary.
    expect(recovery.disabled).toBe(false);
    fireEvent.click(recovery);
  });
  expect(screen.queryByRole('dialog',{name:'恢复账户令牌'})).toBeNull();
  expect(screen.getByRole('dialog',{name:'导入访问令牌'})).toBe(generic);
  expect(token.value).toBe('example-same-batch-token');
  expect(calls('import_token')).toHaveLength(1);
  await act(async()=>resolve(control.state!));
  await waitFor(()=>expect(screen.queryByRole('dialog',{name:'导入访问令牌'})).toBeNull());
});
