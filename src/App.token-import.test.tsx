import {act, cleanup, fireEvent, render, screen, waitFor, within} from '@testing-library/react';
import {afterEach, beforeEach, expect, it, vi} from 'vitest';
import App from './App';
import type {ImportReport, State} from './types';

const control = vi.hoisted(() => ({
  state: null as unknown,
  calls: [] as {action: string; payload: Record<string, unknown>}[],
  importResult: null as unknown,
  importError: '',
}));
const initial: State = {
  appVersion:'0.1.27',
  accounts:[{id:'a',label:'账号5',cloudflareName:'first@example.com',zoneCount:1,checkedAt:null,hasResources:true,needsSelftestKey:false}],
  domains:[{id:'d',accountId:'a',zoneId:'z',host:'go.example.com',prefix:'r',routeId:'route'}],
  links:[{domainId:'d',slug:'welcome',cnUrl:'https://example.com/cn',defaultUrl:'https://example.org/en',updated:''}],
  pools:[],pendingOperations:[],pendingActions:[],
};
vi.mock('@tauri-apps/plugin-opener',()=>({openUrl:async()=>{}}));
vi.mock('./bridge', () => ({preview:false,errorMessage:(error:unknown)=>error instanceof Error?error.message:String(error),dispatch:async(action:string,payload:Record<string,unknown>={})=>{
  control.calls.push({action,payload});
  if(action==='get_state') return control.state;
  if(action==='token_template') return 'https://example.com/token-template';
  if(action==='import_token') {
    if(control.importError) throw Error(control.importError);
    return control.importResult;
  }
  throw Error(`Unexpected action ${action}`);
}}));
beforeEach(()=>{control.state=structuredClone(initial);control.calls=[];control.importResult=null;control.importError='';});
afterEach(()=>{vi.useRealTimers();cleanup();});
const calls=(action:string)=>control.calls.filter(call=>call.action===action);
const added={id:'b',label:'second@example.com',cloudflareName:'second@example.com',zoneCount:0,checkedAt:null,hasResources:false,needsSelftestKey:false};
function result(importReport?: ImportReport){return {...initial,accounts:[...initial.accounts,added],...(importReport?{importReport}:{})};}
async function openImport(){
  render(<App/>);await screen.findByText('/welcome');
  fireEvent.click(screen.getByRole('button',{name:'Cloudflare 账户'}));
  fireEvent.click(screen.getAllByRole('button',{name:'导入账户'})[0]);
  const editor=await screen.findByRole('dialog',{name:'导入访问令牌'});
  fireEvent.change(within(editor).getByPlaceholderText('在此粘贴令牌'),{target:{value:'example-shared-token'}});
  return editor;
}

it('offers no way to overwrite saved tokens from the import dialog and says existing accounts are skipped',async()=>{
  const editor=await openImport();
  expect(within(editor).queryByRole('checkbox')).toBeNull();
  expect(editor.textContent).toContain('已导入的账户会自动跳过');
  expect(editor.textContent).toContain('更换本机令牌');
});
it('adds the new account from a shared token and reports the skipped one until dismissed',async()=>{
  control.importResult=result({imported:[{id:'b',name:'second@example.com'}],skipped:[{id:'a',label:'账号5'}],rejected:[]});
  const editor=await openImport();
  vi.useFakeTimers({shouldAdvanceTime:true});
  fireEvent.click(within(editor).getByRole('button',{name:'验证并导入'}));
  await waitFor(()=>expect(screen.queryByRole('dialog',{name:'导入访问令牌'})).toBeNull());
  expect(calls('import_token').map(call=>call.payload)).toEqual([{token:'example-shared-token',replace:false}]);
  const status=screen.getAllByRole('status').find(node=>node.textContent?.includes('导入完成'))!;
  expect(status.textContent).toContain('已添加 1 个新账户（「second@example.com」）');
  expect(status.textContent).toContain('已导入过的 1 个账户（「账号5」）已自动跳过，保存的令牌没有改动');
  expect(screen.getByRole('article',{name:'second@example.com 账户'})).toBeTruthy();
  expect(screen.getByRole('article',{name:'账号5 账户'})).toBeTruthy();
  await act(async()=>{await vi.advanceTimersByTimeAsync(6000);});
  expect(status.isConnected).toBe(true);
  fireEvent.click(within(status).getByRole('button',{name:'关闭通知'}));
  expect(screen.queryByText(/导入完成/)).toBeNull();
});
it('names an account the token cannot manage while importing the rest',async()=>{
  control.importResult=result({imported:[{id:'b',name:'second@example.com'}],skipped:[],rejected:[{id:'c',name:'third@example.com',reason:'令牌缺少 Workers 脚本读取权限'}]});
  const editor=await openImport();
  fireEvent.click(within(editor).getByRole('button',{name:'验证并导入'}));
  const status=await screen.findByText(/导入完成/);
  expect(status.textContent).toContain('另有 1 个账户未导入：「third@example.com」令牌缺少 Workers 脚本读取权限');
  expect(status.textContent).not.toContain('已自动跳过');
});
it('keeps the short confirmation for a plain import and for an older response without a report',async()=>{
  control.importResult=result();
  const editor=await openImport();
  vi.useFakeTimers({shouldAdvanceTime:true});
  fireEvent.click(within(editor).getByRole('button',{name:'验证并导入'}));
  const status=await screen.findByText('账户已导入。');
  await act(async()=>{await vi.advanceTimersByTimeAsync(6000);});
  expect(status.isConnected).toBe(false);
});
it('keeps the dialog open with the explanation when every account of the token is already imported',async()=>{
  control.importError='这个令牌里的账号都已经导入过，没有新账号可导入。已导入过的账号「账号5」保持不变，保存的令牌没有改动。要给某个账号换令牌，请在账户列表打开它的“管理账户”，选择“更换本机令牌”';
  const editor=await openImport();
  fireEvent.click(within(editor).getByRole('button',{name:'验证并导入'}));
  const alert=await within(editor).findByRole('alert');
  expect(alert.textContent).toContain('都已经导入过');
  expect(alert.textContent).toContain('「账号5」保持不变');
  expect(screen.getByRole('dialog',{name:'导入访问令牌'})).toBe(editor);
  expect(screen.queryByText(/导入完成/)).toBeNull();
});
