import {cleanup,fireEvent,render,screen,waitFor,within} from '@testing-library/react';
import {afterEach,expect,it,vi} from 'vitest';
import App from './App';

const control=vi.hoisted(()=>({calls:[] as {action:string;payload:Record<string,unknown>}[],refreshFails:false,prepareFails:false,getStateCount:0,checkState:null as Record<string,unknown>|null,state:null as Record<string,unknown>|null,deferRefresh:false,resolveRefresh:null as null|((value:unknown)=>void),updateStatus:null as Record<string,unknown>|null}));
const initialState={accounts:[{id:'a',label:'示例账户',cloudflareName:'Example organization',zones:[{id:'z',name:'example.com',status:'active'}],zoneCount:1,checkedAt:null,hasResources:true,needsSelftestKey:false}],domains:[],links:[],pools:[],pendingOperations:[],pendingActions:[]};
const refreshedState={...initialState,accounts:[{...initialState.accounts[0],zones:[{id:'z',name:'new.example.com',status:'active'}],zoneCount:1}]};
vi.mock('./bridge',()=>({preview:false,errorMessage:(error:unknown)=>String(error),dispatch:async(action:string,payload:Record<string,unknown>={})=>{
  control.calls.push({action,payload});
  if(action==='get_state') { control.getStateCount += 1; return control.getStateCount > 1 && control.checkState ? control.checkState : control.state || initialState; }
  if(action==='prepare_domain') { if(control.prepareFails) throw new Error('无权读取此域名'); return {host:payload.input,prefix:payload.prefix,candidates:[{accountId:'a',label:'示例账户',zoneId:'z',status:'active'}],checks:[{label:'目录',ok:true,level:'pass',message:'可接入'}],canApply:true,plan:{id:'domain',title:'添加域名',steps:[],warnings:[],expiresAt:new Date(Date.now()+300000).toISOString()}}; }
  if(action==='refresh_domains') { if(control.refreshFails) throw new Error('令牌无权读取域名'); if(control.deferRefresh)return new Promise(resolve=>{control.resolveRefresh=resolve;}); return refreshedState; }
  if(action==='check_update') return control.updateStatus || {status:'unavailable'};
  throw new Error(`Unexpected ${action}`);
}}));

afterEach(()=>{cleanup();control.calls.length=0;control.refreshFails=false;control.prepareFails=false;control.getStateCount=0;control.checkState=null;control.state=null;control.deferRefresh=false;control.resolveRefresh=null;control.updateStatus=null;});

async function openPreparedDomain() {
  render(<App/>); await screen.findByText('先连接一个域名');
  fireEvent.click(screen.getByRole('button',{name:/^域名管理$/}));
  fireEvent.click(screen.getAllByRole('button',{name:'添加域名'})[0]);
  const dialog=screen.getByRole('dialog',{name:'添加域名'});
  fireEvent.change(within(dialog).getByPlaceholderText('go.example.com'),{target:{value:'old.example.com'}});
  fireEvent.change(within(dialog).getByRole('combobox',{name:'Cloudflare 账户'}),{target:{value:'a'}});
  fireEvent.click(within(dialog).getByRole('button',{name:'检查并接入'}));
  await within(dialog).findByRole('button',{name:'查看接入计划'});
  return dialog;
}

it('refreshes zones, keeps the draft, and invalidates the prepared domain plan',async()=>{
  const dialog=await openPreparedDomain();
  fireEvent.click(within(dialog).getByRole('button',{name:'刷新域名列表'}));
  await waitFor(()=>expect(control.calls.some(call=>call.action==='refresh_domains')).toBe(true));
  expect(control.calls.find(call=>call.action==='refresh_domains')?.payload).toEqual({accountId:'a'});
  expect((within(dialog).getByPlaceholderText('go.example.com') as HTMLInputElement).value).toBe('old.example.com');
  expect((within(dialog).getByRole('combobox',{name:'Cloudflare 账户'}) as HTMLSelectElement).value).toBe('a');
  expect(within(dialog).queryByRole('button',{name:'查看接入计划'})).toBeNull();
  expect(dialog.querySelector('datalist option')?.getAttribute('value')).toBe('new.example.com');
  expect(within(dialog).getByRole('status').textContent).toContain('已读取「Example organization」的 1 个域名。');
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
  expect((await within(dialog).findByRole('alert')).textContent).toContain('无法读取此账户的域名：Error: 令牌无权读取域名');
  expect(within(dialog).queryByRole('button',{name:'查看接入计划'})).toBeNull();
  expect((within(dialog).getByPlaceholderText('go.example.com') as HTMLInputElement).value).toBe('old.example.com');
  expect(screen.queryByText('账户状态已更新。')).toBeNull();
});

it('does not dispatch a refresh before a multi-account selection is made',async()=>{
  control.state={...initialState,accounts:[...initialState.accounts,{id:'b',label:'第二账户',zones:[{id:'b-z',name:'example.org',status:'active'}],zoneCount:1,checkedAt:null,hasResources:true,needsSelftestKey:false}]};
  render(<App/>); await screen.findByText('先连接一个域名');
  fireEvent.click(screen.getByRole('button',{name:/^域名管理$/}));
  fireEvent.click(screen.getAllByRole('button',{name:'添加域名'})[0]);
  const dialog=screen.getByRole('dialog',{name:'添加域名'});
  fireEvent.click(within(dialog).getByRole('button',{name:'刷新域名列表'}));
  expect(control.calls.filter(call=>call.action==='refresh_domains')).toHaveLength(0);
  expect(within(dialog).getByRole('alert').textContent).toContain('请选择要刷新域名的 Cloudflare 账户。');
});

it('sends only the explicitly chosen account when multiple accounts are available',async()=>{
  control.state={...initialState,accounts:[...initialState.accounts,{id:'b',label:'第二账户',zones:[{id:'b-z',name:'example.org',status:'active'}],zoneCount:1,checkedAt:null,hasResources:true,needsSelftestKey:false}]};
  render(<App/>); await screen.findByText('先连接一个域名');
  fireEvent.click(screen.getByRole('button',{name:/^域名管理$/}));
  fireEvent.click(screen.getAllByRole('button',{name:'添加域名'})[0]);
  const dialog=screen.getByRole('dialog',{name:'添加域名'});
  fireEvent.change(within(dialog).getByRole('combobox',{name:'Cloudflare 账户'}),{target:{value:'b'}});
  expect([...dialog.querySelectorAll('#cloudflare-zones option')].map(option=>option.getAttribute('value'))).toEqual(['example.org']);
  fireEvent.click(within(dialog).getByRole('button',{name:'刷新域名列表'}));
  await waitFor(()=>expect(control.calls.some(call=>call.action==='refresh_domains')).toBe(true));
  expect(control.calls.find(call=>call.action==='refresh_domains')?.payload).toEqual({accountId:'b'});
});

it('keeps one domain request in flight across draft edits and closing then reopening the dialog',async()=>{
  control.deferRefresh=true;
  render(<App/>); await screen.findByText('先连接一个域名');
  fireEvent.click(screen.getByRole('button',{name:/^域名管理$/}));
  fireEvent.click(screen.getAllByRole('button',{name:'添加域名'})[0]);
  let dialog=screen.getByRole('dialog',{name:'添加域名'});
  fireEvent.change(within(dialog).getByRole('combobox',{name:'Cloudflare 账户'}),{target:{value:'a'}});
  fireEvent.click(within(dialog).getByRole('button',{name:'刷新域名列表'}));
  expect((await within(dialog).findByRole('status')).textContent).toContain('正在读取此账户的域名，请稍候。');
  fireEvent.change(within(dialog).getByPlaceholderText('go.example.com'),{target:{value:'changed.example.com'}});
  fireEvent.click(within(dialog).getByRole('button',{name:'取消'}));
  fireEvent.click(screen.getAllByRole('button',{name:'添加域名'})[0]);
  dialog=screen.getByRole('dialog',{name:'添加域名'});
  expect(within(dialog).getByRole('status').textContent).toContain('上一项检查仍在进行，请稍候。');
  expect((within(dialog).getByRole('button',{name:'正在读取…'}) as HTMLButtonElement).disabled).toBe(true);
  fireEvent.click(within(dialog).getByRole('button',{name:'正在读取…'}));
  expect(control.calls.filter(call=>call.action==='refresh_domains')).toHaveLength(1);
  control.resolveRefresh?.(refreshedState);
  await waitFor(()=>expect((within(dialog).getByRole('button',{name:'刷新域名列表'}) as HTMLButtonElement).disabled).toBe(false));
  expect(within(dialog).queryByText('已读取「Example organization」的 1 个域名。')).toBeNull();
});

it('shows the backend-provided current and available versions',async()=>{
  control.updateStatus={status:'available',currentVersion:'1.2.3',version:'1.3.0'};
  render(<App/>); await screen.findByText('先连接一个域名');
  fireEvent.click(screen.getByRole('button',{name:'检查更新'}));
  const dialog=await screen.findByRole('dialog',{name:'应用更新'});
  expect(within(dialog).getByText(/当前版本：/).textContent).toBe('当前版本：1.2.3；发现新版本 1.3.0。安装后应用可能会重启。');
});

it('shows the backend-provided current version when already up to date',async()=>{
  control.updateStatus={status:'up_to_date',currentVersion:'1.2.3'};
  render(<App/>); await screen.findByText('先连接一个域名');
  fireEvent.click(screen.getByRole('button',{name:'检查更新'}));
  const dialog=await screen.findByRole('dialog',{name:'应用更新'});
  expect(within(dialog).getByText(/当前已是最新版本/).textContent).toBe('当前已是最新版本（1.2.3）。');
});

it('shows the current valid host and link directory in the link example',async()=>{
  render(<App/>); await screen.findByText('先连接一个域名');
  fireEvent.click(screen.getByRole('button',{name:/^域名管理$/}));
  fireEvent.click(screen.getAllByRole('button',{name:'添加域名'})[0]);
  const dialog=screen.getByRole('dialog',{name:'添加域名'});
  fireEvent.change(within(dialog).getByPlaceholderText('go.example.com'),{target:{value:'go.example.com'}});
  fireEvent.change(within(dialog).getByRole('textbox',{name:/链接目录/}),{target:{value:'r'}});
  expect(within(dialog).getByText('示例链接：https://go.example.com/r/名称')).toBeTruthy();
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
