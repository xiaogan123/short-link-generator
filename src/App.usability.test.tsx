import {act,cleanup,fireEvent,render,screen,waitFor,within} from '@testing-library/react';
import {afterEach,expect,it,vi} from 'vitest';
import App from './App';
import {openUrl} from '@tauri-apps/plugin-opener';

const calls=vi.hoisted(()=>[] as {action:string;payload:Record<string,unknown>}[]);
const clipboard=vi.hoisted(()=>({readText:vi.fn(async()=>''),writeText:vi.fn()}));
vi.mock('@tauri-apps/plugin-opener',()=>({openUrl:vi.fn()}));
vi.mock('@tauri-apps/plugin-clipboard-manager',()=>clipboard);
vi.mock('./bridge',()=>({
  preview:false,
  errorMessage:(error:unknown)=>String(error),
  dispatch:async(action:string,payload:Record<string,unknown>={})=>{
    calls.push({action,payload});
    if(action==='token_template')return 'https://example.com/token';
    if(action==='import_token')return {accounts:[],domains:[],links:[],pools:[],pendingOperations:[],pendingActions:[]};
    if(action==='get_state')return {accounts:[{id:'a',label:'本机备注',cloudflareName:'Example organization',zones:[{id:'z',name:'example.com',status:'active'}],zoneCount:1,checkedAt:null,hasResources:true,needsSelftestKey:false}],domains:[{id:'d',accountId:'a',zoneId:'z',host:'go.example.com',prefix:'r',routeId:'route'}],links:[{domainId:'d',slug:'manual',cnUrl:'https://example.com/cn',defaultUrl:'https://example.org/en',updated:'2026-09-29T00:00:00Z'}],pools:[{id:'p',name:'示例平台',official:{prefix:'https://example.com/join/',suffix:''},candidates:[{id:'c1',prefix:'https://example.org/join/',suffix:'',enabled:true},{id:'c2',prefix:'https://example.org/backup/',suffix:'',enabled:true}],updated:'',accountIds:['a']}],pendingOperations:[],pendingActions:[]};
    if(action==='prepare_domain')return {host:'sub.example.com',prefix:'r',candidates:[{accountId:'a',label:'本机备注',zoneId:'z',status:'active'}],checks:[{label:'区域与代理',ok:true,level:'pass',message:'可用'}],canApply:true,plan:{id:'plan',title:'添加域名',steps:[],warnings:[],expiresAt:new Date(Date.now()+300000).toISOString()}};
    throw new Error(`Unexpected action ${action}`);
  },
}));

afterEach(()=>{cleanup();calls.length=0;vi.clearAllMocks();clipboard.readText.mockReset();clipboard.readText.mockResolvedValue('');});

it('uses a root account dialog and returns focus after Escape',async()=>{
  render(<App/>);
  await screen.findByText('/manual');
  fireEvent.click(screen.getByRole('button',{name:/^Cloudflare 账户$/}));
  const manage=screen.getByRole('button',{name:'管理 本机备注'});
  manage.focus();
  fireEvent.click(manage);
  expect(screen.getByRole('dialog',{name:'账户管理'}).textContent).toContain('Example organization');
  fireEvent.keyDown(document,{key:'Escape'});
  await waitFor(()=>expect(screen.queryByRole('dialog',{name:'账户管理'})).toBeNull());
  expect(document.activeElement).toBe(manage);
});

it('keeps the selected account visible while updating its token',async()=>{
  render(<App/>);
  await screen.findByText('/manual');
  fireEvent.click(screen.getByRole('button',{name:/^Cloudflare 账户$/}));
  fireEvent.click(screen.getByRole('button',{name:'管理 本机备注'}));
  fireEvent.click(within(screen.getByRole('dialog',{name:'账户管理'})).getByRole('button',{name:'更换本机令牌'}));
  const token=screen.getByRole('dialog',{name:'更换本机令牌'});
  expect(token.textContent).toContain('Example organization');
  expect(token.textContent).toContain('必须包含这个 Cloudflare 账户');
  expect(token.textContent).toContain('其他账户不变');
  expect(within(token).queryByRole('checkbox')).toBeNull();
  fireEvent.change(within(token).getByPlaceholderText('在此粘贴令牌'),{target:{value:'replacement-token'}});
  fireEvent.submit(token.querySelector('#token-form')!);
  await waitFor(()=>expect(calls.some(call=>call.action==='import_token'&&call.payload.expectedAccountId==='a'&&call.payload.replace===true)).toBe(true));
});

it.each(['账户管理','更换本机令牌'])('opens existing-token settings from %s without creating or replacing a token',async(location)=>{
  render(<App/>);
  await screen.findByText('/manual');
  fireEvent.click(screen.getByRole('button',{name:/^Cloudflare 账户$/}));
  fireEvent.click(screen.getByRole('button',{name:'管理 本机备注'}));
  if(location==='更换本机令牌')fireEvent.click(within(screen.getByRole('dialog',{name:'账户管理'})).getByRole('button',{name:'更换本机令牌'}));
  const dialog=screen.getByRole('dialog',{name:location});
  fireEvent.click(within(dialog).getByRole('button',{name:'修改已有令牌权限'}));
  await waitFor(()=>expect(openUrl).toHaveBeenCalledWith('https://dash.cloudflare.com/profile/api-tokens'));
  expect(calls.filter(call=>call.action==='token_template'||call.action==='import_token')).toHaveLength(0);
  if(location==='更换本机令牌'){
    expect(dialog.textContent).toContain('无需在这里重新粘贴');
    expect(within(dialog).getByRole('button',{name:'打开新令牌模板'}).closest('details')?.open).toBe(false);
    fireEvent.click(within(dialog).getByRole('button',{name:'取消'}));
    expect(screen.queryByRole('dialog',{name:location})).toBeNull();
  }
});

it.each(['取消','关闭','Escape','遮罩'])('dismisses an unsubmitted token update with %s without retaining the token or replacement choice',async(method)=>{
  render(<App/>);
  await screen.findByText('/manual');
  fireEvent.click(screen.getByRole('button',{name:/^Cloudflare 账户$/}));
  fireEvent.click(screen.getByRole('button',{name:'管理 本机备注'}));
  fireEvent.click(within(screen.getByRole('dialog',{name:'账户管理'})).getByRole('button',{name:'更换本机令牌'}));
  const editor=screen.getByRole('dialog',{name:'更换本机令牌'});
  fireEvent.change(within(editor).getByPlaceholderText('在此粘贴令牌'),{target:{value:'discard-this-test-token'}});
  if(method==='Escape')fireEvent.keyDown(document,{key:'Escape'});
  else if(method==='遮罩')fireEvent.mouseDown(editor.parentElement!);
  else fireEvent.click(within(editor).getByRole('button',{name:method}));
  await waitFor(()=>expect(screen.queryByRole('dialog',{name:'更换本机令牌'})).toBeNull());
  expect(calls.filter(call=>call.action==='import_token')).toHaveLength(0);
  fireEvent.click(screen.getByRole('button',{name:'导入账户'}));
  const imported=screen.getByRole('dialog',{name:'导入访问令牌'});
  expect((within(imported).getByPlaceholderText('在此粘贴令牌') as HTMLInputElement).value).toBe('');
  const replacement=within(imported).getByRole('checkbox') as HTMLInputElement;
  expect(replacement.checked).toBe(false);
  expect(replacement.disabled).toBe(false);
});

async function openTokenEditor(){
  render(<App/>);
  await screen.findByText('/manual');
  fireEvent.click(screen.getByRole('button',{name:/^Cloudflare 账户$/}));
  fireEvent.click(screen.getByRole('button',{name:'管理 本机备注'}));
  fireEvent.click(within(screen.getByRole('dialog',{name:'账户管理'})).getByRole('button',{name:'更换本机令牌'}));
  return screen.getByRole('dialog',{name:'更换本机令牌'});
}

it.each([false,true])('discards a late clipboard result after cancellation (reopen first: %s)',async(reopenFirst)=>{
  const pending:Array<(value:string)=>void>=[];
  clipboard.readText.mockImplementation(()=>new Promise(resolve=>pending.push(resolve)));
  const editor=await openTokenEditor();
  await waitFor(()=>expect(pending.length).toBe(1));
  fireEvent.click(within(editor).getByRole('button',{name:'取消'}));
  if(reopenFirst)fireEvent.click(screen.getByRole('button',{name:'导入账户'}));
  await act(async()=>pending[0]('old'.repeat(14)));
  if(!reopenFirst)fireEvent.click(screen.getByRole('button',{name:'导入账户'}));
  const next=screen.getByRole('dialog',{name:'导入访问令牌'});
  expect(within(next).queryByText('检测到可能的访问令牌，是否填入？')).toBeNull();
  expect((within(next).getByPlaceholderText('在此粘贴令牌') as HTMLInputElement).value).toBe('');
  expect(calls.some(call=>call.action==='import_token')).toBe(false);
});

it('keeps the newest clipboard offer when focus reads finish out of order',async()=>{
  const pending:Array<(value:string)=>void>=[];
  clipboard.readText.mockImplementation(()=>new Promise(resolve=>pending.push(resolve)));
  const editor=await openTokenEditor();
  await waitFor(()=>expect(pending.length).toBe(1));
  fireEvent.focus(window);
  await waitFor(()=>expect(pending.length).toBe(2));
  await act(async()=>pending[1]('new'.repeat(14)));
  expect(within(editor).getByText('检测到可能的访问令牌，是否填入？')).toBeTruthy();
  await act(async()=>pending[0]('old'.repeat(14)));
  fireEvent.click(within(editor).getByRole('button',{name:'填入'}));
  expect((within(editor).getByPlaceholderText('在此粘贴令牌') as HTMLInputElement).value).toBe('new'.repeat(14));
  expect(calls.some(call=>call.action==='import_token')).toBe(false);
});

it('marks manual links and clears a prepared domain plan after input changes',async()=>{
  render(<App/>);
  await screen.findByText('/manual');
  expect(screen.getByText('手动地址')).toBeTruthy();
  fireEvent.click(screen.getByRole('button',{name:'将 manual 改为平台地址'}));
  const editor=screen.getByRole('dialog',{name:'编辑短链接'});
  expect(within(editor).getByRole('button',{name:'平台地址'}).className).toContain('selected');
  fireEvent.click(within(editor).getByRole('button',{name:'取消'}));
  fireEvent.click(screen.getByRole('button',{name:/^域名管理$/}));
  fireEvent.click(screen.getByRole('button',{name:'添加域名'}));
  const domain=screen.getByRole('dialog',{name:'添加域名'});
  fireEvent.change(within(domain).getByPlaceholderText('go.example.com'),{target:{value:'sub.example.com'}});
  fireEvent.click(within(domain).getByRole('button',{name:'检查并接入'}));
  expect(await within(domain).findByRole('button',{name:'查看接入计划'})).toBeTruthy();
  fireEvent.change(within(domain).getByPlaceholderText('go.example.com'),{target:{value:'other.example.com'}});
  expect(within(domain).queryByRole('button',{name:'查看接入计划'})).toBeNull();
});
