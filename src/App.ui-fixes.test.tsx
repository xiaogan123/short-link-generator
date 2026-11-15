import {act,cleanup,fireEvent,render,screen,waitFor,within} from '@testing-library/react';
import {afterEach,beforeEach,expect,it,vi} from 'vitest';
import App from './App';
import {openUrl} from '@tauri-apps/plugin-opener';

const pendingEntry='添加域名 new.example.net：云端结果不确定，需要人工核对';
const mock=vi.hoisted(()=>({
  calls:[] as {action:string;payload:Record<string,unknown>}[],
  accounts:true,
  pending:[] as string[],
  extraLink:false,
  routeStatus:'passed' as 'passed'|'failed',
  routeGate:null as null|Promise<void>,
  redirectGate:false,
  prepareError:'',
  domainBusy:0,
  domainBusyText:'上一个操作还没结束，请稍等几秒再试。',
  redirectStatus:'passed' as 'passed'|'unknown',
  domainPlan:false,
  applyError:'',
  noLinks:false,
  monitorError:'',
  targetsVirtual:false,
  noDomains:false,
  accountPatch:{} as Record<string,unknown>,
}));
const clipboard=vi.hoisted(()=>({writeText:vi.fn(async()=>{}),readText:vi.fn(async()=>'')}));
vi.mock('@tauri-apps/plugin-opener',()=>({openUrl:vi.fn(async()=>{})}));
vi.mock('@tauri-apps/plugin-clipboard-manager',()=>clipboard);
function plan(title:string,steps=['核对当前状态']){return {id:`plan-${mock.calls.length}`,title,steps,warnings:[],expiresAt:new Date(Date.now()+300000).toISOString()};}
function state(){
  const account={id:'a',label:'示例账户',cloudflareName:'Example team',zones:[{id:'z',name:'example.com',status:'active'}],zoneCount:1,checkedAt:null,hasResources:true,needsSelftestKey:false,...mock.accountPatch};
  return {
    accounts:mock.accounts?[account]:[],
    domains:mock.accounts&&!mock.noDomains?[{id:'d',accountId:'a',zoneId:'z',host:'go.example.com',prefix:'r',routeId:'route'},{id:'e',accountId:'a',zoneId:'z',host:'links.example.com',prefix:'s',routeId:'route-2'}]:[],
    links:mock.accounts&&!mock.noLinks&&!mock.noDomains?[
      {domainId:'d',slug:'manual',cnUrl:'https://example.com/cn',defaultUrl:'https://example.org/en',updated:'2026-11-01T00:00:00Z'},
      {domainId:'e',slug:'other',cnUrl:'https://example.com/cn2',defaultUrl:'https://example.org/en2',updated:'2026-11-01T00:00:00Z'},
      ...(mock.extraLink?[{domainId:'d',slug:'fresh',cnUrl:'https://example.com/fresh',defaultUrl:'https://example.org/fresh',updated:'2026-11-02T00:00:00Z'}]:[]),
    ]:[],
    pools:[],
    pendingOperations:[...mock.pending],
    pendingActions:[],
  };
}
vi.mock('./bridge',()=>({preview:false,errorMessage:(e:unknown)=>e instanceof Error?e.message:String(e),dispatch:async(action:string,payload:Record<string,unknown>={})=>{
  mock.calls.push({action,payload});
  if(action==='get_state')return state();
  if(action==='token_template')return 'https://example.com/token-template';
  if(action==='prepare_change'){
    if(mock.prepareError)throw new Error(mock.prepareError);
    // The same two steps the backend sends for this kind.
    return payload.kind==='dismiss_pending_operation'
      ?plan('清除待处理记录',['只从本机删除这条记录，不改动云端',`要清除的记录：${String(payload.entry)}`])
      :plan('保存短链接');
  }
  if(action==='apply_plan'){
    if(mock.applyError){const text=mock.applyError;mock.applyError='';throw new Error(text);}
    const last=[...mock.calls].reverse().find(call=>call.action==='prepare_change');
    if(last?.payload.kind==='dismiss_pending_operation')mock.pending=mock.pending.filter(entry=>entry!==last.payload.entry);
    if(last?.payload.kind==='save_link')mock.extraLink=true;
    return state();
  }
  if(action==='selftest_link'){
    if(mock.routeGate)await mock.routeGate;
    return {status:mock.routeStatus,message:mock.routeStatus==='passed'?'跳转正常。':'跳转不符。',checks:[]};
  }
  if(action==='check_link_targets'){
    const checkedAt=new Date().toISOString();
    // With a VPN on, the local lookup only sees a virtual address; public DNS answers normally.
    const virtual=mock.targetsVirtual&&payload.dnsMode!=='public';
    return {checkedAt,dnsMode:payload.dnsMode==='public'?'public':'system',checks:['中国大陆打开的网址','其他地区打开的网址'].map(label=>({label,status:virtual?'unknown':'passed',message:virtual?'VPN 返回虚拟地址':'可以打开',...(virtual?{reason:'virtual_dns_address'}:{}),checkedAt,source:'local',url:'https://example.org/x',dnsMode:payload.dnsMode==='public'?'public':'system'}))};
  }
  if(action==='check_link_redirect'){
    if(mock.redirectGate)return new Promise(()=>{});
    return {status:mock.redirectStatus,message:mock.redirectStatus==='passed'?'首跳符合预期':'暂时无法确认',checkedAt:new Date().toISOString(),dnsMode:'system'};
  }
  if(action==='prepare_domain'){
    if(mock.domainBusy>0){mock.domainBusy--;throw new Error(mock.domainBusyText);}
    return {host:'sub.example.com',prefix:'r',candidates:[{accountId:'a',label:'示例账户',zoneId:'z',status:'active'}],checks:[{label:'区域与代理',ok:true,level:'pass',message:'可用'}],...(mock.domainPlan?{canApply:true,plan:plan('添加域名')}:{canApply:false})};
  }
  if(action==='refresh_domains'){
    if(mock.domainBusy>0){mock.domainBusy--;throw new Error(mock.domainBusyText);}
    return state();
  }
  if(action==='prepare_monitor'){if(mock.monitorError)throw new Error(mock.monitorError);return plan('启用检测服务');}
  throw new Error(`Unexpected action ${action}`);
}}));

beforeEach(()=>{
  vi.spyOn(HTMLElement.prototype,'getClientRects').mockImplementation(function(this:HTMLElement){return (this.hidden||getComputedStyle(this).display==='none'?[]:[new DOMRect(12,12,120,32)]) as unknown as DOMRectList;});
  Object.assign(mock,{calls:[],accounts:true,pending:[],extraLink:false,routeStatus:'passed',routeGate:null,redirectGate:false,prepareError:'',domainBusy:0,domainBusyText:'上一个操作还没结束，请稍等几秒再试。',redirectStatus:'passed',domainPlan:false,applyError:'',noLinks:false,monitorError:'',targetsVirtual:false,noDomains:false,accountPatch:{}});
  localStorage.clear();
});
afterEach(()=>{cleanup();vi.restoreAllMocks();vi.clearAllMocks();clipboard.writeText.mockReset();clipboard.writeText.mockResolvedValue(undefined);});
const calls=(action:string)=>mock.calls.filter(call=>call.action===action);

it('clears one pending record through a reviewed plan and says the cloud was not touched',async()=>{
  mock.pending=[pendingEntry];
  render(<App/>);
  const details=(await screen.findByText('查看待处理记录（1 条）')).closest('details')!;
  expect(details.textContent).toContain('请先到对应的 Cloudflare 账户核对云端状态，核对完可以在这里清除这条记录');
  // Only a removal or cleanup record that one more click finishes gets a hint.
  expect(details.textContent).not.toContain('会接着做完');
  fireEvent.click(within(details).getByRole('button',{name:'我已核对，清除这条'}));
  const review=await screen.findByRole('dialog',{name:'清除待处理记录'});
  expect(calls('prepare_change').at(-1)?.payload).toEqual({kind:'dismiss_pending_operation',entry:pendingEntry});
  // The record is named once (by the plan step), and nothing claims a cloud check will run.
  expect(review.textContent!.split(pendingEntry)).toHaveLength(2);
  expect(review.textContent).toContain(`要清除的记录：${pendingEntry}`);
  expect(review.textContent).toContain('不会改动 Cloudflare');
  expect(review.textContent).toContain('这次只改本机的记录，不连接 Cloudflare');
  expect(review.textContent).not.toContain('应用将再次检查账户归属');
  expect(calls('apply_plan')).toHaveLength(0);
  fireEvent.click(within(review).getByRole('button',{name:'确认并执行'}));
  expect(await screen.findByText('已清除这条本机记录，云端没有改动。')).toBeTruthy();
  expect(screen.queryByText(/查看待处理记录/)).toBeNull();
});

// One more click finishes an interrupted removal or cleanup, so the record says where that click is,
// and only when that click can be made (the same rule the backend uses for clearing by hand).
it('says next to a removal record that 移除域名 finishes it, only while the domain is still local',async()=>{
  mock.pending=['移除域名 go.example.com (old)：链接删除结果不确定','移除域名 gone.example.net (old)：路由删除结果不确定'];
  render(<App/>);
  const details=(await screen.findByText('查看待处理记录（2 条）')).closest('details')!;
  const [local,gone]=Array.from(details.querySelectorAll('li'));
  expect(local.textContent).toContain('到「域名管理」对这个域名再点一次「移除域名」会接着做完，做完后这条记录会自己消失。又报错的话，先按报错的提示处理。');
  expect(gone.textContent).not.toContain('会接着做完');
  expect(details.querySelector('p')!.textContent).not.toContain('先不要清除');
  fireEvent.click(screen.getByRole('button',{name:/^域名管理$/}));
  expect(screen.getAllByRole('button',{name:/^移除 /})[0].textContent).toBe('移除域名');
});

it('says next to a cleanup record that 删除云端短链接服务 finishes it, only when that button can be pressed',async()=>{
  const hint='到账户「示例账户」的「管理账户」再点一次「删除云端短链接服务」会接着做完，做完后这条记录会自己消失。又报错的话，先按报错的提示处理。';
  mock.pending=['清理账号 a (old)：Worker 删除结果不确定，请核对后继续清理','清理账号 other (old)：Worker 删除结果不确定，请核对后继续清理'];
  const openManager=()=>{
    fireEvent.click(screen.getByRole('button',{name:/^Cloudflare 账户$/}));
    fireEvent.click(screen.getByRole('button',{name:'管理 示例账户'}));
    return within(screen.getByRole('dialog',{name:'账户管理'}));
  };
  // The account still has domains: no hint, and the button cannot be pressed.
  const withDomains=render(<App/>);
  expect((await screen.findByText('查看待处理记录（2 条）')).closest('details')!.textContent).not.toContain('会接着做完');
  expect((openManager().getByRole('button',{name:'删除云端短链接服务'}) as HTMLButtonElement).disabled).toBe(true);
  withDomains.unmount();
  // No cloud resources recorded (removed from this computer and imported again), or the token must
  // be recovered first: the click cannot run, so there is no hint either.
  for(const patch of [{hasResources:false},{needsTokenRecovery:true}]){
    mock.noDomains=true;
    mock.accountPatch=patch;
    const view=render(<App/>);
    expect((await screen.findByText('查看待处理记录（2 条）')).closest('details')!.textContent).not.toContain('会接着做完');
    view.unmount();
  }
  mock.accountPatch={};
  render(<App/>);
  const details=(await screen.findByText('查看待处理记录（2 条）')).closest('details')!;
  const [known,unknown]=Array.from(details.querySelectorAll('li'));
  expect(known.textContent).toContain(hint);
  // An account this computer no longer lists has no such button.
  expect(unknown.textContent).not.toContain('会接着做完');
  const button=openManager().getByRole('button',{name:'删除云端短链接服务'}) as HTMLButtonElement;
  expect(button.disabled).toBe(false);
});

it('shows the backend refusal for a record that has its own recovery entry, as written',async()=>{
  mock.pending=[pendingEntry];
  mock.prepareError='这条记录有专门的恢复入口，请用上方对应的按钮处理。';
  render(<App/>);
  fireEvent.click(await screen.findByRole('button',{name:'我已核对，清除这条'}));
  expect((await screen.findByRole('alert')).textContent).toContain('这条记录有专门的恢复入口，请用上方对应的按钮处理。');
  expect(screen.queryByRole('dialog')).toBeNull();
  expect(calls('apply_plan')).toHaveLength(0);
});

async function saveNewLink(){
  render(<App/>);
  await screen.findByText('/manual');
  fireEvent.click(screen.getByRole('button',{name:'新建链接'}));
  const editor=screen.getByRole('dialog',{name:'创建短链接'});
  fireEvent.change(within(editor).getByPlaceholderText('例如 welcome'),{target:{value:'fresh'}});
  fireEvent.change(within(editor).getByPlaceholderText('https://example.com/zh'),{target:{value:'https://example.com/fresh'}});
  fireEvent.change(within(editor).getByPlaceholderText('https://example.com/en'),{target:{value:'https://example.org/fresh'}});
  fireEvent.click(within(editor).getByRole('button',{name:'下一步，核对内容'}));
  const review=await screen.findByRole('dialog',{name:'保存短链接'});
  fireEvent.click(within(review).getByRole('button',{name:'确认并执行'}));
  await screen.findByText('/fresh');
}

it('reports a passing check after saving in a notice, without opening the result window',async()=>{
  await saveNewLink();
  expect(await screen.findByText('已自动检测 https://go.example.com/r/fresh：通过。')).toBeTruthy();
  expect(screen.queryByRole('button',{name:'查看结果'})).toBeNull();
  expect(screen.queryByRole('dialog',{name:'链接检测'})).toBeNull();
  expect(within(screen.getByRole('row',{name:'https://go.example.com/r/fresh'})).getByText('本机首跳检查通过')).toBeTruthy();
});

it('does not cover the next link being typed; a problem is offered behind 查看结果',async()=>{
  let release=()=>{};
  mock.routeStatus='failed';
  mock.routeGate=new Promise<void>(resolve=>{release=resolve;});
  await saveNewLink();
  await waitFor(()=>expect(calls('selftest_link')).toHaveLength(1));
  fireEvent.click(screen.getByRole('button',{name:'新建链接'}));
  const next=screen.getByRole('dialog',{name:'创建短链接'});
  const slug=within(next).getByPlaceholderText('例如 welcome');
  slug.focus();
  fireEvent.change(slug,{target:{value:'sec'}});
  await act(async()=>release());
  await waitFor(()=>expect(within(screen.getByRole('row',{name:'https://go.example.com/r/fresh'})).getByText('本机检测发现失败')).toBeTruthy());
  expect(screen.queryByRole('dialog',{name:'链接检测'})).toBeNull();
  expect(document.activeElement).toBe(slug);
  expect(screen.getByText(/已自动检测 https:\/\/go\.example\.com\/r\/fresh：有问题/)).toBeTruthy();
  // Close the half-filled editor (two Escapes, since something was typed) and read the result.
  fireEvent.keyDown(document,{key:'Escape'});
  expect(screen.getByRole('dialog',{name:'创建短链接'})).toBe(next);
  fireEvent.keyDown(document,{key:'Escape'});
  await waitFor(()=>expect(screen.queryByRole('dialog',{name:'创建短链接'})).toBeNull());
  fireEvent.click(screen.getByRole('button',{name:'查看结果'}));
  const result=await screen.findByRole('dialog',{name:'链接检测'});
  expect(within(result).getByText('跳转检测失败')).toBeTruthy();
});

it('a manual 检测 still opens the result window',async()=>{
  render(<App/>);
  fireEvent.click(await screen.findByRole('button',{name:'检测 manual'}));
  expect(await screen.findByRole('dialog',{name:'链接检测'})).toBeTruthy();
});

it('turns the copy button into 已复制 ✓ for about two seconds, and keeps notices in the sticky stack',async()=>{
  render(<App/>);
  const button=await screen.findByRole('button',{name:'复制 manual'});
  fireEvent.click(button);
  await waitFor(()=>expect(button.textContent).toBe('已复制 ✓'));
  expect(clipboard.writeText).toHaveBeenCalledWith('https://go.example.com/r/manual');
  expect(screen.getByText('已复制短链接。').closest('.alert-stack')).toBeTruthy();
  await waitFor(()=>expect(button.textContent).toBe('复制'),{timeout:3000});
});

it('does not claim success on the copy button when copying failed',async()=>{
  clipboard.writeText.mockRejectedValue(new Error('Write permission denied.'));
  render(<App/>);
  const button=await screen.findByRole('button',{name:'复制 manual'});
  fireEvent.click(button);
  const alert=await screen.findByRole('alert');
  // The system's English wording is replaced by a sentence that says what to do.
  expect(alert.textContent).toContain('没能复制到剪贴板，请手动选中这条地址再复制。');
  expect(alert.textContent).not.toContain('Write permission denied');
  expect(alert.closest('.alert-stack')).toBeTruthy();
  expect(button.textContent).toBe('复制');
});

it.each([true,false])('opens the token template page automatically only when no account exists yet (accounts: %s)',async(hasAccounts)=>{
  mock.accounts=hasAccounts;
  render(<App/>);
  await waitFor(()=>expect(screen.queryByText('正在读取本机配置…')).toBeNull());
  fireEvent.click(screen.getByRole('button',{name:/^Cloudflare 账户$/}));
  fireEvent.click(screen.getAllByRole('button',{name:'导入账户'})[0]);
  const dialog=screen.getByRole('dialog',{name:'导入访问令牌'});
  if(hasAccounts){
    await act(async()=>{});
    expect(calls('token_template')).toHaveLength(0);
    expect(openUrl).not.toHaveBeenCalled();
    fireEvent.click(within(dialog).getByRole('button',{name:'在系统浏览器中打开令牌模板'}));
    await waitFor(()=>expect(openUrl).toHaveBeenCalledWith('https://example.com/token-template'));
  } else {
    await waitFor(()=>expect(openUrl).toHaveBeenCalledWith('https://example.com/token-template'));
  }
});

it('explains why 只看需关注 is unavailable and shows the filtered count',async()=>{
  render(<App/>);
  await screen.findByText('/manual');
  const attention=screen.getByRole('button',{name:'只看需关注'}) as HTMLButtonElement;
  expect(attention.disabled).toBe(true);
  expect(screen.getByText('先打开上方的自动巡检，才能筛出需关注的链接。')).toBeTruthy();
  expect(attention.getAttribute('aria-describedby')).toBe('attention-disabled-reason');
  expect(screen.getByRole('heading',{name:'全部链接 2'})).toBeTruthy();
  fireEvent.change(screen.getByRole('textbox',{name:'搜索链接'}),{target:{value:'manual'}});
  expect(screen.getByRole('heading',{name:'全部链接 1 / 2'})).toBeTruthy();
  fireEvent.change(screen.getByRole('textbox',{name:'搜索链接'}),{target:{value:''}});
  fireEvent.change(screen.getByRole('combobox',{name:'筛选域名'}),{target:{value:'e'}});
  expect(screen.getByRole('heading',{name:'全部链接 1 / 2'})).toBeTruthy();
});

it('says when nothing has been checked yet, and when nothing needs attention',async()=>{
  mock.redirectGate=true;
  render(<App/>);
  await screen.findByText('/manual');
  fireEvent.click(screen.getByRole('checkbox',{name:/未开启/}));
  expect(await screen.findByText('还没检测过，等第一轮巡检完成后再用。')).toBeTruthy();
  expect((screen.getByRole('button',{name:'只看需关注'}) as HTMLButtonElement).disabled).toBe(true);
  cleanup();
  mock.redirectGate=false;
  render(<App/>);
  await screen.findByText('/manual');
  expect(await screen.findByText('目前没有需要关注的链接。')).toBeTruthy();
  expect((screen.getByRole('button',{name:'只看需关注'}) as HTMLButtonElement).disabled).toBe(true);
});

it('treats a busy reply while adding a domain as "try again", not as a token problem',async()=>{
  mock.domainBusy=1;
  render(<App/>);
  await screen.findByText('/manual');
  fireEvent.click(screen.getByRole('button',{name:/^域名管理$/}));
  fireEvent.click(screen.getByRole('button',{name:'添加域名'}));
  const dialog=screen.getByRole('dialog',{name:'添加域名'});
  fireEvent.change(within(dialog).getByPlaceholderText('go.example.com'),{target:{value:'sub.example.com'}});
  fireEvent.click(within(dialog).getByRole('button',{name:'检查并继续'}));
  expect(await within(dialog).findByText('上一个操作还没结束，请稍等几秒再试。')).toBeTruthy();
  expect(within(dialog).queryByRole('button',{name:'更换本机令牌'})).toBeNull();
  expect(within(dialog).queryByRole('button',{name:'修改已有令牌权限'})).toBeNull();
  expect(within(dialog).queryByRole('alert')).toBeNull();
  fireEvent.click(within(dialog).getByRole('button',{name:'再试一次'}));
  await waitFor(()=>expect(calls('prepare_domain')).toHaveLength(2));
  expect(await within(dialog).findByText('区域与代理')).toBeTruthy();
  expect(within(dialog).queryByText(/上一个操作还没结束/)).toBeNull();
});

it('keeps the typed service key when preparing the monitor fails, so a retry needs no re-paste',async()=>{
  mock.monitorError='上一个操作还没结束，请稍等几秒再试。';
  render(<App/>);
  await screen.findByText('/manual');
  fireEvent.click(screen.getByRole('button',{name:/^Cloudflare 账户$/}));
  fireEvent.click(screen.getByRole('button',{name:'管理 示例账户'}));
  fireEvent.click(within(screen.getByRole('dialog',{name:'账户管理'})).getByRole('button',{name:'配置检测服务'}));
  const editor=screen.getByRole('dialog',{name:'配置检测服务'});
  const secret='example-secret-0123456789abcdefghijkl';
  fireEvent.change(within(editor).getByPlaceholderText('https://probe.example.com/check'),{target:{value:'https://probe.example.com/check'}});
  fireEvent.change(within(editor).getByLabelText(/服务密钥/),{target:{value:secret}});
  fireEvent.click(within(editor).getByRole('button',{name:'预览启用计划'}));
  expect((await within(editor).findByRole('alert')).textContent).toContain('上一个操作还没结束');
  expect((within(editor).getByLabelText(/服务密钥/) as HTMLInputElement).value).toBe(secret);
  mock.monitorError='';
  fireEvent.click(within(editor).getByRole('button',{name:'预览启用计划'}));
  const review=await screen.findByRole('dialog',{name:'启用检测服务'});
  expect(calls('prepare_monitor').at(-1)?.payload.secret).toBe(secret);
  expect(review.textContent).not.toContain(secret);
});

it('asks for a second Escape only in dialogs where something was typed',async()=>{
  render(<App/>);
  await screen.findByText('/manual');
  fireEvent.click(screen.getByRole('button',{name:'新建链接'}));
  fireEvent.keyDown(document,{key:'Escape'});
  expect(screen.queryByRole('dialog',{name:'创建短链接'})).toBeNull();
  fireEvent.click(screen.getByRole('button',{name:'编辑 manual'}));
  const editor=screen.getByRole('dialog',{name:'编辑短链接'});
  // The first text field gets the cursor, not the disabled domain dropdown.
  expect(document.activeElement).toBe(within(editor).getByPlaceholderText('https://example.com/zh'));
  fireEvent.change(within(editor).getByPlaceholderText('https://example.com/zh'),{target:{value:'https://example.com/changed'}});
  fireEvent.keyDown(document,{key:'Escape'});
  expect(screen.getByRole('dialog',{name:'编辑短链接'})).toBe(editor);
  expect(within(editor).getByText('再按一次 Esc 放弃已填的内容。')).toBeTruthy();
  fireEvent.mouseDown(editor.parentElement!);
  expect(screen.getByRole('dialog',{name:'编辑短链接'})).toBe(editor);
  fireEvent.keyDown(document,{key:'Escape'});
  expect(screen.queryByRole('dialog',{name:'编辑短链接'})).toBeNull();
  fireEvent.click(screen.getByRole('button',{name:/^域名管理$/}));
  fireEvent.click(screen.getByRole('button',{name:'添加域名'}));
  const domain=screen.getByRole('dialog',{name:'添加域名'});
  expect(document.activeElement).toBe(within(domain).getByPlaceholderText('go.example.com'));
  fireEvent.change(within(domain).getByPlaceholderText('go.example.com'),{target:{value:'sub.example.com'}});
  fireEvent.keyDown(document,{key:'Escape'});
  expect(screen.getByRole('dialog',{name:'添加域名'})).toBe(domain);
  fireEvent.click(within(domain).getByRole('button',{name:'取消'}));
  expect(screen.queryByRole('dialog',{name:'添加域名'})).toBeNull();
  fireEvent.click(screen.getByRole('button',{name:/^平台地址$/}));
  fireEvent.click(screen.getByRole('button',{name:'添加平台地址'}));
  const pool=screen.getByRole('dialog',{name:'添加平台地址'});
  fireEvent.keyDown(document,{key:'Escape'});
  expect(screen.queryByRole('dialog',{name:'添加平台地址'})).toBeNull();
  fireEvent.click(screen.getByRole('button',{name:'添加平台地址'}));
  const typed=screen.getByRole('dialog',{name:'添加平台地址'});
  expect(typed).not.toBe(pool);
  fireEvent.change(within(typed).getByRole('textbox',{name:'官网链接 完整邀请链接'}),{target:{value:'https://example.com/join/CODE'}});
  fireEvent.keyDown(document,{key:'Escape'});
  expect(screen.getByRole('dialog',{name:'添加平台地址'})).toBe(typed);
});

// The wording the backend sends today mentions 授权, and the agreed new opening may be followed by
// the same hint. Neither is a token problem.
it.each([
  '上一个操作仍在进行，请稍候；若有系统授权窗口，请先完成或取消，无需重复点击',
  '上一个操作还没结束，请稍等几秒再试；如果有系统授权窗口，请先完成或取消。',
])('does not offer token recovery for a busy reply that mentions 授权: %s',async(text)=>{
  mock.domainBusy=1;
  mock.domainBusyText=text;
  render(<App/>);
  await screen.findByText('/manual');
  fireEvent.click(screen.getByRole('button',{name:/^域名管理$/}));
  fireEvent.click(screen.getByRole('button',{name:'添加域名'}));
  const dialog=screen.getByRole('dialog',{name:'添加域名'});
  fireEvent.change(within(dialog).getByPlaceholderText('go.example.com'),{target:{value:'sub.example.com'}});
  fireEvent.click(within(dialog).getByRole('button',{name:'检查并继续'}));
  expect(await within(dialog).findByText(text)).toBeTruthy();
  expect(within(dialog).queryByRole('button',{name:'更换本机令牌'})).toBeNull();
  expect(within(dialog).queryByRole('button',{name:'修改已有令牌权限'})).toBeNull();
  expect(within(dialog).queryByRole('button',{name:'已补好授权，继续检查'})).toBeNull();
  fireEvent.click(within(dialog).getByRole('button',{name:'再试一次'}));
  await waitFor(()=>expect(calls('prepare_domain')).toHaveLength(2));
  expect(await within(dialog).findByText('区域与代理')).toBeTruthy();
});

it('repeats the list refresh, not the check, when the busy reply came from 刷新域名列表',async()=>{
  mock.domainBusy=1;
  mock.domainBusyText='上一个操作仍在进行，请稍候；若有系统授权窗口，请先完成或取消，无需重复点击';
  render(<App/>);
  await screen.findByText('/manual');
  fireEvent.click(screen.getByRole('button',{name:/^域名管理$/}));
  fireEvent.click(screen.getByRole('button',{name:'添加域名'}));
  const dialog=screen.getByRole('dialog',{name:'添加域名'});
  fireEvent.click(within(dialog).getAllByRole('button',{name:'刷新域名列表'})[0]);
  expect(await within(dialog).findByText(/无法读取此账户的域名：上一个操作仍在进行/)).toBeTruthy();
  expect(within(dialog).queryByRole('button',{name:'更换本机令牌'})).toBeNull();
  expect(within(dialog).queryByRole('button',{name:'修改已有令牌权限'})).toBeNull();
  fireEvent.click(within(dialog).getByRole('button',{name:'再试一次'}));
  await waitFor(()=>expect(calls('refresh_domains')).toHaveLength(2));
  expect(calls('prepare_domain')).toHaveLength(0);
  expect(await within(dialog).findByText(/已读取「Example team」的 1 个域名/)).toBeTruthy();
});

it('keeps 只看需关注 clickable while it is switched on, even after nothing needs attention any more',async()=>{
  mock.redirectStatus='unknown';
  render(<App/>);
  await screen.findByText('/manual');
  fireEvent.click(screen.getByRole('checkbox',{name:/未开启/}));
  await waitFor(()=>expect((screen.getByRole('button',{name:'只看需关注'}) as HTMLButtonElement).disabled).toBe(false));
  expect(screen.queryByText(/目前没有需要关注的链接|还没检测过/)).toBeNull();
  fireEvent.click(screen.getByRole('button',{name:'只看需关注'}));
  expect(await screen.findByRole('heading',{name:'需关注链接 2'})).toBeTruthy();
  // The next round finds everything healthy: the filtered list empties, the way back must stay open.
  mock.redirectStatus='passed';
  fireEvent.click(screen.getByRole('button',{name:/立即巡检/}));
  expect(await screen.findByText('目前没有需关注的链接')).toBeTruthy();
  const pressed=screen.getByRole('button',{name:'只看需关注'}) as HTMLButtonElement;
  expect(pressed.getAttribute('aria-pressed')).toBe('true');
  expect(pressed.disabled).toBe(false);
  expect(screen.queryByText('目前没有需要关注的链接。')).toBeNull();
  fireEvent.click(pressed);
  expect(screen.getByRole('heading',{name:'全部链接 2'})).toBeTruthy();
  expect(screen.getByText('/manual')).toBeTruthy();
});

it('keeps the confirmed plan after a busy reply, so 确认并执行 can simply be pressed again',async()=>{
  const busyText='上一个操作还没结束，已经等了几秒。请稍后再点一次；如果屏幕上有系统的钥匙串窗口，请先处理它。';
  mock.domainPlan=true;
  mock.applyError=busyText;
  render(<App/>);
  await screen.findByText('/manual');
  fireEvent.click(screen.getByRole('button',{name:/^域名管理$/}));
  fireEvent.click(screen.getByRole('button',{name:'添加域名'}));
  fireEvent.change(within(screen.getByRole('dialog',{name:'添加域名'})).getByPlaceholderText('go.example.com'),{target:{value:'sub.example.com'}});
  fireEvent.click(screen.getByRole('button',{name:'检查并继续'}));
  fireEvent.click(await screen.findByRole('button',{name:'确认并执行'}));
  await waitFor(()=>expect(calls('apply_plan')).toHaveLength(1));
  // The backend gave up before it took the plan: the same review window stays, with the busy text.
  const review=screen.getByRole('dialog',{name:'添加域名'});
  await waitFor(()=>expect(within(review).getByRole('alert').textContent).toContain(busyText));
  expect(within(review).queryByRole('button',{name:'更换本机令牌'})).toBeNull();
  expect(within(review).queryByRole('button',{name:'修改已有令牌权限'})).toBeNull();
  const again=within(review).getByRole('button',{name:'确认并执行'}) as HTMLButtonElement;
  expect(again.disabled).toBe(false);
  fireEvent.click(again);
  await waitFor(()=>expect(calls('apply_plan')).toHaveLength(2));
  expect(calls('apply_plan')[1].payload.planId).toBe(calls('apply_plan')[0].payload.planId);
  expect(calls('prepare_domain')).toHaveLength(1);
  expect(await screen.findByText(/域名已接入/)).toBeTruthy();
});

it('does not promise a first round when there are no links to check at all',async()=>{
  mock.noLinks=true;
  render(<App/>);
  await screen.findByRole('heading',{name:'全部链接 0'});
  fireEvent.click(screen.getByRole('checkbox',{name:/未开启/}));
  expect(await screen.findByText('目前没有需要关注的链接。')).toBeTruthy();
  expect(screen.queryByText(/等第一轮巡检完成后再用/)).toBeNull();
  expect((screen.getByRole('button',{name:'只看需关注'}) as HTMLButtonElement).disabled).toBe(true);
});

it('opens the result window when 检测 is pressed while the quiet check for that link is still running',async()=>{
  let release=()=>{};
  mock.routeGate=new Promise<void>(resolve=>{release=resolve;});
  await saveNewLink();
  await waitFor(()=>expect(calls('selftest_link')).toHaveLength(1));
  fireEvent.click(screen.getByRole('button',{name:'检测 fresh'}));
  await act(async()=>release());
  expect(await screen.findByRole('dialog',{name:'链接检测'})).toBeTruthy();
  // Still one request: the running check is reused, only its result is shown differently.
  expect(calls('selftest_link')).toHaveLength(1);
  expect(screen.queryByText(/已自动检测/)).toBeNull();
});

it('records a quiet check that is still running when another link is checked by hand',async()=>{
  let release=()=>{};
  mock.routeGate=new Promise<void>(resolve=>{release=resolve;});
  await saveNewLink();
  await waitFor(()=>expect(calls('selftest_link')).toHaveLength(1));
  fireEvent.click(screen.getByRole('button',{name:'检测 manual'}));
  await waitFor(()=>expect(calls('selftest_link')).toHaveLength(2));
  await act(async()=>release());
  expect(await screen.findByRole('dialog',{name:'链接检测'})).toBeTruthy();
  // The quiet check of fresh still reports, in its row and in its notice.
  await waitFor(()=>expect(within(screen.getByRole('row',{name:'https://go.example.com/r/fresh'})).getByText('本机首跳检查通过')).toBeTruthy());
  expect(screen.getByText('已自动检测 https://go.example.com/r/fresh：通过。')).toBeTruthy();
  expect(within(screen.getByRole('row',{name:'https://go.example.com/r/manual'})).getByText('本机首跳检查通过')).toBeTruthy();
});

it('keeps an unread problem notice when a later quiet check of another link passes',async()=>{
  mock.routeStatus='failed';
  await saveNewLink();
  expect(await screen.findByText(/已自动检测 https:\/\/go\.example\.com\/r\/fresh：有问题/)).toBeTruthy();
  mock.routeStatus='passed';
  fireEvent.click(screen.getByRole('button',{name:'编辑 other'}));
  const editor=screen.getByRole('dialog',{name:'编辑短链接'});
  fireEvent.change(within(editor).getByPlaceholderText('https://example.com/zh'),{target:{value:'https://example.com/changed'}});
  fireEvent.click(within(editor).getByRole('button',{name:'下一步，核对内容'}));
  fireEvent.click(within(await screen.findByRole('dialog',{name:'保存短链接'})).getByRole('button',{name:'确认并执行'}));
  await waitFor(()=>expect(within(screen.getByRole('row',{name:'https://links.example.com/s/other'})).getByText('本机首跳检查通过')).toBeTruthy());
  expect(screen.getByText(/已自动检测 https:\/\/go\.example\.com\/r\/fresh：有问题/)).toBeTruthy();
  expect(screen.queryByText(/已自动检测 https:\/\/links\.example\.com/)).toBeNull();
  expect(screen.getByRole('button',{name:'查看结果'})).toBeTruthy();
});

it('runs the quiet check after an older request for the same link finishes, without a stray notice',async()=>{
  let release=()=>{};
  mock.routeGate=new Promise<void>(resolve=>{release=resolve;});
  render(<App/>);
  await screen.findByText('/manual');
  fireEvent.click(screen.getByRole('button',{name:'检测 manual'}));
  await waitFor(()=>expect(calls('selftest_link')).toHaveLength(1));
  fireEvent.click(screen.getByRole('button',{name:'取消等待'}));
  fireEvent.click(screen.getByRole('button',{name:'编辑 manual'}));
  const editor=screen.getByRole('dialog',{name:'编辑短链接'});
  fireEvent.change(within(editor).getByPlaceholderText('https://example.com/zh'),{target:{value:'https://example.com/changed'}});
  fireEvent.click(within(editor).getByRole('button',{name:'下一步，核对内容'}));
  fireEvent.click(within(await screen.findByRole('dialog',{name:'保存短链接'})).getByRole('button',{name:'确认并执行'}));
  await waitFor(()=>expect(screen.queryByRole('dialog',{name:'保存短链接'})).toBeNull());
  expect(screen.queryByText('上一次检测还在收尾，几秒后再试。')).toBeNull();
  expect(calls('selftest_link')).toHaveLength(1);
  await act(async()=>release());
  await waitFor(()=>expect(calls('selftest_link')).toHaveLength(2));
  expect(await screen.findByText('已自动检测 https://go.example.com/r/manual：通过。')).toBeTruthy();
  expect(screen.queryByText('上一次检测还在收尾，几秒后再试。')).toBeNull();
});

it('sends no public DNS retry for a quiet check once the app is gone',async()=>{
  // While the app is open, a quiet check that only saw a VPN address is repeated with public DNS.
  mock.targetsVirtual=true;
  await saveNewLink();
  await waitFor(()=>expect(calls('selftest_link')).toHaveLength(2));
  expect(calls('selftest_link')[1].payload.dnsMode).toBe('public');
  expect(await screen.findByText('已自动检测 https://go.example.com/r/fresh：通过。')).toBeTruthy();
  cleanup();
  // Same answers, but the app is closed while the first round is still running.
  Object.assign(mock,{calls:[],extraLink:false});
  let release=()=>{};
  mock.routeGate=new Promise<void>(resolve=>{release=resolve;});
  await saveNewLink();
  await waitFor(()=>expect(calls('selftest_link')).toHaveLength(1));
  cleanup();
  await act(async()=>{release();await new Promise(resolve=>setTimeout(resolve,30));});
  expect(calls('selftest_link')).toHaveLength(1);
  expect(calls('check_link_targets')).toHaveLength(1);
});

it('asks for a second Escape in 配置检测服务 and 重命名账户 once something was typed',async()=>{
  render(<App/>);
  await screen.findByText('/manual');
  fireEvent.click(screen.getByRole('button',{name:/^Cloudflare 账户$/}));
  const openManage=()=>{fireEvent.click(screen.getByRole('button',{name:'管理 示例账户'}));return screen.getByRole('dialog',{name:'账户管理'});};
  fireEvent.click(within(openManage()).getByRole('button',{name:'配置检测服务'}));
  fireEvent.keyDown(document,{key:'Escape'});
  expect(screen.queryByRole('dialog',{name:'配置检测服务'})).toBeNull();
  fireEvent.click(within(openManage()).getByRole('button',{name:'配置检测服务'}));
  const monitor=screen.getByRole('dialog',{name:'配置检测服务'});
  fireEvent.change(within(monitor).getByLabelText(/服务密钥/),{target:{value:'example-secret-0123456789abcdefghijkl'}});
  fireEvent.keyDown(document,{key:'Escape'});
  expect(screen.getByRole('dialog',{name:'配置检测服务'})).toBe(monitor);
  expect(within(monitor).getByText('再按一次 Esc 放弃已填的内容。')).toBeTruthy();
  fireEvent.keyDown(document,{key:'Escape'});
  expect(screen.queryByRole('dialog',{name:'配置检测服务'})).toBeNull();
  fireEvent.click(within(openManage()).getByRole('button',{name:'修改本机备注'}));
  fireEvent.keyDown(document,{key:'Escape'});
  expect(screen.queryByRole('dialog',{name:'重命名账户'})).toBeNull();
  fireEvent.click(within(openManage()).getByRole('button',{name:'修改本机备注'}));
  const rename=screen.getByRole('dialog',{name:'重命名账户'});
  fireEvent.change(within(rename).getByRole('textbox',{name:/账户名称/}),{target:{value:'新名称'}});
  fireEvent.keyDown(document,{key:'Escape'});
  expect(screen.getByRole('dialog',{name:'重命名账户'})).toBe(rename);
  fireEvent.keyDown(document,{key:'Escape'});
  expect(screen.queryByRole('dialog',{name:'重命名账户'})).toBeNull();
});
