import {act,cleanup,fireEvent,render,screen,waitFor,within} from '@testing-library/react';
import {afterEach,expect,it,vi} from 'vitest';
import App from './App';
import {openUrl} from '@tauri-apps/plugin-opener';

vi.mock('@tauri-apps/plugin-opener',()=>({openUrl:vi.fn()}));

const control=vi.hoisted(()=>({calls:[] as {action:string;payload:Record<string,unknown>}[],resolveApply:null as null|((value:unknown)=>void),dnsReady:false,domainReady:false,applyFails:false,multi:false,ambiguous:false}));
const account={id:'a',label:'示例账户',zones:[{id:'z',name:'example.com',status:'active'}],zoneCount:1,checkedAt:null,hasResources:true,needsSelftestKey:false};
function currentState(){return {accounts:control.multi?[account,{...account,id:'b',label:'第二账户',zones:[]}]:[account],domains:[],links:[],pools:[],pendingOperations:['本机记录待刷新'],pendingActions:[]};}
vi.mock('./bridge',()=>({preview:false,errorMessage:(error:unknown)=>String(error),dispatch:async(action:string,payload:Record<string,unknown>={})=>{
  control.calls.push({action,payload});
  if(action==='get_state')return currentState();
  if(action==='prepare_domain') { const ready=control.domainReady||(control.dnsReady&&control.calls.filter(call=>call.action==='prepare_domain').length>1);const candidates=[{accountId:'a',label:'示例账户',zoneId:'z',status:'active'},...(control.ambiguous?[{accountId:'b',label:'第二账户',zoneId:'b-z',status:'active'}]:[])];return {host:payload.input,prefix:payload.prefix,candidates,checks:[{label:'DNS',ok:ready,level:ready?'pass':'error',message:'示例检查'}],canApply:ready,...(ready?{plan:{id:'domain',title:'添加域名',steps:[],warnings:[],expiresAt:new Date(Date.now()+300000).toISOString()}}:{})}; }
  if(action==='prepare_domain_dns')return control.dnsReady ? {host:payload.input,candidates:[],checks:[{label:'DNS 与代理',ok:true,level:'pass',message:'已就绪'}],dnsStatus:'ready',actions:[],canApply:false} : {host:payload.input,candidates:[],checks:[],dnsStatus:'missing',actions:[{kind:'createPlaceholder',recordType:'AAAA',name:payload.input}],canApply:true,plan:{id:'dns',title:'修复 DNS',steps:[],warnings:[],expiresAt:new Date(Date.now()+300000).toISOString()}};
  if(action==='apply_plan'){if(control.applyFails)throw new Error('Cloudflare 拒绝修改 DNS（HTTP 403）。请检查此令牌的 DNS 编辑权限和域名授权范围');return new Promise(resolve=>{control.resolveApply=resolve;});}
  throw new Error(`Unexpected ${action}`);
}}));

afterEach(()=>{cleanup();control.calls.length=0;control.resolveApply=null;control.dnsReady=false;control.domainReady=false;control.applyFails=false;control.multi=false;control.ambiguous=false;vi.clearAllMocks();});

it('keeps a DNS repair plan open while applying, so its late result cannot prepare another host',async()=>{
  render(<App/>); await screen.findByText('先连接一个域名');
  fireEvent.click(screen.getByRole('button',{name:/^域名管理$/}));
  fireEvent.click(screen.getAllByRole('button',{name:'添加域名'})[0]);
  const form=screen.getByRole('dialog',{name:'添加域名'});
  fireEvent.change(within(form).getByPlaceholderText('go.example.com'),{target:{value:'old.example.com'}});
  fireEvent.click(within(form).getByRole('button',{name:'检查并继续'}));
  const plan=await screen.findByRole('dialog',{name:'修复 DNS'});
  expect(control.calls.filter(call=>call.action==='prepare_domain_dns')).toHaveLength(1);
  fireEvent.click(within(plan).getByRole('button',{name:'确认修改并继续检查'}));
  await waitFor(()=>expect(control.resolveApply).toBeTypeOf('function'));
  fireEvent.keyDown(document,{key:'Escape'});
  fireEvent.mouseDown(plan.parentElement!);
  fireEvent.click(within(plan).getByRole('button',{name:'返回'}));
  expect(screen.getByRole('dialog',{name:'修复 DNS'})).toBeTruthy();
  expect(screen.queryByRole('dialog',{name:'添加域名'})).toBeNull();
  control.domainReady=true;
  await act(async()=>{control.resolveApply!(currentState());});
  expect(await screen.findByText('解析设置已提交，正在继续检查域名。')).toBeTruthy();
  const nextPlan=await screen.findByRole('button',{name:'确认并执行'});
  expect(screen.getByText('域名：old.example.com')).toBeTruthy();
  expect(nextPlan).toBeTruthy();
  expect(control.calls.filter(call=>call.action==='prepare_domain').at(-1)?.payload.input).toBe('old.example.com');
});

it('continues from ready DNS into the domain confirmation without another click',async()=>{
  control.dnsReady=true;
  render(<App/>); await screen.findByText('先连接一个域名');
  fireEvent.click(screen.getByRole('button',{name:/^域名管理$/}));
  fireEvent.click(screen.getAllByRole('button',{name:'添加域名'})[0]);
  const form=screen.getByRole('dialog',{name:'添加域名'});
  fireEvent.change(within(form).getByPlaceholderText('go.example.com'),{target:{value:'ready.example.com'}});
  fireEvent.click(within(form).getByRole('button',{name:'检查并继续'}));
  expect(await screen.findByRole('button',{name:'确认并执行'})).toBeTruthy();
  expect(control.calls.filter(call=>call.action==='prepare_domain')).toHaveLength(2);
  expect(control.calls.filter(call=>call.action==='prepare_domain_dns')).toHaveLength(1);
  expect(control.calls.filter(call=>call.action==='get_state').length).toBeGreaterThan(1);
});

it('prepares a missing DNS repair plan in the first user operation',async()=>{
  render(<App/>); await screen.findByText('先连接一个域名');
  fireEvent.click(screen.getByRole('button',{name:/^域名管理$/}));
  fireEvent.click(screen.getAllByRole('button',{name:'添加域名'})[0]);
  const form=screen.getByRole('dialog',{name:'添加域名'});
  fireEvent.change(within(form).getByPlaceholderText('go.example.com'),{target:{value:'repair.example.com'}});
  fireEvent.click(within(form).getByRole('button',{name:'检查并继续'}));
  expect(await screen.findByRole('dialog',{name:'修复 DNS'})).toBeTruthy();
  expect(control.calls.filter(call=>call.action==='prepare_domain_dns')).toHaveLength(1);
  expect(control.calls.filter(call=>call.action==='get_state').length).toBeGreaterThan(2);
});

it('keeps a DNS permission failure visible and retries only the read preparation',async()=>{
  control.applyFails=true;
  render(<App/>); await screen.findByText('先连接一个域名');
  fireEvent.click(screen.getByRole('button',{name:/^域名管理$/}));
  fireEvent.click(screen.getAllByRole('button',{name:'添加域名'})[0]);
  const form=screen.getByRole('dialog',{name:'添加域名'});
  fireEvent.change(within(form).getByPlaceholderText('go.example.com'),{target:{value:'blocked.example.com'}});
  fireEvent.click(within(form).getByRole('button',{name:'检查并继续'}));
  const plan=await screen.findByRole('dialog',{name:'修复 DNS'});
  fireEvent.click(within(plan).getByRole('button',{name:'确认修改并继续检查'}));
  const reopened=await screen.findByRole('dialog',{name:'添加域名'});
  const alert=within(reopened).getByRole('alert');
  expect(alert.textContent).toContain('当前授权无法修改此域名的解析');
  expect(within(reopened).getByRole('button',{name:'更换本机令牌'})).toBeTruthy();
  const callsBeforeEdit=control.calls.length;
  fireEvent.click(within(reopened).getByRole('button',{name:'修改已有令牌权限'}));
  await waitFor(()=>expect(openUrl).toHaveBeenCalledWith('https://dash.cloudflare.com/profile/api-tokens'));
  expect(control.calls).toHaveLength(callsBeforeEdit);
  fireEvent.click(within(reopened).getByRole('button',{name:'已补好授权，继续检查'}));
  expect(await screen.findByRole('dialog',{name:'修复 DNS'})).toBeTruthy();
  expect(control.calls.filter(call=>call.action==='apply_plan')).toHaveLength(1);
});

it('binds a unique automatic account match so recovery stays available after a DNS failure',async()=>{
  control.multi=true;control.applyFails=true;
  render(<App/>);await screen.findByText('先连接一个域名');
  fireEvent.click(screen.getByRole('button',{name:/^域名管理$/}));
  fireEvent.click(screen.getAllByRole('button',{name:'添加域名'})[0]);
  const form=screen.getByRole('dialog',{name:'添加域名'});
  fireEvent.change(within(form).getByPlaceholderText('go.example.com'),{target:{value:'auto.example.com'}});
  expect((within(form).getByRole('combobox',{name:'Cloudflare 账户'}) as HTMLSelectElement).value).toBe('');
  fireEvent.click(within(form).getByRole('button',{name:'检查并继续'}));
  const plan=await screen.findByRole('dialog',{name:'修复 DNS'});
  expect(control.calls.find(call=>call.action==='prepare_domain_dns')?.payload.accountId).toBe('a');
  fireEvent.click(within(plan).getByRole('button',{name:'确认修改并继续检查'}));
  const reopened=await screen.findByRole('dialog',{name:'添加域名'});
  expect((within(reopened).getByRole('combobox',{name:'Cloudflare 账户'}) as HTMLSelectElement).value).toBe('a');
  expect(within(reopened).getByRole('button',{name:'已补好授权，继续检查'})).toBeTruthy();
  expect(within(reopened).getByRole('button',{name:'更换本机令牌'})).toBeTruthy();
});

it('requires an explicit account choice when domain preparation has multiple candidates',async()=>{
  control.multi=true;control.ambiguous=true;
  render(<App/>);await screen.findByText('先连接一个域名');
  fireEvent.click(screen.getByRole('button',{name:/^域名管理$/}));
  fireEvent.click(screen.getAllByRole('button',{name:'添加域名'})[0]);
  const form=screen.getByRole('dialog',{name:'添加域名'});
  fireEvent.change(within(form).getByPlaceholderText('go.example.com'),{target:{value:'ambiguous.example.com'}});
  fireEvent.click(within(form).getByRole('button',{name:'检查并继续'}));
  expect((await within(form).findByRole('alert')).textContent).toContain('多个账户都可能管理此域名');
  expect(control.calls.filter(call=>call.action==='prepare_domain_dns')).toHaveLength(0);
  expect(control.calls.filter(call=>call.action==='apply_plan')).toHaveLength(0);
});

it('keeps the explicit VPN choice through the DNS-ready automatic directory recheck',async()=>{
  control.dnsReady=true;
  render(<App/>);await screen.findByText('先连接一个域名');
  fireEvent.click(screen.getByRole('button',{name:/^域名管理$/}));
  fireEvent.click(screen.getAllByRole('button',{name:'添加域名'})[0]);
  const form=screen.getByRole('dialog',{name:'添加域名'});
  fireEvent.change(within(form).getByPlaceholderText('go.example.com'),{target:{value:'ready.example.com'}});
  const vpn=within(form).getByRole('checkbox',{name:'直接使用公共 DNS（手动兼容 VPN）'}) as HTMLInputElement;
  expect(vpn.checked).toBe(false);
  fireEvent.click(vpn);
  fireEvent.click(within(form).getByRole('button',{name:'检查并继续'}));
  await screen.findByRole('button',{name:'确认并执行'});
  const checks=control.calls.filter(call=>call.action==='prepare_domain');
  expect(checks).toHaveLength(2);
  expect(checks.every(call=>call.payload.dnsMode==='public')).toBe(true);
  expect(control.calls.filter(call=>call.action==='apply_plan')).toHaveLength(0);
});
