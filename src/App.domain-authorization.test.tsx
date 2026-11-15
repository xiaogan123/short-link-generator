import {cleanup,fireEvent,render,screen,waitFor,within} from '@testing-library/react';
import {afterEach,beforeEach,expect,it,vi} from 'vitest';
import App from './App';
import type {DomainCheck} from './types';

// Backend sentences, quoted from src-tauri/src (domain_check.rs probe result, lib.rs checks and
// BUSY_MESSAGE, cloud.rs failure_message, secret_store.rs SecretError).
const WEBSITE_403='此路径返回 HTTP 403（访问被拒绝），请处理后重新检查';
const NOT_FOUND='已从 Cloudflare 刷新，但当前令牌可见的域名中仍未找到它。请确认所属账户、域名已添加到 Cloudflare，以及令牌允许访问这个新域名';
const CLOUD_403='云端请求失败（HTTP 403），请检查令牌权限与资源状态';
const CLOUD_404='云端请求失败（HTTP 404），请检查令牌权限与资源状态';
const IMPORT_PENDING='账户「示例账户」：此账号的令牌导入尚未完成，请重试原令牌或明确更新该账号令牌';
const KEY_MISSING='系统凭据库中找不到所需密钥';
const BUSY='上一个操作还没结束，已经等了几秒。请稍后再点一次；如果屏幕上有系统的钥匙串窗口，请先处理它。';
const TOKEN_BUTTONS=['修改已有令牌权限','已补好授权，继续检查','更换本机令牌'];

vi.mock('@tauri-apps/plugin-opener',()=>({openUrl:vi.fn(async()=>{})}));
const mock=vi.hoisted(()=>({
  calls:[] as {action:string;payload:Record<string,unknown>}[],
  checks:[] as DomainCheck[],
  candidates:true,
  domainPlan:false,
  dnsChecks:null as null|DomainCheck[],
  prepareError:'',
  applyErrors:[] as string[],
}));
const candidate={accountId:'a',label:'示例账户',zoneId:'z',status:'active'};
const expiresAt=()=>new Date(Date.now()+300000).toISOString();
function state(){
  return {accounts:[{id:'a',label:'示例账户',zones:[{id:'z',name:'example.com',status:'active'}],zoneCount:1,checkedAt:null,hasResources:true,needsSelftestKey:false}],domains:[],links:[],pools:[],pendingOperations:[],pendingActions:[]};
}
vi.mock('./bridge',()=>({preview:false,errorMessage:(e:unknown)=>e instanceof Error?e.message:String(e),dispatch:async(action:string,payload:Record<string,unknown>={})=>{
  mock.calls.push({action,payload});
  if(action==='get_state')return state();
  if(action==='prepare_domain'){
    if(mock.prepareError)throw new Error(mock.prepareError);
    return {host:payload.input,prefix:payload.prefix,candidates:mock.candidates?[candidate]:[],checks:mock.checks,
      ...(mock.domainPlan?{canApply:true,plan:{id:'domain-plan',title:'添加域名',steps:[],warnings:[],expiresAt:expiresAt()}}:{canApply:false})};
  }
  if(action==='prepare_domain_dns'){
    if(mock.dnsChecks)return {host:payload.input,candidates:[candidate],checks:mock.dnsChecks,dnsStatus:'conflict',actions:[],canApply:false};
    return {host:payload.input,candidates:[candidate],checks:[{label:'DNS',ok:true,level:'pass',message:'可以补一条占位解析'}],dnsStatus:'missing',
      actions:[{kind:'createPlaceholder',recordType:'AAAA',name:payload.input}],canApply:true,plan:{id:'dns-plan',title:'修复 DNS',steps:[],warnings:[],expiresAt:expiresAt()}};
  }
  if(action==='apply_plan'){
    const failure=mock.applyErrors.shift();
    if(failure)throw new Error(failure);
    return state();
  }
  throw new Error(`Unexpected action ${action}`);
}}));

beforeEach(()=>{
  vi.spyOn(HTMLElement.prototype,'getClientRects').mockImplementation(function(this:HTMLElement){return (this.hidden||getComputedStyle(this).display==='none'?[]:[new DOMRect(12,12,120,32)]) as unknown as DOMRectList;});
  Object.assign(mock,{calls:[],checks:[],candidates:true,domainPlan:false,dnsChecks:null,prepareError:'',applyErrors:[]});
});
afterEach(()=>{cleanup();vi.restoreAllMocks();vi.clearAllMocks();});
const calls=(action:string)=>mock.calls.filter(call=>call.action===action);
const pass=(label:string):DomainCheck=>({label,ok:true,level:'pass',message:'可用'});
const fail=(label:string,message:string,reason?:string):DomainCheck=>({label,ok:false,level:'error',message,...(reason?{reason}:{})});
// The probe found no record for the host: only the DNS check fails, so the DNS preparation runs.
const dnsOnly=[pass('域名归属状态'),pass('云端域名归属'),fail('DNS','没有找到这个主机名的网站解析')];

async function check(host='sub.example.com'){
  render(<App/>);
  await screen.findByText('先连接一个域名');
  fireEvent.click(screen.getByRole('button',{name:/^域名管理$/}));
  fireEvent.click(screen.getAllByRole('button',{name:'添加域名'})[0]);
  const dialog=screen.getByRole('dialog',{name:'添加域名'});
  fireEvent.change(within(dialog).getByPlaceholderText('go.example.com'),{target:{value:host}});
  fireEvent.click(within(dialog).getByRole('button',{name:'检查并继续'}));
  return dialog;
}
function tokenButtons(dialog:HTMLElement){
  return TOKEN_BUTTONS.filter(name=>within(dialog).queryByRole('button',{name}));
}

it('offers no token help when the website itself answers 403 on 短链接目录',async()=>{
  mock.checks=[pass('域名归属状态'),pass('云端域名归属'),pass('DNS'),pass('转发规则'),fail('短链接目录',WEBSITE_403)];
  const dialog=await check();
  expect(await within(dialog).findByText(`检查没通过：短链接目录——${WEBSITE_403}`)).toBeTruthy();
  expect(tokenButtons(dialog)).toEqual([]);
});

it('offers no token help when the confirm review fails on the website answering 403',async()=>{
  mock.checks=[pass('短链接目录')];
  mock.domainPlan=true;
  const review=`复核没有通过（短链接目录：${WEBSITE_403}）。云端没有任何改动，请重新检查域名。`;
  mock.applyErrors=[review];
  await check();
  fireEvent.click(await screen.findByRole('button',{name:'确认并执行'}));
  await waitFor(()=>expect(calls('apply_plan')).toHaveLength(1));
  // The plan was used up: the review window (also titled 添加域名) gives way to the form again.
  const dialog=(await screen.findByPlaceholderText('go.example.com')).closest('[role="dialog"]') as HTMLElement;
  await waitFor(()=>expect(within(dialog).getByRole('alert').textContent).toContain(review));
  // Not a DNS-edit refusal either: the website's own 403 gets no "当前授权…" opening.
  expect(within(dialog).getByRole('alert').textContent).not.toContain('当前授权无法修改此域名的解析');
  expect(tokenButtons(dialog)).toEqual([]);
});

it('offers token help without the DNS opening when Cloudflare refuses something that is not a DNS edit',async()=>{
  mock.checks=[pass('短链接目录')];
  mock.domainPlan=true;
  // For example the route write of the add itself.
  mock.applyErrors=[CLOUD_403];
  await check();
  fireEvent.click(await screen.findByRole('button',{name:'确认并执行'}));
  await waitFor(()=>expect(calls('apply_plan')).toHaveLength(1));
  const dialog=(await screen.findByPlaceholderText('go.example.com')).closest('[role="dialog"]') as HTMLElement;
  await waitFor(()=>expect(within(dialog).getByRole('alert').textContent).toContain(CLOUD_403));
  expect(within(dialog).getByRole('alert').textContent).not.toContain('当前授权无法修改此域名的解析');
  expect(tokenButtons(dialog)).toEqual(TOKEN_BUTTONS);
});

it('offers no token help for 域名归属 not found, although the sentence mentions 令牌',async()=>{
  mock.candidates=false;
  mock.checks=[fail('域名归属',NOT_FOUND)];
  const dialog=await check();
  expect(await within(dialog).findByText(`检查没通过：域名归属——${NOT_FOUND}`)).toBeTruthy();
  expect(tokenButtons(dialog)).toEqual([]);
});

it('offers token help when Cloudflare refused a read (cloud_refused)',async()=>{
  mock.checks=[pass('域名归属状态'),fail('云端域名归属',CLOUD_403,'cloud_refused')];
  const dialog=await check();
  expect(await within(dialog).findByText(`检查没通过：云端域名归属——${CLOUD_403}`)).toBeTruthy();
  expect(tokenButtons(dialog)).toEqual(TOKEN_BUTTONS);
});

it('offers token help, not the ownership advice, when this computer cannot use the authorization',async()=>{
  mock.checks=[fail('本机授权',IMPORT_PENDING,'credential')];
  const dialog=await check();
  expect(await within(dialog).findByText(`检查没通过：本机授权——${IMPORT_PENDING}`)).toBeTruthy();
  expect(tokenButtons(dialog)).toEqual(TOKEN_BUTTONS);
  expect(within(dialog).queryByText('新买的域名要先刷新一次，本机才有记录。')).toBeNull();
});

it('offers token help, not the ownership advice, when the DNS preparation hits a credential failure',async()=>{
  mock.checks=dnsOnly;
  mock.dnsChecks=[fail('凭据',KEY_MISSING,'credential')];
  const dialog=await check();
  expect(await within(dialog).findByText(KEY_MISSING)).toBeTruthy();
  expect(calls('prepare_domain_dns')).toHaveLength(1);
  expect(tokenButtons(dialog)).toEqual(TOKEN_BUTTONS);
  expect(within(dialog).queryByText('新买的域名要先刷新一次，本机才有记录。')).toBeNull();
});

it.each([
  [CLOUD_403,TOKEN_BUTTONS],
  // The same advice after HTTP 404 is about the resource, not the token.
  [CLOUD_404,[]],
])('judges a rejected call by its text: %s',async(text,expected)=>{
  mock.prepareError=text;
  const dialog=await check();
  expect(await within(dialog).findByText(text)).toBeTruthy();
  expect(tokenButtons(dialog)).toEqual(expected);
});

it('answers a busy reply with 再试一次 only',async()=>{
  mock.prepareError=BUSY;
  const dialog=await check();
  expect(await within(dialog).findByText(BUSY)).toBeTruthy();
  expect(tokenButtons(dialog)).toEqual([]);
  expect(within(dialog).getByRole('button',{name:'再试一次'})).toBeTruthy();
  expect(within(dialog).queryByRole('alert')).toBeNull();
});

it('keeps the DNS repair plan after a busy reply, so 确认修改并继续检查 can simply be pressed again',async()=>{
  mock.checks=dnsOnly;
  mock.applyErrors=[BUSY];
  await check();
  const review=await screen.findByRole('dialog',{name:'修复 DNS'});
  fireEvent.click(within(review).getByRole('button',{name:'确认修改并继续检查'}));
  await waitFor(()=>expect(calls('apply_plan')).toHaveLength(1));
  // The backend answered busy before it took the plan: the same window stays, with the busy text.
  await waitFor(()=>expect(within(review).getByRole('alert').textContent).toContain(BUSY));
  expect(screen.getByRole('dialog',{name:'修复 DNS'})).toBe(review);
  expect(screen.queryByRole('dialog',{name:'添加域名'})).toBeNull();
  expect(tokenButtons(review)).toEqual([]);
  const again=within(review).getByRole('button',{name:'确认修改并继续检查'}) as HTMLButtonElement;
  expect(again.disabled).toBe(false);
  // Nothing was prepared again.
  expect(calls('prepare_domain')).toHaveLength(1);
  expect(calls('prepare_domain_dns')).toHaveLength(1);
  fireEvent.click(again);
  await waitFor(()=>expect(calls('apply_plan')).toHaveLength(2));
  expect(calls('apply_plan')[1].payload.planId).toBe('dns-plan');
  expect(calls('apply_plan')[0].payload.planId).toBe('dns-plan');
  expect(await screen.findByText('解析设置已提交，正在继续检查域名。')).toBeTruthy();
});
