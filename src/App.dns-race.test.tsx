import {act,cleanup,fireEvent,render,screen,waitFor,within} from '@testing-library/react';
import {afterEach,expect,it,vi} from 'vitest';
import App from './App';

const control=vi.hoisted(()=>({calls:[] as {action:string;payload:Record<string,unknown>}[],resolveApply:null as null|((value:unknown)=>void),dnsReady:false,domainReady:false}));
const state={accounts:[{id:'a',label:'示例账户',zones:[{id:'z',name:'example.com',status:'active'}],zoneCount:1,checkedAt:null,hasResources:true,needsSelftestKey:false}],domains:[],links:[],pools:[],pendingOperations:['本机记录待刷新'],pendingActions:[]};
vi.mock('./bridge',()=>({preview:false,errorMessage:(error:unknown)=>String(error),dispatch:async(action:string,payload:Record<string,unknown>={})=>{
  control.calls.push({action,payload});
  if(action==='get_state')return state;
  if(action==='prepare_domain')return {host:payload.input,prefix:payload.prefix,candidates:[{accountId:'a',label:'示例账户',zoneId:'z',status:'active'}],checks:[{label:'DNS',ok:control.domainReady,level:control.domainReady?'pass':'error',message:'示例检查'}],canApply:control.domainReady,...(control.domainReady?{plan:{id:'domain',title:'添加域名',steps:[],warnings:[],expiresAt:new Date(Date.now()+300000).toISOString()}}:{})};
  if(action==='prepare_domain_dns')return control.dnsReady ? {host:payload.input,candidates:[],checks:[{label:'DNS 与代理',ok:true,level:'pass',message:'已就绪'}],dnsStatus:'ready',actions:[],canApply:false} : {host:payload.input,candidates:[],checks:[],dnsStatus:'missing',actions:[{kind:'createPlaceholder',recordType:'AAAA',name:payload.input}],canApply:true,plan:{id:'dns',title:'修复 DNS',steps:[],warnings:[],expiresAt:new Date(Date.now()+300000).toISOString()}};
  if(action==='apply_plan')return new Promise(resolve=>{control.resolveApply=resolve;});
  throw new Error(`Unexpected ${action}`);
}}));

afterEach(()=>{cleanup();control.calls.length=0;control.resolveApply=null;control.dnsReady=false;control.domainReady=false;});

it('keeps a DNS repair plan open while applying, so its late result cannot prepare another host',async()=>{
  render(<App/>); await screen.findByText('先连接一个域名');
  fireEvent.click(screen.getByRole('button',{name:/^域名管理$/}));
  fireEvent.click(screen.getAllByRole('button',{name:'添加域名'})[0]);
  const form=screen.getByRole('dialog',{name:'添加域名'});
  fireEvent.change(within(form).getByPlaceholderText('go.example.com'),{target:{value:'old.example.com'}});
  fireEvent.click(within(form).getByRole('button',{name:'检查并接入'}));
  fireEvent.click(await within(form).findByRole('button',{name:'检查并补齐网站解析'}));
  fireEvent.click(await within(form).findByRole('button',{name:'补齐解析并继续'}));
  const plan=screen.getByRole('dialog',{name:'修复 DNS'});
  fireEvent.click(within(plan).getByRole('button',{name:'确认修改并继续检查'}));
  await waitFor(()=>expect(control.resolveApply).toBeTypeOf('function'));
  fireEvent.keyDown(document,{key:'Escape'});
  fireEvent.mouseDown(plan.parentElement!);
  fireEvent.click(within(plan).getByRole('button',{name:'返回'}));
  expect(screen.getByRole('dialog',{name:'修复 DNS'})).toBeTruthy();
  expect(screen.queryByRole('dialog',{name:'添加域名'})).toBeNull();
  control.domainReady=true;
  await act(async()=>{control.resolveApply!(state);});
  expect(await screen.findByText('解析设置已提交，正在继续检查域名。')).toBeTruthy();
  const reopened=await screen.findByRole('dialog',{name:'添加域名'});
  expect((within(reopened).getByPlaceholderText('go.example.com') as HTMLInputElement).value).toBe('old.example.com');
  expect(control.calls.filter(call=>call.action==='prepare_domain').at(-1)?.payload.input).toBe('old.example.com');
});

it('shows ready DNS as a pass and refreshes local state without applying a domain plan',async()=>{
  control.dnsReady=true;
  render(<App/>); await screen.findByText('先连接一个域名');
  fireEvent.click(screen.getByRole('button',{name:/^域名管理$/}));
  fireEvent.click(screen.getAllByRole('button',{name:'添加域名'})[0]);
  const form=screen.getByRole('dialog',{name:'添加域名'});
  fireEvent.change(within(form).getByPlaceholderText('go.example.com'),{target:{value:'ready.example.com'}});
  fireEvent.click(within(form).getByRole('button',{name:'检查并接入'}));
  fireEvent.click(await within(form).findByRole('button',{name:'检查 DNS 与代理'}));
  expect(await within(form).findByText('网站解析已就绪')).toBeTruthy();
  expect(control.calls.filter(call=>call.action==='get_state').length).toBeGreaterThan(1);
  expect(within(form).queryByRole('button',{name:/查看.*计划/})).toBeNull();
});

it('refreshes cached zones after a DNS result that still needs repair',async()=>{
  render(<App/>); await screen.findByText('先连接一个域名');
  fireEvent.click(screen.getByRole('button',{name:/^域名管理$/}));
  fireEvent.click(screen.getAllByRole('button',{name:'添加域名'})[0]);
  const form=screen.getByRole('dialog',{name:'添加域名'});
  fireEvent.change(within(form).getByPlaceholderText('go.example.com'),{target:{value:'repair.example.com'}});
  fireEvent.click(within(form).getByRole('button',{name:'检查并接入'}));
  fireEvent.click(await within(form).findByRole('button',{name:'检查 DNS 与代理'}));
  expect(await within(form).findByText('需要补齐网站解析')).toBeTruthy();
  expect(control.calls.filter(call=>call.action==='get_state').length).toBeGreaterThan(2);
});
