import {act,cleanup,fireEvent,render,screen,within,waitFor} from '@testing-library/react';
import {afterEach,beforeEach,describe,expect,it,vi} from 'vitest';
import App from './App';
const mock=vi.hoisted(()=>({calls:[] as {action:string;payload:any}[], finish:null as null|((value:any)=>void), deferred:false,changed:false,routeFails:false,systemReason:"dns_failed",publicFails:false,privateMixed:false,keyMissing:false,routeThrows:false,systemDeferred:false,routeReason:"virtual_dns_address",domainChange:"",publicThrows:false,systemPasses:false}));
function report(dnsMode='system') {const checkedAt=new Date().toISOString();return {checkedAt,dnsMode,checks:[{label:'官网链接',status:(dnsMode==='public'&&!mock.publicFails)||(dnsMode==='system'&&mock.systemPasses)?'passed':'unknown',message:dnsMode==='public'?(mock.publicFails?'公共查询失败':'当前网络请求成功'):mock.systemPasses?'系统 DNS 目标检查通过':'VPN 返回虚拟地址',reason:dnsMode==='public'?(mock.publicFails?'public_dns_failed':'http_ok'):mock.systemPasses?'http_ok':mock.systemReason,checkedAt,source:'local',url:'https://example.org/target',dnsMode}]};}
vi.mock('./bridge',()=>({preview:false,errorMessage:String,dispatch:async(action:string,payload:any)=>{
  mock.calls.push({action,payload});
  if(action==='get_state')return {accounts:[{id:'a',label:'示例账户',zoneCount:1,checkedAt:null,hasResources:true,needsSelftestKey:false}],domains:[{id:'d',accountId:mock.domainChange==='account'?'b':'a',zoneId:'z',host:mock.domainChange==='host'?'new.example.com':'go.example.com',prefix:mock.domainChange==='prefix'?'changedprefix':'r',routeId:'route'}],links:[{domainId:'d',slug:'sample',cnUrl:'https://example.com/one',defaultUrl:mock.changed?'https://example.org/changed':'https://example.org/two',updated:'2026-09-28T00:00:00Z'}],pools:[],pendingOperations:[]};
  if(action==='selftest_link'&&mock.routeThrows)throw new Error('授权读取失败');
  if(action==='selftest_link')return {status:mock.keyMissing?'key_missing':mock.routeFails&&payload.dnsMode!=='public'?'failed':'passed',message:'两个地区的跳转检查结果。',checks:mock.routeFails&&payload.dnsMode!=='public'?[{label:'跳转',ok:false,message:'路径受阻',reason:mock.routeReason}]:[]};
  if(action==='check_link_targets'){
    if(payload.dnsMode==='public'&&mock.publicThrows)throw new Error('公共查询请求失败');
    if((payload.dnsMode==='public'&&mock.deferred)||(!payload.dnsMode&&mock.systemDeferred))return new Promise(resolve=>{mock.finish=resolve;});
    const result=report(payload.dnsMode);
    if(mock.privateMixed&&!payload.dnsMode)result.checks.push({...result.checks[0],reason:'blocked_non_public_address'});
    return result;
  }
  throw new Error(`Unexpected action: ${action}`);
}}));
beforeEach(()=>{mock.calls=[];mock.deferred=false;mock.finish=null;mock.changed=false;mock.routeFails=false;mock.systemReason="dns_failed";mock.publicFails=false;mock.privateMixed=false;mock.keyMissing=false;mock.routeThrows=false;mock.systemDeferred=false;mock.routeReason="virtual_dns_address";mock.domainChange="";mock.publicThrows=false;mock.systemPasses=false;});
afterEach(cleanup);
async function open(){render(<App/>);await screen.findByText('/sample');fireEvent.click(screen.getByRole('button',{name:'检测 sample'}));return screen.findByRole('dialog',{name:'链接检测'});}
describe('explicit VPN retry',()=>{
 it('uses public DNS only after consent and retries targets without credentials or route checks',async()=>{
   const dialog=await open();expect(mock.calls.filter(c=>c.action==='check_link_targets')[0].payload.dnsMode).toBeUndefined();
   expect(within(dialog).getByText(/只向查询服务发送域名/)).toBeTruthy();
   fireEvent.click(within(dialog).getByRole('button',{name:'兼容 VPN 重试'}));
   await within(dialog).findByText(/当前网络请求成功/);
   expect(within(dialog).getByText('跳转检测通过')).toBeTruthy();
   expect(within(dialog).getByText(/来源：本机网络 · 公共 DNS/)).toBeTruthy();
   expect(mock.calls.filter(c=>c.action==='selftest_link')).toHaveLength(1);
   expect(mock.calls.at(-1)).toEqual({action:'check_link_targets',payload:{domainId:'d',slug:'sample',dnsMode:'public'}});
 });
 it('explicitly retries both checks with public DNS when route checking also failed',async()=>{
   mock.routeFails=true;const dialog=await open();
   fireEvent.click(within(dialog).getByRole('button',{name:'兼容 VPN 重新检测跳转和网站'}));
   const next=await screen.findByRole('dialog',{name:'链接检测'});
   expect(within(next).getByText('跳转检测通过')).toBeTruthy();
   expect(within(next).getByText(/本次跳转检查使用公共 DNS/)).toBeTruthy();
   expect(mock.calls.filter(c=>c.action==='selftest_link').at(-1)?.payload.dnsMode).toBe('public');
   expect(mock.calls.filter(c=>c.action==='check_link_targets').at(-1)?.payload.dnsMode).toBe('public');
 });
 it('ignores a late response after closing and reopening, and prevents duplicate retries',async()=>{
   const dialog=await open();mock.deferred=true;
   const retry=within(dialog).getByRole('button',{name:'兼容 VPN 重试'});fireEvent.click(retry);fireEvent.click(retry);
   expect(mock.calls.filter(c=>c.payload?.dnsMode==='public')).toHaveLength(1);
   const finish=mock.finish!;fireEvent.click(within(dialog).getByRole('button',{name:'完成'}));
   fireEvent.click(screen.getByRole('button',{name:'检测 sample'}));
   const next=await screen.findByRole('dialog',{name:'链接检测'});
   await act(async()=>finish(report('public')));
   expect(within(next).queryByText(/当前网络请求成功/)).toBeNull();
   expect(within(next).getByText(/VPN 返回虚拟地址/)).toBeTruthy();
 });
 it('discards a public result when link settings changed while checking',async()=>{
   const dialog=await open();mock.deferred=true;fireEvent.click(within(dialog).getByRole('button',{name:'兼容 VPN 重试'}));
   mock.changed=true;fireEvent.click(screen.getByRole('button',{name:'刷新数据'}));
   await waitFor(()=>expect(mock.calls.filter(c=>c.action==='get_state')).toHaveLength(2));
   await act(async()=>mock.finish!(report('public')));
   expect(screen.queryByRole('dialog',{name:'链接检测'})).toBeNull();
   expect(screen.getByText('链接或平台地址已变化，请重新检测。')).toBeTruthy();
 });
});

describe('automatic typed virtual DNS retry',()=>{
 it('retries route and targets once in a fresh session, and remembers only the successful domain mode',async()=>{
   mock.systemReason='virtual_dns_address';mock.routeFails=true;
   const dialog=await open();
   expect(within(dialog).getByText(/本次已自动使用公共 DNS 重查一次/)).toBeTruthy();
   expect(within(dialog).getByText('跳转检测通过')).toBeTruthy();
   expect(mock.calls.filter(c=>c.action==='selftest_link').map(c=>c.payload.dnsMode)).toEqual([undefined,'public']);
   expect(mock.calls.filter(c=>c.action==='check_link_targets').map(c=>c.payload.dnsMode)).toEqual([undefined,'public']);
   fireEvent.click(within(dialog).getByRole('button',{name:'完成'}));
   fireEvent.click(screen.getByRole('button',{name:'检测 sample'}));
   await screen.findByRole('dialog',{name:'链接检测'});
   expect(mock.calls.filter(c=>c.action==='selftest_link').map(c=>c.payload.dnsMode)).toEqual([undefined,'public','public']);
 });
 it('keeps a public failure visible and does not loop',async()=>{
   mock.systemReason='virtual_dns_address';mock.publicFails=true;
   const dialog=await open();
   expect(within(dialog).getByText(/公共查询失败/)).toBeTruthy();
   expect(mock.calls.filter(c=>c.action==='check_link_targets')).toHaveLength(2);
 });
 it('does not fallback when the targets include a private-address blocker',async()=>{
   mock.systemReason='virtual_dns_address';mock.privateMixed=true;
   const dialog=await open();
   expect(within(dialog).queryByText(/本次已自动使用公共 DNS/)).toBeNull();
   expect(mock.calls.filter(c=>c.action==='check_link_targets')).toHaveLength(1);
 });
 it('only retries anonymous targets when the route reports a missing key',async()=>{
   mock.systemReason='virtual_dns_address';mock.keyMissing=true;
   const dialog=await open();
   expect(within(dialog).getByText('检测密钥缺失')).toBeTruthy();
   expect(within(dialog).queryByText(/本次跳转检查使用公共 DNS/)).toBeNull();
   expect(mock.calls.filter(c=>c.action==='selftest_link')).toHaveLength(1);
   expect(mock.calls.filter(c=>c.action==='check_link_targets')).toHaveLength(2);
   expect(within(dialog).getByText(/来源：本机网络 · 公共 DNS/)).toBeTruthy();
 });
 it('does not repeat a rejected route or credential operation',async()=>{
   mock.systemReason='virtual_dns_address';mock.routeThrows=true;
   const dialog=await open();
   expect(within(dialog).getByText(/授权读取失败/)).toBeTruthy();
   expect(mock.calls.filter(c=>c.action==='selftest_link')).toHaveLength(1);
   expect(mock.calls.filter(c=>c.action==='check_link_targets')).toHaveLength(1);
 });
 it.each(['system','public'])('discards a cancelled %s result and prevents duplicate in-flight requests',async mode=>{
   mock.systemReason='virtual_dns_address';mock.deferred=mode==='public';mock.systemDeferred=mode==='system';
   render(<App/>);await screen.findByText('/sample');
   const button=screen.getByRole('button',{name:'检测 sample'});
   fireEvent.click(button);fireEvent.click(button);
   await waitFor(()=>expect(mock.finish).toBeTypeOf('function'));
   const before=mock.calls.filter(c=>c.action==='check_link_targets').length;
   expect(before).toBe(mode==='public'?2:1);
   fireEvent.click(screen.getByRole('button',{name:'取消等待'}));
   fireEvent.click(button);
   expect(mock.calls.filter(c=>c.action==='check_link_targets')).toHaveLength(before);
   await act(async()=>mock.finish!(report(mode)));
   expect(screen.queryByRole('dialog',{name:'链接检测'})).toBeNull();
   expect(mock.calls.filter(c=>c.action==='check_link_targets')).toHaveLength(before);
 });
 it('ignores an automatic retry if the saved link changes before completion',async()=>{
   mock.systemReason='virtual_dns_address';mock.deferred=true;
   render(<App/>);await screen.findByText('/sample');fireEvent.click(screen.getByRole('button',{name:'检测 sample'}));
   await waitFor(()=>expect(mock.finish).toBeTypeOf('function'));
   mock.changed=true;fireEvent.click(screen.getByRole('button',{name:'刷新数据'}));
   await waitFor(()=>expect(mock.calls.filter(c=>c.action==='get_state')).toHaveLength(2));
   await act(async()=>mock.finish!(report('public')));
   expect(screen.queryByRole('dialog',{name:'链接检测'})).toBeNull();
   expect(screen.getByText('链接或平台地址已变化，请重新检测。')).toBeTruthy();
 });
});

it('does not automatically retry a typed result after unmount',async()=>{
  mock.systemReason='virtual_dns_address';mock.systemDeferred=true;
  render(<App/>);await screen.findByText('/sample');fireEvent.click(screen.getByRole('button',{name:'检测 sample'}));
  await waitFor(()=>expect(mock.finish).toBeTypeOf('function'));
  cleanup();await act(async()=>mock.finish!(report('system')));
  expect(mock.calls.filter(c=>c.action==='check_link_targets')).toHaveLength(1);
});

it.each(['blocked_non_public_address','dns_failed','http_blocked',''])('does not automatically retry when the route has a non-virtual blocker: %s',async reason=>{
  mock.systemReason='virtual_dns_address';mock.routeFails=true;mock.routeReason=reason;
  const dialog=await open();
  expect(within(dialog).getByText('跳转检测失败')).toBeTruthy();
  expect(within(dialog).queryByText(/本次已自动使用公共 DNS/)).toBeNull();
  expect(mock.calls.filter(c=>c.action==='selftest_link')).toHaveLength(1);
  expect(mock.calls.filter(c=>c.action==='check_link_targets')).toHaveLength(1);
});

it.each(['host','account','prefix'])('rejects a late automatic response after domain %s changes',async field=>{
  mock.systemReason='virtual_dns_address';mock.deferred=true;
  render(<App/>);await screen.findByText('/sample');fireEvent.click(screen.getByRole('button',{name:'检测 sample'}));
  await waitFor(()=>expect(mock.finish).toBeTypeOf('function'));
  mock.domainChange=field;fireEvent.click(screen.getByRole('button',{name:'刷新数据'}));
  await waitFor(()=>expect(mock.calls.filter(c=>c.action==='get_state')).toHaveLength(2));
  await act(async()=>mock.finish!(report('public')));
  expect(screen.queryByRole('dialog',{name:'链接检测'})).toBeNull();
  expect(screen.getByText('链接或平台地址已变化，请重新检测。')).toBeTruthy();
});

it('keeps public failure provenance for a target-only retry with a missing key',async()=>{
  mock.systemReason='virtual_dns_address';mock.keyMissing=true;mock.publicThrows=true;
  const dialog=await open();
  expect(within(dialog).getByText('检测密钥缺失')).toBeTruthy();
  expect(within(dialog).getByText(/公共查询请求失败/)).toBeTruthy();
  expect(within(dialog).getByText(/来源：本机网络 · 公共 DNS/)).toBeTruthy();
  expect(within(dialog).queryByText(/本次跳转检查使用公共 DNS/)).toBeNull();
  expect(mock.calls.filter(c=>c.action==='selftest_link')).toHaveLength(1);
  expect(mock.calls.filter(c=>c.action==='check_link_targets')).toHaveLength(2);
});

it('automatically retries a route-only virtual address when all targets already pass',async()=>{
  mock.routeFails=true;mock.systemPasses=true;
  const dialog=await open();
  expect(within(dialog).getByText('跳转检测通过')).toBeTruthy();
  expect(within(dialog).getByText(/本次已自动使用公共 DNS 重查一次/)).toBeTruthy();
  expect(within(dialog).getByText(/本次跳转检查使用公共 DNS/)).toBeTruthy();
  expect(within(dialog).getByText(/来源：本机网络 · 公共 DNS/)).toBeTruthy();
  expect(mock.calls.filter(c=>c.action==='selftest_link').map(c=>c.payload.dnsMode)).toEqual([undefined,'public']);
  expect(mock.calls.filter(c=>c.action==='check_link_targets').map(c=>c.payload.dnsMode)).toEqual([undefined,'public']);
});

it.each(['blocked_non_public_address','dns_failed','http_blocked'])('does not retry a virtual route when a target reports %s',async reason=>{
  mock.routeFails=true;mock.systemReason=reason;
  const dialog=await open();
  expect(within(dialog).getByText('跳转检测失败')).toBeTruthy();
  expect(within(dialog).queryByText(/本次已自动使用公共 DNS/)).toBeNull();
  expect(mock.calls.filter(c=>c.action==='selftest_link')).toHaveLength(1);
  expect(mock.calls.filter(c=>c.action==='check_link_targets')).toHaveLength(1);
});

it('does not retry missing-key reads or successful targets based on route-only virtual metadata',async()=>{
  mock.keyMissing=true;mock.routeFails=true;mock.systemPasses=true;
  const dialog=await open();
  expect(within(dialog).getByText('检测密钥缺失')).toBeTruthy();
  expect(within(dialog).getByText(/系统 DNS 目标检查通过/)).toBeTruthy();
  expect(within(dialog).queryByText(/本次已自动使用公共 DNS/)).toBeNull();
  expect(mock.calls.filter(c=>c.action==='selftest_link')).toHaveLength(1);
  expect(mock.calls.filter(c=>c.action==='check_link_targets')).toHaveLength(1);
});
