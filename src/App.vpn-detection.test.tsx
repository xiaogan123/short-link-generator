import {act,cleanup,fireEvent,render,screen,within,waitFor} from '@testing-library/react';
import {afterEach,beforeEach,describe,expect,it,vi} from 'vitest';
import App from './App';
const mock=vi.hoisted(()=>({calls:[] as {action:string;payload:any}[], finish:null as null|((value:any)=>void), deferred:false,changed:false,routeFails:false}));
function report(dnsMode='system') {const checkedAt=new Date().toISOString();return {checkedAt,dnsMode,checks:[{label:'官网链接',status:dnsMode==='public'?'passed':'unknown',message:dnsMode==='public'?'当前网络请求成功':'VPN 返回虚拟地址',reason:dnsMode==='public'?'http_ok':'virtual_dns_address',checkedAt,source:'local',url:'https://example.org/target',dnsMode}]};}
vi.mock('./bridge',()=>({preview:false,errorMessage:String,dispatch:async(action:string,payload:any)=>{
  mock.calls.push({action,payload});
  if(action==='get_state')return {accounts:[{id:'a',label:'示例账户',zoneCount:1,checkedAt:null,hasResources:true,needsSelftestKey:false}],domains:[{id:'d',accountId:'a',zoneId:'z',host:'go.example.com',prefix:'r',routeId:'route'}],links:[{domainId:'d',slug:'sample',cnUrl:'https://example.com/one',defaultUrl:mock.changed?'https://example.org/changed':'https://example.org/two',updated:'2026-09-28T00:00:00Z'}],pools:[],pendingOperations:[]};
  if(action==='selftest_link')return {status:mock.routeFails&&payload.dnsMode!=='public'?'failed':'passed',message:'两个地区的跳转均正确。',checks:[]};
  if(action==='check_link_targets'){
    if(payload.dnsMode==='public'&&mock.deferred)return new Promise(resolve=>{mock.finish=resolve;});
    return report(payload.dnsMode);
  }
  throw new Error(`Unexpected action: ${action}`);
}}));
beforeEach(()=>{mock.calls=[];mock.deferred=false;mock.finish=null;mock.changed=false;mock.routeFails=false;});
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
