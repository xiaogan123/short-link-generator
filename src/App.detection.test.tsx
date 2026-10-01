import {cleanup,fireEvent,render,screen,within} from '@testing-library/react';
import {afterEach,describe,expect,it,vi} from 'vitest';
import App from './App';

const sample=vi.hoisted(()=>({status:'failed' as 'failed'|'unknown'|'passed',message:'HTTP 404'}));
vi.mock('./bridge',()=>({
  preview:false,
  errorMessage:(error:unknown)=>String(error),
  dispatch:async(action:string)=>{
    if(action==='get_state')return {accounts:[{id:'a',label:'示例账户',zoneCount:1,checkedAt:null,hasResources:true,needsSelftestKey:false}],domains:[{id:'d',accountId:'a',zoneId:'z',host:'go.example.com',prefix:'r',routeId:'route'}],links:[{domainId:'d',slug:'sample',cnUrl:'https://example.com/one',defaultUrl:'https://example.org/two',updated:'2026-09-28T00:00:00Z'}],pools:[],pendingOperations:[]};
    if(action==='selftest_link')return {status:'passed',message:'两个地区的跳转均正确。',checks:[]};
    if(action==='check_link_targets'){const checkedAt=new Date().toISOString();return {checkedAt,checks:[{label:'中国大陆目标',status:sample.status,message:sample.message,checkedAt,source:'local',url:'https://example.com/one'},{label:'默认目标',status:'passed',message:'本机请求成功。',checkedAt,source:'local',url:'https://example.org/two'}]};}
    throw new Error(`Unexpected action: ${action}`);
  },
}));

afterEach(()=>cleanup());

describe('visible local detection provenance',()=>{
  it.each([
    {status:'failed' as const,message:'HTTP 404',tone:'red',label:'本机检测发现失败'},
    {status:'unknown' as const,message:'HTTP 403：无法确认',tone:'amber',label:'暂时无法确认'},
    {status:'passed' as const,message:'本机请求成功。',tone:'green',label:'跳转与目标本机检测通过'},
  ])('shows $status with its source and row warning',async({status,message,tone,label})=>{
    sample.status=status;sample.message=message;
    render(<App/>);
    await screen.findByText('/sample');
    fireEvent.click(screen.getByRole('button',{name:'检测 sample'}));
    const dialog=await screen.findByRole('dialog',{name:'链接检测'});
    expect(within(dialog).getAllByText(new RegExp(message)).length).toBeGreaterThan(0);
    expect(within(dialog).getAllByText(/来源：本机网络/)).toHaveLength(2);
    expect(within(dialog).getByText(/VPN、TUN 和网络策略仍会影响结果；未开启大陆监测时不能代表中国大陆网络/)).toBeTruthy();
    fireEvent.click(within(dialog).getByRole('button',{name:'完成'}));
    const row=screen.getByText(label,{exact:false});
    expect(row.classList.contains(`slg-check-${tone}`)).toBe(true);
    const linkRow=row.closest('tr') as HTMLElement;
    fireEvent.click(within(linkRow).getByRole('button',{name:'详情 sample'}));
    const details=linkRow.nextElementSibling as HTMLElement;
    expect(details.textContent).toContain('本机网络');
    expect(details.textContent).toContain('上次检测');
  });
});
