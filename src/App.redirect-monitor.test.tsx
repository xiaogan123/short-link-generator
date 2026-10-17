import {cleanup,fireEvent,render,screen,within} from '@testing-library/react';
import {afterEach,expect,it,vi} from 'vitest';
import App from './App';

const calls=vi.hoisted(()=>({redirect:0}));
vi.mock('./bridge',()=>({
  preview:false,
  errorMessage:(error:unknown)=>String(error),
  dispatch:async(action:string)=>{
    if(action==='get_state')return {accounts:[{id:'a',label:'示例账户',zoneCount:1,checkedAt:null,hasResources:true,needsSelftestKey:false}],domains:[{id:'d',accountId:'a',zoneId:'z',host:'go.example.com',prefix:'r',routeId:'route'}],links:[{domainId:'d',slug:'sample',cnUrl:'https://example.com/one',defaultUrl:'https://example.org/two',updated:'2026-10-17T00:00:00Z'}],pools:[],pendingOperations:[],pendingActions:[]};
    if(action==='check_link_redirect'){calls.redirect++;return {status:'failed',message:'首跳位置不符',reason:'location_mismatch',checkedAt:new Date().toISOString(),dnsMode:'system'};}
    throw new Error(`Unexpected action: ${action}`);
  },
}));
afterEach(()=>{cleanup();localStorage.clear();calls.redirect=0;});

it('keeps automatic result separate from manual detection and clears hidden filters from the global banner',async()=>{
  localStorage.clear();
  render(<App/>);
  const row=await screen.findByRole('row',{name:'https://go.example.com/r/sample'});
  expect(calls.redirect).toBe(0);
  fireEvent.click(screen.getByRole('checkbox',{name:/未开启/}));
  expect(await within(row).findByText('待复查')).toBeTruthy();
  expect(within(row).getByText('自动')).toBeTruthy();
  expect(within(row).getByText('手动')).toBeTruthy();
  expect(within(row).getByText('上次巡检',{exact:false})).toBeTruthy();
  expect(within(row).getByText('未检测')).toBeTruthy();
  fireEvent.change(screen.getByRole('textbox',{name:'搜索链接'}),{target:{value:'not-present'}});
  expect(screen.queryByRole('row',{name:'https://go.example.com/r/sample'})).toBeNull();
  fireEvent.click(screen.getByRole('button',{name:'查看需关注'}));
  expect(screen.getByRole('row',{name:'https://go.example.com/r/sample'})).toBeTruthy();
  expect((screen.getByRole('textbox',{name:'搜索链接'}) as HTMLInputElement).value).toBe('');
  expect(screen.getByRole('button',{name:'只看需关注'}).getAttribute('aria-pressed')).toBe('true');
  fireEvent.click(screen.getByRole('checkbox',{name:/已开启/}));
  expect(screen.getByRole('row',{name:'https://go.example.com/r/sample'})).toBeTruthy();
  expect(screen.getByRole('button',{name:'只看需关注'}).getAttribute('aria-pressed')).toBe('false');
});
