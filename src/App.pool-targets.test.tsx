import {cleanup,fireEvent,render,screen,within} from '@testing-library/react';
import {afterEach,expect,it,vi} from 'vitest';
import App from './App';

const pool={
  id:'pool-global',name:'示例平台',
  official:{prefix:'https://example.com/register?code=',suffix:'&from=short-link'},
  candidates:[
    {id:'first',prefix:'https://example.org/mainland/primary/',suffix:'',enabled:true},
    {id:'backup',prefix:'https://example.org/mainland/backup/',suffix:'?source=demo',enabled:true},
    {id:'disabled',prefix:'https://example.org/mainland/disabled/',suffix:'',enabled:false},
  ],
  updated:'2026-09-30T00:00:00Z',accountIds:['account-a'],
};
const state={
  accounts:[{id:'account-a',label:'示例账户',zoneCount:1,checkedAt:null,hasResources:true,needsSelftestKey:false}],
  domains:[{id:'domain-a',accountId:'account-a',zoneId:'zone-a',host:'go.example.com',prefix:'r',routeId:'route-a'}],
  links:[
    {domainId:'domain-a',slug:'platform-one',cnUrl:'https://stale.example/cn-one',defaultUrl:'https://stale.example/default-one',updated:'2026-09-30T00:00:00Z',poolId:'pool-global',code:'DEMO'},
    {domainId:'domain-a',slug:'platform-two',cnUrl:'https://stale.example/cn-two',defaultUrl:'https://stale.example/default-two',updated:'2026-09-30T00:00:00Z',poolId:'pool-global',code:'DEMO_2'},
    {domainId:'domain-a',slug:'manual',cnUrl:'https://example.com/manual-cn',defaultUrl:'https://example.org/manual-default',updated:'2026-09-30T00:00:00Z'},
  ],
  pools:[pool],pendingOperations:[],pendingActions:[],
};

vi.mock('./bridge',()=>({
  preview:true,
  errorMessage:(error:unknown)=>String(error),
  dispatch:async(action:string)=>{
    if(action==='get_state')return state;
    throw new Error(`Unexpected action ${action}`);
  },
}));

afterEach(cleanup);

it('finds a platform link by its own invitation code and keeps the other links out of the result',async()=>{
  render(<App/>);
  await screen.findByRole('heading',{name:'短链接'});
  fireEvent.change(screen.getByRole('textbox',{name:'搜索链接'}),{target:{value:'DEMO_2'}});
  expect(screen.getByText('/platform-two')).toBeTruthy();
  expect(screen.queryByText('/platform-one')).toBeNull();
  expect(screen.queryByText('/manual')).toBeNull();
});

it('shows the platform official target and expands every mainland template with each link own code',async()=>{
  render(<App/>);
  await screen.findByRole('heading',{name:'短链接'});
  const first=screen.getByText('/platform-one').closest('tr') as HTMLElement;
  fireEvent.click(within(first).getByRole('button',{name:'详情 platform-one'}));
  expect(within(first).getByRole('button',{name:'详情 platform-one'}).getAttribute('aria-expanded')).toBe('true');
  const firstDetails=document.getElementById(within(first).getByRole('button',{name:'详情 platform-one'}).getAttribute('aria-controls')!) as HTMLElement;
  expect(within(firstDetails).getByText('官网链接')).toBeTruthy();
  expect(firstDetails.textContent).toContain('https://example.com/register?code=DEMO&from=short-link');
  expect(firstDetails.textContent).not.toContain('https://stale.example/cn-one');
  fireEvent.click(within(firstDetails).getByText('大陆地址 · 已启用 2 个'));
  expect(firstDetails.textContent).toContain('https://example.org/mainland/primary/DEMO');
  expect(firstDetails.textContent).toContain('https://example.org/mainland/backup/DEMO?source=demo');
  expect(firstDetails.textContent).toContain('备用 2');
  expect(within(firstDetails).getByText('已停用')).toBeTruthy();
  const longTarget=within(firstDetails).getByTitle('https://example.org/mainland/backup/DEMO?source=demo');
  expect(longTarget.closest('.slg-candidate-list')).toBeTruthy();

  const second=screen.getByText('/platform-two').closest('tr') as HTMLElement;
  fireEvent.click(within(second).getByRole('button',{name:'详情 platform-two'}));
  const secondDetails=document.getElementById(within(second).getByRole('button',{name:'详情 platform-two'}).getAttribute('aria-controls')!) as HTMLElement;
  fireEvent.click(within(secondDetails).getByText('大陆地址 · 已启用 2 个'));
  expect(secondDetails.textContent).toContain('https://example.org/mainland/primary/DEMO_2');
  expect(secondDetails.textContent).not.toContain('https://example.org/mainland/primary/DEMO ');

  const manual=screen.getByText('/manual').closest('tr') as HTMLElement;
  fireEvent.click(within(manual).getByRole('button',{name:'详情 manual'}));
  const manualDetails=document.getElementById(within(manual).getByRole('button',{name:'详情 manual'}).getAttribute('aria-controls')!) as HTMLElement;
  expect(manualDetails.textContent).toContain('大陆');
  expect(manualDetails.textContent).toContain('https://example.com/manual-cn');
  expect(manualDetails.textContent).toContain('其他地区');
  expect(manualDetails.textContent).toContain('https://example.org/manual-default');
});
