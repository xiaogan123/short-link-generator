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

it('shows the platform official target and expands every mainland template with each link own code',async()=>{
  render(<App/>);
  await screen.findByRole('heading',{name:'短链接'});
  const first=screen.getByText('/platform-one').closest('tr') as HTMLElement;
  expect(within(first).getByText('官网链接')).toBeTruthy();
  expect(first.textContent).toContain('https://example.com/register?code=DEMO&from=short-link');
  expect(first.textContent).not.toContain('https://stale.example/cn-one');
  expect(within(first).getByText('大陆地址 · 已启用 2 个')).toBeTruthy();
  fireEvent.click(within(first).getByText('大陆地址 · 已启用 2 个'));
  expect(first.textContent).toContain('https://example.org/mainland/primary/DEMO');
  expect(first.textContent).toContain('https://example.org/mainland/backup/DEMO?source=demo');
  expect(first.textContent).toContain('备用 2（已停用）');
  const longTarget=within(first).getByTitle('https://example.org/mainland/backup/DEMO?source=demo');
  expect(longTarget.closest('.pool-health-row')).toBeTruthy();

  const second=screen.getByText('/platform-two').closest('tr') as HTMLElement;
  fireEvent.click(within(second).getByText('大陆地址 · 已启用 2 个'));
  expect(second.textContent).toContain('https://example.org/mainland/primary/DEMO_2');
  expect(second.textContent).not.toContain('https://example.org/mainland/primary/DEMO ');

  const manual=screen.getByText('/manual').closest('tr') as HTMLElement;
  expect(manual.textContent).toContain('大陆');
  expect(manual.textContent).toContain('https://example.com/manual-cn');
  expect(manual.textContent).toContain('其他地区');
  expect(manual.textContent).toContain('https://example.org/manual-default');
});
