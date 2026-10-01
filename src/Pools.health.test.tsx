import {cleanup,render,screen,within} from '@testing-library/react';
import {afterEach,expect,it} from 'vitest';
import Pools from './Pools';
import type {Pool,PoolHealth} from './types';

afterEach(()=>cleanup());

it('does not keep an expired target green when the account check itself is recent',()=>{
  const pool:Pool={id:'p',name:'示例地址池',official:{prefix:'https://example.com/path/',suffix:''},candidates:[{id:'c',prefix:'https://example.org/path/',suffix:'',enabled:true}],updated:new Date().toISOString(),accountIds:['a']};
  const report:PoolHealth={poolId:'p',accounts:[{accountId:'a',source:'mainland_provider',checkedAt:new Date().toISOString(),status:'healthy',candidates:[{id:'c',status:'healthy',checkedAt:new Date(Date.now()-7200000).toISOString(),message:'历史检测结果'}]}]};
  render(<Pools pools={[pool]} accounts={[{id:'a',label:'示例账户',zoneCount:1,checkedAt:null,hasResources:true,needsSelftestKey:false}]} linkCount={()=>0} onSave={async()=>true} onDelete={()=>{}} busy={false} health={{p:report}} onCheckHealth={()=>{}} planOpen={false} savedRevision={0}/>);
  expect(screen.getByText('状态未知')).toBeTruthy();
  expect(screen.getByText(/状态未知或已过期/)).toBeTruthy();
  expect(screen.queryByText('各账户检测通过')).toBeNull();
  expect(screen.queryByText('全部目标检测通过')).toBeNull();
});

it('keeps the official address and all ordered mainland targets in one readable platform card',()=>{
  const pool:Pool={id:'p',name:'示例地址池',official:{prefix:'https://example.com/join/',suffix:'?from=short'},candidates:[
    {id:'first',prefix:'https://example.org/primary/',suffix:'',enabled:true},
    {id:'backup',prefix:'https://example.org/backup/',suffix:'?lang=zh',enabled:true},
    {id:'old',prefix:'https://example.org/old/',suffix:'',enabled:false},
  ],updated:'',accountIds:[]};
  render(<Pools pools={[pool]} accounts={[]} linkCount={()=>2} onSave={async()=>true} onDelete={()=>{}} busy={false} health={{}} onCheckHealth={()=>{}} planOpen={false} savedRevision={0}/>);
  const card=screen.getByRole('article',{name:'示例地址池 平台地址'});
  const official=within(card).getByRole('region',{name:'官网链接'});
  expect(official.textContent).toContain('https://example.com/join/邀请码?from=short');
  const mainland=within(card).getByRole('region',{name:'大陆访问地址'});
  expect(mainland.textContent).toContain('https://example.org/primary/邀请码');
  expect(mainland.textContent).toContain('https://example.org/backup/邀请码?lang=zh');
  expect(mainland.textContent).toContain('https://example.org/old/邀请码');
  expect(within(mainland).getByText('首选').compareDocumentPosition(within(mainland).getByText('备用 1'))&Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy();
  expect(within(mainland).getByText('已停用')).toBeTruthy();
  expect((within(card).getByRole('button',{name:'删除'}) as HTMLButtonElement).disabled).toBe(true);
  expect(card.textContent).not.toContain('注册');
});
