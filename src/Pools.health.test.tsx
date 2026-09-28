import {cleanup,render,screen} from '@testing-library/react';
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
