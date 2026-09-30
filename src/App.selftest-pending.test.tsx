import {cleanup,fireEvent,render,screen,waitFor,within} from '@testing-library/react';
import {afterEach,expect,it,vi} from 'vitest';
import App from './App';

const control=vi.hoisted(()=>({
  calls:[] as {action:string;payload:Record<string,unknown>}[],
  applyFails:false,
}));

const state=()=>({
  accounts:[{id:'account-a',label:'示例账户',zoneCount:1,checkedAt:null,hasResources:true,needsSelftestKey:true}],
  domains:[],links:[],pools:[],pendingOperations:['自检密钥操作待确认'],
  pendingActions:[
    {kind:'resume_selftest_rotation',poolId:null,accountId:'account-a',label:'继续恢复自检密钥'},
    {kind:'recover_selftest_rotation',poolId:null,accountId:'account-a',label:'恢复旧版自检密钥操作'},
    {kind:'resume_selftest_rotation',poolId:null,accountId:null,label:'缺少账户的密钥修复'},
  ],
});

vi.mock('./bridge',()=>({
  preview:true,
  errorMessage:(error:unknown)=>String(error),
  dispatch:async(action:string,payload:Record<string,unknown>={})=>{
    control.calls.push({action,payload});
    if(action==='get_state')return state();
    if(action==='prepare_change')return {
      id:`plan-${payload.kind}`,
      title:payload.kind==='resume_selftest_rotation'?'恢复自检密钥轮换':'恢复旧版自检密钥操作',
      steps:['先复核账户与云端状态','确认后继续修复'],
      warnings:['不会在后台自动重试'],
      expiresAt:new Date(Date.now()+300000).toISOString(),
    };
    if(action==='apply_plan'){
      if(control.applyFails)throw new Error('密钥修复仍未完成');
      return state();
    }
    throw new Error(`Unexpected action ${action}`);
  },
}));

afterEach(()=>{cleanup();control.calls.length=0;control.applyFails=false;});

it('opens both selftest recovery kinds through the ordinary confirmation plan and cancel does not apply',async()=>{
  render(<App/>);
  const pending=await screen.findByRole('region',{name:'可继续的变更'});
  expect(within(pending).getByText(/不会在后台自动重试/)).toBeTruthy();
  fireEvent.click(within(pending).getAllByRole('button',{name:'继续修复'})[0]);
  let review=await screen.findByRole('dialog',{name:'恢复自检密钥轮换'});
  expect(within(review).getByText('账户：示例账户')).toBeTruthy();
  expect(control.calls.some(call=>call.action==='prepare_change'&&call.payload.kind==='resume_selftest_rotation'&&call.payload.accountId==='account-a')).toBe(true);
  expect(control.calls.some(call=>call.action==='resume_selftest_rotation')).toBe(false);
  fireEvent.click(within(review).getByRole('button',{name:'返回'}));
  expect(control.calls.some(call=>call.action==='apply_plan')).toBe(false);
  fireEvent.click(within(pending).getByRole('button',{name:'查看修复计划'}));
  review=await screen.findByRole('dialog',{name:'恢复旧版自检密钥操作'});
  expect(control.calls.some(call=>call.action==='prepare_change'&&call.payload.kind==='recover_selftest_rotation'&&call.payload.accountId==='account-a')).toBe(true);
  expect(control.calls.some(call=>call.action==='recover_selftest_rotation')).toBe(false);
  fireEvent.click(within(review).getByRole('button',{name:'返回'}));
});

it('keeps the recovery entry after apply failure without retrying automatically and disables a missing account',async()=>{
  control.applyFails=true;
  render(<App/>);
  let pending=await screen.findByRole('region',{name:'可继续的变更'});
  const incomplete=within(pending).getByText('缺少账户的密钥修复').closest('.pending-action');
  expect((within(incomplete as HTMLElement).getByRole('button',{name:'继续修复'}) as HTMLButtonElement).disabled).toBe(true);
  fireEvent.click(within(pending).getAllByRole('button',{name:'继续修复'})[0]);
  fireEvent.click(within(await screen.findByRole('dialog',{name:'恢复自检密钥轮换'})).getByRole('button',{name:'确认并执行'}));
  pending=await screen.findByRole('region',{name:'可继续的变更'});
  expect(within(pending).getByText('继续恢复自检密钥')).toBeTruthy();
  expect(screen.getByRole('alert').textContent).toContain('密钥修复仍未完成');
  expect(control.calls.filter(call=>call.action==='apply_plan')).toHaveLength(1);
  await waitFor(()=>expect(control.calls.filter(call=>call.action==='prepare_change'&&call.payload.kind==='resume_selftest_rotation')).toHaveLength(1));
});
