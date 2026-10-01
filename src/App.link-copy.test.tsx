import {cleanup,fireEvent,render,screen,waitFor,within} from '@testing-library/react';
import {afterEach,expect,it,vi} from 'vitest';
import App from './App';

const calls=vi.hoisted(()=>[] as {action:string;payload:Record<string,unknown>}[]);
vi.mock('./bridge',()=>({preview:false,errorMessage:(e:unknown)=>String(e),dispatch:async(action:string,payload:Record<string,unknown>={})=>{
  calls.push({action,payload});
  if(action==='get_state')return {accounts:[{id:'a',label:'示例账户',zoneCount:1,hasResources:true,needsSelftestKey:false}],domains:[{id:'d',accountId:'a',zoneId:'z',host:'go.example.com',prefix:'r',routeId:'route'}],links:[{domainId:'d',slug:'manual',cnUrl:'https://example.com/cn',defaultUrl:'https://example.org/en',updated:''},{domainId:'d',slug:'platform',poolId:'p',code:'DEMO123',cnUrl:'https://example.com/join/DEMO123',defaultUrl:'https://example.org/join/DEMO123',updated:''}],pools:[{id:'p',name:'示例平台',official:{prefix:'https://example.org/join/',suffix:''},candidates:[{id:'c',prefix:'https://example.com/join/',suffix:'',enabled:true}],accountIds:['a'],updated:''}],pendingOperations:[],pendingActions:[]};
  if(action==='prepare_change')return {id:'plan',title:'另存为新链接',steps:['保留已有链接，创建新链接'],warnings:[],expiresAt:new Date(Date.now()+300000).toISOString()};
  throw Error(`Unexpected ${action}`);
}}));
afterEach(()=>{cleanup();calls.length=0;});
async function edit(slug:string){
  render(<App/>);
  fireEvent.click(await screen.findByRole('button',{name:`编辑 ${slug}`}));
  return screen.getByRole('dialog',{name:'编辑短链接'});
}

it.each(['manual','platform'])('creates a separate new name with the current %s settings and an explicit old-link notice',async(slug)=>{
  const editor=await edit(slug);
  expect((within(editor).getByPlaceholderText('例如 welcome') as HTMLInputElement).disabled).toBe(true);
  fireEvent.click(within(editor).getByRole('button',{name:'换一个名称'}));
  const copy=screen.getByRole('dialog',{name:'使用新名称创建链接'});
  const name=within(copy).getByPlaceholderText('例如 welcome') as HTMLInputElement;
  expect(name.disabled).toBe(false);
  expect(name.value).toBe('');
  expect(document.activeElement).toBe(name);
  expect(within(copy).getByRole('status').textContent).toContain(`旧链接 /${slug} 会继续保留`);
  fireEvent.change(name,{target:{value:'new-name'}});
  fireEvent.submit(copy.querySelector('form')!);
  const review=await screen.findByRole('dialog',{name:'另存为新链接'});
  expect(review.textContent).toContain(`旧链接继续保留：https://go.example.com/r/${slug}`);
  expect(review.textContent).toContain('短链接：https://go.example.com/r/new-name');
  const payload=calls.find(call=>call.action==='prepare_change')?.payload;
  expect(payload).toMatchObject({kind:'save_link',domainId:'d',slug:'new-name',createOnly:true});
  expect(payload).toMatchObject(slug==='manual'?{cnUrl:'https://example.com/cn',defaultUrl:'https://example.org/en'}:{poolId:'p',code:'DEMO123'});
  expect(calls.some(call=>call.action==='apply_plan'||call.payload.kind==='delete_link')).toBe(false);
});

it('rejects an occupied name and allows cancellation without submitting anything',async()=>{
  const editor=await edit('manual');
  fireEvent.click(within(editor).getByRole('button',{name:'换一个名称'}));
  const copy=screen.getByRole('dialog',{name:'使用新名称创建链接'});
  fireEvent.change(within(copy).getByPlaceholderText('例如 welcome'),{target:{value:'platform'}});
  fireEvent.submit(copy.querySelector('form')!);
  expect(within(copy).getByRole('alert').textContent).toContain('现有链接不会被覆盖');
  expect(calls.some(call=>call.action==='prepare_change')).toBe(false);
  fireEvent.click(within(copy).getByRole('button',{name:'取消'}));
  expect(screen.queryByRole('dialog')).toBeNull();
  fireEvent.click(screen.getByRole('button',{name:'新建链接'}));
  expect(screen.getByRole('dialog',{name:'创建短链接'}).textContent).not.toContain('旧链接 /');
});

it('continues to edit the target of the existing name when not choosing a new name',async()=>{
  const editor=await edit('manual');
  fireEvent.change(within(editor).getByPlaceholderText('https://example.com/zh'),{target:{value:'https://example.com/changed'}});
  fireEvent.submit(editor.querySelector('form')!);
  await waitFor(()=>expect(calls.some(call=>call.action==='prepare_change')).toBe(true));
  expect(calls.find(call=>call.action==='prepare_change')?.payload).toMatchObject({slug:'manual',createOnly:false,cnUrl:'https://example.com/changed'});
});
