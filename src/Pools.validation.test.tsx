import {cleanup,fireEvent,render,screen,within} from '@testing-library/react';
import {afterEach,expect,it,vi} from 'vitest';
import Pools from './Pools';

afterEach(cleanup);
it('focuses Chinese platform field errors before preparing and permits valid submission',async()=>{
  const save=vi.fn(async()=>true);
  render(<Pools pools={[]} accounts={[]} linkCount={()=>0} onSave={save} onDelete={()=>{}} busy={false} health={{}} onCheckHealth={()=>{}} planOpen={false} savedRevision={0}/>);
  fireEvent.click(screen.getByRole('button',{name:'添加平台地址'}));
  const editor=screen.getByRole('dialog',{name:'添加平台地址'});
  const submit=within(editor).getByRole('button',{name:'下一步，核对内容'});
  fireEvent.click(submit);
  const name=within(editor).getByPlaceholderText('例如：常用平台 A');
  expect(document.activeElement).toBe(name);expect(name.getAttribute('aria-invalid')).toBe('true');
  expect(document.getElementById(name.getAttribute('aria-describedby')!)?.textContent).toBe('请为平台地址命名。');
  expect((editor.querySelector('form') as HTMLFormElement).noValidate).toBe(true);expect(save).not.toHaveBeenCalled();
  fireEvent.change(name,{target:{value:'常用平台'}});
  fireEvent.change(within(editor).getByPlaceholderText('https://example.com/join/'),{target:{value:'https://example.com/join/'}});
  fireEvent.change(within(editor).getByPlaceholderText('https://example.org/join/'),{target:{value:'http://example.org/join/'}});
  fireEvent.click(submit);
  const candidate=within(editor).getByPlaceholderText('https://example.org/join/');
  expect(document.activeElement).toBe(candidate);expect(candidate.getAttribute('aria-invalid')).toBe('true');expect(save).not.toHaveBeenCalled();
  fireEvent.change(candidate,{target:{value:'https://example.org/join/'}});fireEvent.click(submit);
  expect(save).toHaveBeenCalledTimes(1);
});
it('explains and focuses the candidate group when every mainland address is disabled',()=>{
  const save=vi.fn(async()=>true);
  render(<Pools pools={[]} accounts={[]} linkCount={()=>0} onSave={save} onDelete={()=>{}} busy={false} health={{}} onCheckHealth={()=>{}} planOpen={false} savedRevision={0}/>);
  fireEvent.click(screen.getByRole('button',{name:'添加平台地址'}));
  const editor=screen.getByRole('dialog',{name:'添加平台地址'});
  fireEvent.change(within(editor).getByPlaceholderText('例如：常用平台 A'),{target:{value:'常用平台'}});
  fireEvent.change(within(editor).getByPlaceholderText('https://example.com/join/'),{target:{value:'https://example.com/join/'}});
  fireEvent.change(within(editor).getByPlaceholderText('https://example.org/join/'),{target:{value:'https://example.org/join/'}});
  fireEvent.click(within(editor).getByRole('checkbox'));fireEvent.click(within(editor).getByRole('button',{name:'下一步，核对内容'}));
  expect(document.activeElement?.id).toBe('pool-candidates');expect(within(editor).getByRole('alert').textContent).toContain('至少启用一个');expect(save).not.toHaveBeenCalled();
});
