import { useState } from 'react';
import { cleanup, fireEvent, render, screen, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import Dialog from './Dialog';

beforeEach(() => {
  vi.spyOn(HTMLElement.prototype, 'getClientRects').mockImplementation(function(this: HTMLElement) {
    const hidden = this.hidden || getComputedStyle(this).display === 'none' || this.dataset.noLayout === 'true';
    return (hidden ? [] : [new DOMRect(12, 12, 120, 32)]) as unknown as DOMRectList;
  });
});
afterEach(() => { cleanup(); vi.restoreAllMocks(); });

it('keeps Tab and Shift+Tab inside a fully disabled applying dialog and makes the background inert', async () => {
  const user = userEvent.setup();
  render(<><button>背景导航</button><Dialog title="执行中" dismissDisabled onClose={() => {}} footer={<><button disabled>返回</button><button disabled>正在提交</button></>}><p>摘要</p></Dialog></>);
  const modal = screen.getByRole('dialog');
  expect(document.activeElement).toBe(modal);
  expect(screen.getByRole('button', {name:'背景导航'}).hasAttribute('inert')).toBe(true);
  await user.tab(); expect(document.activeElement).toBe(modal);
  await user.tab({shift:true}); expect(document.activeElement).toBe(modal);
  screen.getByRole('button', {name:'背景导航'}).focus();
  expect(document.activeElement).toBe(modal);
});

it('moves focus to the dialog when a focused submit button becomes disabled', async () => {
  const user = userEvent.setup();
  function Example() {
    const [busy, setBusy] = useState(false);
    return <><button>背景</button><Dialog title="计划" dismissDisabled={busy} onClose={() => {}} footer={<button disabled={busy} onClick={() => setBusy(true)}>提交</button>}><p>摘要</p></Dialog></>;
  }
  render(<Example/>);
  await user.click(screen.getByRole('button', {name:'提交'}));
  await user.tab();
  expect(document.activeElement).toBe(screen.getByRole('dialog'));
});

it('only the top dialog traps focus, closes on Escape, and restores the nested trigger', async () => {
  const user = userEvent.setup();
  function Example() {
    const [outer, setOuter] = useState(false);
    const [inner, setInner] = useState(false);
    return <><button onClick={() => setOuter(true)}>打开</button>{outer && <Dialog title="外层" onClose={() => setOuter(false)}><button onClick={() => setInner(true)}>继续</button></Dialog>}{inner && <Dialog title="内层" onClose={() => setInner(false)}><input aria-label="内层输入"/></Dialog>}</>;
  }
  render(<Example/>);
  const trigger = screen.getByRole('button',{name:'打开'});
  await user.click(trigger);
  const nestedTrigger = screen.getByRole('button',{name:'继续'});
  await user.click(nestedTrigger);
  expect(document.activeElement).toBe(screen.getByRole('textbox',{name:'内层输入'}));
  const outer = screen.getByRole('dialog',{name:'外层'});
  expect(outer.parentElement?.hasAttribute('inert')).toBe(true);
  fireEvent.keyDown(document,{key:'Escape'});
  expect(screen.queryByRole('dialog',{name:'内层'})).toBeNull();
  expect(document.activeElement).toBe(nestedTrigger);
  expect(outer.parentElement?.hasAttribute('inert')).toBe(false);
  fireEvent.keyDown(document,{key:'Escape'});
  expect(document.activeElement).toBe(trigger);
  expect(trigger.hasAttribute('inert')).toBe(false);
});

it('preserves existing inert attributes and skips hidden/closed-details controls', () => {
  const {unmount} = render(<><section inert><button>原先不可用</button></section><Dialog title="表单" onClose={() => {}}><input hidden aria-label="隐藏"/><details><summary>更多</summary><input aria-label="折叠输入"/></details><input aria-label="可见输入"/></Dialog></>);
  expect(document.activeElement).toBe(screen.getByRole('textbox',{name:'可见输入'}));
  expect(within(screen.getByRole('dialog')).getByRole('textbox',{name:'可见输入'})).toBeTruthy();
  const inertSection = document.querySelector('section')!;
  unmount();
  expect(inertSection.hasAttribute('inert')).toBe(true);
});

it('uses rendered geometry and includes fixed-position controls in the focus loop', async () => {
  const user = userEvent.setup();
  render(<Dialog title="几何可见性" onClose={() => {}}>
    <input aria-label="没有布局框" data-no-layout="true"/>
    <input aria-label="固定输入" style={{position:'fixed'}}/>
    <button style={{visibility:'hidden'}}>不可见按钮</button>
  </Dialog>);
  const input = screen.getByRole('textbox',{name:'固定输入'});
  expect(document.activeElement).toBe(input);
  expect(input.offsetParent).toBeNull();
  await user.tab();
  expect(document.activeElement).toBe(screen.getByRole('button',{name:'关闭'}));
  await user.tab({shift:true});
  expect(document.activeElement).toBe(input);
});

it('starts on a field marked data-autofocus, otherwise on the first field', () => {
  const { unmount } = render(<Dialog title="选择" onClose={() => {}}><select aria-label="账户"><option>甲</option></select><input aria-label="域名" data-autofocus /></Dialog>);
  expect(document.activeElement).toBe(screen.getByRole('textbox', {name:'域名'}));
  unmount();
  render(<Dialog title="选择" onClose={() => {}}><select aria-label="账户"><option>甲</option></select><input aria-label="域名" /></Dialog>);
  expect(document.activeElement).toBe(screen.getByRole('combobox', {name:'账户'}));
});
