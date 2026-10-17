import {cleanup,fireEvent,render,screen} from '@testing-library/react';
import {afterEach,expect,it,vi} from 'vitest';
import RedirectMonitor,{monitorBannerText,monitorDisplay} from './RedirectMonitor';
import type {VisibleMonitorRecord} from './useRedirectMonitor';

afterEach(cleanup);
const record=(phase:VisibleMonitorRecord['phase'],stale=false):VisibleMonitorRecord=>({identity:'one',phase,stale,checkedAt:'2026-10-17T00:00:00Z',message:'示例',dnsMode:'system',failures:0,unresolvedAlert:false});

it('labels confirmed, pending, unknown and expired results without reusing manual detection wording',()=>{
  expect(monitorDisplay(record('healthy')).label).toBe('首跳符合预期');
  expect(monitorDisplay(record('pending')).label).toBe('待复查');
  expect(monitorDisplay(record('alert')).label).toBe('首跳异常');
  expect(monitorDisplay(record('attention')).label).toBe('需关注');
  expect(monitorDisplay({...record('attention'),unresolvedAlert:true}).label).toBe('异常待确认恢复');
  expect(monitorDisplay(record('healthy',true)).label).toBe('结果已过期');
});

it('keeps banner language aligned with unresolved rows and does not imply an alert for unknown-only results',()=>{
  expect(monitorBannerText({alert:0,unresolved:1,attention:0})).toBe('自动巡检：1 条异常待确认恢复');
  expect(monitorBannerText({alert:1,unresolved:1,attention:2})).toBe('自动巡检：1 条首跳异常，1 条异常待确认恢复，2 条需关注');
  expect(monitorBannerText({alert:0,unresolved:0,attention:1})).toBe('自动巡检：1 条需关注');
  expect(monitorBannerText({alert:0,unresolved:0,attention:0})).toBe('');
});

it('shows the schedule and network limit, and keeps manual run gated',()=>{
  const onEnabled=vi.fn(),onRun=vi.fn();
  const {rerender}=render(<RedirectMonitor enabled={false} active={false} online={true} progress={{done:0,total:0}} lastCompletion={null} onEnabled={onEnabled} onRun={onRun} disabled={false}/>);
  expect(screen.getByText(/每 48 小时/)).toBeTruthy();
  expect(screen.getByText(/不代表大陆网络或目标网站可达/)).toBeTruthy();
  expect(screen.getByRole('button',{name:/立即巡检/}).hasAttribute('disabled')).toBe(true);
  fireEvent.click(screen.getByRole('checkbox'));
  expect(onEnabled).toHaveBeenCalledWith(true);
  rerender(<RedirectMonitor enabled active={false} online progress={{done:0,total:1}} lastCompletion={null} onEnabled={onEnabled} onRun={onRun} disabled={false}/>);
  fireEvent.click(screen.getByRole('button',{name:/立即巡检/}));
  expect(onRun).toHaveBeenCalledTimes(1);
});
