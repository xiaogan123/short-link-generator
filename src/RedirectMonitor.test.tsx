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

it('explains empty, offline, busy and incremental states and shows schedule, progress and attention',()=>{
  const props={enabled:true,active:false,online:true,progress:{done:1,total:3},lastCompletion:'2026-10-17T00:00:00Z',onEnabled:vi.fn(),onRun:vi.fn(),disabled:false};
  const {rerender}=render(<RedirectMonitor {...props} totalLinks={0}/>);
  expect(screen.getByRole('status').textContent).toBe('等待添加短链接');
  expect(screen.getByRole('button',{name:/立即巡检/}).hasAttribute('disabled')).toBe(true);
  rerender(<RedirectMonitor {...props} totalLinks={3} online={false} nextCheckAt="2026-10-19T00:00:00Z"/>);
  expect(screen.getByRole('status').textContent).toBe('等待网络连接');
  expect(screen.getByText(/下次预计/).textContent).toContain('条件恢复后执行');
  rerender(<RedirectMonitor {...props} disabled totalLinks={3}/>);
  expect(screen.getByRole('status').textContent).toBe('当前操作结束后继续');
  rerender(<RedirectMonitor {...props} active totalLinks={3} runKind="changed" summary={{alert:1,unresolved:1,attention:1}}/>);
  expect(screen.getByRole('status').textContent).toContain('正在检查新增或修改的链接 1/3');
  expect(screen.getByRole('progressbar').getAttribute('value')).toBe('1');
  expect(screen.getByText('3 条需关注')).toBeTruthy();
});

it('shows an explicit healthy result only when verified, with separate attention and expired messages',()=>{
  const props={enabled:true,active:false,online:true,progress:{done:2,total:2},lastCompletion:'2026-10-17T00:00:00Z',onEnabled:vi.fn(),onRun:vi.fn(),disabled:false,totalLinks:2,summary:{alert:0,unresolved:0,attention:0}};
  const {rerender}=render(<RedirectMonitor {...props}/>);
  expect(screen.getByText('巡检结果：尚未完成有效巡检')).toBeTruthy();
  expect(screen.queryByText('上次巡检：全部首跳符合预期')).toBeNull();
  rerender(<RedirectMonitor {...props} resultStatus="healthy"/>);
  expect(screen.getByText('上次巡检：全部首跳符合预期').classList.contains('healthy')).toBe(true);
  expect(screen.getByText(/上次整轮完成/)).toBeTruthy();
  rerender(<RedirectMonitor {...props} resultStatus="attention" summary={{alert:0,unresolved:1,attention:1}}/>);
  expect(screen.getByText('上次巡检：2 条链接需关注')).toBeTruthy();
  expect(screen.queryByText('上次巡检：全部首跳符合预期')).toBeNull();
  rerender(<RedirectMonitor {...props} resultStatus="stale"/>);
  expect(screen.getByText('上次巡检结果已过期，等待重新检查')).toBeTruthy();
});

it('hides previous result claims while checking, disabled, loading or empty',()=>{
  const props={enabled:true,active:false,online:true,progress:{done:1,total:2},lastCompletion:'2026-10-17T00:00:00Z',onEnabled:vi.fn(),onRun:vi.fn(),disabled:false,totalLinks:2,resultStatus:'healthy' as const};
  const {rerender}=render(<RedirectMonitor {...props} active/>);
  expect(screen.getByRole('status').textContent).toBe('正在巡检 1/2');
  expect(screen.queryByText('上次巡检：全部首跳符合预期')).toBeNull();
  for(const override of [{enabled:false},{ready:false},{totalLinks:0}]){
    rerender(<RedirectMonitor {...props} {...override}/>);
    expect(screen.queryByText('上次巡检：全部首跳符合预期')).toBeNull();
  }
});

it('says per link and per round what this app start has not checked yet',()=>{
  expect(monitorDisplay(null).label).toBe('本次打开后还没检查');
  const props={enabled:true,active:false,online:true,progress:{done:0,total:2},onEnabled:vi.fn(),onRun:vi.fn(),disabled:false,totalLinks:2};
  const {rerender}=render(<RedirectMonitor {...props} lastCompletion="2026-10-16T12:00:00Z" previousRunAt="2026-10-16T12:00:00Z" resultStatus="healthy"/>);
  expect(screen.getByText(/^上一轮（.+）全部符合预期，本次打开后还没重新检查$/)).toBeTruthy();
  expect(screen.queryByText('上次巡检：全部首跳符合预期')).toBeNull();
  rerender(<RedirectMonitor {...props} lastCompletion="2026-10-16T12:00:00Z" previousRunAt="2026-10-16T12:00:00Z" resultStatus="stale"/>);
  expect(screen.getByText(/^上一轮（.+）的结果已过期，等待重新检查$/)).toBeTruthy();
  rerender(<RedirectMonitor {...props} lastCompletion={null}/>);
  expect(screen.getByText('本次打开后还没跑完一整轮')).toBeTruthy();
  expect(screen.queryByText(/尚未完成$/)).toBeNull();
  rerender(<RedirectMonitor {...props} lastCompletion={null} backendBusy/>);
  expect(screen.getByRole('status').textContent).toBe('后台正忙，过几分钟自动接着查');
});
