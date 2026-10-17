import {act,cleanup,renderHook} from '@testing-library/react';
import {afterEach,beforeEach,expect,it,vi} from 'vitest';
import {CONFIRM_DELAY_MS,MONITOR_INTERVAL_MS,monitorIdentity,useRedirectMonitor} from './useRedirectMonitor';
import type {RedirectCheck,State} from './types';

const base:State = {accounts:[],domains:[{id:'d',accountId:'a',zoneId:'z',host:'go.example.com',prefix:'r',routeId:'route'}],links:[{domainId:'d',slug:'one',cnUrl:'https://example.com/a',defaultUrl:'https://example.org/b',updated:'u1'}],pools:[],pendingOperations:[],pendingActions:[]};
const report = (status:RedirectCheck['status'],reason?:string):RedirectCheck => ({status,message:status,reason,checkedAt:new Date().toISOString(),dnsMode:'system'});
const tick = async (ms=0) => {await act(async()=>{await vi.advanceTimersByTimeAsync(ms);});};
beforeEach(()=>{vi.useFakeTimers();vi.setSystemTime(new Date('2026-10-17T00:00:00Z'));localStorage.clear();});
afterEach(()=>{cleanup();vi.useRealTimers();localStorage.clear();});

it('defaults off, checks once on enable, then repeats after 30 minutes without overlap',async()=>{
  let release!: (value:RedirectCheck)=>void;
  const check=vi.fn().mockImplementationOnce(()=>new Promise<RedirectCheck>(resolve=>{release=resolve;})).mockImplementation(()=>Promise.resolve(report('passed')));
  const {result}=renderHook(()=>useRedirectMonitor({state:base,paused:false,ready:true,check}));
  await tick(MONITOR_INTERVAL_MS);
  expect(check).not.toHaveBeenCalled();
  act(()=>result.current.setEnabled(true)); await tick();
  expect(check).toHaveBeenCalledTimes(1);
  act(()=>result.current.runNow());
  expect(check).toHaveBeenCalledTimes(1);
  await act(async()=>release(report('passed')));
  expect(result.current.getRecord(base.links[0])?.phase).toBe('healthy');
  await tick(MONITOR_INTERVAL_MS);
  expect(check).toHaveBeenCalledTimes(2);
});

it('confirms a definite failure about a minute later; an unknown breaks the streak and later pass recovers',async()=>{
  const check=vi.fn().mockResolvedValueOnce(report('failed')).mockResolvedValueOnce(report('unknown')).mockResolvedValueOnce(report('failed')).mockResolvedValueOnce(report('failed')).mockResolvedValueOnce(report('passed'));
  const {result}=renderHook(()=>useRedirectMonitor({state:base,paused:false,ready:true,check}));
  act(()=>result.current.setEnabled(true)); await tick();
  expect(result.current.getRecord(base.links[0])?.phase).toBe('pending');
  await tick(CONFIRM_DELAY_MS);
  expect(result.current.getRecord(base.links[0])?.phase).toBe('attention');
  act(()=>result.current.runNow()); await tick();
  expect(result.current.getRecord(base.links[0])?.phase).toBe('pending');
  await tick(CONFIRM_DELAY_MS);
  expect(result.current.getRecord(base.links[0])?.phase).toBe('alert');
  act(()=>result.current.runNow()); await tick();
  expect(result.current.getRecord(base.links[0])?.phase).toBe('healthy');
});

it('pauses for offline and busy state, resumes one cycle, and drops a disabled in-flight response',async()=>{
  let release!: (value:RedirectCheck)=>void;
  const check=vi.fn().mockImplementationOnce(()=>new Promise<RedirectCheck>(resolve=>{release=resolve;})).mockResolvedValue(report('passed'));
  const online=vi.spyOn(window.navigator,'onLine','get').mockReturnValue(false);
  const {result,rerender}=renderHook(({paused})=>useRedirectMonitor({state:base,paused,ready:true,check}),{initialProps:{paused:false}});
  act(()=>result.current.setEnabled(true)); await tick();
  expect(check).not.toHaveBeenCalled();
  online.mockReturnValue(true);
  rerender({paused:true});
  act(()=>window.dispatchEvent(new Event('online'))); await tick();
  expect(check).not.toHaveBeenCalled();
  rerender({paused:false}); await tick();
  expect(check).toHaveBeenCalledTimes(1);
  act(()=>result.current.setEnabled(false));
  await act(async()=>release(report('failed')));
  expect(result.current.getRecord(base.links[0])).toBeNull();
  act(()=>result.current.setEnabled(true)); await tick();
  expect(check).toHaveBeenCalledTimes(2);
  online.mockRestore();
});

it('discards stale responses after edit, delete, and unmount; identity includes route and enabled pool candidates',async()=>{
  const resolvers:Array<(value:RedirectCheck)=>void>=[];
  const check=vi.fn(()=>new Promise<RedirectCheck>(resolve=>resolvers.push(resolve)));
  const state:State=structuredClone(base);
  const {result,rerender,unmount}=renderHook(({snapshot})=>useRedirectMonitor({state:snapshot,paused:false,ready:true,check}),{initialProps:{snapshot:state}});
  act(()=>result.current.setEnabled(true));await tick();
  const edited={...state,links:[{...state.links[0],defaultUrl:'https://example.org/new',updated:'u2'}]};
  expect(monitorIdentity(state.links[0],state)).not.toBe(monitorIdentity(edited.links[0],edited));
  rerender({snapshot:edited});
  await act(async()=>resolvers.shift()!(report('failed')));
  expect(result.current.getRecord(edited.links[0])).toBeNull();
  act(()=>result.current.runNow());await tick();
  rerender({snapshot:{...edited,links:[]}});
  await act(async()=>resolvers.shift()!(report('passed')));
  expect(result.current.summary).toEqual({alert:0,unresolved:0,attention:0});
  unmount();
});

it('handles blocked storage and invalid reports as attention without persisting link data',async()=>{
  const getter=vi.spyOn(Storage.prototype,'getItem').mockImplementation(()=>{throw new Error('blocked');});
  const setter=vi.spyOn(Storage.prototype,'setItem').mockImplementation(()=>{throw new Error('blocked');});
  const check=vi.fn().mockResolvedValue({status:'passed'});
  const {result}=renderHook(()=>useRedirectMonitor({state:base,paused:false,ready:true,check}));
  expect(result.current.enabled).toBe(false);
  act(()=>result.current.setEnabled(true));await tick();
  expect(result.current.getRecord(base.links[0])?.phase).toBe('attention');
  expect(setter).toHaveBeenCalledWith('redirect-monitor-preview-enabled','true');
  getter.mockRestore();setter.mockRestore();
});

it('keeps busy responses quiet, retries once, and lets healthy results expire',async()=>{
  const check=vi.fn().mockResolvedValueOnce(report('unknown','busy')).mockResolvedValueOnce(report('passed'));
  const {result,rerender}=renderHook(({paused})=>useRedirectMonitor({state:base,paused,ready:true,check}),{initialProps:{paused:false}});
  act(()=>result.current.setEnabled(true));await tick();
  expect(result.current.summary).toEqual({alert:0,unresolved:0,attention:0});
  expect(check).toHaveBeenCalledTimes(1);
  await tick(CONFIRM_DELAY_MS);
  expect(check).toHaveBeenCalledTimes(2);
  expect(result.current.getRecord(base.links[0])?.phase).toBe('healthy');
  rerender({paused:true});
  await tick(66*60_000);
  expect(result.current.getRecord(base.links[0])?.stale).toBe(true);
  expect(result.current.summary.attention).toBe(1);
});

it('marks missing domain as unknown locally without dispatching a request',async()=>{
  const state={...base,domains:[]};
  const check=vi.fn();
  const {result}=renderHook(()=>useRedirectMonitor({state,paused:false,ready:true,check}));
  act(()=>result.current.setEnabled(true));await tick();
  expect(check).not.toHaveBeenCalled();
  expect(result.current.getRecord(base.links[0])?.phase).toBe('attention');
});

it('does not treat a generic unavailable message as backend busy',async()=>{
  const check=vi.fn().mockResolvedValue(report('unknown','server_unavailable'));
  const {result}=renderHook(()=>useRedirectMonitor({state:base,paused:false,ready:true,check}));
  act(()=>result.current.setEnabled(true));await tick();
  expect(result.current.getRecord(base.links[0])?.phase).toBe('attention');
  expect(result.current.summary.attention).toBe(1);
});

it('retains a confirmed alert through unknown and another failure until passed',async()=>{
  const check=vi.fn().mockResolvedValueOnce(report('failed')).mockResolvedValueOnce(report('failed')).mockResolvedValueOnce(report('unknown')).mockResolvedValueOnce(report('failed')).mockResolvedValueOnce(report('passed'));
  const {result}=renderHook(()=>useRedirectMonitor({state:base,paused:false,ready:true,check}));
  act(()=>result.current.setEnabled(true));await tick(CONFIRM_DELAY_MS);
  expect(result.current.getRecord(base.links[0])?.phase).toBe('alert');
  act(()=>result.current.runNow());await tick();
  expect(result.current.getRecord(base.links[0])).toMatchObject({phase:'attention',unresolvedAlert:true,failures:0});
  expect(result.current.summary).toEqual({alert:0,unresolved:1,attention:0});
  act(()=>result.current.runNow());await tick();
  expect(result.current.getRecord(base.links[0])).toMatchObject({phase:'alert',unresolvedAlert:true});
  expect(result.current.summary).toEqual({alert:1,unresolved:0,attention:0});
  act(()=>result.current.runNow());await tick();
  expect(result.current.getRecord(base.links[0])).toMatchObject({phase:'healthy',unresolvedAlert:false});
  expect(result.current.summary).toEqual({alert:0,unresolved:0,attention:0});
});

it('keeps an expired confirmed alert in the unresolved count rather than claiming no confirmed issue',async()=>{
  const check=vi.fn().mockResolvedValue(report('failed'));
  const {result,rerender}=renderHook(({paused})=>useRedirectMonitor({state:base,paused,ready:true,check}),{initialProps:{paused:false}});
  act(()=>result.current.setEnabled(true));await tick(CONFIRM_DELAY_MS);
  expect(result.current.summary).toEqual({alert:1,unresolved:0,attention:0});
  rerender({paused:true});
  await tick(66*60_000);
  expect(result.current.getRecord(base.links[0])?.stale).toBe(true);
  expect(result.current.summary).toEqual({alert:0,unresolved:1,attention:0});
});

it('does not let a quick manual repeat bypass the one-minute confirmation',async()=>{
  const check=vi.fn().mockResolvedValue(report('failed'));
  const {result}=renderHook(()=>useRedirectMonitor({state:base,paused:false,ready:true,check}));
  act(()=>result.current.setEnabled(true));await tick();
  act(()=>result.current.runNow());await tick();
  expect(check).toHaveBeenCalledTimes(2);
  expect(result.current.getRecord(base.links[0])?.phase).toBe('pending');
  await tick(CONFIRM_DELAY_MS);
  expect(result.current.getRecord(base.links[0])?.phase).toBe('alert');
});

it('prioritizes a due confirmation between links in a long serial cycle',async()=>{
  const state:State={...base,links:[base.links[0],{...base.links[0],slug:'two'},{...base.links[0],slug:'three'}]};
  const order:string[]=[];
  let releaseTwo!:()=>void;
  let inFlight=0,maxInFlight=0,oneCount=0;
  const check=vi.fn(async (_domainId:string,slug:string)=>{
    order.push(slug);
    inFlight++;maxInFlight=Math.max(maxInFlight,inFlight);
    if(slug==='two') await new Promise<void>(resolve=>{releaseTwo=resolve;});
    inFlight--;
    if(slug==='one') return report(++oneCount===1?'failed':'passed');
    return report('passed');
  });
  const {result}=renderHook(()=>useRedirectMonitor({state,paused:false,ready:true,check}));
  act(()=>result.current.setEnabled(true));await tick(250);
  expect(order).toEqual(['one','two']);
  await tick(CONFIRM_DELAY_MS);
  expect(order).toEqual(['one','two']);
  await act(async()=>releaseTwo());
  await tick(250);
  expect(order).toEqual(['one','two','one','three']);
  expect(maxInFlight).toBe(1);
  expect(result.current.getRecord(state.links[0])?.phase).toBe('healthy');
});

it('clears pending state on disable and starts a fresh cycle after re-enable',async()=>{
  const check=vi.fn().mockResolvedValueOnce(report('failed')).mockResolvedValueOnce(report('passed'));
  const {result}=renderHook(()=>useRedirectMonitor({state:base,paused:false,ready:true,check}));
  act(()=>result.current.setEnabled(true));await tick();
  expect(result.current.getRecord(base.links[0])?.phase).toBe('pending');
  act(()=>result.current.setEnabled(false));
  expect(result.current.getRecord(base.links[0])).toBeNull();
  act(()=>result.current.setEnabled(true));await tick();
  expect(result.current.getRecord(base.links[0])?.phase).toBe('healthy');
  await tick(CONFIRM_DELAY_MS);
  expect(check).toHaveBeenCalledTimes(2);
});
