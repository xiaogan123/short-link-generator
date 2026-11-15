import {act,cleanup,renderHook} from '@testing-library/react';
import {afterEach,beforeEach,expect,it,vi} from 'vitest';
import {BUSY_BACKOFF_MS,CONFIRM_DELAY_MS,MONITOR_INTERVAL_MS,STALE_AFTER_MS,monitorIdentity,useRedirectMonitor} from './useRedirectMonitor';
import type {RedirectCheck,State} from './types';

const base:State = {accounts:[],domains:[{id:'d',accountId:'a',zoneId:'z',host:'go.example.com',prefix:'r',routeId:'route'}],links:[{domainId:'d',slug:'one',cnUrl:'https://example.com/a',defaultUrl:'https://example.org/b',updated:'u1'}],pools:[],pendingOperations:[],pendingActions:[]};
const report = (status:RedirectCheck['status'],reason?:string):RedirectCheck => ({status,message:status,reason,checkedAt:new Date().toISOString(),dnsMode:'system'});
const tick = async (ms=0) => {await act(async()=>{await vi.advanceTimersByTimeAsync(ms);});};
beforeEach(()=>{vi.useFakeTimers();vi.setSystemTime(new Date('2026-10-17T00:00:00Z'));localStorage.clear();});
afterEach(()=>{cleanup();vi.useRealTimers();localStorage.clear();});

it('defaults off, checks once on enable, then repeats after 48 hours without overlap',async()=>{
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

it('keeps busy responses quiet, retries after a one-minute wait, and lets healthy results expire',async()=>{
  const check=vi.fn().mockResolvedValueOnce(report('unknown','busy')).mockResolvedValueOnce(report('passed'));
  const {result,rerender}=renderHook(({paused})=>useRedirectMonitor({state:base,paused,ready:true,check}),{initialProps:{paused:false}});
  act(()=>result.current.setEnabled(true));await tick();
  expect(result.current.summary).toEqual({alert:0,unresolved:0,attention:0});
  expect(check).toHaveBeenCalledTimes(1);
  await tick(CONFIRM_DELAY_MS);
  expect(check).toHaveBeenCalledTimes(2);
  expect(result.current.getRecord(base.links[0])?.phase).toBe('healthy');
  rerender({paused:true});
  await tick(STALE_AFTER_MS+60_000);
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
  expect(result.current.resultStatus).toBe('healthy');
});

it('keeps an expired confirmed alert in the unresolved count rather than claiming no confirmed issue',async()=>{
  const check=vi.fn().mockResolvedValue(report('failed'));
  const {result,rerender}=renderHook(({paused})=>useRedirectMonitor({state:base,paused,ready:true,check}),{initialProps:{paused:false}});
  act(()=>result.current.setEnabled(true));await tick(CONFIRM_DELAY_MS);
  expect(result.current.summary).toEqual({alert:1,unresolved:0,attention:0});
  rerender({paused:true});
  await tick(STALE_AFTER_MS+60_000);
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


it('remembers a healthy completion across restart and waits the full 48 hours',async()=>{
  const check=vi.fn(()=>Promise.resolve(report('passed')));
  const first=renderHook(()=>useRedirectMonitor({state:base,paused:false,ready:true,check}));
  act(()=>first.result.current.setEnabled(true));await tick();
  first.unmount();
  await tick(47*60*60_000);
  const second=renderHook(()=>useRedirectMonitor({state:base,paused:false,ready:true,check}));
  await tick();
  expect(second.result.current.lastCompletion).toBe('2026-10-17T00:00:00.000Z');
  expect(check).toHaveBeenCalledTimes(1);
  await tick(60*60_000-60_000);
  expect(check).toHaveBeenCalledTimes(1);
  await tick(60_000);
  expect(check).toHaveBeenCalledTimes(2);
  expect(localStorage.getItem('redirect-monitor-preview-enabled-completed-at')).toBe('2026-10-19T00:00:00.000Z');
});

it('catches up only once after several closed days and retains manual run',async()=>{
  localStorage.setItem('redirect-monitor-preview-enabled','true');
  localStorage.setItem('redirect-monitor-preview-enabled-completed-at','2026-10-10T00:00:00.000Z');
  const check=vi.fn(()=>Promise.resolve(report('passed')));
  const {result}=renderHook(()=>useRedirectMonitor({state:base,paused:false,ready:true,check}));
  await tick();
  expect(check).toHaveBeenCalledTimes(1);
  await tick(60_000);
  expect(check).toHaveBeenCalledTimes(1);
  act(()=>result.current.runNow());await tick();
  expect(check).toHaveBeenCalledTimes(2);
});

it.each(['not-a-date','2027-01-01T00:00:00Z'])('ignores invalid or future saved completion: %s',async value=>{
  localStorage.setItem('redirect-monitor-preview-enabled','true');
  localStorage.setItem('redirect-monitor-preview-enabled-completed-at',value);
  const check=vi.fn(()=>Promise.resolve(report('passed')));
  renderHook(()=>useRedirectMonitor({state:base,paused:false,ready:true,check}));await tick();
  expect(check).toHaveBeenCalledTimes(1);
});

it('does not delay rechecking unresolved results after restarting or persist report data',async()=>{
  const check=vi.fn(()=>Promise.resolve(report('failed')));
  const first=renderHook(()=>useRedirectMonitor({state:base,paused:false,ready:true,check}));
  act(()=>first.result.current.setEnabled(true));await tick(CONFIRM_DELAY_MS);
  expect(first.result.current.getRecord(base.links[0])?.phase).toBe('alert');
  expect(localStorage.getItem('redirect-monitor-preview-enabled-completed-at')).toBeNull();
  first.unmount();
  renderHook(()=>useRedirectMonitor({state:base,paused:false,ready:true,check}));await tick();
  expect(check).toHaveBeenCalledTimes(3);
  expect(Object.keys(localStorage)).toEqual(['redirect-monitor-preview-enabled']);
});

it('does not save an interrupted cycle as completed',async()=>{
  let finish!:(value:RedirectCheck)=>void;
  const check=vi.fn(()=>new Promise<RedirectCheck>(resolve=>{finish=resolve;}));
  const first=renderHook(()=>useRedirectMonitor({state:base,paused:false,ready:true,check}));
  act(()=>first.result.current.setEnabled(true));await tick();
  act(()=>first.result.current.setEnabled(false));
  await act(async()=>finish(report('passed')));
  expect(first.result.current.lastCompletion).toBeNull();
  expect(localStorage.getItem('redirect-monitor-preview-enabled-completed-at')).toBeNull();
});


it('does not reuse an earlier healthy result when a later cycle is busy',async()=>{
  const check=vi.fn().mockImplementationOnce(()=>Promise.resolve(report('passed')))
    .mockImplementationOnce(()=>Promise.resolve(report('unknown','busy')))
    .mockImplementation(()=>Promise.resolve(report('failed')));
  const {result}=renderHook(()=>useRedirectMonitor({state:base,paused:false,ready:true,check}));
  act(()=>result.current.setEnabled(true));await tick();
  expect(localStorage.getItem('redirect-monitor-preview-enabled-completed-at')).not.toBeNull();
  act(()=>result.current.runNow());await tick();
  expect(result.current.getRecord(base.links[0])?.phase).toBe('healthy');
  expect(localStorage.getItem('redirect-monitor-preview-enabled-completed-at')).toBeNull();
  await tick(CONFIRM_DELAY_MS*2);
  expect(result.current.getRecord(base.links[0])?.phase).toBe('alert');
  expect(localStorage.getItem('redirect-monitor-preview-enabled-completed-at')).toBeNull();
});

it.each(['paused','offline'])('retries after the last in-flight check completes while %s',async blocker=>{
  let finish!:(value:RedirectCheck)=>void;
  const check=vi.fn().mockImplementationOnce(()=>new Promise<RedirectCheck>(resolve=>{finish=resolve;}))
    .mockImplementation(()=>Promise.resolve(report('passed')));
  const online=vi.spyOn(window.navigator,'onLine','get').mockReturnValue(true);
  const {result,rerender}=renderHook(({paused})=>useRedirectMonitor({state:base,paused,ready:true,check}),{initialProps:{paused:false}});
  act(()=>result.current.setEnabled(true));await tick();
  if(blocker==='paused') rerender({paused:true});
  else online.mockReturnValue(false);
  await act(async()=>finish(report('passed')));
  expect(result.current.lastCompletion).toBeNull();
  expect(localStorage.getItem('redirect-monitor-preview-enabled-completed-at')).toBeNull();
  if(blocker==='paused') rerender({paused:false});
  else {online.mockReturnValue(true);act(()=>window.dispatchEvent(new Event('online')));}
  await tick();
  expect(check).toHaveBeenCalledTimes(2);
  expect(result.current.lastCompletion).not.toBeNull();
  online.mockRestore();
});

it('keeps the 48-hour deadline and result age safe when the wall clock moves backwards',async()=>{
  const check=vi.fn(()=>Promise.resolve(report('passed')));
  const {result,rerender}=renderHook(({paused})=>useRedirectMonitor({state:base,paused,ready:true,check}),{initialProps:{paused:false}});
  act(()=>result.current.setEnabled(true));await tick();
  vi.setSystemTime(new Date('2026-10-10T00:00:00Z'));
  act(()=>window.dispatchEvent(new Event('focus')));await tick();
  expect(result.current.getRecord(base.links[0])?.stale).toBe(true);
  await tick(MONITOR_INTERVAL_MS);
  expect(check).toHaveBeenCalledTimes(2);
  rerender({paused:true});
  await tick(STALE_AFTER_MS+60_000);
  expect(result.current.getRecord(base.links[0])?.stale).toBe(true);
});

it('confirms a failure after one elapsed minute even after a seven-day rollback',async()=>{
  const check=vi.fn(()=>Promise.resolve(report('failed')));
  const {result}=renderHook(()=>useRedirectMonitor({state:base,paused:false,ready:true,check}));
  act(()=>result.current.setEnabled(true));await tick();
  vi.setSystemTime(new Date('2026-10-10T00:00:00Z'));
  await tick(CONFIRM_DELAY_MS);
  expect(check).toHaveBeenCalledTimes(2);
  expect(result.current.getRecord(base.links[0])?.phase).toBe('alert');
});

it('catches sleep up once on focus even when the monotonic clock did not advance',async()=>{
  const monotonic=vi.spyOn(performance,'now').mockReturnValue(0);
  const check=vi.fn(()=>Promise.resolve(report('passed')));
  const {result}=renderHook(()=>useRedirectMonitor({state:base,paused:false,ready:true,check}));
  act(()=>result.current.setEnabled(true));await tick();
  vi.setSystemTime(new Date('2026-10-20T00:00:00Z'));
  act(()=>window.dispatchEvent(new Event('focus')));await tick();
  expect(check).toHaveBeenCalledTimes(2);
  act(()=>{window.dispatchEvent(new Event('focus'));document.dispatchEvent(new Event('visibilitychange'));});await tick();
  expect(check).toHaveBeenCalledTimes(2);
  monotonic.mockRestore();
});

it('does not complete an empty round and checks the first added link promptly',async()=>{
  const check=vi.fn(()=>Promise.resolve(report('passed')));
  const {result,rerender}=renderHook(({state})=>useRedirectMonitor({state,paused:false,ready:true,check}),{initialProps:{state:{...base,links:[]} as State}});
  act(()=>result.current.setEnabled(true));await tick();
  expect(result.current.lastCompletion).toBeNull();
  expect(localStorage.getItem('redirect-monitor-preview-enabled-completed-at')).toBeNull();
  rerender({state:base});await tick();
  expect(check).toHaveBeenCalledTimes(1);
  expect(result.current.lastCompletion).not.toBeNull();
});

it('checks only changed or added identities without postponing the regular full round',async()=>{
  const initial={...base,links:[base.links[0],{...base.links[0],slug:'two'}]};
  const check=vi.fn(()=>Promise.resolve(report('passed')));
  const {result,rerender}=renderHook(({state})=>useRedirectMonitor({state,paused:false,ready:true,check}),{initialProps:{state:initial}});
  act(()=>result.current.setEnabled(true));await tick(250);
  const fullCompletion=result.current.lastCompletion;
  await tick(24*60*60_000);
  const edited={...initial,links:[{...initial.links[0],updated:'u2',defaultUrl:'https://example.org/new'},initial.links[1]]};
  rerender({state:edited});await tick();
  expect(check.mock.calls).toHaveLength(3);
  expect(check).toHaveBeenLastCalledWith('d','one');
  expect(result.current.lastCompletion).toBe(fullCompletion);
  expect(localStorage.getItem('redirect-monitor-preview-enabled-completed-at')).toBeNull();
  await tick(24*60*60_000+60_000);
  expect(check).toHaveBeenCalledTimes(5);
});

it('queues an edited identity behind its old in-flight request and never accepts the old result',async()=>{
  const releases:Array<(result:RedirectCheck)=>void>=[];
  let inFlight=0,maxInFlight=0;
  const check=vi.fn(()=>{inFlight++;maxInFlight=Math.max(maxInFlight,inFlight);return new Promise<RedirectCheck>(resolve=>releases.push(value=>{inFlight--;resolve(value);}));});
  const {result,rerender}=renderHook(({state})=>useRedirectMonitor({state,paused:false,ready:true,check}),{initialProps:{state:base}});
  act(()=>result.current.setEnabled(true));await tick();
  const edited={...base,links:[{...base.links[0],updated:'changed'}]};
  rerender({state:edited});await tick();
  expect(check).toHaveBeenCalledTimes(1);
  await act(async()=>releases.shift()!(report('failed')));await tick();
  expect(result.current.getRecord(edited.links[0])).toBeNull();
  expect(check).toHaveBeenCalledTimes(2);
  await act(async()=>releases.shift()!(report('passed')));
  expect(result.current.getRecord(edited.links[0])?.phase).toBe('healthy');
  expect(maxInFlight).toBe(1);
});

it('holds incremental checks while offline or paused and removes deleted queued identities',async()=>{
  const check=vi.fn(()=>Promise.resolve(report('passed')));
  const online=vi.spyOn(window.navigator,'onLine','get').mockReturnValue(true);
  const {result,rerender}=renderHook(({state,paused})=>useRedirectMonitor({state,paused,ready:true,check}),{initialProps:{state:base,paused:false}});
  act(()=>result.current.setEnabled(true));await tick();
  online.mockReturnValue(false);
  const added={...base,links:[...base.links,{...base.links[0],slug:'two'}]};
  rerender({state:added,paused:true});await tick();
  expect(check).toHaveBeenCalledTimes(1);
  rerender({state:base,paused:true});
  online.mockReturnValue(true);act(()=>window.dispatchEvent(new Event('online')));await tick();
  rerender({state:base,paused:false});await tick();
  expect(check).toHaveBeenCalledTimes(1);
  expect(result.current.pendingChanges).toBe(0);
  online.mockRestore();
});

it('hydrates the initial workspace without treating every existing link as a new addition',async()=>{
  localStorage.setItem('redirect-monitor-preview-enabled','true');
  localStorage.setItem('redirect-monitor-preview-enabled-completed-at','2026-10-17T00:00:00Z');
  const check=vi.fn(()=>Promise.resolve(report('passed')));
  const {rerender}=renderHook(({state,ready})=>useRedirectMonitor({state,paused:false,ready,check}),{initialProps:{state:{...base,links:[]} as State,ready:false}});
  rerender({state:base,ready:true});await tick();
  expect(check).not.toHaveBeenCalled();
});

it('reports success only after every current link has passed and no round is active',async()=>{
  const state={...base,links:[base.links[0],{...base.links[0],slug:'two'}]};
  let finish!:(value:RedirectCheck)=>void;
  const check=vi.fn().mockImplementationOnce(()=>Promise.resolve(report('passed')))
    .mockImplementationOnce(()=>new Promise<RedirectCheck>(resolve=>{finish=resolve;}));
  const {result}=renderHook(()=>useRedirectMonitor({state,paused:false,ready:true,check}));
  expect(result.current.resultStatus).toBe('unverified');
  act(()=>result.current.setEnabled(true));await tick(250);
  expect(result.current.active).toBe(true);
  expect(result.current.resultStatus).toBe('unverified');
  await act(async()=>finish(report('passed')));
  expect(result.current.resultStatus).toBe('healthy');
});

it('does not reuse success after busy or unknown, and recovers after a pass',async()=>{
  const check=vi.fn().mockImplementationOnce(()=>Promise.resolve(report('passed')))
    .mockImplementationOnce(()=>Promise.resolve(report('unknown','busy')))
    .mockImplementationOnce(()=>Promise.resolve(report('unknown')))
    .mockImplementation(()=>Promise.resolve(report('passed')));
  const {result}=renderHook(()=>useRedirectMonitor({state:base,paused:false,ready:true,check}));
  act(()=>result.current.setEnabled(true));await tick();
  expect(result.current.resultStatus).toBe('healthy');
  act(()=>result.current.runNow());await tick();
  expect(result.current.resultStatus).toBe('unverified');
  await tick(CONFIRM_DELAY_MS);
  expect(result.current.resultStatus).toBe('attention');
  act(()=>result.current.runNow());await tick();
  expect(result.current.resultStatus).toBe('healthy');
});

it('restores only a saved success and marks it stale or future-dated safely',async()=>{
  localStorage.setItem('redirect-monitor-preview-enabled','true');
  localStorage.setItem('redirect-monitor-preview-enabled-completed-at',new Date().toISOString());
  const check=vi.fn(()=>Promise.resolve(report('passed')));
  const first=renderHook(()=>useRedirectMonitor({state:base,paused:true,ready:true,check}));
  expect(first.result.current.resultStatus).toBe('healthy');
  await tick(STALE_AFTER_MS+60_000);
  expect(first.result.current.resultStatus).toBe('stale');
  first.unmount();
  localStorage.setItem('redirect-monitor-preview-enabled-completed-at','2027-01-01T00:00:00Z');
  const second=renderHook(()=>useRedirectMonitor({state:base,paused:true,ready:true,check}));
  expect(second.result.current.resultStatus).toBe('unverified');
});

it('invalidates success when configuration changes until the new identity passes',async()=>{
  let finish!:(value:RedirectCheck)=>void;
  const check=vi.fn().mockImplementationOnce(()=>Promise.resolve(report('passed')))
    .mockImplementationOnce(()=>new Promise<RedirectCheck>(resolve=>{finish=resolve;}));
  const {result,rerender}=renderHook(({state})=>useRedirectMonitor({state,paused:false,ready:true,check}),{initialProps:{state:base}});
  act(()=>result.current.setEnabled(true));await tick();
  expect(result.current.resultStatus).toBe('healthy');
  rerender({state:{...base,links:[{...base.links[0],updated:'changed'}]}});await tick();
  expect(result.current.resultStatus).toBe('unverified');
  await act(async()=>finish(report('passed')));
  expect(result.current.resultStatus).toBe('healthy');
});

it('does not persist a pass whose check time is in the future',async()=>{
  const check=vi.fn(()=>Promise.resolve({...report('passed'),checkedAt:'2027-01-01T00:00:00Z'}));
  const {result}=renderHook(()=>useRedirectMonitor({state:base,paused:false,ready:true,check}));
  act(()=>result.current.setEnabled(true));await tick();
  expect(result.current.resultStatus).toBe('stale');
  expect(localStorage.getItem('redirect-monitor-preview-enabled-completed-at')).toBeNull();
});

it('becomes healthy after a changed link replaces an obsolete first-round response',async()=>{
  const releases:Array<(value:RedirectCheck)=>void>=[];
  const check=vi.fn(()=>new Promise<RedirectCheck>(resolve=>releases.push(resolve)));
  const {result,rerender}=renderHook(({state})=>useRedirectMonitor({state,paused:false,ready:true,check}),{initialProps:{state:base}});
  act(()=>result.current.setEnabled(true));await tick();
  const edited={...base,links:[{...base.links[0],updated:'new'}]};
  rerender({state:edited});
  await act(async()=>releases.shift()!(report('passed')));await tick();
  expect(result.current.resultStatus).toBe('unverified');
  await act(async()=>releases.shift()!(report('passed')));
  expect(result.current.pendingChanges).toBe(0);
  expect(result.current.resultStatus).toBe('healthy');
});

it('becomes healthy when an unchecked link is removed during the first round',async()=>{
  const state={...base,links:[base.links[0],{...base.links[0],slug:'two'}]};
  let finish!:(value:RedirectCheck)=>void;
  const check=vi.fn(()=>new Promise<RedirectCheck>(resolve=>{finish=resolve;}));
  const {result,rerender}=renderHook(({snapshot})=>useRedirectMonitor({state:snapshot,paused:false,ready:true,check}),{initialProps:{snapshot:state}});
  act(()=>result.current.setEnabled(true));await tick();
  rerender({snapshot:base});
  await act(async()=>finish(report('passed')));await tick(250);
  expect(check).toHaveBeenCalledTimes(1);
  expect(result.current.active).toBe(false);
  expect(result.current.pendingChanges).toBe(0);
  expect(result.current.resultStatus).toBe('healthy');
  expect(result.current.lastCompletion).toBeNull();
  expect(localStorage.getItem('redirect-monitor-preview-enabled-completed-at')).toBeNull();
});

it('does not fill an interrupted new round with old healthy records after an edit',async()=>{
  const state={...base,links:[base.links[0],{...base.links[0],slug:'two'}]};
  let finish!:(value:RedirectCheck)=>void;
  const check=vi.fn().mockImplementationOnce(()=>Promise.resolve(report('passed')))
    .mockImplementationOnce(()=>Promise.resolve(report('passed')))
    .mockImplementationOnce(()=>new Promise<RedirectCheck>(resolve=>{finish=resolve;}));
  const {result,rerender}=renderHook(({snapshot,paused})=>useRedirectMonitor({state:snapshot,paused,ready:true,check}),{initialProps:{snapshot:state,paused:false}});
  act(()=>result.current.setEnabled(true));await tick(250);
  expect(result.current.resultStatus).toBe('healthy');
  act(()=>result.current.runNow());await tick();
  const edited={...state,links:[{...state.links[0],updated:'new'},state.links[1]]};
  rerender({snapshot:edited,paused:true});
  await act(async()=>finish(report('passed')));await tick();
  expect(result.current.active).toBe(false);
  expect(result.current.getRecord(state.links[1])?.phase).toBe('healthy');
  expect(result.current.resultStatus).toBe('unverified');
});

const threeLinks:State = {...base,links:[base.links[0],{...base.links[0],slug:'two'},{...base.links[0],slug:'three'}]};

it('keeps busy links in the round, backs off 1, 3 and 10 minutes, and completes only after they are checked',async()=>{
  expect(BUSY_BACKOFF_MS).toEqual([60_000,180_000,600_000]);
  let busyLeft=3;
  const check=vi.fn(async(_domainId:string,slug:string)=>slug==='two'&&busyLeft-->0?report('unknown','busy'):report('passed'));
  const {result}=renderHook(()=>useRedirectMonitor({state:threeLinks,paused:false,ready:true,check}));
  act(()=>result.current.setEnabled(true));await tick(250);
  const slugs=()=>check.mock.calls.map(call=>call[1]);
  expect(slugs()).toEqual(['one','two']);
  expect(result.current.lastCompletion).toBeNull();
  expect(result.current.waitingForBackend).toBe(true);
  expect(result.current.resultStatus).toBe('unverified');
  const wait=Date.parse(result.current.nextCheckAt!)-Date.now();
  expect(wait).toBeGreaterThan(0);
  expect(wait).toBeLessThanOrEqual(60_000);
  await tick(59_000);
  expect(slugs()).toEqual(['one','two']);
  await tick(1_000);
  expect(slugs()).toEqual(['one','two','two']);
  await tick(179_000);
  expect(slugs()).toHaveLength(3);
  await tick(1_000);
  expect(slugs()).toEqual(['one','two','two','two']);
  expect(result.current.lastCompletion).toBeNull();
  await tick(599_000);
  expect(slugs()).toHaveLength(4);
  await tick(1_000);await tick(250);
  expect(slugs()).toEqual(['one','two','two','two','two','three']);
  expect(result.current.waitingForBackend).toBe(false);
  expect(result.current.lastCompletion).not.toBeNull();
  expect(result.current.resultStatus).toBe('healthy');
  expect(localStorage.getItem('redirect-monitor-preview-enabled-completed-at')).not.toBeNull();
  // The round waited 14 minutes in total; the next one counts 48 hours from its start.
  const next=Date.parse(result.current.nextCheckAt!)-Date.now();
  const waited=BUSY_BACKOFF_MS.reduce((sum,value)=>sum+value,0);
  expect(next).toBeGreaterThan(MONITOR_INTERVAL_MS-waited-60_000);
  expect(next).toBeLessThanOrEqual(MONITOR_INTERVAL_MS-waited);
});

it('keeps a busy confirmation pending instead of dropping it',async()=>{
  const check=vi.fn().mockResolvedValueOnce(report('failed'))
    .mockResolvedValueOnce(report('unknown','busy'))
    .mockResolvedValueOnce(report('failed'));
  const {result}=renderHook(()=>useRedirectMonitor({state:base,paused:false,ready:true,check}));
  act(()=>result.current.setEnabled(true));await tick();
  expect(result.current.getRecord(base.links[0])?.phase).toBe('pending');
  await tick(CONFIRM_DELAY_MS);
  expect(check).toHaveBeenCalledTimes(2);
  expect(result.current.getRecord(base.links[0])?.phase).toBe('pending');
  await tick(BUSY_BACKOFF_MS[0]);
  expect(check).toHaveBeenCalledTimes(3);
  expect(result.current.getRecord(base.links[0])?.phase).toBe('alert');
});

it('lets a manual run skip the busy wait',async()=>{
  const check=vi.fn().mockResolvedValueOnce(report('unknown','busy')).mockResolvedValue(report('passed'));
  const {result}=renderHook(()=>useRedirectMonitor({state:base,paused:false,ready:true,check}));
  act(()=>result.current.setEnabled(true));await tick();
  expect(result.current.waitingForBackend).toBe(true);
  act(()=>result.current.runNow());await tick();
  expect(check).toHaveBeenCalledTimes(2);
  expect(result.current.lastCompletion).not.toBeNull();
});

it('resumes an interrupted full round from where it stopped instead of starting over',async()=>{
  let finish:((value:RedirectCheck)=>void)|null=null;
  let held=false;
  const check=vi.fn((_domainId:string,slug:string)=>{
    if(slug==='two'&&!held){held=true;return new Promise<RedirectCheck>(resolve=>{finish=resolve;});}
    return Promise.resolve(report('passed'));
  });
  const {result,rerender}=renderHook(({paused})=>useRedirectMonitor({state:threeLinks,paused,ready:true,check}),{initialProps:{paused:false}});
  act(()=>result.current.setEnabled(true));await tick(250);
  expect(check.mock.calls.map(call=>call[1])).toEqual(['one','two']);
  rerender({paused:true});
  await act(async()=>finish!(report('passed')));await tick();
  expect(result.current.lastCompletion).toBeNull();
  rerender({paused:false});await tick();
  expect(result.current.progress).toEqual({done:3,total:3});
  expect(check.mock.calls.map(call=>call[1])).toEqual(['one','two','three']);
  expect(result.current.lastCompletion).not.toBeNull();
  expect(result.current.resultStatus).toBe('healthy');
});

it('marks a restored healthy result as the previous run until this session checks again',async()=>{
  const saved='2026-10-16T12:00:00.000Z';
  localStorage.setItem('redirect-monitor-preview-enabled','true');
  localStorage.setItem('redirect-monitor-preview-enabled-completed-at',saved);
  const check=vi.fn(()=>Promise.resolve(report('passed')));
  const {result}=renderHook(()=>useRedirectMonitor({state:base,paused:false,ready:true,check}));
  await tick();
  expect(check).not.toHaveBeenCalled();
  expect(result.current.resultStatus).toBe('healthy');
  expect(result.current.previousRunAt).toBe(saved);
  act(()=>result.current.runNow());await tick();
  expect(result.current.resultStatus).toBe('healthy');
  expect(result.current.previousRunAt).toBeNull();
});

it('keeps a busy changed link queued and checks it after the wait',async()=>{
  const check=vi.fn().mockResolvedValueOnce(report('passed'))
    .mockResolvedValueOnce(report('unknown','busy'))
    .mockResolvedValue(report('passed'));
  const {result,rerender}=renderHook(({state})=>useRedirectMonitor({state,paused:false,ready:true,check}),{initialProps:{state:base}});
  act(()=>result.current.setEnabled(true));await tick();
  const edited={...base,links:[{...base.links[0],updated:'u2'}]};
  rerender({state:edited});await tick();
  expect(check).toHaveBeenCalledTimes(2);
  expect(result.current.pendingChanges).toBe(1);
  await tick(BUSY_BACKOFF_MS[0]-1_000);
  expect(check).toHaveBeenCalledTimes(2);
  await tick(1_000);
  expect(check).toHaveBeenCalledTimes(3);
  expect(result.current.pendingChanges).toBe(0);
  expect(result.current.getRecord(edited.links[0])?.phase).toBe('healthy');
});

it('schedules the round after a resumed one from when that round started, so its early results are rechecked before they expire',async()=>{
  let finish:((value:RedirectCheck)=>void)|null=null;
  let held=false;
  const check=vi.fn((_domainId:string,slug:string)=>{
    if(slug==='two'&&!held){held=true;return new Promise<RedirectCheck>(resolve=>{finish=resolve;});}
    return Promise.resolve(report('passed'));
  });
  const {result,rerender}=renderHook(({paused})=>useRedirectMonitor({state:threeLinks,paused,ready:true,check}),{initialProps:{paused:false}});
  act(()=>result.current.setEnabled(true));await tick(250);
  rerender({paused:true});
  await act(async()=>finish!(report('passed')));
  const pausedFor=60*60_000;
  await tick(pausedFor);
  rerender({paused:false});await tick(250);
  expect(check.mock.calls.map(call=>call[1])).toEqual(['one','two','three']);
  expect(result.current.lastCompletion).not.toBeNull();
  const wait=Date.parse(result.current.nextCheckAt!)-Date.now();
  expect(wait).toBeGreaterThan(MONITOR_INTERVAL_MS-pausedFor-60_000);
  expect(wait).toBeLessThanOrEqual(MONITOR_INTERVAL_MS-pausedFor);
  await tick(wait);
  expect(result.current.getRecord(threeLinks.links[0])?.stale).toBe(false);
  await tick(1_000);
  expect(check.mock.calls.map(call=>call[1])).toEqual(['one','two','three','one','two','three']);
  expect(Date.parse(result.current.nextCheckAt!)-Date.now()).toBeGreaterThan(MONITOR_INTERVAL_MS-60_000);
});

it('treats the three worker failure reasons as ordinary failures and keeps the backend text',async()=>{
  for(const reason of ['worker_pool_missing','worker_no_candidate','worker_internal']){
    const message=`访客现在打不开这条链接（${reason}）`;
    const check=vi.fn(async():Promise<RedirectCheck>=>({...report('failed',reason),message}));
    const {result,unmount}=renderHook(()=>useRedirectMonitor({state:base,paused:false,ready:true,check}));
    act(()=>result.current.setEnabled(true));await tick();
    expect(result.current.getRecord(base.links[0])).toMatchObject({phase:'pending',message});
    await tick(CONFIRM_DELAY_MS);
    expect(result.current.getRecord(base.links[0])).toMatchObject({phase:'alert',message,unresolvedAlert:true});
    expect(result.current.waitingForBackend).toBe(false);
    unmount();localStorage.clear();
  }
});
