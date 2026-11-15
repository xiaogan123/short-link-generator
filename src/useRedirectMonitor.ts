import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { dispatch, preview } from './bridge';
import type { Domain, Link, Pool, RedirectCheck, State } from './types';

export const MONITOR_INTERVAL_MS = 48 * 60 * 60_000;
export const CONFIRM_DELAY_MS = 60_000;
export const STALE_AFTER_MS = MONITOR_INTERVAL_MS + 5 * 60_000;
const SPACING_MS = 250;
/** Waits after a "backend busy" reply: 1, 3, then every 10 minutes. */
export const BUSY_BACKOFF_MS = [60_000, 3 * 60_000, 10 * 60_000] as const;
const preferenceKey = preview ? 'redirect-monitor-preview-enabled' : 'redirect-monitor-enabled';
const completionKey = `${preferenceKey}-completed-at`;

type Phase = 'healthy' | 'pending' | 'alert' | 'attention';
export type MonitorRecord = { identity:string; phase:Phase; checkedAt:string; message:string; dnsMode:'system'|'public'; failures:number; unresolvedAlert:boolean };
export type VisibleMonitorRecord = MonitorRecord & { stale:boolean };
export type MonitorSummary = {alert:number;unresolved:number;attention:number};
export type MonitorResultStatus = 'healthy' | 'attention' | 'stale' | 'unverified';
type CheckFn = (domainId:string, slug:string) => Promise<RedirectCheck>;
type Options = {state:State; paused:boolean; ready:boolean; check?:CheckFn};
type RunKind = 'full' | 'changed' | 'confirm';
type IndexedLink = {link:Link;identity:string;domain?:Domain};

export function monitorKey(link:Link) { return JSON.stringify([link.domainId, link.slug]); }
function domainIdentity(domain?:Domain) {
  return domain && [domain.id,domain.accountId,domain.zoneId,domain.host,domain.prefix,domain.routeId];
}
function poolIdentity(pool?:Pool) {
  return pool && [pool.updated,pool.official,pool.candidates.filter(item => item.enabled).map(item => [item.id,item.prefix,item.suffix])];
}
function linkIdentity(link:Link, domain:unknown, pool:unknown) {
  return JSON.stringify([domain,link.domainId,link.slug,link.updated,link.poolId,link.code,link.cnUrl,link.defaultUrl,pool]);
}
export function monitorIdentity(link:Link, state:State):string {
  return linkIdentity(link,domainIdentity(state.domains.find(item => item.id === link.domainId)),poolIdentity(state.pools?.find(item => item.id === link.poolId)));
}
function indexState(state:State) {
  const domains = new Map(state.domains.map(domain => [domain.id,domain]));
  const domainIdentities = new Map(state.domains.map(domain => [domain.id,domainIdentity(domain)]));
  const poolIdentities = new Map(state.pools?.map(pool => [pool.id,poolIdentity(pool)]));
  return new Map(state.links.map(link => [monitorKey(link),{
    link,domain:domains.get(link.domainId),identity:linkIdentity(link,domainIdentities.get(link.domainId),poolIdentities.get(link.poolId || '')),
  }] satisfies [string,IndexedLink]));
}
function readPreference():boolean { try { return window.localStorage.getItem(preferenceKey) === 'true'; } catch { return false; } }
function writePreference(value:boolean) { try { window.localStorage.setItem(preferenceKey, String(value)); } catch { /* Session choice still works. */ } }
// Persist only a completion timestamp, never identities, URLs, reports or a timer clock.
function readCompletion():string|null {
  try {
    const value = window.localStorage.getItem(completionKey);
    const time = value ? Date.parse(value) : NaN;
    return Number.isFinite(time) && time <= Date.now() ? new Date(time).toISOString() : null;
  } catch { return null; }
}
function writeCompletion(value:string|null) {
  try {
    if (value === null) window.localStorage.removeItem(completionKey);
    else window.localStorage.setItem(completionKey,value);
  } catch { /* Scheduling still works for this session. */ }
}
function validReport(value:unknown):value is RedirectCheck {
  if (!value || typeof value !== 'object') return false;
  const item = value as Partial<RedirectCheck>;
  return (item.status === 'passed' || item.status === 'failed' || item.status === 'unknown') &&
    typeof item.message === 'string' && typeof item.checkedAt === 'string' && Number.isFinite(Date.parse(item.checkedAt)) &&
    (item.dnsMode === 'system' || item.dnsMode === 'public');
}
const defaultCheck:CheckFn = (domainId,slug) => dispatch<RedirectCheck>('check_link_redirect',{domainId,slug});

export function useRedirectMonitor({state,paused,ready,check = defaultCheck}:Options) {
  const [enabled,setEnabledState] = useState(readPreference);
  const [records,setRecords] = useState<Record<string,MonitorRecord>>({});
  const [active,setActive] = useState(false);
  const [runKind,setRunKind] = useState<RunKind>('full');
  const [progress,setProgress] = useState({done:0,total:0});
  const [lastCompletion,setLastCompletion] = useState<string|null>(readCompletion);
  const restoredSuccess = useRef(lastCompletion);
  const restoredAge = useRef(lastCompletion ? Math.max(0,Date.now() - Date.parse(lastCompletion)) : Infinity);
  const incompleteRound = useRef(false);
  const roundRemaining = useRef(new Map<string,string>());
  const busyResults = useRef(new Set<string>());
  // A paused or busy-blocked full round resumes from roundRemaining.
  const resumeRound = useRef(false);
  const roundTotal = useRef(0);
  const roundAllPassed = useRef(true);
  // When the current round began, and whether it was continued after a stop.
  const roundStartedAt = useRef(0);
  const roundResumed = useRef(false);
  const busyUntil = useRef(0);
  const busyStreak = useRef(0);
  const busyTimer = useRef<number|undefined>(undefined);
  const [clockView,setClockView] = useState({elapsed:0,wall:Date.now()});
  const clock = useRef({elapsed:0,wall:Date.now(),monotonic:performance.now()});
  const indexed = useMemo(() => indexState(state),[state.links,state.domains,state.pools]);
  const indexRef = useRef(indexed);
  const previousScope = useRef<Map<string,IndexedLink>|null>(null);
  const checkRef = useRef(check);
  const gateRef = useRef({enabled,paused,ready});
  const recordsRef = useRef(records);
  const recordTimes = useRef(new Map<string,{identity:string;at:number;age:number}>());
  const mounted = useRef(true);
  const running = useRef(false);
  const dueAt = useRef(lastCompletion ? Math.max(0,Date.parse(lastCompletion) + MONITOR_INTERVAL_MS - Date.now()) : 0);
  const revision = useRef(0);
  const scopeRevision = useRef(0);
  const requestSequence = useRef<Record<string,number>>({});
  const changed = useRef(new Map<string,string>());
  const confirmations = useRef(new Map<string,{identity:string;due:number}>());
  const confirmationTimers = useRef(new Map<string,number>());
  const drainRef = useRef<() => Promise<void>>(async () => {});
  indexRef.current = indexed;
  checkRef.current = check;
  gateRef.current = {enabled,paused,ready};
  recordsRef.current = records;

  // Wall time catches sleep even on systems whose monotonic clock stops asleep.
  // Monotonic time prevents wall-clock rollback from extending a deadline.
  // Forward jumps conservatively make work due; neither source can reduce age.
  const sampleClock = () => {
    const wall = Date.now();
    const monotonic = performance.now();
    const elapsed = clock.current.elapsed + Math.max(0,wall - clock.current.wall,monotonic - clock.current.monotonic);
    clock.current = {elapsed,wall,monotonic};
    return {elapsed,wall};
  };
  const isOnline = () => typeof navigator === 'undefined' || navigator.onLine !== false;
  const canStart = () => mounted.current && gateRef.current.enabled && gateRef.current.ready && !gateRef.current.paused && isOnline();
  const currentIdentity = (key:string) => indexRef.current.get(key)?.identity;
  const save = (key:string,record:MonitorRecord) => {
    if (!mounted.current) return;
    const at = sampleClock();
    recordTimes.current.set(key,{identity:record.identity,at:at.elapsed,age:Math.max(0,at.wall - Date.parse(record.checkedAt))});
    const next = {...recordsRef.current,[key]:record};
    recordsRef.current = next;
    setRecords(next);
    setClockView(at);
  };
  const clearConfirmation = (key:string) => {
    const timer = confirmationTimers.current.get(key);
    if (timer !== undefined) window.clearTimeout(timer);
    confirmationTimers.current.delete(key);
    confirmations.current.delete(key);
  };
  const confirmLater = (key:string,identity:string) => {
    confirmations.current.set(key,{identity,due:sampleClock().elapsed + CONFIRM_DELAY_MS});
    confirmationTimers.current.set(key,window.setTimeout(() => {
      confirmationTimers.current.delete(key);
      void drainRef.current();
    },CONFIRM_DELAY_MS));
  };

  const backingOff = () => busyUntil.current > sampleClock().elapsed;
  const clearBusyWait = () => {
    if (busyTimer.current !== undefined) window.clearTimeout(busyTimer.current);
    busyTimer.current = undefined;
    busyUntil.current = 0;
  };
  // The backend lock is shared by every check, so one busy reply pauses all work.
  const backOff = () => {
    const delay = BUSY_BACKOFF_MS[Math.min(busyStreak.current,BUSY_BACKOFF_MS.length - 1)];
    busyStreak.current++;
    clearBusyWait();
    busyUntil.current = sampleClock().elapsed + delay;
    busyTimer.current = window.setTimeout(() => {
      busyTimer.current = undefined;
      if (mounted.current) setClockView(sampleClock());
      void drainRef.current();
    },delay);
  };

  // 'busy' means not checked: the caller keeps the link queued for this round.
  const checkOne = async (key:string, expectedIdentity:string, confirm:boolean):Promise<boolean|null|'busy'> => {
    if (!canStart() || currentIdentity(key) !== expectedIdentity) return null;
    const entry = indexRef.current.get(key)!;
    const seq = (requestSequence.current[key] || 0) + 1;
    requestSequence.current[key] = seq;
    const runRevision = revision.current;
    let result:RedirectCheck;
    if (!entry.domain) result = {status:'unknown',message:'对应域名已不存在。',reason:'domain_missing',checkedAt:new Date().toISOString(),dnsMode:'system'};
    else {
      try { result = await checkRef.current(entry.link.domainId,entry.link.slug); }
      catch (error) { result = {status:'unknown',message:error instanceof Error ? error.message : '巡检暂时无法完成。',reason:'request_failed',checkedAt:new Date().toISOString(),dnsMode:'system'}; }
    }
    if (!mounted.current || !gateRef.current.enabled || revision.current !== runRevision || requestSequence.current[key] !== seq || currentIdentity(key) !== expectedIdentity) return null;
    if (!validReport(result)) result = {status:'unknown',message:'巡检返回内容无效。',reason:'invalid_report',checkedAt:new Date().toISOString(),dnsMode:'system'};
    if (result.status !== 'passed') { writeCompletion(null); restoredSuccess.current = null; }
    if (result.reason === 'busy') {
      busyResults.current.add(key);
      backOff();
      if (confirm) confirmations.current.set(key,{identity:expectedIdentity,due:busyUntil.current});
      return 'busy';
    }
    busyResults.current.delete(key);
    busyStreak.current = 0;
    const previous = recordsRef.current[key];
    const same = previous?.identity === expectedIdentity ? previous : undefined;
    let phase:Phase;
    let failures = 0;
    let unresolvedAlert = false;
    if (result.status === 'passed') phase = 'healthy';
    else if (result.status === 'unknown') {
      phase = 'attention';
      unresolvedAlert = Boolean(same?.unresolvedAlert);
    } else {
      failures = same?.unresolvedAlert || confirm && same?.phase === 'pending' && same.failures === 1 ? 2 : 1;
      phase = failures === 2 ? 'alert' : 'pending';
      unresolvedAlert = phase === 'alert';
    }
    save(key,{identity:expectedIdentity,phase,checkedAt:result.checkedAt,message:result.message,dnsMode:result.dnsMode,failures,unresolvedAlert});
    clearConfirmation(key);
    if (phase === 'pending') confirmLater(key,expectedIdentity);
    return result.status === 'passed';
  };
  const hasWork = () => {
    if (backingOff()) return false;
    const time = sampleClock().elapsed;
    return (indexRef.current.size > 0 && dueAt.current <= time) || changed.current.size > 0
      || [...confirmations.current.values()].some(item => item.due <= time);
  };

  drainRef.current = async () => {
    if (running.current || !canStart() || !hasWork()) return;
    running.current = true;
    setActive(true);
    try {
      const runDueConfirmations = async () => {
        for (const [key,item] of [...confirmations.current]) {
          if (!canStart() || backingOff()) return;
          if (item.due > sampleClock().elapsed) continue;
          clearConfirmation(key);
          setRunKind('confirm');
          await checkOne(key,item.identity,true);
        }
      };
      await runDueConfirmations();
      if (!canStart() || backingOff()) return;
      const full = indexRef.current.size > 0 && dueAt.current <= sampleClock().elapsed;
      // Resume an interrupted round with only the links it has not checked yet.
      const resume = full && resumeRound.current && incompleteRound.current && roundRemaining.current.size > 0;
      const items = !full ? [...changed.current]
        : resume ? [...roundRemaining.current]
          : [...indexRef.current].map(([key,item]) => [key,item.identity] as const);
      if (!items.length) return;
      if (full) {
        if (!resume) {
          incompleteRound.current = true;
          roundRemaining.current = new Map(items);
          roundTotal.current = items.length;
          roundAllPassed.current = true;
          roundStartedAt.current = sampleClock().elapsed;
        }
        roundResumed.current = resume;
        resumeRound.current = false;
        restoredSuccess.current = null;
        dueAt.current = sampleClock().elapsed + MONITOR_INTERVAL_MS;
        writeCompletion(null);
      }
      const cycleRevision = revision.current;
      const cycleScope = scopeRevision.current;
      const offset = resume ? Math.max(0,roundTotal.current - items.length) : 0;
      const total = offset + items.length;
      // An interrupted full round stays due and continues where it stopped.
      const interrupt = () => { if (full) { dueAt.current = 0; resumeRound.current = true; } };
      setRunKind(full ? 'full' : 'changed');
      setProgress({done:offset,total});
      let done = 0;
      for (const [key,identity] of items) {
        if (!canStart() || revision.current !== cycleRevision || backingOff()) { interrupt(); break; }
        await runDueConfirmations();
        if (!canStart() || revision.current !== cycleRevision || backingOff()) { interrupt(); break; }
        setRunKind(full ? 'full' : 'changed');
        const passed = await checkOne(key,identity,false);
        // Busy is not checked: keep it in this round and in the changed queue.
        if (passed === 'busy') { interrupt(); break; }
        if (passed !== null && currentIdentity(key) === identity && roundRemaining.current.get(key) === identity) roundRemaining.current.delete(key);
        if (full) roundAllPassed.current = roundAllPassed.current && passed === true;
        if (changed.current.get(key) === identity && (passed !== null || currentIdentity(key) !== identity)) changed.current.delete(key);
        if (!canStart() || revision.current !== cycleRevision) { interrupt(); break; }
        done++;
        if (mounted.current) setProgress({done:offset + done,total});
        if (done < items.length) await new Promise<void>(resolve => window.setTimeout(resolve,SPACING_MS));
      }
      if (full && done === items.length && roundRemaining.current.size === 0 && canStart() && revision.current === cycleRevision && scopeRevision.current === cycleScope) {
        incompleteRound.current = false;
        const completedAt = new Date().toISOString();
        setLastCompletion(completedAt);
        // A continued round holds results from before the stop. Count the next
        // 48 hours from its start so they are rechecked before they expire.
        dueAt.current = (roundResumed.current ? roundStartedAt.current : sampleClock().elapsed) + MONITOR_INTERVAL_MS;
        const allHealthy = roundAllPassed.current && confirmations.current.size === 0 && changed.current.size === 0 && [...indexRef.current].every(([key,item]) => {
          const record = recordsRef.current[key];
          const time = recordTimes.current.get(key);
          const now = sampleClock();
          return record?.identity === item.identity && record.phase === 'healthy' &&
            Date.parse(record.checkedAt) <= now.wall && !!time && time.age + Math.max(0,now.elapsed - time.at) <= STALE_AFTER_MS;
        });
        writeCompletion(allHealthy ? completedAt : null);
      }
      if (done === items.length && canStart() && revision.current === cycleRevision &&
          roundRemaining.current.size === 0 && changed.current.size === 0 &&
          previousScope.current?.size === indexRef.current.size &&
          [...indexRef.current].every(([key,item]) => previousScope.current?.get(key)?.identity === item.identity)) incompleteRound.current = false;
    } finally {
      running.current = false;
      if (mounted.current) { setActive(false); setClockView(sampleClock()); }
      if (canStart() && hasWork()) void drainRef.current();
    }
  };

  const setEnabled = useCallback((value:boolean) => {
    writePreference(value);
    if (!value) {
      restoredSuccess.current = null;
      incompleteRound.current = false;
      resumeRound.current = false;
      roundRemaining.current.clear();
      busyResults.current.clear();
      busyStreak.current = 0;
      clearBusyWait();
      writeCompletion(null);
      revision.current++;
      for (const key of [...confirmations.current.keys()]) clearConfirmation(key);
      changed.current.clear();
      recordTimes.current.clear();
      recordsRef.current = {};
      setRecords({});
    }
    dueAt.current = 0;
    gateRef.current.enabled = value;
    setEnabledState(value);
    if (value) window.setTimeout(() => void drainRef.current(),0);
  },[]);
  const runNow = useCallback(() => { if (!running.current && canStart()) { dueAt.current = 0; clearBusyWait(); void drainRef.current(); } },[]);

  useEffect(() => {
    mounted.current = true;
    const tick = () => { setClockView(sampleClock()); void drainRef.current(); };
    const interval = window.setInterval(tick,60_000);
    window.addEventListener('online',tick);
    window.addEventListener('offline',tick);
    window.addEventListener('focus',tick);
    document.addEventListener('visibilitychange',tick);
    return () => {
      mounted.current = false;
      revision.current++;
      window.clearInterval(interval);
      window.removeEventListener('online',tick);
      window.removeEventListener('offline',tick);
      window.removeEventListener('focus',tick);
      document.removeEventListener('visibilitychange',tick);
      for (const timer of confirmationTimers.current.values()) window.clearTimeout(timer);
      confirmationTimers.current.clear();
      clearBusyWait();
      confirmations.current.clear();
    };
  },[]);
  useEffect(() => {
    if (!ready) return;
    const previous = previousScope.current;
    previousScope.current = indexed;
    let scopeChanged = false;
    if (previous) {
      scopeChanged = previous.size !== indexed.size || [...indexed].some(([key,item]) => previous.get(key)?.identity !== item.identity);
      if (scopeChanged) {
        restoredSuccess.current = null;
        scopeRevision.current++;
        writeCompletion(null);
        if (incompleteRound.current) {
          for (const [key,identity] of roundRemaining.current) if (indexed.get(key)?.identity !== identity) roundRemaining.current.delete(key);
          for (const [key,item] of indexed) if (previous.get(key)?.identity !== item.identity) roundRemaining.current.set(key,item.identity);
        }
        if (enabled) for (const [key,item] of indexed) if (previous.get(key)?.identity !== item.identity) changed.current.set(key,item.identity);
      }
    }
    for (const [key,item] of confirmations.current) if (currentIdentity(key) !== item.identity) clearConfirmation(key);
    for (const [key,identity] of changed.current) if (currentIdentity(key) !== identity) changed.current.delete(key);
    for (const [key,item] of recordTimes.current) if (currentIdentity(key) !== item.identity) recordTimes.current.delete(key);
    for (const key of busyResults.current) if (!indexed.has(key) || previous?.get(key)?.identity !== indexed.get(key)?.identity) busyResults.current.delete(key);
    const next = Object.fromEntries(Object.entries(recordsRef.current).filter(([key,item]) => currentIdentity(key) === item.identity));
    if (Object.keys(next).length !== Object.keys(recordsRef.current).length) { recordsRef.current = next; setRecords(next); }
    if (scopeChanged && enabled) void drainRef.current();
  },[indexed,ready,enabled]);
  useEffect(() => { if (enabled && ready && !paused) void drainRef.current(); },[enabled,ready,paused]);

  const getRecord = (link:Link):VisibleMonitorRecord|null => {
    if (!enabled) return null;
    const key = monitorKey(link);
    const record = records[key];
    if (!record || record.identity !== indexed.get(key)?.identity) return null;
    const time = recordTimes.current.get(key);
    const age = time ? time.age + Math.max(0,clockView.elapsed - time.at) : Infinity;
    return {...record,stale:Date.parse(record.checkedAt) > clockView.wall || age > STALE_AFTER_MS};
  };
  const summary = useMemo(() => {
    const sum:MonitorSummary = {alert:0,unresolved:0,attention:0};
    if (!enabled) return sum;
    for (const [key,record] of Object.entries(records)) {
      if (record.identity !== indexed.get(key)?.identity) continue;
      const time = recordTimes.current.get(key);
      const stale = Date.parse(record.checkedAt) > clockView.wall || !time || time.age + Math.max(0,clockView.elapsed - time.at) > STALE_AFTER_MS;
      if (record.unresolvedAlert) {
        if (record.phase === 'alert' && !stale) sum.alert++;
        else sum.unresolved++;
      } else if (record.phase === 'attention' || record.phase === 'pending' || stale) sum.attention++;
    }
    return sum;
  },[records,indexed,enabled,clockView]);
  const scopePending = previousScope.current !== null && (previousScope.current.size !== indexed.size ||
    [...indexed].some(([key,item]) => previousScope.current?.get(key)?.identity !== item.identity));
  let resultStatus:MonitorResultStatus = 'unverified';
  let previousRunAt:string|null = null;
  if (enabled && ready && indexed.size && !active && !running.current && !scopePending && !changed.current.size && !incompleteRound.current) {
    const current = [...indexed].map(([key,item]) => ({key,item,record:records[key],time:recordTimes.current.get(key)}));
    if (current.some(({record,item}) => record?.identity === item.identity && record.phase !== 'healthy')) resultStatus = 'attention';
    else if (!busyResults.current.size && current.every(({record,item}) => record?.identity === item.identity && record.phase === 'healthy')) {
      resultStatus = current.some(({record,time}) => !time || Date.parse(record!.checkedAt) > clockView.wall || time.age + Math.max(0,clockView.elapsed - time.at) > STALE_AFTER_MS) ? 'stale' : 'healthy';
    } else if (!busyResults.current.size && !current.some(({record}) => record) && restoredSuccess.current && !confirmations.current.size) {
      const timestamp = Date.parse(restoredSuccess.current);
      previousRunAt = restoredSuccess.current;
      resultStatus = timestamp > clockView.wall ? 'unverified' : Math.max(clockView.wall - timestamp,restoredAge.current + clockView.elapsed) > STALE_AFTER_MS ? 'stale' : 'healthy';
    }
  }
  const waitingForBackend = enabled && busyUntil.current > clockView.elapsed;
  const nextDue = Math.max(busyUntil.current,Math.min(changed.current.size ? clockView.elapsed : Infinity,dueAt.current,...[...confirmations.current.values()].map(item => item.due)));
  const nextCheckAt = enabled && indexed.size > 0 ? new Date(clockView.wall + Math.max(0,nextDue - clockView.elapsed)).toISOString() : null;
  return {enabled,setEnabled,runNow,active,runKind,progress,lastCompletion,nextCheckAt,getRecord,summary,resultStatus,previousRunAt,waitingForBackend,online:isOnline(),ready,pendingChanges:changed.current.size,totalLinks:indexed.size};
}
