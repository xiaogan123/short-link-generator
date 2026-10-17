import { useCallback, useEffect, useRef, useState } from 'react';
import { dispatch, preview } from './bridge';
import type { Link, RedirectCheck, State } from './types';

export const MONITOR_INTERVAL_MS = 30 * 60_000;
export const CONFIRM_DELAY_MS = 60_000;
export const STALE_AFTER_MS = 65 * 60_000;
const SPACING_MS = 250;
const preferenceKey = preview ? 'redirect-monitor-preview-enabled' : 'redirect-monitor-enabled';

type Phase = 'healthy' | 'pending' | 'alert' | 'attention';
export type MonitorRecord = { identity:string; phase:Phase; checkedAt:string; message:string; dnsMode:'system'|'public'; failures:number; unresolvedAlert:boolean };
export type VisibleMonitorRecord = MonitorRecord & { stale:boolean };
export type MonitorSummary = {alert:number;unresolved:number;attention:number};
type CheckFn = (domainId:string, slug:string) => Promise<RedirectCheck>;
type Options = {state:State; paused:boolean; ready:boolean; check?:CheckFn};

export function monitorKey(link:Link) { return JSON.stringify([link.domainId, link.slug]); }
export function monitorIdentity(link:Link, state:State):string {
  const domain = state.domains.find(item => item.id === link.domainId);
  const pool = state.pools?.find(item => item.id === link.poolId);
  return JSON.stringify([
    domain?.id, domain?.accountId, domain?.zoneId, domain?.host, domain?.prefix, domain?.routeId,
    link.domainId, link.slug, link.updated, link.poolId, link.code, link.cnUrl, link.defaultUrl,
    pool?.updated, pool?.official, pool?.candidates.filter(item => item.enabled).map(item => [item.id,item.prefix,item.suffix]),
  ]);
}
function readPreference():boolean { try { return window.localStorage.getItem(preferenceKey) === 'true'; } catch { return false; } }
function writePreference(value:boolean) { try { window.localStorage.setItem(preferenceKey, String(value)); } catch { /* Private or unavailable storage: session choice still works. */ } }
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
  const [progress,setProgress] = useState({done:0,total:0});
  const [lastCompletion,setLastCompletion] = useState<string|null>(null);
  const [now,setNow] = useState(Date.now());
  const stateRef = useRef(state);
  const checkRef = useRef(check);
  const gateRef = useRef({enabled,paused,ready});
  const recordsRef = useRef(records);
  const mounted = useRef(true);
  const running = useRef(false);
  const dueAt = useRef(0);
  const revision = useRef(0);
  const requestSequence = useRef<Record<string,number>>({});
  const busyRetries = useRef<Record<string,number>>({});
  const confirmations = useRef(new Map<string,{identity:string;due:number}>());
  const confirmationTimers = useRef(new Map<string,number>());
  stateRef.current = state;
  checkRef.current = check;
  gateRef.current = {enabled,paused,ready};
  recordsRef.current = records;

  const isOnline = () => typeof navigator === 'undefined' || navigator.onLine !== false;
  const canStart = () => mounted.current && gateRef.current.enabled && gateRef.current.ready && !gateRef.current.paused && isOnline();
  const currentIdentity = (key:string) => {
    const link = stateRef.current.links.find(item => monitorKey(item) === key);
    return link ? monitorIdentity(link,stateRef.current) : null;
  };
  const save = (key:string,record:MonitorRecord) => {
    if (!mounted.current) return;
    const next = {...recordsRef.current,[key]:record};
    recordsRef.current = next;
    setRecords(next);
  };
  const clearConfirmation = (key:string) => {
    const timer = confirmationTimers.current.get(key);
    if (timer !== undefined) window.clearTimeout(timer);
    confirmationTimers.current.delete(key);
    confirmations.current.delete(key);
  };

  const checkOne = async (key:string, expectedIdentity:string, confirm:boolean):Promise<void> => {
    if (!canStart() || currentIdentity(key) !== expectedIdentity) return;
    const link = stateRef.current.links.find(item => monitorKey(item) === key);
    if (!link) return;
    const domain = stateRef.current.domains.find(item => item.id === link.domainId);
    const seq = (requestSequence.current[key] || 0) + 1;
    requestSequence.current[key] = seq;
    const runRevision = revision.current;
    let result:RedirectCheck;
    if (!domain) result = {status:'unknown',message:'对应域名已不存在。',reason:'domain_missing',checkedAt:new Date().toISOString(),dnsMode:'system'};
    else {
      try { result = await checkRef.current(link.domainId,link.slug); }
      catch (error) { result = {status:'unknown',message:error instanceof Error ? error.message : '巡检暂时无法完成。',reason:'request_failed',checkedAt:new Date().toISOString(),dnsMode:'system'}; }
    }
    if (!mounted.current || !gateRef.current.enabled || revision.current !== runRevision || requestSequence.current[key] !== seq || currentIdentity(key) !== expectedIdentity) return;
    if (!validReport(result)) result = {status:'unknown',message:'巡检返回内容无效。',reason:'invalid_report',checkedAt:new Date().toISOString(),dnsMode:'system'};
    if (result.reason === 'busy') {
      clearConfirmation(key);
      if ((busyRetries.current[key] || 0) < 1) {
        busyRetries.current[key] = 1;
        const due = Date.now() + CONFIRM_DELAY_MS;
        confirmations.current.set(key,{identity:expectedIdentity,due});
        confirmationTimers.current.set(key,window.setTimeout(() => { confirmationTimers.current.delete(key); void drainRef.current(); },CONFIRM_DELAY_MS));
      }
      return;
    }
    busyRetries.current[key] = 0;
    const previous = recordsRef.current[key];
    const same = previous?.identity === expectedIdentity ? previous : undefined;
    let phase:Phase;
    let failures = 0;
    let unresolvedAlert = false;
    if (result.status === 'passed') phase = 'healthy';
    else if (result.status === 'unknown') {
      phase = 'attention';
      unresolvedAlert = Boolean(same?.unresolvedAlert);
    }
    else {
      failures = same?.unresolvedAlert || confirm && same?.phase === 'pending' && same.failures === 1 ? 2 : 1;
      phase = failures === 2 ? 'alert' : 'pending';
      unresolvedAlert = phase === 'alert';
    }
    save(key,{identity:expectedIdentity,phase,checkedAt:result.checkedAt,message:result.message,dnsMode:result.dnsMode,failures,unresolvedAlert});
    clearConfirmation(key);
    if (phase === 'pending') {
      const due = Date.now() + CONFIRM_DELAY_MS;
      confirmations.current.set(key,{identity:expectedIdentity,due});
      confirmationTimers.current.set(key,window.setTimeout(() => { confirmationTimers.current.delete(key); void drainRef.current(); },CONFIRM_DELAY_MS));
    }
  };

  const drainRef = useRef<() => Promise<void>>(async () => {});
  drainRef.current = async () => {
    if (running.current || !canStart()) return;
    running.current = true;
    setActive(true);
    try {
      const runDueConfirmations = async () => {
        for (const [key,item] of [...confirmations.current]) {
          if (!canStart()) return;
          if (item.due > Date.now()) continue;
          clearConfirmation(key);
          await checkOne(key,item.identity,true);
        }
      };
      await runDueConfirmations();
      if (canStart() && dueAt.current <= Date.now()) {
        dueAt.current = Date.now() + MONITOR_INTERVAL_MS;
        busyRetries.current = {};
        const cycleRevision = revision.current;
        const items = stateRef.current.links.map(link => [monitorKey(link),monitorIdentity(link,stateRef.current)] as const);
        setProgress({done:0,total:items.length});
        let done = 0;
        for (const [key,identity] of items) {
          if (!canStart() || revision.current !== cycleRevision) { dueAt.current = 0; break; }
          await runDueConfirmations();
          if (!canStart() || revision.current !== cycleRevision) { dueAt.current = 0; break; }
          await checkOne(key,identity,false);
          done++;
          if (mounted.current) setProgress({done,total:items.length});
          if (done < items.length) await new Promise<void>(resolve => window.setTimeout(resolve,SPACING_MS));
        }
        if (done === items.length && mounted.current) setLastCompletion(new Date().toISOString());
      }
    } finally {
      running.current = false;
      if (mounted.current) setActive(false);
      if (canStart() && (dueAt.current <= Date.now() || [...confirmations.current.values()].some(item => item.due <= Date.now()))) void drainRef.current();
    }
  };

  const setEnabled = useCallback((value:boolean) => {
    writePreference(value);
    if (!value) {
      revision.current++;
      for (const key of [...confirmations.current.keys()]) clearConfirmation(key);
      dueAt.current = 0;
      recordsRef.current = {};
      setRecords({});
    } else dueAt.current = 0;
    gateRef.current.enabled = value;
    setEnabledState(value);
    if (value) window.setTimeout(() => void drainRef.current(),0);
  },[]);
  const runNow = useCallback(() => { if (!running.current && canStart()) { dueAt.current = 0; void drainRef.current(); } },[]);

  useEffect(() => {
    mounted.current = true;
    const tick = () => { setNow(Date.now()); void drainRef.current(); };
    const interval = window.setInterval(tick,60_000);
    window.addEventListener('online',tick);
    return () => {
      mounted.current = false;
      revision.current++;
      window.clearInterval(interval);
      window.removeEventListener('online',tick);
      for (const timer of confirmationTimers.current.values()) window.clearTimeout(timer);
      confirmationTimers.current.clear();
      confirmations.current.clear();
    };
  },[]);
  useEffect(() => { if (enabled && ready && !paused) void drainRef.current(); },[enabled,ready,paused]);
  useEffect(() => {
    for (const [key,item] of confirmations.current) if (currentIdentity(key) !== item.identity) clearConfirmation(key);
    const next = Object.fromEntries(Object.entries(recordsRef.current).filter(([key,item]) => currentIdentity(key) === item.identity));
    if (Object.keys(next).length !== Object.keys(recordsRef.current).length) { recordsRef.current = next; setRecords(next); }
  },[state]);

  const getRecord = (link:Link):VisibleMonitorRecord|null => {
    if (!enabled) return null;
    const record = records[monitorKey(link)];
    if (!record || record.identity !== monitorIdentity(link,state)) return null;
    return {...record,stale:now - Date.parse(record.checkedAt) > STALE_AFTER_MS};
  };
  const summary = state.links.reduce<MonitorSummary>((sum,link) => {
    const record = getRecord(link);
    if (record?.unresolvedAlert) {
      if (record.phase === 'alert' && !record.stale) sum.alert++;
      else sum.unresolved++;
    } else if (record && (record.phase === 'attention' || record.phase === 'pending' || record.stale)) sum.attention++;
    return sum;
  },{alert:0,unresolved:0,attention:0});
  return {enabled,setEnabled,runNow,active,progress,lastCompletion,getRecord,summary,online:isOnline()};
}
