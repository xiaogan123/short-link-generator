import { ArrowClockwise, WarningCircle } from '@phosphor-icons/react';
import type { MonitorSummary, VisibleMonitorRecord } from './useRedirectMonitor';
import './RedirectMonitor.css';

export function monitorDisplay(record:VisibleMonitorRecord|null) {
  if (!record) return {label:'尚未巡检',tone:'slate' as const};
  if (record.stale) return {label:record.unresolvedAlert ? '异常待确认恢复 · 已过期' : '结果已过期',tone:'amber' as const};
  if (record.phase === 'healthy') return {label:'首跳符合预期',tone:'green' as const};
  if (record.phase === 'alert') return {label:'首跳异常',tone:'red' as const};
  if (record.phase === 'pending') return {label:'待复查',tone:'amber' as const};
  if (record.unresolvedAlert) return {label:'异常待确认恢复',tone:'amber' as const};
  return {label:'需关注',tone:'amber' as const};
}

export function monitorBannerText(summary:MonitorSummary):string {
  const parts = [
    summary.alert > 0 ? `${summary.alert} 条首跳异常` : '',
    summary.unresolved > 0 ? `${summary.unresolved} 条异常待确认恢复` : '',
    summary.attention > 0 ? `${summary.attention} 条需关注` : '',
  ].filter(Boolean);
  return parts.length ? `自动巡检：${parts.join('，')}` : '';
}

type Props = {
  enabled:boolean;
  active:boolean;
  online:boolean;
  progress:{done:number;total:number};
  lastCompletion:string|null;
  onEnabled:(value:boolean)=>void;
  onRun:()=>void;
  disabled:boolean;
};
function formatDate(value:string|null) {
  if (!value) return '尚未完成';
  const date = new Date(value);
  return Number.isFinite(date.getTime()) ? new Intl.DateTimeFormat('zh-CN',{month:'2-digit',day:'2-digit',hour:'2-digit',minute:'2-digit'}).format(date) : '尚未完成';
}

export default function RedirectMonitor({enabled,active,online,progress,lastCompletion,onEnabled,onRun,disabled}:Props) {
  return <section className="redirect-monitor panel" aria-label="自动巡检">
    <div className="redirect-monitor-main">
      <div className="redirect-monitor-title"><WarningCircle size={18} aria-hidden="true"/><div><h2>自动巡检</h2><p>应用打开且联网时每 30 分钟检查一次；关闭应用或电脑休眠后停止。</p></div></div>
      <div className="redirect-monitor-actions">
        <label className="redirect-monitor-switch"><input type="checkbox" checked={enabled} onChange={event=>onEnabled(event.target.checked)}/><span>{enabled?'已开启':'未开启'}</span></label>
        <button type="button" className="button secondary" onClick={onRun} disabled={!enabled || active || disabled || !online}><ArrowClockwise size={15} aria-hidden="true"/>立即巡检</button>
      </div>
    </div>
    <div className="redirect-monitor-meta"><span>{active ? `正在巡检 ${progress.done}/${progress.total}` : enabled ? disabled ? '当前操作结束后继续' : !online ? '等待网络连接' : '等待下次巡检' : '开启后自动开始'}</span><span>上次完成：{formatDate(lastCompletion)}</span></div>
    <p className="redirect-monitor-note">仅检查本机网络看到的首跳及预期地址；不代表大陆网络或目标网站可达。巡检会产生正常的短链接请求，巡检请求不计入点击统计。</p>
  </section>;
}
