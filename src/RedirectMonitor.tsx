import { ArrowClockwise, CheckCircle, WarningCircle } from '@phosphor-icons/react';
import type { MonitorResultStatus, MonitorSummary, VisibleMonitorRecord } from './useRedirectMonitor';
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
  ready?:boolean;
  nextCheckAt?:string|null;
  runKind?:'full'|'changed'|'confirm';
  pendingChanges?:number;
  totalLinks?:number;
  summary?:MonitorSummary;
  resultStatus?:MonitorResultStatus;
};
function formatDate(value:string|null) {
  if (!value) return '尚未完成';
  const date = new Date(value);
  return Number.isFinite(date.getTime()) ? new Intl.DateTimeFormat('zh-CN',{month:'2-digit',day:'2-digit',hour:'2-digit',minute:'2-digit'}).format(date) : '尚未完成';
}

export default function RedirectMonitor({enabled,active,online,progress,lastCompletion,onEnabled,onRun,disabled,ready=true,nextCheckAt,runKind='full',pendingChanges=0,totalLinks,summary,resultStatus='unverified'}:Props) {
  const attention = summary ? summary.alert + summary.unresolved + summary.attention : 0;
  const resultText = resultStatus === 'healthy' ? '上次巡检：全部首跳符合预期'
    : resultStatus === 'attention' ? `上次巡检：${attention > 0 ? `${attention} 条链接需关注` : '有链接需关注'}`
      : resultStatus === 'stale' ? '上次巡检结果已过期，等待重新检查'
        : '巡检结果：尚未完成有效巡检';
  const waiting = !enabled ? '开启后自动开始'
    : !ready ? '等待读取本机配置'
      : totalLinks === 0 ? '等待添加短链接'
        : !online ? '等待网络连接'
          : disabled ? '当前操作结束后继续'
            : pendingChanges > 0 ? `等待检查 ${pendingChanges} 条新增或修改的链接`
              : '等待下次巡检';
  const activity = runKind === 'confirm' ? '正在复查首跳结果'
    : `${runKind === 'changed' ? '正在检查新增或修改的链接' : '正在巡检'} ${progress.done}/${progress.total}`;
  return <section className="redirect-monitor panel" aria-label="自动巡检">
    <div className="redirect-monitor-main">
      <div className="redirect-monitor-title"><WarningCircle size={18} aria-hidden="true"/><div><h2>自动巡检{attention > 0 && <span className="redirect-monitor-count">{attention} 条需关注</span>}</h2><p>每 48 小时巡检一次；新增或修改的链接会补查。仅在应用打开且联网时执行，关闭期间到期的巡检会在下次打开后补查。</p></div></div>
      <div className="redirect-monitor-actions">
        <label className="redirect-monitor-switch"><input type="checkbox" checked={enabled} onChange={event=>onEnabled(event.target.checked)}/><span>{enabled?'已开启':'未开启'}</span></label>
        <button type="button" className="button secondary" onClick={onRun} disabled={!enabled || active || disabled || !ready || !online || totalLinks === 0}><ArrowClockwise size={15} aria-hidden="true"/>立即巡检</button>
      </div>
    </div>
    {enabled && ready && !active && (totalLinks ?? 0) > 0 && <p className={`redirect-monitor-result ${resultStatus}`} aria-live="polite">{resultStatus === 'healthy' ? <CheckCircle size={16} weight="fill" aria-hidden="true"/> : <WarningCircle size={16} aria-hidden="true"/>}{resultText}</p>}
    <div className="redirect-monitor-meta"><span role={enabled ? "status" : undefined}>{active ? activity : waiting}</span><span>上次整轮完成：{formatDate(lastCompletion)}</span>{enabled && nextCheckAt && <span>下次预计：{formatDate(nextCheckAt)}{(!online || disabled || !ready) && ' · 条件恢复后执行'}</span>}</div>
    {active && runKind !== 'confirm' && progress.total > 0 && <progress className="redirect-monitor-progress" aria-label="本次巡检进度" value={progress.done} max={progress.total}/>}
    <p className="redirect-monitor-note">仅检查本机网络看到的首跳及预期地址；不代表大陆网络或目标网站可达。巡检会产生正常的短链接请求，巡检请求不计入点击统计。</p>
  </section>;
}
