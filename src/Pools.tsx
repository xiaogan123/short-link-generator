import {useEffect,useRef,useState,type FormEvent,type ReactNode} from 'react';
import {Plus,Stack,WarningCircle} from '@phosphor-icons/react';
import Dialog from './Dialog';
import type {Account,Pool,PoolCandidate,PoolHealth} from './types';
import {splitInvitationLink,validateTarget,type InvitationParts} from './validators';
const id=()=>crypto.randomUUID().replaceAll('-','');
const candidate=():PoolCandidate=>({id:id(),prefix:'',suffix:'',enabled:true});
export function composeTemplate(prefix:string,code:string,suffix=''){return new URL(prefix+encodeURIComponent(code)+suffix).href;}
export function poolValidation(pool:Pool):string|null{
 if(!pool.name.trim())return '请为平台地址命名。';
 if(!pool.candidates.length||pool.candidates.length>10||!pool.candidates.some(c=>c.enabled))return '请添加 1–10 个大陆访问地址，并至少启用一个。';
 for(const t of [pool.official,...pool.candidates]){
  if(!t.prefix.trim()||/[\u0000-\u0020\u007f\\]/.test(t.prefix+t.suffix)||validateTarget(t.prefix+'EXAMPLE_CODE'+t.suffix))return '地址和邀请码组合后须为有效的 HTTPS 链接。';
  const authority=t.prefix.match(/^https:\/\/[^/?#]+([/?])/);
  if(!authority||t.prefix.includes('#')||t.suffix.includes('#'))return '邀请码必须位于完整域名之后的路径或参数中。';
 }
 return null;
}
function AddressPaste({label,onApply}:{label:string;onApply:(parts:InvitationParts)=>void}){
 const [full,setFull]=useState('');const [parts,setParts]=useState<InvitationParts|null>(null);const [message,setMessage]=useState('');
 function parse(){try{setParts(splitInvitationLink(full));setMessage('');}catch(error){setParts(null);setMessage(error instanceof Error?error.message:'无法识别链接。');}}
 return <div className="address-paste"><label>{label}的完整邀请链接<input aria-label={`${label} 完整邀请链接`} type="text" inputMode="url" value={full} onChange={event=>{setFull(event.target.value);setParts(null);setMessage('');}} placeholder="https://example.com/join/CODE"/></label><button type="button" className="button ghost" onClick={parse}>识别</button>{message&&<p className="inline-warning" role="alert">{message}</p>}{parts&&<div className="address-paste-result"><span>邀请码：<strong>{parts.code}</strong></span><button type="button" className="button secondary" onClick={()=>{onApply(parts);setMessage('已去掉邀请码并填入链接地址，请核对后保存。');}}>填入链接地址</button></div>}</div>;
}
export default function Pools({pools,accounts,linkCount,onSave,onDelete,busy,health,onCheckHealth,planOpen,savedRevision,serverError="",onDraftChange,errorAction,dismissDisabled=false}:{pools:Pool[];accounts:Account[];linkCount:(id:string)=>number;onSave:(pool:Pool,shouldAccept?:()=>boolean)=>Promise<boolean>;onDelete:(id:string)=>void;busy:boolean;health:Record<string,PoolHealth>;onCheckHealth:(id:string)=>void;planOpen:boolean;savedRevision:number;serverError?:string;onDraftChange?:()=>void;errorAction?:ReactNode;dismissDisabled?:boolean}){
 const [draft,setDraft]=useState<Pool|null>(null);const [error,setError]=useState('');
 const [clock,setClock]=useState(Date.now());
 const draftGeneration=useRef(0);
 useEffect(()=>{replaceDraft(null);},[savedRevision]);
 useEffect(()=>{const timer=window.setInterval(()=>setClock(Date.now()),60000);return()=>window.clearInterval(timer);},[]);
 function replaceDraft(next:Pool|null){draftGeneration.current+=1;setDraft(next);setError('');onDraftChange?.();}
 function fresh(timestamp:string|null){const time=timestamp?Date.parse(timestamp):NaN;return Number.isFinite(time)&&time<=clock&&clock-time<3600000;}
 function observedStatus(status:'healthy'|'unhealthy'|'unknown',checkedAt:string|null){return fresh(checkedAt)?status:'unknown';}
 function candidateStatus(pool:Pool,c:PoolCandidate){if(!c.enabled)return 'disabled';const reports=health[pool.id]?.accounts||[];const matching=reports.filter(a=>a.source==='mainland_provider'&&fresh(a.checkedAt)).map(a=>({accountId:a.accountId,status:a.candidates.find(x=>x.id===c.id)}));if(matching.some(a=>a.status&&observedStatus(a.status.status,a.status.checkedAt)==='unhealthy'))return 'unhealthy';if(pool.accountIds.length>0&&pool.accountIds.every(id=>matching.some(a=>a.accountId===id&&a.status&&observedStatus(a.status.status,a.status.checkedAt)==='healthy')))return 'healthy';return 'unknown';}
 function accountHealthLabel(pool:Pool,a:PoolHealth['accounts'][number]){if(a.source!=='mainland_provider'||!fresh(a.checkedAt))return '状态未知或已过期';const statuses=pool.candidates.filter(c=>c.enabled).map(c=>a.candidates.find(x=>x.id===c.id)).map(c=>c?observedStatus(c.status,c.checkedAt):'unknown');if(statuses.includes('unhealthy'))return '有失败目标';if(statuses.length>0&&statuses.every(s=>s==='healthy'))return '全部目标检测通过';return '状态未知或已过期';}
 function open(pool?:Pool){setError('');replaceDraft(pool?structuredClone(pool):{id:'',name:'',official:{prefix:'',suffix:''},candidates:[candidate()],updated:'',accountIds:[]});}
 function patch(index:number,fields:Partial<PoolCandidate>){if(draft)replaceDraft({...draft,candidates:draft.candidates.map((c,i)=>i===index?{...c,...fields}:c)});}
 function move(index:number,delta:number){if(!draft)return;const rows=[...draft.candidates];[rows[index],rows[index+delta]]=[rows[index+delta],rows[index]];replaceDraft({...draft,candidates:rows});}
 function applySplit(target:string,parts:InvitationParts){if(!draft)return;const address={prefix:parts.prefix,suffix:parts.suffix};if(target==='official')replaceDraft({...draft,official:address});else replaceDraft({...draft,candidates:draft.candidates.map(c=>c.id===target?{...c,...address}:c)});setError('');}
 async function save(event:FormEvent){event.preventDefault();if(!draft)return;const validation=poolValidation(draft);if(validation){setError(validation);return;}const generation=draftGeneration.current;await onSave(draft,()=>draftGeneration.current===generation);}
 return <>
  <p className="page-note"><strong>平台地址是什么？</strong>集中维护官网链接和大陆访问地址。创建短链接时会自动配置到对应账户；邀请码由每条短链接单独填写。更新平台地址后，关联链接会使用新地址。</p>
  <section className="panel">
   <div className="panel-head"><div><h2>已保存的平台地址 <span className="heading-count">{pools.length}</span></h2></div><button className="button primary" onClick={()=>open()}><Plus size={16}/>添加平台地址</button></div>
   {!pools.length?<div className="empty"><div className="empty-icon"><Stack size={27}/></div><h3>还没有平台地址</h3><p>添加常用地址后，创建短链接时只需填写邀请码。</p></div>:<div className="pool-list">{pools.map(pool=><article className="pool-card" key={pool.id} aria-label={`${pool.name} 平台地址`}>
    <div className="pool-title"><div><h3>{pool.name}</h3><p>关联短链接 {linkCount(pool.id)} 条 · 已启用大陆访问地址 {pool.candidates.filter(c=>c.enabled).length} 个</p></div><div className="pool-actions"><button className="button secondary" onClick={()=>open(pool)}>编辑地址</button><button className="button ghost danger-hover" disabled={linkCount(pool.id)>0} onClick={()=>onDelete(pool.id)}>删除</button></div></div>
    <div className="pool-targets">
      <section className="pool-target-group" aria-label="官网链接"><div className="pool-target-heading"><strong>官网链接</strong><small>中国大陆以外访客</small></div><div className="pool-address pool-official-address"><code>{pool.official.prefix}<b>邀请码</b>{pool.official.suffix}</code></div></section>
      <section className="pool-target-group" aria-label="大陆访问地址"><div className="pool-target-heading"><strong>大陆访问地址</strong><small>按首选、备用顺序使用</small></div><div className="pool-candidate-list">{pool.candidates.map((c,index)=><div className={`pool-address ${c.enabled?'':'candidate-disabled'}`} key={c.id}><span className="pool-target-label">{index===0?'首选':`备用 ${index}`}</span><code>{c.prefix}<b>邀请码</b>{c.suffix}</code><em className={'status status-'+(candidateStatus(pool,c)==='unhealthy'?'red':candidateStatus(pool,c)==='healthy'?'green':'slate')}>{candidateStatus(pool,c)==='disabled'?'已停用':candidateStatus(pool,c)==='unhealthy'?'检测失败':candidateStatus(pool,c)==='healthy'?'各账户检测通过':'状态未知'}</em></div>)}</div></section>
    </div>
    <div className="pool-foot"><section className="pool-sync-section" aria-label="配置同步"><h4>配置同步</h4><div className="pool-sync">{[...new Set([...accounts.map(a=>a.id),...pool.accountIds])].map(accountId=>{
      const account=accounts.find(a=>a.id===accountId);
      const configured=pool.accountIds.includes(accountId);
      const sync=configured?pool.syncStatus?.find(item=>item.accountId===accountId):undefined;
      const label=!configured?'首次使用时自动同步':sync?.status==='synced'?'已同步配置':sync?.status==='failed'?'同步失败':sync?.status==='unknown'?'同步结果待确认':'待同步';
      return <span key={accountId} className={'status '+(sync?.status==='synced'?'status-green':sync?.status==='failed'?'status-red':'status-slate')} title={sync?.message}>{account?.cloudflareName||account?.label||'未连接账户'} · {label}{sync?.status==='failed'&&sync.message&&<small> · {sync.message}</small>}</span>;
    })}</div><p>官网和大陆地址可供所有已导入账户使用，首次创建相关短链接时自动同步。配置已同步不代表网址已通过访问检测。</p></section><button className="text-button" onClick={()=>onCheckHealth(pool.id)} disabled={busy}>查看网址检测</button></div>
    {health[pool.id]&&<div className="pool-health">{health[pool.id].accounts.map(a=><div key={a.accountId} className="pool-health-row"><strong>{accounts.find(x=>x.id===a.accountId)?.label||'未知账户'}</strong> · {a.source==='mainland_provider'?'用户配置的检测服务':'未配置或来源未知'} · {a.checkedAt?new Date(a.checkedAt).toLocaleString('zh-CN'):'尚无检测'} · {accountHealthLabel(pool,a)}{a.candidates.map(c=><div key={c.id}>{pool.candidates.find(x=>x.id===c.id)?.prefix||c.id}：{a.source==='mainland_provider'&&fresh(a.checkedAt)?observedStatus(c.status,c.checkedAt)==='healthy'?'通过':observedStatus(c.status,c.checkedAt)==='unhealthy'?'失败':'未知或已过期':'未知或已过期'} · {c.checkedAt?new Date(c.checkedAt).toLocaleString('zh-CN'):'尚无检测'} · {c.message}</div>)}</div>)}</div>}
   </article>)}</div>}
  </section>
  <p className="page-footnote"><WarningCircle size={16}/>未配置检测服务时，备用地址状态为未知。状态过期或检测失败也不会被显示为可用；全部备用地址明确失败时，短链接会暂时不可用。</p>
  {draft&&!planOpen&&<Dialog title={draft.id?'编辑平台地址':'添加平台地址'} wide error={error||serverError} errorAction={errorAction} dismissDisabled={dismissDisabled} onClose={()=>{if(!dismissDisabled)replaceDraft(null);}} footer={<><button className="button ghost" disabled={dismissDisabled} onClick={()=>replaceDraft(null)}>取消</button><button className="button primary" form="pool-form" type="submit" disabled={busy}>下一步，核对内容</button></>}>
   <form id="pool-form" className="form-grid" onSubmit={event=>void save(event)}>
    <label>名称<input value={draft.name} onChange={event=>replaceDraft({...draft,name:event.target.value})} placeholder="例如：常用平台 A" maxLength={60} required/><small>仅用于本机区分，不影响链接地址。</small></label>
    <div className="template-card"><div className="template-heading"><h3>官网链接（中国大陆以外访客使用）</h3><span>必填</span></div><AddressPaste label="官网链接" onApply={parts=>applySplit('official',parts)}/><label>链接地址（不含邀请码）<input value={draft.official.prefix} onChange={event=>replaceDraft({...draft,official:{...draft.official,prefix:event.target.value}})} placeholder="https://example.com/join/" required/></label><details className="advanced"><summary>高级设置：额外参数</summary><label>额外参数（可选）<input value={draft.official.suffix} onChange={event=>replaceDraft({...draft,official:{...draft.official,suffix:event.target.value}})} placeholder="例如 ?lang=zh"/></label></details></div>
    <div className="template-heading"><h3>大陆访问地址</h3><span>按首选、备用顺序选择；至少启用一个</span></div>
    {draft.candidates.map((c,index)=><div className="template-card" key={c.id}><div className="template-heading"><label className="checkbox-row"><input type="checkbox" checked={c.enabled} onChange={event=>patch(index,{enabled:event.target.checked})}/>大陆访问地址（{index===0?'首选':`备用 ${index}`}）</label><div className="template-actions"><button type="button" disabled={index===0} onClick={()=>move(index,-1)}>上移</button><button type="button" disabled={index===draft.candidates.length-1} onClick={()=>move(index,1)}>下移</button><button type="button" disabled={draft.candidates.length===1} onClick={()=>replaceDraft({...draft,candidates:draft.candidates.filter(item=>item.id!==c.id)})}>移除</button></div></div><AddressPaste label={`大陆访问地址（${index===0?'首选':`备用 ${index}`}）`} onApply={parts=>applySplit(c.id,parts)}/><label>链接地址（不含邀请码）<input value={c.prefix} onChange={event=>patch(index,{prefix:event.target.value})} placeholder="https://example.org/join/" required/></label><details className="advanced"><summary>高级设置：额外参数</summary><label>额外参数（可选）<input value={c.suffix} onChange={event=>patch(index,{suffix:event.target.value})} placeholder="例如 ?lang=zh"/></label></details></div>)}
    <button type="button" className="button secondary add-candidate" disabled={draft.candidates.length>=10} onClick={()=>replaceDraft({...draft,candidates:[...draft.candidates,candidate()]})}><Plus size={16}/>添加大陆访问地址</button>
    <p className="form-note">确认前会列出关联链接与同步账户。地址只能是 HTTPS，邀请码位于域名后的路径或参数中。</p>
   </form>
  </Dialog>}
 </>;
}
