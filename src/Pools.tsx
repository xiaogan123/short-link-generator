import {useEffect,useState,type FormEvent} from 'react';
import {Plus,Stack,WarningCircle} from '@phosphor-icons/react';
import Dialog from './Dialog';
import type {Account,Pool,PoolCandidate,PoolHealth} from './types';
import {splitInvitationLink,validateTarget,type InvitationParts} from './validators';
const id=()=>crypto.randomUUID().replaceAll('-','');
const candidate=():PoolCandidate=>({id:id(),prefix:'',suffix:'',enabled:true});
export function composeTemplate(prefix:string,code:string,suffix=''){return new URL(prefix+encodeURIComponent(code)+suffix).href;}
export function poolValidation(pool:Pool):string|null{
 if(!pool.name.trim())return '请为平台地址命名。';
 if(!pool.accountIds.length)return '至少选择一个同步账户。';
 if(!pool.candidates.length||pool.candidates.length>10||!pool.candidates.some(c=>c.enabled))return '请添加 1–10 个大陆备用地址，并至少启用一个。';
 for(const t of [pool.official,...pool.candidates]){
  if(!t.prefix.trim()||/[\u0000-\u0020\u007f\\]/.test(t.prefix+t.suffix)||validateTarget(t.prefix+'EXAMPLE_CODE'+t.suffix))return '地址和邀请码组合后须为有效的 HTTPS 链接。';
  const authority=t.prefix.match(/^https:\/\/[^/?#]+([/?])/);
  if(!authority||t.prefix.includes('#')||t.suffix.includes('#'))return '邀请码必须位于完整域名之后的路径或参数中。';
 }
 return null;
}
function InvitationSplitter({candidates,onApply}:{candidates:PoolCandidate[];onApply:(target:string,parts:InvitationParts)=>void}){
 const [full,setFull]=useState('');
 const [target,setTarget]=useState('official');
 const [parts,setParts]=useState<InvitationParts|null>(null);
 const [message,setMessage]=useState('');
 useEffect(()=>{if(target!=='official'&&target!==''&&!candidates.some(candidate=>candidate.id===target)){setTarget('');setMessage('所选备用地址已移除，请重新选择填入位置。');}},[candidates,target]);
 function apply(){if(!parts)return;if(target!=='official'&&!candidates.some(candidate=>candidate.id===target)){setTarget('');setMessage('所选备用地址已移除，请重新选择填入位置。');return;}onApply(target,parts);setMessage('已填入地址；请核对后再保存。');}
 function parse(){try{setParts(splitInvitationLink(full));setMessage('');}catch(error){setParts(null);setMessage(error instanceof Error?error.message:'无法识别链接。');}}
 return <div className="invite-splitter"><div><strong>粘贴完整邀请链接</strong><p>识别后确认拆分结果，再填入指定地址。不会自动保存。</p></div><div className="splitter-controls"><input aria-label="完整邀请链接" type="text" inputMode="url" value={full} onChange={event=>{setFull(event.target.value);setParts(null);setMessage('');}} placeholder="https://example.com/join/CODE"/><button type="button" className="button secondary" onClick={parse}>识别链接</button></div>{message&&<p className="inline-warning" role="alert">{message}</p>}{parts&&<div className="splitter-preview"><p><b>邀请码</b> {parts.code}</p><p><b>邀请码前的地址</b> {parts.prefix}</p><p><b>额外参数</b> {parts.suffix||'无'}</p><div className="splitter-apply"><label>填入位置<select value={target} onChange={event=>{setTarget(event.target.value);setMessage('');}}><option value="" disabled>请选择填入位置</option><option value="official">其他地区地址</option>{candidates.map((candidate,index)=><option key={candidate.id} value={candidate.id}>大陆备用地址 {index+1}</option>)}</select></label><button type="button" className="button primary" disabled={!target} onClick={apply}>填入此地址</button></div></div>}</div>;
}
export default function Pools({pools,accounts,linkCount,onSave,onDelete,busy,health,onCheckHealth,planOpen,savedRevision}:{pools:Pool[];accounts:Account[];linkCount:(id:string)=>number;onSave:(pool:Pool)=>Promise<boolean>;onDelete:(id:string)=>void;busy:boolean;health:Record<string,PoolHealth>;onCheckHealth:(id:string)=>void;planOpen:boolean;savedRevision:number}){
 const [draft,setDraft]=useState<Pool|null>(null);const [error,setError]=useState('');
 const [clock,setClock]=useState(Date.now());
 useEffect(()=>{setDraft(null);},[savedRevision]);
 useEffect(()=>{const timer=window.setInterval(()=>setClock(Date.now()),60000);return()=>window.clearInterval(timer);},[]);
 const capacityAccounts=draft?.accountIds.filter(accountId=>pools.filter(pool=>pool.id!==draft.id&&pool.accountIds.includes(accountId)).reduce((n,pool)=>n+pool.candidates.filter(c=>c.enabled).length,0)+draft.candidates.filter(c=>c.enabled).length>60)||[];
 function fresh(timestamp:string|null){const time=timestamp?Date.parse(timestamp):NaN;return Number.isFinite(time)&&time<=clock&&clock-time<3600000;}
 function observedStatus(status:'healthy'|'unhealthy'|'unknown',checkedAt:string|null){return fresh(checkedAt)?status:'unknown';}
 function candidateStatus(pool:Pool,c:PoolCandidate){if(!c.enabled)return 'disabled';const reports=health[pool.id]?.accounts||[];const matching=reports.filter(a=>a.source==='mainland_provider'&&fresh(a.checkedAt)).map(a=>({accountId:a.accountId,status:a.candidates.find(x=>x.id===c.id)}));if(matching.some(a=>a.status&&observedStatus(a.status.status,a.status.checkedAt)==='unhealthy'))return 'unhealthy';if(pool.accountIds.length>0&&pool.accountIds.every(id=>matching.some(a=>a.accountId===id&&a.status&&observedStatus(a.status.status,a.status.checkedAt)==='healthy')))return 'healthy';return 'unknown';}
 function accountHealthLabel(pool:Pool,a:PoolHealth['accounts'][number]){if(a.source!=='mainland_provider'||!fresh(a.checkedAt))return '状态未知或已过期';const statuses=pool.candidates.filter(c=>c.enabled).map(c=>a.candidates.find(x=>x.id===c.id)).map(c=>c?observedStatus(c.status,c.checkedAt):'unknown');if(statuses.includes('unhealthy'))return '有失败目标';if(statuses.length>0&&statuses.every(s=>s==='healthy'))return '全部目标检测通过';return '状态未知或已过期';}
 function open(pool?:Pool){setError('');setDraft(pool?structuredClone(pool):{id:'',name:'',official:{prefix:'',suffix:''},candidates:[candidate()],updated:'',accountIds:accounts.map(a=>a.id)});}
 function patch(index:number,fields:Partial<PoolCandidate>){if(draft)setDraft({...draft,candidates:draft.candidates.map((c,i)=>i===index?{...c,...fields}:c)});}
 function move(index:number,delta:number){if(!draft)return;const rows=[...draft.candidates];[rows[index],rows[index+delta]]=[rows[index+delta],rows[index]];setDraft({...draft,candidates:rows});}
 function applySplit(target:string,parts:InvitationParts){if(!draft)return;const address={prefix:parts.prefix,suffix:parts.suffix};if(target==='official')setDraft({...draft,official:address});else setDraft({...draft,candidates:draft.candidates.map(c=>c.id===target?{...c,...address}:c)});setError('');}
 async function save(event:FormEvent){event.preventDefault();if(!draft)return;const validation=poolValidation(draft);if(validation){setError(validation);return;}await onSave(draft);}
 return <>
  <p className="page-note"><strong>平台地址是什么？</strong>集中维护其他地区地址和大陆备用地址。每条短链接只需选择平台地址、填写自己的邀请码；修改地址后，关联链接会一起使用新地址。</p>
  <section className="panel">
   <div className="panel-head"><div><h2>已保存的平台地址 <span className="heading-count">{pools.length}</span></h2></div><button className="button primary" onClick={()=>open()} disabled={!accounts.length}><Plus size={16}/>添加平台地址</button></div>
   {!pools.length?<div className="empty"><div className="empty-icon"><Stack size={27}/></div><h3>{accounts.length?'还没有平台地址':'先连接 Cloudflare 账户'}</h3><p>{accounts.length?'添加常用地址后，创建短链接时只需填写邀请码。':'连接账户后即可添加平台地址与短链接。'}</p></div>:<div className="pool-list">{pools.map(pool=><article className="pool-card" key={pool.id}>
    <div className="pool-title"><div><h3>{pool.name}</h3><p>{linkCount(pool.id)} 条关联链接 · {pool.candidates.filter(c=>c.enabled).length} 个大陆备用地址</p></div><div className="pool-actions"><button className="button secondary" onClick={()=>open(pool)}>编辑地址</button><button className="button ghost danger-hover" disabled={linkCount(pool.id)>0} onClick={()=>onDelete(pool.id)}>删除</button></div></div>
    <div className="pool-addresses"><div className="pool-address"><span>其他地区地址</span><code>{pool.official.prefix}<b>邀请码</b>{pool.official.suffix}</code></div>{pool.candidates.map((c,index)=><div className="pool-address" key={c.id}><span>大陆备用地址 {index+1}</span><code>{c.prefix}<b>邀请码</b>{c.suffix}</code><em className={'status status-'+(candidateStatus(pool,c)==='unhealthy'?'red':candidateStatus(pool,c)==='healthy'?'green':'slate')}>{candidateStatus(pool,c)==='disabled'?'已停用':candidateStatus(pool,c)==='unhealthy'?'检测失败':candidateStatus(pool,c)==='healthy'?'各账户检测通过':'状态未知'}</em></div>)}</div>
    <div className="pool-foot"><div className="pool-sync">{pool.accountIds.map(accountId=>{const sync=pool.syncStatus?.find(item=>item.accountId===accountId);return <span key={accountId} className={'status '+(sync?.status==='synced'?'status-green':sync?.status==='failed'?'status-red':'status-slate')} title={sync?.message}>{accounts.find(a=>a.id===accountId)?.label||'未连接账户'} · {sync?.status==='synced'?'已同步':sync?.status==='failed'?'同步失败':'待同步'}{sync?.status==='failed'&&sync.message&&<small> · {sync.message}</small>}</span>;})}</div><button className="text-button" onClick={()=>onCheckHealth(pool.id)} disabled={busy}>查看检测状态</button></div>
    {health[pool.id]&&<div className="pool-health">{health[pool.id].accounts.map(a=><div key={a.accountId} className="pool-health-row"><strong>{accounts.find(x=>x.id===a.accountId)?.label||'未知账户'}</strong> · {a.source==='mainland_provider'?'用户配置的检测服务':'未配置或来源未知'} · {a.checkedAt?new Date(a.checkedAt).toLocaleString('zh-CN'):'尚无检测'} · {accountHealthLabel(pool,a)}{a.candidates.map(c=><div key={c.id}>{pool.candidates.find(x=>x.id===c.id)?.prefix||c.id}：{a.source==='mainland_provider'&&fresh(a.checkedAt)?observedStatus(c.status,c.checkedAt)==='healthy'?'通过':observedStatus(c.status,c.checkedAt)==='unhealthy'?'失败':'未知或已过期':'未知或已过期'} · {c.checkedAt?new Date(c.checkedAt).toLocaleString('zh-CN'):'尚无检测'} · {c.message}</div>)}</div>)}</div>}
   </article>)}</div>}
  </section>
  <p className="page-footnote"><WarningCircle size={16}/>未配置检测服务时，备用地址状态为未知。状态过期或检测失败也不会被显示为可用；全部备用地址明确失败时，短链接会暂时不可用。</p>
  {draft&&!planOpen&&<Dialog title={draft.id?'编辑平台地址':'添加平台地址'} wide error={error} onClose={()=>setDraft(null)} footer={<><button className="button ghost" onClick={()=>setDraft(null)}>取消</button><button className="button primary" form="pool-form" type="submit" disabled={busy}>下一步，核对内容</button></>}>
   <form id="pool-form" className="form-grid" onSubmit={event=>void save(event)}>
    <label>名称<input value={draft.name} onChange={event=>setDraft({...draft,name:event.target.value})} placeholder="例如：常用平台 A" maxLength={60} required/><small>仅用于本机区分，不影响链接地址。</small></label>
    <fieldset className="pool-accounts"><legend>同步到哪些账户</legend>{accounts.map(a=><label className="checkbox-row" key={a.id}><input type="checkbox" checked={draft.accountIds.includes(a.id)} onChange={event=>setDraft({...draft,accountIds:event.target.checked?[...draft.accountIds,a.id]:draft.accountIds.filter(id=>id!==a.id)})}/>{a.label}</label>)}</fieldset>
    {capacityAccounts.length>0&&<p className="inline-warning">这些账户已超过 60 个启用地址：{capacityAccounts.map(id=>accounts.find(a=>a.id===id)?.label||id).join('、')}。每 15 分钟最多检测 20 个地址，部分结果可能超过 1 小时。</p>}
    <InvitationSplitter candidates={draft.candidates} onApply={applySplit}/>
    <div className="template-card"><div className="template-heading"><h3>其他地区地址</h3><span>必填</span></div><label>邀请码前的地址<input value={draft.official.prefix} onChange={event=>setDraft({...draft,official:{...draft.official,prefix:event.target.value}})} placeholder="https://example.com/join/" required/></label><label>额外参数（可选）<input value={draft.official.suffix} onChange={event=>setDraft({...draft,official:{...draft.official,suffix:event.target.value}})} placeholder="例如 ?lang=zh"/></label></div>
    <div className="template-heading"><h3>大陆备用地址</h3><span>按优先顺序选择；至少启用一个</span></div>
    {draft.candidates.map((c,index)=><div className="template-card" key={c.id}><div className="template-heading"><label className="checkbox-row"><input type="checkbox" checked={c.enabled} onChange={event=>patch(index,{enabled:event.target.checked})}/>备用地址 {index+1}</label><div className="template-actions"><button type="button" disabled={index===0} onClick={()=>move(index,-1)}>上移</button><button type="button" disabled={index===draft.candidates.length-1} onClick={()=>move(index,1)}>下移</button><button type="button" disabled={draft.candidates.length===1} onClick={()=>setDraft({...draft,candidates:draft.candidates.filter(item=>item.id!==c.id)})}>移除</button></div></div><label>邀请码前的地址<input value={c.prefix} onChange={event=>patch(index,{prefix:event.target.value})} placeholder="https://example.org/join/" required/></label><label>额外参数（可选）<input value={c.suffix} onChange={event=>patch(index,{suffix:event.target.value})} placeholder="例如 ?lang=zh"/></label></div>)}
    <button type="button" className="button secondary add-candidate" disabled={draft.candidates.length>=10} onClick={()=>setDraft({...draft,candidates:[...draft.candidates,candidate()]})}><Plus size={16}/>添加大陆备用地址</button>
    <p className="form-note">确认前会列出关联链接与同步账户。地址只能是 HTTPS，邀请码位于域名后的路径或参数中。</p>
   </form>
  </Dialog>}
 </>;
}
