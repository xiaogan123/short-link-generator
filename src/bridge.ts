import { invoke } from '@tauri-apps/api/core';
import { normalizeHost } from './validators';
import type { Action, DomainPreparation, Link, Plan, Pool, PoolHealth, Selftest, State, TargetReport } from './types';

export const preview = new URLSearchParams(window.location.search).get('preview') === '1';
const now = () => new Date().toISOString();
const uid = () => Math.random().toString(36).slice(2, 10);
const demoState: State = {
  accounts: [
    { id: 'demo-a', label: '示例账户 · 团队', zoneCount: 2, checkedAt: now(), hasResources: true, needsSelftestKey: false },
    { id: 'demo-b', label: '示例账户 · 个人', zoneCount: 1, checkedAt: now(), hasResources: false, needsSelftestKey: true },
  ],
  domains: [
    { id: 'demo-d1', accountId: 'demo-a', zoneId: 'demo-zone-1', host: 'go.example.com', prefix: 'r', routeId: 'demo-route-1' },
    { id: 'demo-d2', accountId: 'demo-a', zoneId: 'demo-zone-2', host: 'links.example.org', prefix: 's', routeId: 'demo-route-2' },
  ],
  links: [
    { domainId: 'demo-d1', slug: 'welcome', cnUrl: 'https://example.com/zh', defaultUrl: 'https://example.com/en', updated: now() },
    { domainId: 'demo-d1', slug: 'guide', cnUrl: 'https://example.org/zh', defaultUrl: 'https://example.org/en', updated: now() },
    { domainId: 'demo-d2', slug: 'news', cnUrl: 'https://example.com/news', defaultUrl: 'https://example.org/news', updated: now() },
  ],
  pendingOperations: [],
  pendingActions: [],
  pools: [],
};
let local: State = structuredClone(demoState);
const plans = new Map<string, { plan: Plan; action: string; payload: Record<string, unknown> }>();
const clone = ():State => {const state=structuredClone(local);state.links=state.links.map(link=>{if(!link.poolId)return link;const pool=state.pools?.find(p=>p.id===link.poolId);if(!pool)return link;const code=encodeURIComponent(link.code||'');const candidate=pool.candidates.find(c=>c.enabled);return {...link,cnUrl:candidate?candidate.prefix+code+candidate.suffix:'',defaultUrl:pool.official.prefix+code+pool.official.suffix};});return state;};
function makePlan(title: string, steps: string[], warnings: string[], action: string, payload: Record<string, unknown>): Plan {
  const plan = { id: uid(), title, steps, warnings, expiresAt: new Date(Date.now() + 300000).toISOString() };
  plans.set(plan.id, { plan, action, payload });
  return plan;
}
function previewDispatch(action: Action, payload: Record<string, unknown>): unknown {
  if (action === 'get_state') return clone();
  if (action === 'token_template') return 'https://dash.cloudflare.com/profile/api-tokens';
  if (action === 'refresh_accounts') { local.accounts = local.accounts.map(a => ({ ...a, checkedAt: now() })); return clone(); }
  if (action === 'import_token') {
    const token = String(payload.token || '').trim();
    if (!token) throw new Error('请先粘贴令牌。');
    const existing = local.accounts.find(a => a.id === 'demo-imported');
    if (existing && !payload.replace) throw new Error('该账户已经存在。请确认是否替换本机保存的令牌。');
    if (!existing) local.accounts.push({ id: 'demo-imported', label: '导入的示例账户', zoneCount: 1, checkedAt: now(), hasResources: false, needsSelftestKey: false });
    return clone();
  }
  if (action === 'rename_account') { local.accounts = local.accounts.map(a => a.id === payload.accountId ? { ...a, label: String(payload.label) } : a); return clone(); }
  if (action === 'remove_account') {
    const ids = local.domains.filter(d => d.accountId === payload.accountId).map(d => d.id);
    local.accounts = local.accounts.filter(a => a.id !== payload.accountId);
    local.domains = local.domains.filter(d => d.accountId !== payload.accountId);
    local.links = local.links.filter(l => !ids.includes(l.domainId));
    local.pools = (local.pools || []).map(pool => ({...pool, accountIds: pool.accountIds.filter(id => id !== payload.accountId), syncStatus: pool.syncStatus?.filter(s => s.accountId !== payload.accountId)})); return clone();
  }
  if (action === 'prepare_domain') {
    const host = normalizeHost(String(payload.input || ''));
    const prefix = String(payload.prefix || '');
    const candidates = local.accounts.filter(a => !payload.accountId || a.id === payload.accountId).map(a => ({ accountId: a.id, label: a.label, zoneId: `demo-zone-${a.id}`, status: 'active' }));
    const checks = [
      { label: '域名格式', ok: true, message: '格式有效。' },
      { label: '区域与代理', ok: true, message: '预览模拟：活动区域与代理状态。' },
      { label: '根路径与随机子路径', ok: true, message: '预览模拟：均返回 404；未发起真实探测。' },
    ];
    const candidate = candidates.length === 1 ? candidates[0] : undefined;
    const plan = candidate ? makePlan(`添加 ${host}`, [`在 ${candidate.label} 上配置 ${host}/${prefix}/*`, '保存域名与路由关系'], ['本地预览不会连接云服务。'], 'add_domain', { host, prefix, accountId: candidate.accountId, zoneId: candidate.zoneId }) : undefined;
    return { host, prefix, candidates, checks, canApply: Boolean(plan), plan } satisfies DomainPreparation;
  }
  if (action === 'prepare_change') {
    const kind = String(payload.kind);
    const titles: Record<string, string> = { save_link: '保存短链接', delete_link: '删除短链接', save_pool: '保存平台地址', resume_pool_sync:'继续同步平台地址', delete_pool: '删除平台地址', remove_domain: '移除域名', cleanup_account: '清理远端资源', recover_account: '恢复账户资源', rotate_selftest: '轮换检测密钥' };
    if (kind === 'delete_pool' && local.links.some(l => l.poolId === payload.poolId)) throw new Error('平台地址仍有链接引用，无法删除。');
    return makePlan(titles[kind] || '确认变更', [`核对当前状态与资源归属`, `${titles[kind] || kind}并记录结果`], kind === 'delete_link' || kind === 'remove_domain' || kind === 'cleanup_account' ? ['该操作会修改远端资源。请确认影响范围。'] : [], kind, payload);
  }
  if (action === 'apply_plan') {
    const item = plans.get(String(payload.planId));
    if (!item || Date.parse(item.plan.expiresAt) < Date.now()) throw new Error('计划已过期，请重新准备。');
    plans.delete(item.plan.id);
    const p = item.payload;
    if (item.action === 'add_domain') local.domains.push({ id: uid(), host: String(p.host), prefix: String(p.prefix), accountId: String(p.accountId), zoneId: String(p.zoneId), routeId: `demo-route-${uid()}` });
    if (item.action === 'save_link') {
      const pool = (local.pools || []).find(pool => pool.id === p.poolId);
      if (p.poolId && !pool) throw new Error('平台地址不存在。');
      const code = String(p.code || '');
      const entry: Link = pool ? { domainId: String(p.domainId), slug: String(p.slug), poolId: pool.id, code, cnUrl: '', defaultUrl: '', updated: now() } : { domainId: String(p.domainId), slug: String(p.slug), cnUrl: String(p.cnUrl), defaultUrl: String(p.defaultUrl), updated: now() };
      local.links = local.links.filter(l => !(l.domainId === entry.domainId && l.slug === entry.slug)); local.links.push(entry);
    }
    if (item.action === 'save_pool') {const pool = p.pool as Pool; const saved = {...pool,id:pool.id || uid(),updated:now(),syncStatus:pool.accountIds.map(accountId=>({accountId,status:'unknown',message:'本地预览不会同步云端。'}))}; local.pools = (local.pools || []).filter(x=>x.id!==saved.id).concat(saved);}
    if (item.action === 'delete_pool') local.pools = (local.pools || []).filter(x=>x.id!==p.poolId);
    if (item.action === 'enable_monitor') local.accounts = local.accounts.map(a=>a.id===p.accountId?{...a,monitorEnabled:true,monitorEndpoint:String(p.endpoint)}:a);
    if (item.action === 'disable_monitor') local.accounts = local.accounts.map(a=>a.id===p.accountId?{...a,monitorEnabled:false,monitorEndpoint:undefined}:a);
    if (item.action === 'delete_link') local.links = local.links.filter(l => !(l.domainId === p.domainId && l.slug === p.slug));
    if (item.action === 'remove_domain') { local.domains = local.domains.filter(d => d.id !== p.domainId); local.links = local.links.filter(l => l.domainId !== p.domainId); }
    if (item.action === 'rotate_selftest') local.accounts = local.accounts.map(a => a.id === p.accountId ? { ...a, needsSelftestKey: false } : a);
    if (item.action === 'cleanup_account') local.accounts = local.accounts.map(a => a.id === p.accountId ? { ...a, hasResources: false } : a);
    if (item.action === 'recover_account') local.accounts = local.accounts.map(a => a.id === p.accountId ? { ...a, hasResources: true } : a);
    return clone();
  }
  if (action === 'selftest_link') return { status: 'pending', message: '本地预览只展示检测流程，无法判断真实网络或大陆可达性。', checks: [] } satisfies Selftest;
  if (action === 'check_link_targets') return {checkedAt:now(),checks:[{label:'中国大陆打开的网址',status:'unknown',message:'本地预览未发起网络检测。',checkedAt:now(),source:'local',url:''},{label:'其他地区打开的网址',status:'unknown',message:'本地预览未发起网络检测。',checkedAt:now(),source:'local',url:''}]} satisfies TargetReport;
  if (action === 'check_pool_health') {const pool=(local.pools||[]).find(p=>p.id===payload.poolId);return {poolId:String(payload.poolId),accounts:(pool?.accountIds||[]).map(accountId=>({accountId,source:'unconfigured' as const,checkedAt:null,status:'unknown' as const,candidates:pool!.candidates.map(c=>({id:c.id,status:'unknown' as const,checkedAt:null,message:'本地预览未连接检测服务。'}))}))} satisfies PoolHealth;}
  if (action === 'prepare_monitor') return makePlan('启用检测服务',['配置您提供的 HTTPS 检测端点','保存密钥并启用定时检测'],['本地预览不会连接检测服务。'],'enable_monitor',{accountId:payload.accountId,endpoint:payload.endpoint});
  if (action === 'disable_monitor') return makePlan('停用检测服务',['移除定时检测与配置'],[],'disable_monitor',{accountId:payload.accountId});
  if (action === 'resume_monitor') return makePlan('继续处理检测服务',['复核待处理的检测配置并继续'],['本地预览不会连接云服务。'],'resume_monitor',{accountId:payload.accountId});
  if (action === 'export_config') return JSON.stringify({ version: 1, domains: local.domains.map(d => ({ host: d.host, prefix: d.prefix })), links: local.links }, null, 2);
  if (action === 'import_config') throw new Error('本地预览无法验证远端归属，请在桌面应用中导入备份。');
  if (action === 'check_update') return { status: 'unavailable' };
  if (action === 'install_update') throw new Error('本地预览无法安装更新。');
  throw new Error('未知操作。');
}
export async function dispatch<T>(action: Action, payload: Record<string, unknown> = {}): Promise<T> {
  if (preview) return previewDispatch(action, payload) as T;
  return invoke<T>('dispatch', { request: { action, payload } });
}
export function errorMessage(error: unknown): string { return typeof error === 'string' ? error : error instanceof Error ? error.message : '操作未完成，请重试。'; }
