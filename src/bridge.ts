import { invoke } from '@tauri-apps/api/core';
import { normalizeHost } from './validators';
import type { Action, ClickStats, ClickStatsDays, ClickStatsTotals, DomainPreparation, Link, Plan, Pool, PoolHealth, Selftest, State, StatsCenterReport, StatsCenterRow, TargetReport } from './types';

export const preview = new URLSearchParams(window.location.search).get('preview') === '1';
const now = () => new Date().toISOString();
const uid = () => Math.random().toString(36).slice(2, 10);
const demoState: State = {
  appVersion: '0.0.0-preview',
  accounts: [
    { id: 'demo-a', label: '示例账户 · 团队', cloudflareName: 'Example team', zones: [{id:'demo-zone-1',name:'example.com',status:'active'},{id:'demo-zone-2',name:'example.org',status:'active'}], zoneCount: 2, checkedAt: now(), hasResources: true, needsSelftestKey: false, needsCredentialMigration: new URLSearchParams(window.location.search).get('legacyCredentials') === '1' },
    { id: 'demo-b', label: '示例账户 · 个人', cloudflareName: 'Example personal', zones: [{id:'demo-zone-3',name:'example.net',status:'active'}], zoneCount: 1, checkedAt: now(), hasResources: false, needsSelftestKey: true, needsCredentialMigration: false },
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
  pendingOperations: new URLSearchParams(window.location.search).get('legacyRecovery') === '1' ? ['旧版检测密钥操作待确认'] : [],
  pendingActions: new URLSearchParams(window.location.search).get('legacyRecovery') === '1' ? [{kind:'recover_selftest_resources',poolId:null,accountId:'demo-b',label:'找回检测服务配置'}] : [],
  pools: [],
};
let local: State = structuredClone(demoState);
const previewStatsAccounts = new Set<string>();
if (preview && new URLSearchParams(window.location.search).get('clickStats') === '1') previewStatsAccounts.add('demo-a');
// Optional, isolated examples for checking the desktop layout without cloud access.
if (preview && new URLSearchParams(window.location.search).get('visualReview') === '1') {
  local.domains.push({id:'demo-d3',accountId:'demo-b',zoneId:'demo-zone-3',host:'new.example.net',prefix:'go',routeId:'demo-route-3'});
  local.pools = [{id:'demo-platform',name:'示例平台',official:{prefix:'https://www.example.com/join/',suffix:''},candidates:[
    {id:'demo-c1',prefix:'https://cn.example.com/join/',suffix:'',enabled:true},
    {id:'demo-c2',prefix:'https://backup.example.org/join/',suffix:'',enabled:true},
    {id:'demo-c3',prefix:'https://old.example.org/join/',suffix:'',enabled:false},
  ],updated:now(),accountIds:['demo-a']}];
  local.links[0] = {...local.links[0],poolId:'demo-platform',code:'DEMO2026'};
  local.links[2] = {...local.links[2],poolId:'demo-platform',code:'EXAMPLE88'};
}
if (preview && new URLSearchParams(window.location.search).get('manyLinks') === '1') {
  for (let number = local.links.length + 1; number <= 100; number++) {
    const slug = `sample-${String(number).padStart(3, '0')}`;
    local.links.push({
      domainId: number % 2 ? 'demo-d1' : 'demo-d2',
      slug,
      cnUrl: `https://example.com/zh/${slug}`,
      defaultUrl: `https://example.org/en/${slug}`,
      updated: now(),
    });
  }
}
const plans = new Map<string, { plan: Plan; action: string; payload: Record<string, unknown> }>();
const clone = ():State => {const state=structuredClone(local);state.links=state.links.map(link=>{if(!link.poolId)return link;const pool=state.pools?.find(p=>p.id===link.poolId);if(!pool)return link;const code=encodeURIComponent(link.code||'');const candidate=pool.candidates.find(c=>c.enabled);return {...link,cnUrl:candidate?candidate.prefix+code+candidate.suffix:'',defaultUrl:pool.official.prefix+code+pool.official.suffix};});return state;};
function makePlan(title: string, steps: string[], warnings: string[], action: string, payload: Record<string, unknown>, domainTakeoverConfirmation?: string): Plan {
  const plan: Plan = { id: uid(), title, steps, warnings, expiresAt: new Date(Date.now() + 300000).toISOString(), ...(domainTakeoverConfirmation ? { domainTakeoverConfirmation } : {}) };
  plans.set(plan.id, { plan, action, payload });
  return plan;
}
function previewDispatch(action: Action, payload: Record<string, unknown>): unknown {
  if (action === 'get_state') return clone();
  if (action === 'get_stats_center') {
    const accountId = typeof payload.accountId === 'string' ? payload.accountId : '';
    const account = local.accounts.find((item) => item.id === accountId);
    if (!account) throw new Error('请选择有效的 Cloudflare 账户。');
    if (![1,7,30].includes(Number(payload.days)) || typeof payload.days !== 'number') throw new Error('请选择 1、7 或 30 天的统计范围。');
    if (!Number.isSafeInteger(payload.page) || Number(payload.page) < 1) throw new Error('统计页码无效，请重新读取。');
    if (payload.pageSize !== 25) throw new Error('统计中心每页固定显示 25 条短链接。');
    const requestedDomainId = payload.domainId === undefined || payload.domainId === null ? null : payload.domainId;
    if (requestedDomainId !== null && (typeof requestedDomainId !== 'string' || !local.domains.some((item) => item.id === requestedDomainId && item.accountId === accountId))) {
      throw new Error('所选域名不属于当前账户，请重新选择。');
    }
    const days = payload.days as ClickStatsDays;
    const page = Number(payload.page);
    const domainIds = new Set(local.domains.filter((item) => item.accountId === accountId && (!requestedDomainId || item.id === requestedDomainId)).map((item) => item.id));
    const matchingLinks = local.links
      .filter((item) => domainIds.has(item.domainId))
      .sort((left, right) => left.domainId.localeCompare(right.domainId) || left.slug.localeCompare(right.slug));
    const base = {accountId,domainId:requestedDomainId,days,page,pageSize:25 as const,totalLinks:matchingLinks.length,queriedAt:now(),estimated:true as const};
    if (matchingLinks.length === 0) return {status:'no_data',message:'当前账户尚无本机短链接。此状态不代表历史统计为零。',...base,rows:[]} satisfies StatsCenterReport;
    if (!previewStatsAccounts.has(accountId)) return {status:'disabled',message:'本地预览：此示例账户尚未启用统计。',...base} satisfies StatsCenterReport;
    const sampleTotals = (item: Link, index: number): ClickStatsTotals => {
      const seed = [...`${item.domainId}:${item.slug}`].reduce((sum, character) => sum + character.charCodeAt(0), 0) + index;
      const multiplier = days === 1 ? 1 : days === 7 ? 4 : 12;
      const likelyHuman = (18 + seed % 23) * multiplier;
      const likelyBot = (3 + seed % 7) * multiplier;
      const unknown = (2 + seed % 5) * multiplier;
      return {total:likelyHuman+likelyBot+unknown,likelyHuman,likelyBot,unknown,previews:(seed%6)*multiplier,prefetches:(seed%4)*multiplier};
    };
    const allRows: StatsCenterRow[] = matchingLinks.map((item,index)=>({domainId:item.domainId,slug:item.slug,totals:sampleTotals(item,index)}));
    if (new URLSearchParams(window.location.search).get('statsNoData') === '1') {
      const rows = allRows.slice((page-1)*25,page*25).map((row)=>({...row,totals:{total:0,likelyHuman:0,likelyBot:0,unknown:0,previews:0,prefetches:0}}));
      return {status:'no_data',message:'所选时间范围暂时没有可显示的估算记录。',...base,rows} satisfies StatsCenterReport;
    }
    const totals = allRows.reduce<ClickStatsTotals>((sum,row)=>({total:sum.total+row.totals.total,likelyHuman:sum.likelyHuman+row.totals.likelyHuman,likelyBot:sum.likelyBot+row.totals.likelyBot,unknown:sum.unknown+row.totals.unknown,previews:sum.previews+row.totals.previews,prefetches:sum.prefetches+row.totals.prefetches}),{total:0,likelyHuman:0,likelyBot:0,unknown:0,previews:0,prefetches:0});
    return {status:'ready',message:'本地预览：以下为示例统计，未查询真实点击。',...base,totals,rows:allRows.slice((page-1)*25,page*25)} satisfies StatsCenterReport;
  }
  if (action === 'get_link_stats') {
    if (![1,7,30].includes(Number(payload.days)) || typeof payload.days !== 'number') throw new Error('请选择 1、7 或 30 天的统计范围。');
    const domain = local.domains.find((item) => item.id === payload.domainId);
    if (!domain || !local.links.some((link) => link.domainId === domain.id && link.slug === payload.slug)) throw new Error('短链接不存在，请刷新列表。');
    const ready = previewStatsAccounts.has(domain.accountId);
    return {status:ready?'ready':'disabled',message:ready?'本地预览：以下为示例统计，未查询真实点击。':'本地预览：此示例账户尚未启用统计。',domainId:domain.id,slug:String(payload.slug),days:payload.days as ClickStatsDays,queriedAt:now(),estimated:true,...(ready?{totals:{total:128,likelyHuman:84,likelyBot:17,unknown:27,previews:12,prefetches:8}}:{})} satisfies ClickStats;
  }
  if (action === 'token_template') return 'https://dash.cloudflare.com/profile/api-tokens';
  if (action === 'refresh_accounts') { const accountId=typeof payload.accountId==='string' ? payload.accountId : ''; local.accounts = local.accounts.map(a => !accountId || a.id === accountId ? ({ ...a, checkedAt: now() }) : a); return clone(); }
  if (action === 'refresh_domains') {
    const accountId=String(payload.accountId || '');
    if (!accountId) throw new Error('请选择要刷新域名的 Cloudflare 账户。');
    const account=local.accounts.find(item=>item.id===accountId);
    if (!account) throw new Error('所选 Cloudflare 账户已不可用。');
    local.accounts=local.accounts.map(item=>item.id===accountId ? {...item,checkedAt:now()} : item);
    return clone();
  }
  if (action === 'import_token') {
    const token = String(payload.token || '').trim();
    if (!token) throw new Error('请先粘贴令牌。');
    const existing = local.accounts.find(a => a.id === 'demo-imported');
    if (existing && !payload.replace) throw new Error('该账户已经存在。请确认是否替换本机保存的令牌。');
    if (!existing) local.accounts.push({ id: 'demo-imported', label: '导入的示例账户', zoneCount: 1, checkedAt: now(), hasResources: false, needsSelftestKey: false, needsCredentialMigration: false });
    else local.accounts = local.accounts.map(a => a.id === existing.id ? {...a, needsCredentialMigration: false} : a);
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
    const managedDomain = local.domains.find(domain => domain.host === host);
    const isManaged = Boolean(managedDomain);
    const needsTakeover = !isManaged && host.endsWith('.example.com');
    const checks = [
      { label: '域名格式', ok: true, level: 'pass' as const, message: '格式有效。' },
      { label: '区域与代理', ok: true, level: 'pass' as const, message: '示例数据：已启用域名与代理状态。' },
      isManaged
        ? { label: '域名已接入', ok: false, level: 'error' as const, message: `示例数据：${host} 已使用 /${managedDomain?.prefix}/ 目录。一个主机名只能接入一个链接目录，请管理已有域名或更换主机名。` }
        : needsTakeover
          ? { label: '现有网页', ok: true, level: 'warning' as const, message: `示例数据：${host}/${prefix}/ 及随机子路径返回 HTTP 200，确认后可将该目录用于短链接。` }
          : { label: '链接目录', ok: true, level: 'pass' as const, message: '示例数据：目录与随机子路径均返回 404；未发起真实探测。' },
    ];
    const candidate = candidates.length === 1 ? candidates[0] : undefined;
    const confirmation = needsTakeover ? `确认将 ${host}/${prefix}/ 及其所有下级内容改作短链接。原该目录内网页将不能继续按原方式访问。` : undefined;
    const plan = candidate && !isManaged ? makePlan(`添加 ${host}`, [`在 ${candidate.label} 上配置 ${host}/${prefix}/*`, '保存域名与路由关系'], ['本地预览使用示例数据，不会连接云服务。'], 'add_domain', { host, prefix, accountId: candidate.accountId, zoneId: candidate.zoneId }, confirmation) : undefined;
    return { host, prefix, candidates, checks, canApply: Boolean(plan), plan } satisfies DomainPreparation;
  }
  if (action === 'prepare_domain_dns') {
    const host = normalizeHost(String(payload.input || ''));
    const candidates = local.accounts.filter(a => !payload.accountId || a.id === payload.accountId).flatMap(a => (a.zones || []).filter(zone => zone.status === 'active' && (host === zone.name || host.endsWith(`.${zone.name}`))).map(zone => ({accountId:a.id,label:a.label,zoneId:zone.id,status:zone.status})));
    const selected = candidates.length === 1 ? candidates[0] : undefined;
    const status = host.startsWith('missing.') ? 'missing' : host.startsWith('grey.') ? 'dnsOnly' : 'ready';
    const actions = status === 'missing' ? [{kind:'createPlaceholder' as const,recordType:'AAAA',name:host}] : status === 'dnsOnly' ? [{kind:'enableProxy' as const,recordType:'A',name:host}] : [];
    const checks = status === 'ready' ? [{label:'DNS 与代理',ok:true,level:'pass' as const,message:'示例数据：当前主机已使用代理。'}] : status === 'missing' ? [{label:'DNS 记录',ok:false,level:'error' as const,message:'示例数据：精确主机名没有 DNS 记录。可创建一条代理 AAAA 占位记录。'}] : [{label:'DNS 代理',ok:false,level:'error' as const,message:'示例数据：精确主机名的记录未启用代理。可保持记录内容不变，只开启代理。'}];
    const plan = selected && status !== 'ready' ? makePlan(`修复 ${host} 的 DNS 与代理`, actions.map(item => item.kind === 'createPlaceholder' ? `为 ${item.name} 创建代理 ${item.recordType} 占位记录` : `为 ${item.name} 的 ${item.recordType} 记录开启代理`), ['这只修改此精确主机名的 DNS/代理状态，不会接入短链接目录。'], 'fix_domain_dns', {host,accountId:selected.accountId,zoneId:selected.zoneId}) : undefined;
    return {host,candidates,checks,dnsStatus:status,actions,canApply:Boolean(plan),plan};
  }
  if (action === 'prepare_change') {
    const kind = String(payload.kind);
    if (kind === 'enable_click_stats' || kind === 'disable_click_stats') {
      const account = local.accounts.find((item) => item.id === payload.accountId);
      if (!account?.hasResources) throw new Error('请先为此账户接入短链接域名。');
      return makePlan(kind === 'enable_click_stats' ? '启用点击统计' : '停用点击统计', [
        `范围：${account.label} 的全部已接入域名`,
        kind === 'enable_click_stats' ? '后台记录链接和请求分类；访客保持直接跳转，不做访问验证' : '停止之后的统计记录，不改变链接跳转',
      ], ['本地预览只演示流程，不会修改云端。', '统计是估算访问次数，不是去重人数，也不能保证准确识别每个真人。'], kind, {accountId:account.id});
    }
    if (kind === 'save_link') {
      if (payload.createOnly !== undefined && typeof payload.createOnly !== 'boolean') throw new Error('创建方式格式无效。');
      const exact = local.links.some(l => l.domainId === payload.domainId && l.slug === payload.slug);
      const slug = String(payload.slug);
      if (!exact || payload.createOnly === true) {
        if (local.links.some(l => l.domainId === payload.domainId && l.slug.toLowerCase() === slug.toLowerCase())) throw new Error('这个名称已被使用，请换一个名称。现有链接不会被覆盖。');
        payload = { ...payload, slug: slug.toLowerCase() };
      }
    }
    if (kind === 'migrate_credentials') {
      const account = local.accounts.find(a => a.id === payload.accountId);
      if (!account?.needsCredentialMigration) throw new Error('此账户无需更新本机授权。');
      const plan = makePlan('更新本机授权', ['读取此账户的旧凭据', '保存到新的本机凭据存储并验证'], ['本地预览只模拟迁移，不读取真实凭据或访问云服务。'], kind, {accountId:account.id});
      plan.credentialMigrationConfirmation = '系统可能需要你授权访问已保存的令牌或检测密钥；已有记录会保留，云端配置不变。';
      return plan;
    }
    if (kind === 'recover_selftest_resources') {
      const account = local.accounts.find(a => a.id === payload.accountId);
      if (!account || account.hasResources || !local.pendingActions.some(a => a.kind === kind && a.accountId === account.id)) throw new Error('当前账户无需找回检测配置，请重新核对状态。');
      return makePlan('找回检测服务配置', ['只读核对云端唯一的检测服务及其归属', '登记本机检测配置，保留已有密钥与待处理记录', '完成后另行确认恢复检测密钥'], ['本地预览只模拟找回配置，不读取真实凭据或访问云服务。'], kind, {accountId:account.id});
    }
    if (kind === 'upgrade_worker' || kind === 'resume_worker_upgrade' || kind === 'dismiss_worker_upgrade') {
      if (!local.accounts.some(a => a.id === payload.accountId && a.hasResources)) throw new Error('账户尚未部署短链接服务。');
      return makePlan(kind === 'dismiss_worker_upgrade' ? '解除本机升级记录' : '启用名称大小写兼容',
        kind === 'dismiss_worker_upgrade' ? ['只解除本机待处理记录，云端与密钥保持原样'] : ['核对云端服务归属', '保留密钥和检测设置，启用名称大小写兼容'],
        ['本地预览只模拟操作，不连接云端。'], kind, payload);
    }
    const titles: Record<string, string> = { save_link: '保存短链接', delete_link: '删除短链接', save_pool: '保存平台地址', resume_pool_sync:'继续同步平台地址', delete_pool: '删除平台地址', remove_domain: '移除域名', cleanup_account: '清理远端资源', recover_account: '恢复账户资源', rotate_selftest: '轮换检测密钥', recover_selftest_rotation: '恢复检测密钥', resume_selftest_rotation: '继续恢复检测密钥' };
    if (kind === 'delete_pool' && local.links.some(l => l.poolId === payload.poolId)) throw new Error('平台地址仍有链接引用，无法删除。');
    return makePlan(titles[kind] || '确认变更', [`核对当前状态与资源归属`, `${titles[kind] || kind}并记录结果`], kind === 'delete_link' || kind === 'remove_domain' || kind === 'cleanup_account' ? ['该操作会修改远端资源。请确认影响范围。'] : [], kind, payload);
  }
  if (action === 'apply_plan') {
    const item = plans.get(String(payload.planId));
    if (!item || Date.parse(item.plan.expiresAt) < Date.now()) throw new Error('计划已过期，请重新准备。');
    const p = item.payload;
    if (item.plan.domainTakeoverConfirmation && payload.acknowledgeDomainTakeover !== true) throw new Error('请先确认链接目录的接管范围。');
    if (item.action === 'migrate_credentials' && payload.acknowledgeCredentialMigration !== true) throw new Error('请先确认更新本机授权。');
    plans.delete(item.plan.id);
    if (item.action === 'migrate_credentials') local.accounts = local.accounts.map(a => a.id === p.accountId ? {...a, needsCredentialMigration:false} : a);
    if (item.action === 'enable_click_stats') previewStatsAccounts.add(String(p.accountId));
    if (item.action === 'disable_click_stats') previewStatsAccounts.delete(String(p.accountId));
    if (item.action === 'recover_selftest_resources') {
      const account = local.accounts.find(a => a.id === p.accountId);
      if (!account || account.hasResources || !local.pendingActions.some(a => a.kind === item.action && a.accountId === account.id)) throw new Error('计划已失效，请重新核对状态。');
      local.accounts = local.accounts.map(a => a.id === account.id ? {...a,hasResources:true} : a);
      local.pendingActions = local.pendingActions.map(a => a.kind === item.action && a.accountId === account.id ? {...a,kind:'recover_selftest_rotation',label:'恢复旧版自检密钥操作'} : a);
    }
    if (item.action === 'add_domain') local.domains.push({ id: uid(), host: String(p.host), prefix: String(p.prefix), accountId: String(p.accountId), zoneId: String(p.zoneId), routeId: `demo-route-${uid()}` });
    if (item.action === 'save_link') {
      if (p.createOnly === true && local.links.some(l => l.domainId === p.domainId && l.slug.toLowerCase() === String(p.slug).toLowerCase())) throw new Error('这个名称已被使用，请换一个名称。现有链接不会被覆盖。');
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
  if (action === 'check_link_targets') {
    const dnsMode = payload.dnsMode === undefined ? 'system' : payload.dnsMode;
    if (dnsMode !== 'system' && dnsMode !== 'public') throw new Error('不支持的域名查询方式，请重新检测');
    return {checkedAt:now(),dnsMode,checks:[{label:'中国大陆打开的网址',status:'unknown',message:'本地预览未发起网络检测。',checkedAt:now(),source:'local',url:'',dnsMode},{label:'其他地区打开的网址',status:'unknown',message:'本地预览未发起网络检测。',checkedAt:now(),source:'local',url:'',dnsMode}]} satisfies TargetReport;
  }
  if (action === 'check_pool_health') {const pool=(local.pools||[]).find(p=>p.id===payload.poolId);return {poolId:String(payload.poolId),accounts:(pool?.accountIds||[]).map(accountId=>({accountId,source:'unconfigured' as const,checkedAt:null,status:'unknown' as const,candidates:pool!.candidates.map(c=>({id:c.id,status:'unknown' as const,checkedAt:null,message:'本地预览未连接检测服务。'}))}))} satisfies PoolHealth;}
  if (action === 'prepare_monitor') return makePlan('启用检测服务',['配置您提供的 HTTPS 检测端点','保存密钥并启用定时检测'],['本地预览不会连接检测服务。'],'enable_monitor',{accountId:payload.accountId,endpoint:payload.endpoint});
  if (action === 'disable_monitor') return makePlan('停用检测服务',['移除定时检测与配置'],[],'disable_monitor',{accountId:payload.accountId});
  if (action === 'resume_monitor') return makePlan('继续处理检测服务',['复核待处理的检测配置并继续'],['本地预览不会连接云服务。'],'resume_monitor',{accountId:payload.accountId});
  if (action === 'export_config') return JSON.stringify({ version: 1, domains: local.domains.map(d => ({ host: d.host, prefix: d.prefix })), links: local.links }, null, 2);
  if (action === 'import_config') throw new Error('本地预览无法验证远端归属，请在桌面应用中导入备份。');
  if (action === 'check_update') return { status: 'unavailable', currentVersion: local.appVersion };
  if (action === 'install_update') throw new Error('本地预览无法安装更新。');
  throw new Error('未知操作。');
}
export async function dispatch<T>(action: Action, payload: Record<string, unknown> = {}): Promise<T> {
  if (preview) return previewDispatch(action, payload) as T;
  return invoke<T>('dispatch', { request: { action, payload } });
}
export function errorMessage(error: unknown): string { return typeof error === 'string' ? error : error instanceof Error ? error.message : '操作未完成，请重试。'; }
