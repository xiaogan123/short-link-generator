import { Fragment, useId, useRef, useState } from "react";
import { CaretDown, CaretLeft, CaretRight, Copy, Globe, PencilSimple, Plus, ShieldCheck, Trash } from "@phosphor-icons/react";
import { shortUrl } from "./validators";
import type { Domain, Link, Pool } from "./types";
import "./LinkGroups.css";

export type LinkGroup = { domain: Domain; links: Link[] };
export type LinkDetection = {
  label: string;
  tone: "slate" | "amber" | "red" | "green";
  detail?: string;
  title?: string;
};

type Props = {
  groups: LinkGroup[];
  pools: Pool[];
  getDetection: (link: Link) => LinkDetection;
  onCopy: (url: string) => void;
  onCheck: (link: Link, domain: Domain) => void;
  onEdit: (link: Link, usePlatform?: boolean) => void;
  onDelete: (link: Link, domain: Domain) => void;
  onCreate: (domainId: string) => void;
};

const pageSizes = [25, 50, 100] as const;

function formatUpdated(value: string) {
  if (!value) return "暂无更新时间";
  const date = new Date(value);
  return Number.isNaN(date.getTime())
    ? value
    : new Intl.DateTimeFormat("zh-CN", {
        year: "numeric",
        month: "2-digit",
        day: "2-digit",
        hour: "2-digit",
        minute: "2-digit",
      }).format(date);
}

function poolTargetUrl(prefix: string, suffix: string, code = "") {
  return `${prefix}${encodeURIComponent(code)}${suffix}`;
}

function TargetUrl({ url }: { url: string }) {
  if (!url) return <span className="slg-target-missing">未设置</span>;
  if (url.length <= 84)
    return <code className="slg-target-url" title={url}>{url}</code>;
  return (
    <details className="slg-long-url">
      <summary title={url}>
        <span className="slg-url-preview">{url.slice(0, 80)}…</span>
        <span className="slg-url-expand">查看完整地址</span>
      </summary>
      <code className="slg-target-url" title={url}>{url}</code>
    </details>
  );
}

function TargetLine({ label, url }: { label: string; url: string }) {
  return (
    <div className="slg-target-line">
      <span className="slg-target-label">{label}</span>
      <TargetUrl url={url} />
    </div>
  );
}

function Targets({ link, pool }: { link: Link; pool: Pool | undefined }) {
  if (!link.poolId) {
    return (
      <div className="slg-target-grid">
        <TargetLine label="大陆打开" url={link.cnUrl} />
        <TargetLine label="其他地区打开" url={link.defaultUrl} />
      </div>
    );
  }
  if (!pool) {
    return <p className="slg-pool-missing">平台地址已移除，无法从当前平台地址查看目标。</p>;
  }
  const enabledCount = pool.candidates.filter((candidate) => candidate.enabled).length;
  return (
    <div className="slg-pool-targets">
      <TargetLine
        label="官网链接"
        url={poolTargetUrl(pool.official.prefix, pool.official.suffix, link.code)}
      />
      <details className="slg-mainland">
        <summary>
          <span>大陆地址 · 已启用 {enabledCount} 个</span>
          <CaretDown size={14} aria-hidden="true" />
        </summary>
        <div className="slg-candidate-list">
          {pool.candidates.length ? pool.candidates.map((candidate, index) => (
            <div className="slg-candidate" key={candidate.id}>
              <span className="slg-candidate-name">
                {index === 0 ? "首选" : `备用 ${index}`}
                {!candidate.enabled && <span className="slg-disabled">已停用</span>}
              </span>
              <TargetUrl url={poolTargetUrl(candidate.prefix, candidate.suffix, link.code)} />
            </div>
          )) : <p className="slg-no-candidate">暂无大陆地址</p>}
        </div>
      </details>
    </div>
  );
}

function LinkGroupSection({ domain, links, pools, getDetection, onCopy, onCheck, onEdit, onDelete, onCreate }: Props & LinkGroup) {
  const detailPrefix = useId();
  const [pageSize, setPageSize] = useState<(typeof pageSizes)[number]>(25);
  const [pageState, setPageState] = useState({ linkKey: "", page: 1 });
  const [expanded, setExpanded] = useState<Set<string>>(() => new Set());
  const headerRef = useRef<HTMLElement>(null);
  const linkKey = JSON.stringify(links.map((link) => link.slug));
  if (pageState.linkKey !== linkKey) {
    setPageState({ linkKey, page: 1 });
    setExpanded(new Set());
  }
  const pageCount = Math.max(1, Math.ceil(links.length / pageSize));
  const page = pageState.linkKey === linkKey ? Math.min(pageState.page, pageCount) : 1;
  const start = (page - 1) * pageSize;
  const visible = links.slice(start, start + pageSize);
  const poolById = new Map(pools.map((pool) => [pool.id, pool]));
  const showPageStart = () => headerRef.current?.scrollIntoView?.({ block: "start" });
  const choosePage = (next: number) => {
    setPageState({ linkKey, page: Math.min(Math.max(next, 1), pageCount) });
    showPageStart();
  };
  const toggleDetails = (slug: string) => setExpanded((current) => {
    const next = new Set(current);
    if (next.has(slug)) next.delete(slug);
    else next.add(slug);
    return next;
  });

  return (
    <section className="slg-group" aria-label={`${domain.host} 的短链接`}>
      <header className="slg-group-head" ref={headerRef}>
        <div className="slg-domain-identity">
          <Globe size={19} aria-hidden="true" />
          <div>
            <h3>{domain.host}</h3>
            <span>/{domain.prefix}/</span>
          </div>
        </div>
        <span className="slg-group-count">{links.length} 条链接</span>
        {pageCount > 1 && <div className="slg-head-pager" aria-label={`${domain.host} 顶部分页`}>
          <button type="button" aria-label={`${domain.host} 顶部上一页`} disabled={page === 1} onClick={() => choosePage(page - 1)}><CaretLeft size={14} aria-hidden="true" /></button>
          <span>{page} / {pageCount}</span>
          <button type="button" aria-label={`${domain.host} 顶部下一页`} disabled={page === pageCount} onClick={() => choosePage(page + 1)}><CaretRight size={14} aria-hidden="true" /></button>
        </div>}
      </header>
      {links.length ? (
        <>
          <table className="slg-table" aria-label={`${domain.host} 的链接列表`}>
            <colgroup><col className="slg-col-link" /><col className="slg-col-kind" /><col className="slg-col-check" /><col className="slg-col-actions" /></colgroup>
            <thead><tr><th scope="col">短链接</th><th scope="col">目标类型</th><th scope="col">检测与更新</th><th scope="col">操作</th></tr></thead>
            <tbody>
              {visible.map((link) => {
                const url = shortUrl(domain.host, domain.prefix, link.slug);
                const pool = link.poolId ? poolById.get(link.poolId) : undefined;
                const detection = getDetection(link);
                const open = expanded.has(link.slug);
                const detailId = `${detailPrefix}-${encodeURIComponent(link.slug)}`;
                return (
                  <Fragment key={`${domain.id}:${link.slug}`}>
                    <tr className="slg-link-row" aria-label={url}>
                      <th scope="row" className="slg-link-cell">
                        <span className="slg-link-slug">/{link.slug}</span>
                        <span className="slg-short-url" title={url}>{url}</span>
                      </th>
                      <td className="slg-kind-cell">
                        <span className="slg-kind">{link.poolId ? "跟随平台地址" : "手动地址"}</span>
                        {link.poolId && <span className="slg-platform-name" title={pool?.name || "已移除"}>{pool?.name || "已移除"}</span>}
                        {link.poolId && <span className="slg-code" title={link.code || "未填写"}>邀请码：{link.code || "未填写"}</span>}
                      </td>
                      <td className="slg-status-cell">
                        <span className={`slg-check slg-check-${detection.tone}`} title={detection.title}>
                          <span className="slg-check-dot" aria-hidden="true" />{detection.label}
                        </span>
                        <span className="slg-updated">{link.updated && "更新于 "}{formatUpdated(link.updated)}</span>
                      </td>
                      <td className="slg-action-cell">
                        <div className="slg-actions">
                          <button className="slg-copy" type="button" aria-label={`复制 ${link.slug}`} title="复制链接" onClick={() => onCopy(url)}><Copy size={15} aria-hidden="true" /><span>复制</span></button>
                          <button type="button" aria-label={`检测 ${link.slug}`} title="检测链接" onClick={() => onCheck(link, domain)}><ShieldCheck size={15} aria-hidden="true" /><span>检测</span></button>
                          <button type="button" aria-label={`编辑 ${link.slug}`} title="编辑链接" onClick={() => onEdit(link)}><PencilSimple size={15} aria-hidden="true" /><span>编辑</span></button>
                          <button className="slg-details-toggle" type="button" aria-label={`详情 ${link.slug}`} aria-expanded={open} aria-controls={open ? detailId : undefined} onClick={() => toggleDetails(link.slug)}><CaretDown size={15} aria-hidden="true" /><span>详情</span></button>
                        </div>
                      </td>
                    </tr>
                    {open && (
                      <tr className="slg-detail-row" id={detailId}>
                        <td colSpan={4}>
                          <div className="slg-detail-body">
                            <Targets link={link} pool={pool} />
                            {detection.detail && <p className="slg-check-detail">{detection.detail}</p>}
                            <div className="slg-detail-actions">
                              {!link.poolId && pools.length > 0 && <button type="button" aria-label={`将 ${link.slug} 改为平台地址`} onClick={() => onEdit(link, true)}>改为平台地址</button>}
                              <button className="slg-delete" type="button" aria-label={`删除 ${link.slug}`} onClick={() => onDelete(link, domain)}><Trash size={15} aria-hidden="true" />删除链接</button>
                            </div>
                          </div>
                        </td>
                      </tr>
                    )}
                  </Fragment>
                );
              })}
            </tbody>
          </table>
          <div className="slg-pagination" aria-label={`${domain.host} 的分页`}>
            <span>显示 {start + 1}–{start + visible.length} / 共 {links.length} 条</span>
            <label>每页 <select aria-label={`${domain.host} 每页条数`} value={pageSize} onChange={(event) => { setPageSize(Number(event.target.value) as (typeof pageSizes)[number]); setPageState({ linkKey, page: 1 }); showPageStart(); }}>
              {pageSizes.map((size) => <option value={size} key={size}>{size}</option>)}
            </select> 条</label>
            <div className="slg-page-controls">
              <button type="button" aria-label={`${domain.host} 上一页`} disabled={page === 1} onClick={() => choosePage(page - 1)}>上一页</button>
              <span>第 {page} / {pageCount} 页</span>
              <button type="button" aria-label={`${domain.host} 下一页`} disabled={page === pageCount} onClick={() => choosePage(page + 1)}>下一页</button>
            </div>
          </div>
        </>
      ) : (
        <div className="slg-domain-empty">
          <div><strong>这个域名还没有短链接</strong><span>可以从 /{domain.prefix}/ 创建第一条。</span></div>
          <button className="slg-create" type="button" onClick={() => onCreate(domain.id)}><Plus size={16} aria-hidden="true" />创建第一条短链接</button>
        </div>
      )}
    </section>
  );
}

export default function LinkGroups(props: Props) {
  return <div className="slg-groups">{props.groups.map((group) => <LinkGroupSection key={group.domain.id} {...props} {...group} />)}</div>;
}
