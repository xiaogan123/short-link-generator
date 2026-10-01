import { CaretDown, Copy, Globe, PencilSimple, Plus, ShieldCheck, Trash } from "@phosphor-icons/react";
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

export default function LinkGroups({
  groups,
  pools,
  getDetection,
  onCopy,
  onCheck,
  onEdit,
  onDelete,
  onCreate,
}: Props) {
  const poolById = new Map(pools.map((pool) => [pool.id, pool]));
  return (
    <div className="slg-groups">
      {groups.map(({ domain, links }) => (
        <section className="slg-group" key={domain.id} aria-label={`${domain.host} 的短链接`}>
          <header className="slg-group-head">
            <div className="slg-domain-identity">
              <Globe size={19} aria-hidden="true" />
              <div>
                <h3>{domain.host}</h3>
                <span>/{domain.prefix}/</span>
              </div>
            </div>
            <span className="slg-group-count">{links.length} 条链接</span>
          </header>
          {links.length ? (
            <div className="slg-cards">
              {links.map((link) => {
                const url = shortUrl(domain.host, domain.prefix, link.slug);
                const pool = link.poolId ? poolById.get(link.poolId) : undefined;
                const detection = getDetection(link);
                return (
                  <article className="slg-card" key={link.slug} aria-label={url}>
                    <div className="slg-card-head">
                      <div className="slg-link-identity">
                        <h4>/{link.slug}</h4>
                        <span className="slg-short-url" title={url}>{url}</span>
                      </div>
                      <button className="slg-copy" type="button" aria-label={`复制 ${link.slug}`} onClick={() => onCopy(url)}>
                        <Copy size={17} aria-hidden="true" />复制链接
                      </button>
                    </div>
                    <div className="slg-meta">
                      <span className="slg-kind">{link.poolId ? "跟随平台地址" : "手动地址"}</span>
                      {link.poolId && (
                        <>
                          <span className="slg-meta-item"><span>平台</span><strong>{pool?.name || "已移除"}</strong></span>
                          <span className="slg-meta-item"><span>邀请码</span><strong>{link.code || "未填写"}</strong></span>
                        </>
                      )}
                    </div>
                    <Targets link={link} pool={pool} />
                    <footer className="slg-card-foot">
                      <div className="slg-check-info">
                        <span className={`slg-check slg-check-${detection.tone}`} title={detection.title}>
                          <span className="slg-check-dot" aria-hidden="true" />
                          {detection.label}
                        </span>
                        {detection.detail && <span className="slg-check-detail">{detection.detail}</span>}
                        <span className="slg-updated">{link.updated && "更新于 "}{formatUpdated(link.updated)}</span>
                      </div>
                      <div className="slg-actions">
                        <button type="button" aria-label={`检测 ${link.slug}`} onClick={() => onCheck(link, domain)}>
                          <ShieldCheck size={16} aria-hidden="true" />检测
                        </button>
                        <button type="button" aria-label={`编辑 ${link.slug}`} onClick={() => onEdit(link)}>
                          <PencilSimple size={16} aria-hidden="true" />编辑
                        </button>
                        {!link.poolId && pools.length > 0 && (
                          <button type="button" aria-label={`将 ${link.slug} 改为平台地址`} onClick={() => onEdit(link, true)}>
                            改为平台地址
                          </button>
                        )}
                        <button className="slg-delete" type="button" aria-label={`删除 ${link.slug}`} onClick={() => onDelete(link, domain)}>
                          <Trash size={15} aria-hidden="true" />删除
                        </button>
                      </div>
                    </footer>
                  </article>
                );
              })}
            </div>
          ) : (
            <div className="slg-domain-empty">
              <div>
                <strong>这个域名还没有短链接</strong>
                <span>可以从 /{domain.prefix}/ 创建第一条。</span>
              </div>
              <button className="slg-create" type="button" onClick={() => onCreate(domain.id)}>
                <Plus size={16} aria-hidden="true" />创建第一条短链接
              </button>
            </div>
          )}
        </section>
      ))}
    </div>
  );
}
