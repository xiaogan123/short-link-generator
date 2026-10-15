import { useEffect, useMemo, useRef, useState } from "react";
import { ArrowClockwise, ArrowSquareOut, CaretLeft, CaretRight } from "@phosphor-icons/react";
import { dispatch, errorMessage, preview } from "./bridge";
import type {
  Account,
  ClickStatsDays,
  ClickStatsTotals,
  Domain,
  Link,
  StatsCenterReport,
} from "./types";
import "./StatsCenter.css";

const PAGE_SIZE = 25 as const;
const ranges: { value: ClickStatsDays; label: string }[] = [
  { value: 1, label: "近 24 小时" },
  { value: 7, label: "近 7 天" },
  { value: 30, label: "近 30 天" },
];

type ViewState =
  | { kind: "idle" }
  | { kind: "loading" }
  | { kind: "report"; report: StatsCenterReport }
  | { kind: "error"; message: string };

type Props = {
  accounts: Account[];
  domains: Domain[];
  links: Link[];
  revision: number;
  busy?: boolean;
  configurationError?: { accountId: string; message: string } | null;
  onConfigure: (account: Account, enabled: boolean) => void;
  onOpenLinkStats: (link: Link, domain: Domain) => void;
  onScopeInvalidate?: () => void;
};

function validTotals(totals: unknown): totals is ClickStatsTotals {
  if (!totals || typeof totals !== "object") return false;
  const value = totals as ClickStatsTotals;
  const numbers = [value.total, value.likelyHuman, value.likelyBot, value.unknown, value.previews, value.prefetches];
  return numbers.every((number) => Number.isSafeInteger(number) && number >= 0)
    && value.total === value.likelyHuman + value.likelyBot + value.unknown;
}

function validReport(
  value: unknown,
  expected: { accountId: string; domainId: string | null; days: ClickStatsDays; page: number },
  domains: Domain[],
  links: Link[],
): value is StatsCenterReport {
  if (!value || typeof value !== "object") return false;
  const report = value as StatsCenterReport;
  const statuses = ["ready", "disabled", "no_data", "permission_denied", "unavailable"];
  if (!statuses.includes(report.status)
    || typeof report.message !== "string"
    || report.accountId !== expected.accountId
    || report.domainId !== expected.domainId
    || report.days !== expected.days
    || report.page !== expected.page
    || report.pageSize !== PAGE_SIZE
    || !Number.isSafeInteger(report.totalLinks)
    || report.totalLinks < 0
    || typeof report.queriedAt !== "string"
    || report.estimated !== true) return false;

  if (report.status !== "ready" && report.status !== "no_data") {
    return report.totals === undefined && report.rows === undefined;
  }
  if (!Array.isArray(report.rows) || report.rows.length > PAGE_SIZE) return false;
  if (report.status === "ready" ? !validTotals(report.totals) : report.totals !== undefined) return false;
  const allowedDomains = new Set(domains
    .filter((domain) => domain.accountId === expected.accountId && (!expected.domainId || domain.id === expected.domainId))
    .map((domain) => domain.id));
  const knownLinks = new Set(links.map((link) => `${link.domainId}\u0000${link.slug}`));
  const seen = new Set<string>();
  for (const row of report.rows) {
    if (!row || typeof row.domainId !== "string" || typeof row.slug !== "string" || !row.slug
      || !allowedDomains.has(row.domainId) || !knownLinks.has(`${row.domainId}\u0000${row.slug}`)
      || !validTotals(row.totals)) return false;
    const key = `${row.domainId}\u0000${row.slug}`;
    if (seen.has(key)) return false;
    seen.add(key);
    if (report.status === "no_data" && Object.values(row.totals).some((number) => number !== 0)) return false;
  }
  return true;
}

function number(value: number) {
  return value.toLocaleString("zh-CN");
}

function wholePercentages(values: number[]) {
  const total = values.reduce((sum, value) => sum + value, 0);
  if (total === 0) return values.map(() => 0);
  const exact = values.map((value) => value * 100 / total);
  const result = exact.map(Math.floor);
  const remainder = 100 - result.reduce((sum, value) => sum + value, 0);
  exact
    .map((value, index) => ({ index, fraction: value - Math.floor(value) }))
    .sort((left, right) => right.fraction - left.fraction || left.index - right.index)
    .slice(0, remainder)
    .forEach(({ index }) => { result[index] += 1; });
  return result;
}

function formatTime(value: string) {
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return value;
  return new Intl.DateTimeFormat("zh-CN", {
    year: "numeric",
    month: "2-digit",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
  }).format(date);
}

function Notice({ title, children, tone = "neutral" }: {
  title: string;
  children: React.ReactNode;
  tone?: "neutral" | "warning" | "error";
}) {
  return (
    <div className={`scenter-notice scenter-notice-${tone}`} role={tone === "error" ? "alert" : "status"}>
      <strong>{title}</strong>
      <div>{children}</div>
    </div>
  );
}

export default function StatsCenter({
  accounts,
  domains,
  links,
  revision,
  busy = false,
  configurationError,
  onConfigure,
  onOpenLinkStats,
  onScopeInvalidate,
}: Props) {
  const [accountId, setAccountId] = useState("");
  const [domainId, setDomainId] = useState("");
  const [days, setDays] = useState<ClickStatsDays>(7);
  const [page, setPage] = useState(1);
  const [view, setView] = useState<ViewState>({ kind: "idle" });
  const [knownTotalLinks, setKnownTotalLinks] = useState<number | null>(null);
  const [openerError, setOpenerError] = useState("");
  const requestSequence = useRef(0);
  const mounted = useRef(false);
  const onScopeInvalidateRef = useRef(onScopeInvalidate);
  onScopeInvalidateRef.current = onScopeInvalidate;

  const currentAccount = accounts.find((account) => account.id === accountId);
  const accountDomains = useMemo(
    () => domains.filter((domain) => domain.accountId === currentAccount?.id)
      .sort((left, right) => left.host.localeCompare(right.host) || left.prefix.localeCompare(right.prefix)),
    [currentAccount?.id, domains],
  );
  const currentDomain = accountDomains.find((domain) => domain.id === domainId);
  const effectiveDomainId = currentDomain?.id || "";
  const dataIdentity = useMemo(() => JSON.stringify([
    revision,
    accounts.map((account) => [account.id, Boolean(account.needsCredentialMigration)]),
    domains.map((domain) => [domain.id, domain.accountId, domain.host, domain.prefix]),
    links.map((link) => [link.domainId, link.slug]),
  ]), [accounts, domains, links, revision]);
  const latestDataIdentity = useRef(dataIdentity);
  latestDataIdentity.current = dataIdentity;

  function invalidate(clearCount = true) {
    requestSequence.current += 1;
    setView({ kind: "idle" });
    setOpenerError("");
    if (clearCount) setKnownTotalLinks(null);
  }

  useEffect(() => {
    mounted.current = true;
    return () => {
      mounted.current = false;
      requestSequence.current += 1;
      onScopeInvalidateRef.current?.();
    };
  }, []);

  useEffect(() => {
    requestSequence.current += 1;
    setView({ kind: "idle" });
    setKnownTotalLinks(null);
    setPage(1);
    if (accountId && !accounts.some((account) => account.id === accountId)) {
      setAccountId("");
      setDomainId("");
    } else if (domainId && !domains.some((domain) => domain.id === domainId && domain.accountId === accountId)) {
      setDomainId("");
    }
  }, [dataIdentity]);

  const chooseAccount = (nextAccountId: string) => {
    onScopeInvalidate?.();
    invalidate();
    setAccountId(nextAccountId);
    setDomainId("");
    setPage(1);
  };
  const chooseDomain = (nextDomainId: string) => {
    onScopeInvalidate?.();
    invalidate();
    setDomainId(nextDomainId);
    setPage(1);
  };
  const chooseDays = (nextDays: ClickStatsDays) => {
    onScopeInvalidate?.();
    invalidate();
    setDays(nextDays);
    setPage(1);
  };

  const load = async (requestedPage = 1) => {
    if (!currentAccount || currentAccount.needsCredentialMigration) return;
    const expected = {
      accountId: currentAccount.id,
      domainId: effectiveDomainId || null,
      days,
      page: requestedPage,
    };
    const sequence = ++requestSequence.current;
    const requestDataIdentity = dataIdentity;
    setPage(requestedPage);
    setView({ kind: "loading" });
    setOpenerError("");
    try {
      const report = await dispatch<StatsCenterReport>("get_stats_center", {
        accountId: expected.accountId,
        ...(expected.domainId ? { domainId: expected.domainId } : {}),
        days: expected.days,
        page: requestedPage,
        pageSize: PAGE_SIZE,
      });
      if (!mounted.current || sequence !== requestSequence.current || requestDataIdentity !== latestDataIdentity.current) return;
      if (!validReport(report, expected, domains, links)) {
        setKnownTotalLinks(null);
        setView({ kind: "error", message: "返回的统计结果与当前账户、域名、时间或页码不一致，已停止显示。请重试。" });
        return;
      }
      setKnownTotalLinks(report.totalLinks);
      setView({ kind: "report", report });
    } catch (error) {
      if (!mounted.current || sequence !== requestSequence.current || requestDataIdentity !== latestDataIdentity.current) return;
      setKnownTotalLinks(null);
      setView({ kind: "error", message: errorMessage(error) });
    }
  };

  const openTokenSettings = async () => {
    setOpenerError("");
    try {
      const { openUrl } = await import("@tauri-apps/plugin-opener");
      await openUrl("https://dash.cloudflare.com/profile/api-tokens");
    } catch (error) {
      setOpenerError(`无法打开 Cloudflare 令牌管理页：${errorMessage(error)}`);
    }
  };

  const openAnalyticsEngineSettings = async () => {
    setOpenerError("");
    if (!currentAccount || !/^[a-f0-9]{32}$/.test(currentAccount.id)) {
      setOpenerError("无法确认账户，请先更新账户状态。");
      return;
    }
    try {
      const { openUrl } = await import("@tauri-apps/plugin-opener");
      await openUrl(`https://dash.cloudflare.com/${currentAccount.id}/workers/analytics-engine`);
    } catch (error) {
      setOpenerError(`无法打开 Cloudflare Analytics Engine 页面：${errorMessage(error)}`);
    }
  };

  const report = view.kind === "report" ? view.report : undefined;
  const rows = report?.rows || [];
  const pageCount = Math.max(1, Math.ceil((knownTotalLinks || 0) / PAGE_SIZE));
  const visibleConfigurationError = configurationError && configurationError.accountId === currentAccount?.id ? configurationError.message : "";
  const configurationNeedsAnalyticsRead = /AccountAnalyticsRead|Account Analytics Read|账户分析|帐户分析|统计读取权限|analytics.*read/i.test(visibleConfigurationError);
  const canConfigure = Boolean(currentAccount && !currentAccount.needsCredentialMigration && !busy);
  const configurationMode = report?.status === "disabled" ? "enable"
    : report?.status === "no_data" || view.kind === "error" ? "check-disable"
      : report ? "disable"
        : null;
  const scopeLabel = currentDomain
    ? `${currentDomain.host}/${currentDomain.prefix}/`
    : currentAccount ? `「${currentAccount.label}」的全部已导入域名` : "";
  const rangeLabel = report ? ranges.find((range) => range.value === report.days)?.label : "";
  const contextDetails = report && (report.status === "ready" || report.status === "no_data") ? (
    <details className="scenter-context">
      <summary>
        <span>统计口径与其他请求</span>
        <small>{report.totals ? `预览 ${number(report.totals.previews)} · 预加载 ${number(report.totals.prefetches)}` : "范围与历史口径"}</small>
      </summary>
      <div className="scenter-context-body">
        {report.totals && (
          <div className="scenter-secondary" aria-label="预览和预加载请求">
            <span>预览请求 <strong>{number(report.totals.previews)}</strong></span>
            <span>预加载请求 <strong>{number(report.totals.prefetches)}</strong></span>
            <small>单独列出，不计入总访问。</small>
          </div>
        )}
        <div className="scenter-scope" role="note">
          <p><strong>汇总范围</strong><span>{scopeLabel} · {rangeLabel}</span></p>
          <p>{report.status === "ready" ? "汇总包含这一范围内的历史事件，包括后来删除的链接；" : "有可显示汇总时，口径会包含后来删除链接的历史事件；"}下表只列当前本机已导入的短链接。</p>
        </div>
        {report.status === "ready" && report.message && <p className="scenter-message">{report.message}</p>}
      </div>
    </details>
  ) : null;

  const body = (() => {
    if (accounts.length === 0) return <Notice title="还没有可查询的账户" tone="warning">请先导入一个 Cloudflare 账户，再从这里读取访问统计。</Notice>;
    if (!currentAccount) return <Notice title="先选择一个账户">统计中心不会自动读取所有账户。选择账户、域名范围和时间后，再点击“读取统计”。</Notice>;
    if (currentAccount.needsCredentialMigration) return <Notice title="需要先更新本机授权" tone="warning">请先到“Cloudflare 账户”完成此账户的本机授权迁移，再读取或配置访问统计。</Notice>;
    if (view.kind === "loading") return <div className="scenter-loading" role="status">正在读取所选账户的第 {page} 页统计…</div>;
    if (view.kind === "error") return <Notice title="统计读取失败" tone="error">{view.message || "操作未完成，请重试。"}</Notice>;
    if (!report) return <Notice title="等待读取">筛选变化会隐藏上一范围的数据。确认范围后点击“读取统计”，不会自动查询其他账户。</Notice>;
    if (report.status === "disabled") return (
      <Notice title="此账户尚未启用访问统计" tone="warning">
        <p>{report.message || "启用后才能读取访问统计。"}</p>
        <p>启用后开始记录，没有历史回填；访客仍会直接跳转。</p>
        <p>首次启用前，请确认原有 API 令牌包含“账户 → 账户分析 → 读取”（AccountAnalyticsRead）权限。</p>
        <p>首次使用还需在 Cloudflare 对应账户开通 Analytics Engine；本应用不会自动开通账户服务。</p>
        <div className="scenter-notice-actions">
          <button type="button" className="button bordered" onClick={() => void openTokenSettings()}><ArrowSquareOut size={14} aria-hidden="true" />打开 API 令牌管理</button>
          <button type="button" className="button bordered" onClick={() => void openAnalyticsEngineSettings()}><ArrowSquareOut size={14} aria-hidden="true" />打开 Analytics Engine</button>
        </div>
      </Notice>
    );
    if (report.status === "permission_denied") return (
      <Notice title="统计读取被拒绝" tone="warning">
        <p>{report.message}</p>
        <p>请核对原有 API 令牌是否包含“账户 → 账户分析 → 读取”，以及对应账户是否已开通 Analytics Engine。</p>
        <div className="scenter-notice-actions">
          <button type="button" className="button bordered" onClick={() => void openTokenSettings()}><ArrowSquareOut size={14} aria-hidden="true" />打开 API 令牌管理</button>
          <button type="button" className="button bordered" onClick={() => void openAnalyticsEngineSettings()}><ArrowSquareOut size={14} aria-hidden="true" />打开 Analytics Engine</button>
        </div>
      </Notice>
    );
    if (report.status === "unavailable") return <Notice title="暂时无法读取访问统计" tone="error">{report.message || "Cloudflare 暂时未提供可用的统计结果，请稍后重试。"}</Notice>;
    if (report.status === "no_data") return (
      <>
        <Notice title="当前没有可汇总的结果"><p>{report.message}</p><p>这不代表历史访问为零；汇总数字保持隐藏。</p></Notice>
        {contextDetails}
        {rows.length > 0 && <StatsTable report={report} domains={domains} links={links} onOpenLinkStats={onOpenLinkStats} />}
      </>
    );
    if (!report.totals) return null;
    const totals = report.totals;
    const categories = [
      { key: "human", label: "疑似真人", value: totals.likelyHuman },
      { key: "bot", label: "疑似机器人", value: totals.likelyBot },
      { key: "unknown", label: "未知", value: totals.unknown },
    ];
    const percentages = wholePercentages(categories.map((category) => category.value));
    return (
      <>
        <section className="scenter-overview" aria-label="访问概览">
          <div className="scenter-total" aria-label="估算总访问">
            <span>估算总访问</span>
            <strong>{number(totals.total)}</strong>
            <small>{rangeLabel} · 访问次数，不是去重人数</small>
          </div>
          <div className="scenter-distribution" aria-label="访问分类分布">
            <div className="scenter-distribution-head">
              <strong>分类分布</strong>
              <small>按估算访问次数</small>
            </div>
            <div className={`scenter-distribution-bar ${totals.total === 0 ? "is-empty" : ""}`} aria-hidden="true">
              {categories.map((category) => (
                <span key={category.key} className={`scenter-segment scenter-segment-${category.key}`} style={{ width: totals.total > 0 ? `${category.value * 100 / totals.total}%` : "0%" }} />
              ))}
            </div>
            <div className="scenter-distribution-list">
              {categories.map((category, index) => (
                <div key={category.key}>
                  <span className={`scenter-dot scenter-dot-${category.key}`} aria-hidden="true" />
                  <span>{category.label}</span>
                  <strong>{number(category.value)}</strong>
                  <small>{percentages[index]}%</small>
                </div>
              ))}
            </div>
          </div>
        </section>
        {contextDetails}
        <StatsTable report={report} domains={domains} links={links} onOpenLinkStats={onOpenLinkStats} />
      </>
    );
  })();

  return (
    <section className="panel scenter" aria-label="访问统计中心">
      <div className="scenter-head">
        <div>
          <h2>访问统计</h2>
          <p>按一个账户读取估算请求次数；不会增加访客验证。</p>
        </div>
        {preview && <span className="scenter-preview">本地示例</span>}
      </div>
      <div className="scenter-controls">
        <label>账户
          <select aria-label="统计账户" value={currentAccount?.id || ""} onChange={(event) => chooseAccount(event.target.value)}>
            <option value="">请选择账户</option>
            {accounts.map((account) => <option key={account.id} value={account.id}>{account.label}</option>)}
          </select>
        </label>
        <label>域名范围
          <select aria-label="统计域名" value={effectiveDomainId} disabled={!currentAccount} onChange={(event) => chooseDomain(event.target.value)}>
            <option value="">全部已导入域名</option>
            {accountDomains.map((domain) => <option key={domain.id} value={domain.id}>{domain.host}/{domain.prefix}/</option>)}
          </select>
        </label>
        <label>时间范围
          <select aria-label="统计时间范围" value={days} onChange={(event) => chooseDays(Number(event.target.value) as ClickStatsDays)}>
            {ranges.map((range) => <option key={range.value} value={range.value}>{range.label}</option>)}
          </select>
        </label>
        <button type="button" className="button primary scenter-read" disabled={!currentAccount || Boolean(currentAccount.needsCredentialMigration) || view.kind === "loading"} onClick={() => void load(1)}>
          <ArrowClockwise size={15} aria-hidden="true" />{view.kind === "loading" ? "正在读取…" : report ? "刷新统计" : "读取统计"}
        </button>
      </div>
      {visibleConfigurationError && (
        <div className="scenter-config-error" role="alert">
          <span>{visibleConfigurationError}</span>
          {configurationNeedsAnalyticsRead && (
            <>
              <p>请核对原有 API 令牌的“帐户 → 帐户分析 → 读取”权限，并确认对应账户已启用 Analytics Engine。无需删除令牌或重新导入。</p>
              <div className="scenter-notice-actions">
                <button type="button" className="button bordered" onClick={() => void openTokenSettings()}><ArrowSquareOut size={14} aria-hidden="true" />打开并编辑原有令牌</button>
                <button type="button" className="button bordered" onClick={() => void openAnalyticsEngineSettings()}><ArrowSquareOut size={14} aria-hidden="true" />打开 Cloudflare 统计服务</button>
              </div>
            </>
          )}
        </div>
      )}
      {openerError && <div className="scenter-config-error" role="alert">{openerError}</div>}
      {configurationMode && currentAccount && report?.status !== "ready" && (
        <div className="scenter-configure">
          <span>{configurationMode === "enable" ? "统计启用会先生成变更计划供确认。" : "停用前会先检查当前账户并显示变更计划。"}</span>
          <button type="button" className={`button ${configurationMode === "enable" ? "secondary" : "bordered"}`} disabled={!canConfigure} onClick={() => onConfigure(currentAccount, configurationMode === "enable")}>
            {busy ? "正在准备变更计划…" : configurationMode === "enable" ? "启用账户统计" : configurationMode === "check-disable" ? "检查并停用账户统计" : "停用账户统计"}
          </button>
        </div>
      )}
      <div className="scenter-body" aria-live="polite">
        {body}
      </div>
      {knownTotalLinks !== null && knownTotalLinks > PAGE_SIZE && (view.kind === "loading" || report) && (
        <div className="scenter-pagination" aria-label="统计结果分页">
          <span>当前本机短链接 {number(knownTotalLinks)} 条 · 第 {page} / {pageCount} 页</span>
          <div>
            <button type="button" className="button ghost" aria-label="上一页统计" disabled={page <= 1} onClick={() => void load(page - 1)}><CaretLeft size={14} aria-hidden="true" />上一页</button>
            <button type="button" className="button ghost" aria-label="下一页统计" disabled={page >= pageCount} onClick={() => void load(page + 1)}>下一页<CaretRight size={14} aria-hidden="true" /></button>
          </div>
        </div>
      )}
      {report && (
        <div className="scenter-footer">
          {report.status === "ready" && currentAccount && (
            <div className="scenter-ready-configure">
              <span>停用前会显示变更计划</span>
              <button
                type="button"
                className="button ghost"
                title="停用前会先检查当前账户并显示变更计划"
                disabled={!canConfigure}
                onClick={() => onConfigure(currentAccount, false)}
              >
                {busy ? "正在准备变更计划…" : "停用账户统计"}
              </button>
            </div>
          )}
          <p className="scenter-updated">读取时间：{formatTime(report.queriedAt)} · 估算统计</p>
        </div>
      )}
    </section>
  );
}

function StatsTable({ report, domains, links, onOpenLinkStats }: {
  report: StatsCenterReport;
  domains: Domain[];
  links: Link[];
  onOpenLinkStats: (link: Link, domain: Domain) => void;
}) {
  const rows = report.rows || [];
  return (
    <section className="scenter-detail" aria-label="短链接明细">
      <div className="scenter-detail-head">
        <strong>短链接明细</strong>
        <span>当前本机共 {number(report.totalLinks)} 条 · 本页 {number(rows.length)} 条</span>
      </div>
      {rows.length === 0 ? <div className="scenter-table-empty">这一页没有当前本机短链接。</div> : (
        <div className="scenter-table-scroll">
          <table className="scenter-table" aria-label="当前本机短链接统计">
            <thead><tr><th>域名</th><th>短链接</th><th>疑似真人</th><th>疑似机器人</th><th>未知</th><th>总次数</th><th>操作</th></tr></thead>
            <tbody>
              {rows.map((row) => {
                const domain = domains.find((item) => item.id === row.domainId);
                const link = links.find((item) => item.domainId === row.domainId && item.slug === row.slug);
                return (
                  <tr key={`${row.domainId}:${row.slug}`}>
                    <td><strong>{domain?.host}</strong><span>/{domain?.prefix}/</span></td>
                    <td><code>/{row.slug}</code></td>
                    <td>{number(row.totals.likelyHuman)}</td>
                    <td>{number(row.totals.likelyBot)}</td>
                    <td>{number(row.totals.unknown)}</td>
                    <td><strong>{number(row.totals.total)}</strong></td>
                    <td><button type="button" className="button ghost" disabled={!link || !domain} aria-label={`查看 ${row.slug} 的详细统计`} onClick={() => link && domain && onOpenLinkStats(link, domain)}>详细统计</button></td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}
    </section>
  );
}
