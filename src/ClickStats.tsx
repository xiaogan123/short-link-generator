import { useCallback, useEffect, useRef, useState } from "react";
import Dialog from "./Dialog";
import { dispatch, errorMessage, preview } from "./bridge";
import type { Account, ClickStats, ClickStatsDays, Domain, Link } from "./types";
import { dedupNote, validDedup } from "./clickDedup";
import "./ClickStats.css";

type Props = {
  link: Link;
  domain: Domain;
  account: Account | undefined;
  onClose: () => void;
  onConfigure: (enabled: boolean) => void;
  revision: number;
  busy?: boolean;
  configurationError?: string;
};

type ViewState =
  | { kind: "loading" }
  | { kind: "report"; report: ClickStats }
  | { kind: "error"; message: string }
  | { kind: "no-account" }
  | { kind: "credential-migration" };

const ranges: { value: ClickStatsDays; label: string }[] = [
  { value: 1, label: "近 24 小时" },
  { value: 7, label: "近 7 天" },
  { value: 30, label: "近 30 天" },
];

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

function validTotals(totals: ClickStats["totals"]): totals is NonNullable<ClickStats["totals"]> {
  if (!totals) return false;
  const values = [
    totals.total,
    totals.likelyHuman,
    totals.likelyBot,
    totals.unknown,
    totals.previews,
    totals.prefetches,
  ];
  if (!values.every((value) => Number.isSafeInteger(value) && value >= 0)) return false;
  const classified = totals.likelyHuman + totals.likelyBot + totals.unknown;
  return Number.isSafeInteger(classified) && totals.total === classified;
}

function number(value: number) {
  return value.toLocaleString("zh-CN");
}

function Notice({ title, children, tone = "neutral" }: { title: string; children: React.ReactNode; tone?: "neutral" | "warning" | "error" }) {
  return (
    <div className={`cstats-notice cstats-notice-${tone}`} role={tone === "error" ? "alert" : "status"}>
      <strong>{title}</strong>
      <div>{children}</div>
    </div>
  );
}

export default function ClickStatsDialog({
  link,
  domain,
  account,
  onClose,
  onConfigure,
  revision,
  busy = false,
  configurationError,
}: Props) {
  const [days, setDays] = useState<ClickStatsDays>(7);
  const [view, setView] = useState<ViewState>({ kind: "loading" });
  const [openerError, setOpenerError] = useState("");
  const sequence = useRef(0);
  const mounted = useRef(false);
  const inFlight = useRef(new Map<string, Promise<ClickStats>>());

  useEffect(() => {
    mounted.current = true;
    return () => {
      mounted.current = false;
      sequence.current += 1;
    };
  }, []);

  const load = useCallback(async () => {
    const requestSequence = ++sequence.current;
    setOpenerError("");
    if (!account) {
      setView({ kind: "no-account" });
      return;
    }
    if (account.needsCredentialMigration) {
      setView({ kind: "credential-migration" });
      return;
    }

    setView({ kind: "loading" });
    const requestKey = JSON.stringify([domain.id, link.slug, days, revision]);
    let request = inFlight.current.get(requestKey);
    if (!request) {
      request = dispatch<ClickStats>("get_link_stats", {
        domainId: domain.id,
        slug: link.slug,
        days,
      });
      inFlight.current.set(requestKey, request);
    }

    try {
      const report = await request;
      if (!mounted.current || requestSequence !== sequence.current) return;
      if (
        !report
        || report.domainId !== domain.id
        || report.slug !== link.slug
        || report.days !== days
      ) {
        setView({ kind: "error", message: "返回的统计结果与当前链接或时间范围不一致，请重试。" });
        return;
      }
      if (report.status === "ready" && !validTotals(report.totals)) {
        setView({ kind: "error", message: "统计结果不完整，未显示可能失真的数字。请稍后重试。" });
        return;
      }
      setView({ kind: "report", report });
    } catch (error) {
      if (!mounted.current || requestSequence !== sequence.current) return;
      setView({ kind: "error", message: errorMessage(error) });
    } finally {
      if (inFlight.current.get(requestKey) === request) inFlight.current.delete(requestKey);
    }
  }, [account?.id, account?.needsCredentialMigration, days, domain.id, link.slug, revision]);

  useEffect(() => {
    void load();
  }, [load]);

  const report = view.kind === "report" ? view.report : undefined;
  const accountUnavailable = view.kind === "no-account" || view.kind === "credential-migration";
  const checkBeforeDisable = view.kind === "error" || report?.status === "unavailable";
  const showConfigure = accountUnavailable || report !== undefined || checkBeforeDisable;
  const enabling = accountUnavailable || report?.status === "disabled";
  const configureDisabled = busy || !account || Boolean(account.needsCredentialMigration);

  const openTokenSettings = async () => {
    setOpenerError("");
    try {
      const { openUrl } = await import("@tauri-apps/plugin-opener");
      await openUrl("https://dash.cloudflare.com/profile/api-tokens");
    } catch (error) {
      setOpenerError(`无法打开 Cloudflare 令牌管理页：${errorMessage(error)}`);
    }
  };

  const openAnalyticsSettings = async () => {
    setOpenerError("");
    if (!account || !/^[a-f0-9]{32}$/.test(account.id)) {
      setOpenerError("无法确认账户，请先更新账户状态。");
      return;
    }
    try {
      const { openUrl } = await import("@tauri-apps/plugin-opener");
      await openUrl(`https://dash.cloudflare.com/${account.id}/workers/analytics-engine`);
    } catch (error) {
      setOpenerError(`无法打开 Cloudflare 统计服务页：${errorMessage(error)}`);
    }
  };

  const analyticsSettingsButton = <button type="button" className="button bordered cstats-token-button" onClick={() => void openAnalyticsSettings()}>打开 Cloudflare 统计服务</button>;

  const body = (() => {
    if (view.kind === "loading") {
      return <div className="cstats-loading" role="status">正在读取所选时间范围的统计…</div>;
    }
    if (view.kind === "no-account") {
      return <Notice title="未连接账户" tone="warning">没有找到此域名连接的 Cloudflare 账户，暂时无法读取或配置访问统计。</Notice>;
    }
    if (view.kind === "credential-migration") {
      return <Notice title="需要先更新本机授权" tone="warning">请先到“账户”完成此账户的本机授权迁移，再查看或配置访问统计。</Notice>;
    }
    if (view.kind === "error") {
      return <Notice title="访问统计读取失败" tone="error">{view.message || "操作未完成，请重试。"}</Notice>;
    }

    const current = view.report;
    if (current.status === "ready" && validTotals(current.totals)) {
      const totals = current.totals;
      const dedup = validDedup(totals);
      return (
        <>
          <section className="cstats-total" aria-label="总访问">
            <span>估算总访问</span>
            <strong>{number(totals.total)}</strong>
            <small>访问次数，不是去重人数</small>
          </section>
          <div className="cstats-breakdown" aria-label="访问分类">
            <div><span>疑似真人</span><strong>{number(totals.likelyHuman)}</strong></div>
            <div><span>疑似机器人</span><strong>{number(totals.likelyBot)}</strong></div>
            <div><span>未知</span><strong>{number(totals.unknown)}</strong></div>
          </div>
          <div className="cstats-dedup" aria-label="约 30 分钟访问去重估算">
            <span>约 30 分钟去重估算</span>
            <strong>首次 {dedup ? number(dedup.first) : "—"} · 重复 {dedup ? number(dedup.repeat) : "—"}</strong>
            <small>测量覆盖 {dedup ? `${number(dedup.measured)} / ${number(totals.total)}` : "未覆盖"} 次访问。{dedupNote}</small>
          </div>
          <div className="cstats-secondary" aria-label="预览和预加载请求">
            <span>预览请求 <strong>{number(totals.previews)}</strong></span>
            <span>预加载请求 <strong>{number(totals.prefetches)}</strong></span>
            <small>单独列出，不计入总访问。</small>
          </div>
          {current.message && <p className="cstats-message">{current.message}</p>}
        </>
      );
    }
    if (current.status === "disabled") {
      return (
        <Notice title="此账户尚未启用访问统计" tone="warning">
          <p>{current.message || "启用后才能读取访问统计。"}</p>
          <p>启用后开始记录，没有历史回填；已有链接无需重建。</p>
          <p>首次启用前，请确认原有 API 令牌包含“账户 → 账户分析 → 读取”权限。</p>
          <p>首次使用还需在 Cloudflare 的 Analytics Engine 页面启用该账户的统计服务。</p>
          <button type="button" className="button bordered cstats-token-button" onClick={() => void openTokenSettings()}>
            打开 Cloudflare API 令牌管理
          </button>
          {analyticsSettingsButton}
        </Notice>
      );
    }
    if (current.status === "no_data") {
      return (
        <Notice title="所选时间范围暂无统计">
          {current.message || "统计已启用，但当前时间范围还没有可显示的数据。统计可能存在延迟或采样。"}
        </Notice>
      );
    }
    if (current.status === "permission_denied") {
      return (
        <Notice title="统计读取被拒绝" tone="warning">
          <p>{current.message}</p>
          <p>请核对原令牌的“帐户 → 帐户分析 → 读取”权限，并确认该账户已启用 Analytics Engine。无需删除或重新导入令牌。</p>
          <button type="button" className="button bordered cstats-token-button" onClick={() => void openTokenSettings()}>
            打开 Cloudflare API 令牌管理
          </button>
          {analyticsSettingsButton}
        </Notice>
      );
    }
    return <Notice title="暂时无法读取访问统计" tone="error">{current.message || "Cloudflare 暂时未提供可用的统计结果，请稍后重试。"}</Notice>;
  })();

  return (
    <Dialog
      title={`访问统计 · /${link.slug}`}
      wide
      onClose={onClose}
      footer={(
        <>
          {showConfigure && (
            <button
              type="button"
              className={`button ${enabling ? "primary" : "bordered"}`}
              disabled={configureDisabled}
              onClick={() => onConfigure(enabling)}
            >
              {busy ? "正在准备变更计划…" : checkBeforeDisable ? "检查并停用账户统计" : enabling ? "启用账户统计" : "停用账户统计"}
            </button>
          )}
          <button type="button" className="button ghost" onClick={onClose}>关闭</button>
        </>
      )}
    >
      <div className="cstats-shell">
        {preview && <div className="cstats-preview" role="note"><strong>预览</strong> 本地示例，不是真实统计。</div>}
        <div className="cstats-toolbar">
          <div className="cstats-identity">
            <strong>{domain.host}/{domain.prefix}/{link.slug}</strong>
            <span>{account ? `账户：${account.label}` : "未连接账户"}</span>
          </div>
          <div className="cstats-controls">
            <label>
              <span>时间范围</span>
              <select
                aria-label="统计时间范围"
                value={days}
                onChange={(event) => setDays(Number(event.target.value) as ClickStatsDays)}
              >
                {ranges.map((range) => <option key={range.value} value={range.value}>{range.label}</option>)}
              </select>
            </label>
            <button type="button" className="button bordered" aria-label="刷新访问统计" disabled={view.kind === "loading"} onClick={() => void load()}>
              刷新
            </button>
          </div>
        </div>

        {configurationError && <div className="cstats-config-error" role="alert">{configurationError}</div>}
        {openerError && <div className="cstats-config-error" role="alert">{openerError}</div>}
        {body}

        {report && <p className="cstats-updated">更新时间：<time dateTime={report.queriedAt}>{formatTime(report.queriedAt)}</time></p>}
        {showConfigure && (
          <p className="cstats-scope">
            {checkBeforeDisable && "当前统计配置尚未确认；可先检查并准备停用计划，不会直接修改云端。"}
            启用或停用会作用于当前账户下的所有域名，提交前会显示变更计划供你确认。
          </p>
        )}
        <div className="cstats-explainer">
          <strong>统计口径</strong>
          <p>访客直接跳转，不增加访问验证。统计为估算访问次数，不是去重人数。分类只依据请求特征，客户端可以伪装；数据可能存在延迟或采样。</p>
        </div>
      </div>
    </Dialog>
  );
}
