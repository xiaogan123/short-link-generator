import {
  useEffect,
  useMemo,
  useRef,
  useState,
  type FormEvent,
  type ReactNode,
} from "react";
import {
  ArrowClockwise,
  ArrowSquareOut,
  CaretDown,
  ChartBar,
  CheckCircle,
  Clipboard,
  CloudArrowDown,
  CloudArrowUp,
  Globe,
  Key,
  LinkSimple,
  MagnifyingGlass,
  Plus,
  ShieldCheck,
  SidebarSimple,
  Stack,
  Trash,
  WarningCircle,
  X,
} from "@phosphor-icons/react";
import { dispatch, errorMessage, preview } from "./bridge";
import {
  normalizeHost,
  shortUrl,
  validateHost,
  validatePrefix,
  validateSlug,
  validateTarget,
} from "./validators";
import type {
  Account,
  Domain,
  DomainDnsPreparation,
  DomainPreparation,
  Link,
  PendingAction,
  Plan,
  Pool,
  PoolHealth,
  Selftest,
  State,
  TargetReport,
  UpdateStatus,
} from "./types";
import "./styles.css";
import Dialog from "./Dialog";
import LinkEditor, { type LinkDraft } from "./LinkEditor";
import { FieldError, fieldProps, focusFirstError, type FieldErrors } from "./FormFeedback";
import Pools from "./Pools";
import LinkGroups from "./LinkGroups";
import ClickStatsDialog from "./ClickStats";
import StatsCenter from "./StatsCenter";
import { useUpdateCheck } from "./useUpdateCheck";
import RedirectMonitor, {monitorBannerText} from './RedirectMonitor';
import { useRedirectMonitor } from './useRedirectMonitor';

type Page = "links" | "stats" | "pools" | "domains" | "accounts";
type Detection = {
  fingerprint: string;
  selftest: Selftest;
  targets: TargetReport;
  checkedAt: string;
};
const emptyState: State = {
  accounts: [],
  domains: [],
  links: [],
  pendingOperations: [],
  pendingActions: [],
};
const nav: { key: Page; label: string; icon: typeof LinkSimple }[] = [
  { key: "links", label: "短链接", icon: LinkSimple },
  { key: "stats", label: "统计中心", icon: ChartBar },
  { key: "pools", label: "平台地址", icon: Stack },
  { key: "domains", label: "域名管理", icon: Globe },
  { key: "accounts", label: "Cloudflare 账户", icon: Key },
];

function StatusPill({
  children,
  tone = "green",
}: {
  children: ReactNode;
  tone?: "green" | "amber" | "slate";
}) {
  return (
    <span className={`status status-${tone}`}>
      <span className="status-dot" />
      {children}
    </span>
  );
}
function Empty({
  icon,
  title,
  description,
  action,
}: {
  icon: ReactNode;
  title: string;
  description: string;
  action?: ReactNode;
}) {
  return (
    <div className="empty">
      <div className="empty-icon">{icon}</div>
      <h3>{title}</h3>
      <p>{description}</p>
      {action}
    </div>
  );
}
function formatDate(value: string | null) {
  if (!value) return "尚未检查";
  const d = new Date(value);
  return Number.isNaN(d.getTime())
    ? value
    : new Intl.DateTimeFormat("zh-CN", {
        year: "numeric",
        month: "2-digit",
        day: "2-digit",
        hour: "2-digit",
        minute: "2-digit",
      }).format(d);
}
const expiredDomainPlanMessage = "计划已过期，请重新检查当前状态；域名、账户和网络方式已保留。";
function isCurrentPlan(plan: Plan | null | undefined) {
  return Boolean(plan && Number.isFinite(Date.parse(plan.expiresAt)) && Date.parse(plan.expiresAt) > Date.now());
}
function targetSourceLabel(dnsMode?: TargetReport["dnsMode"]) {
  return preview ? "本地预览 · 未探测" : dnsMode === "public" ? "本机网络 · 公共 DNS" : "本机网络";
}
function domainCheckLevel(check: DomainPreparation["checks"][number]) {
  return check.level || (check.ok ? "pass" : "error");
}
function domainOutcome(preparation: DomainPreparation) {
  const levels = preparation.checks.map(domainCheckLevel);
  if (hasOnlyNetworkBlocker(preparation))
    return { level: "warning", label: "网络检查未完成" };
  return levels.includes("error")
    ? { level: "error", label: "需要先处理" }
    : levels.includes("warning")
      ? { level: "warning", label: "确认后可接入" }
      : { level: "pass", label: "可用" };
}
function hasOnlyNetworkBlocker(preparation: DomainPreparation) {
  const errors = preparation.checks.filter(
    (check) => domainCheckLevel(check) === "error",
  );
  return !preparation.canApply && errors.length > 0 && errors.every((check) =>
    ["virtual_dns_address", "dns_timeout", "dns_failed", "public_dns_timeout", "public_dns_failed"].includes(check.reason || ""),
  );
}
function isDomainCredentialError(message: string) {
  return /HTTP 401|HTTP 403|令牌|凭据|授权|权限/.test(message);
}
function hasOnlyDnsBlocker(preparation: DomainPreparation) {
  const errors = preparation.checks.filter(
    (check) => domainCheckLevel(check) === "error",
  );
  return (
    errors.length > 0 &&
    errors.every((check) => /dns|解析|代理/i.test(check.label))
  );
}
function domainErrorMessage(message: string) {
  return /HTTP 403|DNS\s*编辑权限|修改\s*DNS|修改.*解析/i.test(message)
    ? `当前授权无法修改此域名的解析。${message}`
    : message;
}
function hasOnlyVirtualDnsBlocker(preparation: DomainPreparation) {
  const errors = preparation.checks.filter(
    (check) => domainCheckLevel(check) === "error",
  );
  return !preparation.canApply && errors.length > 0 &&
    errors.every((check) => check.reason === "virtual_dns_address");
}
function isSelftestRecovery(kind: PendingAction["kind"]) {
  return kind === "resume_selftest_rotation" || kind === "recover_selftest_rotation" || kind === "recover_selftest_resources";
}

export default function App() {
  const [page, setPage] = useState<Page>("links");
  const [state, setState] = useState<State>(emptyState);
  const [loading, setLoading] = useState(true);
  const [loadFailed, setLoadFailed] = useState(false);
  const [working, setWorking] = useState(false);
  const [mutation, setMutation] = useState<string | null>(null);
  const mutationRef = useRef<string | null>(null);
  const pendingPrepareRef = useRef(false);
  const changePrepareInFlight = useRef(false);
  const busy = working || mutation !== null;
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");
  const [domainSuccessId, setDomainSuccessId] = useState("");
  const [search, setSearch] = useState("");
  const [domainSearch, setDomainSearch] = useState("");
  const [accountSearch, setAccountSearch] = useState("");
  const [formErrors, setFormErrors] = useState<FieldErrors>({});
  const loadSequence = useRef(0);
  function rejectFields(fields: FieldErrors) {
    setFormErrors(fields);
    focusFirstError(fields);
  }
  const [filter, setFilter] = useState("all");
  const [attentionOnly, setAttentionOnly] = useState(false);
  const [attentionViewRequest, setAttentionViewRequest] = useState(0);
  const linkListHeadingRef = useRef<HTMLHeadingElement>(null);
  const [linkDraft, setLinkDraft] = useState<LinkDraft | null>(null);
  const [originalSlug, setOriginalSlug] = useState<string | null>(null);
  const [copySource, setCopySource] = useState<{domainId: string; slug: string} | null>(null);
  const slugInput = useRef<HTMLInputElement>(null);
  const [domainDraft, setDomainDraft] = useState({
    input: "",
    prefix: "r",
    accountId: "",
    dnsMode: "system" as "system" | "public",
  });
  const [domainOpen, setDomainOpen] = useState(false);
  const [domainBusy, setDomainBusy] = useState(false);
  const [domainAutomaticDns, setDomainAutomaticDns] = useState(false);
  const [domainFeedback, setDomainFeedback] = useState<{
    tone: "error" | "success" | "progress" | "warning";
    message: string;
  } | null>(null);
  const [duplicateDomainId, setDuplicateDomainId] = useState("");
  const [preflight, setPreflight] = useState<DomainPreparation | null>(null);
  const [dnsPreflight, setDnsPreflight] = useState<DomainDnsPreparation | null>(
    null,
  );
  const [plan, setPlan] = useState<Plan | null>(null);
  const [planDetails, setPlanDetails] = useState<string[]>([]);
  const [planKind, setPlanKind] = useState("");
  const [migrationAccountId, setMigrationAccountId] = useState<string | null>(null);
  const [tokenOpen, setTokenOpenState] = useState(false);
  const tokenDialogOpen = useRef(false);
  const clipboardReadSequence = useRef(0);
  const [updateTokenAccount, setUpdateTokenAccount] = useState<Account | null>(
    null,
  );
  const [token, setToken] = useState("");
  const [replaceToken, setReplaceToken] = useState(false);
  const [clipboardOffer, setClipboardOffer] = useState("");
  const [clipboardToClear, setClipboardToClear] = useState("");
  function clearClipboardOffer() {
    clipboardReadSequence.current += 1;
    setClipboardOffer("");
  }
  function setTokenOpen(open: boolean) {
    setFormErrors({});
    tokenDialogOpen.current = open;
    clearClipboardOffer();
    setTokenOpenState(open);
  }
  const [renameAccount, setRenameAccount] = useState<Account | null>(null);
  const [renameValue, setRenameValue] = useState("");
  const [removeAccount, setRemoveAccount] = useState<Account | null>(null);
  const [testResult, setTestResult] = useState<{
    url: string;
    result: Selftest;
    domainId: string;
    slug: string;
    fingerprint: string;
    dnsMode: "system" | "public";
    automaticDns?: boolean;
  } | null>(null);
  const [targetResult, setTargetResult] = useState<TargetReport | null>(null);
  const [retryingTargets, setRetryingTargets] = useState(false);
  const targetRetrySequence = useRef(0);
  const targetRetryBusy = useRef(false);
  const [detections, setDetections] = useState<Record<string, Detection>>({});
  const [poolHealth, setPoolHealth] = useState<
    Record<string, { fingerprint: string; report: PoolHealth }>
  >({});
  const [poolSavedRevision, setPoolSavedRevision] = useState(0);
  const [poolError, setPoolError] = useState("");
  const [monitorAccount, setMonitorAccount] = useState<Account | null>(null);
  const [monitorEndpoint, setMonitorEndpoint] = useState("");
  const [monitorSecret, setMonitorSecret] = useState("");
  const [testingLink, setTestingLink] = useState("");
  const [testingAutomaticDns, setTestingAutomaticDns] = useState(false);
  const [updateStatus, setUpdateStatus] = useState<UpdateStatus | null>(null);
  const [updateOpen, setUpdateOpen] = useState(false);
  const [updatePhase, setUpdatePhase] = useState<"checking" | "downloading" | "verifying" | "installing" | null>(null);
  const [cancellingUpdate, setCancellingUpdate] = useState(false);
  const [updateCancelMessage, setUpdateCancelMessage] = useState("");
  const updateCancellationInFlight = useRef(false);
  const updateOperationSequence = useRef(0);
  const updateCheckingInFlight = useRef(false);
  const [updateError, setUpdateError] = useState("");
  const [installedUpdate, setInstalledUpdate] = useState<UpdateStatus | null>(null);
  const [dismissedUpdate, setDismissedUpdate] = useState<string | null>(null);
  const updates = useUpdateCheck(!loading && !loadFailed && !!state.appVersion && !busy && !updateStatus && !installedUpdate);
  const redirectMonitor = useRedirectMonitor({state,ready:!loading && !loadFailed,paused:busy || updates.checking || !!updateStatus});
  const [manageAccount, setManageAccount] = useState<Account | null>(null);
  const [protectionRead, setProtectionRead] = useState<{accountId:string;loading?:boolean;status?:import('./types').ClickProtection;error?:string} | null>(null);
  const protectionReadSequence = useRef(0);
  const [statsTarget, setStatsTarget] = useState<{link: Link; domain: Domain} | null>(null);
  const [statsRevision, setStatsRevision] = useState(0);
  const [statsConfigurationError, setStatsConfigurationError] = useState<{accountId: string; message: string} | null>(null);
  const [statsPlanAccountId, setStatsPlanAccountId] = useState("");
  const statsPrepareSequence = useRef(0);
  const statsTargetRef = useRef(statsTarget);
  statsTargetRef.current = statsTarget;
  const [sidebarOpen, setSidebarOpen] = useState(false);
  const mainRef = useRef<HTMLElement>(null);
  const [clock, setClock] = useState(Date.now());
  const isDomainPlan = planKind === "add_domain" || planKind === "fix_domain_dns";
  const domainPreparationExpired = Boolean(
    (preflight?.plan && !isCurrentPlan(preflight.plan)) ||
    (dnsPreflight?.plan && !isCurrentPlan(dnsPreflight.plan)),
  );
  const stateRef = useRef(state);
  const linkDraftRef = useRef(linkDraft);
  const linkPrepareSequence = useRef(0);
  const monitorPrepareSequence = useRef(0);
  const domainDraftRef = useRef(domainDraft);
  // Session-only, scoped to an account/host/directory that passed public-DNS checks.
  const publicDnsDomains = useRef(new Set<string>());
  const detectionSequence = useRef(0);
  const detectionInflight = useRef(new Set<string>());
  const domainCheckSequence = useRef(0);
  const domainOperation = useRef({ sequence: 0, inflight: false });
  const resumeDomainAfterToken = useRef(false);
  const latestDetectionForLink = useRef<Record<string, number>>({});
  stateRef.current = state;
  linkDraftRef.current = linkDraft;
  domainDraftRef.current = domainDraft;
  function poolFingerprint(poolId: string, snapshot: State) {
    const pool = snapshot.pools?.find((p) => p.id === poolId);
    if (!pool) return "";
    return JSON.stringify([
      pool.updated,
      pool.official,
      pool.candidates,
      pool.accountIds,
      pool.accountIds.map((id) => {
        const account = snapshot.accounts.find((a) => a.id === id);
        return [account?.monitorEnabled, account?.monitorEndpoint];
      }),
    ]);
  }

  function publishState(next: State) {
    loadSequence.current += 1;
    stateRef.current = next;
    setState(next);
    setLoading(false);
    setLoadFailed(false);
  }
  async function load() {
    const sequence = ++loadSequence.current;
    setLoading(true);
    setLoadFailed(false);
    setError("");
    try {
      const next = await dispatch<State>("get_state");
      if (sequence !== loadSequence.current) return;
      stateRef.current = next;
      setState(next);
      setPoolHealth({});
    } catch (e) {
      if (sequence !== loadSequence.current) return;
      setLoadFailed(true);
      setError(errorMessage(e));
    } finally {
      if (sequence === loadSequence.current) setLoading(false);
    }
  }
  useEffect(() => {
    void load();
    return () => {
      loadSequence.current += 1;
      detectionSequence.current++;
      targetRetrySequence.current++;
      domainCheckSequence.current++;
      domainOperation.current.sequence++;
    };
  }, []);
  useEffect(() => {
    const timer = window.setInterval(() => setClock(Date.now()), 60000);
    return () => window.clearInterval(timer);
  }, []);
  useEffect(() => {
    if (mainRef.current) mainRef.current.scrollTop = 0;
  }, [page]);
  useEffect(() => {
    if (attentionViewRequest === 0) return;
    const heading = linkListHeadingRef.current;
    heading?.focus({preventScroll: true});
    heading?.scrollIntoView({block: "start"});
  }, [attentionViewRequest]);
  useEffect(() => {
    const now = Date.now();
    const expiry = Math.min(...[
      isDomainPlan ? plan?.expiresAt : undefined,
      preflight?.plan?.expiresAt,
      dnsPreflight?.plan?.expiresAt,
    ].map((value) => value ? Date.parse(value) : NaN)
      .filter((value) => Number.isFinite(value) && value > now));
    if (!Number.isFinite(expiry)) return;
    const timer = window.setTimeout(() => setClock(Date.now()), expiry - now + 1);
    return () => window.clearTimeout(timer);
  }, [isDomainPlan, plan?.expiresAt, preflight?.plan?.expiresAt, dnsPreflight?.plan?.expiresAt]);
  useEffect(() => {
    if (!notice || notice.startsWith("域名已接入。")) return;
    const id = window.setTimeout(() => setNotice(""), 5000);
    return () => clearTimeout(id);
  }, [notice]);

  async function withMutation(kind: string, work: () => Promise<void>) {
    if (mutationRef.current) return;
    mutationRef.current = kind;
    setMutation(kind);
    try {
      await work();
    } finally {
      mutationRef.current = null;
      setMutation(null);
    }
  }
  function closeMonitor() {
    if (mutationRef.current === "prepare_credentials") return;
    monitorPrepareSequence.current += 1;
    setMonitorAccount(null);
    setMonitorSecret("");
  }

  async function run<T>(
    work: () => Promise<T>,
    success?: string,
    shouldAccept: () => boolean = () => true,
    onFailure?: (message: string) => void,
  ): Promise<T | undefined> {
    setWorking(true);
    setError("");
    try {
      const value = await work();
      if (success && shouldAccept()) setNotice(success);
      return value;
    } catch (e) {
      if (shouldAccept()) {
        const message = errorMessage(e);
        setError(message);
        onFailure?.(message);
      }
      return undefined;
    } finally {
      setWorking(false);
    }
  }
  function requireCurrentCredentials(
    accountIds: string[],
    onFailure?: (message: string) => void,
  ) {
    const account = stateRef.current.accounts.find(
      (item) => accountIds.includes(item.id) && (item.needsTokenRecovery || item.needsCredentialMigration),
    );
    if (!account) {
      setMigrationAccountId(null);
      return true;
    }
    const message = account.needsTokenRecovery
      ? `「${account.label}」的令牌保存未完成。请使用“恢复账户令牌”，验证并保存此账户的令牌后重试。`
      : `「${account.label}」需要先更新本机授权。请使用“更新本机授权”，完成后再重试当前操作。`;
    setMigrationAccountId(account.id);
    setDomainFeedback(null);
    setError(message);
    onFailure?.(message);
    return false;
  }
  function changeAccountIds(fields: Record<string, unknown>) {
    if (typeof fields.accountId === "string") return [fields.accountId];
    if (typeof fields.domainId === "string")
      return stateRef.current.domains
        .filter((d) => d.id === fields.domainId)
        .map((d) => d.accountId);
    const pool = fields.pool as Pool | undefined;
    const poolId = pool?.id || fields.poolId;
    if (!poolId) return pool?.accountIds || [];
    return [...new Set([
      ...(pool?.accountIds || []),
      ...(stateRef.current.pools?.find((p) => p.id === poolId)?.accountIds || []),
      ...stateRef.current.links
        .filter((link) => link.poolId === poolId)
        .flatMap((link) => stateRef.current.domains
          .filter((domain) => domain.id === link.domainId)
          .map((domain) => domain.accountId)),
    ])];
  }
  async function prepareCredentialMigration(accountId: string) {
    if (busy || domainOperation.current.inflight) return;
    await withMutation("prepare_credentials", async () => {
      const account = stateRef.current.accounts.find(
        (item) => item.id === accountId,
      );
      if (!account?.needsCredentialMigration) return;
      setMigrationAccountId(accountId);
      if (await prepare("migrate_credentials", { accountId })) setManageAccount(null);
    });
  }
  function migrationAction(accountId = migrationAccountId) {
    const account = state.accounts.find((item) => item.id === accountId);
    if (account?.needsTokenRecovery) return (
      <button type="button" className="button secondary" disabled={busy || domainBusy}
        onClick={() => openTokenRecovery(account)}>恢复账户令牌</button>
    );
    if (!account?.needsCredentialMigration) return null;
    return (
      <button
        type="button"
        className="button secondary"
        disabled={busy || domainBusy}
        onClick={() => void prepareCredentialMigration(account.id)}
      >
        更新本机授权
      </button>
    );
  }
  function openTokenRecovery(account: Account) {
    // Keep the visible target aligned with the request that owns the mutation lock.
    // The ref also covers a second click before React renders the disabled button.
    if (mutationRef.current || busy || domainOperation.current.inflight) return;
    setUpdateTokenAccount(account);
    setToken("");
    setReplaceToken(true);
    setFormErrors({});
    setError("");
    setManageAccount(null);
    setTokenOpen(true);
  }
  async function prepare(
    kind: string,
    fields: Record<string, unknown>,
    shouldAccept: () => boolean = () => true,
    onFailure?: (message: string) => void,
  ) {
    if (changePrepareInFlight.current) return false;
    if (mutationRef.current && kind !== "migrate_credentials" && !(mutationRef.current === "prepare_click_stats" && (kind === "enable_click_stats" || kind === "disable_click_stats"))) return false;
    if (
      kind !== "migrate_credentials" &&
      kind !== "dismiss_worker_upgrade" &&
      !requireCurrentCredentials(changeAccountIds(fields), onFailure)
    ) return false;
    changePrepareInFlight.current = true;
    try {
    const next = await run(
      () => dispatch<Plan>("prepare_change", { kind, ...fields }),
      undefined,
      shouldAccept,
      onFailure,
    );
    if (next && shouldAccept()) {
      setPlanKind(kind);
      if (kind === "save_link") {
        const domain = domainById.get(String(fields.domainId));
        const pool = state.pools?.find((p) => p.id === fields.poolId);
        const code = encodeURIComponent(String(fields.code));
        const linkDetails = fields.poolId
            ? [
                `短链接：${domain ? shortUrl(domain.host, domain.prefix, String(fields.slug)) : String(fields.slug)}`,
                `跟随平台地址：${pool?.name || String(fields.poolId)}`,
                `邀请码：${String(fields.code)}`,
                ...(pool
                  ? [
                      `官网链接：${pool.official.prefix}${code}${pool.official.suffix}`,
                      ...pool.candidates.map(
                        (candidate, index) =>
                          `大陆访问地址（${index === 0 ? "首选" : `备用 ${index}`}，${candidate.enabled ? "启用" : "停用"}）：${candidate.prefix}${code}${candidate.suffix}`,
                      ),
                    ]
                  : []),
              ]
            : [
                `短链接：${domain ? shortUrl(domain.host, domain.prefix, String(fields.slug)) : String(fields.slug)}`,
                `手动大陆地址：${String(fields.cnUrl)}`,
                `手动其他地区地址：${String(fields.defaultUrl)}`,
              ];
        const sourceDomain = state.domains.find((d) => d.id === copySource?.domainId);
        setPlanDetails([
          ...(fields.createOnly && copySource && sourceDomain
            ? [`旧链接继续保留：${shortUrl(sourceDomain.host, sourceDomain.prefix, copySource.slug)}`]
            : []),
          ...linkDetails,
        ]);
      } else if (kind === "save_pool") {
        const pool = fields.pool as Pool;
        const associations = state.links.filter(
          (l) => l.poolId === pool.id,
        ).length;
        setPlanDetails([
          `平台地址：${pool.name}`,
          associations
            ? `关联链接：${associations} 条会一起更新`
            : "关联链接：0 条；不会影响手动填写的链接",
          pool.accountIds.length
            ? `已使用账户：${pool.accountIds.map((id) => state.accounts.find((a) => a.id === id)?.label || id).join("、")}`
            : "已使用账户：尚无；创建链接时会自动配置到对应账户",
          `官网链接：${pool.official.prefix}邀请码${pool.official.suffix}`,
          ...pool.candidates.map(
            (candidate, index) =>
              `大陆访问地址（${index === 0 ? "首选" : `备用 ${index}`}，${candidate.enabled ? "启用" : "停用"}）：${candidate.prefix}邀请码${candidate.suffix}`,
          ),
        ]);
      } else if (kind === "delete_pool" || kind === "resume_pool_sync")
        setPlanDetails([
          `平台地址：${state.pools?.find((p) => p.id === fields.poolId)?.name || String(fields.poolId)}`,
        ]);
      else if (kind === "delete_link") {
        const domain = domainById.get(String(fields.domainId));
        setPlanDetails([
          `删除：${domain ? shortUrl(domain.host, domain.prefix, String(fields.slug)) : String(fields.slug)}`,
          "确认后，此地址将不再按当前配置跳转。请先保存目标地址；删除不会移除平台地址或其他短链接。",
        ]);
      } else if (kind === "remove_domain")
        setPlanDetails([
          `域名：${domainById.get(String(fields.domainId))?.host || String(fields.domainId)}`,
          `此域名关联 ${linksByDomain.get(String(fields.domainId))?.length || 0} 条短链接。移除将影响这些短链接；如需保留配置，请先导出备份。`,
        ]);
      else
        setPlanDetails([
          `账户：${state.accounts.find((a) => a.id === fields.accountId)?.label || String(fields.accountId)}`,
          ...(kind === "recover_selftest_resources"
            ? ["本次只找回本机检测配置；完成后，恢复检测密钥仍需另行查看计划并确认。"]
            : []),
          ...((kind === "upgrade_worker" || kind === "resume_worker_upgrade" || kind === "enable_click_stats" || kind === "disable_click_stats" || kind === "enable_click_protection" || kind === "disable_click_protection")
            ? state.domains.filter((d) => d.accountId === fields.accountId).map((d) => `影响域名：${d.host}/${d.prefix}/`)
            : []),
        ]);
      setPlan(next);
    }
    return Boolean(next && shouldAccept());
    } finally {
      changePrepareInFlight.current = false;
    }
  }
  function closeStats() {
    statsPrepareSequence.current++;
    setStatsTarget(null);
    statsTargetRef.current = null;
  }
  useEffect(() => {
    if (statsTarget && (!state.accounts.some((account) => account.id === statsTarget.domain.accountId)
      || !state.domains.some((domain) => domain.id === statsTarget.domain.id && domain.accountId === statsTarget.domain.accountId && domain.host === statsTarget.domain.host && domain.prefix === statsTarget.domain.prefix)
      || !state.links.some((link) => link.domainId === statsTarget.domain.id && link.slug === statsTarget.link.slug))) closeStats();
  }, [state, statsTarget]);
  async function configureClickStats(accountId: string, enabled: boolean, target?: {link: Link; domain: Domain}) {
    if (mutationRef.current || !stateRef.current.accounts.some((account) => account.id === accountId)) return;
    const sequence = ++statsPrepareSequence.current;
    const accepts = () => statsPrepareSequence.current === sequence
      && stateRef.current.accounts.some((account) => account.id === accountId)
      && (!target || statsTargetRef.current === target);
    setStatsConfigurationError(null);
    await withMutation("prepare_click_stats", async () => {
      const prepared = await prepare(enabled ? "enable_click_stats" : "disable_click_stats", {
        accountId,
      }, accepts, (message) => {
        setStatsConfigurationError({accountId, message});
        setError("");
      });
      if (prepared && accepts()) setStatsPlanAccountId(accountId);
    });
  }
  async function apply() {
    if (plan && isDomainPlan && !isCurrentPlan(plan)) {
      if (!mutationRef.current) expireDomainPlan();
      return;
    }
    await withMutation("apply", async () => {
      if (!plan) return;
      const appliedKind = planKind;
      const savedLink =
        planKind === "save_link" && linkDraft ? { ...linkDraft } : null;
      const dnsSnapshot =
        appliedKind === "fix_domain_dns" ? { ...domainDraftRef.current } : null;
      const addedHost = appliedKind === "add_domain"
        ? normalizeHost(domainDraftRef.current.input)
        : "";
      const takeover = Boolean(plan.domainTakeoverConfirmation);
      const next = await run(
        () =>
          dispatch<State>("apply_plan", {
            planId: plan.id,
            ...(takeover ? { acknowledgeDomainTakeover: true } : {}),
            ...(appliedKind === "migrate_credentials"
              ? { acknowledgeCredentialMigration: true }
              : {}),
          }),
        appliedKind === "migrate_credentials"
          ? "本机授权已更新，请重试刚才的操作"
          : appliedKind === "recover_selftest_resources"
            ? "本机检测配置已找回。请查看新的修复计划，另行确认恢复检测密钥。"
          : appliedKind === "dismiss_worker_upgrade"
            ? "本机升级记录已解除，云端和密钥未修改。请继续核对云端当前状态。"
          : appliedKind === "resume_worker_upgrade"
            ? "云端升级已核对，待处理记录已完成。请留意账户中的检测密钥恢复提示。"
          : appliedKind === "upgrade_worker"
            ? "云端升级结果已核对。请留意账户中的检测密钥恢复提示。"
          : appliedKind === "enable_click_stats"
            ? "点击统计已启用。之后的访问会逐步显示在统计中，访客仍然直接跳转。"
          : appliedKind === "disable_click_stats"
            ? "点击统计已停用。跳转保持不变，已有统计按服务保留期处理。"
          : appliedKind === "enable_click_protection"
            ? "访问保护已启用：同一 IP 对同一短链接的近似阈值为每个节点 100 次 / 10 秒；服务异常时放行，不保证全球总次数或费用上限。"
          : appliedKind === "disable_click_protection"
            ? "访问保护已停用。"
          : appliedKind === "add_domain"
            ? "域名已接入。现在可以创建第一条短链接；云端配置可能需要稍等片刻才生效。"
            : appliedKind === "fix_domain_dns"
              ? "解析设置已提交，正在继续检查域名。"
              : "已提交修改。云端更新可能需要一点时间生效。",
        undefined,
        appliedKind === "enable_click_stats" || appliedKind === "disable_click_stats"
          ? (message) => {
              if (statsPlanAccountId) setStatsConfigurationError({accountId: statsPlanAccountId, message});
              setError("");
            }
          : appliedKind === "save_pool" || (appliedKind === "migrate_credentials" && page === "pools") ? setPoolError : undefined,
      );
      if (next) {
        if (["enable_click_protection", "disable_click_protection", "upgrade_worker", "resume_worker_upgrade"].includes(appliedKind)) {
          protectionReadSequence.current += 1;
          setProtectionRead(null);
        }
        stateRef.current = next;
        publishState(next);
        if (["enable_click_stats", "disable_click_stats", "upgrade_worker", "resume_worker_upgrade"].includes(appliedKind)) {
          setStatsRevision((n) => n + 1);
          setStatsConfigurationError(null);
          setStatsPlanAccountId("");
        }
        if (appliedKind === "add_domain") {
          setDomainSuccessId(next.domains.find((domain) => domain.host === addedHost)?.id || "");
        }
        setPoolHealth({});
        if (appliedKind === "save_pool") setPoolSavedRevision((n) => n + 1);
        setPlan(null);
        if (appliedKind === "migrate_credentials") {
          setMigrationAccountId(null);
          setPoolError("");
          setDomainFeedback({
            tone: "success",
            message: "本机授权已更新，请重试刚才的操作",
          });
          return;
        }
        if (appliedKind === "recover_selftest_resources") return;
        if (appliedKind === "save_link") closeLink();
        setDomainOpen(appliedKind === "fix_domain_dns");
        setPreflight(null);
        setDnsPreflight(null);
        if (
          appliedKind === "fix_domain_dns" &&
          dnsSnapshot &&
          domainDraftRef.current.input === dnsSnapshot.input &&
          domainDraftRef.current.prefix === dnsSnapshot.prefix &&
          domainDraftRef.current.accountId === dnsSnapshot.accountId
        )
          void refreshDomainPreparation(dnsSnapshot, {
            repairAlreadyApplied: true,
          });
        if (savedLink) {
          const domain = next.domains.find((d) => d.id === savedLink.domainId);
          const link = next.links.find(
            (l) => l.domainId === savedLink.domainId && l.slug === savedLink.slug,
          );
          if (domain && link) void selftest(link, domain);
        }
      } else {
        setPlan(null);
        if (appliedKind !== "migrate_credentials")
          setDomainOpen(
            appliedKind === "add_domain" || appliedKind === "fix_domain_dns",
          );
        try {
          const latest = await dispatch<State>("get_state");
          stateRef.current = latest;
          publishState(latest);
        } catch {
          /* Preserve the original operation error. */
        }
      }
    });
  }
  async function copy(value: string) {
    await run(async () => {
      if (preview) await navigator.clipboard.writeText(value);
      else
        await (
          await import("@tauri-apps/plugin-clipboard-manager")
        ).writeText(value);
    }, "已复制短链接。");
  }
  function openLink(link?: Link, usePlatform = false, preferredDomainId?: string) {
    setFormErrors({});
    linkPrepareSequence.current += 1;
    setError("");
    setCopySource(null);
    setOriginalSlug(link?.slug || null);
    setLinkDraft(
      link
        ? {
            domainId: link.domainId,
            slug: link.slug,
            cnUrl: link.cnUrl,
            defaultUrl: link.defaultUrl,
            poolId: usePlatform
              ? state.pools?.[0]?.id || ""
              : link.poolId || "",
            code: link.code || "",
          }
        : {
            domainId: state.domains.find((domain) => domain.id === preferredDomainId)?.id ||
              state.domains.find((domain) => domain.id === filter)?.id ||
              state.domains[0]?.id || "",
            slug: "",
            cnUrl: "",
            defaultUrl: "",
            poolId: "",
            code: "",
          },
    );
  }
  function updateLinkDraft(fields: Partial<LinkDraft>) {
    setFormErrors({});
    linkPrepareSequence.current += 1;
    setError("");
    setMigrationAccountId(null);
    setLinkDraft((current) => (current ? { ...current, ...fields } : current));
  }
  function useNewLinkName() {
    if (!linkDraft || !originalSlug || busy) return;
    linkPrepareSequence.current += 1;
    setCopySource({ domainId: linkDraft.domainId, slug: originalSlug });
    setOriginalSlug(null);
    setLinkDraft({ ...linkDraft, slug: "" });
    setError("");
  }
  useEffect(() => {
    if (copySource) slugInput.current?.focus();
  }, [copySource]);
  function closeLink() {
    if (mutationRef.current === "prepare_credentials") return;
    linkPrepareSequence.current += 1;
    setLinkDraft(null);
    setCopySource(null);
  }
  async function saveLink(event: FormEvent) {
    event.preventDefault();
    if (!linkDraft || mutationRef.current) return;
    const fields: FieldErrors = {};
    if (!state.domains.some((domain) => domain.id === linkDraft.domainId)) fields["link-domain"] = "请先选择可用域名。";
    const slugError = validateSlug(linkDraft.slug);
    if (slugError) fields["link-slug"] = slugError;
    if (linkDraft.poolId) {
      if (!state.pools?.some((pool) => pool.id === linkDraft.poolId)) fields["link-pool"] = "请选择可用平台地址。";
      if (!/^[A-Za-z0-9_-]{1,128}$/.test(linkDraft.code)) fields["link-code"] = "邀请码须为 1–128 位字母、数字、下划线或连字符。";
    } else {
      const cnError = validateTarget(linkDraft.cnUrl);
      const defaultError = validateTarget(linkDraft.defaultUrl);
      if (cnError) fields["link-cn"] = cnError;
      if (defaultError) fields["link-default"] = defaultError;
    }
    if (originalSlug && originalSlug !== linkDraft.slug) fields["link-slug"] = "请点击“换一个名称”，填写新名称后创建链接。";
    if (!originalSlug && state.links.some((link) => link.domainId === linkDraft.domainId && link.slug.toLowerCase() === linkDraft.slug.toLowerCase())) {
      fields["link-slug"] = "这个名称已被使用，请换一个名称。现有链接不会被覆盖。";
    }
    if (Object.keys(fields).length) { rejectFields(fields); return; }
    setFormErrors({});
    const submittedDraft = { ...linkDraft };
    const requestSequence = ++linkPrepareSequence.current;
    await prepare(
      "save_link",
      linkDraft.poolId
        ? {
            domainId: linkDraft.domainId,
            slug: linkDraft.slug,
            poolId: linkDraft.poolId,
            code: linkDraft.code,
            createOnly: !originalSlug,
          }
        : {
            domainId: linkDraft.domainId,
            slug: linkDraft.slug,
            cnUrl: linkDraft.cnUrl,
            defaultUrl: linkDraft.defaultUrl,
            createOnly: !originalSlug,
          },
      () =>
        requestSequence === linkPrepareSequence.current &&
        JSON.stringify(linkDraftRef.current) === JSON.stringify(submittedDraft),
    );
  }
  function beginDomainOperation() {
    if (
      domainOperation.current.inflight ||
      mutationRef.current === "prepare_credentials" ||
      (mutationRef.current === "apply" && planKind === "migrate_credentials")
    ) return null;
    const sequence = ++domainOperation.current.sequence;
    domainOperation.current.inflight = true;
    setDomainBusy(true);
    setError("");
    return sequence;
  }
  function invalidateDomainPreparation() {
    setFormErrors({});
    domainOperation.current.sequence += 1;
    domainCheckSequence.current += 1;
    setMigrationAccountId(null);
    setPreflight(null);
    setDnsPreflight(null);
    setDomainAutomaticDns(false);
    setDomainFeedback(null);
    setDuplicateDomainId("");
    setError("");
  }
  function finishDomainOperation() {
    domainOperation.current.inflight = false;
    setDomainBusy(false);
  }
  function isCurrentDomainOperation(sequence: number) {
    return sequence === domainOperation.current.sequence;
  }
  function expireDomainPlan() {
    invalidateDomainPreparation();
    setPlan(null);
    setDomainOpen(true);
    setDomainFeedback({ tone: "error", message: expiredDomainPlanMessage });
  }
  function openDomainPlan(result: DomainPreparation) {
    if (!result.plan) return;
    if (!isCurrentPlan(result.plan)) {
      expireDomainPlan();
      return;
    }
    setPlanKind("add_domain");
    setPlanDetails([
      `域名：${result.host}`,
      `链接目录：/${result.prefix}/`,
      `账户：${result.candidates.find((candidate) => candidate.accountId === domainDraftRef.current.accountId)?.label || "待确认"}`,
      ...(result.dnsMode === "public" ? ["网络检查：公共 DNS（兼容 VPN）"] : []),
    ]);
    setPlan(result.plan);
    setDomainOpen(false);
  }
  function openDnsPlan(result: DomainDnsPreparation) {
    if (!result.plan) return;
    if (!isCurrentPlan(result.plan)) {
      expireDomainPlan();
      return;
    }
    setPlanKind("fix_domain_dns");
    setPlanDetails([
      `主机名：${result.host}`,
      ...result.actions.map((action) =>
        action.kind === "createPlaceholder"
          ? `创建代理 ${action.recordType} 占位记录：${action.name}`
          : `开启代理：${action.recordType} ${action.name}`,
      ),
      "解析设置后会自动重新检查域名接入；不会自动接入短链接目录。",
    ]);
    setPlan(result.plan);
    setDomainOpen(false);
  }
  async function syncDomainState(
    operation: number,
    sequence: number,
    failurePrefix: string,
  ) {
    try {
      const next = await dispatch<State>("get_state");
      if (
        sequence !== domainCheckSequence.current ||
        !isCurrentDomainOperation(operation)
      )
        return false;
      stateRef.current = next;
      publishState(next);
      return true;
    } catch (e) {
      if (
        sequence === domainCheckSequence.current &&
        isCurrentDomainOperation(operation)
      )
        setDomainFeedback({
          tone: "error",
          message: `${failurePrefix}：${errorMessage(e)}`,
        });
      return false;
    }
  }
  async function refreshDomainPreparation(
    draft = domainDraftRef.current,
    options: {
      repairAlreadyApplied?: boolean;
    } = {},
  ) {
    const hostError = validateHost(draft.input);
    const prefixError = validatePrefix(draft.prefix);
    const validation = hostError || prefixError;
    if (validation) rejectFields({...(hostError ? {"domain-host": hostError} : {}), ...(prefixError ? {"domain-prefix": prefixError} : {})});
    if (validation) { setDomainFeedback(null); return; }
    const host = normalizeHost(draft.input);
    const existingDomain = stateRef.current.domains.find((domain) => domain.host === host);
    if (existingDomain) {
      domainCheckSequence.current += 1;
      domainOperation.current.sequence += 1;
      setPlan(null);
      setPlanKind("");
      setPreflight(null);
      setDnsPreflight(null);
      setDomainAutomaticDns(false);
      setMigrationAccountId(null);
      setDuplicateDomainId(existingDomain.id);
      setDomainFeedback({
        tone: "warning",
        message: `${host} 已接入 /${existingDomain.prefix}/ 目录。一个主机名只能接入一个链接目录；请查看已有域名或直接创建短链接。`,
      });
      return;
    }
    setDuplicateDomainId("");
    const cachedAccounts = stateRef.current.accounts.filter((account) =>
      account.zones?.some((zone) =>
        zone.status === "active" &&
        (host === zone.name || host.endsWith(`.${zone.name}`))),
    );
    const accountIds = draft.accountId
      ? [draft.accountId]
      : (cachedAccounts.length
          ? cachedAccounts
          : stateRef.current.accounts.length === 1
            ? stateRef.current.accounts
            : []).map((account) => account.id);
    if (!requireCurrentCredentials(accountIds)) return;
    const operation = beginDomainOperation();
    if (operation === null) return;
    const sequence = ++domainCheckSequence.current;
    const snapshot = {
      input: draft.input.trim(),
      prefix: draft.prefix,
      accountId: draft.accountId,
      dnsMode: draft.dnsMode,
    };
    setDomainFeedback({
      tone: "progress",
      message: "正在检查此账户的域名配置，请稍候。",
    });
    setPreflight(null);
    setDnsPreflight(null);
    setDomainAutomaticDns(false);
    const isCurrent = () => sequence === domainCheckSequence.current &&
      isCurrentDomainOperation(operation);
    let automaticRetryUsed = false;
    async function prepareWithAutomaticDns(): Promise<DomainPreparation | null> {
      const prepare = () => dispatch<DomainPreparation>("prepare_domain", {
        input: snapshot.input,
        prefix: snapshot.prefix,
        dnsMode: snapshot.dnsMode,
        ...(snapshot.accountId ? { accountId: snapshot.accountId } : {}),
      });
      let result = await prepare();
      if (!isCurrent()) return null;
      if (snapshot.dnsMode === "system" && !automaticRetryUsed && hasOnlyVirtualDnsBlocker(result)) {
        automaticRetryUsed = true;
        snapshot.dnsMode = "public";
        setDomainAutomaticDns(true);
        setDomainFeedback({
          tone: "progress",
          message: "检测到 VPN 虚拟地址，正在自动使用公共 DNS 重新检查。",
        });
        result = await prepare();
        if (!isCurrent()) return null;
      }
      const accountId = snapshot.accountId || (result.candidates.length === 1 ? result.candidates[0].accountId : "");
      if (accountId && result.dnsMode === "public" && result.canApply && result.plan &&
          !result.checks.some((check) => domainCheckLevel(check) === "error")) {
        publicDnsDomains.current.add(JSON.stringify([accountId, result.host, result.prefix]));
      }
      return result;
    }
    try {
      let result = await prepareWithAutomaticDns();
      if (!result) return;
      if (
        sequence !== domainCheckSequence.current ||
        !isCurrentDomainOperation(operation)
      )
        return;
      if (!snapshot.accountId && result.candidates.length === 1) {
        snapshot.accountId = result.candidates[0].accountId;
        const matchedDraft = {
          ...domainDraftRef.current,
          accountId: result.candidates[0].accountId,
        };
        domainDraftRef.current = matchedDraft;
        setDomainDraft(matchedDraft);
      }
      if (
        !(await syncDomainState(
          operation,
          sequence,
          "域名检查完成，但无法刷新域名列表",
        ))
      )
        return;
      if (!result.canApply && hasOnlyDnsBlocker(result) && !hasOnlyNetworkBlocker(result)) {
        setPreflight(result);
        if (!snapshot.accountId) {
          setDomainFeedback({
            tone: "error",
            message:
              result.candidates.length > 1
                ? "多个账户都可能管理此域名。请选择账户后重新检查；尚未读取或修改 DNS。"
                : "尚未确认此域名所属账户。请选择账户或刷新域名列表后重新检查。",
          });
          return;
        }
        setDomainFeedback({
          tone: "progress",
          message: "域名只缺少网站解析，正在读取现有 DNS；这一步不会修改云端。",
        });
        const dns = await dispatch<DomainDnsPreparation>("prepare_domain_dns", {
          input: snapshot.input,
          ...(snapshot.accountId ? { accountId: snapshot.accountId } : {}),
        });
        if (
          sequence !== domainCheckSequence.current ||
          !isCurrentDomainOperation(operation)
        )
          return;
        if (
          !(await syncDomainState(
            operation,
            sequence,
            "DNS 检查完成，但无法刷新域名列表",
          ))
        )
          return;
        setDnsPreflight(dns);
        if (dns.dnsStatus === "ready") {
          setDomainFeedback({
            tone: "progress",
            message: "网站解析已就绪，正在继续检查域名接入。",
          });
          result = await prepareWithAutomaticDns();
          if (!result) return;
          if (
            sequence !== domainCheckSequence.current ||
            !isCurrentDomainOperation(operation)
          )
            return;
          setPreflight(result);
          if (result.canApply && result.plan) {
            setDomainFeedback(null);
            openDomainPlan(result);
          } else {
            setDomainFeedback(
              hasOnlyDnsBlocker(result)
                ? {
                    tone: "error",
                    message:
                      "DNS 已显示就绪，但域名接入复核仍未通过。请查看下方最新检查结果，不要重复提交修改。",
                  }
                : null,
            );
          }
        } else if (dns.canApply && dns.plan && !options.repairAlreadyApplied) {
          setDomainFeedback(null);
          openDnsPlan(dns);
        } else {
          setDomainFeedback(
            options.repairAlreadyApplied && dns.canApply
              ? {
                  tone: "error",
                  message:
                    "解析修改已提交，但云端复核仍显示需要处理。请先核对下方状态，不要重复提交同一修改。",
                }
              : null,
          );
        }
      } else {
        setPreflight(result);
        setDnsPreflight(null);
        setDomainFeedback(null);
        if (result.canApply && result.plan)
          openDomainPlan(result);
      }
    } catch (e) {
      if (
        sequence === domainCheckSequence.current &&
        isCurrentDomainOperation(operation)
      )
        setDomainFeedback({ tone: "error", message: errorMessage(e) });
    } finally {
      finishDomainOperation();
    }
  }
  async function checkDomain(event: FormEvent) {
    event.preventDefault();
    await refreshDomainPreparation();
  }
  async function refreshDomainAccountList() {
    const selectedAccountId =
      domainDraftRef.current.accountId ||
      (stateRef.current.accounts.length === 1
        ? stateRef.current.accounts[0].id
        : "");
    if (!selectedAccountId) {
      setDomainFeedback({
        tone: "error",
        message: "请选择要刷新域名的 Cloudflare 账户。",
      });
      return;
    }
    if (!requireCurrentCredentials([selectedAccountId])) return;
    const operation = beginDomainOperation();
    if (operation === null) return;
    const sequence = ++domainCheckSequence.current;
    const account = stateRef.current.accounts.find(
      (item) => item.id === selectedAccountId,
    );
    setDomainFeedback({
      tone: "progress",
      message: "正在读取此账户的域名，请稍候。",
    });
    setPreflight(null);
    setDnsPreflight(null);
    setPlan(null);
    setPlanKind("");
    try {
      const next = await dispatch<State>("refresh_domains", {
        accountId: selectedAccountId,
      });
      if (
        sequence !== domainCheckSequence.current ||
        !isCurrentDomainOperation(operation)
      )
        return;
      stateRef.current = next;
      publishState(next);
      const refreshed = next.accounts.find(
        (item) => item.id === selectedAccountId,
      );
      let requestedHost = "";
      try {
        requestedHost = normalizeHost(domainDraftRef.current.input);
      } catch {
        /* The user may only be refreshing the cached list. */
      }
      const hostFound =
        requestedHost &&
        (refreshed?.zones || []).some(
          (zone) =>
            zone.status === "active" &&
            (requestedHost === zone.name ||
              requestedHost.endsWith(`.${zone.name}`)),
        );
      const hostNote = requestedHost
        ? hostFound
          ? `已找到与 ${requestedHost} 匹配的已启用域名。`
          : `暂未在此账户的已启用域名中匹配 ${requestedHost}；这可能与权限、域名尚未启用或输入主机名有关。`
        : "";
      setDomainFeedback({
        tone: "success",
        message: `已读取「${refreshed?.cloudflareName || refreshed?.label || account?.label || "所选账户"}」的 ${refreshed?.zoneCount ?? refreshed?.zones?.length ?? 0} 个域名。${hostNote}`,
      });
    } catch (e) {
      if (
        sequence === domainCheckSequence.current &&
        isCurrentDomainOperation(operation)
      )
        setDomainFeedback({
          tone: "error",
          message: `无法读取此账户的域名：${errorMessage(e)}`,
        });
    } finally {
      finishDomainOperation();
    }
  }
  function updateSelectedDomainToken() {
    const account = stateRef.current.accounts.find(
      (item) => item.id === domainDraftRef.current.accountId,
    );
    if (!account) return;
    if (error)
      setDomainFeedback({ tone: "error", message: domainErrorMessage(error) });
    setError("");
    setUpdateTokenAccount(account);
    setToken("");
    setReplaceToken(true);
    setClipboardOffer("");
    resumeDomainAfterToken.current = true;
    setTokenOpen(true);
  }
  function retryDomainAfterAuthorization() {
    setError("");
    setDomainFeedback({
      tone: "progress",
      message: "正在重新读取域名和 DNS 权限；这一步不会修改云端。",
    });
    void refreshDomainPreparation(domainDraftRef.current);
  }
  function domainRecoveryActions() {
    if (!domainDraft.accountId) return null;
    return (
      <div className="domain-feedback-actions">
        <button
          type="button"
          className="button secondary"
          onClick={() => void openTokenManagement()}
          disabled={domainBusy}
        >
          修改已有令牌权限
        </button>
        <button
          type="button"
          className="button secondary"
          onClick={retryDomainAfterAuthorization}
          disabled={domainBusy}
        >
          已补好授权，继续检查
        </button>
        <button
          type="button"
          className="button ghost"
          onClick={updateSelectedDomainToken}
          disabled={domainBusy}
        >
          更换本机令牌
        </button>
      </div>
    );
  }
  function closeDomain() {
    if (mutationRef.current === "prepare_credentials") return;
    invalidateDomainPreparation();
    setDomainOpen(false);
  }
  function returnFromPlan() {
    if (mutationRef.current === "apply") return;
    if (plan && isDomainPlan && !isCurrentPlan(plan)) {
      expireDomainPlan();
      return;
    }
    setPlan(null);
    if (planKind === "add_domain" || planKind === "fix_domain_dns")
      setDomainOpen(true);
  }
  async function openAccountPage(url: string) {
    try {
      if (preview) window.open(url, "_blank", "noopener,noreferrer");
      else {
        const { openUrl } = await import("@tauri-apps/plugin-opener");
        await openUrl(url);
      }
    } catch (e) {
      const message = `无法打开浏览器：${errorMessage(e)}`;
      setError((current) => current ? `${current}\n${message}` : message);
    }
  }
  async function openTokenManagement() {
    await openAccountPage("https://dash.cloudflare.com/profile/api-tokens");
  }
  async function openTemplate() {
    const url = await run(() => dispatch<string>("token_template"));
    if (url) await openAccountPage(url);
  }
  async function checkClipboard() {
    if (!tokenDialogOpen.current || mutationRef.current === "token") return;
    const sequence = ++clipboardReadSequence.current;
    const isCurrent = () => sequence === clipboardReadSequence.current &&
      tokenDialogOpen.current && mutationRef.current !== "token";
    try {
      const readText = preview
        ? () => navigator.clipboard.readText()
        : (await import("@tauri-apps/plugin-clipboard-manager")).readText;
      if (!isCurrent()) return;
      const text = (await readText()).trim();
      if (!isCurrent()) return;
      if (/^[A-Za-z0-9_-]{35,80}$/.test(text) && text !== token)
        setClipboardOffer(text);
      else setClipboardOffer("");
    } catch {
      /* Clipboard permission is optional. */
    }
  }
  useEffect(() => {
    if (!tokenOpen) return;
    const onFocus = () => {
      void checkClipboard();
    };
    window.addEventListener("focus", onFocus);
    return () => {
      clipboardReadSequence.current += 1;
      window.removeEventListener("focus", onFocus);
    };
  }, [tokenOpen, token]);
  async function tokenDigest(value: string) {
    return Array.from(
      new Uint8Array(
        await crypto.subtle.digest("SHA-256", new TextEncoder().encode(value)),
      ),
    )
      .map((x) => x.toString(16).padStart(2, "0"))
      .join("");
  }
  async function clearImportedClipboard() {
    await run(async () => {
      const clipboard = preview
        ? {
            readText: () => navigator.clipboard.readText(),
            writeText: (text: string) => navigator.clipboard.writeText(text),
          }
        : await import("@tauri-apps/plugin-clipboard-manager");
      const current = await clipboard.readText();
      if ((await tokenDigest(current.trim())) === clipboardToClear) {
        await clipboard.writeText("");
        setNotice("已清空剪贴板中的令牌。");
      } else setNotice("剪贴板已是其他内容，已保留。");
      setClipboardToClear("");
    });
  }
  function closeToken() {
    if (mutationRef.current === "token") return;
    resumeDomainAfterToken.current = false;
    setTokenOpen(false);
    setToken("");
    setClipboardOffer("");
    setReplaceToken(false);
    setUpdateTokenAccount(null);
  }
  async function importToken(event: FormEvent) {
    event.preventDefault();
    if (!token.trim()) {
      setError("");
      rejectFields({"token-value": "请先粘贴令牌。"});
      return;
    }
    await withMutation("token", async () => {
      clearClipboardOffer();
      const next = await run(
        () =>
          dispatch<State>("import_token", {
            token: token.trim(),
            replace: updateTokenAccount ? true : replaceToken,
            ...(updateTokenAccount
              ? { expectedAccountId: updateTokenAccount.id }
              : {}),
          }),
        updateTokenAccount ? "账户访问令牌已更新。" : "账户已导入。",
      );
      if (next) {
        const shouldResumeDomain = resumeDomainAfterToken.current;
        resumeDomainAfterToken.current = false;
        setClipboardToClear(await tokenDigest(token.trim()));
        stateRef.current = next;
        publishState(next);
        setToken("");
        setClipboardOffer("");
        setReplaceToken(false);
        setUpdateTokenAccount(null);
        setTokenOpen(false);
        if (shouldResumeDomain) {
          setDomainOpen(true);
          void refreshDomainPreparation(domainDraftRef.current);
        }
      } else {
        // A failed first import can leave a recoverable account on disk.
        // Preserve the original error while exposing that account immediately.
        try {
          const latest = await dispatch<State>("get_state");
          publishState(latest);
          if (latest.accounts.some((account) => account.needsTokenRecovery)) setPage("accounts");
        } catch { /* Keep the import failure visible; refresh remains available. */ }
      }
    });
  }
  async function exportBackup() {
    const json = await run(() => dispatch<string>("export_config"));
    if (!json) return;
    if (preview) {
      const url = URL.createObjectURL(
        new Blob([json], { type: "application/json" }),
      );
      const anchor = document.createElement("a");
      anchor.href = url;
      anchor.download = "link-config-preview.json";
      anchor.click();
      window.setTimeout(() => URL.revokeObjectURL(url), 1000);
      setNotice("示例备份已下载。");
    } else {
      const { save } = await import("@tauri-apps/plugin-dialog");
      const { writeTextFile } = await import("@tauri-apps/plugin-fs");
      const path = await run(() =>
        save({
          defaultPath: "link-config.json",
          filters: [{ name: "JSON", extensions: ["json"] }],
        }),
      );
      if (path) await run(() => writeTextFile(path, json), "备份已保存。");
    }
  }
  async function importBackup() {
    if (preview) {
      setError("本地预览无法验证远端归属，请在桌面应用中导入备份。");
      return;
    }
    const { open } = await import("@tauri-apps/plugin-dialog");
    const { readTextFile } = await import("@tauri-apps/plugin-fs");
    const path = await run(() =>
      open({
        multiple: false,
        filters: [{ name: "JSON", extensions: ["json"] }],
      }),
    );
    if (typeof path !== "string") return;
    const json = await run(() => readTextFile(path));
    if (!json) return;
    const next = await run(
      () => dispatch<State>("import_config", { json }),
      "备份已导入并验证。",
    );
    if (next) publishState(next);
  }
  async function refreshAccounts() {
    if (!requireCurrentCredentials(stateRef.current.accounts.map((a) => a.id))) return;
    await withMutation("refresh_accounts", async () => {
      const next = await run(() => dispatch<State>("refresh_accounts"), "账户状态已更新。");
      if (next) publishState(next);
    });
  }
  async function checkUpdate() {
    if (updateCheckingInFlight.current) return;
    updateCheckingInFlight.current = true;
    const sequence = ++updateOperationSequence.current;
    setUpdateOpen(true);
    setUpdateStatus(null);
    setUpdateCancelMessage("");
    setUpdateError("");
    setError("");
    try {
      const result = await updates.check();
      setUpdateStatus({
        ...result,
        currentVersion: result.currentVersion || stateRef.current.appVersion,
      });
    } catch (e) {
      setUpdateError(errorMessage(e));
    } finally {
      if (sequence === updateOperationSequence.current) {
        updateOperationSequence.current += 1;
        setUpdateCancelMessage("");
      }
      updateCheckingInFlight.current = false;
    }
  }
  async function cancelUpdate() {
    if (updateCancellationInFlight.current || updatePhase === "installing") return;
    updateCancellationInFlight.current = true;
    const sequence = updateOperationSequence.current;
    setCancellingUpdate(true);
    setUpdateError("");
    try {
      const result = await dispatch<import("./types").UpdateCancellation>("cancel_update");
      if (sequence !== updateOperationSequence.current) return;
      if (result?.status !== "cancel_requested") throw new Error("未能确认取消请求，请等待当前操作返回。");
      setUpdateCancelMessage(result.message || "已请求取消，正在等待本次操作返回。");
    } catch (e) {
      if (sequence === updateOperationSequence.current) setUpdateError(errorMessage(e));
    } finally {
      updateCancellationInFlight.current = false;
      setCancellingUpdate(false);
    }
  }
  function openUpdate() {
    setUpdateOpen(true);
    setUpdateCancelMessage("");
    setUpdateError("");
    setError("");
    if (installedUpdate || updates.available) {
      setUpdateStatus(installedUpdate || updates.available);
    } else {
      void checkUpdate();
    }
  }
  async function installUpdate() {
    await withMutation("update", async () => {
      const sequence = ++updateOperationSequence.current;
      setUpdateError("");
      setUpdateCancelMessage("");
      setUpdatePhase(null);
      let unlisten: (() => void) | undefined;
      let acceptingProgress = true;
      try {
        if (!preview && "__TAURI_INTERNALS__" in window) {
          const { listen } = await import("@tauri-apps/api/event");
          unlisten = await listen<{phase: string}>("update-progress", ({payload}) => {
            if (acceptingProgress && ["checking", "downloading", "verifying", "installing"].includes(payload.phase)) {
              setUpdatePhase(payload.phase as "checking" | "downloading" | "verifying" | "installing");
            }
          });
        }
        const result = await dispatch<UpdateStatus>("install_update");
        if (!result || !["installed", "up_to_date", "unavailable"].includes(result.status)) {
          throw new Error("未能确认更新是否安装完成，请重新检查更新。");
        }
        updates.accept(result);
        setUpdateStatus(result);
        if (result.status === "installed") setInstalledUpdate(result);
      } catch (e) {
        setUpdateError(errorMessage(e));
      } finally {
        acceptingProgress = false;
        if (sequence === updateOperationSequence.current) updateOperationSequence.current += 1;
        unlisten?.();
        setUpdatePhase(null);
        setUpdateCancelMessage("");
      }
    });
  }
  async function doRename(event: FormEvent) {
    event.preventDefault();
    if (!renameAccount) return;
    if (!renameValue.trim()) { setError(""); rejectFields({"account-name": "请填写账户名称。"}); return; }
    await withMutation("rename", async () => {
      const next = await run(
        () =>
          dispatch<State>("rename_account", {
            accountId: renameAccount.id,
            label: renameValue.trim(),
          }),
        "账户名称已更新。",
      );
      if (next) {
        publishState(next);
        setRenameAccount(null);
      }
    });
  }
  async function doRemove() {
    await withMutation("remove", async () => {
      if (!removeAccount) return;
      const next = await run(
        () => dispatch<State>("remove_account", { accountId: removeAccount.id }),
        "本机账户记录已移除。",
      );
      if (next) {
        publishState(next);
        setRemoveAccount(null);
      }
    });
  }
  async function savePool(pool: Pool, shouldAccept?: () => boolean) {
    setPoolError("");
    return prepare("save_pool", { pool }, shouldAccept, setPoolError);
  }
  async function prepareMonitor(event: FormEvent) {
    event.preventDefault();
    if (!monitorAccount || !requireCurrentCredentials([monitorAccount.id])) return;
    const endpoint = monitorEndpoint.trim();
    try {
      const url = new URL(endpoint);
      if (url.protocol !== "https:" || url.username || url.password)
        throw Error();
    } catch {
      rejectFields({"monitor-endpoint": "检测服务地址必须是无凭据的 HTTPS 网址。"});
      return;
    }
    if (!/^[\x21-\x7e]{32,256}$/.test(monitorSecret)) {
      rejectFields({"monitor-secret": "服务密钥须为 32–256 个无空白的可打印 ASCII 字符。"});
      return;
    }
    const requestSequence = ++monitorPrepareSequence.current;
    const shouldAccept = () => requestSequence === monitorPrepareSequence.current;
    setWorking(true);
    setError("");
    let next: Plan | undefined;
    try {
      next = await dispatch<Plan>("prepare_monitor", {
        accountId: monitorAccount.id,
        endpoint,
        secret: monitorSecret,
      });
    } catch (e) {
      if (shouldAccept())
        setError(errorMessage(e).replaceAll(monitorSecret, "[已隐藏]"));
    } finally {
      setWorking(false);
    }
    if (!shouldAccept()) return;
    setMonitorSecret("");
    if (next) {
      setPlanKind("enable_monitor");
      setPlanDetails([
        `账户：${monitorAccount.label}`,
        `检测服务：${endpoint}`,
      ]);
      setPlan({
        ...next,
        title: next.title.replaceAll(monitorSecret, "[已隐藏]"),
        steps: next.steps.map((step) =>
          step.replaceAll(monitorSecret, "[已隐藏]"),
        ),
        warnings: next.warnings.map((w) =>
          w.replaceAll(monitorSecret, "[已隐藏]"),
        ),
      });
      setMonitorAccount(null);
    }
  }
  async function disableMonitor(account: Account) {
    if (!requireCurrentCredentials([account.id])) return;
    const next = await run(() =>
      dispatch<Plan>("disable_monitor", { accountId: account.id }),
    );
    if (next) {
      setPlanKind("disable_monitor");
      setPlanDetails([`账户：${account.label}`]);
      setPlan(next);
    }
  }
  async function resumePending(action: PendingAction) {
    if (busy || mutationRef.current || pendingPrepareRef.current) return;
    pendingPrepareRef.current = true;
    try {
      if (action.accountId && !requireCurrentCredentials([action.accountId])) return;
      if (action.kind === "resume_pool_sync" && action.poolId) {
        await prepare("resume_pool_sync", { poolId: action.poolId });
        return;
      }
      if (action.kind === "delete_pool" && action.poolId) {
        await prepare("delete_pool", { poolId: action.poolId });
        return;
      }
      if (
        (isSelftestRecovery(action.kind) || action.kind === "resume_worker_upgrade") &&
        action.accountId
      ) {
        await prepare(action.kind, { accountId: action.accountId });
        return;
      }
      if (action.kind === "resume_monitor" && action.accountId) {
        const next = await run(() =>
          dispatch<Plan>("resume_monitor", { accountId: action.accountId }),
        );
        if (next) {
          setPlanKind("resume_monitor");
          setPlanDetails([
            `账户：${state.accounts.find((a) => a.id === action.accountId)?.label || action.accountId}`,
          ]);
          setPlan(next);
        }
      }
    } finally {
      pendingPrepareRef.current = false;
    }
  }
  async function inspectPool(poolId: string) {
    const enabledAccounts = (stateRef.current.pools?.find((pool) => pool.id === poolId)?.accountIds || [])
      .filter((id) => stateRef.current.accounts.some((account) => account.id === id && account.monitorEnabled));
    if (!requireCurrentCredentials(enabledAccounts)) return;
    const fingerprint = poolFingerprint(poolId, stateRef.current);
    const result = await run(() =>
      dispatch<PoolHealth>("check_pool_health", { poolId }),
    );
    if (result && fingerprint === poolFingerprint(poolId, stateRef.current))
      setPoolHealth((prev) => ({
        ...prev,
        [poolId]: { fingerprint, report: result },
      }));
  }
  function detectionKey(link: Link) {
    return `${link.domainId}:${link.slug}`;
  }
  function fingerprint(link: Link, snapshot: State = stateRef.current) {
    const pool = snapshot.pools?.find((p) => p.id === link.poolId);
    const domain = snapshot.domains.find((item) => item.id === link.domainId);
    return JSON.stringify([
      domain?.host, domain?.prefix, domain?.accountId,
      link.updated,
      link.poolId,
      link.code,
      link.cnUrl,
      link.defaultUrl,
      pool?.updated,
      pool?.official,
      pool?.candidates,
    ]);
  }
  async function selftest(link: Link, domain: Domain, requestedMode?: "system" | "public") {
    const key = detectionKey(link);
    if (detectionInflight.current.has(key)) return;
    if (!requireCurrentCredentials([domain.accountId])) return;
    const dnsKey = JSON.stringify([domain.accountId, domain.host, domain.prefix]);
    let dnsMode = requestedMode || (publicDnsDomains.current.has(dnsKey) ? "public" : "system");
    let automaticDns = false;
    closeDetection();
    detectionInflight.current.add(key);
    const url = shortUrl(domain.host, domain.prefix, link.slug);
    const sequence = ++detectionSequence.current;
    latestDetectionForLink.current[detectionKey(link)] = sequence;
    setTestingLink(url);
    setError("");
    const observedFingerprint = fingerprint(link);
    const isCurrent = () => {
      const current = stateRef.current.links.find((item) => detectionKey(item) === key);
      return sequence === detectionSequence.current && current && fingerprint(current) === observedFingerprint;
    };
    const routeRequest = () => dispatch<Selftest>("selftest_link", {
      domainId: link.domainId, slug: link.slug, ...(dnsMode === "public" ? {dnsMode} : {}),
    });
    const targetRequest = () => dispatch<TargetReport>("check_link_targets", {
      domainId: link.domainId, slug: link.slug, ...(dnsMode === "public" ? {dnsMode} : {}),
    });
    try {
      let [route, targets] = await Promise.allSettled([routeRequest(), targetRequest()]);
      // A rejected credential/API operation is not a DNS diagnosis. Never retry it
      // automatically; a typed route or target result must establish virtual DNS.
      if (isCurrent() && dnsMode === "system" && route.status === "fulfilled" && targets.status === "fulfilled") {
        const routeVirtual = route.value.checks.some((check) => !check.ok && check.reason === "virtual_dns_address");
        const targetsVirtual = targets.value.checks.some((check) => check.status === "unknown" && check.reason === "virtual_dns_address");
        const routeSafe = (route.value.status === "passed" || route.value.checks.length > 0) &&
          route.value.checks.every((check) => check.ok || check.reason === "virtual_dns_address");
        const targetsSafe = targets.value.checks.every((check) => check.status === "passed" ||
          (check.status === "unknown" && check.reason === "virtual_dns_address"));
        const retry = targetsSafe && (route.value.status === "key_missing"
          ? targetsVirtual
          : routeSafe && (routeVirtual || targetsVirtual));
        if (retry) {
          automaticDns = true;
          setTestingAutomaticDns(true);
          if (route.value.status === "key_missing") {
            // Targets are anonymous; do not repeat a known missing-key read.
            targets = (await Promise.allSettled([dispatch<TargetReport>("check_link_targets", {
              domainId: link.domainId, slug: link.slug, dnsMode: "public",
            })]))[0];
          } else {
            dnsMode = "public";
            [route, targets] = await Promise.allSettled([routeRequest(), targetRequest()]);
          }
        }
      }
      const checkedAt = new Date().toISOString();
      const result: Selftest =
        route.status === "fulfilled"
          ? route.value
          : {
              status: "pending",
              message: `短链接检测未完成：${errorMessage(route.reason)}`,
              checks: [],
            };
      const targetReport: TargetReport =
        targets.status === "fulfilled"
          ? targets.value
          : {
              checkedAt,
              dnsMode: automaticDns ? "public" : dnsMode,
              checks: [
                {
                  label: "目标地址",
                  status: "unknown",
                  message: `本机检测未完成：${errorMessage(targets.reason)}`,
                  checkedAt,
                  source: "local",
                  dnsMode: automaticDns ? "public" : dnsMode,
                  url: "",
                },
              ],
            };
      if (isCurrent() && latestDetectionForLink.current[detectionKey(link)] === sequence)
        setDetections((prev) => ({
          ...prev,
          [detectionKey(link)]: {
            fingerprint: observedFingerprint,
            selftest: result,
            targets: targetReport,
            checkedAt,
          },
        }));
      const current = stateRef.current.links.find(
        (item) => item.domainId === link.domainId && item.slug === link.slug,
      );
      if (sequence === detectionSequence.current) {
        if (current && fingerprint(current) === observedFingerprint) {
          if (dnsMode === "public" && result.status === "passed") publicDnsDomains.current.add(dnsKey);
          setTestResult({ url, result, domainId: link.domainId, slug: link.slug, fingerprint: observedFingerprint, dnsMode, automaticDns });
          setTargetResult(targetReport);
        } else setNotice("链接或平台地址已变化，请重新检测。");
      }
    } catch (e) {
      if (sequence === detectionSequence.current) setError(`检测未完成：${errorMessage(e)}`);
    } finally {
      detectionInflight.current.delete(key);
      if (sequence === detectionSequence.current) setTestingLink("");
    }
  }

  function closeDetection() {
    detectionSequence.current++;
    setTestingLink("");
    setTestingAutomaticDns(false);
    targetRetrySequence.current++;
    targetRetryBusy.current = false;
    setRetryingTargets(false);
    setTestResult(null);
    setTargetResult(null);
  }
  function retryRouteWithPublicDns() {
    if (!testResult || targetRetryBusy.current || testingLink) return;
    const link = stateRef.current.links.find((item) => item.domainId === testResult.domainId && item.slug === testResult.slug);
    const domain = stateRef.current.domains.find((item) => item.id === testResult.domainId);
    if (!link || !domain || fingerprint(link) !== testResult.fingerprint) {
      closeDetection();
      setNotice("链接或平台地址已变化，请重新检测。");
      return;
    }
    void selftest(link, domain, "public");
  }
  async function retryTargetsWithPublicDns() {
    if (!testResult || targetRetryBusy.current) return;
    const context = testResult;
    const currentLink = () => stateRef.current.links.find(
      (item) => item.domainId === context.domainId && item.slug === context.slug,
    );
    const link = currentLink();
    if (!link || fingerprint(link) !== context.fingerprint) {
      closeDetection();
      setNotice("链接或平台地址已变化，请重新检测。");
      return;
    }
    const sequence = ++targetRetrySequence.current;
    targetRetryBusy.current = true;
    setRetryingTargets(true);
    let report: TargetReport;
    try {
      report = await dispatch<TargetReport>("check_link_targets", {
        domainId: context.domainId, slug: context.slug, dnsMode: "public",
      });
    } catch (error) {
      const checkedAt = new Date().toISOString();
      report = {checkedAt, dnsMode: "public", checks: [{
        label: "目标地址", status: "unknown", source: "local", url: "",
        dnsMode: "public", checkedAt,
        message: `兼容 VPN 检测未完成：${errorMessage(error)}`,
      }]};
    }
    if (sequence !== targetRetrySequence.current) return;
    targetRetryBusy.current = false;
    setRetryingTargets(false);
    const latest = currentLink();
    if (!latest || fingerprint(latest) !== context.fingerprint) {
      closeDetection();
      setNotice("链接或平台地址已变化，请重新检测。");
      return;
    }
    setTargetResult(report);
    setDetections((previous) => {
      const key = detectionKey(latest);
      const record = previous[key];
      if (!record || record.fingerprint !== context.fingerprint) return previous;
      // Retain the route check timestamp: a target-only retry cannot renew it.
      return {...previous, [key]: {...record, targets: report}};
    });
  }

  function detectionLabel(link: Link): {tone: "slate" | "amber" | "red" | "green"; label: string} {
    const record = detections[detectionKey(link)];
    if (!record) return { tone: "slate", label: "未检测" };
    if (
      record.fingerprint !== fingerprint(link) ||
      clock - Date.parse(record.checkedAt) >= 3600000
    )
      return { tone: "slate", label: "结果已过期" };
    if (
      record.selftest.status === "failed" ||
      record.targets.checks.some((c) => c.status === "failed")
    )
      return { tone: "red", label: "本机检测发现失败" };
    if (
      record.selftest.status === "passed" &&
      record.targets.checks.length >= 2 &&
      record.targets.checks.every((c) => c.status === "passed")
    )
      return { tone: "green", label: "本机首跳检查通过" };
    return { tone: "amber", label: "暂时无法确认" };
  }

  const accountById = useMemo(
    () => new Map(state.accounts.map((a) => [a.id, a])),
    [state.accounts],
  );
  const visiblePoolHealth = Object.fromEntries(
    Object.entries(poolHealth)
      .filter(
        ([id, record]) => record.fingerprint === poolFingerprint(id, state),
      )
      .map(([id, record]) => [id, record.report]),
  ) as Record<string, PoolHealth>;
  const domainById = useMemo(() => new Map(state.domains.map((domain) => [domain.id, domain])), [state.domains]);
  const poolById = useMemo(() => new Map((state.pools || []).map((pool) => [pool.id, pool])), [state.pools]);
  const linksByDomain = useMemo(() => {
    const result = new Map<string, Link[]>();
    for (const link of state.links) {
      const links = result.get(link.domainId);
      if (links) links.push(link);
      else result.set(link.domainId, [link]);
    }
    return result;
  }, [state.links]);
  const domainCountByAccount = useMemo(() => {
    const counts = new Map<string, number>();
    for (const domain of state.domains) counts.set(domain.accountId, (counts.get(domain.accountId) || 0) + 1);
    return counts;
  }, [state.domains]);
  const linkCountByPool = useMemo(() => {
    const counts = new Map<string, number>();
    for (const link of state.links) if (link.poolId) counts.set(link.poolId, (counts.get(link.poolId) || 0) + 1);
    return counts;
  }, [state.links]);
  const searchTerm = search.trim().toLowerCase();
  const groups = state.domains.filter((domain) => filter === "all" || domain.id === filter)
    .map((domain) => ({domain, links: (linksByDomain.get(domain.id) || []).filter((link) => {
      const record = attentionOnly ? redirectMonitor.getRecord(link) : null;
      if (attentionOnly && (!record || !(record.stale || record.phase !== "healthy"))) return false;
      return `${link.slug} ${link.cnUrl} ${link.defaultUrl} ${link.code || ""} ${poolById.get(link.poolId || "")?.name || ""} ${domain.host}`.toLowerCase().includes(searchTerm);
    })})).filter((group) => (!searchTerm && !attentionOnly) || group.links.length);
  const matchingDomains = state.domains.filter((domain) => `${domain.host} ${domain.prefix} ${accountById.get(domain.accountId)?.label || ""}`.toLowerCase().includes(domainSearch.trim().toLowerCase()));
  const matchingAccounts = state.accounts.filter((account) => `${account.label} ${account.cloudflareName || ""} ${account.id}`.toLowerCase().includes(accountSearch.trim().toLowerCase()));
  const title =
    page === "links"
      ? "短链接"
      : page === "stats"
        ? "统计中心"
      : page === "pools"
        ? "平台地址"
        : page === "domains"
          ? "域名管理"
          : "Cloudflare 账户";
  const subtitle =
    page === "links"
      ? "查看、检测和编辑不同地区的跳转地址。"
      : page === "stats"
        ? "按账户和域名范围集中查看估算访问次数。"
      : page === "pools"
        ? "集中维护地址；关联链接各自保留邀请码。"
        : page === "domains"
          ? "添加前检查所属账户和现有网站配置。"
          : "管理连接、检测服务与本机备份。";
  const domainMigrationAccount = state.accounts.find((account) =>
    account.id === (domainDraft.accountId ||
      (state.accounts.length === 1 ? state.accounts[0].id : "")) &&
    account.needsCredentialMigration,
  );
  const currentVersion = updateStatus?.currentVersion || state.appVersion;
  let domainExampleHost = "example.com";
  try {
    domainExampleHost = normalizeHost(domainDraft.input);
  } catch {
    /* Keep a neutral fallback until the host is valid. */
  }
  const domainExamplePrefix = validatePrefix(domainDraft.prefix)
    ? "go"
    : domainDraft.prefix;

  return (
    <div className="app-shell">
      <aside className={`sidebar ${sidebarOpen ? "sidebar-open" : ""}`}>
        <div className="brand">
          <span className="brand-mark">
            <LinkSimple size={23} weight="duotone" />
          </span>
          <div>
            <strong>短链接工作台</strong>
            <small>本机管理</small>
          </div>
        </div>
        <div className="nav-caption">工作空间</div>
        <nav aria-label="主导航">
          {nav.map((item) => {
            const Icon = item.icon;
            return (
              <button
                key={item.key}
                className={`nav-item ${page === item.key ? "active" : ""}`}
                aria-current={page === item.key ? "page" : undefined}
                onClick={() => {
                  setPage(item.key);
                  setSidebarOpen(false);
                  setError("");
                  setMigrationAccountId(null);
                }}
              >
                <Icon
                  size={19}
                  weight={page === item.key ? "bold" : "regular"}
                />
                <span>{item.label}</span>
                {item.key === "links" && state.links.length > 0 && (
                  <small>{state.links.length}</small>
                )}
              </button>
            );
          })}
        </nav>
        <div className="sidebar-bottom">
          <div className="sidebar-rule" />
          <div className="workspace-badge">
            <span className="live-dot" />
            <div>
              <strong>{preview ? "本地预览" : "本机工作空间"}</strong>
              <small>
                {preview ? "示例数据 · 不连接云服务" : "配置保存在本机"}
                {state.appVersion ? ` · v${state.appVersion}` : ""}
              </small>
            </div>
          </div>
          <button
            className={`sidebar-update ${updates.available ? "has-update" : ""}`}
            onClick={openUpdate}
            disabled={busy || updates.checking}
          >
            {updates.available ? <WarningCircle size={18} weight="fill" aria-hidden="true" /> : <ArrowClockwise size={15} aria-hidden="true" />}
            <span>{updates.checking ? "正在检查更新…" : installedUpdate ? "更新已安装" : updates.available ? "发现新版本" : "检查更新"}</span>
            {updates.available && <small>查看更新</small>}
          </button>
          {updates.checking && !updateOpen && <button type="button" className="sidebar-update" onClick={() => void checkUpdate()}>查看检查进度 / 取消</button>}
        </div>
      </aside>
      <main className="main" ref={mainRef}>
        <div className="topbar">
          <div className="breadcrumbs">
            <button
              className="mobile-menu icon-button"
              aria-label="展开导航"
              onClick={() => setSidebarOpen(!sidebarOpen)}
            >
              <SidebarSimple size={19} />
            </button>
            <span>工作空间</span>
            <span className="slash">/</span>
            <strong>{nav.find((n) => n.key === page)?.label}</strong>
          </div>
          <div className="topbar-actions">
            {preview && (
              <span className="preview-chip">本地预览 · 示例数据</span>
            )}
            <button
              className="text-button"
              onClick={() => void load()}
              disabled={loading || busy}
            >
              <ArrowClockwise size={16} />
              刷新数据
            </button>
          </div>
        </div>
        <div className="content">
          {redirectMonitor.enabled && monitorBannerText(redirectMonitor.summary) && <section className="update-banner redirect-monitor-banner" aria-label="自动巡检提醒" role="status"><WarningCircle size={22} weight="fill" aria-hidden="true"/><div><strong>{monitorBannerText(redirectMonitor.summary)}</strong><p>打开短链接列表查看每条链接的首跳结果。</p></div><button type="button" className="button secondary" onClick={() => {setPage('links');setAttentionOnly(true);setSearch('');setFilter('all');setAttentionViewRequest(value => value + 1);}}>查看需关注</button></section>}
          {updates.available && dismissedUpdate !== updates.available.version && (
            <section className="update-banner" aria-label="新版本提醒">
              <WarningCircle size={22} weight="fill" aria-hidden="true" />
              <div role="status"><strong>新版本 {updates.available.version} 已可用</strong><p>查看更新内容，选择方便的时候安装。</p></div>
              <button className="button primary" onClick={openUpdate} disabled={busy}>查看更新</button>
              <button className="icon-button" aria-label="暂时收起更新提醒" onClick={() => setDismissedUpdate(updates.available?.version || null)}><X size={18} /></button>
            </section>
          )}
          {installedUpdate && (
            <section className="update-banner installed" aria-label="更新已安装" role="status">
              <CheckCircle size={22} weight="fill" aria-hidden="true" />
              <div><strong>更新 {installedUpdate.version} 已安装</strong><p>退出并重新打开软件，即可使用新版本。</p></div>
            </section>
          )}
          <section className="hero">
            <div>
              <h1>{title}</h1>
              <p className="hero-subtitle">{subtitle}</p>
            </div>
            <div className="hero-action">
              {page === "links" && (
                <button
                  className="button primary"
                  onClick={() => openLink()}
                  disabled={!state.domains.length}
                >
                  <Plus size={18} weight="bold" />
                  新建链接
                </button>
              )}
              {page === "domains" && (
                <button
                  className="button primary"
                  onClick={() => {
                    invalidateDomainPreparation();
                    setDomainDraft({
                      dnsMode: "system",
                      input: "",
                      prefix: ["go", "out", "to", "visit", "link", "r", "jump"][
                        crypto.getRandomValues(new Uint32Array(1))[0] % 7
                      ],
                      accountId:
                        state.accounts.length === 1 ? state.accounts[0].id : "",
                    });
                    setDomainOpen(true);
                  }}
                  disabled={!state.accounts.length}
                >
                  <Plus size={18} weight="bold" />
                  添加域名
                </button>
              )}
              {page === "accounts" && (
                <button
                  className="button primary"
                  onClick={() => {
                    setUpdateTokenAccount(null);
                    setToken("");
                    setReplaceToken(false);
                    setClipboardOffer("");
                    setTokenOpen(true);
                    void openTemplate();
                  }}
                >
                  <Plus size={18} weight="bold" />
                  导入账户
                </button>
              )}
            </div>
          </section>
          {error && (
            <div role="alert" className="alert error">
              <WarningCircle size={19} />
              <span>{error}</span>
              {!linkDraft && !domainOpen && !manageAccount && !monitorAccount && !plan && migrationAction()}
              <button aria-label="关闭错误" onClick={() => setError("")}>
                <X size={16} />
              </button>
            </div>
          )}
          {notice && (
            <div role="status" className="alert success">
              <CheckCircle size={19} />
              <span>{notice}</span>
              {notice.startsWith("域名已接入。") && state.domains.some((domain) => domain.id === domainSuccessId) && (
                <button
                  className="button secondary"
                  disabled={busy}
                  onClick={() => {
                    setPage("links");
                    setFilter(domainSuccessId);
                    openLink(undefined, false, domainSuccessId);
                    setNotice("");
                  }}
                >
                  为新域名创建短链接
                </button>
              )}
              <button aria-label="关闭通知" onClick={() => setNotice("")}>
                <X size={16} />
              </button>
            </div>
          )}
          {testingLink && (
            <div role="status" className="alert testing">
              <ShieldCheck size={19} />
              <span>
                正在检测 {testingLink} 的跳转结果。检测期间仍可继续使用应用。
                {testingAutomaticDns && " 检测到 VPN 虚拟地址，正在自动使用公共 DNS 重查一次。"}
              </span>
              <button onClick={closeDetection}>取消等待</button>
            </div>
          )}
          {clipboardToClear && (
            <div className="alert success">
              <span>令牌已导入。你可以清空剪贴板里的令牌。</span>
              <button onClick={() => void clearImportedClipboard()}>
                清空剪贴板
              </button>
              <button onClick={() => setClipboardToClear("")}>保留</button>
            </div>
          )}
          {!loading &&
            !loadFailed &&
            (state.pendingActions?.length || 0) > 0 && (
              <section className="pending-actions" aria-label="可继续的变更">
                <strong>
                  有 {state.pendingActions.length} 项变更可继续处理
                </strong>
                <p>打开计划复核当前状态，再确认后续步骤。应用不会在后台自动重试。</p>
                {state.pendingActions.some((action) => isSelftestRecovery(action.kind)) && (
                  <p>检测密钥用于检查短链接，不是 Cloudflare API 令牌；待处理记录不代表账户连接失效，无需因此删除令牌。</p>
                )}
                {state.pendingActions.map((action, index) => (
                  <div
                    className="pending-action"
                    key={`${action.kind}:${action.poolId || action.accountId || index}`}
                  >
                    <div>
                      {action.accountId && (
                        <strong>账户：{state.accounts.find((account) => account.id === action.accountId)?.label || state.accounts.find((account) => account.id === action.accountId)?.cloudflareName || action.accountId}</strong>
                      )}
                      <div><span>{action.kind === "recover_selftest_resources" ? "找回本机检测配置" : action.label}</span></div>
                      {action.kind === "recover_selftest_resources" && (
                        <p>先只读核对云端，找回本机检测配置，已有密钥和待处理记录会保留。完成后，请另行确认恢复检测密钥。</p>
                      )}
                      {action.kind === "resume_worker_upgrade" && (
                        <p>先核对云端升级结果，再完成本机记录。若云端被其他程序修改，可解除本机升级记录后处理；解除不会改动云端或密钥。</p>
                      )}
                    </div>
                    <button
                      className="button secondary"
                      disabled={
                        busy ||
                        ((action.kind === "resume_pool_sync" ||
                          action.kind === "delete_pool") &&
                          !action.poolId) ||
                        ((action.kind === "resume_monitor" || action.kind === "resume_worker_upgrade" || isSelftestRecovery(action.kind)) &&
                          !state.accounts.some((account) => account.id === action.accountId))
                      }
                      onClick={() => void resumePending(action)}
                    >
                      {action.kind === "resume_pool_sync"
                        ? "继续同步"
                        : action.kind === "resume_worker_upgrade"
                          ? "继续核对升级"
                        : action.kind === "resume_monitor"
                          ? "继续处理监测"
                          : action.kind === "resume_selftest_rotation"
                            ? "继续修复"
                            : action.kind === "recover_selftest_rotation"
                              ? "查看修复计划"
                            : action.kind === "recover_selftest_resources"
                              ? "找回本机检测配置"
                          : "继续删除"}
                    </button>
                    {action.kind === "resume_worker_upgrade" && action.accountId && (
                      <button className="button secondary" disabled={busy}
                        onClick={() => void prepare("dismiss_worker_upgrade", { accountId: action.accountId })}>
                        解除本机升级记录
                      </button>
                    )}
                  </div>
                ))}
              </section>
            )}
          {state.pendingOperations.length > 0 && (
            <details className="operation-log">
              <summary>
                查看待处理记录（{state.pendingOperations.length} 条）
              </summary>
              <p>{state.pendingActions?.length ? "以下为历史操作详情，请按上方对应账户的入口核对后续步骤。" : "以下记录尚未确认完成，请先核对对应账户和云端状态，避免重复提交。"}</p>
              <ul>
                {state.pendingOperations.map((entry, i) => (
                  <li key={i}>{entry}</li>
                ))}
              </ul>
            </details>
          )}
          {loading ? (
            <div className="page-loading">正在读取本机配置…</div>
          ) : loadFailed ? (
            <section className="panel">
              <Empty
                icon={<WarningCircle size={28} />}
                title="无法读取本机配置"
                description="请确认桌面应用运行正常，然后重试。"
                action={
                  <button
                    className="button secondary"
                    onClick={() => void load()}
                  >
                    重新读取
                  </button>
                }
              />
            </section>
          ) : page === "stats" ? (
            <StatsCenter
              accounts={state.accounts}
              domains={state.domains}
              links={state.links}
              revision={statsRevision}
              busy={busy}
              configurationError={statsConfigurationError}
              onConfigure={(account, enabled) => void configureClickStats(account.id, enabled)}
              onScopeInvalidate={() => {
                statsPrepareSequence.current++;
              }}
              onOpenLinkStats={(link, domain) => {
                statsPrepareSequence.current++;
                setStatsTarget({link, domain});
              }}
            />
          ) : page === "links" ? (
            <>
              <RedirectMonitor ready={redirectMonitor.ready} nextCheckAt={redirectMonitor.nextCheckAt} runKind={redirectMonitor.runKind} pendingChanges={redirectMonitor.pendingChanges} totalLinks={redirectMonitor.totalLinks} summary={redirectMonitor.summary} resultStatus={redirectMonitor.resultStatus} enabled={redirectMonitor.enabled} active={redirectMonitor.active} online={redirectMonitor.online} progress={redirectMonitor.progress} lastCompletion={redirectMonitor.lastCompletion} onEnabled={(value) => {if (!value) setAttentionOnly(false);redirectMonitor.setEnabled(value);}} onRun={redirectMonitor.runNow} disabled={busy || loading || updates.checking || !!updateStatus}/>
              <div className="metric-row">
                <div className="metric">
                  <span>全部链接</span>
                  <strong>{state.links.length}</strong>
                  <small>跨 {state.domains.length} 个域名</small>
                </div>
                <div className="metric">
                  <span>已连接域名</span>
                  <strong>{state.domains.length}</strong>
                  <small>可用于创建短路径</small>
                </div>
                <div className="metric">
                  <span>可用账户</span>
                  <strong>{state.accounts.filter((account) => !account.needsTokenRecovery && !account.needsCredentialMigration).length}</strong>
                  <small>按账户管理区域</small>
                </div>
              </div>
              <section className="panel">
                <div className="panel-head">
                  <div>
                    <p className="eyebrow">DESTINATIONS</p>
                    <h2 ref={linkListHeadingRef} tabIndex={-1} className="link-list-heading">
                      {attentionOnly ? "需关注链接" : "全部链接"}{" "}
                      <span className="heading-count">
                        {attentionOnly ? groups.reduce((count, group) => count + group.links.length, 0) : state.links.length}
                      </span>
                    </h2>
                  </div>
                  <div className="panel-tools">
                    <button type="button" className={`button secondary ${attentionOnly ? 'redirect-monitor-filter-active' : ''}`} aria-pressed={attentionOnly} disabled={!redirectMonitor.enabled} onClick={() => {setAttentionOnly(!attentionOnly);setSearch('');setFilter('all');}}>只看需关注</button>
                    <label className="searchbox">
                      <MagnifyingGlass size={17} />
                      <input
                        aria-label="搜索链接"
                        value={search}
                        onChange={(e) => setSearch(e.target.value)}
                        placeholder="搜索短链接、平台或邀请码"
                      />
                    </label>
                    <label className="select-wrap">
                      <select
                        aria-label="筛选域名"
                        value={filter}
                        onChange={(e) => setFilter(e.target.value)}
                      >
                        <option value="all">全部域名</option>
                        {state.domains.map((d) => (
                          <option key={d.id} value={d.id}>
                            {d.host}
                          </option>
                        ))}
                      </select>
                      <CaretDown size={14} />
                    </label>
                  </div>
                </div>
                {!state.domains.length ? (
                  <Empty
                    icon={<Globe size={28} />}
                    title="先连接一个域名"
                    description="创建短链接前，需要导入账户并添加可用域名。"
                    action={
                      <button
                        className="button secondary"
                        onClick={() =>
                          setPage(
                            state.accounts.length ? "domains" : "accounts",
                          )
                        }
                      >
                        {state.accounts.length ? "前往域名" : "前往账户"}
                      </button>
                    }
                  />
                ) : !groups.length ? (
                  <Empty
                    icon={<LinkSimple size={28} />}
                    title={attentionOnly ? "目前没有需关注的链接" : search ? "没有匹配的链接" : "还没有短链接"}
                    description={
                      attentionOnly ? "可切回全部链接查看。" : search
                        ? "换个关键词或域名试试。"
                        : "为已连接域名创建第一条短链接。"
                    }
                    action={
                      !search && !attentionOnly && (
                        <button
                          className="button secondary"
                          onClick={() => openLink()}
                        >
                          <Plus size={17} />
                          新建链接
                        </button>
                      )
                    }
                  />
                ) : (
                  <LinkGroups
                    groups={groups}
                    busy={busy}
                    pools={state.pools || []}
                    getDetection={(link) => {
                      const record = detections[detectionKey(link)];
                      return {
                        ...detectionLabel(link),
                        ...(record ? {
                          detail: `上次检测 ${formatDate(record.checkedAt)} · ${targetSourceLabel(record.targets.dnsMode)}`,
                        } : {}),
                      };
                    }}
                    getAutoDetection={redirectMonitor.enabled ? redirectMonitor.getRecord : undefined}
                    onCopy={(url) => void copy(url)}
                    onCheck={(link, domain) => void selftest(link, domain)}
                    onStats={(link, domain) => {
                      statsPrepareSequence.current++;
                      setStatsConfigurationError(null);
                      setStatsTarget({link, domain});
                    }}
                    onEdit={openLink}
                    onDelete={(link, domain) => void prepare("delete_link", {
                      domainId: domain.id,
                      slug: link.slug,
                    })}
                    onCreate={(domainId) => openLink(undefined, false, domainId)}
                  />
                )}
              </section>
              <p className="page-footnote">
                短链接跳转与目标网站分开检测。
                {preview
                  ? "预览模式不发起目标检测。"
                  : "目标网站检测从本机网络发起；VPN、TUN 和网络策略仍会影响结果，未配置大陆监测时不能代表中国大陆网络。"}
              </p>
            </>
          ) : page === "pools" ? (
            <Pools
              pools={state.pools || []}
              accounts={state.accounts}
              linkCount={(id) => linkCountByPool.get(id) || 0}
              onSave={savePool}
              onDelete={(id) => void prepare("delete_pool", { poolId: id })}
              busy={busy}
              health={visiblePoolHealth}
              onCheckHealth={(id) => void inspectPool(id)}
              planOpen={Boolean(plan && (planKind === "save_pool" || planKind === "migrate_credentials"))}
              errorAction={migrationAction()}
              dismissDisabled={mutation === "prepare_credentials"}
              savedRevision={poolSavedRevision}
              serverError={poolError}
              onDraftChange={() => setPoolError("")}
            />
          ) : page === "domains" ? (
            <>
              <div className="metric-row two">
                <div className="metric">
                  <span>已连接域名</span>
                  <strong>{state.domains.length}</strong>
                  <small>按精确主机名区分</small>
                </div>
                <div className="metric">
                  <span>短链接总数</span>
                  <strong>{state.links.length}</strong>
                  <small>分布在所有域名下</small>
                </div>
              </div>
              <section className="panel">
                <div className="panel-head">
                  <div>
                    <p className="eyebrow">YOUR DOMAINS</p>
                    <h2>已添加的域名 <span className="heading-count">{state.domains.length}</span></h2>
                  </div>
                  <label className="searchbox resource-search"><MagnifyingGlass size={17} aria-hidden="true" /><input aria-label="搜索域名" placeholder="搜索域名或账户备注" value={domainSearch} onChange={(event) => setDomainSearch(event.target.value)} /></label>
                </div>
                {!state.accounts.length ? (
                  <Empty
                    icon={<Key size={28} />}
                    title="先导入账户"
                    description="连接账户后，才能验证并添加该账户下的域名。"
                    action={
                      <button
                        className="button secondary"
                        onClick={() => setPage("accounts")}
                      >
                        前往账户
                      </button>
                    }
                  />
                ) : !state.domains.length ? (
                  <Empty
                    icon={<Globe size={28} />}
                    title="还没有域名"
                    description="添加域名时会先检查区域、代理和路径冲突。"
                    action={
                      <button
                        className="button secondary"
                        onClick={() => {
                          invalidateDomainPreparation();
                          setDomainDraft({
                            dnsMode: "system",
                            input: "",
                            prefix: "r",
                            accountId:
                              state.accounts.length === 1
                                ? state.accounts[0].id
                                : "",
                          });
                          setDomainOpen(true);
                        }}
                      >
                        添加域名
                      </button>
                    }
                  />
                ) : (
                  <div className="domain-cards">
                    {!matchingDomains.length && <Empty icon={<MagnifyingGlass size={26} />} title="没有匹配的域名" description="可按域名或账户备注搜索。" action={<button className="button secondary" onClick={() => setDomainSearch("")}>清除搜索</button>} />}
                    {matchingDomains.map((domain) => (
                      <article className="domain-card" key={domain.id} aria-label={`${domain.host} 域名`}>
                        <div className="domain-symbol">
                          <Globe size={22} />
                        </div>
                        <div className="domain-card-main">
                          <h3>{domain.host}</h3>
                          <div className="domain-facts">
                            <span>链接目录 <strong>/{domain.prefix}/</strong></span>
                            <span>已创建 <strong>{(linksByDomain.get(domain.id)?.length || 0)}</strong> 条链接</span>
                            <span>所属账户 <strong>{accountById.get(domain.accountId)?.label || "未知账户"}</strong></span>
                          </div>
                        </div>
                        <div className="card-actions">
                          <button
                            className="button secondary"
                            onClick={() => {
                              setPage("links");
                              setFilter(domain.id);
                              openLink(undefined, false, domain.id);
                            }}
                          >
                            {Boolean(linksByDomain.get(domain.id)?.length)
                              ? "创建短链接"
                              : "创建第一条短链接"}
                          </button>
                          <button
                            className="button ghost"
                            onClick={() => {
                              setPage("links");
                              setFilter(domain.id);
                            }}
                          >
                            查看链接 <ArrowSquareOut size={16} />
                          </button>
                          <button
                            className="button ghost danger-hover"
                            title="移除域名"
                            aria-label={`移除 ${domain.host}`}
                            onClick={() =>
                              void prepare("remove_domain", {
                                domainId: domain.id,
                              })
                            }
                          >
                            <Trash size={16} />
                            移除域名
                          </button>
                        </div>
                      </article>
                    ))}
                  </div>
                )}
              </section>
              <div className="help-card">
                <ShieldCheck size={21} />
                <p>
                  先检查域名和现有配置。目录已有网页时会请你确认；遇到配置冲突或网络问题时，会说明原因。
                </p>
              </div>
            </>
          ) : (
            <>
              <div className="metric-row two">
                <div className="metric">
                  <span>账户数量</span>
                  <strong>{state.accounts.length}</strong>
                  <small>访问凭据留在系统钥匙串</small>
                </div>
                <div className="metric">
                  <span>关联域名</span>
                  <strong>{state.domains.length}</strong>
                  <small>跨所有已连接账户</small>
                </div>
              </div>
              <section className="panel">
                <div className="panel-head">
                  <div>
                    <p className="eyebrow">CONNECTED ACCOUNTS</p>
                    <h2>账户列表 <span className="heading-count">{state.accounts.length}</span></h2>
                  </div>
                  <div className="panel-tools resource-tools"><label className="searchbox resource-search"><MagnifyingGlass size={17} aria-hidden="true" /><input aria-label="搜索账户" placeholder="搜索备注、Cloudflare 名称或 ID" value={accountSearch} onChange={(event) => setAccountSearch(event.target.value)} /></label>
                  <button
                    className="button ghost"
                    onClick={() => void refreshAccounts()}
                    disabled={busy}
                  >
                    <ArrowClockwise size={16} />
                    更新状态
                  </button></div>
                </div>
                {!state.accounts.length ? (
                  <Empty
                    icon={<Key size={28} />}
                    title="还没有连接账户"
                    description="导入具有最小权限的访问令牌，开始管理短链接。"
                    action={
                      <button
                        className="button secondary"
                        onClick={() => {
                          setUpdateTokenAccount(null);
                          setToken("");
                          setReplaceToken(false);
                          setClipboardOffer("");
                          setTokenOpen(true);
                        }}
                      >
                        导入账户
                      </button>
                    }
                  />
                ) : (
                  <div className="account-cards">
                    {!matchingAccounts.length && <Empty icon={<MagnifyingGlass size={26} />} title="没有匹配的账户" description="可按本机备注、Cloudflare 名称或账户 ID 搜索。" action={<button className="button secondary" onClick={() => setAccountSearch("")}>清除搜索</button>} />}
                    {matchingAccounts.map((account) => (
                      <article className="account-card" key={account.id} aria-label={`${account.label} 账户`}>
                        <div className="account-symbol">
                          <Key size={22} />
                        </div>
                        <div className="account-main">
                          <div className="account-card-head">
                            <div className="account-title">
                              <h3>{account.label}</h3>
                              {account.needsTokenRecovery && <StatusPill tone="amber">令牌待恢复</StatusPill>}
                              {!account.needsTokenRecovery && account.needsCredentialMigration && (
                                <StatusPill tone="amber">需要更新本机授权</StatusPill>
                              )}
                              {account.needsSelftestKey ? (
                                <StatusPill tone="amber">检测密钥待恢复</StatusPill>
                              ) : (
                                !account.needsCredentialMigration && !account.needsTokenRecovery && <StatusPill>已连接</StatusPill>
                              )}
                            </div>
                            <div className="account-card-actions">
                              {migrationAction(account.id)}
                              <button
                                className="button secondary"
                                disabled={mutation === "prepare_credentials"}
                                aria-label={`管理 ${account.label}`}
                                onClick={() => { protectionReadSequence.current += 1; setProtectionRead(null); setManageAccount(account); }}
                              >
                                管理账户
                              </button>
                            </div>
                          </div>
                          <dl className="account-facts">
                            {account.cloudflareName && <div><dt>Cloudflare 名称</dt><dd>{account.cloudflareName}</dd></div>}
                            <div><dt>账户 ID</dt><dd>…{account.id.slice(-8)}</dd></div>
                            <div><dt>Cloudflare 内</dt><dd>{account.zoneCount} 个站点</dd></div>
                            <div><dt>接入域名</dt><dd>{(domainCountByAccount.get(account.id) || 0)} 个域名</dd></div>
                            <div><dt>上次检查</dt><dd>{formatDate(account.checkedAt)}</dd></div>
                          </dl>
                          <div className="account-service">
                            <span className="monitor-status">
                              检测服务：{account.monitorEnabled
                                ? `已启用 · ${account.monitorEndpoint || "地址未提供"}`
                                : "未启用"}
                            </span>
                            {account.needsMonitorKey && (
                              <strong>
                                本机密钥缺失；云端监测可能仍在运行，请先停用再重新配置
                              </strong>
                            )}
                          </div>
                        </div>
                      </article>
                    ))}
                  </div>
                )}
              </section>
              <section className="panel backup-panel">
                <div>
                  <p className="eyebrow">LOCAL BACKUP</p>
                  <h2>配置备份</h2>
                  <p>
                    导出域名和目标地址，不包含访问令牌或检测密钥。备份中含您的链接信息，请妥善保存。
                  </p>
                </div>
                <div className="backup-actions">
                  <button
                    className="button secondary"
                    onClick={() => void exportBackup()}
                    disabled={busy}
                  >
                    <CloudArrowDown size={18} />
                    导出配置
                  </button>
                  <button
                    className="button ghost bordered"
                    onClick={() => void importBackup()}
                    disabled={busy}
                  >
                    <CloudArrowUp size={18} />
                    导入配置
                  </button>
                </div>
              </section>
            </>
          )}
        </div>
      </main>

      {linkDraft && !plan && (
        <Dialog
          title={originalSlug ? "编辑短链接" : copySource ? "使用新名称创建链接" : "创建短链接"}
          eyebrow="LINK DETAILS"
          error={error}
          errorAction={migrationAction()}
          status={notice === "本机授权已更新，请重试刚才的操作" ? <div role="status">{notice}</div> : undefined}
          dismissDisabled={mutation === "prepare_credentials"}
          onClose={closeLink}
          footer={
            <>
              <button
                className="button ghost"
                onClick={closeLink}
                disabled={mutation === "prepare_credentials"}
              >
                取消
              </button>
              <button
                type="submit"
                form="link-form"
                className="button primary"
                disabled={busy}
              >
                {busy ? "正在准备…" : "下一步，核对内容"}
              </button>
            </>
          }
        >
          <LinkEditor linkDraft={linkDraft} originalSlug={originalSlug} copySource={copySource}
            domains={state.domains} pools={state.pools || []} busy={busy} formErrors={formErrors}
            slugInput={slugInput} saveLink={saveLink} updateLinkDraft={updateLinkDraft} useNewLinkName={useNewLinkName} />
        </Dialog>
      )}
      {domainOpen && !plan && (
        <Dialog
          title="添加域名"
          eyebrow="DOMAIN SETUP"
          error={domainErrorMessage(error)}
          errorAction={domainMigrationAccount ? undefined : migrationAction() || (isDomainCredentialError(error) ? domainRecoveryActions() : undefined)}
          dismissDisabled={mutation === "prepare_credentials"}
          status={
            domainFeedback ? (
              <div
                role={domainFeedback.tone === "error" ? "alert" : "status"}
                className={`domain-feedback ${domainFeedback.tone}`}
              >
                <span>{domainFeedback.message}</span>
                {domainFeedback.tone === "error" && isDomainCredentialError(domainFeedback.message) && domainRecoveryActions()}
              </div>
            ) : domainPreparationExpired ? (
              <div role="status" className="domain-feedback error">
                <span>{expiredDomainPlanMessage}</span>
              </div>
            ) : domainBusy ? (
              <div role="status" className="domain-feedback progress">
                <span>
                  上一项检查仍在进行，请稍候。
                </span>
              </div>
            ) : undefined
          }
          onClose={closeDomain}
          wide
          footer={
            <>
              <button className="button ghost" onClick={closeDomain} disabled={mutation === "prepare_credentials"}>
                取消
              </button>
              {preflight?.canApply && isCurrentPlan(preflight.plan) ? (
                <button
                  className="button primary"
                  disabled={busy || domainBusy}
                  onClick={() => openDomainPlan(preflight)}
                >
                  查看接入计划
                </button>
              ) : (
                <button
                  form="domain-form"
                  type="submit"
                  className="button primary"
                  disabled={busy || domainBusy}
                >
                  {domainBusy
                    ? "检查中…"
                    : preflight || dnsPreflight || domainFeedback?.message === expiredDomainPlanMessage
                      ? "重新检查当前状态"
                      : "检查并继续"}
                </button>
              )}
            </>
          }
        >
          <form
            noValidate
            id="domain-form"
            onSubmit={(e) => void checkDomain(e)}
            className="form-grid"
          >
            <div className="form-section-heading">
              <strong>选择域名与链接目录</strong>
              <span>检查当前配置后，再核对接入计划。</span>
            </div>
            <label>
              Cloudflare 账户
              <select
                aria-label="Cloudflare 账户"
                value={domainDraft.accountId}
                onChange={(e) => {
                  setDomainDraft({ ...domainDraft, accountId: e.target.value });
                  invalidateDomainPreparation();
                }}
              >
                <option value="">
                  {state.accounts.length > 1
                    ? "自动匹配已保存的域名"
                    : "由检查结果选择"}
                </option>
                {state.accounts.map((account) => (
                  <option key={account.id} value={account.id}>
                    {account.cloudflareName || account.label}（备注：
                    {account.label}）
                  </option>
                ))}
              </select>
              <small>
                {state.accounts.length > 1 && !domainDraft.accountId
                  ? "可输入域名自动匹配账户；刷新域名列表时需先明确选择账户。"
                  : "更换账户后需重新检查当前配置。"}
              </small>
            </label>
            <div className="form-two">
              <label>
                域名
                <input
                  {...fieldProps("domain-host", formErrors)}
                list="cloudflare-zones"
                  value={domainDraft.input}
                  onChange={(e) => {
                    const input = e.target.value;
                    const matches = state.accounts.flatMap((account) =>
                      (account.zones || [])
                        .filter(
                          (zone) =>
                            zone.status === "active" && zone.name === input,
                        )
                        .map(() => account),
                    );
                    setDomainDraft({
                      ...domainDraft,
                      input,
                      accountId:
                        domainDraft.accountId ||
                        (matches.length === 1 ? matches[0].id : ""),
                    });
                    invalidateDomainPreparation();
                  }}
                  placeholder="go.example.com"
                  required
                />
                <FieldError name="domain-host" errors={formErrors} />
                <datalist id="cloudflare-zones">
                  {state.accounts
                    .filter(
                      (account) =>
                        !domainDraft.accountId ||
                        account.id === domainDraft.accountId,
                    )
                    .flatMap((account) =>
                      (account.zones || [])
                        .filter((zone) => zone.status === "active")
                        .map((zone) => (
                          <option
                            key={`${account.id}:${zone.id}`}
                            value={zone.name}
                          >
                            {account.cloudflareName || account.label}
                          </option>
                        )),
                    )}
                </datalist>
                <small>
                  可搜索并选择已连接账户中的已启用域名，也可手动输入子域名或完整网址。
                </small>
              </label>
              <label>
                链接目录
                <input
                  {...fieldProps("domain-prefix", formErrors)}
                value={domainDraft.prefix}
                  onChange={(e) => {
                    setDomainDraft({ ...domainDraft, prefix: e.target.value });
                    invalidateDomainPreparation();
                  }}
                  maxLength={12}
                  required
                />
                <FieldError name="domain-prefix" errors={formErrors} />
                <small>
                  示例链接：https://{domainExampleHost}/{domainExamplePrefix}
                  /名称
                </small>
              </label>
            </div>
            {duplicateDomainId && state.domains.some((domain) => domain.id === duplicateDomainId) && (
              <div className="domain-duplicate-actions">
                <button
                  type="button"
                  className="button secondary"
                  onClick={() => {
                    closeDomain();
                    setPage("domains");
                  }}
                >
                  查看已有域名
                </button>
                <button
                  type="button"
                  className="button primary"
                  onClick={() => {
                    closeDomain();
                    setPage("links");
                    setFilter(duplicateDomainId);
                    openLink(undefined, false, duplicateDomainId);
                  }}
                >
                  为已有域名创建短链接
                </button>
              </div>
            )}
            {domainMigrationAccount && (
              <div className="warning-box">
                <p>「{domainMigrationAccount.label}」需要更新本机授权后才能读取域名。当前输入会保留。</p>
                {migrationAction(domainMigrationAccount.id)}
              </div>
            )}
            <div className="domain-list-refresh">
              <button
                type="button"
                className="button secondary"
                onClick={() => void refreshDomainAccountList()}
                disabled={busy || domainBusy}
              >
                {domainBusy ? "正在读取…" : "刷新域名列表"}
              </button>
              <small>
                刷新只读取所选账户。新买的域名仍未出现时，请确认令牌有该域名权限且域名已在
                Cloudflare 启用。
              </small>
            </div>
            <div className="domain-setup-notes">
              <p>带 www 和不带 www 的域名需要分别添加；未启用域名不会出现在可选列表中。</p>
              <p>先按本机网络检查；若 VPN 返回虚拟地址，会自动用公共 DNS 重查一次。</p>
            </div>
            <details className="domain-network-options">
              <summary>网络检查选项</summary>
              <label className="domain-network-checkbox">
                <input type="checkbox" checked={domainDraft.dnsMode === "public"} disabled={domainBusy}
                  onChange={(event) => {
                    setDomainDraft({...domainDraft, dnsMode: event.target.checked ? "public" : "system"});
                    invalidateDomainPreparation();
                  }} />
                直接使用公共 DNS（手动兼容 VPN）
              </label>
              <small>公共查询只向 Cloudflare 发送域名，不发送账户令牌，也不会更改本机 DNS 或 VPN 设置。</small>
            </details>
            {domainAutomaticDns && <p role="status" className="inline-warning">本次已自动切换为公共 DNS；接入计划会用同一方式复核，仍需确认后才会接入。</p>}
            {preflight && (
              <div className="preflight">
                {(() => {
                  const outcome = domainOutcome(preflight);
                  return (
                    <div
                      className={`preflight-outcome outcome-${outcome.level}`}
                    >
                      <span>{outcome.label}</span>
                      <strong>
                        {preflight.host}/{preflight.prefix}/
                      </strong>
                    </div>
                  );
                })()}
                <div className="check-list">
                  {preflight.checks.map((check, i) => {
                    const level = domainCheckLevel(check);
                    return (
                      <div className={`check-row check-${level}`} key={i}>
                        {level === "pass" ? (
                          <CheckCircle size={18} className="check-good" />
                        ) : (
                          <WarningCircle
                            size={18}
                            className={
                              level === "warning" ? "check-warn" : "check-bad"
                            }
                          />
                        )}
                        <div>
                          <strong>{check.label}</strong>
                          <p>{check.message}</p>
                        </div>
                      </div>
                    );
                  })}
                </div>
                {hasOnlyNetworkBlocker(preflight) && (
                  <p className="inline-warning">
                    {preflight.dnsMode === "public"
                      ? "公共 DNS 仍未完成网络验证。请检查 VPN 或网络连接后重新检查；域名尚未接入。"
                      : "本机网络未完成验证。请检查网络或 VPN 后重新检查；域名尚未接入。"}
                  </p>
                )}
                {preflight.candidates.length > 1 && (
                  <label>
                    选择账户与区域
                    <select
                      value={domainDraft.accountId}
                      onChange={(e) => {
                        setDomainDraft({
                          ...domainDraft,
                          accountId: e.target.value,
                        });
                        invalidateDomainPreparation();
                      }}
                    >
                      <option value="">请选择</option>
                      {preflight.candidates.map((c) => (
                        <option
                          key={`${c.accountId}-${c.zoneId}`}
                          value={c.accountId}
                        >
                          {c.label} · {c.status}
                        </option>
                      ))}
                    </select>
                    <small>选择后需重新检查该账户下的域名。</small>
                  </label>
                )}
                {!preflight.canApply &&
                  !preflight.checks.some(
                    (check) => domainCheckLevel(check) === "error",
                  ) &&
                  (preflight.candidates.length > 1 && !domainDraft.accountId ? (
                    <p className="inline-warning">请选择账户，然后重新检查。</p>
                  ) : preflight.candidates.length === 0 ? (
                    <p className="inline-warning">
                      未在已读取的账户中找到此域名。请确认该域名权限或是否已在
                      Cloudflare 启用，然后刷新所选账户。
                    </p>
                  ) : null)}
              </div>
            )}
            {dnsPreflight && (
              <div className="preflight dns-preflight">
                <div
                  className={`preflight-outcome outcome-${dnsPreflight.dnsStatus === "ready" ? "pass" : dnsPreflight.canApply ? "warning" : "error"}`}
                >
                  <span>
                    {dnsPreflight.dnsStatus === "ready"
                      ? "网站解析已就绪"
                      : dnsPreflight.dnsStatus === "missing"
                        ? "需要补齐网站解析"
                        : dnsPreflight.dnsStatus === "dnsOnly"
                          ? "需要开启 Cloudflare 代理"
                          : "无法自动修复"}
                  </span>
                  <strong>{dnsPreflight.host}</strong>
                </div>
                <div className="check-list">
                  {dnsPreflight.checks.map((check, index) => (
                    <div
                      className={`check-row check-${domainCheckLevel(check)}`}
                      key={index}
                    >
                      {domainCheckLevel(check) === "pass" ? (
                        <CheckCircle size={18} className="check-good" />
                      ) : (
                        <WarningCircle
                          size={18}
                          className={
                            domainCheckLevel(check) === "warning"
                              ? "check-warn"
                              : "check-bad"
                          }
                        />
                      )}
                      <div>
                        <strong>{check.label}</strong>
                        <p>{check.message}</p>
                      </div>
                    </div>
                  ))}
                </div>
                {dnsPreflight.actions.length > 0 && (
                  <p className="form-note">
                    将要修改：
                    {dnsPreflight.actions
                      .map(
                        (action) =>
                          `${action.kind === "createPlaceholder" ? "创建代理" : "开启代理"} ${action.recordType} ${action.name}`,
                      )
                      .join("；")}
                    。先查看完整计划再确认。
                  </p>
                )}
              </div>
            )}
          </form>
        </Dialog>
      )}
      {statsTarget && !plan && (
        <ClickStatsDialog
          key={`${statsTarget.domain.id}:${statsTarget.link.slug}`}
          link={statsTarget.link}
          domain={statsTarget.domain}
          account={state.accounts.find((account) => account.id === statsTarget.domain.accountId)}
          onClose={closeStats}
          onConfigure={(enabled) => void configureClickStats(statsTarget.domain.accountId, enabled, statsTarget)}
          revision={statsRevision}
          busy={busy}
          configurationError={statsConfigurationError?.accountId === statsTarget.domain.accountId ? statsConfigurationError.message : undefined}
        />
      )}
      {plan && (
        <Dialog
          title={plan.title}
          eyebrow="REVIEW & CONFIRM"
          error={error}
          onClose={returnFromPlan}
          dismissDisabled={mutation === "apply"}
          footer={
            <>
              <button
                className="button ghost"
                onClick={returnFromPlan}
                disabled={mutation === "apply"}
              >
                返回
              </button>
              <button
                className="button primary"
                onClick={() => void apply()}
                disabled={busy || (isDomainPlan ? !isCurrentPlan(plan) : Date.parse(plan.expiresAt) < Date.now())}
              >
                {busy
                  ? "正在提交…"
                  : planKind === "migrate_credentials"
                    ? "确认更新本机授权"
                    : planKind === "fix_domain_dns"
                      ? "确认修改并继续检查"
                      : plan.domainTakeoverConfirmation
                        ? "确认使用此目录"
                        : "确认并执行"}
              </button>
            </>
          }
        >
          <div className="plan-summary">
            <div className="plan-details">
              {planDetails.map((detail, i) => (
                <div key={i}>{detail}</div>
              ))}
            </div>
            {plan.domainTakeoverConfirmation && (
              <div className="takeover-confirmation">
                <WarningCircle size={20} />
                <div>
                  <strong>请确认接管范围</strong>
                  <p>{plan.domainTakeoverConfirmation}</p>
                </div>
              </div>
            )}
            {planKind === "migrate_credentials" && (
              <div className="takeover-confirmation">
                <WarningCircle size={20} />
                <div>
                  <strong>请确认本机授权更新</strong>
                  <p>{plan.credentialMigrationConfirmation || "系统可能需要你授权访问已保存的令牌或检测密钥；已有记录会保留，云端配置不变。"}</p>
                  <p>完成后请手动重试刚才的操作；不会自动重新执行之前的修改。请在系统窗口中授权，不要在本应用中输入系统密码。</p>
                </div>
              </div>
            )}
            <p>{planKind === "migrate_credentials"
              ? "本次仅更新此账户在本机的凭据保存方式："
              : "应用将再次检查账户归属和当前状态，然后执行以下步骤："}</p>
            <ol>
              {plan.steps.map((step, i) => (
                <li key={i}>{step}</li>
              ))}
            </ol>
            {plan.warnings.length > 0 && (
              <div className="warning-box">
                <WarningCircle size={18} />
                <div>
                  {plan.warnings.map((warning, i) => (
                    <p key={i}>{warning}</p>
                  ))}
                </div>
              </div>
            )}
            {isDomainPlan && mutation === "apply" ? (
              <small>正在等待本次提交结果，请勿重复操作。</small>
            ) : isDomainPlan && !isCurrentPlan(plan) ? (
              <p role="status">计划已过期。请点击「返回」后重新检查当前状态；不会自动提交。</p>
            ) : (
              <small>
                请在 {formatDate(plan.expiresAt)} 前确认；超时后需重新核对。
              </small>
            )}
          </div>
        </Dialog>
      )}
      {tokenOpen && (
        <Dialog
          title={updateTokenAccount?.needsTokenRecovery ? "恢复账户令牌" : updateTokenAccount ? "更换本机令牌" : "导入访问令牌"}
          dismissDisabled={mutation === "token"}
          eyebrow="ACCOUNT ACCESS"
          error={error}
          onClose={closeToken}
          footer={
            <>
              <button
                className="button ghost"
                disabled={mutation === "token"}
                onClick={closeToken}
              >
                取消
              </button>
              <button
                className="button primary"
                form="token-form"
                type="submit"
                disabled={busy}
              >
                {busy
                  ? "正在验证…"
                  : updateTokenAccount
                    ? "验证并替换"
                    : "验证并导入"}
              </button>
            </>
          }
        >
          <form
            noValidate
            id="token-form"
            className="form-grid"
            onSubmit={(e) => void importToken(e)}
          >
            {updateTokenAccount ? (
              <div className="token-current-account">
                <strong>正在更新 {updateTokenAccount.label}</strong>
                {updateTokenAccount.cloudflareName && <p className="form-note">Cloudflare 名称：{updateTokenAccount.cloudflareName}</p>}
                <p className="form-note">
                  将只更新此账户（账户 ID：…{updateTokenAccount.id.slice(-8)}）的本机令牌，其他账户不变。令牌必须包含这个 Cloudflare 账户，否则不会保存。
                </p>
              </div>
            ) : (
              <div className="token-step">
                <span className="token-step-number">1</span>
                <div className="token-step-content">
                  <strong>在 Cloudflare 准备令牌</strong>
                  <p className="form-note">先在浏览器登录要连接的 Cloudflare 账户，再创建 API 令牌。</p>
                  <p className="form-note">模板已包含统计中心需要的“账户分析 → 读取”权限；访问统计仍由你选择是否启用。</p>
                  <button
                    className="button bordered opener"
                    type="button"
                    onClick={() => void openTemplate()}
                  >
                    <ArrowSquareOut size={17} />
                    在系统浏览器中打开令牌模板
                  </button>
                </div>
              </div>
            )}
            {updateTokenAccount?.needsTokenRecovery && <p className="form-note">上次保存未完成。请重新粘贴属于此账户的令牌并验证；恢复成功后再执行云端操作。</p>}
            {!updateTokenAccount && state.accounts.some((account) => account.needsTokenRecovery) && <div className="credential-recovery-note"><p>以下账户需要单独恢复令牌，请选择对应账户后继续：</p>{state.accounts.filter((account) => account.needsTokenRecovery).map((account) => <button type="button" className="button secondary" key={account.id} disabled={busy || domainBusy} onClick={() => openTokenRecovery(account)}>恢复 {account.label} 的令牌</button>)}</div>}
            {updateTokenAccount && !updateTokenAccount.needsTokenRecovery && (
              <div className="token-existing-help">
                <p className="form-note">
                  只是补充权限或加入新域名？可以直接编辑已有令牌，无需在这里重新粘贴。保存后关闭此窗口，重试刚才的操作。只有创建了新令牌或重新生成了令牌值，才需要在下方替换。
                </p>
                <button
                  className="button bordered opener"
                  type="button"
                  disabled={mutation === "token"}
                  onClick={() => void openTokenManagement()}
                >
                  <ArrowSquareOut size={17} />
                  修改已有令牌权限
                </button>
                <small>请在浏览器中登录原令牌所属的 Cloudflare 用户，找到正在使用的令牌，点右侧菜单中的“编辑”。</small>
                <details>
                  <summary>需要创建新令牌</summary>
                  <button
                    className="button bordered opener"
                    type="button"
                    disabled={mutation === "token"}
                    onClick={() => void openTemplate()}
                  >
                    <ArrowSquareOut size={17} />
                    打开新令牌模板
                  </button>
                </details>
              </div>
            )}
            <div className={updateTokenAccount ? "token-field" : "token-step"}>
              {!updateTokenAccount && <span className="token-step-number">2</span>}
              <div className="token-step-content">
                <strong>{updateTokenAccount ? "粘贴新令牌" : "粘贴并验证"}</strong>
                {!updateTokenAccount && <p className="form-note">软件会向 Cloudflare 验证令牌，并交给操作系统保存。</p>}
                <label>
                  访问令牌
                  <input
                    type="password"
                    autoComplete="off"
                    {...fieldProps("token-value", formErrors)}
                value={token}
                    disabled={mutation === "token"}
                    onChange={(e) => {
                      clearClipboardOffer();
                      setToken(e.target.value);
                      setFormErrors({});
                    }}
                    onFocus={() => void checkClipboard()}
                    placeholder="在此粘贴令牌"
                    required
                  />
                <FieldError name="token-value" errors={formErrors} />
                </label>
                {clipboardOffer && (
                  <div className="clipboard-offer">
                    <Clipboard size={18} />
                    <span>检测到可能的访问令牌，是否填入？</span>
                    <button
                      type="button"
                      disabled={mutation === "token"}
                      onClick={() => {
                        setToken(clipboardOffer);
                        clearClipboardOffer();
                      }}
                    >
                      填入
                    </button>
                    <button
                      type="button"
                      aria-label="忽略剪贴板"
                      onClick={clearClipboardOffer}
                    >
                      <X size={15} />
                    </button>
                  </div>
                )}
                {!updateTokenAccount && (
                  <label className="checkbox-row">
                    <input
                      type="checkbox"
                      checked={replaceToken}
                      onChange={(e) => setReplaceToken(e.target.checked)}
                      disabled={mutation === "token"}
                    />
                    <span>若账户已存在，确认替换本机保存的令牌</span>
                  </label>
                )}
              </div>
            </div>
          </form>
        </Dialog>
      )}
      {renameAccount && (
        <Dialog
          title="重命名账户"
          dismissDisabled={mutation === "rename"}
          error={error}
          onClose={() => setRenameAccount(null)}
          footer={
            <>
              <button
                className="button ghost"
                disabled={mutation === "rename"}
                onClick={() => setRenameAccount(null)}
              >
                取消
              </button>
              <button
                className="button primary"
                form="rename-form"
                type="submit"
                disabled={busy}
              >
                保存名称
              </button>
            </>
          }
        >
          <form
            noValidate
            id="rename-form"
            onSubmit={(e) => void doRename(e)}
            className="form-grid"
          >
            <label>
              账户名称
              <input
                {...fieldProps("account-name", formErrors)}
                value={renameValue}
                disabled={mutation === "rename"}
                onChange={(e) => { setRenameValue(e.target.value); setFormErrors({}); }}
                maxLength={60}
                required
              />
                <FieldError name="account-name" errors={formErrors} />
            </label>
            <p className="form-note">名称只用于本机识别，不修改远端账户。</p>
          </form>
        </Dialog>
      )}
      {removeAccount && (
        <Dialog
          title="从本机移除账户"
          dismissDisabled={mutation === "remove"}
          error={error}
          onClose={() => setRemoveAccount(null)}
          footer={
            <>
              <button
                className="button ghost"
                disabled={mutation === "remove"}
                onClick={() => setRemoveAccount(null)}
              >
                取消
              </button>
              <button
                className="button danger-button"
                onClick={() => void doRemove()}
                disabled={busy}
              >
                确认本机移除
              </button>
            </>
          }
        >
          <p className="modal-paragraph">
            将移除“{removeAccount.label}
            ”的本机配置及新版使用的凭据。更新本机授权时保留的旧版钥匙串条目不会自动删除。此操作不会删除云端短链接服务；如需删除，请先在账户管理中选择“删除云端短链接服务”。
          </p>
        </Dialog>
      )}
      {manageAccount && (
        <Dialog
          title="账户管理"
          dismissDisabled={mutation === "prepare_credentials"}
          eyebrow="CLOUDFLARE ACCOUNT"
          error={error}
          onClose={() => { if (mutationRef.current !== "prepare_credentials") setManageAccount(null); }}
          footer={
            <button
              className="button ghost"
              onClick={() => setManageAccount(null)}
              disabled={mutation === "prepare_credentials"}
            >
              完成
            </button>
          }
        >
          <div className="account-manager">
            <div className="account-identity">
              <strong>
                {manageAccount.label}
              </strong>
              {manageAccount.cloudflareName && (
                <span>Cloudflare 名称：{manageAccount.cloudflareName}</span>
              )}
              <span>账户 ID：…{manageAccount.id.slice(-8)}</span>
              <details>
                <summary>查看完整账户 ID</summary>
                <code>{manageAccount.id}</code>
              </details>
            </div>
            {manageAccount.needsTokenRecovery && <p className="credential-recovery-note">令牌保存未完成。请先恢复此账户令牌，再管理云端配置。账户备注和本机移除仍可使用。</p>}
            <section className="manager-section">
              <div className="manager-section-heading">
                <strong>账户与访问令牌</strong>
                <p>访问令牌用于管理 Cloudflare 中的域名和短链接配置。</p>
              </div>
              <div className="manager-actions">
                {migrationAction(manageAccount.id)}
              <button
                disabled={mutation === "prepare_credentials"}
                className="button secondary"
                onClick={() => void openTokenManagement()}
              >
                修改已有令牌权限
              </button>
              <button
                disabled={mutation === "prepare_credentials"}
                className="button secondary"
                onClick={() => {
                  setUpdateTokenAccount(manageAccount);
                  setToken("");
                  setReplaceToken(true);
                  setClipboardOffer("");
                  setManageAccount(null);
                  setTokenOpen(true);
                }}
              >
                更换本机令牌
              </button>
              <button
                disabled={mutation === "prepare_credentials"}
                className="button secondary"
                onClick={() => {
                  setRenameAccount(manageAccount);
                  setRenameValue(manageAccount.label);
                  setManageAccount(null);
                }}
              >
                修改本机备注
              </button>
              </div>
            </section>
            <section className="manager-section">
              <div className="manager-section-heading">
                <strong>检测与恢复</strong>
                <p>检测密钥用于短链接健康检查，与 Cloudflare API 令牌分开保存。</p>
              </div>
              <div className="manager-actions">
              {!manageAccount.monitorEnabled && (
                <button
                  disabled={mutation === "prepare_credentials" || Boolean(manageAccount.needsTokenRecovery)}
                  className="button secondary"
                  onClick={() => {
                    monitorPrepareSequence.current += 1;
                    setError("");
                    setMonitorAccount(manageAccount);
                    setMonitorEndpoint(manageAccount.monitorEndpoint || "");
                    setMonitorSecret("");
                    setManageAccount(null);
                  }}
                >
                  配置检测服务
                </button>
              )}
              {manageAccount.monitorEnabled && (
                <button
                  disabled={mutation === "prepare_credentials" || Boolean(manageAccount.needsTokenRecovery)}
                  className="button secondary"
                  onClick={() => {
                    void disableMonitor(manageAccount);
                    setManageAccount(null);
                  }}
                >
                  停用检测服务
                </button>
              )}
              <button
                disabled={mutation === "prepare_credentials" || Boolean(manageAccount.needsTokenRecovery)}
                className="button secondary"
                onClick={() => {
                  void prepare("recover_account", {
                    accountId: manageAccount.id,
                  });
                  setManageAccount(null);
                }}
              >
                从 Cloudflare 找回配置
              </button>
              <button
                disabled={mutation === "prepare_credentials" || Boolean(manageAccount.needsTokenRecovery)}
                className="button secondary"
                onClick={() => {
                  void prepare("rotate_selftest", {
                    accountId: manageAccount.id,
                  });
                  setManageAccount(null);
                }}
              >
                重置检测密钥
              </button>
              </div>
            </section>
            {manageAccount.hasResources && (
              <section className="manager-section">
                <div className="manager-section-heading">
                  <strong>短链接访问保护</strong>
                  <p>默认启用：同一 IP 对同一短链接在每个 Cloudflare 节点的近似阈值为 100 次 / 10 秒，超出时暂时限制；访客无需验证。跨节点计数不合并，保护服务异常时放行，因此不保证全球总次数或费用上限。此设置作用于本账户的全部短链接域名。</p>
                  <p>状态只在点击读取后查询云端。</p>
                  {protectionRead?.accountId === manageAccount.id && <p role="status">{protectionRead.loading ? "正在读取访问保护状态…" : protectionRead.error ? `读取失败：${protectionRead.error}` : protectionRead.status ? `当前状态：${protectionRead.status.status === "enabled" ? "已启用" : protectionRead.status.status === "disabled" ? "已停用" : "需要升级云端跳转服务"} · 每节点近似阈值 ${protectionRead.status.limit} 次 / ${protectionRead.status.periodSeconds} 秒` : "尚未读取"}</p>}
                </div>
                <div className="manager-actions">
                  <button className="button secondary" disabled={busy || Boolean(protectionRead?.loading) || Boolean(manageAccount.needsCredentialMigration || manageAccount.needsTokenRecovery)} onClick={async () => {
                    const accountId = manageAccount.id;
                    const sequence = ++protectionReadSequence.current;
                    setProtectionRead({accountId,loading:true});
                    try {
                      const status = await dispatch<import('./types').ClickProtection>("get_click_protection", {accountId});
                      if (sequence !== protectionReadSequence.current) return;
                      if (status.accountId !== accountId || !["enabled", "disabled", "upgrade_required"].includes(status.status) || status.limit !== 100 || status.periodSeconds !== 10 || typeof status.checkedAt !== "string") throw new Error("返回的访问保护状态无效，请重试。");
                      setProtectionRead({accountId,status});
                    } catch (readError) {
                      if (sequence === protectionReadSequence.current) setProtectionRead({accountId,error:errorMessage(readError)});
                    }
                  }}>读取保护状态</button>
                  <button className="button secondary" disabled={busy || Boolean(manageAccount.needsCredentialMigration || manageAccount.needsTokenRecovery)} onClick={() => {
                    void prepare("enable_click_protection", {accountId:manageAccount.id});
                    setManageAccount(null);
                  }}>启用访问保护</button>
                  <button className="button secondary" disabled={busy || Boolean(manageAccount.needsCredentialMigration || manageAccount.needsTokenRecovery)} onClick={() => {
                    void prepare("disable_click_protection", {accountId:manageAccount.id});
                    setManageAccount(null);
                  }}>停用访问保护</button>
                </div>
              </section>
            )}
            {manageAccount.hasResources && (
              <section className="manager-section">
                <div className="manager-section-heading">
                  <strong>云端跳转功能</strong>
                  <p>升级此账户的云端跳转服务以启用新版功能，包括名称大小写兼容与默认访问保护。旧链接保持原样；已有重名时先匹配原名称，再匹配小写名称。现有密钥和检测设置会保留；此前明确停用的保护设置也会保留。</p>
                </div>
                <div className="manager-actions">
                  <button disabled={busy || Boolean(manageAccount.needsTokenRecovery)} className="button secondary" onClick={() => {
                    void prepare("upgrade_worker", { accountId: manageAccount.id });
                    setManageAccount(null);
                  }}>升级云端跳转服务</button>
                </div>
              </section>
            )}
            <div className="danger-zone">
              <strong>危险操作</strong>
              <p>
                删除云端短链接服务会删除此账户中由本应用管理的
                Worker、路由和短链接数据；不会删除其他网站或 DNS 记录。此账户关联的 {state.domains.filter((domain) => domain.accountId === manageAccount.id).length} 个域名下的短链接会失效。删除后不能靠刷新恢复；如需重建，请先导出配置并妥善保存。
              </p>
              <div className="danger-actions">
                <button
                  disabled={mutation === "prepare_credentials" || Boolean(manageAccount.needsTokenRecovery)}
                  className="button danger-button"
                  onClick={() => {
                    void prepare("cleanup_account", {
                      accountId: manageAccount.id,
                    });
                    setManageAccount(null);
                  }}
                >
                  删除云端短链接服务
                </button>
                <button
                  disabled={mutation === "prepare_credentials"}
                  className="button bordered danger-outline"
                  onClick={() => {
                    setRemoveAccount(manageAccount);
                    setManageAccount(null);
                  }}
                >
                  从本机移除
                </button>
              </div>
            </div>
          </div>
        </Dialog>
      )}
      {monitorAccount && !plan && (
        <Dialog
          title="配置检测服务"
          errorAction={migrationAction()}
          dismissDisabled={mutation === "prepare_credentials"}
          eyebrow="OPTIONAL MONITOR"
          error={error}
          onClose={closeMonitor}
          footer={
            <>
              <button
                className="button ghost"
                onClick={closeMonitor}
                disabled={mutation === "prepare_credentials"}
              >
                取消
              </button>
              <button
                className="button primary"
                form="monitor-form"
                type="submit"
                disabled={busy}
              >
                预览启用计划
              </button>
            </>
          }
        >
          <form
            noValidate
            id="monitor-form"
            className="form-grid"
            onSubmit={(e) => void prepareMonitor(e)}
          >
            <p className="form-note">
              检测服务由您自行提供。应用无法验证任意服务的网络节点是否位于中国大陆。未配置时不会请求服务。
            </p>
            <label>
              检测服务 HTTPS 地址
              <input
                type="url"
                {...fieldProps("monitor-endpoint", formErrors)}
                value={monitorEndpoint}
                onChange={(e) => {
                  monitorPrepareSequence.current += 1;
                  setMonitorEndpoint(e.target.value);
                  setFormErrors({});
                }}
                placeholder="https://probe.example.com/check"
                required
              />
                <FieldError name="monitor-endpoint" errors={formErrors} />
            </label>
            <label>
              服务密钥
              <input
                type="password"
                autoComplete="off"
                {...fieldProps("monitor-secret", formErrors)}
                value={monitorSecret}
                onChange={(e) => {
                  monitorPrepareSequence.current += 1;
                  setMonitorSecret(e.target.value);
                  setFormErrors({});
                }}
                required
              />
                <FieldError name="monitor-secret" errors={formErrors} />
              <small>32–256 个无空白的可打印 ASCII 字符。</small>
            </label>
            <p className="form-note">
              确认启用后，密钥保存在系统凭据库和账户的 Worker
              中，用于验证检测服务；不会写入备份或日志。关闭窗口后表单不再显示密钥。
            </p>
          </form>
        </Dialog>
      )}
      {testResult && (
        <Dialog
          title="链接检测"
          eyebrow="ROUTE & TARGET CHECK"
          onClose={closeDetection}
          footer={
            <button
              className="button primary"
              onClick={closeDetection}
            >
              完成
            </button>
          }
        >
          <div className="test-result">
            <div className="test-url">{testResult.url}</div>
            {testResult.automaticDns && <p role="status">检测到 VPN 虚拟地址，本次已自动使用公共 DNS 重查一次；下方显示实际检查结果。</p>}
            <h3>短链接跳转</h3>
            <StatusPill
              tone={
                testResult.result.status === "passed"
                  ? "green"
                  : testResult.result.status === "failed"
                    ? "amber"
                    : "slate"
              }
            >
              {
                {
                  passed: "跳转检测通过",
                  pending: "等待生效",
                  failed: "跳转检测失败",
                  key_missing: "检测密钥缺失",
                }[testResult.result.status]
              }
            </StatusPill>
            <p>{testResult.result.message}</p>
            {testResult.dnsMode === "public" && <small>本次跳转检查使用公共 DNS 查询短链接域名。</small>}
            {testResult.result.checks.map((c, i) => (
              <div className="check-row" key={i}>
                {c.ok ? <CheckCircle size={17} /> : <WarningCircle size={17} />}
                <span>
                  {c.label}：{c.message}
                </span>
              </div>
            ))}
            <div className="form-divider" />
            <h3>跳转网站检查</h3>
            {targetResult?.checks.map((c, i) => (
              <div className="check-row" key={i}>
                <span
                  className={`status status-${c.status === "passed" ? "green" : c.status === "failed" ? "red" : "amber"}`}
                >
                  {c.status === "passed"
                    ? "本机通过"
                    : c.status === "failed"
                      ? "本机失败"
                      : "暂时无法确认"}
                </span>
                <span>
                  {c.label}：{c.message}
                  <small>
                    来源：{targetSourceLabel(c.dnsMode || targetResult.dnsMode)} · {formatDate(c.checkedAt)}
                  </small>
                </span>
              </div>
            ))}
            {!preview && (targetResult?.dnsMode === "public" || targetResult?.checks.some((check) => check.status === "unknown") || testResult.result.status !== "passed") && (
              <div className="form-note">
                <p>明确检测到 VPN 虚拟地址时会自动兼容重查一次；其他网络问题不会自动切换，也可在这里手动重试。Cloudflare 公共 DNS 只向查询服务发送域名，不发送完整链接或邀请码；重试过程中如遇跳转，也会查询跳转后的域名。</p>
                <button className="button secondary" disabled={retryingTargets} onClick={() => void retryTargetsWithPublicDns()}>
                  {retryingTargets ? "正在重新检测…" : "兼容 VPN 重试"}
                </button>
                {testResult.result.status !== "passed" && (
                  <button className="button secondary" disabled={retryingTargets || Boolean(testingLink)} onClick={retryRouteWithPublicDns}>
                    兼容 VPN 重新检测跳转和网站
                  </button>
                )}
                <p>不会更改你的 VPN 设置。结果仍代表本机当前网络，不能据此判断大陆是否能访问。</p>
              </div>
            )}
            <small>
              {preview
                ? "本地预览未发起目标检测。"
                : "跳转结果与目标网站检查分开显示。目标检查从本机当前网络发起，VPN、TUN 和网络策略仍会影响结果；未开启大陆监测时不能代表中国大陆网络。"}
              403、429
              或超时可能与网站限制或临时网络状况有关，此时暂时无法确认是否可用。
            </small>
          </div>
        </Dialog>
      )}
      {updateOpen && (
        <Dialog
          title="应用更新"
          dismissDisabled={mutation === "update" || updates.checking}
          eyebrow="DESKTOP UPDATE"
          error={updateError}
          onClose={() => {setUpdateOpen(false); setUpdateStatus(null);}}
          footer={
            <>
              <button
                className="button ghost"
                disabled={mutation === "update" || updates.checking}
                onClick={() => {setUpdateOpen(false); setUpdateStatus(null);}}
              >
                {updateStatus?.status === "available" ? "稍后再说" : "关闭"}
              </button>
              {!updateStatus && !updates.checking && <button type="button" className="button primary" onClick={() => void checkUpdate()}>重新检查更新</button>}
              {(updates.checking || mutation === "update") && <button type="button" className="button secondary" disabled={cancellingUpdate || Boolean(updateCancelMessage) || updatePhase === "installing"} onClick={() => void cancelUpdate()}>{updatePhase === "installing" ? "安装开始后无法取消" : cancellingUpdate ? "正在请求取消…" : "取消本次更新"}</button>}
              {updateStatus?.status === "available" && (
                <button
                  className="button primary"
                  onClick={() => void installUpdate()}
                  disabled={busy || updates.checking}
                >
                  {mutation === "update" ? "正在处理更新…" : "确认安装更新"}
                </button>
              )}
            </>
          }
        >
          <div className="update-result">
            {(updates.checking || mutation === "update") && <div className="update-progress" role="status"><span className="update-progress-dot" />{updatePhase === "installing" ? "正在安装，请等待完成。此阶段无法取消。" : updatePhase === "verifying" ? "下载已完成，正在校验更新包。" : updatePhase === "downloading" ? "正在下载更新，可取消本次操作。" : updates.checking || updatePhase === "checking" ? "正在检查更新，可取消本次操作。" : "正在等待更新服务返回，可请求取消。"}</div>}
            {updateCancelMessage && <p role="status">{updateCancelMessage}</p>}
            {!updateStatus && !updates.checking && !updateError && <p>本次检查已结束。</p>}
            {updateStatus?.status === "installed" ? (
              <p>更新 <strong>{updateStatus?.version}</strong> 已安装。请退出并重新打开软件，即可使用新版本。</p>
            ) : updateStatus?.status === "unavailable" ? (
              <p>
                当前版本：<strong>{currentVersion || "未提供"}</strong>
                。更新渠道尚未启用，请使用正式发行渠道获取新版本。
              </p>
            ) : updateStatus?.status === "up_to_date" ? (
              <p>
                当前已是最新版本（
                <strong>{currentVersion || "版本未提供"}</strong>）。
              </p>
            ) : updateStatus ? (
              <>
                <p>
                  当前版本：<strong>{currentVersion || "未提供"}</strong>
                  ；发现新版本{" "}
                  <strong>{updateStatus?.version || "可用更新"}</strong>
                  。安装后应用可能会重启。
                </p>
                {updateStatus?.notes && (
                  <div className="update-notes">{updateStatus?.notes}</div>
                )}
              </>
            ) : null}
          </div>
        </Dialog>
      )}
    </div>
  );
}
