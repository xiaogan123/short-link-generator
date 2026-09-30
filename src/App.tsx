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
  CheckCircle,
  Clipboard,
  CloudArrowDown,
  CloudArrowUp,
  Copy,
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
import Pools from "./Pools";

type Page = "links" | "pools" | "domains" | "accounts";
type LinkDraft = {
  domainId: string;
  slug: string;
  cnUrl: string;
  defaultUrl: string;
  poolId: string;
  code: string;
};
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
function targetSourceLabel() {
  return preview ? "本地预览 · 未探测" : "本机网络";
}
function domainCheckLevel(check: DomainPreparation["checks"][number]) {
  return check.level || (check.ok ? "pass" : "error");
}
function domainOutcome(preparation: DomainPreparation) {
  const levels = preparation.checks.map(domainCheckLevel);
  return levels.includes("error")
    ? { level: "error", label: "需要先处理" }
    : levels.includes("warning")
      ? { level: "warning", label: "确认后可接入" }
      : { level: "pass", label: "可用" };
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

export default function App() {
  const [page, setPage] = useState<Page>("links");
  const [state, setState] = useState<State>(emptyState);
  const [loading, setLoading] = useState(true);
  const [loadFailed, setLoadFailed] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");
  const [search, setSearch] = useState("");
  const [filter, setFilter] = useState("all");
  const [linkDraft, setLinkDraft] = useState<LinkDraft | null>(null);
  const [originalSlug, setOriginalSlug] = useState<string | null>(null);
  const [domainDraft, setDomainDraft] = useState({
    input: "",
    prefix: "r",
    accountId: "",
  });
  const [domainOpen, setDomainOpen] = useState(false);
  const [domainBusy, setDomainBusy] = useState(false);
  const [domainFeedback, setDomainFeedback] = useState<{
    tone: "error" | "success" | "progress";
    message: string;
  } | null>(null);
  const [preflight, setPreflight] = useState<DomainPreparation | null>(null);
  const [dnsPreflight, setDnsPreflight] = useState<DomainDnsPreparation | null>(
    null,
  );
  const [plan, setPlan] = useState<Plan | null>(null);
  const [planDetails, setPlanDetails] = useState<string[]>([]);
  const [planKind, setPlanKind] = useState("");
  const [tokenOpen, setTokenOpen] = useState(false);
  const [updateTokenAccount, setUpdateTokenAccount] = useState<Account | null>(
    null,
  );
  const [token, setToken] = useState("");
  const [replaceToken, setReplaceToken] = useState(false);
  const [clipboardOffer, setClipboardOffer] = useState("");
  const [clipboardToClear, setClipboardToClear] = useState("");
  const [renameAccount, setRenameAccount] = useState<Account | null>(null);
  const [renameValue, setRenameValue] = useState("");
  const [removeAccount, setRemoveAccount] = useState<Account | null>(null);
  const [testResult, setTestResult] = useState<{
    url: string;
    result: Selftest;
  } | null>(null);
  const [targetResult, setTargetResult] = useState<TargetReport | null>(null);
  const [detections, setDetections] = useState<Record<string, Detection>>({});
  const [poolHealth, setPoolHealth] = useState<
    Record<string, { fingerprint: string; report: PoolHealth }>
  >({});
  const [poolSavedRevision, setPoolSavedRevision] = useState(0);
  const [monitorAccount, setMonitorAccount] = useState<Account | null>(null);
  const [monitorEndpoint, setMonitorEndpoint] = useState("");
  const [monitorSecret, setMonitorSecret] = useState("");
  const [testingLink, setTestingLink] = useState("");
  const [updateStatus, setUpdateStatus] = useState<UpdateStatus | null>(null);
  const [manageAccount, setManageAccount] = useState<Account | null>(null);
  const [sidebarOpen, setSidebarOpen] = useState(false);
  const [clock, setClock] = useState(Date.now());
  const stateRef = useRef(state);
  const domainDraftRef = useRef(domainDraft);
  const detectionSequence = useRef(0);
  const domainCheckSequence = useRef(0);
  const domainOperation = useRef({ sequence: 0, inflight: false });
  const resumeDomainAfterToken = useRef(false);
  const latestDetectionForLink = useRef<Record<string, number>>({});
  stateRef.current = state;
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

  async function load() {
    setLoading(true);
    setLoadFailed(false);
    setError("");
    try {
      setState(await dispatch<State>("get_state"));
      setPoolHealth({});
    } catch (e) {
      setLoadFailed(true);
      setError(errorMessage(e));
    } finally {
      setLoading(false);
    }
  }
  useEffect(() => {
    void load();
  }, []);
  useEffect(() => {
    const timer = window.setInterval(() => setClock(Date.now()), 60000);
    return () => window.clearInterval(timer);
  }, []);
  useEffect(() => {
    if (!notice) return;
    const id = window.setTimeout(() => setNotice(""), 5000);
    return () => clearTimeout(id);
  }, [notice]);

  async function run<T>(
    work: () => Promise<T>,
    success?: string,
  ): Promise<T | undefined> {
    setBusy(true);
    setError("");
    try {
      const value = await work();
      if (success) setNotice(success);
      return value;
    } catch (e) {
      setError(errorMessage(e));
      return undefined;
    } finally {
      setBusy(false);
    }
  }
  async function prepare(kind: string, fields: Record<string, unknown>) {
    const next = await run(() =>
      dispatch<Plan>("prepare_change", { kind, ...fields }),
    );
    if (next) {
      setPlanKind(kind);
      if (kind === "save_link") {
        const domain = state.domains.find((d) => d.id === fields.domainId);
        const pool = state.pools?.find((p) => p.id === fields.poolId);
        const code = encodeURIComponent(String(fields.code));
        setPlanDetails(
          fields.poolId
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
              ],
        );
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
          `同步账户：${pool.accountIds.map((id) => state.accounts.find((a) => a.id === id)?.label || id).join("、")}（已同步不等于已关联）`,
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
        const domain = state.domains.find((d) => d.id === fields.domainId);
        setPlanDetails([
          `删除：${domain ? shortUrl(domain.host, domain.prefix, String(fields.slug)) : String(fields.slug)}`,
        ]);
      } else if (kind === "remove_domain")
        setPlanDetails([
          `域名：${state.domains.find((d) => d.id === fields.domainId)?.host || String(fields.domainId)}`,
        ]);
      else
        setPlanDetails([
          `账户：${state.accounts.find((a) => a.id === fields.accountId)?.label || String(fields.accountId)}`,
        ]);
      setPlan(next);
    }
    return Boolean(next);
  }
  async function apply() {
    if (!plan) return;
    const appliedKind = planKind;
    const savedLink =
      planKind === "save_link" && linkDraft ? { ...linkDraft } : null;
    const dnsSnapshot =
      appliedKind === "fix_domain_dns" ? { ...domainDraftRef.current } : null;
    const takeover = Boolean(plan.domainTakeoverConfirmation);
    const next = await run(
      () =>
        dispatch<State>("apply_plan", {
          planId: plan.id,
          ...(takeover ? { acknowledgeDomainTakeover: true } : {}),
        }),
      appliedKind === "add_domain"
        ? "域名已接入。现在可以创建第一条短链接；云端配置可能需要稍等片刻才生效。"
        : appliedKind === "fix_domain_dns"
          ? "解析设置已提交，正在继续检查域名。"
          : "已提交修改。云端更新可能需要一点时间生效。",
    );
    if (next) {
      stateRef.current = next;
      setState(next);
      setPoolHealth({});
      if (appliedKind === "save_pool") setPoolSavedRevision((n) => n + 1);
      setPlan(null);
      setLinkDraft(null);
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
          openPlanWhenReady: true,
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
      setDomainOpen(
        appliedKind === "add_domain" || appliedKind === "fix_domain_dns",
      );
      try {
        const latest = await dispatch<State>("get_state");
        stateRef.current = latest;
        setState(latest);
      } catch {
        /* Preserve the original operation error. */
      }
    }
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
  function openLink(link?: Link, usePlatform = false) {
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
            domainId: state.domains[0]?.id || "",
            slug: "",
            cnUrl: "",
            defaultUrl: "",
            poolId: "",
            code: "",
          },
    );
  }
  async function saveLink(event: FormEvent) {
    event.preventDefault();
    if (!linkDraft) return;
    const validation =
      validateSlug(linkDraft.slug) ||
      (linkDraft.poolId
        ? !state.pools?.some((p) => p.id === linkDraft.poolId)
          ? "请选择可用平台地址。"
          : !/^[A-Za-z0-9_-]{1,128}$/.test(linkDraft.code)
            ? "邀请码须为 1–128 位字母、数字、下划线或连字符。"
            : ""
        : validateTarget(linkDraft.cnUrl) ||
          validateTarget(linkDraft.defaultUrl));
    if (validation) {
      setError(validation);
      return;
    }
    if (!linkDraft.domainId) {
      setError("请先选择域名。");
      return;
    }
    if (originalSlug && originalSlug !== linkDraft.slug) {
      setError("现有短链接不能更改名称。请新建一条链接。");
      return;
    }
    await prepare(
      "save_link",
      linkDraft.poolId
        ? {
            domainId: linkDraft.domainId,
            slug: linkDraft.slug,
            poolId: linkDraft.poolId,
            code: linkDraft.code,
          }
        : {
            domainId: linkDraft.domainId,
            slug: linkDraft.slug,
            cnUrl: linkDraft.cnUrl,
            defaultUrl: linkDraft.defaultUrl,
          },
    );
  }
  function beginDomainOperation() {
    if (domainOperation.current.inflight) return null;
    const sequence = ++domainOperation.current.sequence;
    domainOperation.current.inflight = true;
    setDomainBusy(true);
    setError("");
    return sequence;
  }
  function invalidateDomainPreparation() {
    domainOperation.current.sequence += 1;
    domainCheckSequence.current += 1;
    setPreflight(null);
    setDnsPreflight(null);
    setDomainFeedback(null);
    setError("");
  }
  function finishDomainOperation() {
    domainOperation.current.inflight = false;
    setDomainBusy(false);
  }
  function isCurrentDomainOperation(sequence: number) {
    return sequence === domainOperation.current.sequence;
  }
  function openDomainPlan(result: DomainPreparation) {
    if (!result.plan) return;
    setPlanKind("add_domain");
    setPlanDetails([
      `域名：${result.host}`,
      `链接目录：/${result.prefix}/`,
      `账户：${result.candidates.find((candidate) => candidate.accountId === domainDraftRef.current.accountId)?.label || "待确认"}`,
    ]);
    setPlan(result.plan);
    setDomainOpen(false);
  }
  function openDnsPlan(result: DomainDnsPreparation) {
    if (!result.plan) return;
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
      setState(next);
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
      openPlanWhenReady?: boolean;
      repairAlreadyApplied?: boolean;
    } = {},
  ) {
    const validation =
      validateHost(draft.input) || validatePrefix(draft.prefix);
    if (validation) {
      setDomainFeedback({ tone: "error", message: validation });
      return;
    }
    const operation = beginDomainOperation();
    if (operation === null) return;
    const sequence = ++domainCheckSequence.current;
    const snapshot = {
      input: draft.input.trim(),
      prefix: draft.prefix,
      accountId: draft.accountId,
    };
    setDomainFeedback({
      tone: "progress",
      message: "正在检查此账户的域名配置，请完成系统授权后稍候。",
    });
    setPreflight(null);
    setDnsPreflight(null);
    try {
      let result = await dispatch<DomainPreparation>("prepare_domain", {
        input: snapshot.input,
        prefix: snapshot.prefix,
        ...(snapshot.accountId ? { accountId: snapshot.accountId } : {}),
      });
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
      if (!result.canApply && hasOnlyDnsBlocker(result)) {
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
          result = await dispatch<DomainPreparation>("prepare_domain", {
            input: snapshot.input,
            prefix: snapshot.prefix,
            ...(snapshot.accountId ? { accountId: snapshot.accountId } : {}),
          });
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
        if (options.openPlanWhenReady && result.canApply && result.plan)
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
    const operation = beginDomainOperation();
    if (operation === null) return;
    const sequence = ++domainCheckSequence.current;
    const account = stateRef.current.accounts.find(
      (item) => item.id === selectedAccountId,
    );
    setDomainFeedback({
      tone: "progress",
      message: "正在读取此账户的域名，请完成系统授权后稍候。",
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
      setState(next);
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
          更新当前账户令牌
        </button>
      </div>
    );
  }
  function closeDomain() {
    invalidateDomainPreparation();
    setDomainOpen(false);
  }
  function returnFromPlan() {
    if (busy && planKind === "fix_domain_dns") return;
    setPlan(null);
    if (planKind === "add_domain" || planKind === "fix_domain_dns")
      setDomainOpen(true);
  }
  async function openTemplate() {
    const url = await run(() => dispatch<string>("token_template"));
    if (!url) return;
    if (preview) window.open(url, "_blank", "noopener,noreferrer");
    else {
      const { openUrl } = await import("@tauri-apps/plugin-opener");
      await run(() => openUrl(url));
    }
  }
  async function checkClipboard() {
    try {
      const text = (
        preview
          ? await navigator.clipboard.readText()
          : await (
              await import("@tauri-apps/plugin-clipboard-manager")
            ).readText()
      ).trim();
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
    return () => window.removeEventListener("focus", onFocus);
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
  async function importToken(event: FormEvent) {
    event.preventDefault();
    if (!token.trim()) {
      setError("请先粘贴令牌。");
      return;
    }
    const next = await run(
      () =>
        dispatch<State>("import_token", {
          token: token.trim(),
          replace: replaceToken,
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
      setState(next);
      setToken("");
      setClipboardOffer("");
      setReplaceToken(false);
      setUpdateTokenAccount(null);
      setTokenOpen(false);
      if (shouldResumeDomain) {
        setDomainOpen(true);
        void refreshDomainPreparation(domainDraftRef.current);
      }
    }
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
    if (next) setState(next);
  }
  async function refreshAccounts() {
    const next = await run(
      () => dispatch<State>("refresh_accounts"),
      "账户状态已更新。",
    );
    if (next) setState(next);
  }
  async function checkUpdate() {
    const result = await run(() => dispatch<UpdateStatus>("check_update"));
    if (result)
      setUpdateStatus({
        ...result,
        currentVersion: result.currentVersion || stateRef.current.appVersion,
      });
  }
  async function installUpdate() {
    const result = await run(async () => {
      await dispatch<unknown>("install_update");
      return true;
    });
    if (result) {
      setUpdateStatus(null);
      setNotice("更新已安装，请退出并重新打开软件。");
    }
  }
  async function doRename(event: FormEvent) {
    event.preventDefault();
    if (!renameAccount || !renameValue.trim()) return;
    const next = await run(
      () =>
        dispatch<State>("rename_account", {
          accountId: renameAccount.id,
          label: renameValue.trim(),
        }),
      "账户名称已更新。",
    );
    if (next) {
      setState(next);
      setRenameAccount(null);
    }
  }
  async function doRemove() {
    if (!removeAccount) return;
    const next = await run(
      () => dispatch<State>("remove_account", { accountId: removeAccount.id }),
      "本机账户记录已移除。",
    );
    if (next) {
      setState(next);
      setRemoveAccount(null);
    }
  }
  async function savePool(pool: Pool) {
    return prepare("save_pool", { pool });
  }
  async function prepareMonitor(event: FormEvent) {
    event.preventDefault();
    if (!monitorAccount) return;
    const endpoint = monitorEndpoint.trim();
    try {
      const url = new URL(endpoint);
      if (url.protocol !== "https:" || url.username || url.password)
        throw Error();
    } catch {
      setError("检测服务地址必须是无凭据的 HTTPS 网址。");
      return;
    }
    if (!/^[\x21-\x7e]{32,256}$/.test(monitorSecret)) {
      setError("服务密钥须为 32–256 个无空白的可打印 ASCII 字符。");
      return;
    }
    setBusy(true);
    setError("");
    let next: Plan | undefined;
    try {
      next = await dispatch<Plan>("prepare_monitor", {
        accountId: monitorAccount.id,
        endpoint,
        secret: monitorSecret,
      });
    } catch (e) {
      setError(errorMessage(e).replaceAll(monitorSecret, "[已隐藏]"));
    } finally {
      setBusy(false);
    }
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
    if (action.kind === "resume_pool_sync" && action.poolId) {
      await prepare("resume_pool_sync", { poolId: action.poolId });
      return;
    }
    if (action.kind === "delete_pool" && action.poolId) {
      await prepare("delete_pool", { poolId: action.poolId });
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
  }
  async function inspectPool(poolId: string) {
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
    return JSON.stringify([
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
  async function selftest(link: Link, domain: Domain) {
    const url = shortUrl(domain.host, domain.prefix, link.slug);
    const sequence = ++detectionSequence.current;
    latestDetectionForLink.current[detectionKey(link)] = sequence;
    setTestingLink(url);
    setError("");
    const observedFingerprint = fingerprint(link);
    try {
      const [route, targets] = await Promise.allSettled([
        dispatch<Selftest>("selftest_link", {
          domainId: link.domainId,
          slug: link.slug,
        }),
        dispatch<TargetReport>("check_link_targets", {
          domainId: link.domainId,
          slug: link.slug,
        }),
      ]);
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
              checks: [
                {
                  label: "目标地址",
                  status: "unknown",
                  message: `本机检测未完成：${errorMessage(targets.reason)}`,
                  checkedAt,
                  source: "local",
                  url: "",
                },
              ],
            };
      if (latestDetectionForLink.current[detectionKey(link)] === sequence)
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
          setTestResult({ url, result });
          setTargetResult(targetReport);
        } else setNotice("链接或平台地址已变化，请重新检测。");
      }
    } catch (e) {
      setError(`检测未完成：${errorMessage(e)}`);
    } finally {
      if (sequence === detectionSequence.current) setTestingLink("");
    }
  }

  function detectionLabel(link: Link) {
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
      return { tone: "green", label: "跳转与目标本机检测通过" };
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
  const filteredDomains = state.domains.filter(
    (d) => filter === "all" || d.id === filter,
  );
  const groups = filteredDomains
    .map((domain) => ({
      domain,
      links: state.links.filter(
        (link) =>
          link.domainId === domain.id &&
          `${link.slug} ${link.cnUrl} ${link.defaultUrl} ${state.pools?.find((p) => p.id === link.poolId)?.name || ""} ${domain.host}`
            .toLowerCase()
            .includes(search.trim().toLowerCase()),
      ),
    }))
    .filter((group) => !search || group.links.length);
  const title =
    page === "links"
      ? "短链接"
      : page === "pools"
        ? "平台地址"
        : page === "domains"
          ? "域名管理"
          : "Cloudflare 账户";
  const subtitle =
    page === "links"
      ? "查看、检测和编辑不同地区的跳转地址。"
      : page === "pools"
        ? "集中维护地址；关联链接各自保留邀请码。"
        : page === "domains"
          ? "添加前检查所属账户和现有网站配置。"
          : "管理连接、检测服务与本机备份。";
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
                onClick={() => {
                  setPage(item.key);
                  setSidebarOpen(false);
                  setError("");
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
            className="sidebar-update"
            onClick={() => void checkUpdate()}
            disabled={busy}
          >
            <ArrowClockwise size={15} />
            检查更新
          </button>
        </div>
      </aside>
      <main className="main">
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
              <button aria-label="关闭错误" onClick={() => setError("")}>
                <X size={16} />
              </button>
            </div>
          )}
          {notice && (
            <div role="status" className="alert success">
              <CheckCircle size={19} />
              <span>{notice}</span>
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
              </span>
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
                <p>打开计划复核当前状态，再确认后续步骤。</p>
                {state.pendingActions.map((action, index) => (
                  <div
                    className="pending-action"
                    key={`${action.kind}:${action.poolId || action.accountId || index}`}
                  >
                    <span>{action.label}</span>
                    <button
                      className="button secondary"
                      disabled={
                        busy ||
                        (!action.poolId && action.kind !== "resume_monitor") ||
                        (!action.accountId && action.kind === "resume_monitor")
                      }
                      onClick={() => void resumePending(action)}
                    >
                      {action.kind === "resume_pool_sync"
                        ? "继续同步"
                        : action.kind === "resume_monitor"
                          ? "继续处理监测"
                          : "继续删除"}
                    </button>
                  </div>
                ))}
              </section>
            )}
          {state.pendingOperations.length > 0 && (
            <details className="operation-log">
              <summary>
                有 {state.pendingOperations.length} 条操作需要核对
              </summary>
              <p>以下操作尚未确认完成。请先查看云端实际状态，避免重复提交。</p>
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
          ) : page === "links" ? (
            <>
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
                  <span>已连接账户</span>
                  <strong>{state.accounts.length}</strong>
                  <small>按账户管理区域</small>
                </div>
              </div>
              <section className="panel">
                <div className="panel-head">
                  <div>
                    <p className="eyebrow">DESTINATIONS</p>
                    <h2>
                      全部链接{" "}
                      <span className="heading-count">
                        {state.links.length}
                      </span>
                    </h2>
                  </div>
                  <div className="panel-tools">
                    <label className="searchbox">
                      <MagnifyingGlass size={17} />
                      <input
                        aria-label="搜索链接"
                        value={search}
                        onChange={(e) => setSearch(e.target.value)}
                        placeholder="搜索路径或目标地址"
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
                ) : !groups.length || groups.every((g) => !g.links.length) ? (
                  <Empty
                    icon={<LinkSimple size={28} />}
                    title={search ? "没有匹配的链接" : "还没有短链接"}
                    description={
                      search
                        ? "换个关键词或域名试试。"
                        : "为已连接域名创建第一条短链接。"
                    }
                    action={
                      !search && (
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
                  <div className="link-groups">
                    {groups.map(({ domain, links }) => (
                      <div className="domain-group" key={domain.id}>
                        <div className="group-heading">
                          <div>
                            <Globe size={17} />
                            <strong>{domain.host}</strong>
                            <span>/{domain.prefix}/</span>
                          </div>
                          <small>{links.length} 条链接</small>
                        </div>
                        <div className="table-scroll">
                          <table>
                            <thead>
                              <tr>
                                <th>链接</th>
                                <th>地区目标</th>
                                <th>最后更新</th>
                                <th>操作</th>
                              </tr>
                            </thead>
                            <tbody>
                              {links.map((link) => (
                                <tr key={link.slug}>
                                  <td>
                                    <div className="link-name">
                                      <strong>/{link.slug}</strong>
                                      <span>
                                        {shortUrl(
                                          domain.host,
                                          domain.prefix,
                                          link.slug,
                                        )}
                                      </span>
                                      <small className="link-source">
                                        {link.poolId
                                          ? "跟随平台地址"
                                          : "手动地址"}
                                      </small>
                                      {link.poolId && (
                                        <small className="pool-link-tag">
                                          平台地址：
                                          {state.pools?.find(
                                            (p) => p.id === link.poolId,
                                          )?.name || "已移除"}{" "}
                                          · 邀请码：{link.code}
                                        </small>
                                      )}
                                      <small
                                        className={`link-detection ${detectionLabel(link).tone}`}
                                        title={
                                          detections[detectionKey(link)]
                                            ?.checkedAt
                                            ? `${targetSourceLabel()}结果于 ${formatDate(detections[detectionKey(link)].checkedAt)}`
                                            : undefined
                                        }
                                      >
                                        {detectionLabel(link).label}
                                        {detections[detectionKey(link)] &&
                                          ` · ${targetSourceLabel()} · ${formatDate(detections[detectionKey(link)].checkedAt)}`}
                                      </small>
                                    </div>
                                  </td>
                                  <td>
                                    <div className="route-lines">
                                      <span>
                                        <b>
                                          {link.poolId ? "平台大陆" : "大陆"}
                                        </b>
                                        <span title={link.cnUrl}>
                                          {link.cnUrl}
                                        </span>
                                      </span>
                                      <span>
                                        <b>
                                          {link.poolId
                                            ? "平台其他地区"
                                            : "其他地区"}
                                        </b>
                                        <span title={link.defaultUrl}>
                                          {link.defaultUrl}
                                        </span>
                                      </span>
                                    </div>
                                  </td>
                                  <td className="date-cell">
                                    {formatDate(link.updated)}
                                  </td>
                                  <td>
                                    <div className="row-actions">
                                      <button
                                        title="复制"
                                        aria-label={`复制 ${link.slug}`}
                                        onClick={() =>
                                          void copy(
                                            shortUrl(
                                              domain.host,
                                              domain.prefix,
                                              link.slug,
                                            ),
                                          )
                                        }
                                      >
                                        <Copy size={15} />
                                        复制
                                      </button>
                                      <button
                                        title="检测"
                                        aria-label={`检测 ${link.slug}`}
                                        onClick={() =>
                                          void selftest(link, domain)
                                        }
                                      >
                                        <ShieldCheck size={15} />
                                        检测
                                      </button>
                                      {!link.poolId &&
                                        Boolean(state.pools?.length) && (
                                          <button
                                            title="改为平台地址"
                                            aria-label={`将 ${link.slug} 改为平台地址`}
                                            onClick={() => openLink(link, true)}
                                          >
                                            改为平台地址
                                          </button>
                                        )}
                                      <button
                                        title="编辑"
                                        aria-label={`编辑 ${link.slug}`}
                                        onClick={() => openLink(link)}
                                      >
                                        编辑
                                      </button>
                                      <button
                                        title="删除"
                                        aria-label={`删除 ${link.slug}`}
                                        onClick={() =>
                                          void prepare("delete_link", {
                                            domainId: domain.id,
                                            slug: link.slug,
                                          })
                                        }
                                      >
                                        删除
                                      </button>
                                    </div>
                                  </td>
                                </tr>
                              ))}
                            </tbody>
                          </table>
                        </div>
                      </div>
                    ))}
                  </div>
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
              linkCount={(id) =>
                state.links.filter((l) => l.poolId === id).length
              }
              onSave={savePool}
              onDelete={(id) => void prepare("delete_pool", { poolId: id })}
              busy={busy}
              health={visiblePoolHealth}
              onCheckHealth={(id) => void inspectPool(id)}
              planOpen={Boolean(plan && planKind === "save_pool")}
              savedRevision={poolSavedRevision}
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
                    <h2>已添加的域名</h2>
                  </div>
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
                    {state.domains.map((domain) => (
                      <div className="domain-card" key={domain.id}>
                        <div className="domain-symbol">
                          <Globe size={22} />
                        </div>
                        <div className="domain-card-main">
                          <h3>{domain.host}</h3>
                          <p>
                            链接路径 <strong>/{domain.prefix}/</strong> ·{" "}
                            {accountById.get(domain.accountId)?.label ||
                              "未知账户"}
                          </p>
                          <span>
                            {
                              state.links.filter(
                                (l) => l.domainId === domain.id,
                              ).length
                            }{" "}
                            条链接
                          </span>
                        </div>
                        <div className="card-actions">
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
                      </div>
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
                    <h2>账户列表</h2>
                  </div>
                  <button
                    className="button ghost"
                    onClick={() => void refreshAccounts()}
                    disabled={busy}
                  >
                    <ArrowClockwise size={16} />
                    更新状态
                  </button>
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
                          setTokenOpen(true);
                        }}
                      >
                        导入账户
                      </button>
                    }
                  />
                ) : (
                  <div className="account-cards">
                    {state.accounts.map((account) => (
                      <div className="account-card" key={account.id}>
                        <div className="account-symbol">
                          <Key size={22} />
                        </div>
                        <div className="account-main">
                          <div className="account-title">
                            <h3>{account.cloudflareName || account.label}</h3>
                            {account.needsSelftestKey ? (
                              <StatusPill tone="amber">
                                检测密钥待恢复
                              </StatusPill>
                            ) : (
                              <StatusPill>已连接</StatusPill>
                            )}
                          </div>
                          <p>
                            {account.cloudflareName && (
                              <>本机备注：{account.label} · </>
                            )}
                            账户 ID：…{account.id.slice(-8)} · Cloudflare 内{" "}
                            {account.zoneCount} 个站点 · 已连接{" "}
                            {
                              state.domains.filter(
                                (d) => d.accountId === account.id,
                              ).length
                            }{" "}
                            个域名 · 检查于 {formatDate(account.checkedAt)}
                          </p>
                          <span className="monitor-status">
                            检测服务：
                            {account.monitorEnabled
                              ? `已启用 · ${account.monitorEndpoint || "地址未提供"}`
                              : "未启用"}
                            {account.needsMonitorKey && (
                              <strong>
                                {" "}
                                ·
                                本机密钥缺失；云端监测可能仍在运行，请先停用再重新配置
                              </strong>
                            )}
                          </span>
                        </div>
                        <button
                          className="button ghost"
                          aria-label={`管理 ${account.label}`}
                          onClick={() => setManageAccount(account)}
                        >
                          管理
                        </button>
                      </div>
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
          title={originalSlug ? "编辑短链接" : "创建短链接"}
          eyebrow="LINK DETAILS"
          error={error}
          onClose={() => setLinkDraft(null)}
          footer={
            <>
              <button
                className="button ghost"
                onClick={() => setLinkDraft(null)}
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
          <form
            id="link-form"
            onSubmit={(e) => void saveLink(e)}
            className="form-grid"
          >
            <label>
              所属域名
              <select
                value={linkDraft.domainId}
                onChange={(e) =>
                  setLinkDraft({ ...linkDraft, domainId: e.target.value })
                }
                disabled={Boolean(originalSlug)}
                required
              >
                {state.domains.map((d) => (
                  <option value={d.id} key={d.id}>
                    {d.host} /{d.prefix}/
                  </option>
                ))}
              </select>
            </label>
            <label>
              短链接名称
              <input
                value={linkDraft.slug}
                onChange={(e) =>
                  setLinkDraft({ ...linkDraft, slug: e.target.value })
                }
                placeholder="例如 welcome"
                maxLength={32}
                required
                disabled={Boolean(originalSlug)}
              />
              <small>
                它是网址最后一段，例如
                /welcome；可用字母、数字、下划线或连字符。
              </small>
            </label>
            <div className="form-divider" />
            <div className="mode-switch" role="group" aria-label="地址来源">
              <button
                type="button"
                className={!linkDraft.poolId ? "selected" : ""}
                onClick={() => setLinkDraft({ ...linkDraft, poolId: "" })}
              >
                手动填写
              </button>
              <button
                type="button"
                className={linkDraft.poolId ? "selected" : ""}
                disabled={!state.pools?.length}
                onClick={() =>
                  setLinkDraft({
                    ...linkDraft,
                    poolId: linkDraft.poolId || state.pools?.[0]?.id || "",
                  })
                }
              >
                平台地址
              </button>
            </div>
            {!state.pools?.length && (
              <p className="form-note">
                如需使用平台地址，请先到「平台地址」添加一组地址。
              </p>
            )}
            {linkDraft.poolId ? (
              <>
                <label>
                  平台地址
                  <select
                    value={linkDraft.poolId}
                    onChange={(e) =>
                      setLinkDraft({ ...linkDraft, poolId: e.target.value })
                    }
                  >
                    {(state.pools || []).map((pool) => (
                      <option key={pool.id} value={pool.id}>
                        {pool.name}
                      </option>
                    ))}
                  </select>
                </label>
                <label>
                  此链接的邀请码
                  <input
                    value={linkDraft.code}
                    onChange={(e) =>
                      setLinkDraft({ ...linkDraft, code: e.target.value })
                    }
                    maxLength={128}
                    placeholder="例如 member_01"
                    required
                  />
                </label>
                <p className="form-note">
                  这条链接使用选中的平台地址，并保留自己的邀请码。更改平台地址后，关联链接会一起更新。
                </p>
              </>
            ) : (
              <>
                <label>
                  中国大陆打开的网址
                  <input
                    type="url"
                    value={linkDraft.cnUrl}
                    onChange={(e) =>
                      setLinkDraft({ ...linkDraft, cnUrl: e.target.value })
                    }
                    placeholder="https://example.com/zh"
                    required
                  />
                </label>
                <label>
                  其他地区打开的网址
                  <input
                    type="url"
                    value={linkDraft.defaultUrl}
                    onChange={(e) =>
                      setLinkDraft({ ...linkDraft, defaultUrl: e.target.value })
                    }
                    placeholder="https://example.com/en"
                    required
                  />
                </label>
              </>
            )}
            <p className="form-note">保存前先核对网址和修改范围。</p>
          </form>
        </Dialog>
      )}
      {domainOpen && (
        <Dialog
          title="添加域名"
          eyebrow="DOMAIN SETUP"
          error={domainErrorMessage(error)}
          errorAction={domainRecoveryActions()}
          status={
            domainFeedback ? (
              <div
                role={domainFeedback.tone === "error" ? "alert" : "status"}
                className={`domain-feedback ${domainFeedback.tone}`}
              >
                <span>{domainFeedback.message}</span>
                {domainFeedback.tone === "error" && domainRecoveryActions()}
              </div>
            ) : domainBusy ? (
              <div role="status" className="domain-feedback progress">
                <span>
                  上一项检查仍在进行，请完成或取消系统授权后稍候。
                </span>
              </div>
            ) : undefined
          }
          onClose={closeDomain}
          wide
          footer={
            <>
              <button className="button ghost" onClick={closeDomain}>
                取消
              </button>
              {preflight?.canApply && preflight.plan ? (
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
                    : preflight || dnsPreflight
                      ? "重新检查当前状态"
                      : "检查并接入"}
                </button>
              )}
            </>
          }
        >
          <form
            id="domain-form"
            onSubmit={(e) => void checkDomain(e)}
            className="form-grid"
          >
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
                多账户时，刷新域名列表前必须先选择账户；更换账户后需重新检查。
              </small>
            </label>
            {state.accounts.length > 1 && !domainDraft.accountId && (
              <p className="inline-warning">
                有多个 Cloudflare 账户；刷新域名列表前请先选择一个账户。
              </p>
            )}
            <div className="form-two">
              <label>
                域名
                <input
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
                  value={domainDraft.prefix}
                  onChange={(e) => {
                    setDomainDraft({ ...domainDraft, prefix: e.target.value });
                    invalidateDomainPreparation();
                  }}
                  maxLength={12}
                  required
                />
                <small>
                  示例链接：https://{domainExampleHost}/{domainExamplePrefix}
                  /名称
                </small>
              </label>
            </div>
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
            <p className="form-note">
              带 www 和不带 www
              的域名需要分别添加。未启用域名不会出现在可选列表中。
            </p>
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
      {plan && (
        <Dialog
          title={plan.title}
          eyebrow="REVIEW & CONFIRM"
          error={error}
          onClose={returnFromPlan}
          dismissDisabled={busy && planKind === "fix_domain_dns"}
          footer={
            <>
              <button
                className="button ghost"
                onClick={returnFromPlan}
                disabled={busy && planKind === "fix_domain_dns"}
              >
                返回
              </button>
              <button
                className="button primary"
                onClick={() => void apply()}
                disabled={busy || Date.parse(plan.expiresAt) < Date.now()}
              >
                {busy
                  ? "正在提交…"
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
            <p>应用将再次检查账户归属和当前状态，然后执行以下步骤：</p>
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
            <small>
              请在 {formatDate(plan.expiresAt)} 前确认；超时后需重新核对。
            </small>
          </div>
        </Dialog>
      )}
      {tokenOpen && (
        <Dialog
          title={updateTokenAccount ? "更新访问令牌" : "导入访问令牌"}
          eyebrow="ACCOUNT ACCESS"
          error={error}
          onClose={() => {
            resumeDomainAfterToken.current = false;
            setTokenOpen(false);
            setToken("");
            setClipboardOffer("");
            setUpdateTokenAccount(null);
          }}
          footer={
            <>
              <button
                className="button ghost"
                onClick={() => {
                  resumeDomainAfterToken.current = false;
                  setTokenOpen(false);
                  setToken("");
                  setClipboardOffer("");
                  setUpdateTokenAccount(null);
                }}
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
                    ? "验证并更新"
                    : "验证并导入"}
              </button>
            </>
          }
        >
          <form
            id="token-form"
            className="form-grid"
            onSubmit={(e) => void importToken(e)}
          >
            {updateTokenAccount ? (
              <p className="form-note">
                将只更新{" "}
                <strong>
                  {updateTokenAccount.cloudflareName ||
                    updateTokenAccount.label}
                </strong>
                （账户 ID：…{updateTokenAccount.id.slice(-8)}
                ）的本机令牌。令牌必须包含这个 Cloudflare 账户，否则不会保存。
              </p>
            ) : (
              <p className="form-note">
                先在浏览器登录要连接的 Cloudflare 账户，再创建 API
                令牌并粘贴到这里。软件会向 Cloudflare
                验证令牌，并交给操作系统保存。
              </p>
            )}
            <button
              className="button bordered opener"
              type="button"
              onClick={() => void openTemplate()}
            >
              <ArrowSquareOut size={17} />
              在系统浏览器中打开令牌模板
            </button>
            <label>
              访问令牌
              <input
                type="password"
                autoComplete="off"
                value={token}
                onChange={(e) => setToken(e.target.value)}
                onFocus={() => void checkClipboard()}
                placeholder="在此粘贴令牌"
                required
              />
            </label>
            {clipboardOffer && (
              <div className="clipboard-offer">
                <Clipboard size={18} />
                <span>检测到可能的访问令牌，是否填入？</span>
                <button
                  type="button"
                  onClick={() => {
                    setToken(clipboardOffer);
                    setClipboardOffer("");
                  }}
                >
                  填入
                </button>
                <button
                  type="button"
                  aria-label="忽略剪贴板"
                  onClick={() => setClipboardOffer("")}
                >
                  <X size={15} />
                </button>
              </div>
            )}
            <label className="checkbox-row">
              <input
                type="checkbox"
                checked={replaceToken}
                onChange={(e) => setReplaceToken(e.target.checked)}
                disabled={Boolean(updateTokenAccount)}
              />
              <span>
                {updateTokenAccount
                  ? "只替换这个账户的本机令牌"
                  : "若账户已存在，确认替换本机保存的令牌"}
              </span>
            </label>
          </form>
        </Dialog>
      )}
      {renameAccount && (
        <Dialog
          title="重命名账户"
          error={error}
          onClose={() => setRenameAccount(null)}
          footer={
            <>
              <button
                className="button ghost"
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
            id="rename-form"
            onSubmit={(e) => void doRename(e)}
            className="form-grid"
          >
            <label>
              账户名称
              <input
                value={renameValue}
                onChange={(e) => setRenameValue(e.target.value)}
                maxLength={60}
                required
              />
            </label>
            <p className="form-note">名称只用于本机识别，不修改远端账户。</p>
          </form>
        </Dialog>
      )}
      {removeAccount && (
        <Dialog
          title="从本机移除账户"
          error={error}
          onClose={() => setRemoveAccount(null)}
          footer={
            <>
              <button
                className="button ghost"
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
            ”的本机凭据和关联记录。此操作不会删除云端短链接服务；如需删除，请先在账户管理中选择“删除云端短链接服务”。
          </p>
        </Dialog>
      )}
      {manageAccount && (
        <Dialog
          title="账户管理"
          eyebrow="CLOUDFLARE ACCOUNT"
          error={error}
          onClose={() => setManageAccount(null)}
          footer={
            <button
              className="button ghost"
              onClick={() => setManageAccount(null)}
            >
              完成
            </button>
          }
        >
          <div className="account-manager">
            <div className="account-identity">
              <strong>
                {manageAccount.cloudflareName || manageAccount.label}
              </strong>
              {manageAccount.cloudflareName && (
                <span>本机备注：{manageAccount.label}</span>
              )}
              <span>账户 ID：…{manageAccount.id.slice(-8)}</span>
              <details>
                <summary>查看完整账户 ID</summary>
                <code>{manageAccount.id}</code>
              </details>
            </div>
            <div className="manager-actions">
              <button
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
                更新访问令牌
              </button>
              <button
                className="button secondary"
                onClick={() => {
                  setRenameAccount(manageAccount);
                  setRenameValue(manageAccount.label);
                  setManageAccount(null);
                }}
              >
                修改本机备注
              </button>
              {!manageAccount.monitorEnabled && (
                <button
                  className="button secondary"
                  onClick={() => {
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
            <div className="danger-zone">
              <strong>危险操作</strong>
              <p>
                删除云端短链接服务会删除此账户中由本应用管理的
                Worker、路由和短链接数据；不会删除其他网站或 DNS 记录。
              </p>
              <button
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
                className="button danger-button"
                onClick={() => {
                  setRemoveAccount(manageAccount);
                  setManageAccount(null);
                }}
              >
                从本机移除
              </button>
            </div>
          </div>
        </Dialog>
      )}
      {monitorAccount && (
        <Dialog
          title="配置检测服务"
          eyebrow="OPTIONAL MONITOR"
          error={error}
          onClose={() => {
            setMonitorAccount(null);
            setMonitorSecret("");
          }}
          footer={
            <>
              <button
                className="button ghost"
                onClick={() => {
                  setMonitorAccount(null);
                  setMonitorSecret("");
                }}
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
                value={monitorEndpoint}
                onChange={(e) => setMonitorEndpoint(e.target.value)}
                placeholder="https://probe.example.com/check"
                required
              />
            </label>
            <label>
              服务密钥
              <input
                type="password"
                autoComplete="off"
                value={monitorSecret}
                onChange={(e) => setMonitorSecret(e.target.value)}
                required
              />
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
          onClose={() => {
            setTestResult(null);
            setTargetResult(null);
          }}
          footer={
            <button
              className="button primary"
              onClick={() => {
                setTestResult(null);
                setTargetResult(null);
              }}
            >
              完成
            </button>
          }
        >
          <div className="test-result">
            <div className="test-url">{testResult.url}</div>
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
                    来源：{targetSourceLabel()} · {formatDate(c.checkedAt)}
                  </small>
                </span>
              </div>
            ))}
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
      {updateStatus && (
        <Dialog
          title="应用更新"
          eyebrow="DESKTOP UPDATE"
          error={error}
          onClose={() => setUpdateStatus(null)}
          footer={
            <>
              <button
                className="button ghost"
                onClick={() => setUpdateStatus(null)}
              >
                {updateStatus.status === "available" ? "稍后再说" : "关闭"}
              </button>
              {updateStatus.status === "available" && (
                <button
                  className="button primary"
                  onClick={() => void installUpdate()}
                  disabled={busy}
                >
                  {busy ? "正在安装…" : "确认安装更新"}
                </button>
              )}
            </>
          }
        >
          <div className="update-result">
            {updateStatus.status === "unavailable" ? (
              <p>
                当前版本：<strong>{currentVersion || "未提供"}</strong>
                。更新渠道尚未启用，请使用正式发行渠道获取新版本。
              </p>
            ) : updateStatus.status === "up_to_date" ? (
              <p>
                当前已是最新版本（
                <strong>{currentVersion || "版本未提供"}</strong>）。
              </p>
            ) : (
              <>
                <p>
                  当前版本：<strong>{currentVersion || "未提供"}</strong>
                  ；发现新版本{" "}
                  <strong>{updateStatus.version || "可用更新"}</strong>
                  。安装后应用可能会重启。
                </p>
                {updateStatus.notes && (
                  <div className="update-notes">{updateStatus.notes}</div>
                )}
              </>
            )}
          </div>
        </Dialog>
      )}
    </div>
  );
}
