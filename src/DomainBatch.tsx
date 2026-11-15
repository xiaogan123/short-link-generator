import { useMemo, useRef, useState } from "react";
import { MagnifyingGlass } from "@phosphor-icons/react";
import Dialog from "./Dialog";
import { dispatch, errorMessage } from "./bridge";
import { validatePrefix } from "./validators";
import { FieldError, fieldProps, focusFirstError } from "./FormFeedback";
import "./DomainBatch.css";
import type {
  Account,
  Action,
  Domain,
  DomainCheck,
  DomainDnsPreparation,
  DomainPreparation,
  Plan,
  State,
} from "./types";

/* ------------------------------------------------------------------ */
/* Execution logic: one domain at a time, no React.                    */
/* ------------------------------------------------------------------ */

export type BatchPhase = "waiting" | "checking" | "dns" | "applying" | "added" | "skipped" | "failed";
/**
 * `authorization` is set on a failure that came from the account's authorization
 * (saved credential on this computer, or Cloudflare refusing the token); the next
 * domain of the same account would only repeat it.
 */
export type BatchOutcome = { phase: "added" } | { phase: "skipped" | "failed"; reason: string; authorization?: boolean };
export type BatchCall = <T>(action: Action, payload: Record<string, unknown>) => Promise<T>;
/** Shared by every domain of one batch: once switched to public DNS, later domains start there. */
export type BatchNetwork = { mode: "system" | "public" };
export type BatchOptions = {
  call: BatchCall;
  accountId: string;
  prefix: string;
  /** Create a placeholder record when the host has no website record at all. */
  autoDns: boolean;
  network: BatchNetwork;
  sleep?: (ms: number) => Promise<void>;
  onPhase?: (phase: "checking" | "dns" | "applying") => void;
  onState?: (state: State) => void;
  onPublicDns?: () => void;
  /** Public DNS could not be reached and the local network answered normally again. */
  onSystemDns?: () => void;
  onAdded?: (info: { host: string; prefix: string; accountId: string; dnsMode: "system" | "public" }) => void;
};

export const BATCH_REASONS = {
  takeover: "目录下已有网页，请单独添加并确认",
  proxy: "已有解析但没开代理，会影响现有网站，请单独添加",
  noDns: "还没有网站解析，请在「添加域名」里单独添加",
  certPending: "解析已补好，证书还没生效，过几分钟在「添加域名」里再加一次",
  // A fresh placeholder has no website behind it, so "目录下已有网页" would be wrong here.
  confirmAfterDns: "解析已补好，但接入前还要你确认一次。请在「添加域名」里再加一次这个域名，按提示确认",
};

// Reasons that mean "the network lookup did not finish", not "the domain is wrong".
const networkReasons = ["virtual_dns_address", "dns_timeout", "dns_failed", "public_dns_timeout", "public_dns_failed", "cloud_unreachable", "probe_timeout", "probe_transport_error"];
// Right after this batch wrote a placeholder record, a lookup may still see the old empty
// answer: that is the same "wait a little" case as a network hiccup, not a wrong domain.
const freshRecordReasons = [...networkReasons, "dns_no_answer", "public_dns_invalid_response"];
// DomainCheck.reason values the backend sets when a check failed on the account's authorization:
// "credential" = this computer could not use the saved authorization (本机授权 / 凭据),
// "cloud_refused" = a Cloudflare API read answered HTTP 401 or 403.
const authorizationReasons = ["credential", "cloud_refused"];
const NETWORK_RETRIES = 2;
const BUSY_RETRIES = 3;
const PLAN_KEPT_RETRIES = 2;
/** Marker in an apply_plan error: the plan was kept and its id may be confirmed again (docs/CONTRACT.md). */
const PLAN_KEPT = "接入计划仍然有效";
const CERT_WAITS = 3;

function level(check: DomainCheck) {
  return check.level || (check.ok ? "pass" : "error");
}
function errorsOf(checks: DomainCheck[]) {
  return checks.filter((check) => level(check) === "error");
}
function onlyVirtualAddress(result: DomainPreparation) {
  const errors = errorsOf(result.checks);
  return !result.canApply && errors.length > 0 && errors.every((check) => check.reason === "virtual_dns_address");
}
function onlyPublicDnsFailure(result: DomainPreparation) {
  const errors = errorsOf(result.checks);
  return !result.canApply && errors.length > 0 &&
    errors.every((check) => check.reason === "public_dns_timeout" || check.reason === "public_dns_failed");
}
function onlyReasons(checks: DomainCheck[], reasons: string[]) {
  const errors = errorsOf(checks);
  return errors.length > 0 && errors.every((check) => reasons.includes(check.reason || ""));
}
function onlyNetwork(checks: DomainCheck[]) {
  return onlyReasons(checks, networkReasons);
}
/** True when a failing error-level check has an authorization reason (credential / cloud_refused). */
export function authorizationCheck(checks: DomainCheck[]) {
  return errorsOf(checks).some((check) => authorizationReasons.includes(check.reason || ""));
}
function aboutDnsRecord(checks: DomainCheck[]) {
  const errors = errorsOf(checks);
  return errors.length > 0 && errors.every((check) => /dns|解析|代理/i.test(check.label));
}
function onlyDnsRecord(result: DomainPreparation) {
  return aboutDnsRecord(result.checks);
}
function describe(check: DomainCheck | undefined) {
  return check ? `${check.label}：${check.message}` : "检查没通过";
}
const SINGLE_ADD_STEP = "请在「添加域名」里单独查看这个域名";
const RETRY_STEP = "稍后点「把失败的再试一次」";
/**
 * A backend text (a failed check, or the error of a rejected call), with a next step when it
 * does not already say what to do: the result summary promises one on every row.
 */
function withNextStep(text: string, step = SINGLE_ADD_STEP) {
  if (/请|稍后|再试|再点|再加一次/.test(text)) return text;
  return `${text.replace(/[。．.；;，,\s]+$/, "")}。${step}。`;
}
export function isBusyError(message: string) {
  return /^上一个操作(还没结束|仍在进行)/.test(message.trim());
}
// Texts of the backend's credential and keychain errors (lib.rs require_credentials /
// read_account_token, secret_store.rs SecretError) when a call is rejected outright.
const credentialErrorTexts = [
  "本机授权",
  "系统凭据库",
  "系统授权未完成",
  "令牌导入尚未完成",
  "旧访问令牌缺失",
];
/**
 * True when a rejected backend call (not a check) is about the account's authorization:
 * a keychain or re-authorization failure, or Cloudflare answering HTTP 401/403. A website
 * answering 401/403 on the probed path ("此路径返回 HTTP 403") is not, and neither is the
 * token advice that follows an HTTP 400/404.
 */
export function isAuthorizationError(message: string) {
  if (isBusyError(message)) return false;
  const text = message.replace(/此路径返回 HTTP \d+/g, "");
  return /HTTP 40[13](?!\d)/.test(text) || credentialErrorTexts.some((part) => text.includes(part));
}
function failure(reason: string, authorization: boolean): BatchOutcome {
  return authorization ? { phase: "failed", reason, authorization: true } : { phase: "failed", reason };
}
// One such failure may concern a single domain; two in a row mean the account itself.
const AUTHORIZATION_FAILURES_BEFORE_STOP = 2;
const wait = (ms: number) => new Promise<void>((resolve) => window.setTimeout(resolve, ms));

class StepFailure extends Error {}

/** Adds one domain with the same steps as the single "添加域名" flow. Never throws. */
export async function processBatchDomain(host: string, options: BatchOptions): Promise<BatchOutcome> {
  const sleep = options.sleep || wait;
  // The backend allows one domain command at a time: a busy reply is only a reason to wait.
  async function call<T>(action: Action, payload: Record<string, unknown>): Promise<T> {
    for (let attempt = 0; ; attempt++) {
      try {
        return await options.call<T>(action, payload);
      } catch (error) {
        const message = errorMessage(error);
        if (isBusyError(message) && attempt < BUSY_RETRIES) {
          await sleep(3000);
          continue;
        }
        throw new StepFailure(message);
      }
    }
  }
  async function prepare(): Promise<DomainPreparation> {
    const request = () => call<DomainPreparation>("prepare_domain", {
      input: host,
      prefix: options.prefix,
      accountId: options.accountId,
      dnsMode: options.network.mode,
    });
    let result = await request();
    if (options.network.mode === "public" && !localNetworkTried && onlyPublicDnsFailure(result)) {
      // The VPN may be off again or public DNS unreachable: ask the local network once for this domain.
      localNetworkTried = true;
      const publicResult = result;
      options.network.mode = "system";
      result = await request();
      if (onlyVirtualAddress(result)) {
        // The VPN is still on, so only public DNS can answer: keep it and report its failure.
        options.network.mode = "public";
        return publicResult;
      }
      options.onSystemDns?.();
      return result;
    }
    if (options.network.mode === "system" && onlyVirtualAddress(result)) {
      // A VPN answered with a virtual address: switch this batch to public DNS for good.
      options.network.mode = "public";
      options.onPublicDns?.();
      result = await request();
    }
    return result;
  }
  async function apply(plan: Plan): Promise<BatchOutcome> {
    options.onPhase?.("applying");
    for (let attempt = 0; ; attempt++) {
      try {
        const next = await call<State>("apply_plan", { planId: plan.id });
        options.onState?.(next);
        options.onAdded?.({ host, prefix: options.prefix, accountId: options.accountId, dnsMode: options.network.mode });
        return { phase: "added" };
      } catch (error) {
        const message = errorMessage(error);
        // Only a network-only review keeps the plan; the same plan id may be confirmed again.
        if (message.includes(PLAN_KEPT) && attempt < PLAN_KEPT_RETRIES) {
          await sleep(2000);
          continue;
        }
        // The backend text ends with "再点一次确认", a button this window does not have.
        const kept = message.indexOf(PLAN_KEPT);
        if (kept >= 0) return { phase: "failed", reason: `${message.slice(0, kept)}云端没有任何改动，稍后点「把失败的再试一次」。` };
        return failure(withNextStep(message), isAuthorizationError(message));
      }
    }
  }

  let networkRetries = 0;
  let localNetworkTried = false;
  let certWaits = 0;
  let dnsFixed = false;
  let dnsReadyRechecked = false;
  try {
    for (;;) {
      options.onPhase?.("checking");
      const result = await prepare();
      if (result.canApply && result.plan) {
        // Taking over an existing web directory always needs the user's own confirmation.
        if (result.plan.domainTakeoverConfirmation)
          return { phase: "skipped", reason: dnsFixed ? BATCH_REASONS.confirmAfterDns : BATCH_REASONS.takeover };
        return await apply(result.plan);
      }
      const errors = errorsOf(result.checks);
      if (!result.canApply && dnsFixed && onlyReasons(result.checks, freshRecordReasons)) {
        // A fresh placeholder record needs a few minutes before lookups and its certificate work.
        if (certWaits < CERT_WAITS) {
          certWaits += 1;
          await sleep(5000);
          continue;
        }
        return { phase: "failed", reason: BATCH_REASONS.certPending };
      }
      if (!result.canApply && onlyNetwork(result.checks)) {
        if (networkRetries < NETWORK_RETRIES) {
          networkRetries += 1;
          await sleep(2000);
          continue;
        }
        return { phase: "failed", reason: withNextStep(errors[0].message, RETRY_STEP) };
      }
      if (!result.canApply && !dnsFixed && onlyDnsRecord(result)) {
        // Read-only: tells "no website record" apart from "record without proxy".
        options.onPhase?.("dns");
        const dns = await call<DomainDnsPreparation>("prepare_domain_dns", { input: host, accountId: options.accountId });
        if (dns.dnsStatus === "ready") {
          if (dnsReadyRechecked) return { phase: "failed", reason: "解析已经就绪，但接入检查还没通过，请在「添加域名」里单独查看" };
          dnsReadyRechecked = true;
          continue;
        }
        const placeholderOnly = dns.dnsStatus === "missing" && dns.actions.length > 0 &&
          dns.actions.every((action) => action.kind === "createPlaceholder");
        if (dns.actions.some((action) => action.kind !== "createPlaceholder"))
          return { phase: "skipped", reason: BATCH_REASONS.proxy };
        if (placeholderOnly && !options.autoDns) return { phase: "skipped", reason: BATCH_REASONS.noDns };
        if (placeholderOnly && dns.canApply && dns.plan) {
          try {
            const next = await call<State>("apply_plan", { planId: dns.plan.id });
            options.onState?.(next);
          } catch (error) {
            const message = errorMessage(error);
            return failure(withNextStep(`补解析没成功：${message}`), isAuthorizationError(message));
          }
          dnsFixed = true;
          continue;
        }
        const dnsErrors = errorsOf(dns.checks);
        if (dnsErrors.length && onlyNetwork(dns.checks)) {
          if (networkRetries < NETWORK_RETRIES) {
            networkRetries += 1;
            await sleep(2000);
            continue;
          }
          return { phase: "failed", reason: withNextStep(dnsErrors[0].message, RETRY_STEP) };
        }
        // A read Cloudflare refused is about the account, whatever status came with it.
        if (authorizationCheck(dns.checks)) return failure(withNextStep(describe(dnsErrors[0])), true);
        // "conflict" is also the backend's value when it never got to read the records.
        const recordConflict = (dns.dnsStatus === "conflict" || dns.dnsStatus === "unsupported") && aboutDnsRecord(dns.checks);
        if (recordConflict) return {
          phase: "skipped",
          reason: `解析情况比较复杂（${describe(dnsErrors[0])}），请在「添加域名」里单独处理`,
        };
        // A read that did not finish (network, authorization) is worth another try.
        const shown = dnsErrors.length ? dns.checks : result.checks;
        return failure(withNextStep(describe(dnsErrors[0] || errors[0])), authorizationCheck(shown));
      }
      return failure(withNextStep(describe(errors[0])), authorizationCheck(result.checks));
    }
  } catch (error) {
    const message = errorMessage(error);
    return failure(withNextStep(message), isAuthorizationError(message));
  }
}

/**
 * Runs the hosts one after another; a stop request takes effect after the current host.
 * Two authorization failures in a row end the run early, so a broken token does not
 * fail (and ask the system keychain for) every remaining domain.
 */
export async function runDomainBatch(
  hosts: string[],
  options: BatchOptions & {
    shouldStop: () => boolean;
    onUpdate: (host: string, phase: BatchPhase, reason?: string) => void;
  },
): Promise<{ authorizationStopped: boolean }> {
  let authorizationFailures = 0;
  for (const [index, host] of hosts.entries()) {
    if (options.shouldStop()) break;
    options.onUpdate(host, "checking");
    const outcome = await processBatchDomain(host, {
      ...options,
      onPhase: (phase) => options.onUpdate(host, phase),
    });
    options.onUpdate(host, outcome.phase, outcome.phase === "added" ? undefined : outcome.reason);
    authorizationFailures = outcome.phase === "failed" && outcome.authorization ? authorizationFailures + 1 : 0;
    if (authorizationFailures >= AUTHORIZATION_FAILURES_BEFORE_STOP && index < hosts.length - 1)
      return { authorizationStopped: true };
  }
  return { authorizationStopped: false };
}

/* ------------------------------------------------------------------ */
/* Dialog                                                              */
/* ------------------------------------------------------------------ */

/** "stopped": chosen, but the batch was stopped before its turn; a retry of failures leaves it alone. */
type Row = { host: string; phase: BatchPhase | "stopped"; reason?: string };
type Step = "select" | "confirm" | "running" | "done";
type Feedback = { tone: "progress" | "success" | "error" | "warning"; message: string } | null;

const prefixChoices = ["go", "out", "to", "visit", "link", "r", "jump"];
const phaseLabels: Record<Row["phase"], string> = {
  waiting: "等待",
  checking: "检查中",
  dns: "补解析中",
  applying: "接入中",
  added: "已接入",
  skipped: "已跳过",
  failed: "失败",
  stopped: "没处理（已停止）",
};

type Props = {
  accounts: Account[];
  domains: Domain[];
  /** Public DNS when an earlier check in this session already met a VPN virtual address. */
  initialDnsMode: () => "system" | "public";
  /** Takes the app-wide operation lock; false while another operation is running. */
  begin: () => boolean;
  end: () => void;
  onState: (state: State) => void;
  onPublicDns: () => void;
  onSystemDns?: () => void;
  onAdded: BatchOptions["onAdded"];
  onClose: () => void;
};

export default function DomainBatch({ accounts, domains, initialDnsMode, begin, end, onState, onPublicDns, onSystemDns, onAdded, onClose }: Props) {
  const [accountId, setAccountId] = useState(accounts.length === 1 ? accounts[0].id : "");
  const [prefix, setPrefix] = useState(() => prefixChoices[crypto.getRandomValues(new Uint32Array(1))[0] % prefixChoices.length]);
  const [autoDns, setAutoDns] = useState(true);
  const [search, setSearch] = useState("");
  const [selected, setSelected] = useState<ReadonlySet<string>>(() => new Set());
  const [step, setStep] = useState<Step>("select");
  const [rows, setRows] = useState<Row[]>([]);
  const [feedback, setFeedback] = useState<Feedback>(null);
  const [prefixError, setPrefixError] = useState("");
  const [refreshing, setRefreshing] = useState(false);
  const [stopping, setStopping] = useState(false);
  // The last run ended early because the account's authorization kept failing.
  const [authorizationStopped, setAuthorizationStopped] = useState(false);
  const stopRequested = useRef(false);
  const network = useRef<BatchNetwork | null>(null);
  const runSettings = useRef({ accountId: "", prefix: "", autoDns: true });

  const account = accounts.find((item) => item.id === accountId);
  const blockedAccount = account && (account.needsTokenRecovery || account.needsCredentialMigration);
  const addedHosts = useMemo(() => new Set(domains.map((domain) => domain.host)), [domains]);
  const available = useMemo(
    () => (account?.zones || [])
      .filter((zone) => zone.status === "active" && !addedHosts.has(zone.name))
      .map((zone) => zone.name)
      .sort((left, right) => left.localeCompare(right)),
    [account, addedHosts],
  );
  const visible = available.filter((host) => host.includes(search.trim().toLowerCase()));
  const chosen = available.filter((host) => selected.has(host));
  const running = step === "running";

  function chooseAccount(id: string) {
    setAccountId(id);
    setSelected(new Set());
    setSearch("");
    setFeedback(null);
  }
  function toggle(host: string, on: boolean) {
    setSelected((current) => {
      const next = new Set(current);
      if (on) next.add(host);
      else next.delete(host);
      return next;
    });
  }
  async function refresh() {
    if (!accountId || refreshing) return;
    if (!begin()) {
      setFeedback({ tone: "warning", message: "上一个操作还没结束，请稍后再点一次。" });
      return;
    }
    setRefreshing(true);
    setFeedback({ tone: "progress", message: "正在读取这个账户的域名，请稍候。" });
    try {
      const next = await dispatch<State>("refresh_domains", { accountId });
      onState(next);
      const refreshed = next.accounts.find((item) => item.id === accountId);
      setFeedback({ tone: "success", message: `已读取「${refreshed?.cloudflareName || refreshed?.label || "所选账户"}」的 ${refreshed?.zones?.length ?? refreshed?.zoneCount ?? 0} 个域名。` });
    } catch (error) {
      const message = errorMessage(error);
      setFeedback(isBusyError(message)
        ? { tone: "warning", message: "上一个操作还没结束，请稍后再点一次。" }
        : { tone: "error", message: `没能读取这个账户的域名：${message}` });
    } finally {
      setRefreshing(false);
      end();
    }
  }
  function review() {
    const error = validatePrefix(prefix);
    setPrefixError(error || "");
    if (error) {
      focusFirstError({ "batch-prefix": error });
      return;
    }
    if (!account) {
      setFeedback({ tone: "error", message: "请先选一个 Cloudflare 账户。" });
      return;
    }
    if (!chosen.length) {
      setFeedback({ tone: "error", message: "请至少勾选一个域名。" });
      return;
    }
    setFeedback(null);
    setStep("confirm");
  }
  async function execute(hosts: string[]) {
    if (!begin()) {
      setFeedback({ tone: "warning", message: "上一个操作还没结束，请稍后再点开始。" });
      return;
    }
    stopRequested.current = false;
    setStopping(false);
    setAuthorizationStopped(false);
    setFeedback(null);
    network.current ||= { mode: initialDnsMode() };
    setRows((current) => {
      const retry = new Set(hosts);
      const base = current.length ? current : hosts.map((host) => ({ host, phase: "waiting" as const }));
      return base.map((row) => retry.has(row.host) ? { host: row.host, phase: "waiting" } : row);
    });
    setStep("running");
    try {
      const result = await runDomainBatch(hosts, {
        call: dispatch,
        ...runSettings.current,
        network: network.current,
        onState,
        onPublicDns,
        onSystemDns,
        onAdded,
        shouldStop: () => stopRequested.current,
        onUpdate: (host, phase, reason) =>
          setRows((current) => current.map((row) => row.host === host ? { host, phase, reason } : row)),
      });
      setAuthorizationStopped(result.authorizationStopped);
    } finally {
      end();
      setStopping(false);
      setRows((current) => current.map((row) => row.phase === "waiting" ? { ...row, phase: "stopped" } : row));
      setStep("done");
    }
  }
  function start() {
    runSettings.current = { accountId, prefix, autoDns };
    setRows([]);
    void execute(chosen);
  }
  function retryFailed() {
    void execute(rows.filter((row) => row.phase === "failed").map((row) => row.host));
  }
  /** Runs the rows a stop left untouched, with the settings of this run. */
  function continueStopped() {
    void execute(rows.filter((row) => row.phase === "stopped").map((row) => row.host));
  }

  const counts = {
    added: rows.filter((row) => row.phase === "added").length,
    skipped: rows.filter((row) => row.phase === "skipped").length,
    failed: rows.filter((row) => row.phase === "failed").length,
    stopped: rows.filter((row) => row.phase === "stopped").length,
  };
  const current = rows.find((row) => row.phase === "checking" || row.phase === "dns" || row.phase === "applying");

  const status = feedback ? (
    <div role={feedback.tone === "error" ? "alert" : "status"} className={`domain-feedback ${feedback.tone}`}>
      <span>{feedback.message}</span>
    </div>
  ) : running ? (
    <div role="status" className="domain-feedback progress">
      <span>
        {stopping ? "收到，做完当前这个就停。" : `正在处理${current ? ` ${current.host}` : ""}，已处理完 ${counts.added + counts.skipped + counts.failed} / ${rows.length - counts.stopped} 个。处理期间不能关闭这个窗口，要中途结束请点「停止」。`}
      </span>
    </div>
  ) : step === "done" ? (
    <div role="status" className={`domain-feedback ${counts.failed ? "warning" : "success"}`}>
      <span>
        已接入 {counts.added} 个、跳过 {counts.skipped} 个、失败 {counts.failed} 个
        {counts.stopped ? `，还有 ${counts.stopped} 个因为停止没有处理` : ""}。
        {authorizationStopped
          // The dialog is modal: only a fix that needs no other page (a keychain prompt) can be
          // followed by 继续; a token problem means closing it. The select step never lists added hosts.
          ? `这个账户的授权连续出错，后面的域名没有再试。如果屏幕上有系统的钥匙串窗口，先处理它，再点「继续没处理的（${counts.stopped} 个）」和「把失败的再试一次」。如果只是失败的这几个域名令牌没有权限，可以直接点「继续没处理的（${counts.stopped} 个）」接着处理后面的。如果是令牌本身的问题，请关掉这个窗口，到「Cloudflare 账户」页把这个账户的授权处理好，再重新批量添加，已经接入的域名不会再列出来。`
          : counts.skipped || counts.failed ? "每一行都写了原因和下一步该怎么做。" : ""}
      </span>
    </div>
  ) : undefined;

  const footer = step === "select" ? (
    <>
      <button type="button" className="button ghost" onClick={onClose}>取消</button>
      <button type="button" className="button primary" onClick={review} disabled={!chosen.length || !account || Boolean(blockedAccount) || refreshing}>
        开始添加（{chosen.length} 个）
      </button>
    </>
  ) : step === "confirm" ? (
    <>
      <button type="button" className="button ghost" onClick={() => setStep("select")}>返回修改</button>
      <button type="button" className="button primary" onClick={start}>确认开始</button>
    </>
  ) : running ? (
    <button type="button" className="button secondary" onClick={() => { stopRequested.current = true; setStopping(true); }} disabled={stopping}>
      {stopping ? "正在停止…" : "停止"}
    </button>
  ) : (
    <>
      {counts.failed > 0 && (
        <button type="button" className="button secondary" onClick={retryFailed}>把失败的再试一次</button>
      )}
      {counts.stopped > 0 && (
        <button type="button" className="button secondary" onClick={continueStopped}>继续没处理的（{counts.stopped} 个）</button>
      )}
      <button type="button" className="button primary" onClick={onClose}>关闭</button>
    </>
  );

  return (
    <Dialog
      title="批量添加域名"
      wide
      onClose={() => { if (!running) onClose(); }}
      dismissDisabled={running}
      hasUserInput={(step === "select" && chosen.length > 0) || step === "confirm" ||
        (step === "done" && counts.skipped + counts.failed + counts.stopped > 0)}
      escapeHint={step === "confirm"
        ? "再按一次 Esc 关闭窗口，已选的域名不会保留。"
        : step === "done" ? "再按一次 Esc 关闭窗口，这次每一行的结果不会保留。" : undefined}
      status={status}
      footer={footer}
    >
      {step === "select" && (
        <div className="domain-batch form-grid">
          <div className="form-two">
            <label>
              Cloudflare 账户
              <div className="domain-batch-account">
                <select value={accountId} onChange={(event) => chooseAccount(event.target.value)} disabled={refreshing} aria-label="Cloudflare 账户">
                  {accounts.length > 1 && <option value="">请选择账户</option>}
                  {accounts.map((item) => (
                    <option key={item.id} value={item.id}>{item.label}{item.cloudflareName ? `（${item.cloudflareName}）` : ""}</option>
                  ))}
                </select>
                <button type="button" className="button secondary" onClick={() => void refresh()} disabled={!accountId || refreshing || Boolean(blockedAccount)}>
                  {refreshing ? "正在读取…" : "刷新域名列表"}
                </button>
              </div>
            </label>
            <label>
              链接目录
              <input
                {...fieldProps("batch-prefix", prefixError ? { "batch-prefix": prefixError } : {})}
                value={prefix}
                maxLength={12}
                onChange={(event) => { setPrefix(event.target.value); setPrefixError(""); }}
              />
              {prefixError ? <FieldError name="batch-prefix" errors={{ "batch-prefix": prefixError }} /> : <small>所有选中的域名都用这个目录</small>}
            </label>
          </div>
          <label className="checkbox-row domain-batch-option">
            <input type="checkbox" checked={autoDns} onChange={(event) => setAutoDns(event.target.checked)} />
            域名还没有网站解析时，自动补一条占位解析并开启代理（不影响邮件等现有记录）
          </label>
          <p className="domain-batch-note">
            下面几种情况会跳过，需要回到「添加域名」单独处理：目录下已经有网页（要你单独确认接管）；已有解析但没开代理（开代理会影响现有网站）；解析情况比较复杂。其他检查没通过的会标成「失败」，并写明原因。
          </p>
          {blockedAccount ? (
            <div className="warning-box"><p>这个账户要先在「Cloudflare 账户」页更新授权或恢复令牌，处理好再来批量添加。</p></div>
          ) : !account ? (
            <p className="domain-batch-empty">请先选一个账户，下面会列出这个账户里还没接入的域名。</p>
          ) : (
            <div className="domain-batch-picker">
              <div className="domain-batch-tools">
                <div className="searchbox">
                  <MagnifyingGlass size={14} />
                  <input value={search} onChange={(event) => setSearch(event.target.value)} placeholder="搜索域名" aria-label="搜索域名" />
                </div>
                <button type="button" className="button ghost" disabled={!visible.length} onClick={() => setSelected((current) => new Set([...current, ...visible]))}>全选</button>
                <button type="button" className="button ghost" disabled={!selected.size} onClick={() => setSelected(new Set())}>全不选</button>
                <span className="domain-batch-count">已选 {chosen.length} / {available.length}</span>
              </div>
              <div className="domain-batch-list" role="group" aria-label="可添加的域名">
                {!available.length ? (
                  <p className="domain-batch-empty">
                    {(account.zones || []).length
                      ? "这个账户里已启用的域名都已经接入了。新买的域名请先点「刷新域名列表」。"
                      : "还没读到这个账户的域名，点「刷新域名列表」读取一次。"}
                  </p>
                ) : !visible.length ? (
                  <p className="domain-batch-empty">没有匹配的域名。</p>
                ) : visible.map((host) => (
                  <label key={host} className="domain-batch-item">
                    <input type="checkbox" checked={selected.has(host)} onChange={(event) => toggle(host, event.target.checked)} />
                    <span>{host}</span>
                  </label>
                ))}
              </div>
              <small className="domain-batch-hint">这里只列根域名。要加子域名（比如 go.example.com）请用「添加域名」。</small>
            </div>
          )}
        </div>
      )}
      {step === "confirm" && (
        <div className="domain-batch">
          <div className="plan-details">
            <div>账户：{account?.label}</div>
            <div>链接目录：/{prefix}/</div>
            <div>域名：{chosen.length} 个</div>
          </div>
          <p className="modal-paragraph">接下来会一个接一个处理下面这些域名：</p>
          <ul className="domain-batch-steps">
            <li>先检查域名，能接入的直接把「域名/{prefix}/」接到短链接服务。</li>
            {autoDns
              ? <li>还没有网站解析的，先补一条占位解析并开启代理，再试着接入；邮件等现有记录不动。补完后如果还要你确认一次，会留给你到「添加域名」里单独确认。</li>
              : <li>还没有网站解析的会跳过，不会改动解析。</li>}
            <li>目录下已有网页、已有解析但没开代理、或解析情况比较复杂的，会跳过，不做任何改动。</li>
            <li>其他检查没通过的会标成「失败」，写明原因和下一步。</li>
          </ul>
          <div className="domain-batch-list domain-batch-confirm" aria-label="将要处理的域名">
            {chosen.map((host) => <div key={host}>{host}/{prefix}/</div>)}
          </div>
        </div>
      )}
      {(step === "running" || step === "done") && (
        <div className="domain-batch">
          <ul className="domain-batch-list domain-batch-results" aria-label="处理结果">
            {rows.map((row) => (
              <li key={row.host} className={`batch-row batch-${row.phase}`}>
                <span className="batch-host">{row.host}</span>
                <span className="batch-state">
                  <strong>{phaseLabels[row.phase]}</strong>
                  {row.reason && <span className="batch-reason">{row.reason}</span>}
                </span>
              </li>
            ))}
          </ul>
        </div>
      )}
    </Dialog>
  );
}
