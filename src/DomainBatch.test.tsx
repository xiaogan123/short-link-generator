import { cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import DomainBatch, { BATCH_REASONS, isAuthorizationError, isBusyError, processBatchDomain, runDomainBatch, type BatchCall, type BatchNetwork } from "./DomainBatch";
import type { Account, DomainDnsPreparation, DomainPreparation, Plan, State } from "./types";

const control = vi.hoisted(() => ({
  calls: [] as { action: string; payload: Record<string, unknown> }[],
  handler: null as null | ((action: string, payload: Record<string, unknown>) => unknown),
}));
vi.mock("./bridge", () => ({
  preview: false,
  errorMessage: (error: unknown) => typeof error === "string" ? error : error instanceof Error ? error.message : "操作未完成，请重试。",
  dispatch: async (action: string, payload: Record<string, unknown> = {}) => {
    control.calls.push({ action, payload });
    if (!control.handler) throw new Error(`Unexpected ${action}`);
    return control.handler(action, payload);
  },
}));

afterEach(() => {
  cleanup();
  control.calls.length = 0;
  control.handler = null;
});

const future = () => new Date(Date.now() + 300000).toISOString();
const plan = (id: string, takeover = false): Plan => ({
  id, title: "添加域名", steps: [], warnings: [], expiresAt: future(),
  ...(takeover ? { domainTakeoverConfirmation: "确认接管 example.com/r/" } : {}),
});
const candidate = { accountId: "a", label: "示例账户", zoneId: "z", status: "active" };
const ready = (host: string, planId = `plan-${host}`, takeover = false): DomainPreparation => ({
  host, prefix: "r", candidates: [candidate], canApply: true, plan: plan(planId, takeover),
  checks: [{ label: "链接目录", ok: true, level: takeover ? "warning" : "pass", message: "可以接入" }],
});
const blocked = (host: string, checks: DomainPreparation["checks"]): DomainPreparation => ({
  host, prefix: "r", candidates: [candidate], canApply: false, checks,
});
const networkError = (host: string, reason = "probe_timeout") =>
  blocked(host, [{ label: "链接目录", ok: false, level: "error", reason, message: "访问检查超时" }]);
const virtualError = (host: string) =>
  blocked(host, [{ label: "DNS 查询", ok: false, level: "error", reason: "virtual_dns_address", message: "VPN 虚拟地址" }]);
const dnsError = (host: string) =>
  blocked(host, [{ label: "DNS", ok: false, level: "error", message: "还没有开启代理的网站解析" }]);
const dnsPlan = (host: string, kind: "createPlaceholder" | "enableProxy", status: DomainDnsPreparation["dnsStatus"]): DomainDnsPreparation => ({
  host, candidates: [candidate], dnsStatus: status, canApply: true, plan: plan(`dns-${host}`),
  checks: [{ label: "DNS", ok: true, level: "warning", message: "可以补齐" }],
  actions: [{ kind, recordType: "AAAA", name: host }],
});
const state = (hosts: string[] = []): State => ({
  accounts: [], links: [], pendingOperations: [], pendingActions: [],
  domains: hosts.map((host) => ({ id: host, accountId: "a", zoneId: "z", host, prefix: "r", routeId: `route-${host}` })),
});

/** A scripted backend: each action takes the next queued answer (an Error is thrown). */
function scripted(script: Record<string, unknown[]>) {
  const calls: { action: string; payload: Record<string, unknown> }[] = [];
  const call = (async (action: string, payload: Record<string, unknown>) => {
    calls.push({ action, payload });
    const queue = script[action];
    if (!queue?.length) throw new Error(`Unexpected ${action}`);
    const next = queue.length > 1 ? queue.shift() : queue[0];
    if (next instanceof Error) throw next;
    return typeof next === "function" ? next(payload) : next;
  }) as BatchCall;
  return { call, calls, actions: () => calls.map((item) => item.action) };
}
function options(call: BatchCall, extra: Partial<Parameters<typeof processBatchDomain>[1]> = {}) {
  return { call, accountId: "a", prefix: "r", autoDns: true, network: { mode: "system" } as BatchNetwork, sleep: vi.fn(async () => {}), ...extra };
}

describe("processBatchDomain", () => {
  it("adds a domain whose check passes and publishes the returned state", async () => {
    const backend = scripted({ prepare_domain: [ready("example.com")], apply_plan: [state(["example.com"])] });
    const onState = vi.fn();
    const onAdded = vi.fn();
    const outcome = await processBatchDomain("example.com", options(backend.call, { onState, onAdded }));
    expect(outcome).toEqual({ phase: "added" });
    expect(backend.calls).toEqual([
      { action: "prepare_domain", payload: { input: "example.com", prefix: "r", accountId: "a", dnsMode: "system" } },
      { action: "apply_plan", payload: { planId: "plan-example.com" } },
    ]);
    expect(onState).toHaveBeenCalledWith(state(["example.com"]));
    expect(onAdded).toHaveBeenCalledWith({ host: "example.com", prefix: "r", accountId: "a", dnsMode: "system" });
  });

  it("skips a directory that needs takeover consent and never confirms it", async () => {
    const backend = scripted({ prepare_domain: [ready("example.com", "p", true)] });
    const outcome = await processBatchDomain("example.com", options(backend.call));
    expect(outcome).toEqual({ phase: "skipped", reason: BATCH_REASONS.takeover });
    expect(backend.actions()).toEqual(["prepare_domain"]);
  });

  it("adds a placeholder record, checks again and then attaches the domain", async () => {
    const backend = scripted({
      prepare_domain: [dnsError("example.org"), ready("example.org", "domain-plan")],
      prepare_domain_dns: [dnsPlan("example.org", "createPlaceholder", "missing")],
      apply_plan: [state(), state(["example.org"])],
    });
    const phases: string[] = [];
    const outcome = await processBatchDomain("example.org", options(backend.call, { onPhase: (phase) => phases.push(phase) }));
    expect(outcome).toEqual({ phase: "added" });
    expect(backend.actions()).toEqual(["prepare_domain", "prepare_domain_dns", "apply_plan", "prepare_domain", "apply_plan"]);
    expect(backend.calls[1].payload).toEqual({ input: "example.org", accountId: "a" });
    expect(backend.calls[2].payload).toEqual({ planId: "dns-example.org" });
    expect(backend.calls[4].payload).toEqual({ planId: "domain-plan" });
    expect(phases).toEqual(["checking", "dns", "checking", "applying"]);
  });

  it("skips a record that would need its proxy turned on and changes nothing", async () => {
    const backend = scripted({
      prepare_domain: [dnsError("example.org")],
      prepare_domain_dns: [dnsPlan("example.org", "enableProxy", "dnsOnly")],
    });
    const outcome = await processBatchDomain("example.org", options(backend.call));
    expect(outcome).toEqual({ phase: "skipped", reason: BATCH_REASONS.proxy });
    expect(backend.actions()).not.toContain("apply_plan");
  });

  it("skips a placeholder fix that also asks for other changes", async () => {
    const mixed = { ...dnsPlan("example.org", "createPlaceholder", "missing"), actions: [
      { kind: "createPlaceholder" as const, recordType: "AAAA", name: "example.org" },
      { kind: "enableProxy" as const, recordType: "A", name: "example.org" },
    ] };
    const backend = scripted({ prepare_domain: [dnsError("example.org")], prepare_domain_dns: [mixed] });
    expect(await processBatchDomain("example.org", options(backend.call))).toEqual({ phase: "skipped", reason: BATCH_REASONS.proxy });
    expect(backend.actions()).not.toContain("apply_plan");
  });

  it("leaves DNS alone when the automatic placeholder option is off", async () => {
    const backend = scripted({
      prepare_domain: [dnsError("example.org")],
      prepare_domain_dns: [dnsPlan("example.org", "createPlaceholder", "missing")],
    });
    const outcome = await processBatchDomain("example.org", options(backend.call, { autoDns: false }));
    expect(outcome).toEqual({ phase: "skipped", reason: BATCH_REASONS.noDns });
    expect(backend.actions()).not.toContain("apply_plan");
  });

  it("waits for the certificate after a new placeholder and reports it when it is still not ready", async () => {
    const backend = scripted({
      prepare_domain: [dnsError("example.org"), networkError("example.org", "probe_transport_error")],
      prepare_domain_dns: [dnsPlan("example.org", "createPlaceholder", "missing")],
      apply_plan: [state()],
    });
    const sleep = vi.fn(async () => {});
    const outcome = await processBatchDomain("example.org", options(backend.call, { sleep }));
    expect(outcome).toEqual({ phase: "failed", reason: BATCH_REASONS.certPending });
    expect(backend.actions().filter((action) => action === "prepare_domain")).toHaveLength(5);
    expect(backend.actions().filter((action) => action === "apply_plan")).toHaveLength(1);
    expect(sleep.mock.calls).toEqual([[5000], [5000], [5000]]);
  });

  it("retries a network-only check and adds the domain when it passes", async () => {
    const backend = scripted({ prepare_domain: [networkError("example.com"), ready("example.com")], apply_plan: [state(["example.com"])] });
    const sleep = vi.fn(async () => {});
    expect(await processBatchDomain("example.com", options(backend.call, { sleep }))).toEqual({ phase: "added" });
    expect(backend.actions()).toEqual(["prepare_domain", "prepare_domain", "apply_plan"]);
    expect(sleep).toHaveBeenCalledTimes(1);
  });

  it("gives up after two network retries with the first error text", async () => {
    const backend = scripted({ prepare_domain: [networkError("example.com", "dns_timeout")] });
    const outcome = await processBatchDomain("example.com", options(backend.call));
    // A plain check text gets the batch's own next step.
    expect(outcome).toEqual({ phase: "failed", reason: "访问检查超时。稍后点「把失败的再试一次」。" });
    expect(backend.actions()).toEqual(["prepare_domain", "prepare_domain", "prepare_domain"]);
  });

  it("confirms the same plan again when the backend says it is still valid", async () => {
    const kept = new Error("网络检查没有完成（链接目录：超时）。接入计划仍然有效，云端没有任何改动，可以直接再点一次确认。");
    const backend = scripted({ prepare_domain: [ready("example.com", "same")], apply_plan: [kept, kept, state(["example.com"])] });
    expect(await processBatchDomain("example.com", options(backend.call))).toEqual({ phase: "added" });
    expect(backend.calls.filter((item) => item.action === "apply_plan").map((item) => item.payload)).toEqual([
      { planId: "same" }, { planId: "same" }, { planId: "same" },
    ]);
    expect(backend.actions().filter((action) => action === "prepare_domain")).toHaveLength(1);
  });

  it("stops retrying a kept plan after two more tries", async () => {
    const kept = new Error("网络检查没有完成（链接目录：超时）。接入计划仍然有效，云端没有任何改动，可以直接再点一次确认。");
    const backend = scripted({ prepare_domain: [ready("example.com", "same")], apply_plan: [kept] });
    const outcome = await processBatchDomain("example.com", options(backend.call));
    // "再点一次确认" has no button in a batch: the reason keeps the cause and names the batch's own next step.
    expect(outcome).toEqual({
      phase: "failed",
      reason: "网络检查没有完成（链接目录：超时）。云端没有任何改动，稍后点「把失败的再试一次」。",
    });
    expect(backend.actions().filter((action) => action === "apply_plan")).toHaveLength(3);
  });

  it("waits and retries when the backend is still busy with another request", async () => {
    const busy = new Error("上一个操作还没结束，请稍后再试。");
    const backend = scripted({ prepare_domain: [busy, busy, ready("example.com")], apply_plan: [state(["example.com"])] });
    const sleep = vi.fn(async () => {});
    expect(await processBatchDomain("example.com", options(backend.call, { sleep }))).toEqual({ phase: "added" });
    expect(sleep.mock.calls).toEqual([[3000], [3000]]);
  });

  it("gives up on a busy backend after three waits and knows the wording the backend really sends", async () => {
    // src-tauri still answers with the older wording; both must count as "wait and retry".
    const busyText = "上一个操作仍在进行，请稍候；若有系统授权窗口，请先完成或取消，无需重复点击";
    expect(isBusyError(busyText)).toBe(true);
    expect(isBusyError("令牌读取失败：上一个操作还没结束")).toBe(false);
    const backend = scripted({ prepare_domain: [new Error(busyText)] });
    const sleep = vi.fn(async () => {});
    expect(await processBatchDomain("example.com", options(backend.call, { sleep }))).toEqual({ phase: "failed", reason: busyText });
    expect(backend.actions()).toHaveLength(4);
    expect(sleep.mock.calls).toEqual([[3000], [3000], [3000]]);
  });

  it("reports other check errors with the item name and text", async () => {
    const backend = scripted({ prepare_domain: [blocked("example.com", [
      { label: "转发规则", ok: false, level: "error", message: "已有其他转发规则占用这个目录" },
    ])] });
    expect(await processBatchDomain("example.com", options(backend.call))).toEqual({
      phase: "failed", reason: "转发规则：已有其他转发规则占用这个目录。请在「添加域名」里单独查看这个域名。",
    });
  });

  it("adds a next step to a rejected call whose text has none, and leaves a text that already says what to do", async () => {
    // lib.rs apply_domain: thrown as written, with no advice of its own.
    const drift = scripted({ prepare_domain: [ready("example.com")], apply_plan: [new Error("云端资源归属与本机不一致")] });
    expect(await processBatchDomain("example.com", options(drift.call))).toEqual({
      phase: "failed", reason: "云端资源归属与本机不一致。请在「添加域名」里单独查看这个域名。",
    });
    // lib.rs normalize_host, thrown by prepare_domain itself.
    const format = scripted({ prepare_domain: [new Error("域名不能包含账号信息或端口")] });
    expect(await processBatchDomain("example.com", options(format.call))).toEqual({
      phase: "failed", reason: "域名不能包含账号信息或端口。请在「添加域名」里单独查看这个域名。",
    });
    // domain_check.rs placeholder_conflict, thrown when the placeholder plan is applied.
    const placeholder = scripted({
      prepare_domain: [dnsError("example.org")],
      prepare_domain_dns: [dnsPlan("example.org", "createPlaceholder", "missing")],
      apply_plan: [new Error("DNS 区域记录格式无效，无法安全创建占位记录")],
    });
    expect(await processBatchDomain("example.org", options(placeholder.call))).toEqual({
      phase: "failed", reason: "补解析没成功：DNS 区域记录格式无效，无法安全创建占位记录。请在「添加域名」里单独查看这个域名。",
    });
    // cloud.rs failure_message already tells the user what to do: nothing is appended.
    const later = scripted({ prepare_domain: [ready("example.com")], apply_plan: [new Error("Cloudflare 服务暂时不可用（HTTP 502），请稍后再试")] });
    expect(await processBatchDomain("example.com", options(later.call))).toEqual({
      phase: "failed", reason: "Cloudflare 服务暂时不可用（HTTP 502），请稍后再试",
    });
  });

  const dnsBlocked = (status: DomainDnsPreparation["dnsStatus"], label: string, message: string): DomainDnsPreparation => ({
    host: "example.org", candidates: [candidate], dnsStatus: status, canApply: false, actions: [],
    checks: [{ label, ok: false, level: "error", message }],
  });

  it("marks a DNS read that failed as failed, so it can be tried again", async () => {
    const backend = scripted({
      prepare_domain: [dnsError("example.org")],
      prepare_domain_dns: [dnsBlocked("readFailed", "DNS", "无法读取 DNS 记录：连接云端失败，请检查网络")],
    });
    expect(await processBatchDomain("example.org", options(backend.call))).toEqual({
      phase: "failed", reason: "DNS：无法读取 DNS 记录：连接云端失败，请检查网络",
    });
    expect(backend.actions()).not.toContain("apply_plan");
  });

  it("marks a failed ownership read during the DNS step as failed, not as a complicated record", async () => {
    // The backend leaves dnsStatus at its default "conflict" when it never got to read the records.
    const backend = scripted({
      prepare_domain: [dnsError("example.org")],
      prepare_domain_dns: [dnsBlocked("conflict", "云端域名归属", "连接云端失败，请检查网络")],
    });
    expect(await processBatchDomain("example.org", options(backend.call))).toEqual({
      phase: "failed", reason: "云端域名归属：连接云端失败，请检查网络",
    });
  });

  it("skips a real record conflict and sends it to the single add window", async () => {
    for (const status of ["conflict", "unsupported"] as const) {
      const backend = scripted({
        prepare_domain: [dnsError("example.org")],
        prepare_domain_dns: [dnsBlocked(status, "DNS", "这个主机名有别名记录")],
      });
      expect(await processBatchDomain("example.org", options(backend.call))).toEqual({
        phase: "skipped", reason: "解析情况比较复杂（DNS：这个主机名有别名记录），请在「添加域名」里单独处理",
      });
      expect(backend.actions()).not.toContain("apply_plan");
    }
  });

  it("counts a DNS read Cloudflare refused as an authorization failure, not as a complicated record", async () => {
    // The backend reports a refused full-zone read with dnsStatus "conflict" and reason cloud_refused.
    const refused = dnsBlocked("conflict", "DNS", "云端请求失败（HTTP 403），请检查令牌权限与资源状态");
    refused.checks = refused.checks.map((check) => ({ ...check, reason: "cloud_refused" }));
    const backend = scripted({ prepare_domain: [dnsError("example.org")], prepare_domain_dns: [refused] });
    expect(await processBatchDomain("example.org", options(backend.call))).toEqual({
      phase: "failed", reason: "DNS：云端请求失败（HTTP 403），请检查令牌权限与资源状态", authorization: true,
    });
    expect(backend.actions()).not.toContain("apply_plan");
  });

  it("never confirms a takeover after its own placeholder and says what is left to do", async () => {
    const backend = scripted({
      prepare_domain: [dnsError("example.org"), ready("example.org", "takeover-plan", true)],
      prepare_domain_dns: [dnsPlan("example.org", "createPlaceholder", "missing")],
      apply_plan: [state()],
    });
    const outcome = await processBatchDomain("example.org", options(backend.call));
    expect(outcome).toEqual({ phase: "skipped", reason: BATCH_REASONS.confirmAfterDns });
    expect(BATCH_REASONS.confirmAfterDns).toContain("解析已补好");
    expect(BATCH_REASONS.confirmAfterDns).not.toContain("已有网页");
    // Only the DNS plan was applied; the takeover plan was never sent.
    expect(backend.calls.filter((item) => item.action === "apply_plan").map((item) => item.payload)).toEqual([{ planId: "dns-example.org" }]);
  });

  const publicDnsError = (host: string) =>
    blocked(host, [{ label: "短链接目录", ok: false, level: "error", reason: "public_dns_failed", message: "未能从公共 DNS 查询网站地址" }]);

  it("goes back to the local network when public DNS cannot be reached and the VPN is off", async () => {
    const backend = scripted({
      prepare_domain: [(payload: Record<string, unknown>) => payload.dnsMode === "public" ? publicDnsError(String(payload.input)) : ready(String(payload.input))],
      apply_plan: [state()],
    });
    const network: BatchNetwork = { mode: "public" };
    const onSystemDns = vi.fn();
    const onAdded = vi.fn();
    const shared = options(backend.call, { network, onSystemDns, onAdded });
    expect(await processBatchDomain("example.com", shared)).toEqual({ phase: "added" });
    expect(await processBatchDomain("example.org", shared)).toEqual({ phase: "added" });
    const prepares = backend.calls.filter((item) => item.action === "prepare_domain").map((item) => `${item.payload.input}:${item.payload.dnsMode}`);
    expect(prepares).toEqual(["example.com:public", "example.com:system", "example.org:system"]);
    expect(network.mode).toBe("system");
    expect(onSystemDns).toHaveBeenCalledTimes(1);
    expect(onAdded.mock.calls.map(([info]) => info.dnsMode)).toEqual(["system", "system"]);
  });

  it("keeps public DNS when the local network still answers with a VPN address", async () => {
    const backend = scripted({
      prepare_domain: [(payload: Record<string, unknown>) => payload.dnsMode === "public" ? publicDnsError(String(payload.input)) : virtualError(String(payload.input))],
    });
    const network: BatchNetwork = { mode: "public" };
    const onSystemDns = vi.fn();
    const outcome = await processBatchDomain("example.com", options(backend.call, { network, onSystemDns }));
    expect(outcome).toEqual({ phase: "failed", reason: "未能从公共 DNS 查询网站地址。稍后点「把失败的再试一次」。" });
    // The local network is tried once per domain, not once per retry.
    expect(backend.calls.map((item) => item.payload.dnsMode)).toEqual(["public", "system", "public", "public"]);
    expect(network.mode).toBe("public");
    expect(onSystemDns).not.toHaveBeenCalled();
  });
});

describe("processBatchDomain after a new placeholder record", () => {
  const noAddress = (host: string, reason: string, message: string) =>
    blocked(host, [{ label: "短链接目录", ok: false, level: "error", reason, message }]);
  it.each([
    ["dns_no_answer", "暂时无法检查此路径：没有查询到网站的 IP 地址，尚未连接网站"],
    ["public_dns_invalid_response", "暂时无法检查此路径：公共 DNS 返回的信息不完整或不匹配，已停止检测，尚未连接网站"],
  ])("waits for the record to show up when the lookup says %s, then reports the certificate wait", async (reason, message) => {
    const backend = scripted({
      prepare_domain: [dnsError("example.org"), noAddress("example.org", reason, message)],
      prepare_domain_dns: [dnsPlan("example.org", "createPlaceholder", "missing")],
      apply_plan: [state()],
    });
    const sleep = vi.fn(async () => {});
    expect(await processBatchDomain("example.org", options(backend.call, { sleep }))).toEqual({ phase: "failed", reason: BATCH_REASONS.certPending });
    expect(backend.actions().filter((action) => action === "prepare_domain")).toHaveLength(5);
    expect(sleep.mock.calls).toEqual([[5000], [5000], [5000]]);
  });

  it("adds the domain when the fresh record shows up during the wait", async () => {
    const backend = scripted({
      prepare_domain: [dnsError("example.org"), noAddress("example.org", "dns_no_answer", "没有查询到网站的 IP 地址，尚未连接网站"), ready("example.org", "late")],
      prepare_domain_dns: [dnsPlan("example.org", "createPlaceholder", "missing")],
      apply_plan: [state(), state(["example.org"])],
    });
    expect(await processBatchDomain("example.org", options(backend.call))).toEqual({ phase: "added" });
    expect(backend.calls.filter((item) => item.action === "apply_plan").map((item) => item.payload)).toEqual([{ planId: "dns-example.org" }, { planId: "late" }]);
  });

  it("does not wait on a missing address when the batch wrote no record", async () => {
    const backend = scripted({ prepare_domain: [noAddress("example.org", "dns_no_answer", "暂时无法检查此路径：没有查询到网站的 IP 地址，尚未连接网站")] });
    const sleep = vi.fn(async () => {});
    expect(await processBatchDomain("example.org", options(backend.call, { sleep }))).toEqual({
      phase: "failed", reason: "短链接目录：暂时无法检查此路径：没有查询到网站的 IP 地址，尚未连接网站。请在「添加域名」里单独查看这个域名。",
    });
    expect(backend.actions()).toEqual(["prepare_domain"]);
    expect(sleep).not.toHaveBeenCalled();
  });
});

// Real backend sentences (src-tauri/src): domain_check.rs probe, cloud.rs failure_message,
// lib.rs dns_write_error / prepare_domain / confirm-time review, secret_store.rs SecretError.
const PROBE_403 = "此路径返回 HTTP 403（访问被拒绝），请处理后重新检查";
const PROBE_401 = "此路径返回 HTTP 401（需要身份验证），请处理后重新检查";
const CLOUD_400 = "云端请求失败（HTTP 400），请检查令牌权限与资源状态";
const CLOUD_404 = "云端请求失败（HTTP 404），请检查令牌权限与资源状态";
const NOT_IN_ACCOUNT = "已从 Cloudflare 刷新，但当前令牌可见的域名中仍未找到它。请确认所属账户、域名已添加到 Cloudflare，以及令牌允许访问这个新域名";
const DNS_WRITE_403 = "Cloudflare 拒绝修改 DNS（HTTP 403）。请检查此令牌的 DNS 编辑权限和域名授权范围，补齐授权后再继续；已有功能仍可使用。";
const REAUTHORIZE = "账户「示例账户」：此账户需要更新本机授权，请在账户页面点击“更新本机授权”后重试";
const KEYCHAIN_DENIED = "无法刷新账户「示例账户」的域名：未能访问系统凭据库，请在系统提示中允许访问";

describe("isAuthorizationError", () => {
  it("counts rejected calls about the account's authorization", () => {
    for (const text of [
      DNS_WRITE_403, REAUTHORIZE, KEYCHAIN_DENIED,
      "云端请求失败（HTTP 401），请检查令牌权限与资源状态",
      "无法刷新账户「示例账户」的域名：云端请求失败（HTTP 403），请检查令牌权限与资源状态；可选择此域名所属账户后重试",
      "系统授权未完成，请稍后重试",
      "账户「示例账户」：此账号的令牌导入尚未完成，请重试原令牌或明确更新该账号令牌",
    ]) expect(isAuthorizationError(text), text).toBe(true);
  });
  it("does not count website answers, 400/404 token advice, a missing domain or a busy reply", () => {
    for (const text of [
      PROBE_403, PROBE_401, CLOUD_400, CLOUD_404, NOT_IN_ACCOUNT,
      `补解析没成功：${CLOUD_400}`,
      `复核没有通过（短链接目录：${PROBE_403}）。云端没有任何改动，请重新检查域名。`,
      "上一个操作还没结束，已经等了几秒。请稍后再点一次；如果屏幕上有系统的钥匙串窗口，请先处理它。",
    ]) expect(isAuthorizationError(text), text).toBe(false);
  });
});

describe("authorization stop in a batch", () => {
  const hosts = ["example.com", "example.org", "example.net"];
  async function runAll(script: Record<string, unknown[]>) {
    const backend = scripted(script);
    const updates: string[] = [];
    const result = await runDomainBatch(hosts, {
      ...options(backend.call), shouldStop: () => false,
      onUpdate: (host, phase, reason) => { if (phase === "failed" || phase === "added") updates.push(`${host}:${phase}:${reason || ""}`); },
    });
    return { result, updates, prepared: backend.calls.filter((item) => item.action === "prepare_domain").map((item) => item.payload.input) };
  }
  const probe = (message: string, label = "短链接目录") => [(payload: Record<string, unknown>) =>
    blocked(String(payload.input), [{ label, ok: false, level: "error", message }])];

  it.each([
    ["the website answers 403 on 短链接目录", { prepare_domain: probe(PROBE_403) }],
    ["the website answers 401 on 随机测试链接", { prepare_domain: probe(PROBE_401, "随机测试链接") }],
    ["the domain is no longer in the account", { prepare_domain: probe(NOT_IN_ACCOUNT, "域名归属") }],
    ["a placeholder write is answered with HTTP 400", {
      prepare_domain: [(payload: Record<string, unknown>) => dnsError(String(payload.input))],
      prepare_domain_dns: [(payload: Record<string, unknown>) => dnsPlan(String(payload.input), "createPlaceholder", "missing")],
      apply_plan: [new Error(CLOUD_400)],
    }],
    ["the confirm-time review meets a website 403", {
      prepare_domain: [(payload: Record<string, unknown>) => ready(String(payload.input))],
      apply_plan: [new Error(`复核没有通过（短链接目录：${PROBE_403}）。云端没有任何改动，请重新检查域名。`)],
    }],
  ])("keeps going when %s", async (_name, script) => {
    const { result, updates, prepared } = await runAll(script as Record<string, unknown[]>);
    expect(result).toEqual({ authorizationStopped: false });
    expect(prepared).toEqual(hosts);
    expect(updates).toHaveLength(3);
    expect(updates.every((line) => line.includes(":failed:"))).toBe(true);
  });

  it.each([
    ["the token is dead (Cloudflare read answered HTTP 401)", { prepare_domain: [(payload: Record<string, unknown>) => blocked(String(payload.input), [
      { label: "云端域名归属", ok: false, level: "error", reason: "cloud_refused", message: "云端请求失败（HTTP 401），请检查令牌权限与资源状态" }])] }],
    ["the saved authorization cannot be read on this computer", { prepare_domain: [(payload: Record<string, unknown>) => blocked(String(payload.input), [
      { label: "凭据", ok: false, level: "error", reason: "credential", message: "未能访问系统凭据库，请在系统提示中允许访问" }])] }],
    ["the account must be authorized again (rejected call)", { prepare_domain: [new Error(REAUTHORIZE)] }],
    ["the keychain refuses access (rejected call)", { prepare_domain: [new Error(KEYCHAIN_DENIED)] }],
    ["a DNS write is refused for lack of permission", {
      prepare_domain: [(payload: Record<string, unknown>) => dnsError(String(payload.input))],
      prepare_domain_dns: [(payload: Record<string, unknown>) => dnsPlan(String(payload.input), "createPlaceholder", "missing")],
      apply_plan: [new Error(DNS_WRITE_403)],
    }],
  ])("stops after two when %s", async (_name, script) => {
    const { result, prepared } = await runAll(script as Record<string, unknown[]>);
    expect(result).toEqual({ authorizationStopped: true });
    expect(prepared).toEqual(["example.com", "example.org"]);
  });

  it("returns the authorization verdict as data on the outcome", async () => {
    const refusedWrite = scripted({
      prepare_domain: [dnsError("example.org")],
      prepare_domain_dns: [dnsPlan("example.org", "createPlaceholder", "missing")],
      apply_plan: [new Error(DNS_WRITE_403)],
    });
    expect(await processBatchDomain("example.org", options(refusedWrite.call))).toEqual({
      phase: "failed", reason: `补解析没成功：${DNS_WRITE_403}`, authorization: true,
    });
    const website = scripted({ prepare_domain: probe(PROBE_403) });
    expect(await processBatchDomain("example.org", options(website.call))).toEqual({
      phase: "failed", reason: `短链接目录：${PROBE_403}`,
    });
  });
});

describe("runDomainBatch", () => {
  it("keeps going after a failed domain", async () => {
    const backend = scripted({
      prepare_domain: [(payload: Record<string, unknown>) => payload.input === "example.com"
        ? blocked("example.com", [{ label: "域名归属", ok: false, level: "error", message: "这个账户里没有这个域名" }])
        : ready(String(payload.input))],
      apply_plan: [state(["example.org"])],
    });
    const updates: string[] = [];
    await runDomainBatch(["example.com", "example.org"], {
      ...options(backend.call), shouldStop: () => false,
      onUpdate: (host, phase, reason) => updates.push(`${host}:${phase}${reason ? `:${reason}` : ""}`),
    });
    expect(updates).toContain("example.com:failed:域名归属：这个账户里没有这个域名。请在「添加域名」里单独查看这个域名。");
    expect(updates.at(-1)).toBe("example.org:added");
  });

  it("ends the run after two authorization failures in a row and leaves the rest untouched", async () => {
    // A dead token: the Cloudflare read for 云端域名归属 is answered with HTTP 401 (cloud.rs failure_message).
    const refused = (host: string) => blocked(host, [{ label: "云端域名归属", ok: false, level: "error", reason: "cloud_refused", message: "云端请求失败（HTTP 401），请检查令牌权限与资源状态" }]);
    const backend = scripted({ prepare_domain: [(payload: Record<string, unknown>) => refused(String(payload.input))] });
    const updates: string[] = [];
    const result = await runDomainBatch(["example.com", "example.org", "example.net"], {
      ...options(backend.call), shouldStop: () => false,
      onUpdate: (host, phase) => updates.push(`${host}:${phase}`),
    });
    expect(result).toEqual({ authorizationStopped: true });
    expect(updates.at(-1)).toBe("example.org:failed");
    expect(backend.calls.some((item) => item.payload.input === "example.net")).toBe(false);
  });

  it("keeps going when an authorization failure concerns one domain only, or the backend is merely busy", async () => {
    const refused = (host: string) => blocked(host, [{ label: "凭据", ok: false, level: "error", reason: "credential", message: "未能访问系统凭据库，请在系统提示中允许访问" }]);
    const backend = scripted({
      prepare_domain: [(payload: Record<string, unknown>) => {
        if (payload.input === "example.com" || payload.input === "example.net") return refused(String(payload.input));
        // The busy text mentions the keychain; it is not an authorization problem.
        if (payload.input === "example.org") throw new Error("上一个操作还没结束，已经等了几秒。请稍后再点一次；如果屏幕上有系统的钥匙串窗口，请先处理它。");
        return ready(String(payload.input));
      }],
      apply_plan: [state()],
    });
    const updates: string[] = [];
    const result = await runDomainBatch(["example.com", "example.org", "example.net", "www.example.com"], {
      ...options(backend.call), shouldStop: () => false,
      onUpdate: (host, phase) => updates.push(`${host}:${phase}`),
    });
    expect(result).toEqual({ authorizationStopped: false });
    expect(updates.at(-1)).toBe("www.example.com:added");
  });

  it("does not report an early end when the second authorization failure is the last domain", async () => {
    const backend = scripted({ prepare_domain: [(payload: Record<string, unknown>) =>
      blocked(String(payload.input), [{ label: "本机授权", ok: false, level: "error", reason: "credential", message: "账户「示例账户」：此账户需要更新本机授权，请在账户页面点击“更新本机授权”后重试" }])] });
    const result = await runDomainBatch(["example.com", "example.org"], { ...options(backend.call), shouldStop: () => false, onUpdate: () => {} });
    expect(result).toEqual({ authorizationStopped: false });
  });

  it("finishes the current domain after a stop request and leaves the rest untouched", async () => {
    const backend = scripted({ prepare_domain: [(payload: Record<string, unknown>) => ready(String(payload.input))], apply_plan: [state()] });
    let stop = false;
    const updates: string[] = [];
    await runDomainBatch(["example.com", "example.org", "example.net"], {
      ...options(backend.call),
      shouldStop: () => stop,
      onUpdate: (host, phase) => {
        updates.push(`${host}:${phase}`);
        if (host === "example.com" && phase === "checking") stop = true;
      },
    });
    expect(updates.at(-1)).toBe("example.com:added");
    expect(backend.calls.some((item) => item.payload.input === "example.org" || item.payload.input === "example.net")).toBe(false);
  });

  it("switches to public DNS after a VPN address and keeps it for later domains", async () => {
    const backend = scripted({
      prepare_domain: [(payload: Record<string, unknown>) => payload.dnsMode === "system" ? virtualError(String(payload.input)) : ready(String(payload.input))],
      apply_plan: [state()],
    });
    const onPublicDns = vi.fn();
    const network: BatchNetwork = { mode: "system" };
    await runDomainBatch(["example.com", "example.org"], {
      ...options(backend.call, { network, onPublicDns }), shouldStop: () => false, onUpdate: () => {},
    });
    const prepares = backend.calls.filter((item) => item.action === "prepare_domain").map((item) => `${item.payload.input}:${item.payload.dnsMode}`);
    expect(prepares).toEqual(["example.com:system", "example.com:public", "example.org:public"]);
    expect(onPublicDns).toHaveBeenCalledTimes(1);
    expect(network.mode).toBe("public");
  });

  it("walks every sample outcome against the preview bridge", async () => {
    const real = await vi.importActual<typeof import("./bridge")>("./bridge");
    expect(real.preview).toBe(true);
    const before = await real.dispatch<State>("get_state");
    const zones = before.accounts.find((account) => account.id === "demo-b")?.zones?.map((zone) => zone.name) || [];
    const results: Record<string, string> = {};
    await runDomainBatch(zones, {
      call: real.dispatch, accountId: "demo-b", prefix: "go", autoDns: true, network: { mode: "system" },
      sleep: async () => {}, shouldStop: () => false,
      onUpdate: (host, phase, reason) => { results[host] = reason ? `${phase}:${reason}` : phase; },
    });
    expect(results).toEqual({
      "example.net": "added",
      "old.example.com": `skipped:${BATCH_REASONS.takeover}`,
      "missing.example.net": "added",
      "grey.example.net": `skipped:${BATCH_REASONS.proxy}`,
      "slow.example.net": "added",
    });
    const after = await real.dispatch<State>("get_state");
    expect(after.domains.filter((domain) => domain.accountId === "demo-b").map((domain) => domain.host).sort())
      .toEqual(["example.net", "missing.example.net", "slow.example.net"]);
  });
});

const account = (id: string, zones: string[], extra: Partial<Account> = {}): Account => ({
  id, label: `账户 ${id}`, zones: zones.map((name, index) => ({ id: `${id}-z${index}`, name, status: "active" })),
  zoneCount: zones.length, checkedAt: null, hasResources: true, needsSelftestKey: false, ...extra,
});
function renderBatch(props: Partial<Parameters<typeof DomainBatch>[0]> = {}) {
  const handlers = {
    begin: vi.fn(() => true), end: vi.fn(), onState: vi.fn(), onPublicDns: vi.fn(), onAdded: vi.fn(), onClose: vi.fn(),
  };
  render(<DomainBatch
    accounts={[account("a", ["example.com", "example.org", "example.net"])]}
    domains={[{ id: "d", accountId: "a", zoneId: "a-z2", host: "example.net", prefix: "r", routeId: "route" }]}
    initialDnsMode={() => "system"}
    {...handlers}
    {...props}
  />);
  return { dialog: screen.getByRole("dialog", { name: "批量添加域名" }), ...handlers };
}

describe("DomainBatch dialog", () => {
  it("lists only zones that are not added yet and runs the chosen ones in order", async () => {
    control.handler = (action, payload) => {
      if (action === "prepare_domain") return payload.input === "example.org"
        ? ready("example.org", "p2", true)
        : ready(String(payload.input), "p1");
      if (action === "apply_plan") return state(["example.com", "example.net"]);
      throw new Error(`Unexpected ${action}`);
    };
    const { dialog, onState, begin, end } = renderBatch();
    const list = within(dialog).getByRole("group", { name: "可添加的域名" });
    expect(within(list).getAllByRole("checkbox").map((box) => box.parentElement?.textContent)).toEqual(["example.com", "example.org"]);
    expect(within(dialog).getByText(/要加子域名（比如 go.example.com）请用「添加域名」/)).toBeTruthy();
    expect((within(dialog).getByRole("checkbox", { name: /自动补一条占位解析/ }) as HTMLInputElement).checked).toBe(true);
    const start = within(dialog).getByRole("button", { name: "开始添加（0 个）" }) as HTMLButtonElement;
    expect(start.disabled).toBe(true);
    fireEvent.click(within(dialog).getByRole("button", { name: "全选" }));
    fireEvent.change(within(dialog).getByRole("textbox", { name: /^链接目录/ }), { target: { value: "go" } });
    fireEvent.click(within(dialog).getByRole("button", { name: "开始添加（2 个）" }));
    expect(within(dialog).getByText("example.com/go/")).toBeTruthy();
    expect(control.calls).toHaveLength(0);
    fireEvent.click(within(dialog).getByRole("button", { name: "确认开始" }));
    await within(dialog).findByText(/已接入 1 个、跳过 1 个、失败 0 个/);
    expect(control.calls.filter((call) => call.action === "prepare_domain").map((call) => call.payload)).toEqual([
      { input: "example.com", prefix: "go", accountId: "a", dnsMode: "system" },
      { input: "example.org", prefix: "go", accountId: "a", dnsMode: "system" },
    ]);
    expect(control.calls.filter((call) => call.action === "apply_plan").map((call) => call.payload)).toEqual([{ planId: "p1" }]);
    expect(within(dialog).getByText(BATCH_REASONS.takeover)).toBeTruthy();
    expect(onState).toHaveBeenCalledTimes(1);
    expect(begin).toHaveBeenCalledTimes(1);
    expect(end).toHaveBeenCalledTimes(1);
  });

  it("filters with search and clears the choice with 全不选", () => {
    const { dialog } = renderBatch();
    fireEvent.change(within(dialog).getByRole("textbox", { name: "搜索域名" }), { target: { value: "org" } });
    const list = within(dialog).getByRole("group", { name: "可添加的域名" });
    expect(within(list).getAllByRole("checkbox")).toHaveLength(1);
    fireEvent.click(within(dialog).getByRole("button", { name: "全选" }));
    expect(within(dialog).getByRole("button", { name: "开始添加（1 个）" })).toBeTruthy();
    fireEvent.click(within(dialog).getByRole("button", { name: "全不选" }));
    expect(within(dialog).getByRole("button", { name: "开始添加（0 个）" })).toBeTruthy();
  });

  it("rejects an invalid directory name before anything runs", () => {
    const { dialog } = renderBatch();
    fireEvent.click(within(dialog).getByRole("button", { name: "全选" }));
    fireEvent.change(within(dialog).getByRole("textbox", { name: /^链接目录/ }), { target: { value: "Bad/Dir" } });
    fireEvent.click(within(dialog).getByRole("button", { name: "开始添加（2 个）" }));
    expect(within(dialog).getByRole("alert").textContent).toContain("路径前缀须为");
    expect(within(dialog).queryByRole("button", { name: "确认开始" })).toBeNull();
  });

  it("asks for an account first when there are several and refreshes only the chosen one", async () => {
    control.handler = (action) => {
      if (action === "refresh_domains") return { ...state(), accounts: [account("a", ["example.com"]), account("b", ["example.org", "new.example.org"])] };
      throw new Error("Unexpected");
    };
    const { dialog, onState } = renderBatch({ accounts: [account("a", ["example.com"]), account("b", ["example.org"])], domains: [] });
    expect((within(dialog).getByRole("button", { name: "刷新域名列表" }) as HTMLButtonElement).disabled).toBe(true);
    expect(within(dialog).queryByRole("group", { name: "可添加的域名" })).toBeNull();
    fireEvent.change(within(dialog).getByRole("combobox", { name: "Cloudflare 账户" }), { target: { value: "b" } });
    fireEvent.click(within(dialog).getByRole("button", { name: "刷新域名列表" }));
    await within(dialog).findByText(/已读取「账户 b」的 2 个域名/);
    expect(control.calls).toEqual([{ action: "refresh_domains", payload: { accountId: "b" } }]);
    expect(onState).toHaveBeenCalledTimes(1);
  });

  it("cannot be closed while running, stops after the current domain and retries only failures", async () => {
    let release: (value: unknown) => void = () => {};
    let firstRound = true;
    control.handler = (action, payload) => {
      if (action === "prepare_domain" && payload.input === "example.com" && firstRound)
        return new Promise((resolve) => { release = resolve; });
      if (action === "prepare_domain" && payload.input === "example.com")
        return ready("example.com", "p-retry");
      if (action === "apply_plan") return state(["example.com"]);
      throw new Error(`Unexpected ${action}`);
    };
    const { dialog, onClose } = renderBatch();
    fireEvent.click(within(dialog).getByRole("button", { name: "全选" }));
    fireEvent.click(within(dialog).getByRole("button", { name: "开始添加（2 个）" }));
    fireEvent.click(within(dialog).getByRole("button", { name: "确认开始" }));
    await waitFor(() => expect(control.calls).toHaveLength(1));
    expect((within(dialog).getByRole("button", { name: "关闭" }) as HTMLButtonElement).disabled).toBe(true);
    fireEvent.keyDown(document, { key: "Escape" });
    expect(onClose).not.toHaveBeenCalled();
    fireEvent.click(within(dialog).getByRole("button", { name: "停止" }));
    firstRound = false;
    release(blocked("example.com", [{ label: "转发规则", ok: false, level: "error", message: "目录被占用" }]));
    await within(dialog).findByText(/已接入 0 个、跳过 0 个、失败 1 个，还有 1 个因为停止没有处理/);
    expect(control.calls.some((call) => call.payload.input === "example.org")).toBe(false);
    expect(within(dialog).getByText("没处理（已停止）")).toBeTruthy();
    fireEvent.click(within(dialog).getByRole("button", { name: "把失败的再试一次" }));
    await within(dialog).findByText(/已接入 1 个、跳过 0 个、失败 0 个/);
    expect(control.calls.some((call) => call.payload.input === "example.org")).toBe(false);
    fireEvent.click(within(dialog).getAllByRole("button", { name: "关闭" }).at(-1)!);
    expect(onClose).toHaveBeenCalledTimes(1);
  });

  it("says why it ended early when the account's authorization keeps failing", async () => {
    control.handler = (action, payload) => {
      if (action === "prepare_domain")
        return blocked(String(payload.input), [{ label: "云端域名归属", ok: false, level: "error", reason: "cloud_refused", message: "云端请求失败（HTTP 403），请检查令牌权限与资源状态" }]);
      throw new Error(`Unexpected ${action}`);
    };
    const { dialog } = renderBatch({ accounts: [account("a", ["example.com", "example.org", "example.net"])], domains: [] });
    fireEvent.click(within(dialog).getByRole("button", { name: "全选" }));
    fireEvent.click(within(dialog).getByRole("button", { name: "开始添加（3 个）" }));
    fireEvent.click(within(dialog).getByRole("button", { name: "确认开始" }));
    const summary = await within(dialog).findByText(/失败 2 个，还有 1 个因为停止没有处理。这个账户的授权连续出错，后面的域名没有再试。/);
    // Each case gets a step it can actually take: a keychain prompt can be handled without leaving
    // this modal window; a token problem means closing it first.
    expect(summary.textContent).toContain("如果屏幕上有系统的钥匙串窗口，先处理它，再点「继续没处理的（1 个）」和「把失败的再试一次」。");
    expect(summary.textContent).toContain("如果只是失败的这几个域名令牌没有权限，可以直接点「继续没处理的（1 个）」接着处理后面的。");
    expect(summary.textContent).toContain("如果是令牌本身的问题，请关掉这个窗口，到「Cloudflare 账户」页把这个账户的授权处理好，再重新批量添加，已经接入的域名不会再列出来。");
    expect(summary.textContent).not.toContain("再回来添加");
    // The buttons the sentence names are the ones on screen.
    expect(within(dialog).getByRole("button", { name: "继续没处理的（1 个）" })).toBeTruthy();
    expect(within(dialog).getByRole("button", { name: "把失败的再试一次" })).toBeTruthy();
    expect(control.calls.filter((call) => call.action === "prepare_domain")).toHaveLength(2);
    expect(within(dialog).getByText("没处理（已停止）")).toBeTruthy();
  });

  it("keeps showing stopped domains as not processed while the failed ones are retried", async () => {
    let release: (value: unknown) => void = () => {};
    let attempts = 0;
    control.handler = (action, payload) => {
      if (action === "prepare_domain" && payload.input === "example.com") {
        attempts += 1;
        return new Promise((resolve) => { release = resolve; });
      }
      if (action === "apply_plan") return state(["example.com"]);
      throw new Error(`Unexpected ${action}`);
    };
    const { dialog } = renderBatch();
    fireEvent.click(within(dialog).getByRole("button", { name: "全选" }));
    fireEvent.click(within(dialog).getByRole("button", { name: "开始添加（2 个）" }));
    fireEvent.click(within(dialog).getByRole("button", { name: "确认开始" }));
    await waitFor(() => expect(attempts).toBe(1));
    fireEvent.click(within(dialog).getByRole("button", { name: "停止" }));
    release(blocked("example.com", [{ label: "转发规则", ok: false, level: "error", message: "目录被占用" }]));
    fireEvent.click(await within(dialog).findByRole("button", { name: "把失败的再试一次" }));
    await waitFor(() => expect(attempts).toBe(2));
    // example.org is not part of this retry: it must not look as if it were queued.
    const stoppedRow = within(dialog).getByText("example.org").closest("li")!;
    expect(stoppedRow.textContent).toContain("没处理（已停止）");
    expect(stoppedRow.textContent).not.toContain("等待");
    release(ready("example.com", "p-retry"));
    await within(dialog).findByText(/已接入 1 个、跳过 0 个、失败 0 个，还有 1 个因为停止没有处理/);
    expect(control.calls.some((call) => call.payload.input === "example.org")).toBe(false);
  });

  it("continues the domains an authorization stop left untouched, with the same directory", async () => {
    let refuse = true;
    control.handler = (action, payload) => {
      if (action === "prepare_domain") return refuse
        ? blocked(String(payload.input), [{ label: "凭据", ok: false, level: "error", reason: "credential", message: "未能访问系统凭据库，请在系统提示中允许访问" }])
        : ready(String(payload.input), `p-${String(payload.input)}`);
      if (action === "apply_plan") return state();
      throw new Error(`Unexpected ${action}`);
    };
    const { dialog } = renderBatch({ accounts: [account("a", ["example.com", "example.org", "example.net"])], domains: [] });
    fireEvent.click(within(dialog).getByRole("button", { name: "全选" }));
    fireEvent.change(within(dialog).getByRole("textbox", { name: /^链接目录/ }), { target: { value: "go" } });
    fireEvent.click(within(dialog).getByRole("button", { name: "开始添加（3 个）" }));
    fireEvent.click(within(dialog).getByRole("button", { name: "确认开始" }));
    await within(dialog).findByText(/还有 1 个因为停止没有处理/);
    expect(within(dialog).getByRole("button", { name: "把失败的再试一次" })).toBeTruthy();
    refuse = false;
    control.calls.length = 0;
    fireEvent.click(within(dialog).getByRole("button", { name: "继续没处理的（1 个）" }));
    await within(dialog).findByText(/已接入 1 个、跳过 0 个、失败 2 个。/);
    // The list is sorted (example.com, example.net, example.org): only the untouched last row ran,
    // with the directory chosen for this run.
    expect(control.calls.filter((call) => call.action === "prepare_domain").map((call) => call.payload))
      .toEqual([{ input: "example.org", prefix: "go", accountId: "a", dnsMode: "system" }]);
    expect(within(dialog).queryByRole("button", { name: /继续没处理的/ })).toBeNull();
    expect(within(dialog).getByRole("button", { name: "把失败的再试一次" })).toBeTruthy();
  });

  it("offers to continue after a manual stop as well", async () => {
    let release: (value: unknown) => void = () => {};
    control.handler = (action, payload) => {
      if (action === "prepare_domain" && payload.input === "example.com") return new Promise((resolve) => { release = resolve; });
      if (action === "prepare_domain") return ready(String(payload.input), "p-org");
      if (action === "apply_plan") return state();
      throw new Error(`Unexpected ${action}`);
    };
    const { dialog } = renderBatch();
    fireEvent.click(within(dialog).getByRole("button", { name: "全选" }));
    fireEvent.click(within(dialog).getByRole("button", { name: "开始添加（2 个）" }));
    fireEvent.click(within(dialog).getByRole("button", { name: "确认开始" }));
    await waitFor(() => expect(control.calls).toHaveLength(1));
    fireEvent.click(within(dialog).getByRole("button", { name: "停止" }));
    release(ready("example.com", "p-com"));
    fireEvent.click(await within(dialog).findByRole("button", { name: "继续没处理的（1 个）" }));
    await within(dialog).findByText(/已接入 2 个、跳过 0 个、失败 0 个。/);
    expect(control.calls.filter((call) => call.action === "prepare_domain").map((call) => call.payload.input)).toEqual(["example.com", "example.org"]);
  });

  it("says which cases are skipped and that other failed checks are marked 失败", () => {
    const { dialog } = renderBatch();
    const note = dialog.querySelector(".domain-batch-note")!.textContent!;
    expect(note).toContain("目录下已经有网页");
    expect(note).toContain("已有解析但没开代理");
    expect(note).toContain("其他检查没通过的会标成「失败」，并写明原因");
    expect(note).not.toContain("其他冲突");
    fireEvent.click(within(dialog).getByRole("button", { name: "全选" }));
    fireEvent.click(within(dialog).getByRole("button", { name: "开始添加（2 个）" }));
    const steps = dialog.querySelector(".domain-batch-steps")!.textContent!;
    expect(steps).toContain("其他检查没通过的会标成「失败」");
    expect(steps).not.toContain("其他冲突");
  });

  it("asks for a second Escape on the confirm step", () => {
    const { dialog, onClose } = renderBatch();
    fireEvent.click(within(dialog).getByRole("button", { name: "全选" }));
    fireEvent.click(within(dialog).getByRole("button", { name: "开始添加（2 个）" }));
    fireEvent.keyDown(document, { key: "Escape" });
    expect(onClose).not.toHaveBeenCalled();
    expect(within(dialog).getByText("再按一次 Esc 关闭窗口，已选的域名不会保留。")).toBeTruthy();
    fireEvent.keyDown(document, { key: "Escape" });
    expect(onClose).toHaveBeenCalledTimes(1);
  });

  it("asks for a second Escape on the result step when a row needs attention, not when all were added", async () => {
    control.handler = (action, payload) => {
      if (action === "prepare_domain") return payload.input === "example.org"
        ? blocked("example.org", [{ label: "转发规则", ok: false, level: "error", message: "现有转发规则与此前缀重叠" }])
        : ready(String(payload.input));
      if (action === "apply_plan") return state();
      throw new Error(`Unexpected ${action}`);
    };
    const first = renderBatch();
    fireEvent.click(within(first.dialog).getByRole("button", { name: "全选" }));
    fireEvent.click(within(first.dialog).getByRole("button", { name: "开始添加（2 个）" }));
    fireEvent.click(within(first.dialog).getByRole("button", { name: "确认开始" }));
    await within(first.dialog).findByText(/失败 1 个。每一行都写了原因和下一步该怎么做/);
    expect(within(first.dialog).getByText("转发规则：现有转发规则与此前缀重叠。请在「添加域名」里单独查看这个域名。")).toBeTruthy();
    fireEvent.keyDown(document, { key: "Escape" });
    expect(first.onClose).not.toHaveBeenCalled();
    expect(within(first.dialog).getByText("再按一次 Esc 关闭窗口，这次每一行的结果不会保留。")).toBeTruthy();
    fireEvent.keyDown(document, { key: "Escape" });
    expect(first.onClose).toHaveBeenCalledTimes(1);
    cleanup();
    control.handler = (action, payload) => {
      if (action === "prepare_domain") return ready(String(payload.input));
      if (action === "apply_plan") return state();
      throw new Error(`Unexpected ${action}`);
    };
    const second = renderBatch();
    fireEvent.click(within(second.dialog).getByRole("button", { name: "全选" }));
    fireEvent.click(within(second.dialog).getByRole("button", { name: "开始添加（2 个）" }));
    fireEvent.click(within(second.dialog).getByRole("button", { name: "确认开始" }));
    await within(second.dialog).findByText(/已接入 2 个、跳过 0 个、失败 0 个/);
    fireEvent.keyDown(document, { key: "Escape" });
    expect(second.onClose).toHaveBeenCalledTimes(1);
  });

  it("starts with public DNS when the app remembers a VPN and reports going back to the local network", async () => {
    control.handler = (action, payload) => {
      if (action === "prepare_domain") return payload.dnsMode === "public"
        ? blocked(String(payload.input), [{ label: "短链接目录", ok: false, level: "error", reason: "public_dns_timeout", message: "公共 DNS 查询超时" }])
        : ready(String(payload.input));
      if (action === "apply_plan") return state();
      throw new Error(`Unexpected ${action}`);
    };
    const onSystemDns = vi.fn();
    const { dialog, onPublicDns } = renderBatch({ initialDnsMode: () => "public", onSystemDns });
    fireEvent.click(within(dialog).getByRole("button", { name: "全选" }));
    fireEvent.click(within(dialog).getByRole("button", { name: "开始添加（2 个）" }));
    fireEvent.click(within(dialog).getByRole("button", { name: "确认开始" }));
    await within(dialog).findByText(/已接入 2 个、跳过 0 个、失败 0 个/);
    expect(control.calls.filter((call) => call.action === "prepare_domain").map((call) => `${call.payload.input}:${call.payload.dnsMode}`))
      .toEqual(["example.com:public", "example.com:system", "example.org:system"]);
    expect(onSystemDns).toHaveBeenCalledTimes(1);
    expect(onPublicDns).not.toHaveBeenCalled();
  });

  it("does not start while another operation holds the lock", () => {
    const { dialog } = renderBatch({ begin: vi.fn(() => false) });
    fireEvent.click(within(dialog).getByRole("button", { name: "全选" }));
    fireEvent.click(within(dialog).getByRole("button", { name: "开始添加（2 个）" }));
    fireEvent.click(within(dialog).getByRole("button", { name: "确认开始" }));
    expect(within(dialog).getByRole("status").textContent).toContain("上一个操作还没结束");
    expect(control.calls).toHaveLength(0);
  });

  it("sends an account that needs new authorization to the accounts page first", () => {
    const { dialog } = renderBatch({ accounts: [account("a", ["example.com"], { needsTokenRecovery: true })], domains: [] });
    expect(within(dialog).getByText(/要先在「Cloudflare 账户」页更新授权或恢复令牌/)).toBeTruthy();
    expect((within(dialog).getByRole("button", { name: /开始添加/ }) as HTMLButtonElement).disabled).toBe(true);
  });
});

describe("domain page entry", () => {
  it("disables 批量添加 without accounts and opens the dialog when an account exists", async () => {
    const { default: App } = await import("./App");
    let current: State = { ...state(), pools: [] };
    control.handler = (action) => {
      if (action === "get_state") return current;
      if (action === "check_update") return { status: "unavailable" };
      throw new Error(`Unexpected ${action}`);
    };
    const first = render(<App />);
    fireEvent.click(await screen.findByRole("button", { name: /^域名管理$/ }));
    expect((screen.getByRole("button", { name: "批量添加" }) as HTMLButtonElement).disabled).toBe(true);
    first.unmount();
    current = { ...state(), pools: [], accounts: [account("a", ["example.com"])] };
    render(<App />);
    fireEvent.click(await screen.findByRole("button", { name: /^域名管理$/ }));
    await waitFor(() => expect((screen.getByRole("button", { name: "批量添加" }) as HTMLButtonElement).disabled).toBe(false));
    fireEvent.click(screen.getByRole("button", { name: "批量添加" }));
    const dialog = screen.getByRole("dialog", { name: "批量添加域名" });
    expect((within(dialog).getByRole("combobox", { name: "Cloudflare 账户" }) as HTMLSelectElement).value).toBe("a");
    const reads = control.calls.filter((call) => call.action === "get_state").length;
    fireEvent.click(within(dialog).getByRole("button", { name: "取消" }));
    await waitFor(() => expect(control.calls.filter((call) => call.action === "get_state").length).toBe(reads + 1));
    expect(screen.queryByRole("dialog", { name: "批量添加域名" })).toBeNull();
  });
});
