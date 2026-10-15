import { act, cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { afterEach, expect, it, vi } from "vitest";
import { openUrl } from "@tauri-apps/plugin-opener";
import StatsCenter from "./StatsCenter";
import App from "./App";
import { dispatch } from "./bridge";
import type { Account, ClickStatsTotals, Domain, Link, StatsCenterReport, StatsCenterRow } from "./types";

vi.mock("./bridge", () => ({
  preview: true,
  dispatch: vi.fn(),
  errorMessage: (error: unknown) => error instanceof Error ? error.message : String(error),
}));
vi.mock("@tauri-apps/plugin-opener", () => ({ openUrl: vi.fn() }));

const mockedDispatch = vi.mocked(dispatch);
const mockedOpenUrl = vi.mocked(openUrl);
const accounts: Account[] = [
  { id: "account-a", label: "示例账户 A", zoneCount: 2, checkedAt: null, hasResources: true, needsSelftestKey: false },
  { id: "account-b", label: "示例账户 B", zoneCount: 1, checkedAt: null, hasResources: true, needsSelftestKey: false },
];
const domains: Domain[] = [
  { id: "domain-a1", accountId: "account-a", zoneId: "zone-a1", host: "go.example.com", prefix: "r", routeId: "route-a1" },
  { id: "domain-a2", accountId: "account-a", zoneId: "zone-a2", host: "links.example.org", prefix: "s", routeId: "route-a2" },
  { id: "domain-b1", accountId: "account-b", zoneId: "zone-b1", host: "go.example.net", prefix: "go", routeId: "route-b1" },
];
const links: Link[] = Array.from({ length: 30 }, (_, index) => ({
  domainId: index % 2 ? "domain-a2" : "domain-a1",
  slug: `sample-${String(index + 1).padStart(2, "0")}`,
  cnUrl: `https://example.com/zh/${index + 1}`,
  defaultUrl: `https://example.org/en/${index + 1}`,
  updated: "2026-10-15T00:00:00Z",
})).concat({
  domainId: "domain-b1",
  slug: "welcome",
  cnUrl: "https://example.com/zh/welcome",
  defaultUrl: "https://example.org/en/welcome",
  updated: "2026-10-15T00:00:00Z",
});
const totals: ClickStatsTotals = { total: 120, likelyHuman: 80, likelyBot: 25, unknown: 15, previews: 9, prefetches: 4 };
const zeroTotals: ClickStatsTotals = { total: 0, likelyHuman: 0, likelyBot: 0, unknown: 0, previews: 0, prefetches: 0 };
const onConfigure = vi.fn();
const onOpenLinkStats = vi.fn();
const onScopeInvalidate = vi.fn();

function row(domainId = "domain-a1", slug = "sample-01", value = totals): StatsCenterRow {
  return { domainId, slug, totals: value };
}

function response(overrides: Partial<StatsCenterReport> = {}): StatsCenterReport {
  return {
    status: "ready",
    message: "示例估算统计",
    accountId: "account-a",
    domainId: null,
    days: 7,
    page: 1,
    pageSize: 25,
    totalLinks: 1,
    queriedAt: "2026-10-15T03:20:00Z",
    estimated: true,
    totals,
    rows: [row()],
    ...overrides,
  };
}

function deferred<T>() {
  let resolve!: (value: T) => void;
  let reject!: (error: unknown) => void;
  const promise = new Promise<T>((yes, no) => { resolve = yes; reject = no; });
  return { promise, resolve, reject };
}

function view(props: Partial<React.ComponentProps<typeof StatsCenter>> = {}) {
  return <StatsCenter accounts={accounts} domains={domains} links={links} revision={0}
    onConfigure={onConfigure} onOpenLinkStats={onOpenLinkStats} onScopeInvalidate={onScopeInvalidate} {...props} />;
}

function chooseAccount(label = "示例账户 A") {
  fireEvent.change(screen.getByLabelText("统计账户"), { target: { value: label.endsWith("B") ? "account-b" : "account-a" } });
}

async function expectSummary(value: string) {
  const summary = await screen.findByLabelText("估算总访问");
  expect(within(summary).getByText(value)).toBeTruthy();
}

afterEach(() => {
  cleanup();
  vi.clearAllMocks();
});

it("queries only after an explicit read and sends one selected account and scope", async () => {
  mockedDispatch.mockResolvedValue(response({ domainId: "domain-a1", days: 30 }));
  render(view());
  expect(mockedDispatch).not.toHaveBeenCalled();
  chooseAccount();
  fireEvent.change(screen.getByLabelText("统计域名"), { target: { value: "domain-a1" } });
  fireEvent.change(screen.getByLabelText("统计时间范围"), { target: { value: "30" } });
  expect(mockedDispatch).not.toHaveBeenCalled();
  fireEvent.click(screen.getByRole("button", { name: "读取统计" }));
  await expectSummary("120");
  const distribution = screen.getByLabelText("访问分类分布");
  expect(within(distribution).getByText("疑似真人")).toBeTruthy();
  expect(within(distribution).getByText("67%")).toBeTruthy();
  expect(within(distribution).getByText("21%")).toBeTruthy();
  expect(within(distribution).getByText("12%")).toBeTruthy();
  const context = screen.getByText("统计口径与其他请求").closest("details") as HTMLDetailsElement;
  expect(context.open).toBe(false);
  expect(within(context).getByText(/预览 9 · 预加载 4/)).toBeTruthy();
  expect(screen.queryByText(/独立访客|VPN/)).toBeNull();
  expect(mockedDispatch).toHaveBeenCalledTimes(1);
  expect(mockedDispatch).toHaveBeenCalledWith("get_stats_center", {
    accountId: "account-a", domainId: "domain-a1", days: 30, page: 1, pageSize: 25,
  });
  expect(screen.getByText(/汇总包含这一范围内的历史事件，包括后来删除的链接/)).toBeTruthy();
  expect(screen.getByText(/下表只列当前本机已导入的短链接/)).toBeTruthy();
  const stop = screen.getByRole("button", { name: "停用账户统计" });
  expect(stop.closest(".scenter-footer")).toBeTruthy();
  expect(screen.getByText("停用前会显示变更计划")).toBeTruthy();
  fireEvent.click(screen.getByRole("button", { name: "查看 sample-01 的详细统计" }));
  expect(onOpenLinkStats).toHaveBeenCalledWith(links[0], domains[0]);
});

it("hides the previous scope immediately when account, domain, or days changes", async () => {
  mockedDispatch.mockResolvedValue(response());
  render(view());
  chooseAccount();
  fireEvent.click(screen.getByRole("button", { name: "读取统计" }));
  await expectSummary("120");
  fireEvent.change(screen.getByLabelText("统计域名"), { target: { value: "domain-a2" } });
  expect(screen.queryByLabelText("估算总访问")).toBeNull();
  expect(mockedDispatch).toHaveBeenCalledTimes(1);
  fireEvent.change(screen.getByLabelText("统计时间范围"), { target: { value: "1" } });
  expect(mockedDispatch).toHaveBeenCalledTimes(1);
  chooseAccount("示例账户 B");
  expect(mockedDispatch).toHaveBeenCalledTimes(1);
  expect(screen.getByText(/不会自动查询其他账户/)).toBeTruthy();
});

it("does not let an older account response replace the current account", async () => {
  const oldRequest = deferred<StatsCenterReport>();
  const currentRequest = deferred<StatsCenterReport>();
  mockedDispatch.mockImplementationOnce(() => oldRequest.promise).mockImplementationOnce(() => currentRequest.promise);
  render(view());
  chooseAccount();
  fireEvent.click(screen.getByRole("button", { name: "读取统计" }));
  chooseAccount("示例账户 B");
  fireEvent.click(screen.getByRole("button", { name: "读取统计" }));
  currentRequest.resolve(response({
    accountId: "account-b", totalLinks: 1,
    totals: { total: 222, likelyHuman: 200, likelyBot: 12, unknown: 10, previews: 2, prefetches: 1 },
    rows: [row("domain-b1", "welcome", { total: 222, likelyHuman: 200, likelyBot: 12, unknown: 10, previews: 2, prefetches: 1 })],
  }));
  await expectSummary("222");
  oldRequest.resolve(response({ totals: { total: 999, likelyHuman: 900, likelyBot: 70, unknown: 29, previews: 0, prefetches: 0 } }));
  await waitFor(() => expect(within(screen.getByLabelText("估算总访问")).queryByText("999")).toBeNull());
  expect(within(screen.getByLabelText("估算总访问")).getByText("222")).toBeTruthy();
  expect(mockedDispatch.mock.calls.map((call) => call[1]?.accountId)).toEqual(["account-a", "account-b"]);
});

it("rejects stale domain and days responses", async () => {
  const oldRequest = deferred<StatsCenterReport>();
  const currentRequest = deferred<StatsCenterReport>();
  mockedDispatch.mockImplementationOnce(() => oldRequest.promise).mockImplementationOnce(() => currentRequest.promise);
  render(view());
  chooseAccount();
  fireEvent.click(screen.getByRole("button", { name: "读取统计" }));
  fireEvent.change(screen.getByLabelText("统计域名"), { target: { value: "domain-a2" } });
  fireEvent.change(screen.getByLabelText("统计时间范围"), { target: { value: "30" } });
  fireEvent.click(screen.getByRole("button", { name: "读取统计" }));
  oldRequest.resolve(response({ totals: { total: 999, likelyHuman: 900, likelyBot: 70, unknown: 29, previews: 0, prefetches: 0 } }));
  currentRequest.resolve(response({
    domainId: "domain-a2", days: 30,
    totals: { total: 333, likelyHuman: 300, likelyBot: 20, unknown: 13, previews: 3, prefetches: 2 },
    rows: [row("domain-a2", "sample-02", { total: 333, likelyHuman: 300, likelyBot: 20, unknown: 13, previews: 3, prefetches: 2 })],
  }));
  await expectSummary("333");
  expect(within(screen.getByLabelText("估算总访问")).queryByText("999")).toBeNull();
});

it("keeps page responses scoped and uses a fixed page size of 25", async () => {
  const secondPage = deferred<StatsCenterReport>();
  const latestFirstPage = deferred<StatsCenterReport>();
  mockedDispatch
    .mockResolvedValueOnce(response({ totalLinks: 30, rows: [row()] }))
    .mockImplementationOnce(() => secondPage.promise)
    .mockImplementationOnce(() => latestFirstPage.promise);
  render(view());
  chooseAccount();
  fireEvent.click(screen.getByRole("button", { name: "读取统计" }));
  expect(await screen.findByText(/第 1 \/ 2 页/)).toBeTruthy();
  fireEvent.click(screen.getByRole("button", { name: "下一页统计" }));
  expect(screen.getByText(/第 2 \/ 2 页/)).toBeTruthy();
  fireEvent.click(screen.getByRole("button", { name: "上一页统计" }));
  latestFirstPage.resolve(response({
    totalLinks: 30,
    totals: { total: 111, likelyHuman: 90, likelyBot: 12, unknown: 9, previews: 1, prefetches: 1 },
    rows: [row("domain-a1", "sample-01", { total: 111, likelyHuman: 90, likelyBot: 12, unknown: 9, previews: 1, prefetches: 1 })],
  }));
  await expectSummary("111");
  secondPage.resolve(response({
    page: 2, totalLinks: 30,
    totals: { total: 999, likelyHuman: 900, likelyBot: 70, unknown: 29, previews: 0, prefetches: 0 },
    rows: [row("domain-a1", "sample-03")],
  }));
  await waitFor(() => expect(within(screen.getByLabelText("估算总访问")).queryByText("999")).toBeNull());
  expect(mockedDispatch.mock.calls.map((call) => call[1]?.page)).toEqual([1, 2, 1]);
  expect(mockedDispatch.mock.calls.every((call) => call[1]?.pageSize === 25)).toBe(true);
});

it("shows failures as failures rather than zero and binds configuration errors to an account", async () => {
  mockedDispatch.mockRejectedValue(new Error("读取暂时失败"));
  const { rerender } = render(view({ configurationError: { accountId: "account-a", message: "账户 A 缺少 AccountAnalyticsRead 权限" } }));
  chooseAccount("示例账户 B");
  expect(screen.queryByText("账户 A 缺少 AccountAnalyticsRead 权限")).toBeNull();
  chooseAccount();
  expect(screen.getByText("账户 A 缺少 AccountAnalyticsRead 权限")).toBeTruthy();
  expect(screen.getByText(/核对原有 API 令牌/)).toBeTruthy();
  expect(screen.getByText(/对应账户已启用 Analytics Engine/)).toBeTruthy();
  expect(screen.getByRole("button", { name: "打开并编辑原有令牌" })).toBeTruthy();
  expect(screen.getByRole("button", { name: "打开 Cloudflare 统计服务" })).toBeTruthy();
  fireEvent.click(screen.getByRole("button", { name: "读取统计" }));
  expect(await screen.findByText("读取暂时失败")).toBeTruthy();
  expect(screen.queryByText(/^0$/)).toBeNull();
  fireEvent.click(screen.getByRole("button", { name: "检查并停用账户统计" }));
  expect(onConfigure).toHaveBeenCalledWith(accounts[0], false);
  rerender(view({ configurationError: { accountId: "account-b", message: "账户 B 的计划失败" } }));
  expect(screen.queryByText("账户 B 的计划失败")).toBeNull();
});

it("keeps no-data distinct from a historical zero and can list current links with zero period rows", async () => {
  mockedDispatch.mockResolvedValue(response({
    status: "no_data", message: "当前账户尚无本机短链接。", totals: undefined,
    rows: [row("domain-a1", "sample-01", zeroTotals)],
  }));
  render(view());
  chooseAccount();
  fireEvent.click(screen.getByRole("button", { name: "读取统计" }));
  expect(await screen.findByText("当前没有可汇总的结果")).toBeTruthy();
  expect(screen.getByText(/不代表历史访问为零/)).toBeTruthy();
  expect(screen.queryByLabelText("估算总访问")).toBeNull();
  expect(screen.getByRole("table", { name: "当前本机短链接统计" })).toBeTruthy();
  fireEvent.click(screen.getByRole("button", { name: "检查并停用账户统计" }));
  expect(onConfigure).toHaveBeenCalledWith(accounts[0], false);
});

it("keeps the check-and-disable plan available when no local links exist", async () => {
  mockedDispatch.mockResolvedValue(response({
    status: "no_data", message: "当前账户尚无本机短链接。", totals: undefined,
    totalLinks: 0, rows: [],
  }));
  render(view({ links: [] }));
  chooseAccount();
  fireEvent.click(screen.getByRole("button", { name: "读取统计" }));
  expect(await screen.findByText("当前没有可汇总的结果")).toBeTruthy();
  expect(screen.queryByLabelText("估算总访问")).toBeNull();
  fireEvent.click(screen.getByRole("button", { name: "检查并停用账户统计" }));
  expect(onConfigure).toHaveBeenCalledWith(accounts[0], false);
});

it("offers the existing plan callback for a disabled selected account", async () => {
  mockedDispatch.mockResolvedValue(response({ status: "disabled", totals: undefined, rows: undefined }));
  render(view());
  chooseAccount();
  fireEvent.click(screen.getByRole("button", { name: "读取统计" }));
  fireEvent.click(await screen.findByRole("button", { name: "启用账户统计" }));
  expect(onConfigure).toHaveBeenCalledWith(accounts[0], true);
  expect(screen.getByText(/AccountAnalyticsRead/)).toBeTruthy();
  expect(screen.getByText(/开通 Analytics Engine/)).toBeTruthy();
  expect(screen.getByRole("button", { name: "打开 API 令牌管理" })).toBeTruthy();
  expect(screen.getByRole("button", { name: "打开 Analytics Engine" })).toBeTruthy();
  expect(mockedDispatch).toHaveBeenCalledTimes(1);
});

it("treats permission denial as either token permission or account service configuration", async () => {
  mockedDispatch.mockResolvedValue(response({
    status: "permission_denied", message: "Cloudflare 拒绝了统计读取。", totals: undefined, rows: undefined,
  }));
  render(view());
  chooseAccount();
  fireEvent.click(screen.getByRole("button", { name: "读取统计" }));
  expect(await screen.findByText("统计读取被拒绝")).toBeTruthy();
  expect(screen.getByText(/原有 API 令牌/)).toBeTruthy();
  expect(screen.getByText(/对应账户是否已开通 Analytics Engine/)).toBeTruthy();
  expect(screen.getByRole("button", { name: "打开 API 令牌管理" })).toBeTruthy();
  expect(screen.getByRole("button", { name: "打开 Analytics Engine" })).toBeTruthy();
  expect(screen.queryByText("令牌缺少统计读取权限")).toBeNull();
});

it("opens Analytics Engine for the selected validated Cloudflare account only", async () => {
  const accountId = "a".repeat(32);
  const scopedAccount = { ...accounts[0], id: accountId };
  const scopedDomain = { ...domains[0], accountId };
  const scopedLink = { ...links[0], domainId: scopedDomain.id };
  mockedDispatch.mockResolvedValue(response({
    status: "permission_denied", accountId, message: "Cloudflare 拒绝了统计读取。",
    totals: undefined, rows: undefined,
  }));
  render(view({ accounts: [scopedAccount], domains: [scopedDomain], links: [scopedLink] }));
  fireEvent.change(screen.getByLabelText("统计账户"), { target: { value: accountId } });
  fireEvent.click(screen.getByRole("button", { name: "读取统计" }));
  fireEvent.click(await screen.findByRole("button", { name: "打开 Analytics Engine" }));
  await waitFor(() => expect(mockedOpenUrl).toHaveBeenCalledWith(
    `https://dash.cloudflare.com/${accountId}/workers/analytics-engine`,
  ));
});

function centerAppState() {
  return { accounts, domains, links: [links[0]], pools: [], pendingOperations: [], pendingActions: [] };
}

function centerDisabled(payload: Record<string, unknown> | undefined): StatsCenterReport {
  return response({
    status: "disabled",
    message: "此账户尚未启用访问统计。",
    accountId: String(payload?.accountId || ""),
    totals: undefined,
    rows: undefined,
  });
}

function enablePlan() {
  return {
    id: "enable-account-a",
    title: "启用示例账户 A 的点击统计",
    steps: ["启用账户统计"],
    warnings: [],
    expiresAt: "2026-10-15T04:00:00Z",
  };
}

async function beginDeferredCenterEnable() {
  const prepared = deferred<ReturnType<typeof enablePlan>>();
  mockedDispatch.mockImplementation((action, payload) => {
    if (action === "get_state") return Promise.resolve(centerAppState());
    if (action === "get_stats_center") return Promise.resolve(centerDisabled(payload));
    if (action === "prepare_change") return prepared.promise;
    return Promise.reject(new Error(`unexpected action: ${action}`));
  });
  render(<App />);
  fireEvent.click(await screen.findByRole("button", { name: "统计中心" }));
  chooseAccount();
  fireEvent.click(screen.getByRole("button", { name: "读取统计" }));
  fireEvent.click(await screen.findByRole("button", { name: "启用账户统计" }));
  await waitFor(() => expect(mockedDispatch.mock.calls.some(([action]) => action === "prepare_change")).toBe(true));
  return prepared;
}

it("rejects a late account plan after the center selects another account", async () => {
  const prepared = await beginDeferredCenterEnable();
  chooseAccount("示例账户 B");
  await act(async () => prepared.resolve(enablePlan()));
  expect(screen.queryByRole("dialog", { name: "启用示例账户 A 的点击统计" })).toBeNull();
  expect((screen.getByLabelText("统计账户") as HTMLSelectElement).value).toBe("account-b");
});

it("rejects a late account plan after leaving the statistics center", async () => {
  const prepared = await beginDeferredCenterEnable();
  fireEvent.click(screen.getByRole("button", { name: /^短链接/ }));
  await act(async () => prepared.resolve(enablePlan()));
  expect(screen.queryByRole("dialog", { name: "启用示例账户 A 的点击统计" })).toBeNull();
  expect(screen.getByRole("heading", { name: "短链接" })).toBeTruthy();
});

it("wires the independent App navigation to the center and reuses detailed link statistics", async () => {
  const state = { accounts, domains, links: [links[0]], pools: [], pendingOperations: [], pendingActions: [] };
  mockedDispatch.mockImplementation((action) => {
    if (action === "get_state") return Promise.resolve(state);
    if (action === "get_stats_center") return Promise.resolve(response());
    if (action === "get_link_stats") return Promise.resolve({
      status: "ready", message: "单链接示例", domainId: "domain-a1", slug: "sample-01", days: 7,
      queriedAt: "2026-10-15T03:20:00Z", estimated: true, totals,
    });
    return Promise.reject(new Error(`unexpected action: ${action}`));
  });
  render(<App />);
  fireEvent.click(await screen.findByRole("button", { name: "统计中心" }));
  expect(screen.getByRole("heading", { name: "统计中心" })).toBeTruthy();
  expect(mockedDispatch.mock.calls.filter((call) => call[0] === "get_stats_center")).toHaveLength(0);
  chooseAccount();
  fireEvent.click(screen.getByRole("button", { name: "读取统计" }));
  await expectSummary("120");
  fireEvent.click(screen.getByRole("button", { name: "查看 sample-01 的详细统计" }));
  expect(await screen.findByRole("dialog", { name: "访问统计 · /sample-01" })).toBeTruthy();
  expect(mockedDispatch.mock.calls.filter((call) => call[0] === "get_link_stats")).toHaveLength(1);
});
