import { cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { afterEach, expect, it, vi } from "vitest";
import { openUrl } from "@tauri-apps/plugin-opener";
import ClickStatsDialog from "./ClickStats";
import { dispatch } from "./bridge";
import type { Account, ClickStats, ClickStatsDays, Domain, Link } from "./types";

vi.mock("./bridge", () => ({
  preview: true,
  dispatch: vi.fn(),
  errorMessage: (error: unknown) => error instanceof Error ? error.message : String(error),
}));
vi.mock("@tauri-apps/plugin-opener", () => ({ openUrl: vi.fn() }));

const mockedDispatch = vi.mocked(dispatch);
const mockedOpenUrl = vi.mocked(openUrl);
const account: Account = {
  id: "account-a", label: "示例账户", zoneCount: 1, checkedAt: null,
  hasResources: true, needsSelftestKey: false,
};
const domain: Domain = {
  id: "domain-a", accountId: account.id, zoneId: "zone-a",
  host: "go.example.com", prefix: "r", routeId: "route-a",
};
const link: Link = {
  domainId: domain.id, slug: "welcome", cnUrl: "https://example.com/cn",
  defaultUrl: "https://example.org/global", updated: "2026-10-01T00:00:00Z",
};
const onClose = vi.fn();
const onConfigure = vi.fn();

function response(status: ClickStats["status"], days: ClickStatsDays = 7, extra: Partial<ClickStats> = {}): ClickStats {
  return {
    status,
    message: `${status} message`,
    domainId: domain.id,
    slug: link.slug,
    days,
    queriedAt: "2026-10-15T03:20:00Z",
    estimated: true,
    ...extra,
  };
}

function view(props: Partial<React.ComponentProps<typeof ClickStatsDialog>> = {}) {
  return <ClickStatsDialog link={link} domain={domain} account={account} onClose={onClose}
    onConfigure={onConfigure} revision={0} {...props} />;
}

function deferred<T>() {
  let resolve!: (value: T) => void;
  let reject!: (reason?: unknown) => void;
  const promise = new Promise<T>((yes, no) => { resolve = yes; reject = no; });
  return { promise, resolve, reject };
}

afterEach(() => {
  cleanup();
  vi.clearAllMocks();
});

it("shows only validated ready totals and explains the estimate and preview data", async () => {
  mockedDispatch.mockResolvedValue(response("ready", 7, {
    totals: { total: 1250, likelyHuman: 900, likelyBot: 240, unknown: 110, previews: 18, prefetches: 7 },
  }));
  render(view());
  expect(await screen.findByText("1,250")).toBeTruthy();
  expect(screen.getByText("900")).toBeTruthy();
  expect(screen.getByText("240")).toBeTruthy();
  expect(screen.getByText("110")).toBeTruthy();
  expect(screen.getByText(/预览请求/).textContent).toContain("18");
  expect(screen.getByText(/预加载请求/).textContent).toContain("7");
  expect(screen.getByText("访问次数，不是去重人数")).toBeTruthy();
  expect(screen.getByText(/本地示例，不是真实统计/)).toBeTruthy();
  expect(mockedDispatch).toHaveBeenCalledWith("get_link_stats", { domainId: domain.id, slug: link.slug, days: 7 });
});

it.each([
  ["disabled" as const, "此账户尚未启用访问统计"],
  ["no_data" as const, "所选时间范围暂无统计"],
  ["unavailable" as const, "暂时无法读取访问统计"],
])("shows %s as an explicit state rather than a zero", async (status, title) => {
  mockedDispatch.mockResolvedValue(response(status));
  render(view());
  expect(await screen.findByText(title)).toBeTruthy();
  expect(screen.queryByText(/^0$/)).toBeNull();
});

it("handles permission guidance on click without opening a page automatically", async () => {
  mockedDispatch.mockResolvedValue(response("permission_denied"));
  render(view());
  expect(await screen.findByText("统计读取被拒绝")).toBeTruthy();
  expect(screen.getByText(/帐户 → 帐户分析 → 读取/)).toBeTruthy();
  expect(mockedOpenUrl).not.toHaveBeenCalled();
  fireEvent.click(screen.getByRole("button", { name: "打开 Cloudflare API 令牌管理" }));
  await waitFor(() => expect(mockedOpenUrl).toHaveBeenCalledWith("https://dash.cloudflare.com/profile/api-tokens"));
  expect(screen.queryByText(/^0$/)).toBeNull();
});

it("opens the selected account analytics service only after an explicit click", async () => {
  mockedDispatch.mockResolvedValue(response("disabled"));
  const accountId = "0123456789abcdef0123456789abcdef";
  render(view({ account: { ...account, id: accountId } }));
  const service = await screen.findByRole("button", { name: "打开 Cloudflare 统计服务" });
  expect(mockedOpenUrl).not.toHaveBeenCalled();
  fireEvent.click(service);
  await waitFor(() => expect(mockedOpenUrl).toHaveBeenCalledWith(`https://dash.cloudflare.com/${accountId}/workers/analytics-engine`));
});

it("rejects an invalid account identifier before opening analytics settings", async () => {
  mockedDispatch.mockResolvedValue(response("permission_denied"));
  render(view({ account: { ...account, id: "../profile?redirect=example.com" } }));
  fireEvent.click(await screen.findByRole("button", { name: "打开 Cloudflare 统计服务" }));
  expect(await screen.findByText("无法确认账户，请先更新账户状态。")).toBeTruthy();
  expect(mockedOpenUrl).not.toHaveBeenCalled();
});

it.each(["permission_denied" as const, "unavailable" as const])("permits preparing a stop plan when %s without claiming success", async (status) => {
  mockedDispatch.mockResolvedValue(response(status));
  render(view());
  const label = status === "permission_denied" ? "停用账户统计" : "检查并停用账户统计";
  const stop = await screen.findByRole("button", { name: label });
  expect(onConfigure).not.toHaveBeenCalled();
  fireEvent.click(stop);
  expect(onConfigure).toHaveBeenCalledWith(false);
  expect(mockedDispatch).toHaveBeenCalledTimes(1);
  expect(screen.queryByText("估算总访问")).toBeNull();
});

it("shows bridge failures without a numeric fallback", async () => {
  mockedDispatch.mockRejectedValueOnce(new Error("local read failed"));
  render(view());
  expect(await screen.findByText("local read failed")).toBeTruthy();
  expect(screen.queryByText(/^0$/)).toBeNull();
  fireEvent.click(screen.getByRole("button", { name: "检查并停用账户统计" }));
  expect(onConfigure).toHaveBeenCalledWith(false);
});

it.each([
  ["缺少固定字段", { total: 3, likelyHuman: 1, likelyBot: 1, unknown: 1, previews: 0 }],
  ["分类合计不一致", { total: 4, likelyHuman: 1, likelyBot: 1, unknown: 1, previews: 0, prefetches: 0 }],
  ["包含 NaN", { total: 3, likelyHuman: 1, likelyBot: Number.NaN, unknown: 2, previews: 0, prefetches: 0 }],
  ["超过安全整数", { total: Number.MAX_SAFE_INTEGER + 1, likelyHuman: Number.MAX_SAFE_INTEGER, likelyBot: 1, unknown: 0, previews: 0, prefetches: 0 }],
])("rejects ready totals when %s", async (_label, totals) => {
  mockedDispatch.mockResolvedValue(response("ready", 7, {
    totals: totals as ClickStats["totals"],
  }));
  render(view());
  expect(await screen.findByText(/统计结果不完整/)).toBeTruthy();
  expect(screen.queryByText(/^0$/)).toBeNull();
});

it("requests 1, 7 and 30 day ranges and reloads when revision changes", async () => {
  mockedDispatch.mockImplementation(async (_action, payload = {}) => response("no_data", payload.days as ClickStatsDays));
  const { rerender } = render(view());
  await screen.findByText("所选时间范围暂无统计");
  fireEvent.change(screen.getByRole("combobox", { name: "统计时间范围" }), { target: { value: "1" } });
  await waitFor(() => expect(mockedDispatch).toHaveBeenCalledWith("get_link_stats", { domainId: domain.id, slug: link.slug, days: 1 }));
  fireEvent.change(screen.getByRole("combobox", { name: "统计时间范围" }), { target: { value: "30" } });
  await waitFor(() => expect(mockedDispatch).toHaveBeenCalledWith("get_link_stats", { domainId: domain.id, slug: link.slug, days: 30 }));
  const callsBeforeRevision = mockedDispatch.mock.calls.length;
  rerender(view({ revision: 1 }));
  await waitFor(() => expect(mockedDispatch.mock.calls.length).toBe(callsBeforeRevision + 1));
});

it("never lets an older link response overwrite the current link", async () => {
  const first = deferred<ClickStats>();
  const second = deferred<ClickStats>();
  mockedDispatch.mockReturnValueOnce(first.promise).mockReturnValueOnce(second.promise);
  const { rerender } = render(view());
  const otherLink = { ...link, slug: "current" };
  rerender(view({ link: otherLink }));
  second.resolve({ ...response("ready"), slug: otherLink.slug, totals: { total: 22, likelyHuman: 20, likelyBot: 1, unknown: 1, previews: 2, prefetches: 1 } });
  expect(await screen.findByText("22")).toBeTruthy();
  first.resolve({ ...response("ready"), totals: { total: 999, likelyHuman: 999, likelyBot: 0, unknown: 0, previews: 0, prefetches: 0 } });
  await waitFor(() => expect(screen.queryByText("999")).toBeNull());
  expect(screen.getByText("22")).toBeTruthy();
});

it("rejects a response whose identity does not match the requested range", async () => {
  mockedDispatch.mockResolvedValue(response("ready", 1, {
    totals: { total: 99, likelyHuman: 90, likelyBot: 5, unknown: 4, previews: 0, prefetches: 0 },
  }));
  render(view());
  expect(await screen.findByText(/与当前链接或时间范围不一致/)).toBeTruthy();
  expect(screen.queryByText("99")).toBeNull();
});

it("keeps close available and bounds repeated refreshes while a read is pending", async () => {
  const pending = deferred<ClickStats>();
  mockedDispatch.mockReturnValue(pending.promise);
  render(view({ busy: true }));
  const dialog = screen.getByRole("dialog", { name: `访问统计 · /${link.slug}` });
  const refresh = within(dialog).getByRole("button", { name: "刷新访问统计" }) as HTMLButtonElement;
  expect(refresh.disabled).toBe(true);
  fireEvent.click(refresh);
  fireEvent.click(refresh);
  expect(mockedDispatch).toHaveBeenCalledTimes(1);
  const closeButtons = within(dialog).getAllByRole("button", { name: "关闭" });
  closeButtons.forEach((button) => expect((button as HTMLButtonElement).disabled).toBe(false));
  fireEvent.click(closeButtons[0]);
  expect(onClose).toHaveBeenCalledTimes(1);
});

it("only asks the parent to configure after an explicit click", async () => {
  mockedDispatch.mockResolvedValueOnce(response("disabled"));
  const { rerender } = render(view());
  const enable = await screen.findByRole("button", { name: "启用账户统计" });
  expect(onConfigure).not.toHaveBeenCalled();
  fireEvent.click(enable);
  expect(onConfigure).toHaveBeenCalledWith(true);

  mockedDispatch.mockResolvedValueOnce(response("no_data"));
  rerender(view({ revision: 1 }));
  const disable = await screen.findByRole("button", { name: "停用账户统计" });
  fireEvent.click(disable);
  expect(onConfigure).toHaveBeenCalledWith(false);
  expect(mockedDispatch.mock.calls.every(([action]) => action === "get_link_stats")).toBe(true);
});

it("does not read or configure through a missing or migration-pending account", async () => {
  const { rerender } = render(view({ account: undefined, configurationError: "准备计划失败" }));
  expect((await screen.findAllByText("未连接账户")).length).toBeGreaterThan(0);
  expect(screen.getByRole("alert").textContent).toContain("准备计划失败");
  expect((screen.getByRole("button", { name: "启用账户统计" }) as HTMLButtonElement).disabled).toBe(true);
  expect(mockedDispatch).not.toHaveBeenCalled();

  rerender(view({ account: { ...account, needsCredentialMigration: true }, revision: 1 }));
  expect(await screen.findByText("需要先更新本机授权")).toBeTruthy();
  expect(mockedDispatch).not.toHaveBeenCalled();
});
