import { act, cleanup, fireEvent, render, screen, within } from "@testing-library/react";
import { afterEach, beforeEach, expect, it, vi } from "vitest";
import App from "./App";
import type { UpdateStatus } from "./types";

const c = vi.hoisted(() => ({
  result: { status: "available", currentVersion: "0.1.19", version: "0.1.20" } as UpdateStatus,
  installResult: { status: "installed", currentVersion: "0.1.19", version: "0.1.20" } as UpdateStatus,
  fail: false,
  deferred: null as Promise<UpdateStatus> | null,
  calls: [] as string[],
}));
vi.mock("./bridge", () => ({
  preview: false,
  errorMessage: (e: unknown) => e instanceof Error ? e.message : String(e),
  dispatch: async (action: string) => {
    c.calls.push(action);
    if (action === "get_state") return { appVersion: "0.1.19", accounts: [], domains: [], links: [], pools: [], pendingOperations: [], pendingActions: [] };
    if (action === "check_update") {
      if (c.fail) throw Error("网络不可用，请稍后重试");
      return c.deferred || c.result;
    }
    if (action === "install_update") return c.installResult;
    throw Error(action);
  },
}));
beforeEach(() => { vi.useFakeTimers(); });
afterEach(() => {
  cleanup(); vi.useRealTimers(); vi.restoreAllMocks();
  c.calls = []; c.fail = false; c.deferred = null;
  c.result = { status: "available", currentVersion: "0.1.19", version: "0.1.20" };
  c.installResult = { status: "installed", currentVersion: "0.1.19", version: "0.1.20" };
});
async function start() { await act(async () => { render(<App />); }); }
async function advance(ms: number) { await act(async () => { await vi.advanceTimersByTimeAsync(ms); }); }
async function click(name: string) { await act(async () => { fireEvent.click(screen.getByRole("button", { name })); }); }

it("quietly discovers a release without opening a dialog, installing, or disabling account navigation", async () => {
  await start(); expect(c.calls).toEqual(["get_state"]);
  await advance(5000);
  expect(screen.getByRole("region", { name: "新版本提醒" }).textContent).toContain("0.1.20");
  expect(screen.queryByRole("dialog")).toBeNull();
  expect(c.calls).toEqual(["get_state", "check_update"]);
  await click("Cloudflare 账户");
  expect(screen.getByRole("heading", { name: "Cloudflare 账户", level: 1 })).toBeTruthy();
  expect(screen.getByRole("button", { name: /发现新版本/ })).toBeTruthy();
});

it("retains the sidebar badge after dismissing the top reminder and update details", async () => {
  await start(); await advance(5000);
  await click("暂时收起更新提醒");
  expect(screen.queryByRole("region", { name: "新版本提醒" })).toBeNull();
  await act(async () => { fireEvent.click(screen.getByRole("button", { name: /发现新版本/ })); });
  const dialog = screen.getByRole("dialog", { name: "应用更新" });
  expect(dialog.textContent).toContain("0.1.20");
  await click("稍后再说");
  expect(screen.queryByRole("dialog")).toBeNull();
  expect(screen.getByRole("button", { name: /发现新版本/ })).toBeTruthy();
  expect(c.calls.filter(a => a === "check_update")).toHaveLength(1);
});

it("keeps automatic failures quiet, but reports manual failures and permits immediate retry", async () => {
  c.fail = true; await start(); await advance(5000);
  expect(screen.queryByRole("alert")).toBeNull();
  expect(screen.queryByRole("region", { name: "新版本提醒" })).toBeNull();
  await click("检查更新");
  expect(screen.getByRole("alert").textContent).toContain("网络不可用");
  c.fail = false; await click("检查更新");
  expect(screen.getByRole("dialog", { name: "应用更新" }).textContent).toContain("0.1.20");
  expect(screen.queryByRole("alert")).toBeNull();
});

it("does not report missing update metadata as a new release", async () => {
  c.result = { status: "available" }; await start(); await advance(5000);
  expect(screen.queryByRole("region", { name: "新版本提醒" })).toBeNull();
  await click("检查更新");
  expect(screen.getByRole("alert").textContent).toContain("未能确认更新状态");
});

it("does not recheck on repeated focus events and checks again after six hours", async () => {
  c.result = { status: "up_to_date", currentVersion: "0.1.19" };
  await start(); await advance(5000);
  await act(async () => { fireEvent.focus(window); fireEvent.focus(window); });
  expect(c.calls.filter(a => a === "check_update")).toHaveLength(1);
  await advance(6 * 3600_000);
  expect(c.calls.filter(a => a === "check_update")).toHaveLength(2);
});

it("does not check while hidden and checks on return without requiring a restart", async () => {
  const visibility = vi.spyOn(document, "visibilityState", "get").mockReturnValue("hidden");
  await start(); await advance(5000);
  expect(c.calls).toEqual(["get_state"]);
  visibility.mockReturnValue("visible");
  await act(async () => { fireEvent(document, new Event("visibilitychange")); });
  expect(screen.getByRole("region", { name: "新版本提醒" })).toBeTruthy();
});

it("shares an outstanding check and allows normal UI work while the network is slow", async () => {
  let finish!: (result: UpdateStatus) => void;
  c.deferred = new Promise(resolve => { finish = resolve; });
  await start(); await advance(5000);
  await act(async () => { fireEvent.focus(window); });
  expect((screen.getByRole("button", { name: "正在检查更新…" }) as HTMLButtonElement).disabled).toBe(true);
  await click("Cloudflare 账户");
  expect(screen.getAllByRole("button", { name: "导入账户" }).every(button => !(button as HTMLButtonElement).disabled)).toBe(true);
  expect(c.calls.filter(a => a === "check_update")).toHaveLength(1);
  await act(async () => { finish(c.result); });
  expect(screen.queryByRole("dialog")).toBeNull();
});

it("shows a newly released version even if an older banner was dismissed", async () => {
  await start(); await advance(5000); await click("暂时收起更新提醒");
  c.result = { status: "available", version: "0.1.21", currentVersion: "0.1.19" };
  await advance(6 * 3600_000);
  await act(async () => { fireEvent.focus(window); });
  expect(screen.getByRole("region", { name: "新版本提醒" }).textContent).toContain("0.1.21");
});

it.each(["up_to_date", "unavailable"] as const)("does not claim installation success for %s", async status => {
  c.installResult = { status, currentVersion: "0.1.19" };
  await start(); await click("检查更新"); await click("确认安装更新");
  const dialog = screen.getByRole("dialog", { name: "应用更新" });
  expect(dialog.textContent).not.toContain("已安装");
  expect(screen.queryByRole("button", { name: /发现新版本/ })).toBeNull();
  expect(c.calls.filter(a => a === "install_update")).toHaveLength(1);
});

it("keeps a restart reminder and stops old-binary checks after confirmed installation", async () => {
  await start(); await click("检查更新"); await click("确认安装更新");
  const dialog = screen.getByRole("dialog", { name: "应用更新" });
  expect(dialog.textContent).toContain("请退出并重新打开软件");
  await act(async () => { fireEvent.click(within(dialog).getByLabelText("关闭")); });
  // Closing the dialog cannot discard the restart reminder.
  expect(screen.getByRole("status", { name: "更新已安装" }).textContent).toContain("0.1.20");
  await advance(7 * 3600_000); await act(async () => { fireEvent.focus(window); });
  expect(c.calls.filter(a => a === "check_update")).toHaveLength(1);
  expect(screen.getByText(/配置保存在本机.*v0.1.19/)).toBeTruthy();
});

it("cleans up automatic work after unmount", async () => {
  await start(); cleanup(); await advance(7 * 3600_000);
  await act(async () => { fireEvent.focus(window); });
  expect(c.calls).toEqual(["get_state"]);
});

it("ignores stale background availability after a confirmed installation", async () => {
  await start(); await advance(5000);
  let finish!: (result: UpdateStatus) => void;
  c.deferred = new Promise(resolve => { finish = resolve; });
  await advance(6 * 3600_000);
  await click("查看更新"); await click("确认安装更新");
  expect(screen.getByRole("status", { name: "更新已安装" })).toBeTruthy();
  await act(async () => { finish(c.result); });
  expect(screen.queryByRole("region", { name: "新版本提醒" })).toBeNull();
  expect(screen.queryByRole("button", { name: /发现新版本/ })).toBeNull();
  expect(screen.getByRole("dialog", { name: "应用更新" }).textContent).toContain("已安装");
});
