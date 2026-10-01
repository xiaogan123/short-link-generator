import { cleanup, fireEvent, render, screen, within } from "@testing-library/react";
import { afterEach, expect, it, vi } from "vitest";
import LinkGroups from "./LinkGroups";
import type { Domain, Link, Pool } from "./types";

const domain: Domain = {
  id: "domain-a", accountId: "account-a", zoneId: "zone-a",
  host: "go.example.com", prefix: "r", routeId: "route-a",
};
const manual: Link = {
  domainId: domain.id, slug: "manual", cnUrl: "https://example.com/cn",
  defaultUrl: "https://example.org/global", updated: "2026-09-30T10:00:00Z",
};
const pool: Pool = {
  id: "pool-a", name: "示例平台",
  official: { prefix: "https://example.com/register?code=", suffix: "&from=short" },
  candidates: [
    { id: "first", prefix: "https://example.org/cn/", suffix: "", enabled: true },
    { id: "backup", prefix: "https://example.org/backup/", suffix: "?from=short", enabled: true },
    { id: "old", prefix: "https://example.org/old/", suffix: "", enabled: false },
  ],
  updated: "2026-09-30T10:00:00Z", accountIds: ["account-a"],
};

const onCopy = vi.fn();
const onCheck = vi.fn();
const onEdit = vi.fn();
const onDelete = vi.fn();
const onCreate = vi.fn();

function show(groups = [{ domain, links: [manual] }], pools: Pool[] = []) {
  return render(
    <LinkGroups
      groups={groups}
      pools={pools}
      getDetection={() => ({ label: "结果已过期", tone: "slate", detail: "本机网络 · 2026/09/30 10:01" })}
      onCopy={onCopy}
      onCheck={onCheck}
      onEdit={onEdit}
      onDelete={onDelete}
      onCreate={onCreate}
    />,
  );
}

afterEach(() => {
  cleanup();
  vi.clearAllMocks();
});

it("keeps each link action tied to its original link and domain", () => {
  show();
  const card = screen.getByRole("article", { name: "https://go.example.com/r/manual" });
  expect(within(card).getByText("结果已过期")).toBeTruthy();
  expect(within(card).queryByText(/检测通过/)).toBeNull();
  expect(within(card).getByText("https://example.com/cn")).toBeTruthy();
  expect(within(card).getByText("https://example.org/global")).toBeTruthy();
  fireEvent.click(within(card).getByRole("button", { name: "复制 manual" }));
  fireEvent.click(within(card).getByRole("button", { name: "检测 manual" }));
  fireEvent.click(within(card).getByRole("button", { name: "编辑 manual" }));
  fireEvent.click(within(card).getByRole("button", { name: "删除 manual" }));
  expect(onCopy).toHaveBeenCalledWith("https://go.example.com/r/manual");
  expect(onCheck).toHaveBeenCalledWith(manual, domain);
  expect(onEdit).toHaveBeenCalledWith(manual);
  expect(onDelete).toHaveBeenCalledWith(manual, domain);
});

it("shows a platform name and code, with all enabled and disabled mainland addresses", () => {
  const linked: Link = { ...manual, slug: "platform", poolId: pool.id, code: "A B" };
  show([{ domain, links: [linked] }], [pool]);
  const card = screen.getByRole("article", { name: "https://go.example.com/r/platform" });
  expect(within(card).getByText("示例平台")).toBeTruthy();
  expect(within(card).getByText("A B")).toBeTruthy();
  expect(card.textContent).toContain("https://example.com/register?code=A%20B&from=short");
  expect(card.textContent).not.toContain("https://example.com/cn");
  fireEvent.click(within(card).getByText("大陆地址 · 已启用 2 个"));
  expect(card.textContent).toContain("https://example.org/cn/A%20B");
  expect(card.textContent).toContain("https://example.org/backup/A%20B?from=short");
  expect(card.textContent).toContain("https://example.org/old/A%20B");
  expect(within(card).getByText("已停用")).toBeTruthy();
  expect(within(card).queryByRole("button", { name: "将 platform 改为平台地址" })).toBeNull();
});

it("treats a missing platform as missing and keeps manual conversion available", () => {
  const linked: Link = { ...manual, slug: "missing", poolId: "removed", code: "CODE" };
  show([{ domain, links: [manual, linked] }], [pool]);
  const missing = screen.getByRole("article", { name: "https://go.example.com/r/missing" });
  expect(within(missing).getByText("已移除")).toBeTruthy();
  expect(within(missing).getByText(/平台地址已移除/)).toBeTruthy();
  expect(missing.textContent).not.toContain(manual.cnUrl);
  fireEvent.click(screen.getByRole("button", { name: "将 manual 改为平台地址" }));
  expect(onEdit).toHaveBeenCalledWith(manual, true);
});

it("offers an expandable full value for a long address", () => {
  const longUrl = `https://example.com/path/${"segment".repeat(25)}?code=DEMO`;
  show([{ domain, links: [{ ...manual, cnUrl: longUrl }] }]);
  const card = screen.getByRole("article", { name: "https://go.example.com/r/manual" });
  const summary = within(card).getByText("查看完整地址").closest("summary")!;
  const disclosure = summary.closest("details") as HTMLDetailsElement;
  expect(disclosure.open).toBe(false);
  fireEvent.click(summary);
  expect(disclosure.open).toBe(true);
  expect(disclosure.querySelector("code")?.textContent).toBe(longUrl);
});

it("gives a domain with no links its own create action", () => {
  show([{ domain, links: [] }]);
  const group = screen.getByRole("region", { name: "go.example.com 的短链接" });
  expect(within(group).getByText("0 条链接")).toBeTruthy();
  expect(within(group).queryByRole("table")).toBeNull();
  fireEvent.click(within(group).getByRole("button", { name: "创建第一条短链接" }));
  expect(onCreate).toHaveBeenCalledWith(domain.id);
});
