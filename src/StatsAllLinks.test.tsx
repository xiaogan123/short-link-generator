import { cleanup, fireEvent, render, screen, within } from "@testing-library/react";
import { afterEach, expect, it, vi } from "vitest";
import StatsAllLinks, { type AllStatsLinkItem } from "./StatsAllLinks";
import type { Account, ClickStatsTotals, Domain, Link } from "./types";

const zero: ClickStatsTotals = { total: 0, likelyHuman: 0, likelyBot: 0, unknown: 0, previews: 0, prefetches: 0 };
const onOpenLinkStats = vi.fn();
const account = (id: string): Account => ({ id, label: `账户 ${id}`, zoneCount: 1, checkedAt: null, hasResources: true, needsSelftestKey: false });
const domain = (id: string, accountId: string): Domain => ({ id, accountId, zoneId: `zone-${id}`, host: `${id}.example.com`, prefix: "r", routeId: `route-${id}` });
const link = (domainId: string, slug: string): Link => ({ domainId, slug, cnUrl: "https://example.com/zh", defaultUrl: "https://example.com/en", updated: "2026-10-15" });
const item = (accountId: string, domainId: string, slug: string, total?: number): AllStatsLinkItem => ({
  account: account(accountId), domain: domain(domainId, accountId), link: link(domainId, slug),
  status: total === undefined ? "pending" : "ready",
  totals: total === undefined ? undefined : { ...zero, total, likelyHuman: total, likelyBot: 0 },
});

function view(items: AllStatsLinkItem[], loading = false) {
  return <StatsAllLinks items={items} loading={loading} onOpenLinkStats={onOpenLinkStats} />;
}

afterEach(() => { cleanup(); vi.clearAllMocks(); });

it("keeps equal slugs on different accounts distinct and opens the correct link and domain", () => {
  const first = item("A", "a", "same", 5);
  const second = item("B", "b", "same", 8);
  render(view([first, second]));
  const table = screen.getByRole("table", { name: "全部短链接统计" });
  const rows = within(table).getAllByRole("row").slice(1);
  expect(rows).toHaveLength(2);
  expect(within(rows[0]).getByText("https://b.example.com/r/same")).toBeTruthy();
  expect(within(rows[1]).getByText("https://a.example.com/r/same")).toBeTruthy();
  fireEvent.click(within(rows[0]).getByRole("button", { name: "详细统计" }));
  expect(onOpenLinkStats).toHaveBeenCalledWith(second.link, second.domain);
  fireEvent.click(within(rows[1]).getByRole("button", { name: "详细统计" }));
  expect(onOpenLinkStats).toHaveBeenLastCalledWith(first.link, first.domain);
});

it("searches full URLs, keeps unread counts unknown, and ranks read zero ahead of unread", () => {
  const items = [item("A", "a", "zero", 0), item("B", "b", "unread")];
  const rendered = render(view(items, true));
  const rows = within(screen.getByRole("table")).getAllByRole("row").slice(1);
  expect(within(rows[0]).getByText("https://a.example.com/r/zero")).toBeTruthy();
  expect(within(rows[0]).getAllByText("0")).toHaveLength(4);
  expect(within(rows[1]).getByText("https://b.example.com/r/unread")).toBeTruthy();
  expect(within(rows[1]).getAllByText("—")).toHaveLength(4);
  expect(screen.getByText(/当前排序只基于已读取结果/)).toBeTruthy();
  rendered.rerender(view(items));
  expect(screen.getByText(/部分链接尚无可用统计/)).toBeTruthy();
  fireEvent.change(screen.getByRole("searchbox", { name: "搜索短链接或账户" }), { target: { value: "HTTPS://B.EXAMPLE.COM/R/UNREAD" } });
  expect(within(screen.getByRole("table")).getAllByRole("row")).toHaveLength(2);
  expect(screen.getByText("https://b.example.com/r/unread")).toBeTruthy();
});

it("sorts and pages locally, then resets for search and changed item identity", () => {
  const items = Array.from({ length: 30 }, (_, index) => item("A", "a", `link-${String(index).padStart(2, "0")}`, index));
  const rendered = render(view(items));
  expect(within(screen.getByRole("table")).getAllByRole("row")).toHaveLength(26);
  expect(screen.getByText("https://a.example.com/r/link-29")).toBeTruthy();
  fireEvent.click(screen.getByRole("button", { name: "下一页" }));
  expect(screen.getByText(/第 2 \/ 2 页/)).toBeTruthy();
  expect(screen.getByText("https://a.example.com/r/link-04")).toBeTruthy();
  fireEvent.change(screen.getByRole("combobox", { name: "排序" }), { target: { value: "name" } });
  expect(screen.getByText(/第 1 \/ 2 页/)).toBeTruthy();
  expect(screen.getByText("https://a.example.com/r/link-00")).toBeTruthy();
  fireEvent.click(screen.getByRole("button", { name: "下一页" }));
  fireEvent.change(screen.getByRole("searchbox", { name: "搜索短链接或账户" }), { target: { value: "link-03" } });
  expect(screen.getByText(/第 1 \/ 1 页/)).toBeTruthy();
  fireEvent.change(screen.getByRole("searchbox", { name: "搜索短链接或账户" }), { target: { value: "" } });
  fireEvent.click(screen.getByRole("button", { name: "下一页" }));
  rendered.rerender(view([item("B", "b", "new", 2)]));
  expect(screen.getByText(/第 1 \/ 1 页/)).toBeTruthy();
  expect(screen.getByText("https://b.example.com/r/new")).toBeTruthy();
});
