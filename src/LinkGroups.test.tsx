import { cleanup, fireEvent, render, screen, within } from "@testing-library/react";
import { afterEach, expect, it, vi } from "vitest";
import LinkGroups from "./LinkGroups";
import type { Domain, Link, Pool } from "./types";

const domain: Domain = {
  id: "domain-a", accountId: "account-a", zoneId: "zone-a",
  host: "go.example.com", prefix: "r", routeId: "route-a",
};
const otherDomain: Domain = { ...domain, id: "domain-b", host: "links.example.org", prefix: "s" };
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
const detection = () => ({ label: "结果已过期", tone: "slate" as const, detail: "本机网络 · 2026/09/30 10:01" });
function view(groups = [{ domain, links: [manual] }], pools: Pool[] = []) {
  return <LinkGroups groups={groups} pools={pools} getDetection={detection}
    onCopy={onCopy} onCheck={onCheck} onEdit={onEdit} onDelete={onDelete} onCreate={onCreate} />;
}
function groupFor(host: string) { return screen.getByRole("region", { name: `${host} 的短链接` }); }
function rowFor(host: string, slug: string) {
  const prefix = host === domain.host ? domain.prefix : otherDomain.prefix;
  return within(groupFor(host)).getByRole("row", { name: `https://${host}/${prefix}/${slug}` });
}
afterEach(() => { cleanup(); vi.clearAllMocks(); });

it("uses semantic table headers and keeps actions bound to their original link and domain", () => {
  render(view());
  const table = within(groupFor(domain.host)).getByRole("table", { name: `${domain.host} 的链接列表` });
  expect(within(table).getAllByRole("columnheader").map((item) => item.textContent)).toEqual(["短链接", "目标类型", "检测与更新", "操作"]);
  const row = rowFor(domain.host, manual.slug);
  expect(within(row).getByText("结果已过期")).toBeTruthy();
  expect(within(row).queryByText(/检测通过/)).toBeNull();
  expect(within(groupFor(domain.host)).queryByText(manual.cnUrl)).toBeNull();
  fireEvent.click(within(row).getByRole("button", { name: "复制 manual" }));
  fireEvent.click(within(row).getByRole("button", { name: "检测 manual" }));
  fireEvent.click(within(row).getByRole("button", { name: "编辑 manual" }));
  const details = within(row).getByRole("button", { name: "详情 manual" });
  expect(details.getAttribute("aria-expanded")).toBe("false");
  fireEvent.click(details);
  expect(details.getAttribute("aria-expanded")).toBe("true");
  expect(within(groupFor(domain.host)).getByText(manual.cnUrl)).toBeTruthy();
  expect(within(groupFor(domain.host)).getByText(manual.defaultUrl)).toBeTruthy();
  fireEvent.click(within(groupFor(domain.host)).getByRole("button", { name: "删除 manual" }));
  expect(onCopy).toHaveBeenCalledWith("https://go.example.com/r/manual");
  expect(onCheck).toHaveBeenCalledWith(manual, domain);
  expect(onEdit).toHaveBeenCalledWith(manual);
  expect(onDelete).toHaveBeenCalledWith(manual, domain);
});

it("keeps platform code and an unknown health label honest, with encoded targets in details", () => {
  const linked: Link = { ...manual, slug: "platform", poolId: pool.id, code: "A B" };
  render(view([{ domain, links: [linked] }], [pool]));
  const row = rowFor(domain.host, linked.slug);
  expect(within(row).getByText("示例平台")).toBeTruthy();
  expect(within(row).getByText("邀请码：A B")).toBeTruthy();
  expect(within(row).getByText("结果已过期")).toBeTruthy();
  fireEvent.click(within(row).getByRole("button", { name: "详情 platform" }));
  const group = groupFor(domain.host);
  expect(group.textContent).toContain("https://example.com/register?code=A%20B&from=short");
  expect(group.textContent).not.toContain(manual.cnUrl);
  fireEvent.click(within(group).getByText("大陆地址 · 已启用 2 个"));
  expect(group.textContent).toContain("https://example.org/cn/A%20B");
  expect(group.textContent).toContain("https://example.org/backup/A%20B?from=short");
  expect(group.textContent).toContain("https://example.org/old/A%20B");
  expect(within(group).getByText("已停用")).toBeTruthy();
  expect(within(group).queryByRole("button", { name: "将 platform 改为平台地址" })).toBeNull();
});

it("shows missing platform as missing and offers manual conversion only in expanded details", () => {
  const linked: Link = { ...manual, slug: "missing", poolId: "removed", code: "CODE" };
  render(view([{ domain, links: [manual, linked] }], [pool]));
  expect(within(rowFor(domain.host, linked.slug)).getByText("已移除")).toBeTruthy();
  expect(within(groupFor(domain.host)).queryByRole("button", { name: "将 manual 改为平台地址" })).toBeNull();
  fireEvent.click(within(rowFor(domain.host, linked.slug)).getByRole("button", { name: "详情 missing" }));
  expect(within(groupFor(domain.host)).getByText(/平台地址已移除/)).toBeTruthy();
  fireEvent.click(within(rowFor(domain.host, manual.slug)).getByRole("button", { name: "详情 manual" }));
  fireEvent.click(within(groupFor(domain.host)).getByRole("button", { name: "将 manual 改为平台地址" }));
  expect(onEdit).toHaveBeenCalledWith(manual, true);
});

it("offers an expandable full value for a long target address", () => {
  const longUrl = `https://example.com/path/${"segment".repeat(25)}?code=DEMO`;
  render(view([{ domain, links: [{ ...manual, cnUrl: longUrl }] }]));
  fireEvent.click(within(rowFor(domain.host, manual.slug)).getByRole("button", { name: "详情 manual" }));
  const summary = within(groupFor(domain.host)).getByText("查看完整地址").closest("summary")!;
  const disclosure = summary.closest("details") as HTMLDetailsElement;
  expect(disclosure.open).toBe(false);
  fireEvent.click(summary);
  expect(disclosure.open).toBe(true);
  expect(disclosure.querySelector("code")?.textContent).toBe(longUrl);
});

it("paginates each domain at 25/50/100 and resets on changed filtered or deleted links", () => {
  const links = Array.from({ length: 61 }, (_, index) => ({ ...manual, slug: `item-${String(index + 1).padStart(2, "0")}` }));
  const { rerender } = render(view([{ domain, links }]));
  const group = groupFor(domain.host);
  expect(within(group).getByText("显示 1–25 / 共 61 条")).toBeTruthy();
  expect(within(group).getByRole("button", { name: `${domain.host} 上一页` }).hasAttribute("disabled")).toBe(true);
  expect(within(group).queryByRole("row", { name: "https://go.example.com/r/item-26" })).toBeNull();
  fireEvent.click(within(group).getByRole("button", { name: `${domain.host} 顶部下一页` }));
  expect(within(group).getByText("显示 26–50 / 共 61 条")).toBeTruthy();
  expect(within(group).getByRole("row", { name: "https://go.example.com/r/item-26" })).toBeTruthy();
  rerender(view([{ domain, links: [links[40], links[59]] }]));
  expect(within(group).getByText("显示 1–2 / 共 2 条")).toBeTruthy();
  expect(within(group).getByRole("row", { name: "https://go.example.com/r/item-41" })).toBeTruthy();
  rerender(view([{ domain, links }]));
  expect(within(group).getByText("显示 1–25 / 共 61 条")).toBeTruthy();
  fireEvent.change(within(group).getByRole("combobox", { name: `${domain.host} 每页条数` }), { target: { value: "50" } });
  expect(within(group).getByText("显示 1–50 / 共 61 条")).toBeTruthy();
  fireEvent.click(within(group).getByRole("button", { name: `${domain.host} 下一页` }));
  expect(within(group).getByText("显示 51–61 / 共 61 条")).toBeTruthy();
  rerender(view([{ domain, links: links.slice(0, 50) }]));
  expect(within(group).getByText("显示 1–50 / 共 50 条")).toBeTruthy();
  fireEvent.change(within(group).getByRole("combobox", { name: `${domain.host} 每页条数` }), { target: { value: "100" } });
  expect(within(group).getByText("显示 1–50 / 共 50 条")).toBeTruthy();
});

it("scrolls to the domain heading on deliberate pagination, not when search results change", () => {
  const previous = Object.getOwnPropertyDescriptor(HTMLElement.prototype, "scrollIntoView");
  const scroll = vi.fn();
  Object.defineProperty(HTMLElement.prototype, "scrollIntoView", { configurable: true, value: scroll });
  try {
    const links = Array.from({ length: 26 }, (_, index) => ({ ...manual, slug: `item-${index + 1}` }));
    const { rerender } = render(view([{ domain, links }]));
    fireEvent.click(within(groupFor(domain.host)).getByRole("button", { name: `${domain.host} 顶部下一页` }));
    expect(scroll).toHaveBeenCalledWith({ block: "start" });
    scroll.mockClear();
    rerender(view([{ domain, links: links.slice(0, 2) }]));
    expect(scroll).not.toHaveBeenCalled();
    rerender(view([{ domain, links }]));
    fireEvent.change(within(groupFor(domain.host)).getByRole("combobox", { name: `${domain.host} 每页条数` }), { target: { value: "50" } });
    expect(scroll).toHaveBeenCalledWith({ block: "start" });
  } finally {
    if (previous) Object.defineProperty(HTMLElement.prototype, "scrollIntoView", previous);
    else delete (HTMLElement.prototype as unknown as Record<string, unknown>).scrollIntoView;
  }
});

it("isolates same slugs and expanded state across domains", () => {
  const other = { ...manual, domainId: otherDomain.id };
  render(view([{ domain, links: [manual] }, { domain: otherDomain, links: [other] }]));
  fireEvent.click(within(rowFor(otherDomain.host, manual.slug)).getByRole("button", { name: "复制 manual" }));
  fireEvent.click(within(rowFor(domain.host, manual.slug)).getByRole("button", { name: "详情 manual" }));
  expect(within(rowFor(otherDomain.host, manual.slug)).getByRole("button", { name: "详情 manual" }).getAttribute("aria-expanded")).toBe("false");
  expect(onCopy).toHaveBeenCalledWith("https://links.example.org/s/manual");
  fireEvent.click(within(rowFor(otherDomain.host, manual.slug)).getByRole("button", { name: "检测 manual" }));
  expect(onCheck).toHaveBeenCalledWith(other, otherDomain);
});

it("gives a domain with no links its own create action", () => {
  render(view([{ domain, links: [] }]));
  const group = groupFor(domain.host);
  expect(within(group).getByText("0 条链接")).toBeTruthy();
  expect(within(group).queryByRole("table")).toBeNull();
  fireEvent.click(within(group).getByRole("button", { name: "创建第一条短链接" }));
  expect(onCreate).toHaveBeenCalledWith(domain.id);
});
