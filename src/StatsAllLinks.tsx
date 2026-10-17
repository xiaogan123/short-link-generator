import { useEffect, useMemo, useState } from "react";
import type { Account, ClickStatsTotals, Domain, Link } from "./types";
import { dedupLabel } from "./clickDedup";
import "./StatsAllLinks.css";

export type AllStatsLinkItem = {
  account: Account;
  domain: Domain;
  link: Link;
  totals?: ClickStatsTotals;
  status: string;
};

type SortOrder = "total" | "human" | "name";
type Props = {
  items: AllStatsLinkItem[];
  loading: boolean;
  onOpenLinkStats: (link: Link, domain: Domain) => void;
};

const PAGE_SIZE = 25;

function shortUrl({ domain, link }: AllStatsLinkItem) {
  return `https://${domain.host}/${domain.prefix}/${link.slug}`;
}

function formatCount(value: number | undefined) {
  return value === undefined ? "—" : value.toLocaleString("zh-CN");
}

function statusLabel(status: string) {
  const labels: Record<string, string> = {
    ready: "已读取", pending: "未读取", loading: "读取中", disabled: "未启用",
    no_data: "无数据", permission_denied: "权限不足", unavailable: "暂不可用",
    migration: "需迁移授权", error: "读取失败",
  };
  return labels[status] ?? status;
}

export default function StatsAllLinks({ items, loading, onOpenLinkStats }: Props) {
  const [query, setQuery] = useState("");
  const [sort, setSort] = useState<SortOrder>("total");
  const [page, setPage] = useState(1);
  const identity = useMemo(() => JSON.stringify(items.map(({ account, domain, link }) => [account.id, domain.id, link.slug])), [items]);

  useEffect(() => { setPage(1); }, [identity]);

  const visible = useMemo(() => {
    const term = query.trim().toLocaleLowerCase();
    const filtered = items.filter((item) => {
      if (!term) return true;
      const { account, domain, link } = item;
      return [account.label, domain.host, domain.prefix, link.slug, shortUrl(item)]
        .some((value) => value.toLocaleLowerCase().includes(term));
    });
    const lexical = (left: AllStatsLinkItem, right: AllStatsLinkItem) =>
      left.account.label.localeCompare(right.account.label, "zh-CN")
      || left.domain.host.localeCompare(right.domain.host)
      || left.domain.prefix.localeCompare(right.domain.prefix)
      || left.link.slug.localeCompare(right.link.slug)
      || left.account.id.localeCompare(right.account.id)
      || left.domain.id.localeCompare(right.domain.id);
    return filtered.sort((left, right) => {
      if (sort !== "name") {
        const leftCount = left.totals?.[sort === "total" ? "total" : "likelyHuman"];
        const rightCount = right.totals?.[sort === "total" ? "total" : "likelyHuman"];
        if (leftCount === undefined || rightCount === undefined) {
          if (leftCount === undefined && rightCount !== undefined) return 1;
          if (rightCount === undefined && leftCount !== undefined) return -1;
        } else if (leftCount !== rightCount) return rightCount - leftCount;
      }
      return lexical(left, right);
    });
  }, [items, query, sort]);

  const pageCount = Math.max(1, Math.ceil(visible.length / PAGE_SIZE));
  const currentPage = Math.min(page, pageCount);
  const rows = visible.slice((currentPage - 1) * PAGE_SIZE, currentPage * PAGE_SIZE);
  const readCount = items.filter(({ totals }) => totals !== undefined).length;

  return <section className="sall" aria-label="全部短链接">
    <div className="sall-head">
      <div><h2>全部短链接</h2><p>跨账户查看每条短链接的访问统计</p></div>
      <div className="sall-counts"><strong>{formatCount(items.length)}</strong> 条链接 <span>·</span> 已读 {formatCount(readCount)} 条</div>
    </div>
    <div className="sall-controls">
      <label>搜索短链接或账户
        <input value={query} onChange={(event) => { setQuery(event.target.value); setPage(1); }} placeholder="账户、域名、路径或完整短链接" type="search" />
      </label>
      <label>排序
        <select value={sort} onChange={(event) => { setSort(event.target.value as SortOrder); setPage(1); }}>
          <option value="total">总访问降序</option>
          <option value="human">疑似真人降序</option>
          <option value="name">账户与链接</option>
        </select>
      </label>
    </div>
    {loading && <p className="sall-loading" role="status">正在读取统计；当前排序只基于已读取结果，尚不是全部链接的最终排名。</p>}
    {!loading && readCount < items.length && <p className="sall-loading" role="status">部分链接尚无可用统计，显示为“—”；当前排序只比较已读取结果。</p>}
    <div className="sall-scroll">
      <table className="sall-table" aria-label="全部短链接统计">
        <thead><tr><th scope="col">短链接</th><th scope="col">所属账户</th><th scope="col">总访问</th><th scope="col">疑似真人</th><th scope="col">疑似机器人</th><th scope="col">未知</th><th scope="col">操作</th></tr></thead>
        <tbody>{rows.length ? rows.map((item) => <tr key={`${item.account.id}\u0000${item.domain.id}\u0000${item.link.slug}`}>
          <td><span className="sall-url">{shortUrl(item)}</span><small>{statusLabel(item.status)}</small></td>
          <td className="sall-account">{item.account.label}</td>
          <td className="sall-total">{formatCount(item.totals?.total)}{item.totals && <small>{dedupLabel(item.totals)}</small>}</td>
          <td>{formatCount(item.totals?.likelyHuman)}</td>
          <td>{formatCount(item.totals?.likelyBot)}</td>
          <td>{formatCount(item.totals?.unknown)}</td>
          <td><button className="button bordered sall-detail" type="button" onClick={() => onOpenLinkStats(item.link, item.domain)}>详细统计</button></td>
        </tr>) : <tr><td className="sall-empty" colSpan={7}>{items.length ? "没有匹配的短链接" : "暂无短链接"}</td></tr>}</tbody>
      </table>
    </div>
    <div className="sall-pagination">
      <span>第 {currentPage} / {pageCount} 页 · 筛选结果 {formatCount(visible.length)} 条</span>
      <div><button className="button bordered" type="button" disabled={currentPage <= 1} onClick={() => setPage(currentPage - 1)}>上一页</button><button className="button bordered" type="button" disabled={currentPage >= pageCount} onClick={() => setPage(currentPage + 1)}>下一页</button></div>
    </div>
  </section>;
}
