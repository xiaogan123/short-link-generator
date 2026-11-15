// Adding a domain should not need several clicks: a consumed plan is never offered again, a still-valid
// plan can be confirmed again, the VPN is remembered for this run, and results are visible right away.
import { act, cleanup, fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import App from './App';

type Prepared = { reasons?: string[]; label?: string; candidates?: string[]; ready?: boolean };
const control = vi.hoisted(() => ({
  calls: [] as { action: string; payload: Record<string, unknown> }[],
  usedPlanIds: [] as string[],
  applyError: '' as string,
  applyErrorTimes: 0,
  respond: null as null | ((payload: Record<string, unknown>, index: number) => Prepared),
  selftest: null as null | ((payload: Record<string, unknown>) => unknown),
  installed: false,
}));
const accountA = { id: 'a', label: '示例账户', zones: [{ id: 'za', name: 'example.com', status: 'active' }], zoneCount: 1, checkedAt: null, hasResources: true, needsSelftestKey: false };
const accountB = { ...accountA, id: 'b', label: '第二账户', zones: [{ id: 'zb', name: 'example.org', status: 'active' }] };
const state = () => ({
  accounts: [accountA, accountB],
  domains: control.installed ? [{ id: 'd1', accountId: 'a', zoneId: 'za', host: 'go.example.com', prefix: 'r', routeId: 'r1' }] : [],
  links: control.installed ? [{ domainId: 'd1', slug: 'sample', cnUrl: 'https://example.org/cn', defaultUrl: 'https://example.org/en', updated: '2026-01-01T00:00:00Z' }] : [],
  pools: [], pendingOperations: [], pendingActions: [],
});
function prepared(payload: Record<string, unknown>, index: number) {
  const spec = control.respond?.(payload, index) ?? {};
  const reasons = spec.reasons ?? [];
  const ready = spec.ready ?? !reasons.length;
  const candidates = (spec.candidates ?? [String(payload.accountId || 'a')]).map(id => ({ accountId: id, label: id === 'b' ? '第二账户' : '示例账户', zoneId: `z${id}`, status: 'active' }));
  return {
    host: payload.input, prefix: payload.prefix, dnsMode: payload.dnsMode, candidates,
    checks: ready
      ? [{ label: '短链接目录', ok: true, level: 'pass', message: '可接入' }]
      : reasons.map((reason, i) => ({ label: spec.label ?? (i ? `检查项${i}` : '短链接目录'), ok: false, level: 'error', reason, message: `模拟原因 ${reason}` })),
    canApply: ready && candidates.length === 1,
    ...(ready && candidates.length === 1 ? { plan: { id: `plan-${index}`, title: '添加域名', steps: ['重新核对后才提交'], warnings: [], expiresAt: new Date(Date.now() + 300000).toISOString() } } : {}),
  };
}
vi.mock('./bridge', () => ({
  preview: false,
  errorMessage: (e: unknown) => (e instanceof Error ? e.message : String(e)),
  dispatch: async (action: string, payload: Record<string, unknown> = {}) => {
    control.calls.push({ action, payload });
    if (action === 'get_state') return state();
    if (action === 'prepare_domain') return prepared(payload, control.calls.filter(call => call.action === 'prepare_domain').length);
    if (action === 'refresh_domains') return state();
    if (action === 'apply_plan') {
      const id = String(payload.planId);
      if (control.usedPlanIds.includes(id)) throw new Error('计划不存在或已被使用');
      if (control.applyErrorTimes > 0) {
        control.applyErrorTimes -= 1;
        // Like the backend: only a network-only review failure leaves the plan usable.
        if (!control.applyError.includes('接入计划仍然有效')) control.usedPlanIds.push(id);
        throw new Error(control.applyError);
      }
      control.usedPlanIds.push(id);
      control.installed = true;
      return state();
    }
    if (action === 'selftest_link') return control.selftest?.(payload) ?? { status: 'passed', message: '跳转通过', checks: [] };
    if (action === 'check_link_targets') return { checkedAt: new Date().toISOString(), dnsMode: payload.dnsMode || 'system', checks: [] };
    throw new Error(`Unexpected action ${action}`);
  },
}));
beforeEach(() => {
  control.calls = []; control.usedPlanIds = []; control.applyError = ''; control.applyErrorTimes = 0;
  control.respond = null; control.selftest = null; control.installed = false;
});
afterEach(() => { cleanup(); vi.restoreAllMocks(); });

const prepares = () => control.calls.filter(call => call.action === 'prepare_domain');
const applies = () => control.calls.filter(call => call.action === 'apply_plan').map(call => call.payload.planId);
const domainDialog = () => screen.getByRole('dialog', { name: '添加域名' });
async function openDialog() {
  render(<App />); await screen.findByText('先连接一个域名');
  fireEvent.click(screen.getByRole('button', { name: /^域名管理$/ }));
  fireEvent.click(screen.getAllByRole('button', { name: '添加域名' })[0]);
  return domainDialog();
}
async function fill(host = 'new.example.com', account = 'a') {
  const form = await openDialog();
  fireEvent.change(within(form).getByPlaceholderText('go.example.com'), { target: { value: host } });
  fireEvent.change(within(form).getByRole('textbox', { name: /^链接目录/ }), { target: { value: 'visit' } });
  if (account) fireEvent.change(within(form).getByRole('combobox', { name: 'Cloudflare 账户' }), { target: { value: account } });
  return form;
}
async function settle() {
  await waitFor(() => expect(screen.queryByRole('button', { name: '检查中…' })).toBeNull());
  await act(async () => { await Promise.resolve(); });
}
async function check(form: HTMLElement, name = '检查并继续') {
  await act(async () => { fireEvent.click(within(form).getByRole('button', { name })); });
  await settle();
}
async function confirm() {
  await act(async () => { fireEvent.click(screen.getByRole('button', { name: '确认并执行' })); });
  await settle();
}

it('after a failed confirmation that consumed the plan, offers only a fresh check and keeps the draft', async () => {
  control.applyError = '预检状态已变化，请重新检查域名'; control.applyErrorTimes = 1;
  const form = await fill();
  fireEvent.click(within(form).getByText('更多选项与说明'));
  fireEvent.click(within(form).getByRole('checkbox', { name: '直接使用公共 DNS（手动兼容 VPN）' }));
  await check(form);
  await confirm();
  const restored = domainDialog();
  expect(within(restored).getByRole('alert').textContent).toContain('预检状态已变化，请重新检查域名');
  expect(within(restored).queryByRole('button', { name: '查看接入计划' })).toBeNull();
  expect(within(restored).queryByText('可用')).toBeNull();
  expect((within(restored).getByPlaceholderText('go.example.com') as HTMLInputElement).value).toBe('new.example.com');
  expect((within(restored).getByRole('textbox', { name: /^链接目录/ }) as HTMLInputElement).value).toBe('visit');
  expect((within(restored).getByRole('combobox', { name: 'Cloudflare 账户' }) as HTMLSelectElement).value).toBe('a');
  expect((within(restored).getByRole('checkbox', { name: '直接使用公共 DNS（手动兼容 VPN）' }) as HTMLInputElement).checked).toBe(true);
  await check(restored, '重新检查当前状态');
  expect(prepares()).toHaveLength(2);
  expect(prepares()[1].payload).toMatchObject({ input: 'new.example.com', prefix: 'visit', accountId: 'a', dnsMode: 'public' });
  await confirm();
  expect(applies()).toEqual(['plan-1', 'plan-2']);
  expect(screen.queryByRole('dialog')).toBeNull();
});

it('keeps a still-valid plan open after a network-only review failure and confirms the same plan again', async () => {
  control.applyError = '确认前复核时网络查询没完成（公共 DNS 超时）。接入计划仍然有效，云端没有改动，请再点一次确认。';
  control.applyErrorTimes = 1;
  const form = await fill();
  await check(form);
  await confirm();
  const review = screen.getByRole('dialog', { name: '添加域名' });
  expect(within(review).getByRole('alert').textContent).toContain('接入计划仍然有效');
  const again = within(review).getByRole('button', { name: '确认并执行' }) as HTMLButtonElement;
  expect(again.disabled).toBe(false);
  expect(within(review).getByText('域名：new.example.com')).toBeTruthy();
  await confirm();
  expect(applies()).toEqual(['plan-1', 'plan-1']);
  expect(prepares()).toHaveLength(1);
  expect(screen.getByText(/域名已接入/)).toBeTruthy();
});

it('treats a "still valid" message on an expired plan as consumed', async () => {
  control.applyError = '网络查询没完成。接入计划仍然有效。'; control.applyErrorTimes = 1;
  const form = await fill();
  await check(form);
  const realNow = Date.now();
  const spy = vi.spyOn(Date, 'now').mockReturnValue(realNow);
  // The plan expires while the request is in flight.
  await act(async () => {
    fireEvent.click(screen.getByRole('button', { name: '确认并执行' }));
    spy.mockReturnValue(realNow + 600000);
  });
  await settle();
  const restored = domainDialog();
  expect(screen.queryByRole('button', { name: '确认并执行' })).toBeNull();
  // The old results are gone, so the consumed plan cannot come back once the clock is normal again.
  expect(within(restored).queryByText('可用')).toBeNull();
  spy.mockRestore();
  expect(within(restored).queryByRole('button', { name: '查看接入计划' })).toBeNull();
  expect(within(restored).getByRole('alert').textContent).toContain('接入计划仍然有效');
});

it('remembers the VPN for this run, falls back to the local network once when public DNS fails, then forgets it', async () => {
  // check 1: local -> virtual address -> automatic public succeeds (flag set)
  // check 2: starts public (remembered) -> public DNS fails -> one local retry passes (proxy is off), flag cleared
  // check 3: starts local again
  control.respond = (_payload, index) => index === 1 ? { reasons: ['virtual_dns_address'] }
    : index === 3 ? { reasons: ['public_dns_timeout', 'public_dns_failed'] }
    : {};
  const form = await fill();
  await check(form);
  expect(prepares().map(call => call.payload.dnsMode)).toEqual(['system', 'public']);
  fireEvent.click(screen.getByRole('button', { name: '返回' }));
  fireEvent.change(within(domainDialog()).getByRole('textbox', { name: /^链接目录/ }), { target: { value: 'go' } });
  await check(domainDialog());
  expect(prepares().map(call => call.payload.dnsMode)).toEqual(['system', 'public', 'public', 'system']);
  // The local retry passed, so the plan is for the local network and says nothing about public DNS.
  expect(screen.getByRole('button', { name: '确认并执行' })).toBeTruthy();
  expect(screen.queryByText('网络检查：公共 DNS（兼容 VPN）')).toBeNull();
  fireEvent.click(screen.getByRole('button', { name: '返回' }));
  expect(within(domainDialog()).queryByText(/本次已自动切换为公共 DNS/)).toBeNull();
  fireEvent.change(within(domainDialog()).getByRole('textbox', { name: /^链接目录/ }), { target: { value: 'to' } });
  await check(domainDialog());
  expect(prepares().map(call => call.payload.dnsMode)).toEqual(['system', 'public', 'public', 'system', 'system']);
});

it('keeps the public-DNS result and the VPN memory when the one local retry still sees the VPN address', async () => {
  // check 1: local -> virtual address -> automatic public succeeds (flag set)
  // check 2: starts public (remembered) -> public DNS timeout -> one local retry -> virtual address again
  // The proxy is still on: show the retryable public-DNS failure, not a hard "check failed" about the VPN address.
  control.respond = (_payload, index) => index === 1 || index === 4 ? { reasons: ['virtual_dns_address'] }
    : index === 3 ? { reasons: ['public_dns_timeout'] }
    : {};
  const form = await fill();
  await check(form);
  fireEvent.click(screen.getByRole('button', { name: '返回' }));
  fireEvent.change(within(domainDialog()).getByRole('textbox', { name: /^链接目录/ }), { target: { value: 'go' } });
  await check(domainDialog());
  // No loop: one public round, one local round, and public DNS is not tried again in this check.
  expect(prepares().map(call => call.payload.dnsMode)).toEqual(['system', 'public', 'public', 'system']);
  const summary = domainDialog().querySelector('.dialog-status .domain-summary') as HTMLElement;
  expect(summary.textContent).toContain('网络查询没完成（模拟原因 public_dns_timeout）。通常再查一次就好。');
  expect(domainDialog().textContent).not.toContain('检查没通过');
  expect(within(domainDialog()).getByText(/本次已自动切换为公共 DNS/)).toBeTruthy();
  expect(within(domainDialog()).getByText('网络查询没完成，通常再查一次就好；还不行再检查 VPN 或网络。域名尚未接入。')).toBeTruthy();
  await act(async () => { fireEvent.click(within(summary).getByRole('button', { name: '再查一次' })); });
  await settle();
  // The VPN is still remembered, so the retry goes straight to public DNS.
  expect(prepares().map(call => call.payload.dnsMode)).toEqual(['system', 'public', 'public', 'system', 'public']);
  expect(screen.getByText('网络检查：公共 DNS（兼容 VPN）')).toBeTruthy();
});

it('treats a local result that mixes the VPN address with a lookup timeout as a network problem with a way out', async () => {
  // Not only the virtual address, so there is no automatic switch; the top line must still offer the next step.
  control.respond = (_payload, index) => (index === 1 ? { reasons: ['virtual_dns_address', 'dns_timeout'] } : {});
  const form = await fill();
  await check(form);
  expect(prepares().map(call => call.payload.dnsMode)).toEqual(['system']);
  const summary = form.querySelector('.dialog-status .domain-summary') as HTMLElement;
  expect(summary.textContent).toContain('网络查询没完成（');
  expect(form.textContent).not.toContain('检查没通过');
  await act(async () => { fireEvent.click(within(summary).getByRole('button', { name: '改用公共 DNS 再查一次' })); });
  await settle();
  expect(prepares().map(call => call.payload.dnsMode)).toEqual(['system', 'public']);
  expect(screen.getByRole('button', { name: '确认并执行' })).toBeTruthy();
});

it('does not offer the list refresh when the ownership read only failed for a network reason', async () => {
  // The backend labels an unreachable Cloudflare read 「云端域名归属」; that is not a missing domain.
  control.respond = () => ({ reasons: ['cloud_unreachable'], label: '云端域名归属' });
  const form = await fill();
  await check(form);
  expect((form.querySelector('.dialog-status .domain-summary') as HTMLElement).textContent).toContain('网络查询没完成（');
  expect(form.querySelector('.preflight .domain-result-actions')).toBeNull();
  expect(within(form).queryByText('新买的域名要先刷新一次，本机才有记录。')).toBeNull();
});

it('does not fall back when the user chose public DNS by hand', async () => {
  control.respond = () => ({ reasons: ['public_dns_timeout'] });
  const form = await fill();
  fireEvent.click(within(form).getByText('更多选项与说明'));
  fireEvent.click(within(form).getByRole('checkbox', { name: '直接使用公共 DNS（手动兼容 VPN）' }));
  await check(form);
  expect(prepares().map(call => call.payload.dnsMode)).toEqual(['public']);
});

it('starts the next domain check with public DNS after a link detection saw the VPN address', async () => {
  control.installed = true;
  // Link detection itself keeps starting on the local network (that round is one
  // instant local lookup, and it is the way back once the proxy is switched off).
  control.selftest = payload => payload.dnsMode === 'public'
    ? { status: 'failed', message: '目标异常', checks: [{ label: '目标', ok: false, reason: 'http_status', message: 'HTTP 500' }] }
    : { status: 'failed', message: '虚拟地址', checks: [{ label: '解析', ok: false, reason: 'virtual_dns_address', message: 'VPN 虚拟地址' }] };
  render(<App />);
  fireEvent.click(await screen.findByRole('button', { name: '检测 sample' }));
  let dialog = await screen.findByRole('dialog', { name: '链接检测' });
  fireEvent.click(within(dialog).getByRole('button', { name: '完成' }));
  fireEvent.click(screen.getByRole('button', { name: '检测 sample' }));
  dialog = await screen.findByRole('dialog', { name: '链接检测' });
  expect(control.calls.filter(call => call.action === 'selftest_link').map(call => call.payload.dnsMode)).toEqual([undefined, 'public', undefined, 'public']);
  // The domain check starts with public DNS.
  fireEvent.click(within(dialog).getByRole('button', { name: '完成' }));
  fireEvent.click(screen.getByRole('button', { name: /^域名管理$/ }));
  fireEvent.click(screen.getAllByRole('button', { name: '添加域名' })[0]);
  const form = domainDialog();
  fireEvent.change(within(form).getByPlaceholderText('go.example.com'), { target: { value: 'next.example.com' } });
  await check(form);
  expect(prepares().map(call => call.payload.dnsMode)).toEqual(['public']);
});

it('asks for the account before sending anything when several accounts exist and the host is unknown', async () => {
  const form = await fill('new.example.net', '');
  await act(async () => { fireEvent.click(within(form).getByRole('button', { name: '检查并继续' })); });
  expect(prepares()).toHaveLength(0);
  const select = within(form).getByRole('combobox', { name: 'Cloudflare 账户' });
  expect(within(form).getByText('本机还没有这个域名的记录。请先选它所在的 Cloudflare 账户，再点检查。')).toBeTruthy();
  expect(select.getAttribute('aria-invalid')).toBe('true');
  expect(document.activeElement).toBe(select);
  fireEvent.change(select, { target: { value: 'b' } });
  expect(within(form).queryByText(/本机还没有这个域名的记录/)).toBeNull();
  await check(form);
  expect(prepares()[0].payload.accountId).toBe('b');
});

it('a cached host still checks without choosing an account', async () => {
  const form = await fill('go.example.org', '');
  await check(form);
  expect(prepares()).toHaveLength(1);
  expect(prepares()[0].payload.accountId).toBeUndefined();
});

it('an automatically picked account follows the host, a hand-picked one stays', async () => {
  const form = await openDialog();
  const host = within(form).getByPlaceholderText('go.example.com');
  const select = within(form).getByRole('combobox', { name: 'Cloudflare 账户' }) as HTMLSelectElement;
  const zones = () => [...form.querySelectorAll('#cloudflare-zones option')].map(option => option.getAttribute('value'));
  fireEvent.change(host, { target: { value: 'example.com' } });
  expect(select.value).toBe('a');
  expect(zones()).toEqual(['example.com', 'example.org']);
  fireEvent.change(host, { target: { value: 'example.org' } });
  expect(select.value).toBe('b');
  fireEvent.change(host, { target: { value: 'new.example.net' } });
  expect(select.value).toBe('');
  fireEvent.change(select, { target: { value: 'b' } });
  expect(zones()).toEqual(['example.org']);
  fireEvent.change(host, { target: { value: 'example.com' } });
  expect(select.value).toBe('b');
});

it('an account filled in by the check is automatic and follows a new host', async () => {
  control.respond = () => ({ reasons: ['probe_timeout'], candidates: ['a'] });
  const form = await fill('go.example.com', '');
  await check(form);
  const select = within(form).getByRole('combobox', { name: 'Cloudflare 账户' }) as HTMLSelectElement;
  expect(select.value).toBe('a');
  fireEvent.change(within(form).getByPlaceholderText('go.example.com'), { target: { value: 'example.org' } });
  expect(select.value).toBe('b');
});

it('re-checks right away after choosing the account and zone in the result', async () => {
  control.respond = payload => payload.accountId ? {} : { candidates: ['a', 'b'], ready: false, reasons: [] };
  const form = await fill('go.example.com', '');
  await check(form);
  expect(prepares()).toHaveLength(1);
  await act(async () => { fireEvent.change(within(form).getByRole('combobox', { name: /选择账户与区域/ }), { target: { value: 'b' } }); });
  await settle();
  expect(prepares()).toHaveLength(2);
  expect(prepares()[1].payload.accountId).toBe('b');
  expect(screen.getByRole('button', { name: '确认并执行' })).toBeTruthy();
});

it.each([['cloud_unreachable'], ['probe_timeout'], ['probe_transport_error'], ['public_dns_timeout']])('summarises a network-only result (%s) at the top with a retry button', async reason => {
  control.respond = (_payload, index) => (index === 1 ? { reasons: [reason] } : {});
  const form = await fill();
  await check(form);
  expect(within(form).getByText('网络检查未完成')).toBeTruthy();
  const summary = form.querySelector('.dialog-status .domain-summary') as HTMLElement;
  expect(summary.textContent).toContain(`网络查询没完成（模拟原因 ${reason}）。通常再查一次就好。`);
  expect(within(form).getByText(/本机网络查询没完成，通常再查一次就好；还不行再检查网络或 VPN。域名尚未接入。/)).toBeTruthy();
  await act(async () => { fireEvent.click(within(summary).getByRole('button', { name: '再查一次' })); });
  await settle();
  expect(prepares()).toHaveLength(2);
  expect(prepares()[1].payload.dnsMode).toBe('system');
  expect(screen.getByRole('button', { name: '确认并执行' })).toBeTruthy();
});

it('offers public DNS when the local lookup timed out', async () => {
  control.respond = (_payload, index) => (index === 1 ? { reasons: ['dns_timeout'] } : {});
  const form = await fill();
  await check(form);
  const summary = form.querySelector('.dialog-status .domain-summary') as HTMLElement;
  await act(async () => { fireEvent.click(within(summary).getByRole('button', { name: '改用公共 DNS 再查一次' })); });
  await settle();
  expect(prepares().map(call => call.payload.dnsMode)).toEqual(['system', 'public']);
  fireEvent.click(screen.getByRole('button', { name: '返回' }));
  expect((within(domainDialog()).getByRole('checkbox', { name: '直接使用公共 DNS（手动兼容 VPN）' }) as HTMLInputElement).checked).toBe(true);
});

it('shows the public-DNS wording under a public result', async () => {
  control.respond = () => ({ reasons: ['public_dns_failed'] });
  const form = await fill();
  fireEvent.click(within(form).getByText('更多选项与说明'));
  fireEvent.click(within(form).getByRole('checkbox', { name: '直接使用公共 DNS（手动兼容 VPN）' }));
  await check(form);
  expect(within(form).getByText('网络查询没完成，通常再查一次就好；还不行再检查 VPN 或网络。域名尚未接入。')).toBeTruthy();
  expect(within(form.querySelector('.domain-summary') as HTMLElement).getByRole('button', { name: '再查一次' })).toBeTruthy();
});

it('names the first real problem when the result is not only a network issue', async () => {
  control.respond = () => ({ reasons: ['probe_timeout', 'blocked_non_public_address'] });
  const form = await fill();
  await check(form);
  const summary = form.querySelector('.dialog-status .domain-summary') as HTMLElement;
  expect(summary.textContent).toBe('检查没通过：检查项1——模拟原因 blocked_non_public_address');
  expect(within(summary).queryByRole('button')).toBeNull();
});

it('scrolls only the dialog content to a result that is out of view', async () => {
  control.respond = () => ({ reasons: ['blocked_non_public_address'] });
  const rect = vi.spyOn(HTMLElement.prototype, 'getBoundingClientRect').mockImplementation(function(this: HTMLElement) {
    return new DOMRect(0, this.classList.contains('dialog-body') ? 100 : this.classList.contains('preflight') ? 700 : 0, 100, 10);
  });
  const form = await fill();
  const body = form.querySelector('.dialog-body') as HTMLElement;
  Object.defineProperty(body, 'clientHeight', { configurable: true, value: 400 });
  Object.defineProperty(body, 'scrollTop', { configurable: true, writable: true, value: 0 });
  const page = document.scrollingElement || document.documentElement;
  await check(form);
  expect(body.scrollTop).toBe(588);
  expect(page.scrollTop).toBe(0);
  rect.mockRestore();
});

it('keeps the long notes folded and offers the list refresh next to an ownership problem', async () => {
  control.respond = () => ({ reasons: ['zone_not_found'], label: '域名归属', candidates: [] });
  const form = await fill();
  const more = within(form).getByText('更多选项与说明').closest('details') as HTMLDetailsElement;
  expect(more.open).toBe(false);
  for (const text of [/带 www 和不带 www/, /先按本机网络检查/, '网络检查选项'])
    expect(more.contains(within(form).getByText(text))).toBe(true);
  expect(more.contains(within(form).getByRole('checkbox', { name: '直接使用公共 DNS（手动兼容 VPN）' }))).toBe(true);
  const listButtons = () => within(form).getAllByRole('button', { name: '刷新域名列表' });
  expect(listButtons()).toHaveLength(1);
  expect(more.contains(listButtons()[0])).toBe(true);
  await check(form);
  expect(listButtons()).toHaveLength(2);
  const inResult = listButtons().find(button => !more.contains(button))!;
  expect(inResult.closest('.preflight')).toBeTruthy();
  await act(async () => { fireEvent.click(inResult); });
  await settle();
  expect(control.calls.filter(call => call.action === 'refresh_domains').map(call => call.payload)).toEqual([{ accountId: 'a' }]);
});

it('puts the cursor in the domain field when the dialog opens', async () => {
  vi.spyOn(HTMLElement.prototype, 'getClientRects').mockImplementation(function(this: HTMLElement) {
    return [new DOMRect(0, 0, 100, 20)] as unknown as DOMRectList;
  });
  const form = await openDialog();
  expect(document.activeElement).toBe(within(form).getByPlaceholderText('go.example.com'));
});
