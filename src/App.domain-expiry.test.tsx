import { act, cleanup, fireEvent, render, screen, within } from '@testing-library/react';
import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import App from './App';

const control = vi.hoisted(() => ({
  calls: [] as { action: string; payload: Record<string, unknown> }[],
  ttl: 300000,
  issuedPlanIds: [] as string[],
  invalidExpiry: false,
  dnsRepair: false,
  defer: false,
  finish: null as null | (() => void),
}));
const account = { id: 'a', label: '示例账户', zones: [{ id: 'z', name: 'example.com', status: 'active' }], zoneCount: 1, checkedAt: null, hasResources: true, needsSelftestKey: false };
const state = () => ({ accounts: [account], domains: [], links: [], pools: [], pendingOperations: [] });
vi.mock('./bridge', () => ({
  preview: false,
  errorMessage: String,
  dispatch: async (action: string, payload: Record<string, unknown> = {}) => {
    control.calls.push({ action, payload });
    if (action === 'get_state') return state();
    const plan = () => {
      const id = `plan-${control.calls.length}`;
      control.issuedPlanIds.push(id);
      return ({
      id, title: control.dnsRepair ? '修复 DNS' : '添加域名',
      steps: ['重新核对后才提交'], warnings: [],
      expiresAt: control.invalidExpiry ? 'invalid-date' : new Date(Date.now() + control.ttl).toISOString(),
      ...(control.dnsRepair ? {} : { domainTakeoverConfirmation: '确认接管此目录及其下级网页。' }),
    });
    };
    if (action === 'prepare_domain') {
      const result = {
        host: payload.input, prefix: payload.prefix,
        candidates: [{ accountId: 'a', label: '示例账户', zoneId: 'z', status: 'active' }],
        checks: [{ label: 'DNS', ok: !control.dnsRepair, level: control.dnsRepair ? 'error' : 'pass', message: '模拟检查结果' }],
        canApply: !control.dnsRepair, ...(control.dnsRepair ? {} : { plan: plan() }),
      };
      if (control.defer) return new Promise(resolve => { control.finish = () => resolve(result); });
      return result;
    }
    if (action === 'prepare_domain_dns') return {
      host: payload.input, candidates: [], checks: [], dnsStatus: 'missing', canApply: true,
      actions: [{ kind: 'createPlaceholder', recordType: 'AAAA', name: payload.input }], plan: plan(),
    };
    if (action === 'apply_plan') return new Promise(() => {});
    throw new Error(`Unexpected action ${action}`);
  },
}));
beforeEach(() => {
  vi.useFakeTimers();
  vi.setSystemTime(new Date('2026-01-01T00:00:00Z'));
  control.calls = []; control.issuedPlanIds = []; control.ttl = 300000; control.invalidExpiry = false;
  control.dnsRepair = false; control.defer = false; control.finish = null;
});
afterEach(() => { cleanup(); vi.useRealTimers(); });
async function click(element: HTMLElement) { await act(async () => { fireEvent.click(element); }); }
function form() { return screen.getByRole('dialog', { name: '添加域名' }); }
async function open() {
  await act(async () => { render(<App />); });
  await click(screen.getByRole('button', { name: /^域名管理$/ }));
  await click(screen.getAllByRole('button', { name: '添加域名' })[0]);
  fireEvent.change(within(form()).getByPlaceholderText('go.example.com'), { target: { value: 'new.example.com' } });
  fireEvent.change(within(form()).getByRole('textbox', { name: /^链接目录/ }), { target: { value: 'visit' } });
  fireEvent.change(within(form()).getByRole('combobox', { name: 'Cloudflare 账户' }), { target: { value: 'a' } });
  await click(within(form()).getByText('网络检查选项'));
  await click(within(form()).getByRole('checkbox', { name: '直接使用公共 DNS（手动兼容 VPN）' }));
}
function checkDraft() {
  expect((within(form()).getByPlaceholderText('go.example.com') as HTMLInputElement).value).toBe('new.example.com');
  expect((within(form()).getByRole('textbox', { name: /^链接目录/ }) as HTMLInputElement).value).toBe('visit');
  expect((within(form()).getByRole('combobox', { name: 'Cloudflare 账户' }) as HTMLSelectElement).value).toBe('a');
  expect((within(form()).getByRole('checkbox', { name: '直接使用公共 DNS（手动兼容 VPN）' }) as HTMLInputElement).checked).toBe(true);
}
function applies() { return control.calls.filter(call => call.action === 'apply_plan'); }

it.each(['expired', 'invalid'] as const)('lets a %s response be explicitly rechecked without changing the draft or applying', async kind => {
  control.ttl = -1; control.invalidExpiry = kind === 'invalid';
  await open(); await click(within(form()).getByRole('button', { name: '检查并继续' }));
  expect(within(form()).queryByRole('button', { name: '查看接入计划' })).toBeNull();
  expect(within(form()).getByText(/计划已过期/)).toBeTruthy(); checkDraft();
  control.ttl = 300000; control.invalidExpiry = false;
  await click(within(form()).getByRole('button', { name: '重新检查当前状态' }));
  expect(within(form()).getByText('确认接管此目录及其下级网页。')).toBeTruthy();
  expect((within(form()).getByRole('button', { name: '确认使用此目录' }) as HTMLButtonElement).disabled).toBe(false);
  const requests = control.calls.filter(call => call.action === 'prepare_domain');
  expect(requests).toHaveLength(2);
  expect(requests[1].payload).toEqual(requests[0].payload);
  expect(applies()).toHaveLength(0);
  await click(within(form()).getByRole('button', { name: '确认使用此目录' }));
  expect(applies()).toHaveLength(1);
  expect(applies()[0].payload).toEqual({ planId: control.issuedPlanIds[1], acknowledgeDomainTakeover: true });
  expect(applies()[0].payload.planId).not.toBe(control.issuedPlanIds[0]);
});

it('expires an open plan, then returns directly to a usable recheck without reusing its ID', async () => {
  await open(); await click(within(form()).getByRole('button', { name: '检查并继续' }));
  const confirm = within(form()).getByRole('button', { name: '确认使用此目录' }) as HTMLButtonElement;
  await act(async () => { vi.advanceTimersByTime(300001); });
  expect(confirm.disabled).toBe(true);
  expect(within(form()).getByText(/请点击「返回」后重新检查/)).toBeTruthy();
  await click(within(form()).getByRole('button', { name: '返回' })); checkDraft();
  await click(within(form()).getByRole('button', { name: '重新检查当前状态' }));
  expect(control.calls.filter(call => call.action === 'prepare_domain')).toHaveLength(2);
  expect(applies()).toHaveLength(0);
});

it('rechecks the deadline when opening between renders', async () => {
  await open(); await click(within(form()).getByRole('button', { name: '检查并继续' }));
  await click(within(form()).getByRole('button', { name: '返回' }));
  const button = within(form()).getByRole('button', { name: '查看接入计划' });
  vi.setSystemTime(Date.now() + 300001); // No timer/render before the click.
  await click(button); checkDraft();
  expect(within(form()).queryByRole('button', { name: '确认使用此目录' })).toBeNull();
  expect(within(form()).getByRole('button', { name: '重新检查当前状态' })).toBeTruthy();
  expect(applies()).toHaveLength(0);
});

it('does not submit an ID which expires between the confirmation render and click', async () => {
  await open(); await click(within(form()).getByRole('button', { name: '检查并继续' }));
  const confirm = within(form()).getByRole('button', { name: '确认使用此目录' });
  vi.setSystemTime(Date.now() + 300001);
  await click(confirm);
  expect(applies()).toHaveLength(0); checkDraft();
  expect(within(form()).getByRole('button', { name: '重新检查当前状态' })).toBeTruthy();
});

it('ignores a late recheck after cancellation and a new draft or DNS-mode choice', async () => {
  control.ttl = -1; await open();
  await click(within(form()).getByRole('button', { name: '检查并继续' }));
  control.ttl = 300000; control.defer = true;
  await click(within(form()).getByRole('button', { name: '重新检查当前状态' }));
  const finish = control.finish!;
  await click(within(form()).getByRole('button', { name: '取消' }));
  await click(screen.getAllByRole('button', { name: '添加域名' })[0]);
  fireEvent.change(within(form()).getByPlaceholderText('go.example.com'), { target: { value: 'other.example.com' } });
  const vpn = within(form()).getByRole('checkbox', { name: '直接使用公共 DNS（手动兼容 VPN）' }) as HTMLInputElement;
  if (vpn.checked) await click(vpn);
  await act(async () => { finish(); });
  expect(within(form()).queryByRole('button', { name: '查看接入计划' })).toBeNull();
  control.defer = false;
  await click(within(form()).getByRole('button', { name: '检查并继续' }));
  expect(control.calls.filter(call => call.action === 'prepare_domain').at(-1)?.payload).toMatchObject({ input: 'other.example.com', dnsMode: 'system' });
  expect(applies()).toHaveLength(0);
});

it('does not unlock cancellation or refresh after expiry while a native apply is pending', async () => {
  await open(); await click(within(form()).getByRole('button', { name: '检查并继续' }));
  await click(within(form()).getByRole('button', { name: '确认使用此目录' }));
  await act(async () => { vi.advanceTimersByTime(300001); });
  const dialog = form();
  expect((within(dialog).getByRole('button', { name: '返回' }) as HTMLButtonElement).disabled).toBe(true);
  fireEvent.keyDown(document, { key: 'Escape' }); fireEvent.mouseDown(dialog.parentElement!);
  expect(screen.getByRole('dialog', { name: '添加域名' })).toBe(dialog);
  expect(within(dialog).queryByRole('button', { name: '重新检查当前状态' })).toBeNull();
  expect(applies()).toHaveLength(1);
  expect(within(dialog).queryByText(/请点击「返回」后重新检查/)).toBeNull();
});

it('sends an already expired automatic DNS plan back to explicit preparation, not apply', async () => {
  control.dnsRepair = true; control.ttl = -1; await open();
  await click(within(form()).getByRole('button', { name: '检查并继续' }));
  expect(screen.queryByRole('dialog', { name: '修复 DNS' })).toBeNull(); checkDraft();
  expect(within(form()).getByRole('button', { name: '重新检查当前状态' })).toBeTruthy();
  control.ttl = 300000;
  await click(within(form()).getByRole('button', { name: '重新检查当前状态' }));
  expect(screen.getByRole('dialog', { name: '修复 DNS' })).toBeTruthy();
  expect(applies()).toHaveLength(0);
});
