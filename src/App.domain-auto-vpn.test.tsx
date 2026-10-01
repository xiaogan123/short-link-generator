import { act, cleanup, fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import App from './App';

const control = vi.hoisted(() => ({
  calls: [] as {action: string; payload: Record<string, unknown>}[],
  reasons: ['virtual_dns_address', 'virtual_dns_address'] as (string | undefined)[],
  publicReason: '', publicThrows: false, defer: '',
  finish: null as null | (() => void), dns: '', repaired: false,
  showLinksOnApply: false, installed: false, preparedPrefix: '',
}));
const account = {id: 'a', label: '示例账户', zones: [{id: 'z', name: 'example.com', status: 'active'}], zoneCount: 1, hasResources: true, needsSelftestKey: false};
const state = () => ({accounts: [account, {...account, id: 'b', label: '第二账户'}],
  domains: control.installed ? ['go.example.com', 'other.example.com'].map((host, i) => ({id: `d${i}`, accountId: 'a', zoneId: 'z', host, prefix: control.preparedPrefix, routeId: `r${i}`})) : [],
  links: control.installed ? ['sample', 'other'].map((slug, i) => ({domainId: `d${i}`, slug, cnUrl: 'https://example.org/cn', defaultUrl: 'https://example.org/en', updated: '2026-01-01T00:00:00Z'})) : [],
  pools: [], pendingOperations: []});
function prepared(payload: Record<string, unknown>) {
  const first = control.calls.filter(call => call.action === 'prepare_domain').length === 1;
  const dnsMissing = control.dns && (control.dns === 'ready' ? first : !control.repaired);
  const reasons = dnsMissing ? ['dns_record_missing'] : payload.dnsMode === 'public' ? (control.publicReason ? [control.publicReason] : []) : control.reasons;
  const ready = !reasons.length;
  return {
    host: payload.input, prefix: payload.prefix, dnsMode: payload.dnsMode,
    candidates: [{accountId: payload.accountId || 'a', label: '示例账户', zoneId: 'z', status: 'active'}],
    checks: ready ? [{label: '短链接目录', ok: true, level: 'warning', message: '真实模拟结果 HTTP 522，需确认接管'}] : reasons.map(reason => ({label: dnsMissing ? 'DNS' : '短链接目录', ok: false, level: 'error', reason, message: '路径受阻：VPN 虚拟地址或其它错误'})),
    canApply: ready,
    ...(ready ? {plan: {id: `plan-${payload.dnsMode}`, title: '添加域名', steps: ['复核同一 DNS 方式'], warnings: [], domainTakeoverConfirmation: '确认接管此目录及其下级网页。', expiresAt: new Date(Date.now() + 300000).toISOString()}} : {}),
  };
}
vi.mock('./bridge', () => ({preview: false, errorMessage: String, dispatch: async (action: string, payload: Record<string, unknown> = {}) => {
  control.calls.push({action, payload});
  if (action === 'get_state') return state();
  if (action === 'prepare_domain') {
    control.preparedPrefix = payload.prefix as string;
    if (payload.dnsMode === 'public' && control.publicThrows) throw new Error('公共 DNS 不可用');
    const result = prepared(payload);
    if (payload.dnsMode === control.defer) return new Promise(resolve => {control.finish = () => resolve(result);});
    return result;
  }
  if (action === 'prepare_domain_dns') return {host: payload.input, candidates: [], checks: [], dnsStatus: control.dns, actions: [{kind: 'createPlaceholder', recordType: 'AAAA', name: payload.input}], canApply: control.dns === 'missing', ...(control.dns === 'missing' ? {plan: {id: 'dns', title: '修复 DNS', steps: [], warnings: [], expiresAt: new Date(Date.now() + 300000).toISOString()}} : {})};
  if (action === 'apply_plan') {control.repaired = true; if (control.showLinksOnApply && payload.planId === 'plan-public') control.installed = true; return state();}
  if (action === 'selftest_link') return {status: 'passed', message: '跳转通过', checks: []};
  if (action === 'check_link_targets') return {checkedAt: new Date().toISOString(), dnsMode: payload.dnsMode || 'system', checks: []};
  throw new Error(`Unexpected ${action}`);
}}));
beforeEach(() => {
  control.calls = []; control.reasons = ['virtual_dns_address', 'virtual_dns_address'];
  control.publicReason = ''; control.publicThrows = false; control.defer = ''; control.finish = null;
  control.dns = ''; control.repaired = false;
  control.showLinksOnApply = false; control.installed = false; control.preparedPrefix = '';
});
afterEach(cleanup);
const calls = () => control.calls.filter(call => call.action === 'prepare_domain');
const applies = () => control.calls.filter(call => call.action === 'apply_plan');
async function open() {
  render(<App />); await screen.findByText('先连接一个域名');
  fireEvent.click(screen.getByRole('button', {name: /^域名管理$/}));
  fireEvent.click(screen.getAllByRole('button', {name: '添加域名'})[0]);
  const form = screen.getByRole('dialog', {name: '添加域名'});
  fireEvent.change(within(form).getByPlaceholderText('go.example.com'), {target: {value: 'go.example.com'}});
  fireEvent.change(within(form).getByRole('combobox', {name: 'Cloudflare 账户'}), {target: {value: 'a'}});
  return form;
}
function submit(form: HTMLElement) {fireEvent.click(within(form).getByRole('button', {name: '检查并继续'}));}
async function done(_form: HTMLElement) {
  await waitFor(() => expect(screen.queryByRole('button', {name: '检查中…'})).toBeNull());
}

it('automatically retries only typed virtual DNS, shows the actual warning, and binds only the public plan behind takeover confirmation', async () => {
  const form = await open(); submit(form); await done(form);
  expect(calls().map(call => call.payload.dnsMode)).toEqual(['system', 'public']);
  expect(applies()).toHaveLength(0);
  const plan = screen.getByRole('dialog', {name: '添加域名'});
  expect(within(plan).getByText('网络检查：公共 DNS（兼容 VPN）')).toBeTruthy();
  expect(within(plan).getByRole('button', {name: '确认使用此目录'})).toBeTruthy();
  expect(within(plan).getByText('确认接管此目录及其下级网页。')).toBeTruthy();
  fireEvent.click(within(plan).getByRole('button', {name:'返回'}));
  const restored = screen.getByRole('dialog', {name:'添加域名'});
  expect(within(restored).getByText(/本次已自动切换为公共 DNS/)).toBeTruthy();
  expect(within(restored).getByText('确认后可接入')).toBeTruthy();
  expect(within(restored).getByText(/真实模拟结果 HTTP 522/)).toBeTruthy();
  fireEvent.click(within(restored).getByRole('button', {name:'查看接入计划'}));
  expect(applies()).toHaveLength(0);
  fireEvent.click(screen.getByRole('button', {name:'确认使用此目录'}));
  await waitFor(() => expect(applies()).toHaveLength(1));
  expect(applies()[0].payload).toMatchObject({planId: 'plan-public', acknowledgeDomainTakeover: true});
});

it.each(['virtual_dns_address', 'public_dns_failed', 'blocked_non_public_address'])('does not retry again or offer a plan when public lookup returns %s', async reason => {
  control.publicReason = reason;
  const form = await open(); submit(form); await done(form);
  expect(calls().map(call => call.payload.dnsMode)).toEqual(['system', 'public']);
  expect(within(form).getByText(reason === 'blocked_non_public_address' ? '需要先处理' : '网络检查未完成')).toBeTruthy();
  if (reason !== 'blocked_non_public_address') expect(within(form).getByText(/域名尚未接入/)).toBeTruthy();
  expect(within(form).queryByRole('button', {name: '查看接入计划'})).toBeNull();
  expect(applies()).toHaveLength(0);
});

it('retains the public failure and never converts a thrown retry into success', async () => {
  control.publicThrows = true;
  const form = await open(); submit(form); await done(form);
  expect(within(form).getByRole('alert').textContent).toContain('公共 DNS 不可用');
  expect(calls()).toHaveLength(2); expect(applies()).toHaveLength(0);
});

it.each([
  ['dns_failed'], ['dns_timeout'], ['blocked_non_public_address'], ['connection_failed'],
  [undefined], ['virtual_dns_address', 'blocked_non_public_address'], ['virtual_dns_address', undefined],
])('does not infer a retry from messages or other blocking errors: %j', async (...reasons) => {
  control.reasons = reasons as (string | undefined)[];
  const form = await open(); submit(form); await done(form);
  expect(calls().map(call => call.payload.dnsMode)).toEqual(['system']);
  expect(within(form).queryByText(/本次已自动切换/)).toBeNull();
  expect(applies()).toHaveLength(0);
});

it('honors explicit public mode without an extra fallback', async () => {
  const form = await open(); fireEvent.click(within(form).getByText('网络检查选项'));
  fireEvent.click(within(form).getByRole('checkbox', {name: '直接使用公共 DNS（手动兼容 VPN）'}));
  submit(form); await done(form);
  expect(calls().map(call => call.payload.dnsMode)).toEqual(['public']);
  expect(screen.getByText('网络检查：公共 DNS（兼容 VPN）')).toBeTruthy();
  expect(applies()).toHaveLength(0);
});

it.each(['system', 'public'])('ignores a late %s result after cancel and reopen, without duplicate requests', async mode => {
  control.defer = mode;
  let form = await open(); submit(form);
  await waitFor(() => expect(control.finish).toBeTypeOf('function'));
  fireEvent.submit(form.querySelector('form')!);
  const before = calls().length;
  fireEvent.click(within(form).getByRole('button', {name: '取消'}));
  fireEvent.click(screen.getAllByRole('button', {name: '添加域名'})[0]);
  form = screen.getByRole('dialog', {name: '添加域名'});
  await act(async () => control.finish!());
  expect(calls()).toHaveLength(before);
  expect(within(form).queryByRole('button', {name: '查看接入计划'})).toBeNull();
  expect(within(form).queryByText(/本次已自动切换/)).toBeNull();
});

it.each(['host', 'prefix', 'account'])('discards a late public result after changing %s', async field => {
  control.defer = 'public'; const form = await open(); submit(form);
  await waitFor(() => expect(control.finish).toBeTypeOf('function'));
  const target = field === 'host' ? within(form).getByPlaceholderText('go.example.com') : field === 'prefix' ? within(form).getByRole('textbox', {name: /^链接目录/}) : within(form).getByRole('combobox', {name: 'Cloudflare 账户'});
  fireEvent.change(target, {target: {value: field === 'host' ? 'new.example.com' : field === 'prefix' ? 'changedprefix' : 'b'}});
  await act(async () => control.finish!());
  expect(within(form).queryByRole('button', {name: '查看接入计划'})).toBeNull();
  expect(within(form).queryByText(/本次已自动切换/)).toBeNull();
  expect(applies()).toHaveLength(0);
});

it.each(['ready', 'missing'])('covers the followup check after DNS is %s with the same single fallback', async dns => {
  control.dns = dns; const form = await open(); submit(form);
  if (dns === 'missing') {
    const plan = await screen.findByRole('dialog', {name: '修复 DNS'});
    fireEvent.click(within(plan).getByRole('button', {name: '确认修改并继续检查'}));
  }
  await screen.findByRole('button', {name: '确认使用此目录'});
  expect(calls().map(call => call.payload.dnsMode)).toEqual(['system', 'system', 'public']);
  expect(screen.getByText('网络检查：公共 DNS（兼容 VPN）')).toBeTruthy();
  expect(applies().map(call => call.payload.planId)).toEqual(dns === 'missing' ? ['dns'] : []);
});

it('does not silently remember public mode for a different host', async () => {
  const form = await open(); submit(form); await done(form);
  fireEvent.click(screen.getByRole('button', {name:'返回'}));
  const restored = screen.getByRole('dialog', {name:'添加域名'});
  fireEvent.change(within(restored).getByPlaceholderText('go.example.com'), {target: {value: 'next.example.com'}});
  control.reasons = []; submit(restored); await done(restored);
  expect(calls().map(call => call.payload.dnsMode)).toEqual(['system', 'public', 'system']);
  expect(screen.getByRole('button',{name:'确认使用此目录'})).toBeTruthy();
  expect(screen.queryByText('网络检查：公共 DNS（兼容 VPN）')).toBeNull();
});

it('reuses a domain public-DNS preparation for link detection, without changing another domain', async () => {
  control.showLinksOnApply = true;
  const form = await open(); submit(form); await done(form);
  fireEvent.click(screen.getByRole('button', {name: '确认使用此目录'}));
  await waitFor(() => expect(control.installed).toBe(true));
  fireEvent.click(screen.getByRole('button', {name: /^短链接\d*$/}));
  fireEvent.click(await screen.findByRole('button', {name: '检测 sample'}));
  let dialog = await screen.findByRole('dialog', {name: '链接检测'});
  expect(within(dialog).getByText(/本次跳转检查使用公共 DNS/)).toBeTruthy();
  fireEvent.click(within(dialog).getByRole('button', {name: '完成'}));
  fireEvent.click(screen.getByRole('button', {name: '检测 other'}));
  dialog = await screen.findByRole('dialog', {name: '链接检测'});
  expect(within(dialog).queryByText(/本次跳转检查使用公共 DNS/)).toBeNull();
  expect(control.calls.filter(call => call.action === 'selftest_link').map(call => call.payload.dnsMode)).toEqual(['public', undefined]);
});

it('does not start the automatic public request after unmount', async () => {
  control.defer = 'system'; const form = await open(); submit(form);
  await waitFor(() => expect(control.finish).toBeTypeOf('function'));
  cleanup(); await act(async () => control.finish!());
  expect(calls()).toHaveLength(1); expect(applies()).toHaveLength(0);
});
