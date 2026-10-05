import { cleanup, fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import { afterEach, expect, it, vi } from 'vitest';
import App from './App';

const control = vi.hoisted(() => ({ pending: false, calls: [] as { action: string; payload: Record<string, unknown> }[] }));
vi.mock('./bridge', () => ({ preview: false, errorMessage: (e: unknown) => String(e), dispatch: async (action: string, payload: Record<string, unknown> = {}) => {
  control.calls.push({ action, payload });
  if (action === 'get_state' || action === 'apply_plan') return {
    accounts: [{ id: 'a', label: '示例账户', zoneCount: 2, hasResources: true, needsSelftestKey: false }, { id: 'b', label: '其他账户', zoneCount: 1, hasResources: true, needsSelftestKey: false }],
    domains: [{ id: 'd', accountId: 'a', zoneId: 'z', host: 'go.example.com', prefix: 'r', routeId: 'route' }, { id: 'd2', accountId: 'a', zoneId: 'z2', host: 'links.example.org', prefix: 'go', routeId: 'route2' }, { id: 'd3', accountId: 'b', zoneId: 'z3', host: 'other.example.net', prefix: 'r', routeId: 'route3' }],
    links: [{ domainId: 'd', slug: 'OK', cnUrl: 'https://example.com/join/Code_A', defaultUrl: 'https://example.org/join/Code_A', updated: '' }], pools: [],
    pendingOperations: control.pending ? ['升级需核对'] : [],
    pendingActions: control.pending ? [{ kind: 'resume_worker_upgrade', accountId: 'a', poolId: null, label: '继续核对云端升级' }] : [],
  };
  if (action === 'prepare_change') return { id: 'p', title: payload.kind === 'save_link' ? '保存短链接' : payload.kind === 'dismiss_worker_upgrade' ? '解除本机升级记录' : '启用名称大小写兼容', steps: ['核对状态，保留旧链接与密钥'], warnings: [], expiresAt: new Date(Date.now() + 300000).toISOString() };
  throw Error(`Unexpected action ${action}`);
} }));
afterEach(() => { cleanup(); control.calls.length = 0; control.pending = false; });
async function copy() {
  render(<App />);
  fireEvent.click(await screen.findByRole('button', { name: '编辑 OK' }));
  fireEvent.click(within(screen.getByRole('dialog', { name: '编辑短链接' })).getByRole('button', { name: '换一个名称' }));
  return screen.getByRole('dialog', { name: '使用新名称创建链接' });
}

it('new names are lowercase in the form, payload and review; targets retain case', async () => {
  const form = await copy();
  const name = within(form).getByPlaceholderText('例如 welcome') as HTMLInputElement;
  fireEvent.change(name, { target: { value: 'NeW_Name' } });
  expect(name.value).toBe('new_name');
  fireEvent.submit(form.querySelector('form')!);
  const review = await screen.findByRole('dialog', { name: '保存短链接' });
  expect(review.textContent).toContain('https://go.example.com/r/new_name');
  expect(review.textContent).toContain('https://example.org/join/Code_A');
  expect(control.calls.find(c => c.action === 'prepare_change')?.payload).toMatchObject({ slug: 'new_name', createOnly: true, defaultUrl: 'https://example.org/join/Code_A' });
  expect(control.calls.some(c => c.action === 'apply_plan')).toBe(false);
});

it('rejects a new case-only collision with a legacy name without preparing a cloud write', async () => {
  const form = await copy();
  fireEvent.change(within(form).getByPlaceholderText('例如 welcome'), { target: { value: 'ok' } });
  fireEvent.submit(form.querySelector('form')!);
  expect(within(form).getByRole('alert').textContent).toContain('现有链接不会被覆盖');
  expect(control.calls.some(c => c.action === 'prepare_change')).toBe(false);
});

it('legacy name edits keep the exact uppercase identity', async () => {
  render(<App />);
  fireEvent.click(await screen.findByRole('button', { name: '编辑 OK' }));
  const form = screen.getByRole('dialog', { name: '编辑短链接' });
  expect((within(form).getByPlaceholderText('例如 welcome') as HTMLInputElement).value).toBe('OK');
  fireEvent.submit(form.querySelector('form')!);
  await waitFor(() => expect(control.calls.some(c => c.action === 'prepare_change')).toBe(true));
  expect(control.calls.find(c => c.action === 'prepare_change')?.payload).toMatchObject({ slug: 'OK', createOnly: false });
});

it('cloud upgrade is explicit, account-scoped and cancellable; startup never upgrades', async () => {
  render(<App />);
  await screen.findByRole('button', { name: '编辑 OK' });
  expect(control.calls.some(c => c.action === 'prepare_change')).toBe(false);
  fireEvent.click(screen.getByRole('button', { name: /^Cloudflare 账户$/ }));
  fireEvent.click(screen.getByRole('button', { name: '管理 示例账户' }));
  const manager = screen.getByRole('dialog', { name: '账户管理' });
  fireEvent.click(within(manager).getByRole('button', { name: '启用名称大小写兼容' }));
  const review = await screen.findByRole('dialog', { name: '启用名称大小写兼容' });
  expect(review.textContent).toContain('go.example.com/r/');
  expect(review.textContent).toContain('links.example.org/go/');
  expect(review.textContent).not.toContain('other.example.net');
  expect(control.calls.find(c => c.action === 'prepare_change')?.payload).toEqual({ kind: 'upgrade_worker', accountId: 'a' });
  fireEvent.click(within(review).getByRole('button', { name: '返回' }));
  expect(control.calls.some(c => c.action === 'apply_plan')).toBe(false);
});

it.each([['继续核对升级', 'resume_worker_upgrade'], ['解除本机升级记录', 'dismiss_worker_upgrade']])('pending %s opens its own review and never auto-applies', async (label, kind) => {
  control.pending = true;
  render(<App />);
  fireEvent.click(await screen.findByRole('button', { name: label }));
  await waitFor(() => expect(control.calls.some(c => c.action === 'prepare_change')).toBe(true));
  expect(control.calls.find(c => c.action === 'prepare_change')?.payload).toEqual({ kind, accountId: 'a' });
  expect(control.calls.some(c => c.action === 'apply_plan')).toBe(false);
});

it.each([
  ['继续核对升级', '云端升级已核对，待处理记录已完成'],
  ['解除本机升级记录', '本机升级记录已解除，云端和密钥未修改'],
])('confirmed %s reports its actual scope', async (label, message) => {
  control.pending = true;
  render(<App />);
  fireEvent.click(await screen.findByRole('button', { name: label }));
  const review = await screen.findByRole('dialog');
  fireEvent.click(within(review).getByRole('button', { name: '确认并执行' }));
  await waitFor(() => expect(screen.getByRole('status').textContent).toContain(message));
  expect(control.calls.filter(c => c.action === 'apply_plan')).toHaveLength(1);
  expect(screen.queryByText('已提交修改。云端更新可能需要一点时间生效。')).toBeNull();
});
