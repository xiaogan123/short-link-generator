export const PREFIX_RE = /^[a-z0-9-]{1,12}$/;
export const SLUG_RE = /^[A-Za-z0-9_-]{1,32}$/;

export function validatePrefix(value: string): string | null {
  return PREFIX_RE.test(value) ? null : '路径前缀须为 1–12 位小写字母、数字或连字符。';
}
export function validateSlug(value: string): string | null {
  return SLUG_RE.test(value) ? null : '短路径须为 1–32 位字母、数字、下划线或连字符。';
}
export function validateTarget(value: string): string | null {
  if (/[\u0000-\u0020\u007f\\]/.test(value)) return '目标地址不能包含空白、控制字符或反斜杠。';
  try {
    const url = new URL(value);
    if (url.protocol !== 'https:' || !url.hostname || url.username || url.password) return '请输入完整的 HTTPS 地址，不能包含账号信息。';
    return null;
  } catch { return '请输入完整的 HTTPS 地址。'; }
}
export function validateHost(value: string): string | null {
  try { normalizeHost(value); return null; }
  catch { return '请输入有效域名或 HTTPS 地址，例如 go.example.com。'; }
}
export function normalizeHost(value: string): string {
  const input = value.trim();
  if (!input || /[\u0000-\u0020\u007f\\]/.test(input)) throw new Error('Invalid host');
  const url = new URL(input.includes('://') ? input : `https://${input}`);
  const host = url.hostname.toLowerCase().replace(/\.$/, '');
  if (!['https:', 'http:'].includes(url.protocol) || url.username || url.password || url.port || host.length > 253 || !host.includes('.') || !host.split('.').every(label => /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(label))) throw new Error('Invalid host');
  return host;
}
export function shortUrl(host: string, prefix: string, slug: string) { return `https://${host}/${prefix}/${slug}`; }
