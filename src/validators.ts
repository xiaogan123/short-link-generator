export const PREFIX_RE = /^[a-z0-9-]{1,12}$/;
export const SLUG_RE = /^[A-Za-z0-9_-]{1,32}$/;

export function validatePrefix(value: string): string | null {
  return PREFIX_RE.test(value) ? null : '路径前缀须为 1–12 位小写字母、数字或连字符。';
}
export function validateSlug(value: string): string | null {
  return SLUG_RE.test(value) ? null : '短链接名称须为 1–32 位字母、数字、下划线或连字符。';
}
export function validateTarget(value: string): string | null {
  if (/[\u0000-\u0020\u007f\\]/.test(value)) return '目标地址不能包含空白、控制字符或反斜杠。';
  try {
    const url = new URL(value);
    if (url.protocol !== 'https:' || !url.hostname || url.username || url.password) return '请输入完整的 HTTPS 地址，不能包含账号信息。';
    if (value.length > 2048 || url.href.length > 2048) return '目标网址过长，转换为标准网址后不能超过 2048 个字符。';
    if (url.port === '0') return '目标网址的端口不能为 0，请核对网址。';
    if (value.includes('#')) return '目标网址不能包含 # 后面的片段，请先去掉再保存。';
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

export type InvitationParts = {prefix:string;code:string;suffix:string};
export function splitInvitationLink(value:string):InvitationParts {
  const input=value.trim();
  if(input.includes('#'))throw new Error('链接含有 # 后面的内容，请先去掉再拆分。');
  if(/^https:\/\/[^/?#]*@/.test(input))throw new Error('邀请链接的域名中不能包含 @；请使用不带账号信息的网址。');
  if(validateTarget(input))throw new Error('请输入完整的 HTTPS 邀请链接。');
  if(new URL(input).searchParams.getAll('ref').length>1)throw new Error('邀请码位置不明确：链接中有多个 ref 参数，请手动填写地址。');
  const path=input.match(/^(https:\/\/[^/?#]+\/(?:join|zh\/share)\/)([A-Za-z0-9_-]{1,128})(\?[^#]*)?$/);
  if(path){if(new URL(input).searchParams.has('ref'))throw new Error('邀请码位置不明确，请手动填写地址。');return {prefix:path[1],code:path[2],suffix:path[3]||''};}
  const query=input.match(/^(https:\/\/[^/?#]+\/(?:register|join)\?)([^#]+)$/);
  if(query){
    const fields=query[2].split('&');
    const at=fields.findIndex(field=>field.startsWith('ref='));
    if(at>=0){
      if(fields.filter(field=>field.startsWith('ref=')).length!==1)throw new Error('邀请码位置不明确：链接中有多个 ref 参数，请手动填写地址。');
      const code=fields[at].slice(4);
      if(!/^[A-Za-z0-9_-]{1,128}$/.test(code))throw new Error('未找到有效邀请码；请确认 ref 参数只包含字母、数字、下划线或连字符。');
      return {prefix:query[1]+fields.slice(0,at).concat('ref=').join('&'),code,suffix:fields.slice(at+1).length?`&${fields.slice(at+1).join('&')}`:''};
    }
  }
  throw new Error('暂不识别这种链接。支持 /join?ref=邀请码、/register?ref=邀请码、/join/邀请码，或 /zh/share/邀请码；也可在下方手动填写地址。');
}
