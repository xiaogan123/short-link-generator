import { describe, expect, it } from 'vitest';
import { normalizeHost, shortUrl, splitInvitationLink, validateHost, validatePrefix, validateSlug, validateTarget } from './validators';

describe('link inputs', () => {
  it('accepts URLs and international hostnames while preserving www', () => {
    expect(validateHost('go.example.com')).toBeNull();
    expect(validateHost('www.go.example.com')).toBeNull();
    expect(validateHost('https://go.example.com')).toBeNull();
    expect(validateHost('go.example.com/path')).toBeNull();
    expect(normalizeHost('https://WWW.Example.com/path')).toBe('www.example.com');
    expect(normalizeHost('例子.example.com/说明')).toBe('xn--fsqu00a.example.com');
    expect(validateHost('https://name:pass@example.com')).not.toBeNull();
    expect(validateHost('bad..example.com')).not.toBeNull();
    expect(validateHost('-bad.example.com')).not.toBeNull();
  });
  it('enforces edge path limits', () => {
    expect(validatePrefix('go-1')).toBeNull();
    expect(validatePrefix('Upper')).not.toBeNull();
    expect(validatePrefix('longer-than-twelve')).not.toBeNull();
    expect(validateSlug('Abc_123-')).toBeNull();
    expect(validateSlug('contains space')).not.toBeNull();
    expect(validateSlug('a'.repeat(33))).not.toBeNull();
  });
  it('accepts only absolute HTTPS targets without embedded credentials', () => {
    expect(validateTarget('https://example.com/path?q=1')).toBeNull();
    expect(validateTarget('http://example.com')).not.toBeNull();
    expect(validateTarget('https://user:pass@example.com')).not.toBeNull();
    expect(validateTarget('/relative')).not.toBeNull();
  });
  it('constructs exact route paths', () => expect(shortUrl('go.example.com', 'r', 'test')).toBe('https://go.example.com/r/test'));
  it('rejects destinations the redirect service cannot serve before saving', () => {
    const base='https://example.org/';
    expect(validateTarget(base+'a'.repeat(2048-base.length))).toBeNull();
    expect(validateTarget(base+'a'.repeat(2049-base.length))).not.toBeNull();
    expect(validateTarget(base+'值'.repeat(230))).not.toBeNull();
    expect(validateTarget('https://example.org:0/')).not.toBeNull();
    expect(validateTarget('https://example.org:8443/')).toBeNull();
    expect(validateTarget(base+'#')).not.toBeNull();
    expect(validateTarget(base+'#fragment')).not.toBeNull();
  });
  it('splits supported invitation links without losing query parameters',()=>{
    expect(splitInvitationLink('https://example.com/join/CODE_1?lang=zh')).toEqual({prefix:'https://example.com/join/',code:'CODE_1',suffix:'?lang=zh'});
    expect(splitInvitationLink('https://example.org/zh/share/CODE-2')).toEqual({prefix:'https://example.org/zh/share/',code:'CODE-2',suffix:''});
    expect(splitInvitationLink('https://example.com/register?lang=zh&ref=CODE_3&utm=sample')).toEqual({prefix:'https://example.com/register?lang=zh&ref=',code:'CODE_3',suffix:'&utm=sample'});
    expect(splitInvitationLink('https://EXAMPLE.com/register?lang=%2F&ref=CODE_4&utm=%2B')).toEqual({prefix:'https://EXAMPLE.com/register?lang=%2F&ref=',code:'CODE_4',suffix:'&utm=%2B'});
  });
  it.each(['join','register'])('preserves referral codes and exact extra parameters in /%s query links',path=>{
    expect(splitInvitationLink(`https://example.com/${path}?ref=DEMO_Code-1`)).toEqual({prefix:`https://example.com/${path}?ref=`,code:'DEMO_Code-1',suffix:''});
    const input=`https://EXAMPLE.com/${path}?lang=%2F&ref=DEMO_Code-1&utm=%2B&lang=zh`;
    const parts=splitInvitationLink(input);
    expect(parts).toEqual({prefix:`https://EXAMPLE.com/${path}?lang=%2F&ref=`,code:'DEMO_Code-1',suffix:'&utm=%2B&lang=zh'});
    expect(parts.prefix+parts.code+parts.suffix).toBe(input);
    expect(splitInvitationLink(`https://example.com/${path}?ref=${'a'.repeat(128)}`).code).toHaveLength(128);
  });
  it.each(['join','register'])('rejects ambiguous or invalid referrals in /%s query links',path=>{
    for(const query of ['ref=ONE&ref=TWO','ref=ONE&%72ef=TWO'])expect(()=>splitInvitationLink(`https://example.com/${path}?${query}`)).toThrow(/多个 ref/);
    for(const code of ['', 'ONE+TWO', '%41', 'a'.repeat(129)])expect(()=>splitInvitationLink(`https://example.com/${path}?ref=${code}`)).toThrow(/有效邀请码/);
    expect(()=>splitInvitationLink(`https://example.com/${path}?source=sample`)).toThrow(/暂不识别/);
  });
  it('rejects unknown invitation forms instead of guessing where the code begins',()=>{
    expect(()=>splitInvitationLink('https://example.com/ref/CODE_1')).toThrow(/暂不识别/);
    expect(()=>splitInvitationLink('https://example.com/other?ref=CODE_1')).toThrow(/暂不识别/);
    expect(()=>splitInvitationLink('https://example.com/register?ref=ONE&ref=TWO')).toThrow(/多个 ref/);
    expect(()=>splitInvitationLink('https://example.com/register?ref=ONE&%72ef=TWO')).toThrow(/多个 ref/);
    expect(()=>splitInvitationLink('https://example.com/join/ONE?ref=TWO')).toThrow(/位置不明确/);
    expect(()=>splitInvitationLink('https://example.com/join/ONE?%72ef=TWO')).toThrow(/位置不明确/);
    expect(()=>splitInvitationLink('https://@example.com/join/ONE')).toThrow(/不能包含 @/);
    expect(()=>splitInvitationLink('https://example.com/join/CODE#fragment')).toThrow(/# 后面的内容/);
  });
});
