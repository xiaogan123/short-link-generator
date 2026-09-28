import { describe, expect, it } from 'vitest';
import { normalizeHost, shortUrl, validateHost, validatePrefix, validateSlug, validateTarget } from './validators';

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
});
