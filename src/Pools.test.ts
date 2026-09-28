import {describe,expect,it} from 'vitest';
import {poolValidation,composeTemplate} from './Pools';
import type {Pool} from './types';

const base:Pool={id:'p1',name:'示例',official:{prefix:'https://example.com/path/',suffix:''},candidates:[{id:'c1',prefix:'https://example.org/?code=',suffix:'&lang=zh',enabled:true}],updated:'',accountIds:['a1']};

describe('shared address templates',()=>{
  it('keeps codes in path or query and retains each code on composition',()=>{
    expect(poolValidation(base)).toBeNull();
    expect(composeTemplate(base.official.prefix,'one_1')).toBe('https://example.com/path/one_1');
    expect(composeTemplate(base.official.prefix,'two_2')).toBe('https://example.com/path/two_2');
  });
  it('rejects code insertion into host or fragment',()=>{
    expect(poolValidation({...base,official:{prefix:'https://',suffix:'.example.com/path'}})).not.toBeNull();
    expect(poolValidation({...base,official:{prefix:'https://example.com/#',suffix:''}})).not.toBeNull();
  });
});
