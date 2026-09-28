// This runs only inside the protected release environment. Do not print terms.
import { mkdirSync, writeFileSync } from 'node:fs';
import { homedir } from 'node:os';
import { join } from 'node:path';
const text=process.env.PRIVACY_DENYLIST;
if(!text || !text.split(/\r?\n/).some(x=>x.trim()&&!x.trim().startsWith('#')))throw new Error('Configure the protected release privacy denylist first.');
const dir=join(homedir(),'.config','short-link-generator');mkdirSync(dir,{recursive:true,mode:0o700});
writeFileSync(join(dir,'denylist.txt'),text,{mode:0o600});
