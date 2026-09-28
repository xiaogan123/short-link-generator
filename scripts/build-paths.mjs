import { appendFileSync } from 'node:fs';
import { homedir } from 'node:os';
import { resolve } from 'node:path';
if(!process.env.GITHUB_ENV)throw new Error('This helper runs in the native build workflow.');
const paths=[process.cwd(),process.env.CARGO_HOME||resolve(homedir(),'.cargo'),homedir()];
const flags=paths.flatMap((p,i)=>['--remap-path-prefix',`${p}=/build/${i}`]).join('\u001f');
appendFileSync(process.env.GITHUB_ENV,`CARGO_ENCODED_RUSTFLAGS=${flags}\n`);
