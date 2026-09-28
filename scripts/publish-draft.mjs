import {readFileSync} from 'node:fs';
import {execFileSync} from 'node:child_process';
const tag=`v${JSON.parse(readFileSync('package.json','utf8')).version}`;
const head=execFileSync('git',['rev-parse','HEAD'],{encoding:'utf8'}).trim();
const refs=execFileSync('git',['ls-remote','origin',`refs/tags/${tag}`,`refs/tags/${tag}^{}`],{encoding:'utf8'}).trim().split('\n').filter(Boolean);
const target=(refs.find(x=>x.endsWith('^{}'))||refs[0]||'').split(/\s+/)[0];
if(target!==head)throw new Error('Release tag moved after verification.');
const files=JSON.parse(readFileSync('release-assets.json','utf8'));
execFileSync('gh',['release','create',tag,'--verify-tag','--draft','--title',tag,'--notes-file','docs/RELEASE-NOTES.md',...files],{stdio:'inherit'});
