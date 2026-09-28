import { readdirSync, readFileSync, writeFileSync, mkdirSync, copyFileSync } from 'node:fs';
import { join, basename } from 'node:path';
import { createHash } from 'node:crypto';
const version=JSON.parse(readFileSync('package.json','utf8')).version;
const repository=process.env.GITHUB_REPOSITORY;
if (!/^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/.test(repository??''))throw new Error('Invalid repository.');
const root=process.argv[2]??'candidates';
const files=[];
function walk(p){for(const e of readdirSync(p,{withFileTypes:true})){const x=join(p,e.name);if(e.isDirectory())walk(x);else files.push(x);}}
walk(root);
const platforms={};const uploads=[];const names=new Set();
mkdirSync('release-assets',{recursive:true});
for(const file of files){
  const suffix=file.endsWith('.app.tar.gz')?'.app.tar.gz':/\.(dmg|msi|exe)$/.exec(file)?.[0];
  if(!suffix)continue;
  let platform;
  if(file.includes('aarch64-apple-darwin'))platform='darwin-aarch64';
  if(file.includes('x86_64-apple-darwin'))platform='darwin-x86_64';
  if(file.includes('x86_64-pc-windows-msvc'))platform='windows-x86_64';
  if(!platform)throw new Error('Artifact is outside its native platform directory.');
  const name=`short-link-generator_${version}_${platform}${suffix}`;
  if(names.has(name))throw new Error(`Duplicate platform artifact: ${name}`);names.add(name);
  const out=join('release-assets',name);copyFileSync(file,out);uploads.push(out);
  if(files.includes(file+'.sig')) {
    const signature=readFileSync(file+'.sig','utf8').trim();if(!signature)throw new Error('Empty update signature.');
    copyFileSync(file+'.sig',out+'.sig');uploads.push(out+'.sig');
    if(suffix==='.app.tar.gz'||(platform==='windows-x86_64'&&suffix==='.exe'))platforms[platform]={signature,url:`https://github.com/${repository}/releases/download/v${version}/${name}`};
  }
}
for(const p of ['darwin-aarch64','darwin-x86_64','windows-x86_64'])if(!platforms[p])throw new Error(`Missing signed updater artifact: ${p}`);
writeFileSync('latest.json',JSON.stringify({version,notes:'See the release notes for changes and installation details.',pub_date:new Date().toISOString(),platforms},null,2)+'\n');
writeFileSync('SHA256SUMS',uploads.filter(x=>!x.endsWith('.sig')).map(x=>`${createHash('sha256').update(readFileSync(x)).digest('hex')}  ${basename(x)}`).join('\n')+'\n');
writeFileSync('release-assets.json',JSON.stringify([...uploads,'latest.json','SHA256SUMS']));
