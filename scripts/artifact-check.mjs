import { readFileSync, readdirSync, lstatSync, readlinkSync, mkdtempSync, rmSync, existsSync } from 'node:fs';
import { resolve, join, relative, dirname, isAbsolute } from 'node:path';
import { tmpdir, homedir } from 'node:os';
import { execFileSync } from 'node:child_process';
import { inspect, loadWords } from './privacy-check.mjs';
const root=resolve(process.argv[2] ?? '');
if (!process.argv[2] || !existsSync(root)) throw new Error('Supply the candidate bundle directory.');
const words=loadWords(resolve(homedir(),'.config/short-link-generator/denylist.txt'),true);
const failures=[];let files=0;let expanded=0;
const run=(cmd,args)=>execFileSync(cmd,args,{stdio:'pipe',maxBuffer:16*1024*1024});
const outside=(base,path)=>{const r=relative(base,path);return r==='..'||r.startsWith('..'+(process.platform==='win32'?'\\':'/'))||isAbsolute(r);};
function record(label,value){const hits=inspect(value,words);if(hits.length)failures.push({file:label,rules:hits});}
function scan(path,base,depth=0) {
  record('path',relative(base,path));
  const stat=lstatSync(path);
  if (stat.isSymbolicLink()) {
    const target=readlinkSync(path);record('symlink',target);
    // Installer drag-to-Applications shortcut is not application content.
    if(target==='/Applications'&&path.endsWith('/Applications'))return;
    if(outside(base,resolve(dirname(path),target)))throw new Error('Artifact symlink escapes bundle.');
    if(!existsSync(resolve(dirname(path),target)))throw new Error('Artifact contains broken symlink.');
    return; // Internal target is scanned through its real directory entry.
  }
  if (stat.isDirectory()) {for (const name of readdirSync(path)) scan(join(path,name),base,depth);return;}
  const data=readFileSync(path); files++;record(files,data);
  const lower=path.toLowerCase();
  if(depth>3)throw new Error('Archive nesting limit exceeded.');
  if(lower.endsWith('.dmg')) {
    if(process.platform!=='darwin') throw new Error('DMG contents must be inspected on macOS.');
    const mount=mkdtempSync(join(tmpdir(),'candidate-volume-'));let mounted=false;
    try {run('hdiutil',['attach','-readonly','-nobrowse','-mountpoint',mount,path]);mounted=true;expanded++;scan(mount,mount,depth+1);}
    finally {if(mounted)run('hdiutil',['detach',mount]);rmSync(mount,{recursive:true,force:true});}
  } else if(lower.endsWith('.tar.gz') || lower.endsWith('.tgz')) {
    const dir=mkdtempSync(join(tmpdir(),'candidate-tar-'));
    try {
      const list=run('tar',['-tzf',path]).toString().split('\n').filter(Boolean);
      if(list.some(x=>x.startsWith('/')||x.split('/').includes('..'))) throw new Error('Unsafe archive path.');
      run('tar',['-xzf',path,'-C',dir]);expanded++;scan(dir,dir,depth+1);
    }finally{rmSync(dir,{recursive:true,force:true});}
  } else if((lower.endsWith('.exe') && (depth===0 || lower.includes('setup'))) || /\.(msi|zip|cab|7z)$/.test(lower)) {
    const dir=mkdtempSync(join(tmpdir(),'candidate-installer-'));
    try {
      const seven=process.platform==='win32'?'C:\\Program Files\\7-Zip\\7z.exe':'7zz';
      run(seven,['x','-y',`-o${dir}`,path]);expanded++;scan(dir,dir,depth+1);
    }finally{rmSync(dir,{recursive:true,force:true});}
  } else if(/\.(gz|bz2|xz|rar|tar)$/.test(lower)||data.subarray(0,4).equals(Buffer.from([0x50,0x4b,3,4]))||data.subarray(0,2).equals(Buffer.from([0x1f,0x8b]))) {
    throw new Error('Unsupported compressed artifact must be explicitly inspected.');
  }
}
scan(root,root);
if(files===0)throw new Error('No artifact files were inspected.');
console.log(JSON.stringify({files,expanded,privateDenylist:'enforced',failures},null,2));
if(failures.length)process.exitCode=1;
