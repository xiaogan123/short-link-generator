import { readdirSync, readFileSync, writeFileSync, mkdirSync, copyFileSync, lstatSync } from 'node:fs';
import { join, basename, dirname } from 'node:path';
import { createHash } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { matchingAppInputs } from './release-app-inputs.mjs';
const version=JSON.parse(readFileSync('package.json','utf8')).version;
const repository=process.env.GITHUB_REPOSITORY;
if (!/^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/.test(repository??''))throw new Error('Invalid repository.');
const root=process.argv[2]??'candidates';
const requireEvidence=process.argv.includes('--require-evidence');
const files=[];
function walk(p){for(const e of readdirSync(p,{withFileTypes:true})){const x=join(p,e.name);if(e.isDirectory())walk(x);else files.push(x);}}
walk(root);
const sha256=path=>createHash('sha256').update(readFileSync(path)).digest('hex');
const hex=value=>/^[0-9a-f]{64}$/.test(value??'');
const targets={
  'aarch64-apple-darwin':{host:'darwin-arm64',platform:'darwin-aarch64',installerDir:'dmg',installerSuffix:'.dmg',updaterDir:'macos',updaterSuffix:'.app.tar.gz'},
  'x86_64-apple-darwin':{host:'darwin-x64',platform:'darwin-x86_64',installerDir:'dmg',installerSuffix:'.dmg',updaterDir:'macos',updaterSuffix:'.app.tar.gz'},
  'x86_64-pc-windows-msvc':{host:'win32-x64',platform:'windows-x86_64',installerDir:'nsis',installerSuffix:'-setup.exe',updaterDir:'nsis',updaterSuffix:'-setup.exe'},
};
const verified=new Map();
function exactArtifact(candidateRoot,subdir,name,suffix,digest){
  if(typeof name!=='string'||basename(name)!==name||!name.endsWith(suffix)||!hex(digest))throw new Error('Invalid native artifact name or digest.');
  const matches=files.filter(file=>dirname(file)===join(candidateRoot,subdir)&&basename(file)===name);
  if(matches.length!==1||lstatSync(matches[0]).isSymbolicLink()||sha256(matches[0])!==digest)throw new Error('Native evidence does not match its exact artifact.');
  return matches[0];
}
function validateManualLocal(evidence,reviewedSha,target){
  if(target!=='aarch64-apple-darwin'||evidence.schema!==2||evidence.method!=='manual-local'||
     evidence.reviewedSha!==reviewedSha||!/^[0-9a-f]{40}$/.test(evidence.buildSha??'')||evidence.buildSha===reviewedSha||
     evidence.osVersion!=='26.5.2'||evidence.guiObserved!==true||evidence.processAlive!==true||
     evidence.architectureVerified!==true||evidence.signatureVerified!==true||evidence.updaterSignatureVerified!==true||
     evidence.updaterSignaturePresent!==true||evidence.minimumSystemVersionMetadata!=='11.0'||
     evidence.minimumSystemRuntimeTested!==false)throw new Error('Manual local ARM evidence is incomplete.');
  const manifest=matchingAppInputs(evidence.buildSha,reviewedSha);
  if(evidence.appInputManifestSha256!==manifest.sha256||evidence.appInputFileCount!==manifest.fileCount)throw new Error('Manual local ARM app input manifest mismatch.');
  const config=evidence.buildConfiguration;
  if(!config||!hex(config.releaseConfigSha256)||!hex(config.updaterPublicKeySha256)||!hex(config.encodedRustflagsSha256)||
     config.updaterEndpoint!==`https://github.com/${repository}/releases/latest/download/latest.json`||
     JSON.stringify(config.normalizedRustflags)!==JSON.stringify(['workspace-path-remap','home-path-remap']))throw new Error('Manual local ARM build configuration evidence is incomplete.');
}
if(requireEvidence){
  const sha=process.env.RELEASE_SHA??execFileSync('git',['rev-parse','HEAD'],{encoding:'utf8'}).trim();
  const tag=process.env.RELEASE_TAG??`v${version}`;
  if(!/^[0-9a-f]{40}$/.test(sha)||tag!==`v${version}`)throw new Error('Reviewed release tag and SHA are required.');
  const head=execFileSync('git',['rev-parse','HEAD'],{encoding:'utf8'}).trim();
  const tagged=execFileSync('git',['rev-parse','--verify',`refs/tags/${tag}^{commit}`],{encoding:'utf8'}).trim();
  if(head!==sha||tagged!==sha)throw new Error('Candidate source does not match the checked-out reviewed tag.');
  for(const [target,config] of Object.entries(targets)){
    const candidateRoot=join(root,`candidate-${target}`);
    const matches=files.filter(file=>file===join(candidateRoot,'native-smoke.json'));
    if(matches.length!==1||lstatSync(matches[0]).isSymbolicLink())throw new Error(`Missing unique native startup evidence for ${target}.`);
    const evidence=JSON.parse(readFileSync(matches[0],'utf8'));
    if(evidence.tag!==tag||evidence.target!==target||evidence.host!==config.host||
       evidence.processAlive!==true||evidence.updaterSignaturePresent!==true||evidence.architectureVerified!==true){
      throw new Error(`Native startup evidence is invalid for ${target}.`);
    }
    if(evidence.method==='manual-local')validateManualLocal(evidence,sha,target);
    else if(evidence.schema!==1||evidence.sha!==sha||
            (target.includes('apple')&&evidence.signatureVerified!==true)||
            (target.includes('windows')&&evidence.windowObserved!==true)){
      throw new Error(`Native runner evidence is invalid for ${target}.`);
    }
    const installer=exactArtifact(candidateRoot,config.installerDir,evidence.installer,config.installerSuffix,evidence.installerSha256);
    const updater=exactArtifact(candidateRoot,config.updaterDir,evidence.updater,config.updaterSuffix,evidence.updaterSha256);
    const signature=`${updater}.sig`;
    if(!files.includes(signature)||lstatSync(signature).isSymbolicLink()||!readFileSync(signature,'utf8').trim())throw new Error(`Missing updater signature for ${target}.`);
    verified.set(installer,{platform:config.platform,suffix:config.installerSuffix==='-setup.exe'?'.exe':config.installerSuffix});
    verified.set(updater,{platform:config.platform,suffix:config.updaterSuffix==='-setup.exe'?'.exe':config.updaterSuffix,signature});
  }
  const signatures=new Set([...verified.values()].map(item=>item.signature).filter(Boolean));
  for(const file of files){
    if((file.endsWith('.app.tar.gz')||/\.(dmg|exe)$/.test(file))&&!verified.has(file))throw new Error(`Unreviewed publishable artifact: ${basename(file)}`);
    if(file.endsWith('.sig')&&!signatures.has(file))throw new Error(`Unreviewed updater signature: ${basename(file)}`);
  }
}
const platforms={};const uploads=[];const names=new Set();
mkdirSync('release-assets',{recursive:true});
const publishFiles=requireEvidence?[...verified.keys()]:files;
for(const file of publishFiles){
  const item=verified.get(file);
  const suffix=item?.suffix??(file.endsWith('.app.tar.gz')?'.app.tar.gz':/\.(dmg|exe)$/.exec(file)?.[0]);
  if(!suffix)continue;
  let platform=item?.platform;
  if(!platform){
    if(file.includes('aarch64-apple-darwin'))platform='darwin-aarch64';
    if(file.includes('x86_64-apple-darwin'))platform='darwin-x86_64';
    if(file.includes('x86_64-pc-windows-msvc'))platform='windows-x86_64';
  }
  if(!platform)throw new Error('Artifact is outside its native platform directory.');
  const name=`short-link-generator_${version}_${platform}${suffix}`;
  if(names.has(name))throw new Error(`Duplicate platform artifact: ${name}`);names.add(name);
  const out=join('release-assets',name);copyFileSync(file,out);uploads.push(out);
  const signatureFile=item?.signature??file+'.sig';
  if(files.includes(signatureFile)) {
    const signature=readFileSync(signatureFile,'utf8').trim();if(!signature)throw new Error('Empty update signature.');
    copyFileSync(signatureFile,out+'.sig');uploads.push(out+'.sig');
    if(suffix==='.app.tar.gz'||(platform==='windows-x86_64'&&suffix==='.exe'))platforms[platform]={signature,url:`https://github.com/${repository}/releases/download/v${version}/${name}`};
  }
}
for(const p of ['darwin-aarch64','darwin-x86_64','windows-x86_64'])if(!platforms[p])throw new Error(`Missing signed updater artifact: ${p}`);
writeFileSync('latest.json',JSON.stringify({version,notes:'See the release notes for changes and installation details.',pub_date:new Date().toISOString(),platforms},null,2)+'\n');
writeFileSync('SHA256SUMS',[...uploads.filter(x=>!x.endsWith('.sig')),'latest.json'].map(x=>`${sha256(x)}  ${basename(x)}`).join('\n')+'\n');
writeFileSync('release-assets.json',JSON.stringify([...uploads,'latest.json','SHA256SUMS']));
