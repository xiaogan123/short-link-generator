import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync,writeFileSync,mkdtempSync,mkdirSync,copyFileSync,rmSync,existsSync } from 'node:fs';
import { join,resolve } from 'node:path';
import { tmpdir } from 'node:os';
import { execFileSync,spawnSync } from 'node:child_process';
import YAML from 'yaml';
const root=process.cwd();
function fixture(){const dir=mkdtempSync(join(tmpdir(),'release-fixture-'));writeFileSync(join(dir,'package.json'),JSON.stringify({version:'0.1.0',type:'module'}));return dir;}
test('three signed platforms with identical source basenames generate unique updater assets',()=>{
 const dir=fixture();try{
  for(const [target,file] of [['aarch64-apple-darwin','Example.app.tar.gz'],['x86_64-apple-darwin','Example.app.tar.gz'],['x86_64-pc-windows-msvc','Example.exe']]){
   const path=join(dir,'candidates','candidate-'+target);mkdirSync(path,{recursive:true});writeFileSync(join(path,file),'fixture package');writeFileSync(join(path,file+'.sig'),'fixture signature');
  }
  const r=spawnSync(process.execPath,[resolve(root,'scripts/release-manifest.mjs'),'candidates'],{cwd:dir,encoding:'utf8',env:{...process.env,GITHUB_REPOSITORY:'sample/short-link-generator'}});
  assert.equal(r.status,0,r.stderr);const manifest=JSON.parse(readFileSync(join(dir,'latest.json'),'utf8'));
  assert.deepEqual(Object.keys(manifest.platforms).sort(),['darwin-aarch64','darwin-x86_64','windows-x86_64']);
  assert.equal(new Set(Object.values(manifest.platforms).map(x=>x.url)).size,3);
 }finally{rmSync(dir,{recursive:true,force:true});}
});
test('release validation refuses a version-named branch without an actual tag',()=>{
 const dir=fixture();try{
  const git=(...args)=>execFileSync('git',args,{cwd:dir,stdio:'pipe'});
  git('init','-q');git('config','user.name','Example');git('config','user.email','example@example.org');git('add','.');git('commit','-qm','init');git('branch','v0.1.0');
  const run=()=>spawnSync(process.execPath,[resolve(root,'scripts/release-config.mjs'),'--validate-tag'],{cwd:dir,encoding:'utf8',env:{...process.env,RELEASE_TAG:'v0.1.0',GITHUB_OUTPUT:join(dir,'out')}});
  assert.notEqual(run().status,0);assert.equal(existsSync(join(dir,'out')),false);
  git('tag','v0.1.0');assert.equal(run().status,0);
  const sha=execFileSync('git',['rev-parse','HEAD'],{cwd:dir,encoding:'utf8'}).trim();assert.ok(readFileSync(join(dir,'out'),'utf8').includes('sha='+sha));
 }finally{rmSync(dir,{recursive:true,force:true});}
});
test('untrusted PR jobs cannot access release secrets and native checks are explicitly selected',()=>{
 const ci=YAML.parse(readFileSync('.github/workflows/ci.yml','utf8'));
 const release=YAML.parse(readFileSync('.github/workflows/release.yml','utf8'));
 assert.equal(ci.permissions.contents,'read');assert.equal(ci.jobs.native.if,"github.event_name == 'workflow_dispatch'");
 assert.ok(!JSON.stringify(ci).includes('secrets.'));assert.ok(!release.on.pull_request);
 for(const job of Object.values(release.jobs))assert.equal(job.environment,'release');
 assert.ok(JSON.stringify(release.jobs.build.steps).includes('needs.prepare.outputs.sha'));
 assert.ok(JSON.stringify(release.jobs.draft.steps).includes('needs.prepare.outputs.sha'));
 for(const workflow of [ci,release])for(const job of Object.values(workflow.jobs))for(const step of job.steps??[])if(step.uses)assert.match(step.uses,/@[0-9a-f]{40}$/);
});
