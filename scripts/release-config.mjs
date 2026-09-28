import { appendFileSync, readFileSync, writeFileSync } from 'node:fs';
import {execFileSync} from 'node:child_process';
const pkg = JSON.parse(readFileSync('package.json','utf8'));
if (process.argv.includes('--validate-tag')) {
  const tag=process.env.RELEASE_TAG ?? '';
  if (tag !== `v${pkg.version}` || !/^v\d+\.\d+\.\d+(?:-[a-zA-Z0-9.-]+)?$/.test(tag)) throw new Error('Release tag must match the package version.');
  const head=execFileSync('git',['rev-parse','HEAD'],{encoding:'utf8'}).trim();
  const tagged=execFileSync('git',['rev-parse','--verify',`refs/tags/${tag}^{commit}`],{encoding:'utf8'}).trim();
  if(tagged!==head)throw new Error('The requested tag must exist and point to the checked-out commit.');
  if (!process.env.GITHUB_OUTPUT) throw new Error('Workflow output is unavailable.');
  appendFileSync(process.env.GITHUB_OUTPUT,`tag=${tag}\nsha=${head}\n`);
} else {
  const pubkey=process.env.SLG_UPDATER_PUBLIC_KEY;
  const endpoint=process.env.SLG_UPDATER_ENDPOINT;
  if (!pubkey || !endpoint || !/^https:\/\/github\.com\/[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+\/releases\/latest\/download\/latest\.json$/.test(endpoint)) throw new Error('Configure a real updater public key and repository endpoint first.');
  const decoded=Buffer.from(pubkey,'base64').toString('utf8');
  if (!decoded.startsWith('untrusted comment:') || !decoded.includes('\n')) throw new Error('Updater public key is not a base64 minisign public key.');
  writeFileSync('release-config.json',JSON.stringify({bundle:{createUpdaterArtifacts:true},plugins:{updater:{pubkey,endpoints:[endpoint]}}},null,2)+'\n');
  if (process.env.GITHUB_ENV) {
    if (/[\r\n]/.test(pubkey+endpoint)) throw new Error('Unexpected newline in release configuration.');
    appendFileSync(process.env.GITHUB_ENV,`SLG_UPDATER_PUBLIC_KEY=${pubkey}\nSLG_UPDATER_ENDPOINT=${endpoint}\n`);
  }
}
