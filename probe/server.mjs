import http from 'node:http';
import https from 'node:https';
import { resolve4 } from 'node:dns/promises';
import { createHmac, timingSafeEqual } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { isIP } from 'node:net';
import { pathToFileURL } from 'node:url';

const ID = /^[A-Za-z0-9_-]{1,128}$/;
const MAX_BODY = 64 * 1024;
const UNKNOWN = 'unknown';
export function publicIPv4(address) {
  if (isIP(address) !== 4) return false;
  const [a,b,c] = address.split('.').map(Number);
  return !(a === 0 || a === 10 || a === 127 || a >= 224 ||
    (a === 100 && b >= 64 && b <= 127) || (a === 169 && b === 254) ||
    (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168) ||
    (a === 192 && b === 0 && (c === 0 || c === 2)) ||
    (a === 192 && b === 88 && c === 99) || (a === 198 && (b === 18 || b === 19)) ||
    (a === 198 && b === 51 && c === 100) || (a === 203 && b === 0 && c === 113));
}
export function allowedUrl(value, hosts) {
  if (typeof value !== 'string' || value.length > 2048 || /[\u0000-\u0020\u007f\\]/.test(value)) throw new Error('Invalid URL');
  const authority=/^https:\/\/([^/?#]+)/i.exec(value)?.[1];
  if(!authority || authority.includes('@'))throw new Error('Invalid authority');
  const url = new URL(value);
  if (url.protocol !== 'https:' || url.username || url.password || url.port ||
    isIP(url.hostname) || !hosts.has(url.hostname) || !url.hostname.includes('.')) throw new Error('Target not allowed');
  return url;
}
export function parseHosts(value) {
  const hosts = new Set();
  for (const item of String(value || '').split(',').map(x => x.trim()).filter(Boolean)) {
    if (!/^[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?$/.test(item) || !item.includes('.') ||
      isIP(item) || item.split('.').some(x => !x || x.length > 63 || x.startsWith('-') || x.endsWith('-'))) throw new Error('Invalid allowed host');
    hosts.add(item);
  }
  if (!hosts.size || hosts.size > 256) throw new Error('Configure 1–256 exact allowed hostnames');
  return hosts;
}
function constantEqual(a,b) {
  const left=Buffer.from(a),right=Buffer.from(b);
  return left.length === right.length && timingSafeEqual(left,right);
}
export function validateBatch(payload, hosts, now = Math.floor(Date.now()/1000)) {
  if (!payload || !Number.isSafeInteger(payload.timestamp) || Math.abs(now-payload.timestamp)>300 ||
      !Array.isArray(payload.targets) || !payload.targets.length || payload.targets.length>20) throw new Error('Invalid batch');
  const seen = new Set();
  return payload.targets.map(target => {
    if (!target || typeof target.poolId !== 'string' || !ID.test(target.poolId) ||
        typeof target.id !== 'string' || !ID.test(target.id)) throw new Error('Invalid target');
    const key=target.poolId+'\0'+target.id;
    if (seen.has(key)) throw new Error('Duplicate target');
    seen.add(key); allowedUrl(target.url,hosts);
    return {poolId:target.poolId,id:target.id,url:target.url};
  });
}
function head(url, address, signal) {
  return new Promise((resolve,reject) => {
    const request=https.request(url, {method:'HEAD',agent:false,signal,
      lookup:(_hostname,options,callback) => options.all ? callback(null,[{address,family:4}]) : callback(null,address,4),
      headers:{'User-Agent':'Route-Check','Accept':'*/*'}}, response => {
      const result={status:response.statusCode || 0,location:response.headers.location,challenge:response.headers['cf-mitigated']==='challenge'};
      response.destroy(); resolve(result);
    });
    request.on('error',reject);request.end();
  });
}
export async function checkReachability(raw, hosts, signal, network = {resolve4,head}) {
  try {
    let url=allowedUrl(raw,hosts);
    // A synthetic code is not a real page. Probe the fixed authority itself;
    // an application 404 cannot establish a network failure for an entire pool.
    url=new URL('/',url);
    for (let hop=0;hop<4;hop++) {
      if(signal.aborted)return UNKNOWN;
      const addresses=await network.resolve4(url.hostname);
      if (!addresses.length || addresses.some(x=>!publicIPv4(x))) return UNKNOWN;
      const result=await network.head(url,addresses[0],signal);
      if(result.challenge || result.status===403 || result.status===429 || result.status===401)return UNKNOWN;
      if([301,302,303,307,308].includes(result.status)) {
        if(hop===3 || !result.location)return UNKNOWN;
        url=allowedUrl(new URL(result.location,url).href,hosts); continue;
      }
      if(result.status>=200 && result.status<500)return 'reachable';
      if(result.status>=500 && result.status<=599)return 'unreachable';
      return UNKNOWN;
    }
  } catch {
    // DNS, TLS and transport failures can be local/provider faults. They are
    // inconclusive without independent measurement, not proof of blocking.
  }
  return UNKNOWN;
}
export function createProbeServer({secret,hosts,check=checkReachability}) {
  if(typeof secret!=='string'||!/^[\x21-\x7e]{32,256}$/.test(secret))throw new Error('Use a 32–256 character printable ASCII key without whitespace');
  if(!(hosts instanceof Set)||!hosts.size)throw new Error('Allowed hosts required');
  let active=false;
  const server=http.createServer(async (request,response)=>{
    const reply=(status,body='')=>{response.writeHead(status,{'Content-Type':'application/json','Cache-Control':'no-store'});response.end(body);};
    if(request.method!=='POST'||request.url!=='/check'){reply(404);request.resume();return;}
    if(!constantEqual(request.headers.authorization || '',`Bearer ${secret}`)){reply(401);request.resume();return;}
    if(!/^application\/json(?:\s*;\s*charset\s*=\s*(?:utf-8|"utf-8"))?$/i.test(String(request.headers['content-type']||'').trim())){reply(415);request.resume();return;}
    if(active){reply(429);request.resume();return;}
    active=true;
    const controller=new AbortController();
    const deadline=setTimeout(()=>controller.abort(),7500);
    let bodyTimer;
    try {
      bodyTimer=setTimeout(()=>request.destroy(),2000);
      const chunks=[];let size=0;
      for await(const chunk of request){size+=chunk.length;if(size>MAX_BODY){reply(413);return;}chunks.push(chunk);}
      clearTimeout(bodyTimer);
      const targets=validateBatch(JSON.parse(Buffer.concat(chunks).toString('utf8')),hosts);
      const results=targets.map(({poolId,id})=>({poolId,id,status:UNKNOWN}));
      let cursor=0;
      const work=Promise.all(Array.from({length:Math.min(5,targets.length)},async()=>{
        while(cursor<targets.length&&!controller.signal.aborted){const index=cursor++;const status=await check(targets[index].url,hosts,controller.signal);if(!controller.signal.aborted)results[index].status=['reachable','unreachable','unknown'].includes(status)?status:UNKNOWN;}
      }));
      await Promise.race([work,new Promise(resolve=>controller.signal.addEventListener('abort',resolve,{once:true}))]);
      const raw=JSON.stringify({timestamp:Math.floor(Date.now()/1000),results});
      response.writeHead(200,{'Content-Type':'application/json','Cache-Control':'no-store','X-Probe-Signature':createHmac('sha256',secret).update(raw).digest('hex')});response.end(raw);
    }catch{if(!response.headersSent&&!response.destroyed)reply(400);}
    finally{clearTimeout(bodyTimer);clearTimeout(deadline);controller.abort();active=false;}
  });
  server.requestTimeout=10000;server.headersTimeout=5000;server.keepAliveTimeout=1000;server.maxHeadersCount=30;
  return server;
}
if(process.argv[1]&&import.meta.url===pathToFileURL(process.argv[1]).href){
  try{
    const keyPath=process.env.PROBE_KEY_FILE;
    if(!keyPath)throw new Error('Set PROBE_KEY_FILE to a private key file');
    const secret=readFileSync(keyPath,'utf8').trim();const hosts=parseHosts(process.env.PROBE_ALLOWED_HOSTS);
    const port=Number(process.env.PROBE_PORT||8789);if(!Number.isInteger(port)||port<1024||port>65535)throw new Error('Invalid port');
    createProbeServer({secret,hosts}).listen(port,'127.0.0.1',()=>console.log('Probe ready on loopback; use a trusted HTTPS reverse proxy.'));
  }catch{console.error('Probe configuration invalid; check private key file, exact allowed hosts and port.');process.exitCode=1;}
}
