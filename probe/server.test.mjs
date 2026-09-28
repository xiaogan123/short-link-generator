import test from 'node:test';
import assert from 'node:assert/strict';
import {createHmac} from 'node:crypto';
import {createProbeServer,parseHosts,publicIPv4,allowedUrl,validateBatch,checkReachability} from './server.mjs';
const hosts=parseHosts('example.com,example.org');
const secret='test-key-'.repeat(8);
const batch=()=>({timestamp:Math.floor(Date.now()/1000),targets:[{poolId:'pool',id:'first',url:'https://example.com/join/probe'}]});
test('only public IPv4 destinations and exact explicitly configured hosts are permitted',()=>{
 for(const ip of ['127.0.0.1','10.1.1.1','169.254.169.254','172.16.0.1','192.168.1.1','100.64.0.1','198.19.0.1','192.0.2.1','203.0.113.1','224.0.0.1','::1'])assert.equal(publicIPv4(ip),false,ip);
 assert.equal(publicIPv4('1.1.1.1'),true);
 for(const url of ['https://example.com.evil.invalid/','https://example.com:8080/','https://u@example.com/','https://127.0.0.1/','http://example.com/'])assert.throws(()=>allowedUrl(url,hosts));
 assert.throws(()=>parseHosts('*'));assert.throws(()=>parseHosts('example.com,'+ 'a'.repeat(64)+'.example.org'));
 assert.equal(allowedUrl('https://example.com/path',hosts).hostname,'example.com');
});
test('batch validation rejects replay window, oversize target count and duplicate pairs',()=>{
 assert.equal(validateBatch(batch(),hosts).length,1);
 assert.throws(()=>validateBatch({...batch(),timestamp:0},hosts));
 assert.throws(()=>validateBatch({...batch(),targets:Array(21).fill(batch().targets[0])},hosts));
 assert.throws(()=>validateBatch({...batch(),targets:Array(2).fill(batch().targets[0])},hosts));
});
test('probe uses fixed authority, pins resolved public address, treats synthetic page absence as reachable',async()=>{
 let call;
 const network={resolve4:async()=>['1.1.1.1'],head:async(url,address)=>{call={url:url.href,address};return{status:404};}};
 assert.equal(await checkReachability('https://example.com/join/probe',hosts,new AbortController().signal,network),'reachable');
 assert.deepEqual(call,{url:'https://example.com/',address:'1.1.1.1'});
 network.resolve4=async()=>['1.1.1.1','10.0.0.1'];call=null;
 assert.equal(await checkReachability('https://example.com/',hosts,new AbortController().signal,network),'unknown');assert.equal(call,null);
});
test('redirects are bounded and cannot leave allowlist; challenge and transport errors stay unknown',async()=>{
 const network={resolve4:async()=>['1.1.1.1'],head:async()=>({status:302,location:'https://unlisted.example.org/'})};
 const run=()=>checkReachability('https://example.com/',hosts,new AbortController().signal,network);
 assert.equal(await run(),'unknown');
 let count=0;network.head=async()=>{count++;return{status:302,location:'/loop'};};assert.equal(await run(),'unknown');assert.equal(count,4);
 network.head=async()=>({status:200,challenge:true});assert.equal(await run(),'unknown');
 network.head=async()=>({status:429});assert.equal(await run(),'unknown');
 network.head=async()=>{throw new Error('timeout');};assert.equal(await run(),'unknown');
 network.head=async()=>({status:503});assert.equal(await run(),'unreachable');
});
test('HTTP service authenticates, signs exact bytes and rejects unauthorized targets before any measurement',async()=>{
 let calls=0;const server=createProbeServer({secret,hosts,check:async()=>{calls++;return 'reachable';}});
 await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));
 const endpoint=`http://127.0.0.1:${server.address().port}/check`;
 const send=(body,key=secret)=>fetch(endpoint,{method:'POST',headers:{authorization:`Bearer ${key}`,'Content-Type':'application/json'},body:JSON.stringify(body)});
 try{
  assert.equal((await send(batch(),'invalid')).status,401);assert.equal(calls,0);
  const bad=batch();bad.targets[0].url='https://unlisted.example.org/';assert.equal((await send(bad)).status,400);assert.equal(calls,0);
  const response=await send(batch());assert.equal(response.status,200);const raw=await response.text();
  assert.equal(response.headers.get('X-Probe-Signature'),createHmac('sha256',secret).update(raw).digest('hex'));
  assert.equal(JSON.parse(raw).results[0].status,'reachable');assert.equal(calls,1);
 }finally{await new Promise(resolve=>server.close(resolve));}
});

test('keys must be transportable ASCII and raw authorities cannot hide empty credentials',()=>{
 for(const value of ['x'.repeat(31),'x'.repeat(257),'x'.repeat(31)+'中','x'.repeat(31)+' ','x'.repeat(31)+'\t','x'.repeat(31)+'\x7f']){
  assert.throws(()=>createProbeServer({secret:value,hosts}));
 }
 for(const url of ['https://@example.com/','https://:@example.com/','https:///example.com/'])assert.throws(()=>allowedUrl(url,hosts));
});

test('JSON content type matches complete media type and optional UTF-8 charset',async()=>{
 let calls=0;const server=createProbeServer({secret,hosts,check:async()=>{calls++;return 'reachable';}});
 await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));
 const endpoint=`http://127.0.0.1:${server.address().port}/check`;
 try{
  for(const type of ['application/jsonBad','application/json-patch+json','application/json; charset=latin1','application/json; boundary=x']){
   const response=await fetch(endpoint,{method:'POST',headers:{authorization:`Bearer ${secret}`,'Content-Type':type},body:JSON.stringify(batch())});
   assert.equal(response.status,415,type);await response.text();
  }
  assert.equal(calls,0);
  for(const type of ['application/json','application/json; charset=UTF-8','Application/JSON; charset="utf-8"']){
   const response=await fetch(endpoint,{method:'POST',headers:{authorization:`Bearer ${secret}`,'Content-Type':type},body:JSON.stringify(batch())});
   assert.equal(response.status,200,type);await response.text();
  }
  assert.equal(calls,3);
 }finally{await new Promise(resolve=>server.close(resolve));}
});
