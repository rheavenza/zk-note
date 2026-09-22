#!/usr/bin/env node
// Starts isolated local services, applies local migrations, builds and checks both backends.
import { spawn } from 'node:child_process';
import { once } from 'node:events';
import { fileURLToPath } from 'node:url';
import { mkdtemp, rm, open } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import net from 'node:net';
async function freePort(){ const server=net.createServer();server.listen(0,'127.0.0.1');await once(server,'listening');const port=server.address().port;await new Promise(r=>server.close(r));return port; }
const nativePort=await freePort(),workerPort=await freePort();
const nativeUrl=`http://127.0.0.1:${nativePort}`,workerUrl=`http://127.0.0.1:${workerPort}`;
const root=fileURLToPath(new URL('..',import.meta.url));
const cwd=path.join(root,'apps/cloudflare-worker');
const temp=await mkdtemp(path.join(tmpdir(),'zk-cloudflare-smoke-'));
const env={...process.env,WRANGLER_SEND_METRICS:'false'};
const children=[];
async function run(command,args,options={}) {
  const child=spawn(command,args,{cwd,env,stdio:'inherit',...options});
  const [code]=await once(child,'exit'); if(code!==0)throw Error(`${command} failed (${code})`);
}
async function start(command,args,options={}) {
  const log=await open(path.join(temp,`${children.length}.log`),'w',0o600);
  const child=spawn(command,args,{cwd,env,stdio:['ignore',log.fd,log.fd],detached:true,...options});children.push(child);await log.close();return child;
}
async function ready(url,child) {
  for(let n=0;n<180;n++) {
    if(child.exitCode!==null)throw Error(`Service exited; logs: ${temp}`);
    try{if((await fetch(url+'/health')).ok)return;}catch{}
    await new Promise(r=>setTimeout(r,500));
  }
  throw Error(`Service did not start: ${url}; logs: ${temp}`);
}
let passed=false;
try {
  await run('npx',['wrangler','d1','migrations','apply','zk-note-staging-db','--local','--persist-to',temp]);
  await run('worker-build',['--release']);
  await run('cargo',['build','-p','zk-server'],{cwd:root});
  const native=await start(path.join(root,'target/debug/zk-server'),[],{env:{...env,ZK_SERVER_PORT:String(nativePort),ZK_SERVER_DB_PATH:path.join(temp,'native.db')}});
  const worker=await start('npx',['wrangler','dev','--local','--port',String(workerPort),'--persist-to',temp]);
  await Promise.all([ready(nativeUrl,native),ready(workerUrl,worker)]);
  await run('node',[path.join(root,'scripts/server-contract.mjs'),nativeUrl,workerUrl]);
  passed=true;
} finally {
  for(const child of children){try{process.kill(-child.pid,'SIGTERM');}catch{}}
  if(passed)await rm(temp,{recursive:true,force:true});else console.error(`Local logs retained at ${temp}`);
}
