#!/usr/bin/env node
// Identical signed WebAuthn and opaque sync fixtures for native and Cloudflare servers.
import assert from 'node:assert/strict';
import { generateKeyPairSync, randomBytes, randomUUID, createHash, sign } from 'node:crypto';
const b64 = b => Buffer.from(b).toString('base64url');
const sha = b => createHash('sha256').update(b).digest();
const origin = process.env.ZK_TEST_ORIGIN || 'http://localhost:5173';
const rp = process.env.ZK_TEST_RP_ID || 'localhost';
function cbor(value) {
  const head = (major, n) => n < 24 ? Buffer.from([major * 32 + n]) : n < 256 ? Buffer.from([major * 32 + 24, n]) : Buffer.from([major * 32 + 25, n >> 8, n & 255]);
  if (Number.isInteger(value)) return value >= 0 ? head(0, value) : head(1, -1-value);
  if (typeof value === 'string') { const data=Buffer.from(value); return Buffer.concat([head(3,data.length),data]); }
  if (Buffer.isBuffer(value)) return Buffer.concat([head(2,value.length),value]);
  if (value instanceof Map) return Buffer.concat([head(5,value.size),...[...value].flatMap(([k,v])=>[cbor(k),cbor(v)])]);
  throw Error('unsupported test CBOR fixture');
}
async function contract(base) {
  let checks=0;
  async function call(path,{method='GET',body,token,raw=false,status=200,headers={}}={}) {
    const response=await fetch(base+path,{method,headers:{...(body!==undefined&&!raw?{'content-type':'application/json'}:{}),...(token?{authorization:`Bearer ${token}`} : {}),...headers},body:body===undefined?undefined:raw?body:JSON.stringify(body)});
    const bytes=Buffer.from(await response.arrayBuffer());
    const data=response.headers.get('content-type')?.includes('json')?JSON.parse(bytes.toString()):bytes;
    assert.equal(response.status,status,`${method} ${path}: unexpected status`);
    assert.ok(response.headers.get('x-request-id')); assert.equal(response.headers.get('x-content-type-options'),'nosniff');
    checks++;return data;
  }
  async function register(account,token) {
    const start=await call('/v1/auth/webauthn/register/start',{method:'POST',body:account?{account_id:account}:{},token});
    const {publicKey,privateKey}=generateKeyPairSync('ec',{namedCurve:'prime256v1'});
    const jwk=publicKey.export({format:'jwk'}); const credential=randomBytes(32); const device=randomUUID();
    const key=cbor(new Map([[1,2],[3,-7],[-1,1],[-2,Buffer.from(jwk.x,'base64url')],[-3,Buffer.from(jwk.y,'base64url')]]));
    const authData=Buffer.concat([sha(rp),Buffer.from([0x45]),Buffer.alloc(4),Buffer.alloc(16),Buffer.from([0,32]),credential,key]);
    const body={challenge_id:start.challenge_id,credential_id:b64(credential),public_key:b64(publicKey.export({type:'spki',format:'der'})),attestation_object:b64(cbor(new Map([['fmt','none'],['attStmt',new Map()],['authData',authData]]))),client_data_json:b64(JSON.stringify({type:'webauthn.create',challenge:start.challenge_b64,origin,crossOrigin:false})),device_id:device};
    const result=await call('/v1/auth/webauthn/register/finish',{method:'POST',body});
    assert.equal(result.session.account_id,start.user.id);
    await call('/v1/auth/webauthn/register/finish',{method:'POST',body,status:400});
    return {session:result.session,credential,privateKey};
  }
  async function login(user,mutate,status=200) {
    const start=await call('/v1/auth/webauthn/login/start',{method:'POST',body:{}});
    const client=Buffer.from(JSON.stringify({type:'webauthn.get',challenge:start.challenge_b64,origin,crossOrigin:false}));
    const authData=Buffer.concat([sha(rp),Buffer.from([5]),Buffer.alloc(4)]);
    const signature=sign('sha256',Buffer.concat([authData,sha(client)]),user.privateKey);
    const body={challenge_id:start.challenge_id,credential_id:b64(user.credential),signature:b64(signature),authenticator_data:b64(authData),client_data_json:b64(client)};
    if(mutate)mutate(body);
    const result=await call('/v1/auth/webauthn/login/finish',{method:'POST',body,status});
    await call('/v1/auth/webauthn/login/finish',{method:'POST',body,status:400});return result;
  }
  for(const path of ['/health','/v1/health']) { const h=await call(path);assert.equal(h.status,'ok');assert.equal(h.protocol_version,1); }
  await call('/v1/sync/pull',{status:401});
  const a=await register(), b=await register();const token=a.session.token, other=b.session.token, account=a.session.account_id;
  await login(a);await login(a,p=>{p.signature=b64(randomBytes(64));},400);
  await login(a,p=>{p.client_data_json=b64(JSON.stringify({type:'webauthn.get',challenge:'wrong',origin}));},400);
  await call('/v1/auth/webauthn/register/start',{method:'POST',body:{account_id:account},status:401});
  await call('/v1/auth/webauthn/register/start',{method:'POST',body:{account_id:account},token:other,status:403});
  await call('/v1/auth/whoami',{token:account,status:401});
  assert.equal((await call('/v1/auth/whoami',{token})).account_id,account);
  const wrap={cipher_suite:'xchacha20poly1305',nonce:randomBytes(24).toString('base64'),ciphertext:randomBytes(48).toString('base64')};
  const bootstrap={crypto_version:1,kdf:{algorithm:'argon2id',salt:randomBytes(16).toString('base64'),memory_kib:65536,iterations:3,parallelism:1},wrapped_vault_key:wrap,recovery_wrapped_vault_key:wrap};
  await call('/v1/vault/bootstrap',{token,status:404});
  assert.deepEqual(await call('/v1/vault/bootstrap',{method:'POST',body:bootstrap,token,status:201}),bootstrap);
  assert.deepEqual(await call('/v1/vault/bootstrap',{token}),bootstrap);
  await call('/v1/vault/bootstrap',{method:'POST',body:bootstrap,token,status:409});
  await call('/v1/vault/bootstrap',{token:other,status:404});
  const object=randomUUID();
  const envelope={envelope_version:1,object_id:object,object_kind:1,wrapped_key:{nonce:wrap.nonce,ciphertext:wrap.ciphertext},payload:{nonce:wrap.nonce,ciphertext:randomBytes(64).toString('base64')}};
  const initial={mutation_id:randomUUID(),object_id:object,expected_revision:0,object_kind:1,envelope,is_deleted:false};
  const push=(body,status=200,t=token)=>call('/v1/sync/push',{method:'POST',body,token:t,status});
  const created=await push(initial);assert.equal(created.revision,1);
  assert.deepEqual(await push(initial),created);
  assert.equal((await push({...initial,is_deleted:true},409)).code,'MUTATION_REPLAY_MISMATCH');
  const update={...initial,mutation_id:randomUUID(),expected_revision:1};const updated=await push(update);assert.equal(updated.revision,2);assert.ok(updated.server_seq>created.server_seq);
  assert.equal((await push({...update,mutation_id:randomUUID()},409)).error,'REVISION_CONFLICT');
  assert.deepEqual(await push(update),updated);
  await push({...update,mutation_id:randomUUID()},404,other);
  // Simultaneous stale writers: one winner, all others capture a conflict.
  const races=await Promise.all(Array.from({length:12},()=>fetch(base+'/v1/sync/push',{method:'POST',headers:{authorization:`Bearer ${token}`,'content-type':'application/json'},body:JSON.stringify({...initial,expected_revision:2,mutation_id:randomUUID()})}).then(async r=>({status:r.status,body:await r.json()}))));
  assert.equal(races.filter(r=>r.status===200).length,1);assert.equal(races.filter(r=>r.status===409).length,11);checks++;
  const deletion={...initial,expected_revision:3,mutation_id:randomUUID(),is_deleted:true};
  const replay=await Promise.all(Array.from({length:12},()=>push(deletion)));assert.ok(replay.every(v=>JSON.stringify(v)===JSON.stringify(replay[0])));assert.equal(replay[0].revision,4);
  const conflict=await push({...initial,expected_revision:3,mutation_id:randomUUID()},409);assert.equal(conflict.is_deleted,true);
  let page=await call('/v1/sync/pull?after=0&limit=1',{token});assert.equal(page.changes[0].revision,4);assert.equal(page.changes[0].is_deleted,true);
  assert.equal((await call(`/v1/sync/changes?cursor=${page.next_cursor}`,{token})).changes.length,0);
  assert.equal((await call('/v1/sync/pull',{token:other})).changes.length,0);
  // Distinct object races prove account sequence allocation remains unique.
  const distinct=await Promise.all(Array.from({length:12},()=>{const object_id=randomUUID();return push({...initial,object_id,mutation_id:randomUUID(),envelope:{...envelope,object_id}});}));
  assert.equal(new Set(distinct.map(v=>v.server_seq)).size,12);assert.ok(distinct.every(v=>v.server_seq>replay[0].server_seq));
  let cursor=0,seen=[];do{page=await call(`/v1/sync/pull?after=${cursor}&limit=3`,{token});seen.push(...page.changes);assert.ok(page.next_cursor>cursor);cursor=page.next_cursor;}while(page.has_more);
  assert.equal(seen.length,13);assert.ok(seen.every((v,i)=>i===0||v.server_seq>seen[i-1].server_seq));
  const blob='contract-'+randomUUID(), bytes=randomBytes(256*1024+16);
  await call('/v1/blobs/'+blob,{method:'PUT',body:bytes,raw:true,token,status:201});
  assert.deepEqual(await call('/v1/blobs/'+blob,{token}),bytes);
  await call('/v1/blobs/'+blob,{token:other,status:404});
  await call('/v1/blobs/'+blob,{method:'DELETE',token:other,status:404});
  await call('/v1/blobs/'+blob,{method:'DELETE',token});await call('/v1/blobs/'+blob,{token,status:404});
  const device=randomUUID();
  await call('/v1/auth/device/authorize',{method:'POST',body:{account_id:account,device_id:device},status:401});
  const enrolled=await call('/v1/auth/device/authorize',{method:'POST',body:{account_id:account,device_id:device,device_name:'Contract device'},token});
  assert.ok((await call('/v1/devices',{token})).devices.some(d=>d.device_id===device));
  await call('/v1/devices/'+device,{method:'DELETE',token:other});
  await call('/v1/auth/whoami',{token:enrolled.session.token});
  await call('/v1/devices/'+device,{method:'DELETE',token});
  await call('/v1/auth/whoami',{token:enrolled.session.token,status:401});
  await call('/v1/auth/session/revoke',{method:'POST',body:{session_id:b.session.session_id},token,status:404});
  await call('/v1/auth/logout',{method:'POST',body:{},token});await call('/v1/auth/whoami',{token,status:401});
  console.log(`${base}: PASS (${checks} protocol checks plus CAS/replay concurrency)`);
}
for(const base of process.argv.slice(2).length?process.argv.slice(2):['http://localhost:8787'])await contract(base.replace(/\/$/,''));
