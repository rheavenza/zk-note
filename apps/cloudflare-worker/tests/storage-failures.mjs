import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import {fileURLToPath} from 'node:url';
import {createHash,randomUUID,randomBytes} from 'node:crypto';
import {Miniflare,convertV4MiniflareOptions} from 'miniflare';
const mf=new Miniflare(convertV4MiniflareOptions({modules:[{type:'ESModule',path:fileURLToPath(new URL('./fault-worker.mjs',import.meta.url))},{type:'ESModule',path:fileURLToPath(new URL('../build/index.js',import.meta.url))},{type:'CompiledWasm',path:fileURLToPath(new URL('../build/index_bg.wasm',import.meta.url))}],compatibilityDate:'2026-09-01',d1Databases:['DB'],r2Buckets:['BLOBS'],bindings:{MAX_BLOB_SIZE:'1048576',ACCOUNT_BLOB_QUOTA:'1024',WEBAUTHN_RP_ID:'localhost',WEBAUTHN_ORIGIN:'http://localhost:5173'},port:0}));
try {
  const db=await mf.getD1Database('DB'),bucket=await mf.getR2Bucket('BLOBS');
  const sql=await readFile(new URL('../migrations/0001_server.sql',import.meta.url),'utf8');
  let buffer='',statements=[];
  for(const line of sql.split('\n')) {
    if(line.trim().startsWith('--'))continue;
    buffer+=line+'\n';
    if((buffer.trimStart().startsWith('CREATE TRIGGER')?line.trim()==='END;':line.trimEnd().endsWith(';'))) {statements.push(buffer);buffer='';}
  }
  await db.batch(statements.map(sql=>db.prepare(sql)));
  const account=randomUUID(),token=randomBytes(32).toString('base64url');
  await db.prepare('INSERT INTO accounts(id) VALUES(?)').bind(account).run();
  await db.prepare('INSERT INTO sessions(session_id,account_id,token_hash) VALUES(?,?,?)').bind(randomUUID(),account,createHash('blake2s256').update(token).digest('base64url')).run();
  const call=async(path,method='GET',body,fault)=>{
    const r=await mf.dispatchFetch('http://worker'+path,{method,headers:{authorization:`Bearer ${token}`,...(fault?{'x-test-fault':fault}:{} )},body});
    await r.arrayBuffer();return r.status;
  };
  const counters=async()=>await db.prepare('SELECT blob_bytes,reserved_bytes FROM accounts WHERE id=?').bind(account).first();
  const count=async(table)=> (await db.prepare(`SELECT count(*) AS n FROM ${table}`).first()).n;
  const reconcile=async(fault)=>{await call('/__test/reconcile','GET',undefined,fault);};
  // R2 rejects before accepting; reservation compensation releases quota.
  assert.equal(await call('/v1/blobs/fail-before','PUT',randomBytes(32),'r2-put-before'),503);
  assert.deepEqual(await counters(),{blob_bytes:0,reserved_bytes:0});
  // R2 accepts bytes but response fails; a durable tombstone cleans the orphan.
  assert.equal(await call('/v1/blobs/fail-after','PUT',randomBytes(32),'r2-put-after'),503);
  assert.deepEqual(await counters(),{blob_bytes:0,reserved_bytes:0});
  assert.equal((await bucket.list()).objects.length,1);
  await reconcile();assert.equal((await bucket.list()).objects.length,0);
  // Delayed R2 completion after cancellation is eventually removed again.
  const canceled=await db.prepare("SELECT storage_key FROM blob_garbage WHERE storage_key LIKE '%/fail-after/%'").first();
  await bucket.put(canceled.storage_key,randomBytes(32));
  await db.prepare("UPDATE blob_garbage SET next_attempt=datetime('now','-1 day')").run();
  await reconcile();assert.equal((await bucket.list()).objects.length,0);
  // Publication failure: existing bytes stay readable, expired reservation restores quota.
  assert.equal(await call('/v1/blobs/stable','PUT',randomBytes(200)),201);
  await db.prepare("CREATE TRIGGER inject_publish_failure BEFORE INSERT ON blobs BEGIN SELECT RAISE(ABORT,'injected'); END;").run();
  assert.equal(await call('/v1/blobs/stable','PUT',randomBytes(300)),503);
  assert.deepEqual(await counters(),{blob_bytes:200,reserved_bytes:300});
  assert.equal(await call('/v1/blobs/stable'),200);
  await db.prepare('DROP TRIGGER inject_publish_failure').run();
  await db.prepare("UPDATE blob_uploads SET expires_at=datetime('now','-1 hour')").run();
  await reconcile();assert.deepEqual(await counters(),{blob_bytes:200,reserved_bytes:0});
  // Lost D1 response after publication must not delete the committed R2 bytes.
  assert.equal(await call('/v1/blobs/committed','PUT',randomBytes(100),'d1-publish-after'),503);
  assert.equal(await call('/v1/blobs/committed'),200);
  assert.deepEqual(await counters(),{blob_bytes:300,reserved_bytes:0});
  // Concurrent quota reservations: only available capacity can be accepted.
  const statuses=await Promise.all(Array.from({length:8},(_,i)=>call('/v1/blobs/quota-'+i,'PUT',randomBytes(200))));
  assert.equal(statuses.filter(s=>s===201).length,3);assert.equal(statuses.filter(s=>s===413).length,5);
  assert.deepEqual(await counters(),{blob_bytes:900,reserved_bytes:0});
  // Deletion release and cleanup are atomic; R2 deletion failure cannot leak quota.
  assert.equal(await call('/v1/blobs/stable','DELETE'),200);
  await reconcile('r2-delete');assert.deepEqual(await counters(),{blob_bytes:700,reserved_bytes:0});
  assert.ok(await count('blob_garbage')>0);await reconcile();
  assert.equal(await call('/v1/blobs/stable'),404);
  // D1 trigger failure rolls back history, object, sequence and idempotency together.
  const object=randomUUID(),wrapped={nonce:randomBytes(24).toString('base64'),ciphertext:randomBytes(48).toString('base64')};
  const mutation={mutation_id:randomUUID(),object_id:object,expected_revision:0,object_kind:1,is_deleted:false,envelope:{envelope_version:1,object_id:object,object_kind:1,wrapped_key:wrapped,payload:wrapped}};
  const push=()=>call('/v1/sync/push','POST',JSON.stringify(mutation));
  assert.equal(await push(),200);mutation.expected_revision=1;mutation.mutation_id=randomUUID();
  await db.prepare("CREATE TRIGGER inject_history_failure BEFORE INSERT ON object_history BEGIN SELECT RAISE(ABORT,'injected'); END;").run();
  assert.equal(await push(),500);assert.equal(await count('object_history'),0);assert.equal(await count('processed_mutations'),1);assert.equal(await count('mutation_attempts'),0);
  assert.equal((await db.prepare('SELECT current_seq FROM account_sequences WHERE account_id=?').bind(account).first()).current_seq,1);
  await db.prepare('DROP TRIGGER inject_history_failure').run();assert.equal(await push(),200);assert.equal(await count('object_history'),1);
  // Pull planning must use the account/sequence index.
  const plan=await db.prepare('EXPLAIN QUERY PLAN SELECT * FROM encrypted_objects WHERE account_id=? AND server_seq>? ORDER BY server_seq LIMIT 50').bind(account,0).all();
  assert.ok(plan.results.some(r=>r.detail.includes('encrypted_objects_account_seq_idx')));
  console.log('PASS: local D1/R2 fault injection, reconciliation, concurrent quota and rollback tests');
} finally {await mf.dispose();}
