// Test-only entrypoint. Never referenced by wrangler.toml or deployment scripts.
import Worker from '../build/index.js';
function wrap(target, overrides) {
  return new Proxy(target,{get(object,key){
    if(Object.hasOwn(overrides,key))return overrides[key];
    const value=Reflect.get(object,key,object);
    return typeof value==='function' && key!=='constructor'?value.bind(object):value;
  }});
}
export default {
  async fetch(req,env,ctx) {
    const fault=req.headers.get('x-test-fault');
    if(fault==='r2-put-before'||fault==='r2-put-after') {
      const bucket=env.BLOBS;
      env={...env,BLOBS:wrap(bucket,{put:async(...args)=>{
        if(fault==='r2-put-after')await bucket.put(...args);
        throw Error('Injected R2 failure');
      }})};
    }
    if(fault==='d1-publish-after') {
      const db=env.DB;
      env={...env,DB:wrap(db,{batch:async(...args)=>{await db.batch(...args);throw Error('Injected lost D1 response');}})};
    }
    if(fault==='r2-delete') {
      env={...env,BLOBS:wrap(env.BLOBS,{delete:async()=>{throw Error('Injected R2 delete failure');}})};
    }
    const app=new Worker(ctx,env);
    if(new URL(req.url).pathname==='/__test/reconcile') {
      await app.scheduled({scheduledTime:Date.now(),cron:'0 * * * *',noRetry() {}});
      return new Response('ok');
    }
    return app.fetch(req);
  }
};
