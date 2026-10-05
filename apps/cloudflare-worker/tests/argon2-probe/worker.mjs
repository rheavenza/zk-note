// Test-only Worker: no deployment configuration references this file.
import {initSync, hash_probe, verify_probe} from './pkg/zk_108_argon2_probe.js';
import wasm from './pkg/zk_108_argon2_probe_bg.wasm';
initSync({module: wasm});
let verifier;
export default {
  fetch(request) {
    const url = new URL(request.url);
    if (url.pathname === '/hash') {
      verifier = hash_probe(Number(url.searchParams.get('memory')), Number(url.searchParams.get('iterations')));
      return Response.json({ok: true, encoded_parameters: verifier.split('$')[3]});
    }
    if (url.pathname === '/verify') return Response.json({ok: verify_probe(verifier, true)});
    if (url.pathname === '/wrong') return Response.json({ok: !verify_probe(verifier, false)});
    if (url.pathname === '/malformed') return Response.json({ok: !verify_probe('malformed-verifier', true)});
    return Response.json({ok: true});
  }
};
