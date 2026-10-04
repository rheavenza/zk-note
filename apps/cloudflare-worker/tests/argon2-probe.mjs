// Local workerd CPU evidence for ZK-108. Linux /proc CPU accounting, no real secrets.
import assert from 'node:assert/strict';
import {readFile, readdir} from 'node:fs/promises';
import {execFileSync} from 'node:child_process';
import {performance} from 'node:perf_hooks';
import {fileURLToPath} from 'node:url';
import {Miniflare, convertV4MiniflareOptions} from 'miniflare';
const hz = Number(execFileSync('getconf', ['CLK_TCK'], {encoding:'utf8'}).trim());
assert.ok(Number.isFinite(hz) && hz > 0, 'valid Linux CPU-accounting frequency is required');
async function processStat(pid) {
  const raw = await readFile(`/proc/${pid}/stat`, 'utf8');
  const fields = raw.slice(raw.lastIndexOf(')') + 2).split(' ');
  return {ppid: Number(fields[1]), ticks: Number(fields[11]) + Number(fields[12])};
}
async function workerPid() {
  const candidates = [];
  for (const pid of await readdir('/proc')) {
    if (!/^\d+$/.test(pid)) continue;
    try {
      const command = await readFile(`/proc/${pid}/comm`, 'utf8');
      if (command.trim() !== 'workerd') continue;
      let parent = Number(pid);
      while (parent > 1 && parent !== process.pid) parent = (await processStat(parent)).ppid;
      if (parent === process.pid) candidates.push(Number(pid));
    } catch { /* Process may have exited. */ }
  }
  assert.equal(candidates.length, 1, 'one isolated workerd child is required');
  return candidates[0];
}
const mf = new Miniflare(convertV4MiniflareOptions({
  modules: [
    {type:'ESModule', path:fileURLToPath(new URL('./argon2-probe/worker.mjs', import.meta.url))},
    {type:'ESModule', path:fileURLToPath(new URL('./argon2-probe/pkg/zk_108_argon2_probe.js', import.meta.url))},
    {type:'CompiledWasm', path:fileURLToPath(new URL('./argon2-probe/pkg/zk_108_argon2_probe_bg.wasm', import.meta.url))},
  ], compatibilityDate:'2026-09-01', port:0,
}));
try {
  await mf.dispatchFetch('http://probe/health');
  const pid = await workerPid();
  const baselineStart = await processStat(pid);
  for (let i = 0; i < 18; i++) await (await mf.dispatchFetch('http://probe/health')).json();
  console.log(JSON.stringify({kind:'baseline', requests:18, cpu_ms:((await processStat(pid)).ticks-baselineStart.ticks)*1000/hz, clock_ticks_per_second:hz}));
  for (const [memory, iterations] of [[47104,1],[19456,2],[12288,3],[9216,4],[7168,5]]) {
    const configStart = await processStat(pid);
    for (let sample = 0; sample < 6; sample++) {
      const result = {memory_kib:memory, iterations, parallelism:1, sample};
      for (const phase of ['hash', 'verify', 'wrong']) {
        const before = await processStat(pid), start = performance.now();
        const response = await mf.dispatchFetch(`http://probe/${phase}?memory=${memory}&iterations=${iterations}`);
        assert.equal(response.status, 200);
        assert.equal((await response.json()).ok, true);
        result[`${phase}_wall_ms`] = performance.now() - start;
        result[`${phase}_cpu_ms`] = ((await processStat(pid)).ticks - before.ticks) * 1000 / hz;
      }
      console.log(JSON.stringify(result));
    }
    const cpu_ms = ((await processStat(pid)).ticks-configStart.ticks)*1000/hz;
    console.log(JSON.stringify({kind:'configuration_summary', memory_kib:memory, iterations, parallelism:1, operations:18, cpu_ms, mean_cpu_ms:cpu_ms/18}));
  }
  assert.equal((await (await mf.dispatchFetch('http://probe/malformed')).json()).ok, true);
} finally { await mf.dispose(); }
