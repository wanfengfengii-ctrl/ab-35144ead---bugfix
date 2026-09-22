'use strict';
// Local equivalent of the deployed acceptance topology, used to validate the
// verify/verify.mjs acceptance service without Docker: real PostgreSQL, two
// independent HTTP server instances behind a tiny round-robin TCP proxy, and
// a periodic background compaction loop. The acceptance script runs as a real
// subprocess with only BASE_URL + credentials in its environment.

import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { setupHarness, stopTestPostgres } from './helpers/harness.mjs';
import { createServer } from '../src/http/server.mjs';
import { createPool } from '../src/db/pool.mjs';
import { compactionPass } from '../src/services/compaction.mjs';

const here = dirname(fileURLToPath(import.meta.url));
const root = join(here, '..');
const silent = { info() {}, error() {}, warn() {}, debug() {} };

function listen(server) {
  return new Promise((resolve) => server.listen(0, '127.0.0.1', () => resolve(server.address().port)));
}

// Minimal connection-level round-robin reverse proxy supporting bodies and
// long-lived responses (the /wait long poll).
function roundRobin(targets) {
  let i = 0;
  return http.createServer((req, res) => {
    const target = targets[i++ % targets.length];
    const proxyReq = http.request(
      { host: '127.0.0.1', port: target, path: req.url, method: req.method, headers: req.headers },
      (proxyRes) => {
        res.writeHead(proxyRes.statusCode, proxyRes.headers);
        proxyRes.pipe(res);
      }
    );
    proxyReq.on('error', (e) => {
      if (!res.headersSent) res.writeHead(502).end(JSON.stringify({ error: { code: 'BAD_GATEWAY', message: e.message } }));
      else res.end();
    });
    req.pipe(proxyReq);
  });
}

test('verify/verify.mjs acceptance run passes against two instances + worker', async (t) => {
  const overrides = {
    adminToken: 'acceptance-admin-token',
    checkpointKeySeed: Buffer.from('shared-prod-checkpoint-seed-32!!'),
    compaction: { retentionEvents: 10, viewTtlMs: 600_000, intervalMs: 300, minEvents: 5 },
  };
  const h = await setupHarness(overrides);

  const apiA = createServer({ pool: h.pool, cfg: h.cfg, serverKey: h.serverKey, log: silent });
  const apiB = createServer({ pool: h.pool, cfg: h.cfg, serverKey: h.serverKey, log: silent });
  const portA = await listen(apiA);
  const portB = await listen(apiB);

  const proxy = roundRobin([portA, portB]);
  const proxyPort = await listen(proxy);

  // Background compaction loop (stands in for the worker container).
  let stopping = false;
  const workerLoop = async () => {
    while (!stopping) {
      try {
        await compactionPass(h.pool, h.serverKey, h.cfg, silent);
      } catch {
        /* retried on the next tick */
      }
      await new Promise((r) => setTimeout(r, 300));
    }
  };
  const workerDone = workerLoop();

  let result;
  try {
    result = await new Promise((resolve) => {
      const child = spawn(process.execPath, [join(root, 'verify', 'verify.mjs')], {
        env: {
          ...process.env,
          BASE_URL: `http://127.0.0.1:${proxyPort}`,
          ADMIN_TOKEN: 'acceptance-admin-token',
          CHECKPOINT_SIGNING_KEY: overrides.checkpointKeySeed.toString('base64url'),
          PATH: process.env.PATH,
        },
      });
      let stdout = '';
      let stderr = '';
      child.stdout.on('data', (d) => { stdout += d; });
      child.stderr.on('data', (d) => { stderr += d; });
      child.on('exit', (code) => resolve({ code, stdout, stderr }));
    });
  } finally {
    stopping = true;
    await workerDone;
    await new Promise((r) => proxy.close(r));
    await new Promise((r) => apiA.close(r));
    await new Promise((r) => apiB.close(r));
    await h.pool.end();
    await stopTestPostgres();
  }

  console.log(result.stdout);
  if (result.stderr.trim()) console.log('STDERR:', result.stderr);

  assert.equal(result.code, 0, `verify exited ${result.code}\n${result.stdout}\n${result.stderr}`);
  assert.match(result.stdout, /ACCEPTANCE PASSED/);
  assert.match(result.stdout, /both API instances observed behind proxy/);
}, 120_000);
