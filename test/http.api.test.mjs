'use strict';
// HTTP-level tests: boots the REAL server on an ephemeral port and exercises
// the versioned API over TCP, including auth, body limits and structured
// errors. A second server instance shares the same database to prove
// instance-agnostic behavior.

import { test, before, after, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import { setupHarness, stopTestPostgres, truncateAll } from './helpers/harness.mjs';
import { createServer } from '../src/http/server.mjs';
import { registerDevice } from '../src/services/devices.mjs';
import { DeviceSigner, buildChain } from './helpers/events.mjs';

let h, server1, server2, base1, base2;

async function listen(server) {
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  const { port } = server.address();
  return `http://127.0.0.1:${port}`;
}

before(async () => {
  h = await setupHarness();
  server1 = createServer({ pool: h.pool, cfg: h.cfg, serverKey: h.serverKey, log: { info() {}, error() {}, warn() {}, debug() {} } });
  server2 = createServer({ pool: h.pool, cfg: h.cfg, serverKey: h.serverKey, log: { info() {}, error() {}, warn() {}, debug() {} } });
  base1 = await listen(server1);
  base2 = await listen(server2);
});
after(async () => {
  await new Promise((r) => server1.close(r));
  await new Promise((r) => server2.close(r));
  await h.pool.end();
  await stopTestPostgres();
});
beforeEach(async () => { await truncateAll(h.pool); });

async function call(base, method, path, { body, token, admin, raw, contentType } = {}) {
  const headers = {};
  if (body !== undefined || raw !== undefined) headers['content-type'] = contentType || 'application/json';
  if (token) headers['authorization'] = `Bearer ${token}`;
  if (admin) headers['x-admin-token'] = 'test-admin';
  const res = await fetch(base + path, {
    method,
    headers,
    body: raw ?? (body !== undefined ? JSON.stringify(body) : undefined),
  });
  const json = res.status === 204 ? null : await res.json().catch(() => null);
  return { status: res.status, json, headers: res.headers };
}

test('health checks do not need external network', async () => {
  const a = await call(base1, 'GET', '/healthz');
  assert.equal(a.status, 200);
  const b = await call(base1, 'GET', '/healthz/ready');
  assert.equal(b.status, 200);
});

test('register then ingest then read over HTTP', async () => {
  const id = 'dev-http';
  const signer = new DeviceSigner();
  const reg = await call(base1, 'POST', '/v1/devices', {
    body: { deviceId: id, publicKey: signer.publicB64Url },
  });
  assert.equal(reg.status, 201);
  assert.equal(reg.json.keyVersion, 1);

  const chain = buildChain(signer, id, 3);
  const ing = await call(base1, 'POST', `/v1/devices/${id}/ingest`, {
    body: { requestId: 'req-http', events: chain },
  });
  assert.equal(ing.status, 200);
  assert.equal(ing.json.highWatermark, 3);

  const page = await call(base2, 'GET', `/v1/devices/${id}/events?limit=2`);
  assert.equal(page.status, 200);
  assert.equal(page.json.events.length, 2);
  assert.ok(page.json.nextCursor);

  const page2 = await call(base2, 'GET', `/v1/devices/${id}/events?limit=2&cursor=${encodeURIComponent(page.json.nextCursor)}`);
  assert.equal(page2.json.events.length, 1);
});

test('identical retry across instances returns the stored result', async () => {
  const id = 'dev-cross';
  const signer = new DeviceSigner();
  await registerDevice(h.pool, { deviceId: id, publicKeyRaw: signer.publicRaw });
  const ev = buildChain(signer, id, 1)[0];
  const payload = { requestId: 'cross-rid', events: [ev] };
  const a = await call(base1, 'POST', `/v1/devices/${id}/ingest`, { body: payload });
  const b = await call(base2, 'POST', `/v1/devices/${id}/ingest`, { body: payload });
  assert.equal(a.status, 200);
  assert.equal(b.status, 200);
  assert.equal(b.json.replayed, true);
});

test('admin endpoints require configured credentials', async () => {
  const id = 'dev-admin';
  const signer = new DeviceSigner();
  await registerDevice(h.pool, { deviceId: id, publicKeyRaw: signer.publicRaw });
  const body = {
    deviceId: id, commandId: 'rot', keyVersion: 2,
    effectiveSequence: 5, expectedControlRevision: 1,
    publicKey: new DeviceSigner().publicB64Url,
  };
  const noCreds = await call(base1, 'POST', `/v1/devices/${id}/keys/rotate`, { body });
  assert.equal(noCreds.status, 401);
  const wrong = await call(base1, 'POST', `/v1/devices/${id}/keys/rotate`, { body, token: 'nope' });
  assert.equal(wrong.status, 401);
  const ok = await call(base1, 'POST', `/v1/devices/${id}/keys/rotate`, { body, admin: true });
  assert.equal(ok.status, 200);
  assert.equal(ok.json.controlRevision, 2);
});

test('structured error shape for validation failures', async () => {
  const r = await call(base1, 'POST', '/v1/devices', { body: { deviceId: '' } });
  assert.equal(r.status, 400);
  assert.equal(r.json.error.code, 'VALIDATION_ERROR');
  assert.equal(typeof r.json.error.message, 'string');
});

test('unknown route is 404 JSON', async () => {
  const r = await call(base1, 'GET', '/v1/nope');
  assert.equal(r.status, 404);
  assert.equal(r.json.error.code, 'NOT_FOUND');
});

test('request body size limit returns 413', async () => {
  const huge = 'x'.repeat(h.cfg.maxBodyBytes + 10);
  const r = await call(base1, 'POST', '/v1/devices', { raw: huge, contentType: 'application/json' });
  assert.equal(r.status, 413);
  assert.equal(r.json.error.code, 'PAYLOAD_TOO_LARGE');
});

test('bad content type and malformed JSON are 400', async () => {
  const r1 = await call(base1, 'POST', '/v1/devices', { raw: '{}', contentType: 'text/plain' });
  assert.equal(r1.status, 400);
  const r2 = await call(base1, 'POST', '/v1/devices', { raw: '{not json', contentType: 'application/json' });
  assert.equal(r2.status, 400);
});

test('device state and conflict listing endpoints', async () => {
  const id = 'dev-state-http';
  const signer = new DeviceSigner();
  await call(base1, 'POST', '/v1/devices', { body: { deviceId: id, publicKey: signer.publicB64Url } });
  const state = await call(base1, 'GET', `/v1/devices/${id}`);
  assert.equal(state.status, 200);
  assert.equal(state.json.highWatermark, 0);
  assert.equal(state.json.keys.length, 1);
  const conf = await call(base1, 'GET', `/v1/devices/${id}/conflicts`);
  assert.equal(conf.status, 200);
  assert.deepEqual(conf.json.conflicts, []);
});

test('wait long-polls and returns new events', async () => {
  const id = 'dev-http-wait';
  const signer = new DeviceSigner();
  await call(base1, 'POST', '/v1/devices', { body: { deviceId: id, publicKey: signer.publicB64Url } });
  const p = call(base1, 'GET', `/v1/devices/${id}/wait?afterSequence=0`);
  setTimeout(async () => {
    await call(base2, 'POST', `/v1/devices/${id}/ingest`, {
      body: { requestId: 'w', events: buildChain(signer, id, 1) },
    });
  }, 200);
  const r = await p;
  assert.equal(r.status, 200);
  assert.equal(r.json.timeout, false);
  assert.equal(r.json.events.length, 1);
});
