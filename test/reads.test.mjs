'use strict';
// Fixed-view pagination, cursor integrity and long-poll waiting.

import { test, before, after, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import { setupHarness, stopTestPostgres, truncateAll } from './helpers/harness.mjs';
import { registerDevice } from '../src/services/devices.mjs';
import { ingestBatch } from '../src/services/ingest.mjs';
import { readPage, waitForEvents } from '../src/services/reads.mjs';
import { DeviceSigner, buildChain, prepareBatch } from './helpers/events.mjs';
import { signCursor } from '../src/crypto/checkpoint.mjs';
import { ApiError } from '../src/errors.mjs';

let h;
before(async () => { h = await setupHarness(); });
after(async () => { await h.pool.end(); await stopTestPostgres(); });
beforeEach(async () => { await truncateAll(h.pool); });

const ingest = (id, rid, evs) => ingestBatch(h.pool, prepareBatch(id, rid, evs));
const readFirst = (id, limit) =>
  readPage(h.pool, h.serverKey, h.cfg, { deviceId: id, limit, cursorToken: null, explicitAfterSequence: undefined });

test('view is fixed: commits after the first page never mix in', async () => {
  const id = 'dev-view';
  const signer = new DeviceSigner();
  await registerDevice(h.pool, { deviceId: id, publicKeyRaw: signer.publicRaw });
  await ingest(id, 'a', buildChain(signer, id, 3));

  const first = await readFirst(id, 1);
  assert.equal(first.viewHighWatermark, 3);
  assert.equal(first.events.length, 1);
  const { viewId } = first;

  // New commits arrive while the client pages through the old view.
  await ingest(id, 'b', buildChain(signer, id, 5).slice(3));

  const second = await readPage(h.pool, h.serverKey, h.cfg, {
    deviceId: id, limit: 5, cursorToken: first.nextCursor, explicitAfterSequence: undefined,
  });
  assert.equal(second.viewId, viewId);
  assert.equal(second.viewHighWatermark, 3);
  assert.deepEqual(second.events.map((e) => e.sequence), [2, 3]);
  assert.equal(second.nextCursor, null);

  // A fresh first page observes the new watermark.
  const fresh = await readFirst(id, 10);
  assert.equal(fresh.viewHighWatermark, 5);
});

test('tampered, cross-device and contradictory cursors are rejected', async () => {
  const a = 'dev-cur-a';
  const b = 'dev-cur-b';
  const s1 = new DeviceSigner();
  const s2 = new DeviceSigner();
  await registerDevice(h.pool, { deviceId: a, publicKeyRaw: s1.publicRaw });
  await registerDevice(h.pool, { deviceId: b, publicKeyRaw: s2.publicRaw });
  await ingest(a, 'a', buildChain(s1, a, 2));
  await ingest(b, 'b', buildChain(s2, b, 2));

  const page = await readFirst(a, 1);
  const cursor = page.nextCursor;

  // Tamper with the body.
  const [body, sig] = cursor.split('.');
  const tampered = body.replace(/.$/, (c) => (c === 'A' ? 'B' : 'A')) + '.' + sig;
  await assert.rejects(
    () => readPage(h.pool, h.serverKey, h.cfg, { deviceId: a, cursorToken: tampered, explicitAfterSequence: undefined }),
    (e) => e.status === 400
  );

  // Forge a cursor for another view/device but signed by nobody valid.
  const forged = signCursor(h.serverKey, { viewId: page.viewId, deviceId: b, afterSequence: 0 });
  await assert.rejects(
    () => readPage(h.pool, h.serverKey, h.cfg, { deviceId: a, cursorToken: forged, explicitAfterSequence: undefined }),
    (e) => e.status === 400
  );

  // Correctly signed cursor for device b bound to a's (nonexistent there) view.
  const cross = signCursor(h.serverKey, { viewId: page.viewId, deviceId: b, afterSequence: 0 });
  await assert.rejects(
    () => readPage(h.pool, h.serverKey, h.cfg, { deviceId: b, cursorToken: cross, explicitAfterSequence: undefined }),
    (e) => e.status === 410 || e.status === 400
  );

  // afterSequence contradicting the cursor position.
  await assert.rejects(
    () => readPage(h.pool, h.serverKey, h.cfg, { deviceId: a, cursorToken: cursor, explicitAfterSequence: 99 }),
    (e) => e.status === 400
  );

  // Valid continuation works.
  const ok = await readPage(h.pool, h.serverKey, h.cfg, { deviceId: a, cursorToken: cursor, explicitAfterSequence: undefined });
  assert.equal(ok.events[0].sequence, 2);
});

test('wait returns immediately when events already exist', async () => {
  const id = 'dev-wait-now';
  const signer = new DeviceSigner();
  await registerDevice(h.pool, { deviceId: id, publicKeyRaw: signer.publicRaw });
  await ingest(id, 'a', buildChain(signer, id, 2));
  const ac = new AbortController();
  const t0 = Date.now();
  const res = await waitForEvents(h.pool, h.cfg, { deviceId: id, afterSequence: 0, limit: 10, signal: ac.signal });
  assert.ok(Date.now() - t0 < 1000);
  assert.equal(res.events.length, 2);
  assert.equal(res.timeout, false);
});

test('wait wakes on a new commit and does not miss the notification', async () => {
  const id = 'dev-wait-later';
  const signer = new DeviceSigner();
  await registerDevice(h.pool, { deviceId: id, publicKeyRaw: signer.publicRaw });

  const ac = new AbortController();
  const waiter = waitForEvents(h.pool, h.cfg, {
    deviceId: id, afterSequence: 0, limit: 10, signal: ac.signal,
  });
  // Commit after the waiter has begun listening (small delay to ensure LISTEN).
  setTimeout(() => ingest(id, 'a', buildChain(signer, id, 1)), 150);
  const res = await waiter;
  assert.equal(res.timeout, false);
  assert.equal(res.events.length, 1);
  assert.equal(res.highWatermark, 1);
});

test('wait timeout returns an empty result', async () => {
  const id = 'dev-wait-timeout';
  const signer = new DeviceSigner();
  await registerDevice(h.pool, { deviceId: id, publicKeyRaw: signer.publicRaw });
  const cfg = { ...h.cfg, waitTimeoutMs: 400 };
  const ac = new AbortController();
  const res = await waitForEvents(h.pool, cfg, { deviceId: id, afterSequence: 0, limit: 10, signal: ac.signal });
  assert.equal(res.timeout, true);
  assert.equal(res.events.length, 0);
});

test('aborting the wait releases it (client disconnect)', async () => {
  const id = 'dev-wait-abort';
  const signer = new DeviceSigner();
  await registerDevice(h.pool, { deviceId: id, publicKeyRaw: signer.publicRaw });
  const ac = new AbortController();
  const p = waitForEvents(h.pool, h.cfg, { deviceId: id, afterSequence: 0, limit: 10, signal: ac.signal });
  setTimeout(() => ac.abort(), 100);
  await assert.rejects(p, (e) => e.code === 'ABORTED');
  // Pool stays usable after an aborted wait.
  const { rows } = await h.pool.query('SELECT 1 AS ok');
  assert.equal(rows[0].ok, 1);
});
