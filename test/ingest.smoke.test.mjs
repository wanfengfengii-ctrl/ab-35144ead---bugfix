'use strict';
// End-to-end smoke test against real PostgreSQL: registration, chained
// ingestion, watermark advancement and paged reads.

import { test, before, after, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import { setupHarness, stopTestPostgres, truncateAll } from './helpers/harness.mjs';
import { registerDevice } from '../src/services/devices.mjs';
import { ingestBatch } from '../src/services/ingest.mjs';
import { readPage } from '../src/services/reads.mjs';
import { DeviceSigner, buildChain, prepareBatch } from './helpers/events.mjs';

let h;

before(async () => {
  h = await setupHarness();
});
after(async () => {
  await h.pool.end();
  await stopTestPostgres();
});
beforeEach(async () => {
  await truncateAll(h.pool);
});

const ingest = (deviceId, requestId, events) =>
  ingestBatch(h.pool, prepareBatch(deviceId, requestId, events));

test('register, ingest a correct chain, and read it back', async () => {
  const deviceId = 'dev-smoke';
  const signer = new DeviceSigner();
  await registerDevice(h.pool, { deviceId, publicKeyRaw: signer.publicRaw });
  const chain = buildChain(signer, deviceId, 5);
  const out = await ingest(deviceId, 'req-1', chain);
  assert.equal(out.highWatermark, 5);
  for (const e of out.events) assert.equal(e.state, 'visible');

  const page = await readPage(h.pool, h.serverKey, h.cfg, {
    deviceId, limit: 2, cursorToken: null, explicitAfterSequence: undefined,
  });
  assert.equal(page.viewHighWatermark, 5);
  assert.equal(page.events.length, 2);
  assert.equal(page.events[0].sequence, 1);
  assert.equal(page.events[1].sequence, 2);
  assert.ok(page.nextCursor);
  assert.equal(page.hasMore, true);

  const page2 = await readPage(h.pool, h.serverKey, h.cfg, {
    deviceId, limit: 2, cursorToken: page.nextCursor, explicitAfterSequence: undefined,
  });
  assert.equal(page2.events.length, 2);
  assert.equal(page2.events[0].sequence, 3);
  const page3 = await readPage(h.pool, h.serverKey, h.cfg, {
    deviceId, limit: 2, cursorToken: page2.nextCursor, explicitAfterSequence: undefined,
  });
  assert.equal(page3.events.length, 1);
  assert.equal(page3.events[0].sequence, 5);
  assert.equal(page3.nextCursor, null);
});

test('out-of-order arrival: gap keeps watermark low, fill promotes a run', async () => {
  const deviceId = 'dev-ooo';
  const signer = new DeviceSigner();
  await registerDevice(h.pool, { deviceId, publicKeyRaw: signer.publicRaw });
  const chain = buildChain(signer, deviceId, 4);

  // Arrive: 3,4,1,2
  let r = await ingest(deviceId, 'a', [chain[2], chain[3]]);
  assert.equal(r.highWatermark, 0);
  r = await ingest(deviceId, 'b', [chain[0]]);
  assert.equal(r.highWatermark, 1);
  r = await ingest(deviceId, 'c', [chain[1]]);
  assert.equal(r.highWatermark, 4);
});

test('identical retry returns the stored result and does not duplicate', async () => {
  const deviceId = 'dev-retry';
  const signer = new DeviceSigner();
  await registerDevice(h.pool, { deviceId, publicKeyRaw: signer.publicRaw });
  const ev = buildChain(signer, deviceId, 1)[0];
  const first = await ingest(deviceId, 'rid', [ev]);
  const second = await ingest(deviceId, 'rid', [ev]);
  assert.equal(second.replayed, true);
  assert.deepEqual(second.highWatermark, first.highWatermark);
  const { rows } = await h.pool.query(
    'SELECT count(*) FROM event_records WHERE device_id=$1',
    [deviceId]
  );
  assert.equal(Number(rows[0].count), 1);
});
