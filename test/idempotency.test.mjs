'use strict';
// Idempotency: identical retries collapse; same requestId with different
// canonical content is a stable conflict; invalid batches leave no data.

import { test, before, after, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import { setupHarness, stopTestPostgres, truncateAll } from './helpers/harness.mjs';
import { registerDevice } from '../src/services/devices.mjs';
import { ingestBatch } from '../src/services/ingest.mjs';
import { DeviceSigner, buildChain, prepareBatch } from './helpers/events.mjs';
import { ApiError } from '../src/errors.mjs';

let h;
before(async () => { h = await setupHarness(); });
after(async () => { await h.pool.end(); await stopTestPostgres(); });
beforeEach(async () => { await truncateAll(h.pool); });

const ingest = (deviceId, requestId, events) =>
  ingestBatch(h.pool, prepareBatch(deviceId, requestId, events));

async function newDevice(id) {
  const signer = new DeviceSigner();
  await registerDevice(h.pool, { deviceId: id, publicKeyRaw: signer.publicRaw });
  return signer;
}

test('same requestId with different content returns a stable IDEMPOTENCY_CONFLICT', async () => {
  const signer = await newDevice('dev-ic');
  const chain = buildChain(signer, 'dev-ic', 2);
  const first = await ingest('dev-ic', 'same-rid', [chain[0]]);
  assert.equal(first.highWatermark, 1);

  await assert.rejects(
    () => ingest('dev-ic', 'same-rid', [chain[1]]),
    (e) => e instanceof ApiError && e.code === 'IDEMPOTENCY_CONFLICT'
  );
  // Repeating the divergent call gives the same stable error.
  await assert.rejects(
    () => ingest('dev-ic', 'same-rid', [chain[1]]),
    (e) => e instanceof ApiError && e.code === 'IDEMPOTENCY_CONFLICT'
  );
  // The second content never produced an event.
  const { rows } = await h.pool.query(
    'SELECT sequence FROM event_records WHERE device_id=$1 ORDER BY sequence',
    ['dev-ic']
  );
  assert.deepEqual(rows.map((r) => Number(r.sequence)), [1]);
});

test('field reordering and payload key reordering are still identical retries', async () => {
  const signer = await newDevice('dev-reorder');
  const ev = buildChain(signer, 'dev-reorder', 1)[0];
  await ingest('dev-reorder', 'rid-reorder', [ev]);

  // Same semantic content, fields in different order at all levels.
  const reordered = {
    signature: ev.signature,
    payload: { text: ev.payload.text, n: ev.payload.n },
    prevDigest: ev.prevDigest,
    keyVersion: ev.keyVersion,
    occurredAt: ev.occurredAt,
    eventId: ev.eventId,
    sequence: ev.sequence,
    deviceId: ev.deviceId,
  };
  const again = await ingest('dev-reorder', 'rid-reorder', [reordered]);
  assert.equal(again.replayed, true);
});

test('batch fails atomically: one invalid signature leaves no events', async () => {
  const signer = await newDevice('dev-atomic');
  const chain = buildChain(signer, 'dev-atomic', 3);
  const tampered = { ...chain[2], signature: chain[0].signature };
  await assert.rejects(
    () => ingest('dev-atomic', 'bad-batch', [chain[0], chain[1], tampered]),
    (e) => e.code === 'SIGNATURE_INVALID'
  );
  const { rows } = await h.pool.query(
    'SELECT count(*)::int AS n FROM event_records WHERE device_id=$1',
    ['dev-atomic']
  );
  assert.equal(rows[0].n, 0);
  const { rows: reqRows } = await h.pool.query(
    'SELECT count(*)::int AS n FROM ingest_requests WHERE request_id=$1',
    ['bad-batch']
  );
  assert.equal(reqRows[0].n, 0);
});

test('batch fails atomically on an unknown key version', async () => {
  const signer = await newDevice('dev-kv');
  const chain = buildChain(signer, 'dev-kv', 1);
  chain[0].keyVersion = 9;
  // Re-sign with the existing key but claim generation 9.
  const { buildEnvelope } = await import('../src/crypto/envelope.js');
  const { signBytes, encodeB64Url } = await import('../src/crypto/keys.js');
  const bytes = buildEnvelope(chain[0]).bytes;
  chain[0].signature = encodeB64Url(signBytes(signer.privateKey, bytes));
  await assert.rejects(() => ingest('dev-kv', 'kv-batch', chain), (e) => e.code === 'UNKNOWN_KEY_VERSION');
});

test('agent retry after commit-before-response: concurrent identical submissions produce one event', async () => {
  const signer = await newDevice('dev-conn-retry');
  const ev = buildChain(signer, 'dev-conn-retry', 1)[0];
  const [a, b] = await Promise.all([
    ingest('dev-conn-retry', 'rid-conn', [ev]),
    ingest('dev-conn-retry', 'rid-conn', [ev]),
  ]);
  const states = [a, b].map((r) => (r.replayed ? 'replayed' : 'first'));
  assert.deepEqual(states.sort(), ['first', 'replayed']);
  const { rows } = await h.pool.query(
    'SELECT count(*)::int AS n FROM event_records WHERE device_id=$1',
    ['dev-conn-retry']
  );
  assert.equal(rows[0].n, 1);
});

test('batch size bounds are enforced', async () => {
  const signer = await newDevice('dev-bounds');
  assert.throws(() => prepareBatch('dev-bounds', 'r', []), (e) => e.code === 'VALIDATION_ERROR');
  const big = buildChain(signer, 'dev-bounds', 501);
  assert.throws(() => prepareBatch('dev-bounds', 'r', big), (e) => e.code === 'VALIDATION_ERROR');
});
