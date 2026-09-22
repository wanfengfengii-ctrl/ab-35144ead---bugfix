'use strict';
// Key rotation: generation boundaries, effectiveSequence strictly beyond the
// contiguous watermark, expectedControlRevision guarding, idempotent
// commandId, overlap/duplicate/boundary rejections, and correct acceptance of
// old-key backfill after rotation.

import { test, before, after, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import { setupHarness, stopTestPostgres, truncateAll } from './helpers/harness.mjs';
import { registerDevice, rotateKey, getDevice } from '../src/services/devices.mjs';
import { ingestBatch } from '../src/services/ingest.mjs';
import { DeviceSigner, buildChain, prepareBatch } from './helpers/events.mjs';
import { buildEnvelope } from '../src/crypto/envelope.js';
import { signBytes, encodeB64Url } from '../src/crypto/keys.js';
import { ApiError } from '../src/errors.mjs';

let h;
before(async () => { h = await setupHarness(); });
after(async () => { await h.pool.end(); await stopTestPostgres(); });
beforeEach(async () => { await truncateAll(h.pool); });

const ingest = (deviceId, requestId, events) =>
  ingestBatch(h.pool, prepareBatch(deviceId, requestId, events));

/** Sign one event with an explicit signer and keyVersion. */
function signEvent(signer, fields) {
  const { bytes } = buildEnvelope(fields);
  return { ...fields, signature: encodeB64Url(signBytes(signer.privateKey, bytes)) };
}

test('events below/above the boundary require the right generation', async () => {
  const id = 'dev-rot';
  const k1 = new DeviceSigner();
  const k2 = new DeviceSigner();
  await registerDevice(h.pool, { deviceId: id, publicKeyRaw: k1.publicRaw });

  const rot = await rotateKey(h.pool, {
    deviceId: id, commandId: 'rot-1', keyVersion: 2,
    effectiveSequence: 5, expectedControlRevision: 1, publicKeyRaw: k2.publicRaw,
  });
  assert.equal(rot.controlRevision, 2);

  // seq 1..4 signed by k1, correctly chained.
  const chain1 = buildChain(k1, id, 4, { keyVersion: 1 });
  const r1 = await ingest(id, 'old-part', chain1);
  assert.equal(r1.highWatermark, 4);

  // seq 5 signed by k2, prevDigest = digest of k1-signed seq 4.
  const prev4 = buildEnvelope(chain1[3]).digest;
  const ev5 = signEvent(k2, {
    deviceId: id, sequence: 5, eventId: 'e5', occurredAt: '2026-02-01T00:00:00Z',
    keyVersion: 2, prevDigest: prev4, payload: { gen: 2 },
  });
  const r2 = await ingest(id, 'new-part', [ev5]);
  assert.equal(r2.highWatermark, 5);

  // Old key cannot sign at/after the boundary.
  const fake5 = signEvent(k1, {
    deviceId: id, sequence: 5, eventId: 'e5b', occurredAt: '2026-02-01T00:00:01Z',
    keyVersion: 1, prevDigest: prev4, payload: { gen: 1 },
  });
  await assert.rejects(() => ingest(id, 'old-at-5', [fake5]), (e) => e.code === 'KEY_GENERATION_MISMATCH');

  // New key cannot sign below the boundary (out-of-order backfill protection).
  const fake3 = signEvent(k2, {
    deviceId: id, sequence: 3, eventId: 'e3b', occurredAt: '2026-01-01T00:00:00Z',
    keyVersion: 2, prevDigest: '0'.repeat(64), payload: {},
  });
  await assert.rejects(() => ingest(id, 'new-at-3', [fake3]), (e) => e.code === 'KEY_GENERATION_MISMATCH');
});

test('out-of-order old events still validate after the key has rotated', async () => {
  const id = 'dev-backfill';
  const k1 = new DeviceSigner();
  const k2 = new DeviceSigner();
  await registerDevice(h.pool, { deviceId: id, publicKeyRaw: k1.publicRaw });
  await rotateKey(h.pool, {
    deviceId: id, commandId: 'rot', keyVersion: 2,
    effectiveSequence: 10, expectedControlRevision: 1, publicKeyRaw: k2.publicRaw,
  });
  // Only seq 1 exists; seq 2..9 arrive much later, after rotation, still k1.
  const chain = buildChain(k1, id, 9, { keyVersion: 1 });
  const first = await ingest(id, 's1', [chain[0]]);
  assert.equal(first.highWatermark, 1);
  const rest = await ingest(id, 's-rest', chain.slice(1));
  assert.equal(rest.highWatermark, 9);
});

test('expectedControlRevision mismatch is rejected', async () => {
  const id = 'dev-rev';
  const k1 = new DeviceSigner();
  const k2 = new DeviceSigner();
  await registerDevice(h.pool, { deviceId: id, publicKeyRaw: k1.publicRaw });
  await rotateKey(h.pool, {
    deviceId: id, commandId: 'rot-a', keyVersion: 2,
    effectiveSequence: 3, expectedControlRevision: 1, publicKeyRaw: k2.publicRaw,
  });
  const k3 = new DeviceSigner();
  await assert.rejects(
    () => rotateKey(h.pool, {
      deviceId: id, commandId: 'rot-b', keyVersion: 3,
      effectiveSequence: 6, expectedControlRevision: 1, publicKeyRaw: k3.publicRaw,
    }),
    (e) => e instanceof ApiError && e.code === 'CONTROL_REVISION_MISMATCH'
  );
});

test('effectiveSequence must be strictly beyond the contiguous watermark', async () => {
  const id = 'dev-eff';
  const k1 = new DeviceSigner();
  const k2 = new DeviceSigner();
  await registerDevice(h.pool, { deviceId: id, publicKeyRaw: k1.publicRaw });
  await ingest(id, 'fill', buildChain(k1, id, 5));
  await assert.rejects(
    () => rotateKey(h.pool, {
      deviceId: id, commandId: 'rot', keyVersion: 2,
      effectiveSequence: 3, expectedControlRevision: 1, publicKeyRaw: k2.publicRaw,
    }),
    (e) => e.code === 'EFFECTIVE_SEQUENCE_NOT_AHEAD_OF_WATERMARK'
  );
  await assert.rejects(
    () => rotateKey(h.pool, {
      deviceId: id, commandId: 'rot2', keyVersion: 2,
      effectiveSequence: 5, expectedControlRevision: 1, publicKeyRaw: k2.publicRaw,
    }),
    (e) => e.code === 'EFFECTIVE_SEQUENCE_NOT_AHEAD_OF_WATERMARK'
  );
});

test('duplicate version, overlapping effectiveSequence and occupied boundary are deterministic', async () => {
  const id = 'dev-boundary';
  const k1 = new DeviceSigner();
  await registerDevice(h.pool, { deviceId: id, publicKeyRaw: k1.publicRaw });

  // A staged future event at seq 8 (gap, nothing visible yet).
  const future = signEvent(k1, {
    deviceId: id, sequence: 8, eventId: 'e8', occurredAt: '2026-03-01T00:00:00Z',
    keyVersion: 1, prevDigest: '0'.repeat(64), payload: {},
  });
  await ingest(id, 'future', [future]);

  const k2 = new DeviceSigner();
  await assert.rejects(
    () => rotateKey(h.pool, {
      deviceId: id, commandId: 'rot-occupy', keyVersion: 2,
      effectiveSequence: 8, expectedControlRevision: 1, publicKeyRaw: k2.publicRaw,
    }),
    (e) => e.code === 'ROTATION_BOUNDARY_OCCUPIED'
  );
  // Also rejects a boundary below an already-staged later event (would strand it).
  await assert.rejects(
    () => rotateKey(h.pool, {
      deviceId: id, commandId: 'rot-occupy2', keyVersion: 2,
      effectiveSequence: 5, expectedControlRevision: 1, publicKeyRaw: k2.publicRaw,
    }),
    (e) => e.code === 'ROTATION_BOUNDARY_OCCUPIED'
  );

  // Valid rotation beyond the staged events.
  const rot = await rotateKey(h.pool, {
    deviceId: id, commandId: 'rot-ok', keyVersion: 2,
    effectiveSequence: 9, expectedControlRevision: 1, publicKeyRaw: k2.publicRaw,
  });
  assert.equal(rot.controlRevision, 2);

  // Reusing version 2 / same effective sequence.
  const k3 = new DeviceSigner();
  await assert.rejects(
    () => rotateKey(h.pool, {
      deviceId: id, commandId: 'rot-dup', keyVersion: 2,
      effectiveSequence: 20, expectedControlRevision: 2, publicKeyRaw: k3.publicRaw,
    }),
    (e) => e.code === 'KEY_VERSION_CONFLICT'
  );
  await assert.rejects(
    () => rotateKey(h.pool, {
      deviceId: id, commandId: 'rot-overlap', keyVersion: 3,
      effectiveSequence: 9, expectedControlRevision: 2, publicKeyRaw: k3.publicRaw,
    }),
    (e) => e.code === 'OVERLAPPING_EFFECTIVE_RANGE'
  );
});

test('rotation commandId is idempotent and content-conflicting', async () => {
  const id = 'dev-rotidem';
  const k1 = new DeviceSigner();
  const k2 = new DeviceSigner();
  await registerDevice(h.pool, { deviceId: id, publicKeyRaw: k1.publicRaw });
  const cmd = {
    deviceId: id, commandId: 'rot-cmd', keyVersion: 2,
    effectiveSequence: 4, expectedControlRevision: 1, publicKeyRaw: k2.publicRaw,
  };
  const first = await rotateKey(h.pool, cmd);
  assert.equal(first.replayed, false);
  const again = await rotateKey(h.pool, cmd);
  assert.equal(again.replayed, true);

  const k3 = new DeviceSigner();
  await assert.rejects(
    () => rotateKey(h.pool, { ...cmd, publicKeyRaw: k3.publicRaw }),
    (e) => e instanceof ApiError && e.code === 'IDEMPOTENCY_CONFLICT'
  );
});

test('device state reports all key generations', async () => {
  const id = 'dev-state';
  const k1 = new DeviceSigner();
  const k2 = new DeviceSigner();
  await registerDevice(h.pool, { deviceId: id, publicKeyRaw: k1.publicRaw });
  await rotateKey(h.pool, {
    deviceId: id, commandId: 'r', keyVersion: 2,
    effectiveSequence: 7, expectedControlRevision: 1, publicKeyRaw: k2.publicRaw,
  });
  const state = await getDevice(h.pool, id);
  assert.equal(state.controlRevision, 2);
  assert.deepEqual(state.keys.map((k) => [k.keyVersion, k.effectiveSequence]), [[1, 1], [2, 7]]);
});
