'use strict';
// History compaction: checkpoints cover exactly a real visible prefix, are
// server-signed and hash-chained, never cross an active view, stale cursors
// get 410 with a verifiable recovery point, and retries are safe.

import { test, before, after, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import { setupHarness, stopTestPostgres, truncateAll } from './helpers/harness.mjs';
import { registerDevice } from '../src/services/devices.mjs';
import { ingestBatch } from '../src/services/ingest.mjs';
import { readPage } from '../src/services/reads.mjs';
import { compactDevice, compactionPass } from '../src/services/compaction.mjs';
import { DeviceSigner, buildChain, prepareBatch } from './helpers/events.mjs';
import { canonicalCheckpoint } from '../src/crypto/checkpoint.mjs';
import { buildEnvelope, digestHex } from '../src/crypto/envelope.js';
import { decodeB64Url, rawToPublicKeyObject, verifyBytes, signBytes, encodeB64Url } from '../src/crypto/keys.js';
import { ApiError } from '../src/errors.mjs';

let h;
before(async () => { h = await setupHarness(); });
after(async () => { await h.pool.end(); await stopTestPostgres(); });
beforeEach(async () => { await truncateAll(h.pool); });

const ingest = (id, rid, evs) => ingestBatch(h.pool, prepareBatch(id, rid, evs));

async function buildVisible(id, n) {
  const signer = new DeviceSigner();
  await registerDevice(h.pool, { deviceId: id, publicKeyRaw: signer.publicRaw });
  const chain = buildChain(signer, id, n);
  await ingest(id, 'fill', chain);
  return { signer, chain };
}

/** Append correctly-linked events after an existing chain. */
function extendChain(signer, prevChain, id, extra) {
  const out = [];
  let prevDigest = buildEnvelope(prevChain[prevChain.length - 1]).digest;
  const baseSeq = prevChain.length;
  for (let i = 1; i <= extra; i++) {
    const seq = baseSeq + i;
    const fields = {
      deviceId: id, sequence: seq, eventId: `evt-${seq}`,
      occurredAt: `2026-01-02T00:00:0${i}Z`, keyVersion: 1,
      prevDigest, payload: { ext: i },
    };
    const { bytes, digest } = buildEnvelope(fields);
    const ev = { ...fields, signature: encodeB64Url(signBytes(signer.privateKey, bytes)) };
    out.push(ev);
    prevDigest = digest;
  }
  return out;
}

test('checkpoint signature, chain link and cutoff digest verify independently', async () => {
  const id = 'dev-cp';
  const { chain, signer } = await buildVisible(id, 20);
  // retentionEvents=5 and minEvents=3 => background cutoff = 20-5 = 15.
  const out = await compactDevice(h.pool, h.serverKey, h.cfg, id);
  assert.equal(out.checkpoint.sequence, 15);
  assert.equal(out.deletedEvents, 15);

  const { bytes } = canonicalCheckpoint(out.checkpoint);
  const sigOk = verifyBytes(
    rawToPublicKeyObject(h.serverKey.publicRaw),
    bytes,
    decodeB64Url(out.checkpoint.signature)
  );
  assert.ok(sigOk);
  assert.equal(out.checkpoint.digest, buildEnvelope(chain[14]).digest);
  assert.equal(out.checkpoint.prevCheckpointDigest, '0'.repeat(64));

  // Grow past retention again and make a second checkpoint that links back.
  await ingest(id, 'more', extendChain(signer, chain, id, 8));
  const out2 = await compactDevice(h.pool, h.serverKey, h.cfg, id);
  assert.equal(out2.checkpoint.sequence, 23); // 28-5
  assert.equal(out2.checkpoint.prevCheckpointDigest, digestHex(
    canonicalCheckpoint(out.checkpoint).bytes
  ));
});

test('fresh reads behind a checkpoint get 410; checkpoint recovery then reads remaining events', async () => {
  const id = 'dev-410';
  await buildVisible(id, 12);
  await compactDevice(h.pool, h.serverKey, h.cfg, id); // cutoff 7 (12-5)

  const err = await readPage(h.pool, h.serverKey, h.cfg, {
    deviceId: id, cursorToken: null, explicitAfterSequence: undefined,
  }).then(() => null, (e) => e);
  assert.ok(err instanceof ApiError && err.status === 410);
  const cp = err.details.checkpoint;
  assert.equal(cp.sequence, 7);
  assert.equal(err.details.resumeFromSequence, 8);

  // A consumer verifies the checkpoint, anchors afterSequence at its sequence,
  // and gets exactly the retained tail without any gap.
  const resumed = await readPage(h.pool, h.serverKey, h.cfg, {
    deviceId: id, cursorToken: null, explicitAfterSequence: 7,
  });
  assert.deepEqual(resumed.events.map((e) => e.sequence), [8, 9, 10, 11, 12]);
  assert.equal(resumed.viewHighWatermark, 12);
});

test('active fixed view pins history so it cannot be compacted away', async () => {
  const id = 'dev-view-pin';
  await buildVisible(id, 20);
  // Open a view that starts reading at 0: it pins ALL events.
  await readPage(h.pool, h.serverKey, h.cfg, { deviceId: id, limit: 1 });
  const out = await compactDevice(h.pool, h.serverKey, h.cfg, id);
  assert.equal(out, null); // floor 0 blocks any deletion

  // A view anchored later only pins events it can still need. A fresh view at
  // afterSequence=18 has start_sequence=18 and allows cutoff up to 18.
  await readPage(h.pool, h.serverKey, h.cfg, {
    deviceId: id, limit: 1, cursorToken: null, explicitAfterSequence: 18,
  });
  const out2 = await compactDevice(h.pool, h.serverKey, h.cfg, id);
  // min(20-5=15, min(0,18)=0) still 0 due the first open view: expire it.
  assert.equal(out2, null);
  await h.pool.query(`UPDATE read_views SET expires_at = now() - interval '1 second' WHERE device_id=$1 AND start_sequence=0`, [id]);
  const out3 = await compactDevice(h.pool, h.serverKey, h.cfg, id);
  assert.equal(out3.checkpoint.sequence, 15); // retention binds before view 18
});

test('events deleted are exactly the visible prefix through the cutoff', async () => {
  const id = 'dev-del';
  await buildVisible(id, 10);
  await compactDevice(h.pool, h.serverKey, h.cfg, id, 4);
  const { rows } = await h.pool.query(
    `SELECT min(sequence)::int AS lo, max(sequence)::int AS hi, count(*)::int AS n
       FROM event_records WHERE device_id=$1 AND status='visible'`,
    [id]
  );
  assert.deepEqual([rows[0].lo, rows[0].hi, rows[0].n], [5, 10, 6]);
});

test('manual cutoff beyond watermark conflicts; equal replay idempotent; content reuse conflicts', async () => {
  const id = 'dev-manual';
  await buildVisible(id, 10);
  await assert.rejects(
    () => compactDevice(h.pool, h.serverKey, h.cfg, id, 100, 'cmd-m1'),
    (e) => e instanceof ApiError && e.code === 'CUTOFF_BEYOND_WATERMARK'
  );
  const first = await compactDevice(h.pool, h.serverKey, h.cfg, id, 3, 'cmd-m2');
  assert.equal(first.checkpoint.sequence, 3);
  const replay = await compactDevice(h.pool, h.serverKey, h.cfg, id, 3, 'cmd-m2');
  assert.equal(replay.replayed, true);
  await assert.rejects(
    () => compactDevice(h.pool, h.serverKey, h.cfg, id, 4, 'cmd-m2'),
    (e) => e instanceof ApiError && e.code === 'IDEMPOTENCY_CONFLICT'
  );
});

test('compactionPass is idempotent across restarts (one consistent checkpoint)', async () => {
  const id = 'dev-pass';
  await buildVisible(id, 12);
  const s1 = await compactionPass(h.pool, h.serverKey, h.cfg, { info() {}, error() {} });
  assert.ok(s1.checkpoints >= 1);
  const s2 = await compactionPass(h.pool, h.serverKey, h.cfg, { info() {}, error() {} });
  assert.equal(s2.checkpoints, 0);
  const { rows } = await h.pool.query(
    'SELECT count(*)::int AS n FROM checkpoints WHERE device_id=$1', [id]
  );
  assert.equal(rows[0].n, 1);
});

test('checkpoint and delete are atomic: no event is both unreadable and uncovered', async () => {
  const id = 'dev-atomic-cp';
  const { chain } = await buildVisible(id, 10);
  await compactDevice(h.pool, h.serverKey, h.cfg, id, 5);
  // Event 5 row is deleted, yet its digest is recoverable from the checkpoint;
  // event 6 still reads normally and its prevDigest equals checkpoint digest.
  const page = await readPage(h.pool, h.serverKey, h.cfg, {
    deviceId: id, cursorToken: null, explicitAfterSequence: 5,
  });
  assert.equal(page.events[0].sequence, 6);
  assert.equal(page.events[0].prevDigest, buildEnvelope(chain[4]).digest);
});
