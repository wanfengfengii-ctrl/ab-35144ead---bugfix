'use strict';
// Compacted-prefix anchoring. After compaction - even up to the current high
// watermark - the deleted visible prefix keeps participating as immutable
// committed history through its digest tombstones / checkpoints:
//  * a legal continuation whose prevDigest links to the checkpoint digest
//    promotes and advances the watermark;
//  * an identical retransmission of a compacted event is an idempotent no-op;
//  * a different digest at a compacted sequence opens a queryable,
//    adjudicable post_visibility_divergence conflict instead of sitting
//    around as an ordinary staged candidate;
//  * adjudication can confirm the committed digest but never replace it.

import { test, before, after, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import { setupHarness, stopTestPostgres, truncateAll } from './helpers/harness.mjs';
import { registerDevice } from '../src/services/devices.mjs';
import { ingestBatch } from '../src/services/ingest.mjs';
import { compactDevice } from '../src/services/compaction.mjs';
import { adjudicate, getConflict, listConflicts } from '../src/services/conflicts.mjs';
import { readPage } from '../src/services/reads.mjs';
import { DeviceSigner, buildChain, prepareBatch } from './helpers/events.mjs';
import { buildEnvelope } from '../src/crypto/envelope.js';
import { signBytes, encodeB64Url } from '../src/crypto/keys.js';
import { ApiError } from '../src/errors.mjs';

let h;
before(async () => { h = await setupHarness(); });
after(async () => { await h.pool.end(); await stopTestPostgres(); });
beforeEach(async () => { await truncateAll(h.pool); });

const ingest = (id, rid, evs) => ingestBatch(h.pool, prepareBatch(id, rid, evs));

function digestOf(event) {
  return buildEnvelope(event).digest;
}

/** Re-sign an existing event object with changed fields (used to craft forks). */
function resign(signer, event, overrides = {}) {
  const fields = {
    deviceId: event.deviceId,
    sequence: event.sequence,
    eventId: overrides.eventId ?? event.eventId,
    occurredAt: overrides.occurredAt ?? event.occurredAt,
    keyVersion: overrides.keyVersion ?? event.keyVersion,
    prevDigest: overrides.prevDigest ?? event.prevDigest,
    payload: overrides.payload ?? event.payload,
  };
  const { bytes } = buildEnvelope(fields);
  return { ...fields, signature: encodeB64Url(signBytes(signer.privateKey, bytes)) };
}

/** Append correctly-linked events after an existing chain. */
function extendChain(signer, prevChain, id, extra) {
  const out = [];
  let prevDigest = digestOf(prevChain[prevChain.length - 1]);
  const baseSeq = prevChain.length;
  for (let i = 1; i <= extra; i++) {
    const seq = baseSeq + i;
    const fields = {
      deviceId: id, sequence: seq, eventId: `evt-${seq}`,
      occurredAt: `2026-01-02T00:00:0${i}Z`, keyVersion: 1,
      prevDigest, payload: { ext: i },
    };
    const { bytes, digest } = buildEnvelope(fields);
    out.push({ ...fields, signature: encodeB64Url(signBytes(signer.privateKey, bytes)) });
    prevDigest = digest;
  }
  return out;
}

async function hwmOf(id) {
  const { rows } = await h.pool.query('SELECT high_watermark FROM devices WHERE device_id=$1', [id]);
  return Number(rows[0].high_watermark);
}

/** Device with visible 1..3, then manually compacted exactly to the watermark. */
async function deviceCompactedToWatermark(id) {
  const signer = new DeviceSigner();
  await registerDevice(h.pool, { deviceId: id, publicKeyRaw: signer.publicRaw });
  const chain = buildChain(signer, id, 3);
  await ingest(id, 'seed', chain);
  const out = await compactDevice(h.pool, h.serverKey, h.cfg, id, 3, `cp-${id}`);
  assert.equal(out.checkpoint.sequence, 3);
  assert.equal(out.deletedEvents, 3);
  assert.equal(out.checkpoint.digest, digestOf(chain[2]));
  return { signer, chain, checkpoint: out.checkpoint };
}

test('continuation linked to the checkpoint digest promotes after compaction to the watermark', async () => {
  const id = 'dev-anchor-cont';
  const { signer, chain, checkpoint } = await deviceCompactedToWatermark(id);

  // The exact task scenario: seq 4 with prevDigest = checkpoint digest of seq 3.
  const [e4] = extendChain(signer, chain, id, 1);
  assert.equal(e4.prevDigest, checkpoint.digest);
  const r = await ingest(id, 'cont-4', [e4]);
  assert.equal(r.highWatermark, 4);
  assert.deepEqual(r.conflicts, []);
  assert.equal(r.events[0].state, 'visible');
  assert.equal(await hwmOf(id), 4);

  // The promoted event reads normally right after the checkpoint.
  const page = await readPage(h.pool, h.serverKey, h.cfg, {
    deviceId: id, cursorToken: null, explicitAfterSequence: 3,
  });
  assert.deepEqual(page.events.map((e) => e.sequence), [4]);
  assert.equal(page.events[0].prevDigest, checkpoint.digest);
});

test('identical retransmission of compacted events is an idempotent no-op', async () => {
  const id = 'dev-anchor-retran';
  const { chain } = await deviceCompactedToWatermark(id);

  // Retransmit the checkpoint event itself (new requestId: not a stored replay).
  const atCheckpoint = await ingest(id, 'again-3', [chain[2]]);
  assert.equal(atCheckpoint.highWatermark, 3);
  assert.deepEqual(atCheckpoint.conflicts, []);
  assert.equal(atCheckpoint.events[0].state, 'compacted');

  // Retransmit events below the checkpoint: equally idempotent.
  const below = await ingest(id, 'again-12', [chain[0], chain[1]]);
  assert.equal(below.highWatermark, 3);
  assert.deepEqual(below.conflicts, []);
  assert.deepEqual(below.events.map((e) => e.state), ['compacted', 'compacted']);

  // No staged residue, no conflicts, watermark untouched.
  const { rows } = await h.pool.query(
    'SELECT count(*)::int AS n FROM event_records WHERE device_id=$1', [id]);
  assert.equal(rows[0].n, 0);
  const open = await listConflicts(h.pool, id);
  assert.equal(open.conflicts.length, 0);
  assert.equal(await hwmOf(id), 3);
});

test('a different digest at the checkpoint sequence opens a queryable, adjudicable conflict', async () => {
  const id = 'dev-anchor-fork';
  const { signer, chain, checkpoint } = await deviceCompactedToWatermark(id);

  // The task scenario: valid signature, prevDigest correctly pointing at the
  // original seq 2, but different content and therefore a different digest.
  const fork3 = resign(signer, chain[2], { payload: { fork: true } });
  assert.notEqual(digestOf(fork3), checkpoint.digest);
  assert.equal(fork3.prevDigest, digestOf(chain[1]));

  const r = await ingest(id, 'fork-3', [fork3]);
  assert.equal(r.highWatermark, 3);
  assert.equal(r.conflicts.length, 1);
  assert.equal(r.conflicts[0].sequence, 3);
  assert.equal(r.conflicts[0].reason, 'post_visibility_divergence');

  // Queryable: the conflict exposes the fork candidate and the committed digest.
  const c = await getConflict(h.pool, id, 3);
  assert.equal(c.status, 'open');
  assert.equal(c.reason, 'post_visibility_divergence');
  assert.equal(c.committedDigest, checkpoint.digest);
  assert.deepEqual(c.candidates.map((x) => x.digest), [digestOf(fork3)]);

  // The fork can never replace committed history.
  await assert.rejects(
    () => adjudicate(h.pool, {
      deviceId: id, sequence: 3, commandId: 'adj-replace',
      expectedConflictRevision: c.revision,
      decision: { type: 'select', digest: digestOf(fork3) },
    }),
    (e) => e instanceof ApiError && e.code === 'CANNOT_REPLACE_VISIBLE_EVENT'
  );

  // Confirming the committed digest resolves the conflict; watermark unchanged.
  const ok = await adjudicate(h.pool, {
    deviceId: id, sequence: 3, commandId: 'adj-confirm',
    expectedConflictRevision: c.revision,
    decision: { type: 'select', digest: checkpoint.digest },
  });
  assert.equal(ok.resolution, 'selected');
  assert.equal(ok.chosenDigest, checkpoint.digest);
  assert.equal(ok.highWatermark, 3);

  const after = await getConflict(h.pool, id, 3);
  assert.equal(after.status, 'resolved');
  assert.equal(after.committedDigest, checkpoint.digest);
  assert.equal(await hwmOf(id), 3);

  // reject_all is also a valid disposition for the forked candidate.
  const fork3b = resign(signer, chain[2], { payload: { fork: 2 } });
  const r2 = await ingest(id, 'fork-3b', [fork3b]);
  assert.equal(r2.conflicts[0].reason, 'post_visibility_divergence');
  const c2 = await getConflict(h.pool, id, 3);
  const rej = await adjudicate(h.pool, {
    deviceId: id, sequence: 3, commandId: 'adj-rej',
    expectedConflictRevision: c2.revision, decision: { type: 'reject_all' },
  });
  assert.equal(rej.resolution, 'rejected_all');
  assert.equal(rej.highWatermark, 3);
});

test('a different digest below the checkpoint sequence is also a committed-history fork', async () => {
  const id = 'dev-anchor-below';
  const { signer, chain } = await deviceCompactedToWatermark(id);

  const fork2 = resign(signer, chain[1], { payload: { fork: true } });
  const r = await ingest(id, 'fork-2', [fork2]);
  assert.equal(r.highWatermark, 3);
  assert.equal(r.conflicts[0].reason, 'post_visibility_divergence');

  const c = await getConflict(h.pool, id, 2);
  assert.equal(c.committedDigest, digestOf(chain[1]));
  await assert.rejects(
    () => adjudicate(h.pool, {
      deviceId: id, sequence: 2, commandId: 'adj-below',
      expectedConflictRevision: c.revision,
      decision: { type: 'select', digest: digestOf(fork2) },
    }),
    (e) => e instanceof ApiError && e.code === 'CANNOT_REPLACE_VISIBLE_EVENT'
  );
});

test('a continuation with a wrong prevDigest after compaction still fails as bad_predecessor', async () => {
  const id = 'dev-anchor-badprev';
  const { signer, chain } = await deviceCompactedToWatermark(id);

  const [e4] = extendChain(signer, chain, id, 1);
  const bad4 = resign(signer, e4, { prevDigest: 'a'.repeat(64) });
  const r = await ingest(id, 'bad-4', [bad4]);
  assert.equal(r.highWatermark, 3);
  assert.equal(r.conflicts[0].reason, 'bad_predecessor');
  assert.equal(await hwmOf(id), 3);
});

test('repeated compaction rounds keep anchoring continuation and forks', async () => {
  const id = 'dev-anchor-rounds';
  const { signer, chain } = await deviceCompactedToWatermark(id);

  // Continue the chain past the checkpoint, then compact again to the new watermark.
  const more = extendChain(signer, chain, id, 3); // seq 4..6
  const r1 = await ingest(id, 'cont-456', more);
  assert.equal(r1.highWatermark, 6);
  const out2 = await compactDevice(h.pool, h.serverKey, h.cfg, id, 6, `cp2-${id}`);
  assert.equal(out2.checkpoint.sequence, 6);
  assert.equal(out2.checkpoint.digest, digestOf(more[2]));

  // Legal continuation from the second checkpoint.
  const [e7] = extendChain(signer, [...chain, ...more], id, 1);
  const r2 = await ingest(id, 'cont-7', [e7]);
  assert.equal(r2.highWatermark, 7);
  assert.deepEqual(r2.conflicts, []);

  // A fork at a sequence compacted between the two checkpoints (no checkpoint
  // row of its own) is still caught by its tombstone.
  const fork4 = resign(signer, more[0], { payload: { fork: 4 } });
  const r3 = await ingest(id, 'fork-4', [fork4]);
  assert.equal(r3.conflicts[0].reason, 'post_visibility_divergence');
  const c = await getConflict(h.pool, id, 4);
  assert.equal(c.committedDigest, digestOf(more[0]));

  // Identical retransmission of an event compacted in the first round.
  const again = await ingest(id, 'again-2', [chain[1]]);
  assert.equal(again.events[0].state, 'compacted');
  assert.deepEqual(again.conflicts, []);
  assert.equal(await hwmOf(id), 7);
});

test('concurrent continuation ingest and compaction to the watermark converge', async () => {
  const id = 'dev-anchor-race';
  const signer = new DeviceSigner();
  await registerDevice(h.pool, { deviceId: id, publicKeyRaw: signer.publicRaw });
  const chain = buildChain(signer, id, 3);
  await ingest(id, 'seed', chain);
  const [e4] = extendChain(signer, chain, id, 1);

  // The devices row lock serializes the two; both interleavings must land in
  // the same final state: checkpoint at 3, seq 4 visible, watermark 4.
  await Promise.all([
    compactDevice(h.pool, h.serverKey, h.cfg, id, 3, `cp-${id}`),
    ingest(id, 'cont-4', [e4]),
  ]);

  assert.equal(await hwmOf(id), 4);
  const { rows: cps } = await h.pool.query(
    'SELECT sequence, digest FROM checkpoints WHERE device_id=$1', [id]);
  assert.equal(cps.length, 1);
  assert.equal(Number(cps[0].sequence), 3);
  assert.equal(cps[0].digest, digestOf(chain[2]));
  const page = await readPage(h.pool, h.serverKey, h.cfg, {
    deviceId: id, cursorToken: null, explicitAfterSequence: 3,
  });
  assert.deepEqual(page.events.map((e) => e.sequence), [4]);
});

test('one batch can mix compacted no-ops with a legal continuation', async () => {
  const id = 'dev-anchor-mixed';
  const { signer, chain } = await deviceCompactedToWatermark(id);
  const [e4, e5] = extendChain(signer, chain, id, 2);

  // Retransmitted compacted events + the new frontier events in ONE request.
  const r = await ingest(id, 'mixed', [chain[1], chain[2], e4, e5]);
  assert.equal(r.highWatermark, 5);
  assert.deepEqual(r.conflicts, []);
  assert.deepEqual(
    r.events.map((e) => e.state),
    ['compacted', 'compacted', 'visible', 'visible']
  );
});

test('ingest requestId idempotency survives compaction of the recorded events', async () => {
  const id = 'dev-anchor-idem';
  const signer = new DeviceSigner();
  await registerDevice(h.pool, { deviceId: id, publicKeyRaw: signer.publicRaw });
  const chain = buildChain(signer, id, 3);
  const first = await ingest(id, 'rid-stable', chain);
  assert.equal(first.highWatermark, 3);

  await compactDevice(h.pool, h.serverKey, h.cfg, id, 3, `cp-${id}`);

  // Same requestId + same content after compaction: exact stored replay.
  const replay = await ingest(id, 'rid-stable', chain);
  assert.equal(replay.replayed, true);
  assert.equal(replay.highWatermark, 3);
  // Same requestId + different content: stable idempotency conflict.
  await assert.rejects(
    () => ingest(id, 'rid-stable', [chain[0]]),
    (e) => e instanceof ApiError && e.code === 'IDEMPOTENCY_CONFLICT'
  );
});
