'use strict';
// Compaction to the CURRENT watermark: the compacted consecutive prefix must
// keep participating in every later judgment as immutable committed history.
//
//  * a legal continuation whose prevDigest matches the checkpoint digest is
//    accepted and advances the watermark across the compaction boundary;
//  * an identical retransmission of a compacted event is a conflict-free
//    no-op that rejoins the committed prefix;
//  * a different digest at a compacted sequence is compared against the
//    committed (checkpoint) digest and becomes a queryable, adjudicable
//    post_visibility_divergence conflict - never an ordinary candidate that
//    could rewrite history;
//  * adjudication cannot select anything but the checkpoint-attested digest
//    at a compacted sequence;
//  * bad_predecessor / key-generation checks and checkpoint chaining keep
//    working across the boundary, and compaction racing continuation stays
//    consistent.

import { test, before, after, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import { setupHarness, stopTestPostgres, truncateAll } from './helpers/harness.mjs';
import { registerDevice, rotateKey } from '../src/services/devices.mjs';
import { ingestBatch } from '../src/services/ingest.mjs';
import { adjudicate, listConflicts, getConflict } from '../src/services/conflicts.mjs';
import { readPage } from '../src/services/reads.mjs';
import { compactDevice } from '../src/services/compaction.mjs';
import { DeviceSigner, buildChain, prepareBatch } from './helpers/events.mjs';
import { canonicalCheckpoint } from '../src/crypto/checkpoint.mjs';
import { buildEnvelope, digestHex } from '../src/crypto/envelope.js';
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

/** Sign one event with explicit fields (used for continuations and forks). */
function signEvent(signer, fields) {
  const { bytes, digest } = buildEnvelope(fields);
  return { event: { ...fields, signature: encodeB64Url(signBytes(signer.privateKey, bytes)) }, digest };
}

async function hwmOf(id) {
  const { rows } = await h.pool.query('SELECT high_watermark FROM devices WHERE device_id=$1', [id]);
  return Number(rows[0].high_watermark);
}

/** Register a device, commit a chain of n, compact exactly to the watermark. */
async function compactedToWatermark(id, n) {
  const signer = new DeviceSigner();
  await registerDevice(h.pool, { deviceId: id, publicKeyRaw: signer.publicRaw });
  const chain = buildChain(signer, id, n);
  await ingest(id, 'seed', chain);
  const out = await compactDevice(h.pool, h.serverKey, h.cfg, id, n, `cp-${id}`);
  assert.equal(out.checkpoint.sequence, n);
  assert.equal(out.deletedEvents, n);
  assert.equal(out.checkpoint.digest, digestOf(chain[n - 1]));
  return { signer, chain, checkpoint: out.checkpoint };
}

test('legal continuation across the checkpoint advances the watermark; reads resume at the checkpoint', async () => {
  const id = 'dev-cc-cont';
  const { signer, checkpoint } = await compactedToWatermark(id, 3);

  const e4 = signEvent(signer, {
    deviceId: id, sequence: 4, eventId: 'evt-4', occurredAt: '2026-01-02T00:00:04Z',
    keyVersion: 1, prevDigest: checkpoint.digest, payload: { after: 'checkpoint' },
  });
  const r = await ingest(id, 'cont-4', [e4.event]);
  assert.equal(r.highWatermark, 4);
  assert.deepEqual(r.conflicts, []);
  assert.equal(r.events[0].state, 'visible');

  // The chain continues normally afterwards (out-of-order arrival included).
  const e5 = signEvent(signer, {
    deviceId: id, sequence: 5, eventId: 'evt-5', occurredAt: '2026-01-02T00:00:05Z',
    keyVersion: 1, prevDigest: e4.digest, payload: {},
  });
  const e6 = signEvent(signer, {
    deviceId: id, sequence: 6, eventId: 'evt-6', occurredAt: '2026-01-02T00:00:06Z',
    keyVersion: 1, prevDigest: e5.digest, payload: {},
  });
  const r2 = await ingest(id, 'cont-56', [e6.event, e5.event]);
  assert.equal(r2.highWatermark, 6);

  // Reads behind the checkpoint are 410 with the recovery point; the resumed
  // tail is exactly the consecutive post-checkpoint prefix.
  const err = await readPage(h.pool, h.serverKey, h.cfg, {
    deviceId: id, cursorToken: null, explicitAfterSequence: undefined,
  }).then(() => null, (e) => e);
  assert.ok(err instanceof ApiError && err.status === 410);
  assert.equal(err.details.checkpoint.sequence, 3);
  assert.equal(err.details.resumeFromSequence, 4);

  const tail = await readPage(h.pool, h.serverKey, h.cfg, {
    deviceId: id, cursorToken: null, explicitAfterSequence: 3,
  });
  assert.deepEqual(tail.events.map((e) => e.sequence), [4, 5, 6]);
  assert.equal(tail.events[0].prevDigest, checkpoint.digest);
});

test('identical retransmission of a compacted event is a conflict-free no-op', async () => {
  const id = 'dev-cc-retransmit';
  const { chain } = await compactedToWatermark(id, 3);

  const r = await ingest(id, 'again-3', [chain[2]]);
  assert.equal(r.highWatermark, 3);
  assert.deepEqual(r.conflicts, []);
  assert.equal(r.events[0].state, 'visible'); // attested by the checkpoint

  // Repetition stays stable; the committed digest still cannot diverge.
  const r2 = await ingest(id, 'again-3b', [chain[2]]);
  assert.equal(r2.highWatermark, 3);
  assert.deepEqual(r2.conflicts, []);
  assert.equal((await listConflicts(h.pool, id)).conflicts.length, 0);

  // The resurrected row never leaks into reads behind the checkpoint.
  const tail = await readPage(h.pool, h.serverKey, h.cfg, {
    deviceId: id, cursorToken: null, explicitAfterSequence: 3,
  });
  assert.deepEqual(tail.events, []);
});

test('divergent fork at a compacted sequence forms a queryable conflict and cannot be selected', async () => {
  const id = 'dev-cc-fork';
  const { signer, chain, checkpoint } = await compactedToWatermark(id, 3);

  // Legal continuation first: the live chain moves to 4.
  const e4 = signEvent(signer, {
    deviceId: id, sequence: 4, eventId: 'evt-4', occurredAt: '2026-01-02T00:00:04Z',
    keyVersion: 1, prevDigest: checkpoint.digest, payload: {},
  });
  await ingest(id, 'cont-4', [e4.event]);

  // A validly signed seq-3 event whose digest differs from the committed one.
  const fork3 = signEvent(signer, {
    deviceId: id, sequence: 3, eventId: 'evt-3-fork', occurredAt: '2026-01-01T00:02:00Z',
    keyVersion: 1, prevDigest: digestOf(chain[1]), payload: { rewritten: true },
  });
  const rf = await ingest(id, 'fork-3', [fork3.event]);
  assert.equal(rf.highWatermark, 4); // live watermark unaffected
  assert.equal(rf.events[0].state, 'staged');
  assert.equal(rf.conflicts.length, 1);
  assert.equal(rf.conflicts[0].sequence, 3);
  assert.equal(rf.conflicts[0].reason, 'post_visibility_divergence');

  // Queryable through both conflict endpoints, with the fork as candidate.
  const open = await listConflicts(h.pool, id);
  assert.equal(open.conflicts.length, 1);
  assert.equal(open.conflicts[0].reason, 'post_visibility_divergence');
  const one = await getConflict(h.pool, id, 3);
  assert.equal(one.status, 'open');
  assert.ok(one.candidates.some((c) => c.digest === fork3.digest));
  const revision = one.revision;

  // The historical fork does not block the live chain.
  const e5 = signEvent(signer, {
    deviceId: id, sequence: 5, eventId: 'evt-5', occurredAt: '2026-01-02T00:00:05Z',
    keyVersion: 1, prevDigest: e4.digest, payload: {},
  });
  const r5 = await ingest(id, 'cont-5', [e5.event]);
  assert.equal(r5.highWatermark, 5);

  // Stale revisions are still refused.
  await assert.rejects(
    () => adjudicate(h.pool, {
      deviceId: id, sequence: 3, commandId: 'adj-stale',
      expectedConflictRevision: revision + 9, decision: { type: 'reject_all' },
    }),
    (e) => e instanceof ApiError && e.code === 'CONFLICT_REVISION_MISMATCH'
  );

  // The fork digest can never replace checkpoint-committed history.
  await assert.rejects(
    () => adjudicate(h.pool, {
      deviceId: id, sequence: 3, commandId: 'adj-select-fork',
      expectedConflictRevision: revision,
      decision: { type: 'select', digest: fork3.digest },
    }),
    (e) => e instanceof ApiError && e.code === 'CANNOT_REPLACE_VISIBLE_EVENT'
  );

  // Confirming the committed digest resolves the conflict and refuses the fork.
  const ok = await adjudicate(h.pool, {
    deviceId: id, sequence: 3, commandId: 'adj-select-committed',
    expectedConflictRevision: revision,
    decision: { type: 'select', digest: checkpoint.digest },
  });
  assert.equal(ok.resolution, 'selected');
  assert.equal(ok.chosenDigest, checkpoint.digest);
  assert.equal(ok.highWatermark, 5);
  const resolved = await getConflict(h.pool, id, 3);
  assert.equal(resolved.status, 'resolved');
  const { rows: forkRows } = await h.pool.query(
    'SELECT status FROM event_records WHERE device_id=$1 AND sequence=3 AND digest=$2',
    [id, fork3.digest]
  );
  assert.equal(forkRows[0].status, 'rejected');

  // A re-uploaded fork reopens the conflict (revision bumps); reject_all ends it.
  const again = await ingest(id, 'fork-3-again', [fork3.event]);
  assert.equal(again.conflicts[0].reason, 'post_visibility_divergence');
  assert.equal(again.conflicts[0].revision, revision + 1);
  const rej = await adjudicate(h.pool, {
    deviceId: id, sequence: 3, commandId: 'adj-reject-all',
    expectedConflictRevision: revision + 1, decision: { type: 'reject_all' },
  });
  assert.equal(rej.resolution, 'rejected_all');
  assert.equal(rej.highWatermark, 5);
  assert.equal((await listConflicts(h.pool, id)).conflicts.length, 0);
});

test('selecting the committed digest works even without any candidate row', async () => {
  const id = 'dev-cc-virtual';
  const { signer, chain, checkpoint } = await compactedToWatermark(id, 3);
  const fork3 = signEvent(signer, {
    deviceId: id, sequence: 3, eventId: 'evt-3-fork', occurredAt: '2026-01-01T00:02:00Z',
    keyVersion: 1, prevDigest: digestOf(chain[1]), payload: { rewritten: true },
  });
  const rf = await ingest(id, 'fork-only', [fork3.event]);
  const revision = rf.conflicts[0].revision;

  // No row with the committed digest exists (compaction deleted it); the
  // checkpoint itself attests it, so the selection is still valid.
  const ok = await adjudicate(h.pool, {
    deviceId: id, sequence: 3, commandId: 'adj-virtual',
    expectedConflictRevision: revision,
    decision: { type: 'select', digest: checkpoint.digest },
  });
  assert.equal(ok.resolution, 'selected');
  assert.equal(ok.chosenDigest, checkpoint.digest);
});

test('bad_predecessor is still detected across the checkpoint boundary', async () => {
  const id = 'dev-cc-badprev';
  const { signer, checkpoint } = await compactedToWatermark(id, 3);

  const bad4 = signEvent(signer, {
    deviceId: id, sequence: 4, eventId: 'evt-4-bad', occurredAt: '2026-01-02T00:00:04Z',
    keyVersion: 1, prevDigest: 'a'.repeat(64), payload: {},
  });
  const r = await ingest(id, 'bad-4', [bad4.event]);
  assert.equal(r.highWatermark, 3);
  assert.equal(r.conflicts[0].reason, 'bad_predecessor');

  // Reject the broken candidate, then the correctly linked one promotes.
  const c = await getConflict(h.pool, id, 4);
  await adjudicate(h.pool, {
    deviceId: id, sequence: 4, commandId: 'adj-bad4',
    expectedConflictRevision: c.revision, decision: { type: 'reject_all' },
  });
  const good4 = signEvent(signer, {
    deviceId: id, sequence: 4, eventId: 'evt-4', occurredAt: '2026-01-02T00:00:04Z',
    keyVersion: 1, prevDigest: checkpoint.digest, payload: {},
  });
  const fixed = await ingest(id, 'good-4', [good4.event]);
  assert.equal(fixed.highWatermark, 4);
  assert.deepEqual(fixed.conflicts, []);
});

test('divergent candidates at the post-checkpoint frontier still conflict and adjudicate', async () => {
  const id = 'dev-cc-frontier';
  const { signer, checkpoint } = await compactedToWatermark(id, 3);

  // Both seq-5 forks arrive while the frontier is still at 3 (out-of-order
  // backfill), so neither can promote yet: a genuine divergent pair.
  const e4 = signEvent(signer, {
    deviceId: id, sequence: 4, eventId: 'evt-4', occurredAt: '2026-01-02T00:00:04Z',
    keyVersion: 1, prevDigest: checkpoint.digest, payload: {},
  });
  const honest5 = signEvent(signer, {
    deviceId: id, sequence: 5, eventId: 'evt-5', occurredAt: '2026-01-02T00:00:05Z',
    keyVersion: 1, prevDigest: e4.digest, payload: { honest: true },
  });
  const fork5 = signEvent(signer, {
    deviceId: id, sequence: 5, eventId: 'evt-5-fork', occurredAt: '2026-01-02T00:00:05Z',
    keyVersion: 1, prevDigest: e4.digest, payload: { honest: false },
  });
  await ingest(id, 'honest-5', [honest5.event]);
  const r = await ingest(id, 'fork-5', [fork5.event]);
  assert.equal(r.highWatermark, 3);
  assert.equal(r.conflicts[0].reason, 'divergent_candidates');

  // The linking event promotes across the checkpoint, then stops at the open
  // conflict at 5.
  const r4 = await ingest(id, 'cont-4', [e4.event]);
  assert.equal(r4.highWatermark, 4);

  const c = await getConflict(h.pool, id, 5);
  const adj = await adjudicate(h.pool, {
    deviceId: id, sequence: 5, commandId: 'adj-frontier',
    expectedConflictRevision: c.revision,
    decision: { type: 'select', digest: honest5.digest },
  });
  assert.equal(adj.highWatermark, 5);
});

test('key generations and a second checkpoint chain across the compaction boundary', async () => {
  const id = 'dev-cc-keys';
  const { signer, checkpoint } = await compactedToWatermark(id, 3);

  // Rotate: generation 2 owns sequences >= 5 (hwm is 3, so 5 is ahead).
  const signer2 = new DeviceSigner();
  const rot = await rotateKey(h.pool, {
    deviceId: id, commandId: 'rot-1', keyVersion: 2, effectiveSequence: 5,
    expectedControlRevision: 1, publicKeyRaw: signer2.publicRaw,
  });
  assert.equal(rot.controlRevision, 2);

  const e4 = signEvent(signer, {
    deviceId: id, sequence: 4, eventId: 'evt-4', occurredAt: '2026-01-02T00:00:04Z',
    keyVersion: 1, prevDigest: checkpoint.digest, payload: {},
  });
  const r4 = await ingest(id, 'gen1-4', [e4.event]);
  assert.equal(r4.highWatermark, 4);

  const e5 = signEvent(signer2, {
    deviceId: id, sequence: 5, eventId: 'evt-5', occurredAt: '2026-01-02T00:00:05Z',
    keyVersion: 2, prevDigest: e4.digest, payload: {},
  });
  const r5 = await ingest(id, 'gen2-5', [e5.event]);
  assert.equal(r5.highWatermark, 5);

  // The old key past the boundary is rejected atomically at ingest validation.
  const stale6 = signEvent(signer, {
    deviceId: id, sequence: 6, eventId: 'evt-6-stale', occurredAt: '2026-01-02T00:00:06Z',
    keyVersion: 1, prevDigest: e5.digest, payload: {},
  });
  await assert.rejects(
    () => ingest(id, 'gen1-6', [stale6.event]),
    (e) => e instanceof ApiError && e.code === 'KEY_GENERATION_MISMATCH'
  );

  // A second compaction at the new watermark chains to the first checkpoint.
  const out2 = await compactDevice(h.pool, h.serverKey, h.cfg, id, 5, 'cp-second');
  assert.equal(out2.checkpoint.sequence, 5);
  assert.equal(out2.checkpoint.digest, e5.digest);
  assert.equal(
    out2.checkpoint.prevCheckpointDigest,
    digestHex(canonicalCheckpoint(checkpoint).bytes)
  );

  // And the chain still continues across the second checkpoint.
  const e6 = signEvent(signer2, {
    deviceId: id, sequence: 6, eventId: 'evt-6', occurredAt: '2026-01-02T00:00:06Z',
    keyVersion: 2, prevDigest: e5.digest, payload: {},
  });
  const r6 = await ingest(id, 'gen2-6', [e6.event]);
  assert.equal(r6.highWatermark, 6);
});

test('a batch spanning the compaction boundary resolves in one shot', async () => {
  const id = 'dev-cc-batch';
  const { signer, chain, checkpoint } = await compactedToWatermark(id, 3);

  const e4 = signEvent(signer, {
    deviceId: id, sequence: 4, eventId: 'evt-4', occurredAt: '2026-01-02T00:00:04Z',
    keyVersion: 1, prevDigest: checkpoint.digest, payload: {},
  });
  const e5 = signEvent(signer, {
    deviceId: id, sequence: 5, eventId: 'evt-5', occurredAt: '2026-01-02T00:00:05Z',
    keyVersion: 1, prevDigest: e4.digest, payload: {},
  });
  // Identical retransmission of compacted seq 3 plus the continuation run.
  const r = await ingest(id, 'span', [chain[2], e4.event, e5.event]);
  assert.equal(r.highWatermark, 5);
  assert.deepEqual(r.events.map((e) => e.state), ['visible', 'visible', 'visible']);
  assert.deepEqual(r.conflicts, []);
});

test('ingest idempotency records survive compaction of the events they wrote', async () => {
  const id = 'dev-cc-idem';
  const signer = new DeviceSigner();
  await registerDevice(h.pool, { deviceId: id, publicKeyRaw: signer.publicRaw });
  const chain = buildChain(signer, id, 3);
  const first = await ingest(id, 'rid-seed', chain);
  await compactDevice(h.pool, h.serverKey, h.cfg, id, 3, 'cp-idem');

  // Same requestId + same content replays the exact first response.
  const replay = await ingest(id, 'rid-seed', chain);
  assert.equal(replay.replayed, true);
  assert.deepEqual(replay.events, first.events);
  assert.equal(replay.highWatermark, first.highWatermark);

  // Same requestId with different content is still a stable 409.
  const other = buildChain(signer, id, 1, { payloadSeed: 99 })[0];
  await assert.rejects(
    () => ingest(id, 'rid-seed', [other]),
    (e) => e instanceof ApiError && e.code === 'IDEMPOTENCY_CONFLICT'
  );
});

test('compaction to the watermark racing a continuation ingest stays consistent', async () => {
  const id = 'dev-cc-race';
  const signer = new DeviceSigner();
  await registerDevice(h.pool, { deviceId: id, publicKeyRaw: signer.publicRaw });
  const chain = buildChain(signer, id, 3);
  await ingest(id, 'seed', chain);

  const e4 = signEvent(signer, {
    deviceId: id, sequence: 4, eventId: 'evt-4', occurredAt: '2026-01-02T00:00:04Z',
    keyVersion: 1, prevDigest: digestOf(chain[2]), payload: {},
  });
  // The device row lock serializes the two; either order must converge to the
  // same state: checkpoint at 3, watermark 4, event 4 visible.
  const [compactOut, ingestOut] = await Promise.all([
    compactDevice(h.pool, h.serverKey, h.cfg, id, 3, 'cp-race'),
    ingest(id, 'race-4', [e4.event]),
  ]);
  assert.equal(compactOut.checkpoint.sequence, 3);
  assert.equal(ingestOut.highWatermark, 4);
  assert.equal(await hwmOf(id), 4);

  const { rows } = await h.pool.query(
    `SELECT status FROM event_records WHERE device_id=$1 AND sequence=4 AND digest=$2`,
    [id, e4.digest]
  );
  assert.equal(rows[0].status, 'visible');
  const tail = await readPage(h.pool, h.serverKey, h.cfg, {
    deviceId: id, cursorToken: null, explicitAfterSequence: 3,
  });
  assert.deepEqual(tail.events.map((e) => e.sequence), [4]);
});
