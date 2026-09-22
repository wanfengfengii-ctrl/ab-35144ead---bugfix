'use strict';
// Conflicts: divergent candidates never overwrite, wrong predecessor blocks,
// adjudication is revision-guarded and idempotent, watermark only advances
// past a resolved conflict.
//
// Deterministic concurrency semantics (all writers of a device serialize on
// the devices row lock):
//  * Two different candidates for a sequence that is still BEYOND the frontier
//    (classic out-of-order backfill) form an open divergent_candidates
//    conflict; the prefix blocks at the previous sequence.
//  * A different candidate arriving at an ALREADY visible sequence forms an
//    open post_visibility_divergence conflict: the committed prefix can never
//    move backwards, but the divergence is queryable and only the visible
//    digest may be confirmed.

import { test, before, after, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import { setupHarness, stopTestPostgres, truncateAll } from './helpers/harness.mjs';
import { registerDevice } from '../src/services/devices.mjs';
import { ingestBatch } from '../src/services/ingest.mjs';
import { adjudicate, listConflicts, getConflict } from '../src/services/conflicts.mjs';
import { readPage } from '../src/services/reads.mjs';
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

async function hwmOf(id) {
  const { rows } = await h.pool.query('SELECT high_watermark FROM devices WHERE device_id=$1', [id]);
  return Number(rows[0].high_watermark);
}

test('two future forks create divergent_candidates; prefix blocks; adjudicate promotes the run', async () => {
  const id = 'dev-fork';
  const signer = new DeviceSigner();
  await registerDevice(h.pool, { deviceId: id, publicKeyRaw: signer.publicRaw });
  const chain = buildChain(signer, id, 3);

  // Two different seq-3 candidates arrive BEFORE 1 and 2 (offline backfill).
  const fork3 = resign(signer, chain[2], { payload: { fork: true } });
  await ingest(id, 'r-fork', [fork3]);
  const pre = await ingest(id, 'r-real3', [chain[2]]);
  assert.equal(pre.highWatermark, 0);
  assert.equal(pre.conflicts[0].reason, 'divergent_candidates');
  const revision = pre.conflicts[0].revision;

  // 1 and 2 then arrive; promotion stops at 2 because of the conflict at 3.
  const filled = await ingest(id, 'r-12', [chain[0], chain[1]]);
  assert.equal(filled.highWatermark, 2);

  // Select the honest chain candidate; the run promotes through 3.
  const adj = await adjudicate(h.pool, {
    deviceId: id, sequence: 3, commandId: 'cmd-1',
    expectedConflictRevision: revision,
    decision: { type: 'select', digest: digestOf(chain[2]) },
  });
  assert.equal(adj.highWatermark, 3);
  assert.equal(adj.resolution, 'selected');

  const page = await readPage(h.pool, h.serverKey, h.cfg, { deviceId: id });
  assert.equal(page.events.length, 3);
  assert.equal(page.events[2].payload.fork, undefined);
});

test('stale expectedConflictRevision is rejected', async () => {
  const id = 'dev-stale';
  const signer = new DeviceSigner();
  await registerDevice(h.pool, { deviceId: id, publicKeyRaw: signer.publicRaw });
  const chain = buildChain(signer, id, 2);
  const fork2 = resign(signer, chain[1], { payload: { x: 2 } });
  await ingest(id, 'a', [fork2]);
  const r = await ingest(id, 'b', [chain[1]]);
  const revision = r.conflicts[0].revision; // divergent at future seq 2

  await assert.rejects(
    () => adjudicate(h.pool, {
      deviceId: id, sequence: 2, commandId: 'cmd-stale',
      expectedConflictRevision: revision + 1,
      decision: { type: 'select', digest: digestOf(chain[1]) },
    }),
    (e) => e instanceof ApiError && e.code === 'CONFLICT_REVISION_MISMATCH'
  );
  const ok = await adjudicate(h.pool, {
    deviceId: id, sequence: 2, commandId: 'cmd-ok',
    expectedConflictRevision: revision,
    decision: { type: 'select', digest: digestOf(fork2) },
  });
  assert.equal(ok.resolution, 'selected');
});

test('adjudication commandId retries are idempotent and parameter changes conflict', async () => {
  const id = 'dev-adj-idem';
  const signer = new DeviceSigner();
  await registerDevice(h.pool, { deviceId: id, publicKeyRaw: signer.publicRaw });
  const chain = buildChain(signer, id, 1);
  const other = buildChain(signer, id, 1, { payloadSeed: 5 })[0];
  // Sequential at genesis: first promotes, second is post-visibility divergence.
  await ingest(id, 'a', [chain[0]]);
  const r2 = await ingest(id, 'b', [other]);
  assert.equal(r2.conflicts[0].reason, 'post_visibility_divergence');
  const revision = r2.conflicts[0].revision;

  const cmd = {
    deviceId: id, sequence: 1, commandId: 'cmd-idem',
    expectedConflictRevision: revision,
    decision: { type: 'select', digest: digestOf(chain[0]) },
  };
  const first = await adjudicate(h.pool, cmd);
  assert.equal(first.replayed, false);
  const again = await adjudicate(h.pool, cmd);
  assert.equal(again.replayed, true);
  assert.equal(again.chosenDigest, digestOf(chain[0]));

  await assert.rejects(
    () => adjudicate(h.pool, { ...cmd, decision: { type: 'select', digest: digestOf(other) } }),
    (e) => e instanceof ApiError && e.code === 'IDEMPOTENCY_CONFLICT'
  );
});

test('a different candidate cannot replace an already visible event', async () => {
  const id = 'dev-pvd';
  const signer = new DeviceSigner();
  await registerDevice(h.pool, { deviceId: id, publicKeyRaw: signer.publicRaw });
  const chain = buildChain(signer, id, 1);
  const other = buildChain(signer, id, 1, { payloadSeed: 7 })[0];
  await ingest(id, 'a', [chain[0]]);
  const r = await ingest(id, 'b', [other]);
  const revision = r.conflicts[0].revision;

  await assert.rejects(
    () => adjudicate(h.pool, {
      deviceId: id, sequence: 1, commandId: 'cmd-try-replace',
      expectedConflictRevision: revision,
      decision: { type: 'select', digest: digestOf(other) },
    }),
    (e) => e instanceof ApiError && e.code === 'CANNOT_REPLACE_VISIBLE_EVENT'
  );
  // The visible prefix is intact.
  assert.equal(await hwmOf(id), 1);
});

test('reject_all blocks until re-upload, then a fresh upload revives and promotes', async () => {
  const id = 'dev-rejectall';
  const signer = new DeviceSigner();
  await registerDevice(h.pool, { deviceId: id, publicKeyRaw: signer.publicRaw });
  const chain = buildChain(signer, id, 2);
  // A forked seq2, distinct from chain[1].
  const alt2 = resign(signer, chain[1], { payload: { alt: true } });
  await ingest(id, 'a', [alt2]);
  const r = await ingest(id, 'b', [chain[1]]);
  assert.equal(r.conflicts[0].reason, 'divergent_candidates');
  const revision = r.conflicts[0].revision;

  const rej = await adjudicate(h.pool, {
    deviceId: id, sequence: 2, commandId: 'cmd-rej',
    expectedConflictRevision: revision, decision: { type: 'reject_all' },
  });
  assert.equal(rej.resolution, 'rejected_all');
  assert.equal(rej.highWatermark, 0);

  // Upload seq 1: promotion stops at 1 since seq 2 has no live candidate.
  const p1 = await ingest(id, 'c', [chain[0]]);
  assert.equal(p1.highWatermark, 1);

  // Re-upload the honest seq 2: the rejected row revives and the run promotes.
  const re = await ingest(id, 'd', [chain[1]]);
  assert.equal(re.highWatermark, 2);
  assert.equal(re.conflicts.length, 0);
});

test('wrong prevDigest creates a bad_predecessor conflict that blocks higher events', async () => {
  const id = 'dev-badprev';
  const signer = new DeviceSigner();
  await registerDevice(h.pool, { deviceId: id, publicKeyRaw: signer.publicRaw });
  const chain = buildChain(signer, id, 3);
  await ingest(id, 'a', [chain[0]]);

  const bad2 = resign(signer, chain[1], { prevDigest: 'a'.repeat(64) });
  const r = await ingest(id, 'b', [bad2]);
  assert.equal(r.highWatermark, 1);
  assert.equal(r.conflicts[0].reason, 'bad_predecessor');

  // A perfectly good seq 3 still cannot become visible.
  const r3 = await ingest(id, 'c', [chain[2]]);
  assert.equal(r3.highWatermark, 1);

  // Reject the bad candidate, then re-upload the correct seq 2; run promotes.
  const c = await getConflict(h.pool, id, 2);
  await adjudicate(h.pool, {
    deviceId: id, sequence: 2, commandId: 'cmd-fix1',
    expectedConflictRevision: c.revision, decision: { type: 'reject_all' },
  });
  const fixed = await ingest(id, 'd', [chain[1]]);
  assert.equal(fixed.highWatermark, 3);
});

test('concurrent uploads of different genesis events never silently overwrite', async () => {
  const id = 'dev-concur';
  const signer = new DeviceSigner();
  await registerDevice(h.pool, { deviceId: id, publicKeyRaw: signer.publicRaw });
  const a = buildChain(signer, id, 1, { payloadSeed: 1 })[0];
  const b = buildChain(signer, id, 1, { payloadSeed: 2 })[0];
  await Promise.allSettled([
    ingest(id, 'gateway-a', [a]),
    ingest(id, 'gateway-b', [b]),
  ]);
  const open = await listConflicts(h.pool, id);
  assert.equal(open.conflicts.length, 1);
  assert.equal(open.conflicts[0].candidates.length, 2);
  assert.ok(['divergent_candidates', 'post_visibility_divergence'].includes(open.conflicts[0].reason));
  // Whichever committed first is a fully valid event; exactly one row visible.
  const { rows } = await h.pool.query(
    "SELECT count(*)::int AS n FROM event_records WHERE device_id=$1 AND status='visible'",
    [id]
  );
  assert.equal(rows[0].n, 1);
});

test('identical concurrent retries collapse onto one candidate and never conflict', async () => {
  const id = 'dev-same-concur';
  const signer = new DeviceSigner();
  await registerDevice(h.pool, { deviceId: id, publicKeyRaw: signer.publicRaw });
  const ev = buildChain(signer, id, 1)[0];
  const results = await Promise.all([
    ingest(id, 'same-rid', [ev]),
    ingest(id, 'same-rid', [ev]),
  ]);
  assert.deepEqual(results.map((r) => r.replayed).sort(), [false, true]);
  const open = await listConflicts(h.pool, id);
  assert.equal(open.conflicts.length, 0);
  assert.equal(await hwmOf(id), 1);
});
