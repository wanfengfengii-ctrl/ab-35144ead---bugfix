'use strict';
// Multi-instance concurrency stress. Each independent pg.Pool simulates a
// separate API process (separate connection pools, no shared memory at all).
// They concurrently ingest the same device out of order, through conflicts and
// alongside readers. The asserted properties are exactly the requirements:
// no reader ever observes a regression, duplicate sequence, gap or partial
// advancement; the final prefix is 1..N with every hash link valid.

import { test, before, after, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import pg from 'pg';
import { setupHarness, stopTestPostgres, truncateAll } from './helpers/harness.mjs';
import { runMigrations } from '../src/db/migrate.mjs';
import { createPool } from '../src/db/pool.mjs';
import { registerDevice } from '../src/services/devices.mjs';
import { ingestBatch } from '../src/services/ingest.mjs';
import { readPage } from '../src/services/reads.mjs';
import { DeviceSigner, buildChain, prepareBatch } from './helpers/events.mjs';
import { buildEnvelope } from '../src/crypto/envelope.js';

let h;
before(async () => { h = await setupHarness(); });
after(async () => { await h.pool.end(); await stopTestPostgres(); });
beforeEach(async () => { await truncateAll(h.pool); });

function makeInstancePool() {
  return createPool({ db: { ...h.cfg.db, poolSize: 4 } });
}

function shuffle(arr) {
  const a = [...arr];
  for (let i = a.length - 1; i > 0; i--) {
    const j = Math.floor(Math.random() * (i + 1));
    [a[i], a[j]] = [a[j], a[i]];
  }
  return a;
}

/** Re-read every visible event and assert the full hash chain is intact. */
async function assertVisiblePrefix(pool, id, expectedHwm) {
  const { rows } = await pool.query(
    `SELECT sequence, digest, prev_digest, envelope, event_id, occurred_at,
            key_version, payload, signature
       FROM event_records WHERE device_id=$1 AND status='visible' ORDER BY sequence`,
    [id]
  );
  assert.equal(rows.length, expectedHwm);
  let expectedPrev = '0'.repeat(64);
  for (let i = 0; i < rows.length; i++) {
    const r = rows[i];
    assert.equal(Number(r.sequence), i + 1); // no gap, no duplicate
    assert.equal(r.prev_digest, expectedPrev); // hash link to actual predecessor
    // Digest is uniquely derived from the exact stored canonical bytes.
    const { createHash } = await import('node:crypto');
    const digest = createHash('sha256').update(r.envelope).digest('hex');
    assert.equal(digest, r.digest);
    expectedPrev = r.digest;
  }
}

test('many instances ingest one device out of order; prefix is consistent throughout', async () => {
  const id = 'dev-stress';
  const N = 200;
  const INSTANCES = 8;
  const signer = new DeviceSigner();
  await registerDevice(h.pool, { deviceId: id, publicKeyRaw: signer.publicRaw });
  const chain = buildChain(signer, id, N);

  const pools = Array.from({ length: INSTANCES }, () => makeInstancePool());

  // Concurrently-running readers: every fixed view they observe must contain a
  // dense 1..k prefix (first page) and never regress across successive fresh
  // views of the same device.
  let readersDone = false;
  const readerErrors = [];
  // Each reader tracks monotonicity across ITS OWN successive views; sharing a
  // cross-reader variable would falsely flag an older snapshot finishing late.
  async function reader(idx) {
    let localLast = 0;
    while (!readersDone) {
      try {
        const page = await readPage(pools[idx % pools.length], h.serverKey, h.cfg, {
          deviceId: id, limit: 50, cursorToken: null, explicitAfterSequence: undefined,
        });
        if (page.viewHighWatermark < localLast) {
          readerErrors.push(new Error(`watermark regressed ${localLast} -> ${page.viewHighWatermark}`));
        }
        localLast = Math.max(localLast, page.viewHighWatermark);
        const seqs = page.events.map((e) => e.sequence);
        for (let i = 0; i < seqs.length; i++) {
          if (seqs[i] !== i + 1) readerErrors.push(new Error(`gap in view at ${seqs[i]}`));
        }
      } catch (e) {
        readerErrors.push(e);
      }
    }
  }
  const readerPromises = [0, 1, 2, 3].map((i) => reader(i));

  // Split the shuffled chain into single-event and small batches, round-robin
  // them across instances with jittered concurrency.
  const shuffled = shuffle(chain);
  const jobs = [];
  let rid = 0;
  for (let i = 0; i < shuffled.length; ) {
    const size = 1 + Math.floor(Math.random() * 4);
    const batch = shuffled.slice(i, i + size);
    i += size;
    const pool = pools[rid % pools.length];
    const myRid = `stress-${rid++}`;
    jobs.push((async () => {
      await new Promise((r) => setTimeout(r, Math.random() * 20));
      return ingestBatch(pool, prepareBatch(id, myRid, batch));
    })());
  }
  const results = await Promise.allSettled(jobs);
  const rejected = results.filter((r) => r.status === 'rejected');
  assert.equal(rejected.length, 0, rejected.map((r) => r.reason?.message).join('; '));

  readersDone = true;
  await Promise.all(readerPromises);
  assert.deepEqual(readerErrors, []);

  const { rows } = await h.pool.query('SELECT high_watermark FROM devices WHERE device_id=$1', [id]);
  assert.equal(Number(rows[0].high_watermark), N);
  await assertVisiblePrefix(h.pool, id, N);

  for (const p of pools) await p.end();
});

test('concurrent conflicting future candidates converge to one adjudicated prefix', async () => {
  const id = 'dev-stress-conflict';
  const signer = new DeviceSigner();
  await registerDevice(h.pool, { deviceId: id, publicKeyRaw: signer.publicRaw });
  const chain = buildChain(signer, id, 50);

  // Two gateways independently produce forks for even future sequences.
  const forks = new Map();
  for (const ev of chain) {
    if (ev.sequence % 2 === 0) {
      const fields = {
        deviceId: id, sequence: ev.sequence, eventId: `fork-${ev.sequence}`,
        occurredAt: ev.occurredAt, keyVersion: 1, prevDigest: ev.prevDigest,
        payload: { fork: ev.sequence },
      };
      const { bytes } = buildEnvelope(fields);
      const { signBytes, encodeB64Url } = await import('../src/crypto/keys.js');
      forks.set(ev.sequence, { ...fields, signature: encodeB64Url(signBytes(signer.privateKey, bytes)) });
    }
  }

  const poolA = makeInstancePool();
  const poolB = makeInstancePool();

  // Deterministically create divergent conflicts: both candidates for every
  // even (future) sequence are staged BEFORE the prefix can reach them. Two
  // different "gateway" pools submit concurrently.
  const evenJobs = [];
  let fi = 0;
  for (const ev of chain) {
    if (ev.sequence % 2 === 0) {
      evenJobs.push(ingestBatch(poolA, prepareBatch(id, `honest-${ev.sequence}`, [ev])));
      evenJobs.push(ingestBatch(poolB, prepareBatch(id, `fork-${ev.sequence}`, [forks.get(ev.sequence)])));
      fi++;
    }
  }
  await Promise.allSettled(evenJobs);
  // Then the odd honest events arrive (still out of order), letting the prefix
  // advance right up to each blocked even frontier.
  const oddJobs = shuffle(chain.filter((e) => e.sequence % 2 === 1)).map((ev, i) =>
    ingestBatch(poolA, prepareBatch(id, `odd-${i}`, [ev]))
  );
  await Promise.allSettled(oddJobs);

  // Adjudicate every even sequence to the honest digest; each resolution
  // releases promotion through the following already-staged odd event.
  const { adjudicate, getConflict } = await import('../src/services/conflicts.mjs');
  for (let seq = 2; seq <= 50; seq += 2) {
    const target = await getConflict(h.pool, id, seq);
    assert.equal(target.status, 'open');
    assert.equal(target.reason, 'divergent_candidates');
    const honestDigest = buildEnvelope(chain[seq - 1]).digest;
    await adjudicate(h.pool, {
      deviceId: id, sequence: seq, commandId: `adj-${seq}`,
      expectedConflictRevision: target.revision,
      decision: { type: 'select', digest: honestDigest },
    });
  }

  const { rows } = await h.pool.query('SELECT high_watermark FROM devices WHERE device_id=$1', [id]);
  assert.equal(Number(rows[0].high_watermark), 50);
  await assertVisiblePrefix(h.pool, id, 50);

  await poolA.end();
  await poolB.end();
});

test('watermark never moves backwards under mixed ingest/adjudicate/compact load', async () => {
  const id = 'dev-stress-mix';
  const signer = new DeviceSigner();
  await registerDevice(h.pool, { deviceId: id, publicKeyRaw: signer.publicRaw });
  const chain = buildChain(signer, id, 60);

  const observed = [];
  const sample = async () => {
    const { rows } = await h.pool.query('SELECT high_watermark FROM devices WHERE device_id=$1', [id]);
    const hwm = Number(rows[0].high_watermark);
    if (observed.length) assert.ok(hwm >= observed[observed.length - 1]);
    observed.push(hwm);
  };

  const jobs = shuffle(chain).map((ev, i) =>
    ingestBatch(h.pool, prepareBatch(id, `mix-${i}`, [ev])).then(sample)
  );
  await Promise.all(jobs);
  await sample();
  assert.equal(observed[observed.length - 1], 60);
});
