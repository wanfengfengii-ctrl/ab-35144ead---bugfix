'use strict';
// Batch ingestion. The whole batch is validated (structure, signatures, key
// generation) BEFORE any row is written, and every row plus the idempotency
// record plus watermark advancement commit in one transaction holding the
// device row lock. Different devices therefore ingest concurrently across
// instances; only submissions touching one device serialize, and they
// serialize on a DATABASE lock, never on an in-process mutex.

import { withTransaction } from '../db/pool.mjs';
import { errors, ApiError } from '../errors.mjs';
import { buildEnvelope, ZERO_DIGEST, digestHex } from '../crypto/envelope.js';
import { rawToPublicKeyObject, verifyBytes } from '../crypto/keys.js';
import { canonicalize } from '../crypto/canonical.js';

function requestFingerprint({ deviceId, events }) {
  // Content identity for idempotency: exact canonical event fields including
  // the signature, canonicalized so field order cannot matter.
  const content = canonicalize({
    deviceId,
    events: events.map((e) => ({
      deviceId: e.deviceId,
      sequence: e.sequence,
      eventId: e.eventId,
      occurredAt: e.occurredAt,
      keyVersion: e.keyVersion,
      prevDigest: e.prevDigest,
      payload: e.payload,
      signature: e.signatureB64,
    })),
  });
  return digestHex(content);
}

/**
 * @param {Pool} pool
 * @param {{deviceId:string, requestId:string, events: Array}} batch
 */
export async function ingestBatch(pool, batch) {
  const { deviceId, requestId, events } = batch;
  const fingerprint = requestFingerprint(batch);

  try {
    return await withTransaction(pool, async (client) => {
      // Serialize all writers of one device on this row lock.
      const dev = await client.query(
        'SELECT high_watermark FROM devices WHERE device_id=$1 FOR UPDATE',
        [deviceId]
      );
      if (dev.rows.length === 0) throw errors.deviceNotFound(deviceId);

      // Same-device retries are fully serialized by the lock above; this read
      // therefore always observes the winner's committed record.
      const prior = await client.query(
        'SELECT request_hash, response FROM ingest_requests WHERE request_id=$1',
        [requestId]
      );
      if (prior.rows.length) {
        return handlePrior(prior.rows[0], fingerprint);
      }

      // ---- Load all key generations of this device -----------------------
      const keyRows = await client.query(
        'SELECT key_version, public_key, effective_sequence FROM device_keys WHERE device_id=$1',
        [deviceId]
      );
      if (keyRows.rows.length === 0) {
        throw errors.internal('device has no key generations');
      }
      const keysByVersion = new Map();
      const boundaries = [];
      for (const r of keyRows.rows) {
        const kv = Number(r.key_version);
        keysByVersion.set(kv, { raw: r.public_key, effective: Number(r.effective_sequence) });
        boundaries.push({ kv, effective: Number(r.effective_sequence) });
      }
      boundaries.sort((a, b) => a.effective - b.effective);
      const ownerOf = (seq) => {
        let owner = boundaries[0].kv;
        for (const b of boundaries) {
          if (seq >= b.effective) owner = b.kv;
          else break;
        }
        return owner;
      };
      const keyObjects = new Map();
      const keyObj = (kv) => {
        if (!keyObjects.has(kv)) keyObjects.set(kv, rawToPublicKeyObject(keysByVersion.get(kv).raw));
        return keyObjects.get(kv);
      };

      // ---- Phase 1: pure validation, no writes ---------------------------
      // Every event re-derives its envelope from the exact request fields and
      // verifies the Ed25519 signature against the generation that owns the
      // sequence. Any failure aborts the whole batch atomically.
      const prepared = new Array(events.length);
      for (let i = 0; i < events.length; i++) {
        const e = events[i];
        if (e.sequence === 1 && e.prevDigest !== ZERO_DIGEST) {
          throw new ApiError(
            'INVALID_GENESIS_PREV_DIGEST',
            422,
            `events[${i}]: sequence 1 must carry prevDigest = ${ZERO_DIGEST}`,
            { index: i, sequence: 1 }
          );
        }
        const owner = ownerOf(e.sequence);
        if (!keysByVersion.has(e.keyVersion)) {
          throw new ApiError(
            'UNKNOWN_KEY_VERSION',
            422,
            `events[${i}]: keyVersion ${e.keyVersion} is not registered for this device`,
            { index: i, sequence: e.sequence, keyVersion: e.keyVersion }
          );
        }
        if (e.keyVersion !== owner) {
          throw new ApiError(
            'KEY_GENERATION_MISMATCH',
            422,
            `events[${i}]: sequence ${e.sequence} must be signed by keyVersion ${owner}, got ${e.keyVersion}`,
            {
              index: i,
              sequence: e.sequence,
              requiredKeyVersion: owner,
              providedKeyVersion: e.keyVersion,
            }
          );
        }
        const { bytes, digest } = buildEnvelope(e);
        if (!verifyBytes(keyObj(e.keyVersion), bytes, e.signature)) {
          throw new ApiError(
            'SIGNATURE_INVALID',
            422,
            `events[${i}]: Ed25519 signature does not verify against keyVersion ${e.keyVersion}`,
            { index: i, sequence: e.sequence, keyVersion: e.keyVersion, digest }
          );
        }
        prepared[i] = { ...e, envelope: bytes, digest };
      }

      // ---- Phase 2: persist candidates (all validation already passed) ----
      // Sequences already committed AND compacted are immutable history: an
      // identical retransmission collapses onto the digest tombstone as a
      // no-op (reported as 'compacted'), while a different digest is staged
      // as fork evidence and reconciled against the committed digest below.
      // The devices row lock held by this transaction serializes against
      // compaction, so the tombstone view read here cannot change underneath.
      const preparedSeqs = [...new Set(prepared.map((p) => p.sequence))];
      const { rows: tombRows } = await client.query(
        `SELECT sequence, digest FROM compacted_events
          WHERE device_id=$1 AND sequence = ANY($2::bigint[])`,
        [deviceId, preparedSeqs]
      );
      const compactedDigestBySeq = new Map(tombRows.map((r) => [Number(r.sequence), r.digest]));

      const affectedSeqs = new Map(); // seq -> addedNewDigest?
      const compactedNoop = new Set(); // digests of identical retransmissions
      for (const p of prepared) {
        const committed = compactedDigestBySeq.get(p.sequence);
        if (committed !== undefined && committed === p.digest) {
          compactedNoop.add(p.digest);
          continue;
        }

        const before = await client.query(
          `SELECT status FROM event_records
            WHERE device_id=$1 AND sequence=$2 AND digest=$3`,
          [deviceId, p.sequence, p.digest]
        );
        const existed = before.rows.length > 0;
        const wasRejected = existed && before.rows[0].status === 'rejected';
        const added = !existed || wasRejected;

        await client.query(
          `INSERT INTO event_records
             (device_id, sequence, digest, event_id, occurred_at, key_version,
              prev_digest, payload, envelope, signature, status)
           VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,'staged')
           ON CONFLICT (device_id, sequence, digest) DO UPDATE
             SET status = CASE WHEN event_records.status = 'rejected'
                               THEN 'staged' ELSE event_records.status END,
                 ingested_at = now(),
                 envelope = EXCLUDED.envelope,
                 signature = EXCLUDED.signature,
                 payload = EXCLUDED.payload`,
          [
            deviceId, p.sequence, p.digest, p.eventId, p.occurredAt,
            p.keyVersion, p.prevDigest, canonicalize(p.payload).toString('utf8'),
            p.envelope, p.signature,
          ]
        );
        // One event per sequence per batch (enforced in validation); a new
        // distinct digest or a revived rejected candidate is what may reopen
        // or create a conflict.
        affectedSeqs.set(p.sequence, (affectedSeqs.get(p.sequence) || false) || added);
      }

      for (const [seq, added] of affectedSeqs) {
        await client.query('SELECT reconcile_conflict($1,$2,$3)', [deviceId, seq, added]);
      }

      const adv = await client.query('SELECT try_advance($1) AS hwm', [deviceId]);
      const hwm = Number(adv.rows[0].hwm);

      // ---- Per-event final state ------------------------------------------
      const digests = prepared.map((p) => p.digest);
      const { rows: stateRows } = await client.query(
        `SELECT sequence, digest, status FROM event_records
          WHERE device_id=$1 AND (digest = ANY($2::text[]))`,
        [deviceId, digests]
      );
      const stateByDigest = new Map(stateRows.map((r) => [r.digest, r.status]));
      const accepted = prepared.map((p) => ({
        sequence: p.sequence,
        digest: p.digest,
        state: compactedNoop.has(p.digest) ? 'compacted' : stateByDigest.get(p.digest),
      }));

      const { rows: conflictRows } = await client.query(
        `SELECT sequence, reason, revision FROM conflicts
          WHERE device_id=$1 AND status='open'
            AND (sequence = ANY($2::bigint[]))
          ORDER BY sequence`,
        [deviceId, [...affectedSeqs.keys()]]
      );

      const response = {
        requestId,
        deviceId,
        highWatermark: hwm,
        events: accepted,
        conflicts: conflictRows.map((r) => ({
          sequence: Number(r.sequence),
          reason: r.reason,
          revision: Number(r.revision),
        })),
      };

      await client.query(
        `INSERT INTO ingest_requests (request_id, device_id, request_hash, conflict, response)
         VALUES ($1,$2,$3,false,$4)`,
        [requestId, deviceId, fingerprint, JSON.stringify(response)]
      );
      return { ...response, replayed: false };
    });
  } catch (e) {
    // Cross-device requestId race (same-device races are serialized by the
    // device lock): the unique constraint on ingest_requests is the final
    // arbiter. Re-read the winner's record and answer deterministically.
    if (e instanceof ApiError && e.code === 'INTERNAL_ERROR') throw e;
    if (e && e.code === '23505' && e.constraint === 'ingest_requests_pkey') {
      return replayStoredRequest(pool, requestId, fingerprint);
    }
    throw e;
  }
}

function handlePrior(row, fingerprint) {
  if (row.request_hash !== fingerprint) {
    throw errors.conflict(
      'IDEMPOTENCY_CONFLICT',
      'requestId was already submitted with different canonical content',
      { requestId: row.response?.requestId }
    );
  }
  return { ...row.response, replayed: true };
}

async function replayStoredRequest(pool, requestId, fingerprint) {
  const { rows } = await pool.query(
    'SELECT request_hash, response FROM ingest_requests WHERE request_id=$1',
    [requestId]
  );
  if (rows.length === 0) throw errors.internal('idempotency record vanished');
  return handlePrior(rows[0], fingerprint);
}
