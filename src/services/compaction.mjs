'use strict';
// History compaction.
//
// Invariants enforced in one transaction per device:
//  * only status='visible' events may be deleted (consecutively committed);
//  * the cutoff never crosses the earliest event an unexpired fixed view can
//    still read;
//  * the checkpoint row (device, cutoff digest, generatedAt, server signature,
//    hash link to the previous checkpoint) and the DELETE commit atomically,
//    so an event can never be both unreadable and uncovered;
//  * cutoff strictly advances the latest checkpoint, whose stored digest is
//    re-read to prove the new checkpoint extends the real visible prefix;
//  * a per-device transaction advisory lock makes concurrent worker/manual
//    runs collapse instead of producing contradictory checkpoints; a crash
//    after commit leaves the checkpoint in place and the retry simply skips
//    ahead (checkpoint insertion is idempotent by primary key).

import { withTransaction } from '../db/pool.mjs';
import { errors } from '../errors.mjs';
import { canonicalCheckpoint, signCheckpoint } from '../crypto/checkpoint.mjs';
import { digestHex } from '../crypto/envelope.js';
import { canonicalize } from '../crypto/canonical.js';

// Stable 64-bit advisory-lock key derived from a device id string.
function lockKey(deviceId) {
  // FNV-1a 64-ish folded into a signed bigint range.
  let h = 0x811c9dc5;
  for (let i = 0; i < deviceId.length; i++) {
    h ^= deviceId.charCodeAt(i);
    h = Math.imul(h, 0x01000193) >>> 0;
  }
  return h % 2_147_483_647;
}

/**
 * Create one checkpoint for a device.
 * @param desiredCutoff explicit cutoff (manual compaction) or null (policy)
 * @param commandId optional idempotency token for a manual compaction
 * @returns checkpoint response, or null if nothing eligible
 */
export async function compactDevice(pool, serverKey, cfg, deviceId, desiredCutoff = null, commandId = null) {
  const requestHash = digestHex(
    canonicalize({ kind: 'compact', deviceId, cutoffSequence: desiredCutoff })
  );
  return withTransaction(pool, async (client) => {
    if (commandId !== null) {
      const replay = await client.query(
        'SELECT request_hash, response FROM admin_commands WHERE command_id=$1 AND kind=$2',
        [commandId, 'compact']
      );
      if (replay.rows.length) {
        const r = replay.rows[0];
        if (r.request_hash !== requestHash) {
          throw errors.conflict(
            'IDEMPOTENCY_CONFLICT',
            `commandId ${commandId} was already used with different parameters`,
            { commandId }
          );
        }
        return { ...r.response, replayed: true };
      }
    }

    const gotLock = await client.query('SELECT pg_try_advisory_xact_lock($1) AS ok', [lockKey(deviceId)]);
    if (!gotLock.rows[0].ok) return null; // another compaction is running

    const dev = await client.query(
      'SELECT high_watermark FROM devices WHERE device_id=$1 FOR UPDATE',
      [deviceId]
    );
    if (dev.rows.length === 0) throw errors.deviceNotFound(deviceId);
    const hwm = Number(dev.rows[0].high_watermark);

    const prev = await client.query(
      'SELECT sequence, digest, prev_checkpoint_digest, generated_at, signature FROM checkpoints WHERE device_id=$1 ORDER BY sequence DESC LIMIT 1',
      [deviceId]
    );
    const prevSeq = prev.rows.length ? Number(prev.rows[0].sequence) : 0;

    let cutoff;
    if (desiredCutoff === null) {
      // Background policy: keep `retentionEvents` newest events, and do not
      // bother until at least one event beyond the previous cutoff is eligible.
      cutoff = hwm - cfg.compaction.retentionEvents;
      if (cutoff <= prevSeq) return null;
      if (hwm < cfg.compaction.minEvents) return null;
    } else {
      if (desiredCutoff > hwm) {
        throw errors.conflict(
          'CUTOFF_BEYOND_WATERMARK',
          `cutoffSequence ${desiredCutoff} exceeds highWatermark ${hwm}`,
          { deviceId, highWatermark: hwm, cutoffSequence: desiredCutoff }
        );
      }
      cutoff = desiredCutoff;
      if (cutoff <= prevSeq) {
        // Idempotent: an equal-or-later checkpoint already covers this request.
        const skipped = { deviceId, skipped: true, latestCheckpointSequence: prevSeq };
        if (commandId !== null) {
          await client.query(
            `INSERT INTO admin_commands (command_id, device_id, kind, request_hash, conflict, response)
             VALUES ($1,$2,'compact',$3,false,$4)`,
            [commandId, deviceId, requestHash, JSON.stringify(skipped)]
          );
        }
        return skipped;
      }
    }

    // Never cross an active fixed view: an event may be deleted only if every
    // unexpired view's first readable sequence is strictly above it. A view
    // with start_sequence s reads from s+1 (or from s when s=0), so the
    // largest safe cutoff is min(start_sequence) (view at 0 blocks deletion).
    const viewFloor = await client.query(
      `SELECT COALESCE(min(start_sequence), $2::bigint) AS floor_seq
         FROM read_views
        WHERE device_id=$1 AND expires_at > now()`,
      [deviceId, hwm]
    );
    const safeCutoff = Math.min(cutoff, Number(viewFloor.rows[0].floor_seq));
    if (safeCutoff <= prevSeq) return null; // active views pin the history

    // The cutoff event must be a real event of the consecutive prefix.
    const { rows: evRows } = await client.query(
      `SELECT digest FROM event_records
        WHERE device_id=$1 AND sequence=$2 AND status='visible'`,
      [deviceId, safeCutoff]
    );
    if (evRows.length === 0) {
      throw errors.internal(`no visible event at cutoff ${safeCutoff}`);
    }
    const cutoffDigest = evRows[0].digest;

    let prevCheckpointDigest;
    if (prev.rows.length === 0) {
      prevCheckpointDigest = '0'.repeat(64);
    } else {
      const p = prev.rows[0];
      // Recompute over the EXACT canonical bytes of the previous checkpoint so
      // the chain can be verified by clients from public fields alone.
      const { bytes } = canonicalCheckpoint({
        deviceId,
        sequence: Number(p.sequence),
        digest: p.digest,
        prevCheckpointDigest: p.prev_checkpoint_digest,
        generatedAt: p.generated_at.toISOString(),
      });
      prevCheckpointDigest = digestHex(bytes);
    }

    const generatedAt = new Date().toISOString();
    const cp = signCheckpoint(serverKey, {
      deviceId,
      sequence: safeCutoff,
      digest: cutoffDigest,
      prevCheckpointDigest,
      generatedAt,
    });

    await client.query(
      `INSERT INTO checkpoints
         (device_id, sequence, digest, prev_checkpoint_digest, generated_at, signature)
       VALUES ($1,$2,$3,$4,$5,$6)`,
      [
        deviceId, safeCutoff, cutoffDigest, prevCheckpointDigest,
        generatedAt, Buffer.from(cp.signature, 'base64url'),
      ]
    );

    const deleted = await client.query(
      `DELETE FROM event_records
        WHERE device_id=$1 AND status='visible' AND sequence <= $2`,
      [deviceId, safeCutoff]
    );

    const checkpoint = {
      ...cp,
      signerPublicKey: serverKey.publicB64Url,
    };
    const result = {
      deviceId,
      checkpoint,
      deletedEvents: deleted.rowCount,
      retainedEvents: hwm - safeCutoff,
    };

    if (commandId !== null) {
      await client.query(
        `INSERT INTO admin_commands (command_id, device_id, kind, request_hash, conflict, response)
         VALUES ($1,$2,'compact',$3,false,$4)`,
        [commandId, deviceId, requestHash, JSON.stringify(result)]
      );
    }
    return result;
  });
}

/** One background pass: expire views and checkpoint eligible devices. */
export async function compactionPass(pool, serverKey, cfg, log = console) {
  const summary = { devices: 0, checkpoints: 0, deletedEvents: 0 };
  await withTransaction(pool, async (client) => {
    await client.query('DELETE FROM read_views WHERE expires_at <= now()');
  });

  const { rows } = await pool.query(
    `SELECT d.device_id
       FROM devices d
      WHERE d.high_watermark >= $1
      ORDER BY d.device_id`,
    [cfg.compaction.minEvents]
  );
  for (const { device_id: deviceId } of rows) {
    summary.devices++;
    try {
      const r = await compactDevice(pool, serverKey, cfg, deviceId);
      if (r?.checkpoint) {
        summary.checkpoints++;
        summary.deletedEvents += r.deletedEvents;
        log.info?.({
          msg: 'checkpoint created',
          deviceId, sequence: r.checkpoint.sequence, deletedEvents: r.deletedEvents,
        });
      }
    } catch (e) {
      // One bad device must not kill the worker loop; the pass is retried.
      log.error?.({ msg: 'compaction failed', deviceId, err: e.message });
    }
  }
  return summary;
}
