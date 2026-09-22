'use strict';
// Device registration and Ed25519 key rotation. All mutual exclusion is the
// devices row lock (SELECT ... FOR UPDATE); control_revision is the optimistic
// concurrency token exposed to administrators.

import { withTransaction } from '../db/pool.mjs';
import { errors } from '../errors.mjs';
import { digestHex } from '../crypto/envelope.js';
import { canonicalize } from '../crypto/canonical.js';
import { encodeB64Url } from '../crypto/keys.js';

function keyRowToApi(row) {
  return {
    keyVersion: Number(row.key_version),
    effectiveSequence: Number(row.effective_sequence),
    publicKey: encodeB64Url(row.public_key),
    createdAt: row.created_at.toISOString(),
  };
}

export async function registerDevice(pool, { deviceId, publicKeyRaw }) {
  return withTransaction(pool, async (client) => {
    const existing = await client.query(
      'INSERT INTO devices (device_id) VALUES ($1) ON CONFLICT (device_id) DO NOTHING RETURNING device_id, control_revision',
      [deviceId]
    );
    let controlRevision;
    let created = true;
    if (existing.rows.length === 0) {
      created = false;
      const dev = await client.query('SELECT control_revision FROM devices WHERE device_id=$1', [deviceId]);
      controlRevision = Number(dev.rows[0].control_revision);
    } else {
      controlRevision = Number(existing.rows[0].control_revision);
    }
    const keyInsert = await client.query(
      `INSERT INTO device_keys (device_id, key_version, public_key, effective_sequence)
       VALUES ($1, 1, $2, 1)
       ON CONFLICT (device_id, key_version) DO NOTHING
       RETURNING key_version`,
      [deviceId, publicKeyRaw]
    );
    if (keyInsert.rows.length === 0) {
      // Re-registration: deterministic. Same key -> idempotent replay of the
      // current state; different key -> conflict, the first key is immutable.
      const first = await client.query(
        'SELECT public_key FROM device_keys WHERE device_id=$1 AND key_version=1',
        [deviceId]
      );
      if (!first.rows[0].public_key.equals(publicKeyRaw)) {
        throw errors.conflict(
          'DEVICE_ALREADY_REGISTERED',
          `device ${deviceId} is already registered with a different initial public key`,
          { deviceId, controlRevision }
        );
      }
    }
    return {
      deviceId,
      created,
      keyVersion: 1,
      effectiveSequence: 1,
      controlRevision,
    };
  });
}

function adminHash(kind, body) {
  return digestHex(canonicalize({ kind, ...body }));
}

export async function rotateKey(pool, cmd) {
  const { deviceId, commandId, keyVersion, effectiveSequence, expectedControlRevision, publicKeyRaw } = cmd;
  const requestHash = adminHash('rotate', {
    deviceId, commandId, keyVersion, effectiveSequence,
    expectedControlRevision,
  });
  // NOTE: the public key is part of the command content too.
  const fullHash = digestHex(Buffer.concat([Buffer.from(requestHash, 'hex'), publicKeyRaw]));

  return withTransaction(pool, async (client) => {
    const replay = await client.query(
      'SELECT request_hash, conflict, response FROM admin_commands WHERE command_id=$1 AND kind=$2',
      [commandId, 'rotate']
    );
    if (replay.rows.length) {
      const r = replay.rows[0];
      if (r.request_hash !== fullHash) {
        throw errors.conflict(
          'IDEMPOTENCY_CONFLICT',
          `commandId ${commandId} was already used with different parameters`,
          { commandId, deviceId: r.response.deviceId }
        );
      }
      return { ...r.response, replayed: true };
    }

    const dev = await client.query(
      'SELECT high_watermark, control_revision FROM devices WHERE device_id=$1 FOR UPDATE',
      [deviceId]
    );
    if (dev.rows.length === 0) throw errors.deviceNotFound(deviceId);
    const hwm = Number(dev.rows[0].high_watermark);
    const currentRevision = Number(dev.rows[0].control_revision);

    if (currentRevision !== expectedControlRevision) {
      throw errors.conflict(
        'CONTROL_REVISION_MISMATCH',
        `expectedControlRevision ${expectedControlRevision} does not match current revision ${currentRevision}`,
        { deviceId, currentRevision, expectedControlRevision }
      );
    }

    const keys = await client.query(
      'SELECT key_version, effective_sequence FROM device_keys WHERE device_id=$1 ORDER BY key_version',
      [deviceId]
    );
    const maxVersion = Number(keys.rows[keys.rows.length - 1].key_version);
    if (keyVersion !== maxVersion + 1) {
      throw errors.conflict(
        'KEY_VERSION_CONFLICT',
        `keyVersion must be exactly ${maxVersion + 1} (the next generation); reuse and gaps are not allowed`,
        { deviceId, expectedKeyVersion: maxVersion + 1, providedKeyVersion: keyVersion }
      );
    }
    if (effectiveSequence <= hwm) {
      throw errors.conflict(
        'EFFECTIVE_SEQUENCE_NOT_AHEAD_OF_WATERMARK',
        `effectiveSequence must be strictly greater than the current contiguous watermark ${hwm}`,
        { deviceId, highWatermark: hwm, effectiveSequence }
      );
    }
    const overlaps = keys.rows.find((r) => Number(r.effective_sequence) === effectiveSequence);
    if (overlaps) {
      throw errors.conflict(
        'OVERLAPPING_EFFECTIVE_RANGE',
        `effectiveSequence ${effectiveSequence} is already used by keyVersion ${overlaps.key_version}`,
        { deviceId, effectiveSequence, conflictingKeyVersion: Number(overlaps.key_version) }
      );
    }
    // Deterministic handling of a boundary already occupied by staged events.
    // Any staged event at or beyond the new effectiveSequence must have been
    // signed by a key generation that existed before the rotation (i.e. the
    // old key), which must never be accepted past the boundary. Rejecting the
    // rotation is the only outcome that does not strand such events into a
    // later key_generation_invalid conflict; strictly-below events stay valid
    // under the old key and may still promote.
    const occupied = await client.query(
      `SELECT min(sequence) AS s FROM event_records
        WHERE device_id=$1 AND status='staged' AND sequence >= $2`,
      [deviceId, effectiveSequence]
    );
    if (occupied.rows[0].s !== null) {
      throw errors.conflict(
        'ROTATION_BOUNDARY_OCCUPIED',
        `staged events already exist at or beyond effectiveSequence ${effectiveSequence}; ` +
          'choose a boundary beyond all staged sequences',
        { deviceId, effectiveSequence, firstOccupiedSequence: Number(occupied.rows[0].s) }
      );
    }

    await client.query(
      `INSERT INTO device_keys (device_id, key_version, public_key, effective_sequence)
       VALUES ($1, $2, $3, $4)`,
      [deviceId, keyVersion, publicKeyRaw, effectiveSequence]
    );
    const nextRevision = currentRevision + 1;
    await client.query(
      'UPDATE devices SET control_revision=$2, updated_at=now() WHERE device_id=$1',
      [deviceId, nextRevision]
    );
    // Promotion cannot cross the new boundary until new-key events arrive, but
    // old-key events already staged below the boundary may now promote.
    await client.query('SELECT try_advance($1)', [deviceId]);

    const response = {
      deviceId, commandId, keyVersion, effectiveSequence,
      controlRevision: nextRevision,
    };
    await client.query(
      `INSERT INTO admin_commands (command_id, device_id, kind, request_hash, conflict, response)
       VALUES ($1,$2,'rotate',$3,false,$4)`,
      [commandId, deviceId, fullHash, JSON.stringify(response)]
    );
    return { ...response, replayed: false };
  });
}

export async function getDevice(pool, deviceId) {
  const { rows } = await pool.query(
    `SELECT d.device_id, d.high_watermark, d.control_revision, d.created_at, d.updated_at
       FROM devices d WHERE d.device_id=$1`,
    [deviceId]
  );
  if (rows.length === 0) throw errors.deviceNotFound(deviceId);
  const [keys, cp] = await Promise.all([
    pool.query(
      'SELECT key_version, effective_sequence, public_key, created_at FROM device_keys WHERE device_id=$1 ORDER BY key_version',
      [deviceId]
    ),
    pool.query(
      `SELECT sequence, digest, prev_checkpoint_digest, generated_at, signature
         FROM checkpoints WHERE device_id=$1 ORDER BY sequence DESC LIMIT 1`,
      [deviceId]
    ),
  ]);
  const out = {
    deviceId,
    highWatermark: Number(rows[0].high_watermark),
    controlRevision: Number(rows[0].control_revision),
    keys: keys.rows.map(keyRowToApi),
    createdAt: rows[0].created_at.toISOString(),
    updatedAt: rows[0].updated_at.toISOString(),
  };
  if (cp.rows.length) {
    const c = cp.rows[0];
    out.latestCheckpoint = {
      sequence: Number(c.sequence),
      digest: c.digest,
      prevCheckpointDigest: c.prev_checkpoint_digest,
      generatedAt: c.generated_at.toISOString(),
      signature: encodeB64Url(c.signature),
    };
  }
  return out;
}
