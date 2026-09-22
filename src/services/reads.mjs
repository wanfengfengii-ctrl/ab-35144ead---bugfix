'use strict';
// Consecutive-event reads.
//
// Fixed views: the first page request snapshots (device, highWatermark) into
// read_views and returns viewHighWatermark plus an unforgeable cursor. Every
// later page with that cursor reads ONLY data inside the view; events that
// commit afterwards can never mix in. The cursor is signed and binds (view,
// device, position): tampering, cross-device use and parameter contradictions
// are all rejected.
//
// Waiting: /wait uses LISTEN/NOTIFY. The order is LISTEN -> read watermark
// -> block, so a notification produced between the check and the wait cannot
// be lost. On timeout an empty page is returned. Client disconnect releases
// the dedicated connection back to the pool immediately.

import { randomUUID } from 'node:crypto';
import { withTransaction } from '../db/pool.mjs';
import { errors } from '../errors.mjs';
import { signCursor } from '../crypto/checkpoint.mjs';
import { verifyCursor } from '../crypto/checkpoint.mjs';
import { encodeB64Url } from '../crypto/keys.js';

function eventRow(r) {
  return {
    deviceId: r.device_id,
    sequence: Number(r.sequence),
    digest: r.digest,
    eventId: r.event_id,
    occurredAt: r.occurred_at,
    keyVersion: Number(r.key_version),
    prevDigest: r.prev_digest,
    payload: r.payload,
    signature: encodeB64Url(r.signature),
  };
}

export async function getCheckpointPayload(pool, serverKey, deviceId, sequence) {
  const { rows } = await pool.query(
    `SELECT sequence, digest, prev_checkpoint_digest, generated_at, signature
       FROM checkpoints WHERE device_id=$1 AND sequence=$2`,
    [deviceId, sequence]
  );
  if (rows.length === 0) throw errors.internal('checkpoint row missing');
  const r = rows[0];
  return {
    deviceId,
    sequence: Number(r.sequence),
    digest: r.digest,
    prevCheckpointDigest: r.prev_checkpoint_digest,
    generatedAt: r.generated_at.toISOString(),
    signature: encodeB64Url(r.signature),
    signerPublicKey: serverKey.publicB64Url,
  };
}

/**
 * Open (or continue) a fixed view and fetch one page.
 * @param afterSequence null/0 to start a new view; otherwise a signed cursor
 */
export async function readPage(pool, serverKey, cfg, params) {
  const { deviceId, limit, cursorToken, explicitAfterSequence } = params;

  let view;
  let afterSequence;

  if (cursorToken) {
    const parsed = verifyCursor(serverKey, cursorToken);
    if (!parsed) throw errors.validation('invalid or tampered page cursor');
    if (parsed.deviceId !== deviceId) {
      throw errors.validation('cursor was issued for a different device', {
        cursorDeviceId: parsed.deviceId,
        deviceId,
      });
    }
    if (explicitAfterSequence !== undefined && explicitAfterSequence !== parsed.afterSequence) {
      throw errors.validation('afterSequence contradicts the cursor position', {
        cursorAfterSequence: parsed.afterSequence,
        afterSequence: explicitAfterSequence,
      });
    }
    afterSequence = parsed.afterSequence;

    const { rows } = await pool.query(
      `SELECT view_id, device_id, high_watermark, start_sequence, expires_at
         FROM read_views WHERE view_id=$1 AND device_id=$2`,
      [parsed.viewId, deviceId]
    );
    if (rows.length === 0) throw errors.gone('read view no longer exists');
    view = rows[0];
  } else {
    // First page: create the fixed snapshot.
    afterSequence = explicitAfterSequence ?? 0;
    if (!Number.isInteger(afterSequence) || afterSequence < 0) {
      throw errors.validation('afterSequence must be a non-negative integer');
    }
    view = await withTransaction(pool, async (client) => {
      const dev = await client.query(
        'SELECT high_watermark FROM devices WHERE device_id=$1 FOR SHARE',
        [deviceId]
      );
      if (dev.rows.length === 0) throw errors.deviceNotFound(deviceId);
      const hwm = Number(dev.rows[0].high_watermark);
      const viewId = randomUUID();
      const expiresAt = new Date(Date.now() + cfg.compaction.viewTtlMs);
      await client.query(
        `INSERT INTO read_views (view_id, device_id, high_watermark, start_sequence, expires_at)
         VALUES ($1,$2,$3,$4,$5)`,
        [viewId, deviceId, hwm, afterSequence, expiresAt]
      );
      return { view_id: viewId, device_id: deviceId, high_watermark: hwm, start_sequence: afterSequence };
    });
    if (afterSequence > Number(view.high_watermark)) {
      throw errors.validation('afterSequence is beyond the current high watermark', {
        afterSequence,
        viewHighWatermark: Number(view.high_watermark),
      });
    }
  }

  const viewHwm = Number(view.high_watermark);
  const pageSize = Math.min(Math.max(1, limit || cfg.defaultPageSize), cfg.maxPageSize);

  // Latest checkpoint: events at or below it may have been deleted.
  const { rows: cpRows } = await pool.query(
    'SELECT sequence FROM checkpoints WHERE device_id=$1 ORDER BY sequence DESC LIMIT 1',
    [deviceId]
  );
  const checkpointSeq = cpRows.length ? Number(cpRows[0].sequence) : 0;

  const expired = cursorToken && Date.parse(view.expires_at) < Date.now();

  if (afterSequence < checkpointSeq) {
    // The requested position is behind a checkpoint. Return 410 with a
    // verifiable recovery point rather than silently skipping auditable data.
    const cp = await getCheckpointPayload(pool, serverKey, deviceId, checkpointSeq);
    throw errors.gone(
      `events through sequence ${checkpointSeq} have been compacted into a checkpoint; ` +
        'verify the checkpoint signature and resume from checkpoint.sequence + 1',
      { checkpoint: cp, resumeFromSequence: checkpointSeq + 1 }
    );
  }

  if (expired) {
    throw errors.gone('read view has expired; open a new view');
  }

  if (afterSequence > viewHwm) {
    throw errors.validation('cursor position is beyond the view watermark');
  }

  const { rows } = await pool.query(
    `SELECT device_id, sequence, digest, event_id, occurred_at, key_version,
            prev_digest, payload, signature
       FROM event_records
      WHERE device_id=$1
        AND status='visible'
        AND sequence > $2
        AND sequence <= $3
      ORDER BY sequence
      LIMIT $4`,
    [deviceId, afterSequence, viewHwm, pageSize]
  );
  const events = rows.map(eventRow);
  const lastSeq = events.length ? Number(events[events.length - 1].sequence) : afterSequence;
  const nextCursor = lastSeq < viewHwm
    ? signCursor(serverKey, { viewId: view.view_id, deviceId, afterSequence: lastSeq })
    : null;

  return {
    deviceId,
    viewId: view.view_id,
    viewHighWatermark: viewHwm,
    fromSequence: afterSequence + 1,
    events,
    nextCursor,
    hasMore: nextCursor !== null,
  };
}

/**
 * Long-poll for new consecutive events.
 * @param signal AbortSignal from the HTTP request (client disconnect)
 */
export async function waitForEvents(pool, cfg, { deviceId, afterSequence, limit, signal }) {
  if (!Number.isInteger(afterSequence) || afterSequence < 0) {
    throw errors.validation('afterSequence must be a non-negative integer');
  }
  const pageSize = Math.min(Math.max(1, limit || cfg.defaultPageSize), cfg.maxPageSize);
  const maxWait = Math.min(cfg.waitTimeoutMs, 30_000);

  // Dedicated client: LISTEN state is per-connection. Released on every exit
  // path (including abort), so a disconnecting client never leaks a waiter or
  // a database connection.
  const client = await pool.connect();
  try {
    await client.query('LISTEN telemetry_events');

    const readBatch = async (from) => {
      const { rows } = await client.query(
        `SELECT device_id, sequence, digest, event_id, occurred_at, key_version,
                prev_digest, payload, signature
           FROM event_records
          WHERE device_id=$1 AND status='visible' AND sequence > $2
          ORDER BY sequence LIMIT $3`,
        [deviceId, from, pageSize]
      );
      return rows.map(eventRow);
    };

    // LISTEN happened BEFORE this check: any committing advancement either was
    // already visible here, or its NOTIFY is queued for the wait below.
    const dev = await client.query('SELECT high_watermark FROM devices WHERE device_id=$1', [deviceId]);
    if (dev.rows.length === 0) throw errors.deviceNotFound(deviceId);
    let hwm = Number(dev.rows[0].high_watermark);

    let events = hwm > afterSequence ? await readBatch(afterSequence) : [];
    if (events.length === 0) {
      await new Promise((resolve) => {
        let settled = false;
        let timer = null;
        const finish = () => {
          if (settled) return;
          settled = true;
          if (timer) clearTimeout(timer);
          signal?.removeEventListener('abort', onAbort);
          client.removeListener('notification', onNotification);
          resolve();
        };
        const onNotification = (msg) => {
          if (msg.channel === 'telemetry_events' && msg.payload === deviceId) finish();
        };
        const onAbort = () => finish();
        // node-postgres keeps parsing the socket stream while the connection
        // is idle, so NOTIFY arrives immediately with no polling query.
        client.on('notification', onNotification);
        signal?.addEventListener('abort', onAbort, { once: true });
        timer = setTimeout(finish, maxWait);
      });

      if (signal?.aborted) {
        const e = new Error('client closed request');
        e.code = 'ABORTED';
        throw e;
      }
      const again = await client.query('SELECT high_watermark FROM devices WHERE device_id=$1', [deviceId]);
      hwm = Number(again.rows[0].high_watermark);
      events = hwm > afterSequence ? await readBatch(afterSequence) : [];
    }

    return {
      deviceId,
      highWatermark: hwm,
      afterSequence,
      timeout: events.length === 0,
      events,
    };
  } finally {
    try {
      await client.query('UNLISTEN telemetry_events');
    } catch {
      // connection may already be gone
    }
    client.release();
  }
}
