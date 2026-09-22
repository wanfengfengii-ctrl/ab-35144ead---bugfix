'use strict';
// Conflict listing and adjudication. Adjudication is an idempotent admin
// command guarded by expectedConflictRevision: a stale revision can never
// overwrite a newer decision. A select/reject_all, the candidate status
// changes and watermark advancement commit in one transaction.

import { withTransaction } from '../db/pool.mjs';
import { errors } from '../errors.mjs';
import { canonicalize } from '../crypto/canonical.js';
import { digestHex } from '../crypto/envelope.js';
import { encodeB64Url } from '../crypto/keys.js';

function candidateRow(r) {
  return {
    sequence: Number(r.sequence),
    digest: r.digest,
    eventId: r.event_id,
    occurredAt: r.occurred_at,
    keyVersion: Number(r.key_version),
    prevDigest: r.prev_digest,
    payload: r.payload,
    signature: encodeB64Url(r.signature),
    status: r.status,
    ingestedAt: r.ingested_at.toISOString(),
  };
}

export async function listConflicts(pool, deviceId, { status = 'open', limit = 100 } = {}) {
  const dev = await pool.query('SELECT 1 FROM devices WHERE device_id=$1', [deviceId]);
  if (dev.rows.length === 0) throw errors.deviceNotFound(deviceId);
  const { rows } = await pool.query(
    `SELECT c.sequence, c.status, c.revision, c.reason, c.resolution, c.chosen_digest,
            c.decided_command_id, c.created_at, c.resolved_at
       FROM conflicts c
      WHERE c.device_id=$1 AND ($2::text = 'all' OR c.status = $2)
      ORDER BY c.sequence
      LIMIT $3`,
    [deviceId, status, limit]
  );
  const seqs = rows.map((r) => Number(r.sequence));
  let candidates = [];
  if (seqs.length) {
    const { rows: candRows } = await pool.query(
      `SELECT sequence, digest, event_id, occurred_at, key_version, prev_digest,
              payload, signature, status, ingested_at
         FROM event_records
        WHERE device_id=$1 AND sequence = ANY($2::bigint[])
        ORDER BY sequence, digest`,
      [deviceId, seqs]
    );
    candidates = candRows.map(candidateRow);
  }
  const bySeq = new Map();
  for (const c of candidates) {
    if (!bySeq.has(c.sequence)) bySeq.set(c.sequence, []);
    bySeq.get(c.sequence).push(c);
  }
  return {
    deviceId,
    conflicts: rows.map((r) => ({
      sequence: Number(r.sequence),
      status: r.status,
      revision: Number(r.revision),
      reason: r.reason,
      resolution: r.resolution,
      chosenDigest: r.chosen_digest,
      decidedCommandId: r.decided_command_id,
      createdAt: r.created_at.toISOString(),
      resolvedAt: r.resolved_at ? r.resolved_at.toISOString() : null,
      candidates: bySeq.get(Number(r.sequence)) || [],
    })),
  };
}

export async function getConflict(pool, deviceId, sequence) {
  const res = await listConflicts(pool, deviceId, { status: 'all', limit: 500 });
  const found = res.conflicts.find((c) => c.sequence === sequence);
  if (!found) throw errors.notFound(`no conflict at sequence ${sequence} for device ${deviceId}`);
  return found;
}

function adjudicateHash(cmd) {
  return digestHex(
    canonicalize({
      kind: 'adjudicate',
      deviceId: cmd.deviceId,
      sequence: cmd.sequence,
      commandId: cmd.commandId,
      expectedConflictRevision: cmd.expectedConflictRevision,
      decision: cmd.decision,
    })
  );
}

export async function adjudicate(pool, cmd) {
  const requestHash = adjudicateHash(cmd);
  return withTransaction(pool, async (client) => {
    // Idempotency first: the same commandId always returns the first outcome.
    const replay = await client.query(
      'SELECT request_hash, response FROM admin_commands WHERE command_id=$1 AND kind=$2',
      [cmd.commandId, 'adjudicate']
    );
    if (replay.rows.length) {
      const r = replay.rows[0];
      if (r.request_hash !== requestHash) {
        throw errors.conflict(
          'IDEMPOTENCY_CONFLICT',
          `commandId ${cmd.commandId} was already used with different parameters`,
          { commandId: cmd.commandId }
        );
      }
      return { ...r.response, replayed: true };
    }

    // Serialize against ingestion for this device.
    const dev = await client.query(
      'SELECT 1 FROM devices WHERE device_id=$1 FOR UPDATE',
      [cmd.deviceId]
    );
    if (dev.rows.length === 0) throw errors.deviceNotFound(cmd.deviceId);

    const cRows = await client.query(
      `SELECT status, revision, reason, resolution, chosen_digest
         FROM conflicts WHERE device_id=$1 AND sequence=$2 FOR UPDATE`,
      [cmd.deviceId, cmd.sequence]
    );
    if (cRows.rows.length === 0) {
      throw errors.notFound(
        `no conflict at sequence ${cmd.sequence} for device ${cmd.deviceId}`,
        { deviceId: cmd.deviceId, sequence: cmd.sequence }
      );
    }
    const conflict = cRows.rows[0];

    if (Number(conflict.revision) !== cmd.expectedConflictRevision) {
      throw errors.conflict(
        'CONFLICT_REVISION_MISMATCH',
        `expectedConflictRevision ${cmd.expectedConflictRevision} is stale; current revision is ${conflict.revision}`,
        {
          deviceId: cmd.deviceId,
          sequence: cmd.sequence,
          currentRevision: Number(conflict.revision),
          expectedConflictRevision: cmd.expectedConflictRevision,
        }
      );
    }

    let chosenDigest = null;
    if (cmd.decision.type === 'select') {
      // Compacted committed history: the checkpoint at this sequence attests
      // the committed digest even though the event row itself is deleted.
      const cp = await client.query(
        'SELECT digest FROM checkpoints WHERE device_id=$1 AND sequence=$2',
        [cmd.deviceId, cmd.sequence]
      );
      const committedDigest = cp.rows.length ? cp.rows[0].digest : null;

      const cand = await client.query(
        `SELECT 1 FROM event_records
          WHERE device_id=$1 AND sequence=$2 AND digest=$3
            AND status IN ('staged','visible')`,
        [cmd.deviceId, cmd.sequence, cmd.decision.digest]
      );
      // The checkpoint-attested digest is always selectable: confirming
      // committed history needs no live candidate row.
      if (cand.rows.length === 0 && cmd.decision.digest !== committedDigest) {
        throw errors.notFound(
          'selected digest is not a current candidate at this sequence',
          { deviceId: cmd.deviceId, sequence: cmd.sequence, digest: cmd.decision.digest }
        );
      }
      // Mark the chosen one staged/visible (if currently visible it stays),
      // reject every OTHER digest at this sequence.
      await client.query(
        `UPDATE event_records SET status='rejected'
          WHERE device_id=$1 AND sequence=$2 AND digest <> $3
            AND status <> 'visible'`,
        [cmd.deviceId, cmd.sequence, cmd.decision.digest]
      );
      // If a visible event already exists here (post-visibility divergence),
      // selecting a different candidate is forbidden: the prefix cannot be
      // rewritten. Selecting the visible digest simply resolves the conflict.
      const vis = await client.query(
        `SELECT digest FROM event_records
          WHERE device_id=$1 AND sequence=$2 AND status='visible'`,
        [cmd.deviceId, cmd.sequence]
      );
      if (vis.rows.length && vis.rows[0].digest !== cmd.decision.digest) {
        throw errors.conflict(
          'CANNOT_REPLACE_VISIBLE_EVENT',
          'sequence is already part of the consecutive prefix; a different event cannot be selected',
          { deviceId: cmd.deviceId, sequence: cmd.sequence, visibleDigest: vis.rows[0].digest }
        );
      }
      // Compacted history is equally immutable: at a checkpointed sequence the
      // checkpoint-attested digest is the only selectable one.
      if (committedDigest !== null && committedDigest !== cmd.decision.digest) {
        throw errors.conflict(
          'CANNOT_REPLACE_VISIBLE_EVENT',
          'sequence is covered by a compaction checkpoint; committed history cannot be rewritten',
          { deviceId: cmd.deviceId, sequence: cmd.sequence, checkpointDigest: committedDigest }
        );
      }
      chosenDigest = cmd.decision.digest;
    } else {
      // reject_all: every non-visible candidate is refused; nothing new can
      // promote until the device re-uploads.
      await client.query(
        `UPDATE event_records SET status='rejected'
          WHERE device_id=$1 AND sequence=$2 AND status='staged'`,
        [cmd.deviceId, cmd.sequence]
      );
    }

    await client.query(
      `UPDATE conflicts
         SET status='resolved', resolution=$3, chosen_digest=$4,
             decided_command_id=$5, resolved_at=now()
       WHERE device_id=$1 AND sequence=$2`,
      [cmd.deviceId, cmd.sequence, cmd.decision.type === 'select' ? 'selected' : 'rejected_all', chosenDigest, cmd.commandId]
    );

    const adv = await client.query('SELECT try_advance($1) AS hwm', [cmd.deviceId]);
    const hwm = Number(adv.rows[0].hwm);

    const response = {
      deviceId: cmd.deviceId,
      sequence: cmd.sequence,
      commandId: cmd.commandId,
      revision: cmd.expectedConflictRevision,
      resolution: cmd.decision.type === 'select' ? 'selected' : 'rejected_all',
      chosenDigest,
      highWatermark: hwm,
    };
    await client.query(
      `INSERT INTO admin_commands (command_id, device_id, kind, request_hash, conflict, response)
       VALUES ($1,$2,'adjudicate',$3,false,$4)`,
      [cmd.commandId, cmd.deviceId, requestHash, JSON.stringify(response)]
    );
    return { ...response, replayed: false };
  });
}
