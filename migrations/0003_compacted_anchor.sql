-- Compacted-prefix anchoring.
--
-- Compaction deletes the visible event rows through the cutoff, but the
-- committed prefix must keep participating in later judgments as immutable
-- history:
--   * try_advance must accept a frontier event whose prevDigest links to the
--     digest recorded for the (now deleted) committed predecessor, so a legal
--     continuation of the chain still promotes after compaction - even when
--     compaction reached the current high watermark;
--   * a different digest arriving at an already-compacted sequence is a
--     divergence from committed history and must open a queryable,
--     adjudicable conflict - it is not an ordinary staged candidate and the
--     committed prefix can never be rewritten by it;
--   * an identical retransmission of a compacted event stays an idempotent
--     no-op (handled by the ingest path against this table).
--
-- compacted_events preserves exactly the (sequence, digest) of every
-- committed event removed by compaction. The event payload is gone for good;
-- the digest tombstone is all the hash chain and the adjudicator need.

CREATE TABLE IF NOT EXISTS compacted_events (
  device_id    text NOT NULL REFERENCES devices(device_id) ON DELETE CASCADE,
  sequence     bigint NOT NULL CHECK (sequence >= 1),
  digest       text NOT NULL CHECK (digest ~ '^[0-9a-f]{64}$'),
  compacted_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (device_id, sequence)
);

-- Databases that compacted before this table existed still know the committed
-- digest at every checkpoint sequence; backfill those tombstones. Sequences
-- below a checkpoint that have no checkpoint of their own are unrecoverable
-- by construction (their digests were deleted with the events).
INSERT INTO compacted_events (device_id, sequence, digest)
  SELECT device_id, sequence, digest FROM checkpoints
  ON CONFLICT (device_id, sequence) DO NOTHING;

-- Reconcile the conflict row at one sequence against its current candidate
-- set. Called by ingest AFTER inserting/updating candidate rows.
--   p_added = true only when the triggering request actually inserted a NEW
--   distinct digest at this sequence (identical retries pass false and never
--   bump the revision).
CREATE OR REPLACE FUNCTION reconcile_conflict(
  p_device text, p_seq bigint, p_added boolean
) RETURNS void
LANGUAGE plpgsql
AS $$
DECLARE
  v_visible text;
  v_staged  bigint;
  v_reason  text;
BEGIN
  SELECT digest INTO v_visible
    FROM event_records
   WHERE device_id = p_device AND sequence = p_seq AND status = 'visible';

  IF v_visible IS NULL THEN
    -- The committed event here may have been compacted away; its digest
    -- tombstone (or the checkpoint covering it) is still the immutable
    -- committed digest for this sequence.
    SELECT digest INTO v_visible
      FROM compacted_events
     WHERE device_id = p_device AND sequence = p_seq;
    IF v_visible IS NULL THEN
      SELECT digest INTO v_visible
        FROM checkpoints
       WHERE device_id = p_device AND sequence = p_seq;
    END IF;
  END IF;

  IF v_visible IS NOT NULL THEN
    -- The prefix already has a committed event here; any different staged
    -- digest is a divergence that can never silently replace it.
    IF EXISTS (
      SELECT 1 FROM event_records
       WHERE device_id = p_device AND sequence = p_seq
         AND status = 'staged' AND digest <> v_visible
    ) THEN
      v_reason := 'post_visibility_divergence';
    ELSE
      RETURN; -- no divergence, any existing row is already correct/resolved
    END IF;
  ELSE
    SELECT count(DISTINCT digest) INTO v_staged
      FROM event_records
     WHERE device_id = p_device AND sequence = p_seq AND status = 'staged';
    IF v_staged >= 2 THEN
      v_reason := 'divergent_candidates';
    ELSE
      RETURN; -- 0/1 candidates: nothing to reconcile at ingest time
    END IF;
  END IF;

  INSERT INTO conflicts AS c (device_id, sequence, status, revision, reason)
  VALUES (p_device, p_seq, 'open', 1, v_reason)
  ON CONFLICT (device_id, sequence) DO UPDATE
    SET status = 'open',
        reason = EXCLUDED.reason,
        -- A resolved conflict reopened, or a genuinely new digest at an
        -- already-open conflict, invalidates any in-flight stale adjudication.
        revision = c.revision + CASE
                   WHEN c.status = 'resolved' THEN 1
                   WHEN p_added THEN 1
                   ELSE 0 END,
        resolution = NULL,
        chosen_digest = NULL,
        decided_command_id = NULL,
        resolved_at = NULL;
END;
$$;

-- Advance the visible prefix as far as possible. Filling one missing sequence
-- can promote a whole run of out-of-order staged events. Every single
-- promotion re-validates the hash link against the ACTUAL predecessor digest
-- and the key generation that owns the sequence. A broken link or a wrong key
-- generation becomes an open, adjudicable conflict and blocks every higher
-- sequence from becoming visible.
--
-- The committed predecessor digest is looked up in the live rows first and
-- then in the compacted tombstones / checkpoints: compaction may have deleted
-- the row at the watermark, but the committed prefix it belonged to still
-- anchors the next link.
--
-- The caller (ingest / adjudication / rotation) already runs in a transaction
-- that holds the devices row lock; this function takes it as well.
CREATE OR REPLACE FUNCTION try_advance(p_device text)
RETURNS bigint
LANGUAGE plpgsql
AS $$
DECLARE
  v_hwm   bigint;
  v_next  bigint;
  v_cand  RECORD;
  v_prev  text;
  v_reqkey bigint;
  v_n     bigint;
  v_changed boolean := false;
BEGIN
  PERFORM 1 FROM devices WHERE device_id = p_device FOR UPDATE;
  SELECT high_watermark INTO v_hwm FROM devices WHERE device_id = p_device;

  LOOP
    v_next := v_hwm + 1;

    -- An open conflict at the frontier always blocks promotion.
    EXIT WHEN EXISTS (
      SELECT 1 FROM conflicts
      WHERE device_id = p_device AND sequence = v_next AND status = 'open'
    );

    -- Count staged candidates at the next sequence (visible rows cannot exist
    -- past the watermark).
    SELECT count(*) INTO v_n
    FROM event_records
    WHERE device_id = p_device AND sequence = v_next AND status = 'staged';

    EXIT WHEN v_n = 0; -- gap: nothing to promote yet

    IF v_n >= 2 THEN
      -- Divergent candidates at the frontier: deterministic conflict, never
      -- first-writer-wins.
      PERFORM reconcile_conflict(p_device, v_next, false);
      EXIT;
    END IF;

    -- Exactly one candidate: verify chain + key generation against the real
    -- consecutive prefix.
    SELECT digest, prev_digest, key_version INTO v_cand
    FROM event_records
    WHERE device_id = p_device AND sequence = v_next AND status = 'staged';

    IF v_hwm = 0 THEN
      v_prev := repeat('0', 64);
    ELSE
      SELECT digest INTO v_prev
      FROM event_records
      WHERE device_id = p_device AND sequence = v_hwm AND status = 'visible';
      IF v_prev IS NULL THEN
        -- The committed predecessor was compacted: its digest tombstone (or
        -- the checkpoint at the watermark) anchors the next hash link.
        SELECT digest INTO v_prev
          FROM compacted_events
         WHERE device_id = p_device AND sequence = v_hwm;
        IF v_prev IS NULL THEN
          SELECT digest INTO v_prev
            FROM checkpoints
           WHERE device_id = p_device AND sequence = v_hwm;
        END IF;
      END IF;
    END IF;

    IF v_cand.prev_digest IS DISTINCT FROM v_prev THEN
      INSERT INTO conflicts (device_id, sequence, status, revision, reason)
      VALUES (p_device, v_next, 'open', 1, 'bad_predecessor')
      ON CONFLICT (device_id, sequence) DO UPDATE
        SET status = 'open',
            reason = 'bad_predecessor',
            revision = conflicts.revision + 1,
            resolution = NULL, chosen_digest = NULL,
            decided_command_id = NULL, resolved_at = NULL
        WHERE conflicts.status = 'resolved';
      EXIT;
    END IF;

    -- Which key generation owns this exact sequence?
    SELECT key_version INTO v_reqkey
      FROM device_keys
     WHERE device_id = p_device AND effective_sequence <= v_next
     ORDER BY effective_sequence DESC
     LIMIT 1;

    IF v_cand.key_version IS DISTINCT FROM v_reqkey THEN
      INSERT INTO conflicts (device_id, sequence, status, revision, reason)
      VALUES (p_device, v_next, 'open', 1, 'key_generation_invalid')
      ON CONFLICT (device_id, sequence) DO UPDATE
        SET status = 'open',
            reason = 'key_generation_invalid',
            revision = conflicts.revision + 1,
            resolution = NULL, chosen_digest = NULL,
            decided_command_id = NULL, resolved_at = NULL
        WHERE conflicts.status = 'resolved';
      EXIT;
    END IF;

    -- Link valid, generation valid: promote.
    UPDATE event_records
       SET status = 'visible'
     WHERE device_id = p_device AND sequence = v_next AND digest = v_cand.digest;
    v_hwm := v_next;
    v_changed := true;
  END LOOP;

  IF v_changed THEN
    UPDATE devices SET high_watermark = v_hwm, updated_at = now()
     WHERE device_id = p_device;
    -- Wake every long-poll waiter across ALL API instances. NOTIFY is delivered
    -- at commit; waiters LISTEN before reading the watermark, so a commit that
    -- lands between LISTEN and the read is still observed (no lost wakeup).
    PERFORM pg_notify('telemetry_events', p_device);
  END IF;

  RETURN v_hwm;
END;
$$;
