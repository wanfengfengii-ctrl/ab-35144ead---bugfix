-- Compacted-prefix arbitration.
--
-- Compaction deletes the visible event rows at or below the checkpoint
-- sequence, but the checkpoint row itself permanently attests the committed
-- digest at that sequence. This migration teaches the arbitration functions
-- to treat that attestation as immutable committed history:
--
--  * try_advance: when the visible row at the watermark is gone (compacted
--    up to the watermark), the checkpoint at the watermark supplies the
--    predecessor digest, so a correctly linked next event still promotes and
--    the watermark keeps advancing across the compaction boundary.
--  * reconcile_conflict: when no visible row exists at a sequence covered by
--    a checkpoint, the checkpoint digest arbitrates exactly like a visible
--    row. An identical re-upload of the committed event rejoins the visible
--    prefix; a different digest is a post_visibility_divergence conflict
--    against immutable history - queryable and adjudicable - instead of an
--    ordinary candidate that could silently rewrite the past.

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
    -- Compacted prefix: the checkpoint at this exact sequence attests the
    -- committed digest and arbitrates exactly like a visible row.
    SELECT digest INTO v_visible
      FROM checkpoints
     WHERE device_id = p_device AND sequence = p_seq;

    IF v_visible IS NOT NULL THEN
      -- An identical re-upload of the committed event is not a candidate: it
      -- rejoins the visible prefix (a later compaction may delete it again).
      UPDATE event_records
         SET status = 'visible'
       WHERE device_id = p_device AND sequence = p_seq
         AND status = 'staged' AND digest = v_visible;
    END IF;
  END IF;

  IF v_visible IS NOT NULL THEN
    -- The prefix already has an event here; any different staged digest is a
    -- divergence that can never silently replace it.
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

-- Advance the visible prefix as far as possible. Identical to the 0002
-- version except that the predecessor digest lookup falls back to the
-- checkpoint at the watermark when compaction has already deleted that
-- visible row: the checkpoint is the committed head of the chain.
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
        -- The visible prefix was compacted away up to the watermark: the
        -- checkpoint at the watermark is the committed head of the chain.
        SELECT digest INTO v_prev
          FROM checkpoints
         WHERE device_id = p_device AND sequence = v_hwm;
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
