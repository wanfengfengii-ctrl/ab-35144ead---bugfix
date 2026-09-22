-- Telemetry sequence service - initial schema.
-- PostgreSQL is the sole arbitration authority across API instances and
-- background workers. All correctness invariants (idempotency, conflicts,
-- watermark monotonicity, key generations, checkpoints) are enforced here with
-- constraints and row locks; application code holds no in-memory locks and no
-- single-instance assumptions.

CREATE TABLE IF NOT EXISTS schema_migrations (
  version    text PRIMARY KEY,
  applied_at timestamptz NOT NULL DEFAULT now()
);

-- Devices and their consecutive visible watermark.
CREATE TABLE devices (
  device_id        text PRIMARY KEY,
  high_watermark   bigint NOT NULL DEFAULT 0
                     CHECK (high_watermark >= 0),
  control_revision bigint NOT NULL DEFAULT 1
                     CHECK (control_revision >= 1),
  created_at       timestamptz NOT NULL DEFAULT now(),
  updated_at       timestamptz NOT NULL DEFAULT now()
);

-- Ed25519 key generations. Generation g signs exactly the sequences s with
-- effective_sequence(g) <= s < effective_sequence(g+1); the newest generation
-- covers every s >= its effective_sequence. The first generation is always
-- (key_version=1, effective_sequence=1).
CREATE TABLE device_keys (
  device_id          text NOT NULL REFERENCES devices(device_id) ON DELETE CASCADE,
  key_version        bigint NOT NULL CHECK (key_version >= 1),
  public_key         bytea NOT NULL CHECK (octet_length(public_key) = 32),
  effective_sequence bigint NOT NULL CHECK (effective_sequence >= 1),
  created_at         timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (device_id, key_version),
  UNIQUE (device_id, effective_sequence)
);

-- Every structurally valid, signature-valid event ever received. One row per
-- (device, sequence, digest); identical retries collapse onto the same row and
-- conflicting submissions coexist until adjudicated.
--   staged   - a candidate, eligible for promotion to the visible prefix
--   visible  - part of the consecutive auditable prefix (sequence <= hwm)
--   rejected - refused by an adjudication (a later re-upload revives it)
CREATE TABLE event_records (
  device_id   text NOT NULL REFERENCES devices(device_id) ON DELETE CASCADE,
  sequence    bigint NOT NULL CHECK (sequence >= 1),
  digest      text NOT NULL CHECK (digest ~ '^[0-9a-f]{64}$'),
  event_id    text NOT NULL,
  occurred_at text NOT NULL,
  key_version bigint NOT NULL,
  prev_digest text NOT NULL CHECK (prev_digest ~ '^[0-9a-f]{64}$'),
  payload     jsonb NOT NULL,
  envelope    bytea NOT NULL,          -- exact canonical signed bytes
  signature   bytea NOT NULL CHECK (octet_length(signature) = 64),
  status      text NOT NULL CHECK (status IN ('staged','visible','rejected')),
  ingested_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (device_id, sequence, digest)
);
CREATE INDEX idx_event_visible ON event_records (device_id, sequence)
  WHERE status = 'visible';
CREATE INDEX idx_event_staged ON event_records (device_id, sequence)
  WHERE status = 'staged';

-- Conflicts at a sequence.
--   divergent_candidates      : >= 2 different digests, none visible yet
--   bad_predecessor           : candidate(s) present but the hash chain breaks
--   key_generation_invalid    : sole candidate signed by the wrong key
--                               generation for its sequence (e.g. an old key
--                               signing at/after a rotation boundary)
--   post_visibility_divergence: a different digest arrived at an already
--                               visible sequence (the prefix cannot move back)
-- resolution is NULL while open; 'selected' stores chosen_digest,
-- 'rejected_all' means every candidate was refused pending re-upload.
CREATE TABLE conflicts (
  device_id          text NOT NULL REFERENCES devices(device_id) ON DELETE CASCADE,
  sequence           bigint NOT NULL CHECK (sequence >= 1),
  status             text NOT NULL CHECK (status IN ('open','resolved')),
  revision           bigint NOT NULL CHECK (revision >= 1),
  reason             text NOT NULL CHECK (reason IN
                       ('divergent_candidates','bad_predecessor',
                        'key_generation_invalid',
                        'post_visibility_divergence')),
  resolution         text CHECK (resolution IS NULL OR
                       resolution IN ('selected','rejected_all')),
  chosen_digest      text CHECK (chosen_digest IS NULL OR
                       chosen_digest ~ '^[0-9a-f]{64}$'),
  decided_command_id text,
  created_at         timestamptz NOT NULL DEFAULT now(),
  resolved_at        timestamptz,
  PRIMARY KEY (device_id, sequence)
);
CREATE INDEX idx_conflicts_open ON conflicts (device_id, sequence)
  WHERE status = 'open';

-- Ingest idempotency: requestId -> first outcome, replayable forever.
CREATE TABLE ingest_requests (
  request_id   text PRIMARY KEY,
  device_id    text NOT NULL,
  request_hash text NOT NULL,         -- JCS hash over {deviceId, events[]}
  conflict     boolean NOT NULL,      -- always false here; column kept for symmetry
  response     jsonb NOT NULL,        -- exact first response to replay
  created_at   timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX idx_ingest_req_device ON ingest_requests (device_id, created_at);

-- Idempotent admin commands (key rotation, adjudication, compaction).
CREATE TABLE admin_commands (
  command_id   text PRIMARY KEY,
  device_id    text NOT NULL,
  kind         text NOT NULL CHECK (kind IN ('rotate','adjudicate','compact')),
  request_hash text NOT NULL,
  conflict     boolean NOT NULL,
  response     jsonb NOT NULL,
  created_at   timestamptz NOT NULL DEFAULT now()
);

-- Fixed-view snapshots for paginated reads.
CREATE TABLE read_views (
  view_id        uuid PRIMARY KEY,
  device_id      text NOT NULL REFERENCES devices(device_id) ON DELETE CASCADE,
  high_watermark bigint NOT NULL,
  start_sequence bigint NOT NULL,
  created_at     timestamptz NOT NULL DEFAULT now(),
  expires_at     timestamptz NOT NULL
);
CREATE INDEX idx_views_expiry ON read_views (expires_at);
CREATE INDEX idx_views_device_active ON read_views (device_id, start_sequence);

-- Signed compaction checkpoints. The insert and the event deletion happen in
-- one transaction, so an event can never be both unreadable and uncovered.
-- digest              = digest of the canonical event at `sequence` (cutoff)
-- prev_checkpoint_digest = hex SHA-256 over the previous checkpoint's exact
--                       canonical bytes (zeros for the first checkpoint)
CREATE TABLE checkpoints (
  device_id             text NOT NULL REFERENCES devices(device_id) ON DELETE CASCADE,
  sequence              bigint NOT NULL CHECK (sequence >= 1),
  digest                text NOT NULL CHECK (digest ~ '^[0-9a-f]{64}$'),
  prev_checkpoint_digest text NOT NULL CHECK (prev_checkpoint_digest ~ '^[0-9a-f]{64}$'),
  generated_at          timestamptz NOT NULL DEFAULT now(),
  signature             bytea NOT NULL CHECK (octet_length(signature) = 64),
  PRIMARY KEY (device_id, sequence)
);
CREATE INDEX idx_checkpoints_device_seq ON checkpoints (device_id, sequence DESC);
