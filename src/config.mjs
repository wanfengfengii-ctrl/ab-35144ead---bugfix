'use strict';
// Service configuration loaded from environment. Both API and worker share
// this module. Sensible local-dev defaults are provided so the bare command
// works; every operational value is overridable.

function intEnv(name, def) {
  const v = process.env[name];
  if (v === undefined || v === '') return def;
  if (!/^\d+$/.test(v)) throw new Error(`invalid ${name}=${v}`);
  return Number(v);
}

function durationMs(name, def) {
  const v = process.env[name];
  if (v === undefined || v === '') return def;
  const m = /^(\d+)(ms|s|m)$/.exec(v);
  if (!m) throw new Error(`invalid duration ${name}=${v}`);
  return Number(m[1]) * (m[2] === 'ms' ? 1 : m[2] === 's' ? 1000 : 60000);
}

// Fixed 32-byte dev seed (the phrase is exactly 32 ASCII bytes). MUST be
// overridden via CHECKPOINT_SIGNING_KEY (base64url 32-byte Ed25519 seed) in
// real deployments.
const DEV_CHECKPOINT_SEED = Buffer.from('dev-only-checkpoint-signing-seed', 'utf8');

export function loadConfig(env = process.env) {
  return {
    role: env.ROLE || 'api',
    db: {
      host: env.DATABASE_HOST || 'db',
      port: intEnv('DATABASE_PORT', 5432),
      database: env.DATABASE_NAME || 'telemetry',
      user: env.DATABASE_USER || 'telemetry',
      password: env.DATABASE_PASSWORD || 'telemetry',
      poolSize: intEnv('DATABASE_POOL_SIZE', 10),
    },
    port: intEnv('API_PORT', 8080),
    maxBodyBytes: intEnv('REQUEST_SIZE_LIMIT', 16 * 1024 * 1024),
    maxEventsPerBatch: 500,
    adminToken: env.ADMIN_TOKEN || 'dev-admin-token',
    // Checkpoint signing key: Ed25519 private SEED (base64url, exactly 32
    // bytes). All API instances and workers must share the same key so any
    // instance can verify a checkpoint signed by another.
    checkpointKeySeed:
      env.CHECKPOINT_SIGNING_KEY !== undefined && env.CHECKPOINT_SIGNING_KEY !== ''
        ? Buffer.from(env.CHECKPOINT_SIGNING_KEY, 'base64url')
        : DEV_CHECKPOINT_SEED,
    waitTimeoutMs: durationMs('WAIT_TIMEOUT', '30s'),
    defaultPageSize: intEnv('PAGE_SIZE', 200),
    maxPageSize: intEnv('MAX_PAGE_SIZE', 500),
    shutdownTimeoutMs: durationMs('SHUTDOWN_TIMEOUT', '20s'),
    logLevel: env.LOG_LEVEL || 'info',
    compaction: {
      // Keep at least this many consecutive newest events beyond a checkpoint.
      retentionEvents: intEnv('COMPACTION_RETENTION_EVENTS', 2000),
      // Fixed read views older than this expire and stop blocking deletion.
      viewTtlMs: durationMs('VIEW_TTL', '10m'),
      // Interval between background compaction passes.
      intervalMs: durationMs('COMPACTION_INTERVAL', '30s'),
      // Minimum consecutive high-watermark before a device is checkpointed.
      minEvents: intEnv('COMPACTION_MIN_EVENTS', 1000),
    },
  };
}
