'use strict';
// Full in-process service harness for integration tests: real PostgreSQL +
// production migrations + production service modules.

import { startTestPostgres, stopTestPostgres, dbConfig, freshPool, truncateAll } from './pg.mjs';
import { runMigrations } from '../../src/db/migrate.mjs';
import { createPool } from '../../src/db/pool.mjs';
import { serverKeyFromSeed } from '../../src/crypto/checkpoint.mjs';

export async function setupHarness(overrides = {}) {
  const { port } = await startTestPostgres();
  const cfg = dbConfig(port, overrides);
  const pool = createPool(cfg);
  await runMigrations(pool);
  const serverKey = serverKeyFromSeed(cfg.checkpointKeySeed);
  return { cfg, pool, serverKey, port };
}

export { stopTestPostgres, freshPool, truncateAll };
