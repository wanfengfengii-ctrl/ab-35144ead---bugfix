'use strict';
// PostgreSQL connection pool. This pool (and the database behind it) is the
// only shared state between API instances and workers.

import pg from 'pg';

const { Pool } = pg;

export function createPool(cfg) {
  const pool = new Pool({
    host: cfg.db.host,
    port: cfg.db.port,
    database: cfg.db.database,
    user: cfg.db.user,
    password: cfg.db.password,
    max: cfg.db.poolSize,
    idleTimeoutMillis: 30_000,
    connectionTimeoutMillis: 10_000,
  });
  pool.on('error', (err) => {
    // A client errored while idle; the pool recovers it. Just log.
    console.error(JSON.stringify({ ts: logTs(), level: 'error', msg: 'idle pg client error', err: err.message }));
  });
  return pool;
}

function logTs() {
  return new Date().toISOString();
}

/**
 * Run fn with a dedicated client, committing on success and rolling back on
 * throw. BEGIN/COMMIT through the simple query protocol.
 */
export async function withTransaction(pool, fn, options = {}) {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    if (options.serializable) await client.query('SET TRANSACTION ISOLATION LEVEL SERIALIZABLE');
    const result = await fn(client);
    await client.query('COMMIT');
    return result;
  } catch (e) {
    try {
      await client.query('ROLLBACK');
    } catch {
      // already rolled back / client gone
    }
    throw e;
  } finally {
    client.release();
  }
}
