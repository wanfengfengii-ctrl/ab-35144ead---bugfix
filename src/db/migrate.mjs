'use strict';
// Applies SQL migrations from the migrations/ directory in filename order.
// Safe to run on every boot: schema_migrations records applied versions, and
// a session-scoped advisory lock serializes the several API instances and the
// worker that boot at the same time.
//
// The lock MUST be acquired before any DDL (including creating the migrations
// table itself): on a clean database every instance boots within milliseconds
// of each other, and concurrent `CREATE TABLE IF NOT EXISTS` statements race
// on the system catalogs with errors like
// `duplicate key value violates unique constraint "pg_type_typname_nsp_index"`.
// Each migration plus its bookkeeping row is applied in one transaction, so a
// crash mid-migration never leaves a partially applied, unrecorded migration.

import { readdirSync, readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const here = dirname(fileURLToPath(import.meta.url));
const migrationsDir = join(here, '..', '..', 'migrations');
const MIGRATION_LOCK_KEY = 912367221;

export async function runMigrations(pool) {
  const files = readdirSync(migrationsDir)
    .filter((f) => /^\d+_.*\.sql$/.test(f))
    .sort();

  const client = await pool.connect();
  try {
    // Serialize all concurrent migrators FIRST - before touching any catalog.
    await client.query('SELECT pg_advisory_lock($1)', [MIGRATION_LOCK_KEY]);

    await client.query(
      'CREATE TABLE IF NOT EXISTS schema_migrations (version text PRIMARY KEY, applied_at timestamptz NOT NULL DEFAULT now())'
    );

    for (const f of files) {
      const { rows } = await client.query(
        'SELECT 1 FROM schema_migrations WHERE version = $1',
        [f]
      );
      if (rows.length) continue;
      const sql = readFileSync(join(migrationsDir, f), 'utf8');
      try {
        // DDL is transactional in PostgreSQL: migration body + bookkeeping row
        // commit atomically. A process killed between them leaves nothing
        // behind, so a later boot safely reapplies the whole file.
        await client.query('BEGIN');
        await client.query(sql);
        await client.query('INSERT INTO schema_migrations (version) VALUES ($1)', [f]);
        await client.query('COMMIT');
        console.log(`[migrations] applied ${f}`);
      } catch (e) {
        try {
          await client.query('ROLLBACK');
        } catch {
          // connection will be discarded by the pool
        }
        throw e;
      }
    }
  } finally {
    await client
      .query('SELECT pg_advisory_unlock($1)', [MIGRATION_LOCK_KEY])
      .catch(() => {});
    client.release();
  }
}
