'use strict';
// Test harness: boots a REAL PostgreSQL (embedded-postgres downloads/uses the
// official postgres binaries), creates an isolated database and applies the
// production migrations. Tests therefore exercise the actual SQL functions,
// constraints and LISTEN/NOTIFY behavior - not a mock.

import { rmSync, mkdirSync } from 'node:fs';
import EmbeddedPostgres from 'embedded-postgres';
import pg from 'pg';

const { Client } = pg;

let singleton;

function randomPort() {
  return 40000 + Math.floor(Math.random() * 20000);
}

export async function startTestPostgres() {
  if (singleton) return singleton;
  const port = randomPort();
  const dataDir = `/tmp/tss-pg-${port}-${process.pid}`;
  rmSync(dataDir, { recursive: true, force: true });
  mkdirSync(dataDir, { recursive: true });

  const pgServer = new EmbeddedPostgres({
    databaseDir: dataDir,
    user: 'tss',
    password: 'tss',
    port,
    persistent: true,
    initdbFlags: [],
  });
  await pgServer.initialise();
  await pgServer.start();
  await pgServer.createDatabase('tss_test');

  singleton = { pgServer, port, dataDir };
  return singleton;
}

export async function stopTestPostgres() {
  if (!singleton) return;
  await singleton.pgServer.stop();
  rmSync(singleton.dataDir, { recursive: true, force: true });
  singleton = undefined;
}

export function dbConfig(port, overrides = {}) {
  return {
    db: {
      host: '127.0.0.1',
      port,
      database: 'tss_test',
      user: 'tss',
      password: 'tss',
      poolSize: 8,
    },
    port: 0,
    maxBodyBytes: 16 * 1024 * 1024,
    maxEventsPerBatch: 500,
    adminToken: 'test-admin',
    checkpointKeySeed: Buffer.from('0123456789abcdef0123456789abcdef'),
    waitTimeoutMs: 30_000,
    defaultPageSize: 200,
    maxPageSize: 500,
    shutdownTimeoutMs: 20_000,
    logLevel: 'error',
    compaction: {
      retentionEvents: 5,
      viewTtlMs: 600_000,
      intervalMs: 30_000,
      minEvents: 3,
    },
    ...overrides,
  };
}

export async function freshPool(port) {
  const pool = new pg.Pool({
    host: '127.0.0.1', port, database: 'tss_test', user: 'tss', password: 'tss', max: 8,
  });
  return pool;
}

export async function truncateAll(pool) {
  await pool.query(`
    DO $$
    DECLARE r record;
    BEGIN
      FOR r IN SELECT tablename FROM pg_tables WHERE schemaname='public' AND tablename <> 'schema_migrations'
      LOOP
        EXECUTE 'TRUNCATE TABLE ' || quote_ident(r.tablename) || ' RESTART IDENTITY CASCADE';
      END LOOP;
    END $$;
  `);
}
