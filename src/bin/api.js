'use strict';
// API process entry point. Boots the pool, applies migrations (advisory-lock
// guarded, so every instance can run it), starts the HTTP server, and shuts
// down gracefully on SIGTERM/SIGINT: it stops accepting new connections,
// waits for in-flight requests and closes the database pool.

import { loadConfig } from '../config.mjs';
import { createPool } from '../db/pool.mjs';
import { runMigrations } from '../db/migrate.mjs';
import { serverKeyFromSeed } from '../crypto/checkpoint.mjs';
import { createLogger } from '../observability/log.mjs';
import { createServer } from '../http/server.mjs';

async function main() {
  const cfg = loadConfig();
  const log = createLogger(cfg.role);
  const pool = createPool(cfg);

  // Wait for the database to accept connections (compose starts db first with
  // healthcheck, but be resilient anyway).
  await waitForDatabase(pool, log);
  await runMigrations(pool);

  const serverKey = serverKeyFromSeed(cfg.checkpointKeySeed);
  const server = createServer({ pool, cfg, serverKey, log });

  await new Promise((resolve) => server.listen(cfg.port, '0.0.0.0', resolve));
  log.info({ msg: 'api listening', port: cfg.port });

  let shuttingDown = false;
  const shutdown = async (signal) => {
    if (shuttingDown) return;
    shuttingDown = true;
    log.info({ msg: 'shutdown requested', signal });
    const forceTimer = setTimeout(() => {
      log.error({ msg: 'shutdown timeout, forcing exit' });
      process.exit(1);
    }, cfg.shutdownTimeoutMs);
    forceTimer.unref();
    server.close(() => log.info({ msg: 'http server closed' }));
    // Close idle keep-alive sockets immediately; in-flight requests are
    // allowed to finish, after which server.close() completes.
    server.closeIdleConnections?.();
    try {
      await pool.end();
      log.info({ msg: 'database pool closed' });
    } catch (e) {
      log.error({ msg: 'pool close error', err: e.message });
    }
    clearTimeout(forceTimer);
    process.exit(0);
  };
  process.on('SIGTERM', () => shutdown('SIGTERM'));
  process.on('SIGINT', () => shutdown('SIGINT'));
}

async function waitForDatabase(pool, log) {
  const deadline = Date.now() + 60_000;
  for (;;) {
    try {
      await pool.query('SELECT 1');
      return;
    } catch (e) {
      if (Date.now() > deadline) throw e;
      log.info({ msg: 'waiting for database', err: e.message });
      await new Promise((r) => setTimeout(r, 1000));
    }
  }
}

main().catch((e) => {
  console.error(JSON.stringify({ ts: new Date().toISOString(), level: 'error', msg: 'fatal boot error', err: e.stack || e.message }));
  process.exit(1);
});
