'use strict';
// Standalone background worker. Runs periodic compaction passes. It is a
// separate process (and a separate compose service) from the API instances;
// any number of workers may run - the per-device advisory transaction locks in
// compactDevice make concurrent runs collapse safely, and a crash at any point
// only leaves committed checkpoints behind (checkpoint + delete are one
// transaction, so retries never contradict an earlier checkpoint).

import { loadConfig } from '../config.mjs';
import { createPool } from '../db/pool.mjs';
import { runMigrations } from '../db/migrate.mjs';
import { serverKeyFromSeed } from '../crypto/checkpoint.mjs';
import { createLogger } from '../observability/log.mjs';
import { compactionPass } from '../services/compaction.mjs';

async function main() {
  const cfg = loadConfig();
  const log = createLogger(cfg.role);
  const pool = createPool(cfg);

  await waitForDatabase(pool, log);
  await runMigrations(pool);
  const serverKey = serverKeyFromSeed(cfg.checkpointKeySeed);

  let stopping = false;
  let timer = null;

  const runOnce = async () => {
    try {
      const summary = await compactionPass(pool, serverKey, cfg, log);
      log.info({ msg: 'compaction pass complete', ...summary });
    } catch (e) {
      log.error({ msg: 'compaction pass failed', err: e.message });
    }
  };

  const schedule = () => {
    timer = setTimeout(async () => {
      if (stopping) return;
      await runOnce();
      if (!stopping) schedule();
    }, cfg.compaction.intervalMs);
    timer.unref?.();
  };

  // Run one pass shortly after boot, then on the configured interval.
  timer = setTimeout(async () => {
    await runOnce();
    schedule();
  }, 2000);
  timer.unref?.();

  const shutdown = async (signal) => {
    if (stopping) return;
    stopping = true;
    log.info({ msg: 'worker shutdown requested', signal });
    if (timer) clearTimeout(timer);
    try {
      await pool.end();
    } catch (e) {
      log.error({ msg: 'pool close error', err: e.message });
    }
    process.exit(0);
  };
  process.on('SIGTERM', () => shutdown('SIGTERM'));
  process.on('SIGINT', () => shutdown('SIGINT'));
  log.info({ msg: 'worker started', intervalMs: cfg.compaction.intervalMs });
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
  console.error(JSON.stringify({ ts: new Date().toISOString(), level: 'error', msg: 'fatal worker boot error', err: e.stack || e.message }));
  process.exit(1);
});
