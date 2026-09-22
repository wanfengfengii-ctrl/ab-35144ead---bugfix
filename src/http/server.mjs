'use strict';
// Versioned HTTP JSON API. Implemented with the node:http standard library -
// no framework dependency. Every response is JSON; every error is rendered
// through the structured ApiError shape. The server is instance-agnostic: any
// number of identical processes can run behind the proxy.

import http from 'node:http';
import { Buffer } from 'node:buffer';
import { ApiError, errors } from '../errors.mjs';
import {
  validateRegisterBody, validateRotateBody, validateIngestBody,
  validateAdjudicateBody, validateCompactBody, asPositiveInt, asListLimit,
} from '../services/validation.mjs';
import { registerDevice, rotateKey, getDevice } from '../services/devices.mjs';
import { ingestBatch } from '../services/ingest.mjs';
import { listConflicts, getConflict, adjudicate } from '../services/conflicts.mjs';
import { readPage, waitForEvents } from '../services/reads.mjs';
import { compactDevice } from '../services/compaction.mjs';

let serverCounter = 0;
export function createServer(deps) {
  const { pool, cfg, serverKey, log } = deps;
  // Stable per-server identity so an acceptance client can prove traffic is
  // served by more than one API instance behind the proxy. Controllers set
  // HOSTNAME; the counter suffix distinguishes multiple servers in one process
  // (used by tests that run two instances in-process).
  // Stable per-server identity. ROLE is set per container in compose
  // (api1/api2); without it we fall back to HOSTNAME. The counter suffix both
  // distinguishes same-host deployments and makes two servers constructed in
  // one process (tests) distinguishable.
  const instanceId = `${process.env.ROLE || process.env.HOSTNAME || 'api'}-${++serverCounter}`;

  const server = http.createServer((req, res) => {
    res.setHeader('x-instance', instanceId);
    const started = Date.now();
    handle(req, res, deps)
      .then((body) => {
        if (res.headersSent || res.writableEnded) return;
        sendJson(res, body.statusCode || 200, body.data);
        logRequest(log, req, body.statusCode || 200, started);
      })
      .catch((err) => {
        if (err?.code === 'ABORTED') {
          // Client went away; nothing to send.
          logRequest(log, req, 499, started);
          return;
        }
        const rendered = renderError(err);
        if (!res.headersSent) sendJson(res, rendered.status, rendered.body);
        logRequest(log, req, rendered.status, started, err);
      });
  });

  server.keepAliveTimeout = 60_000;
  server.headersTimeout = 65_000;
  return server;
}

async function handle(req, res, deps) {
  const { pool, cfg, serverKey } = deps;
  const url = new URL(req.url, 'http://localhost');
  const p = url.pathname;
  const method = req.method;

  if (method === 'GET' && p === '/healthz') {
    return { statusCode: 200, data: { status: 'ok' } };
  }
  if (method === 'GET' && p === '/healthz/ready') {
    await pool.query('SELECT 1');
    return { statusCode: 200, data: { status: 'ready' } };
  }

  // --- /v1 routing ---------------------------------------------------------
  let m;
  if (method === 'POST' && p === '/v1/devices') {
    const body = await readJson(req, cfg);
    const input = validateRegisterBody(body);
    const out = await registerDevice(pool, input);
    return { statusCode: out.created ? 201 : 200, data: out };
  }

  if ((m = /^\/v1\/devices\/([^/]+)\/keys\/rotate$/.exec(p))) {
    if (method !== 'POST') throw errors.validation('method not allowed');
    requireAdmin(req, cfg);
    const body = await readJson(req, cfg);
    const input = validateRotateBody({ ...body, deviceId: body.deviceId ?? decodeURIComponent(m[1]) });
    if (input.deviceId !== decodeURIComponent(m[1])) throw errors.validation('deviceId in body must match path');
    return { statusCode: 200, data: await rotateKey(pool, input) };
  }

  if ((m = /^\/v1\/devices\/([^/]+)\/ingest$/.exec(p))) {
    if (method !== 'POST') throw errors.validation('method not allowed');
    const body = await readJson(req, cfg);
    const pathDevice = decodeURIComponent(m[1]);
    const input = validateIngestBody({ ...body, deviceId: body.deviceId ?? pathDevice }, cfg.maxEventsPerBatch);
    if (input.deviceId !== pathDevice) throw errors.validation('deviceId in body must match path');
    const out = await ingestBatch(pool, input);
    return { statusCode: 200, data: out };
  }

  if ((m = /^\/v1\/devices\/([^/]+)\/conflicts$/.exec(p))) {
    if (method !== 'GET') throw errors.validation('method not allowed');
    const deviceId = decodeURIComponent(m[1]);
    const status = url.searchParams.get('status') || 'open';
    if (!['open', 'resolved', 'all'].includes(status)) {
      throw errors.validation("status must be one of open|resolved|all");
    }
    const limit = asListLimit(url.searchParams.get('limit') ?? undefined, 100, 500);
    return { statusCode: 200, data: await listConflicts(pool, deviceId, { status, limit }) };
  }

  if ((m = /^\/v1\/devices\/([^/]+)\/conflicts\/(\d+)\/adjudicate$/.exec(p))) {
    if (method !== 'POST') throw errors.validation('method not allowed');
    requireAdmin(req, cfg);
    const body = await readJson(req, cfg);
    const deviceId = decodeURIComponent(m[1]);
    const sequence = Number(m[2]);
    const input = validateAdjudicateBody({ ...body, deviceId: body.deviceId ?? deviceId, sequence: body.sequence ?? sequence });
    if (input.deviceId !== deviceId || input.sequence !== sequence) {
      throw errors.validation('deviceId/sequence in body must match path');
    }
    return { statusCode: 200, data: await adjudicate(pool, input) };
  }

  if ((m = /^\/v1\/devices\/([^/]+)\/conflicts\/(\d+)$/.exec(p))) {
    if (method !== 'GET') throw errors.validation('method not allowed');
    return { statusCode: 200, data: await getConflict(pool, decodeURIComponent(m[1]), Number(m[2])) };
  }

  if ((m = /^\/v1\/devices\/([^/]+)\/events$/.exec(p))) {
    if (method !== 'GET') throw errors.validation('method not allowed');
    const deviceId = decodeURIComponent(m[1]);
    const cursor = url.searchParams.get('cursor') || null;
    const afterRaw = url.searchParams.get('afterSequence');
    const explicitAfterSequence = afterRaw === null ? undefined : asPositiveInt(afterRaw, 'afterSequence', { min: 0 });
    const limit = asListLimit(url.searchParams.get('limit') ?? undefined, cfg.defaultPageSize, cfg.maxPageSize);
    const data = await readPage(pool, serverKey, cfg, {
      deviceId, limit, cursorToken: cursor, explicitAfterSequence,
    });
    return { statusCode: 200, data };
  }

  if ((m = /^\/v1\/devices\/([^/]+)\/wait$/.exec(p))) {
    if (method !== 'GET') throw errors.validation('method not allowed');
    const deviceId = decodeURIComponent(m[1]);
    const afterRaw = url.searchParams.get('afterSequence');
    if (afterRaw === null) throw errors.validation('afterSequence query parameter is required');
    const afterSequence = asPositiveInt(afterRaw, 'afterSequence', { min: 0 });
    const limit = asListLimit(url.searchParams.get('limit') ?? undefined, cfg.defaultPageSize, cfg.maxPageSize);
    const ac = new AbortController();
    const onClose = () => ac.abort();
    res.on('close', onClose);
    try {
      const data = await waitForEvents(pool, cfg, { deviceId, afterSequence, limit, signal: ac.signal });
      return { statusCode: 200, data };
    } finally {
      res.off('close', onClose);
    }
  }

  if ((m = /^\/v1\/devices\/([^/]+)\/checkpoints\/latest$/.exec(p))) {
    if (method !== 'GET') throw errors.validation('method not allowed');
    const deviceId = decodeURIComponent(m[1]);
    const { rows } = await pool.query(
      `SELECT sequence, digest, prev_checkpoint_digest, generated_at, signature
         FROM checkpoints WHERE device_id=$1 ORDER BY sequence DESC LIMIT 1`,
      [deviceId]
    );
    if (rows.length === 0) throw errors.notFound(`no checkpoint exists yet for device ${deviceId}`);
    const r = rows[0];
    return {
      statusCode: 200,
      data: {
        deviceId,
        sequence: Number(r.sequence),
        digest: r.digest,
        prevCheckpointDigest: r.prev_checkpoint_digest,
        generatedAt: r.generated_at.toISOString(),
        signature: r.signature.toString('base64url'),
        signerPublicKey: serverKey.publicB64Url,
      },
    };
  }

  if (method === 'POST' && p === '/v1/admin/compact') {
    requireAdmin(req, cfg);
    const body = await readJson(req, cfg);
    const input = validateCompactBody(body);
    const out = await compactDevice(pool, serverKey, cfg, input.deviceId, input.cutoffSequence, input.commandId);
    return { statusCode: 200, data: out ?? { deviceId: input.deviceId, eligible: false } };
  }

  if ((m = /^\/v1\/devices\/([^/]+)$/.exec(p))) {
    if (method !== 'GET') throw errors.validation('method not allowed');
    return { statusCode: 200, data: await getDevice(pool, decodeURIComponent(m[1])) };
  }

  throw new ApiError('NOT_FOUND', 404, `no such route: ${method} ${p}`);
}

function requireAdmin(req, cfg) {
  const header = req.headers['x-admin-token'] || '';
  const auth = req.headers['authorization'] || '';
  const provided = header || (/^Bearer (.+)$/.exec(auth)?.[1] ?? '');
  if (!provided || !timingSafeEqualStr(provided, cfg.adminToken)) {
    throw errors.unauthorized('admin credentials required');
  }
}

function timingSafeEqualStr(a, b) {
  const ba = Buffer.from(String(a));
  const bb = Buffer.from(String(b));
  if (ba.length !== bb.length) return false;
  let diff = 0;
  for (let i = 0; i < ba.length; i++) diff |= ba[i] ^ bb[i];
  return diff === 0;
}

async function readJson(req, cfg) {
  const contentType = req.headers['content-type'] || '';
  if (!/^application\/json(?:;|$)/i.test(contentType)) {
    throw errors.validation('Content-Type must be application/json');
  }
  const limit = cfg.maxBodyBytes;
  const chunks = [];
  let size = 0;
  for await (const chunk of req) {
    size += chunk.length;
    if (size > limit) {
      throw errors.payloadTooLarge(`request body exceeds ${limit} bytes`, { limit, size });
    }
    chunks.push(chunk);
  }
  const raw = Buffer.concat(chunks).toString('utf8');
  if (raw.length === 0) throw errors.validation('request body is empty');
  try {
    return JSON.parse(raw);
  } catch {
    throw errors.validation('request body is not valid JSON');
  }
}

function sendJson(res, status, data) {
  const buf = Buffer.from(JSON.stringify(data), 'utf8');
  res.writeHead(status, {
    'content-type': 'application/json; charset=utf-8',
    'content-length': buf.length,
  });
  res.end(buf);
}

function renderError(err) {
  if (err instanceof ApiError) {
    return {
      status: err.status,
      body: { error: { code: err.code, message: err.message, ...(err.details ? { details: err.details } : {}) } },
    };
  }
  // Database / unexpected errors never leak internals; full detail is logged.
  const body = { error: { code: 'INTERNAL_ERROR', message: 'internal error' } };
  return { status: 500, body };
}

function logRequest(log, req, status, started, err = null) {
  const line = {
    ts: new Date().toISOString(),
    level: status >= 500 ? 'error' : 'info',
    msg: 'http_request',
    method: req.method,
    path: req.url,
    status,
    durationMs: Date.now() - started,
  };
  if (err && status >= 500) line.err = err.stack || err.message;
  if (status >= 500) log.error(line);
  else log.info(line);
}
