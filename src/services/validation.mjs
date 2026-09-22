'use strict';
// Strict request/field validation. All parsing rules live here so the service
// never depends on incidental runtime behavior.

import { ApiError } from '../errors.mjs';
import { assertJsonValue } from '../crypto/canonical.js';
import { parsePublicKey, parseSignature } from '../crypto/keys.js';
import { isDigest, ZERO_DIGEST } from '../crypto/envelope.js';

const ID_PATTERN = /^[A-Za-z0-9][A-Za-z0-9:._-]{0,127}$/;
const TOKEN_PATTERN = /^[A-Za-z0-9][A-Za-z0-9:._-]{0,127}$/;
const RFC3339 = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})$/;
export const MAX_SAFE_SEQ = Number.MAX_SAFE_INTEGER;

function bad(msg, details) {
  return new ApiError('VALIDATION_ERROR', 400, msg, details);
}

export function requireObject(body, what = 'request body') {
  if (typeof body !== 'object' || body === null || Array.isArray(body)) {
    throw bad(`${what} must be a JSON object`);
  }
  return body;
}

export function asId(value, field) {
  if (typeof value !== 'string' || !ID_PATTERN.test(value)) {
    throw bad(`${field} must be a non-empty identifier (1-128 chars, letters/digits and :._-)`);
  }
  return value;
}

export function asToken(value, field) {
  if (typeof value !== 'string' || !TOKEN_PATTERN.test(value)) {
    throw bad(`${field} must be a non-empty token (1-128 chars, letters/digits and :._-)`);
  }
  return value;
}

export function asPositiveInt(value, field, { max = MAX_SAFE_SEQ, min = 1 } = {}) {
  if (typeof value === 'string' && /^\d+$/.test(value)) value = Number(value);
  if (!Number.isInteger(value) || value < min || value > max) {
    throw bad(`${field} must be an integer in [${min}, ${max}]`);
  }
  return value;
}

export function asRevision(value, field) {
  return asPositiveInt(value, field, { min: 1 });
}

export function asOccurredAt(value, field = 'occurredAt') {
  if (typeof value !== 'string' || !RFC3339.test(value) || Number.isNaN(Date.parse(value))) {
    throw bad(`${field} must be an RFC 3339 timestamp (e.g. 2026-01-01T00:00:00Z)`);
  }
  return value;
}

/**
 * Validate one raw event as carried in an ingest batch. Signature bytes and
 * public key parsing happen separately (the public key is looked up by
 * keyVersion during ingest); this returns the normalized raw fields.
 */
export function validateEvent(raw, index) {
  const where = `events[${index}]`;
  requireObject(raw, where);
  const deviceId = asId(raw.deviceId, `${where}.deviceId`);
  const sequence = asPositiveInt(raw.sequence, `${where}.sequence`);
  const eventId = asToken(raw.eventId, `${where}.eventId`);
  const occurredAt = asOccurredAt(raw.occurredAt, `${where}.occurredAt`);
  const keyVersion = asPositiveInt(raw.keyVersion, `${where}.keyVersion`);
  const prevDigest = raw.prevDigest;
  if (!isDigest(prevDigest)) {
    throw bad(`${where}.prevDigest must be 64 lowercase hex characters (sha256)`);
  }
  if (!('payload' in raw)) throw bad(`${where}.payload is required`);
  assertJsonValue(raw.payload, `${where}.payload`);
  const signature = raw.signature;
  if (typeof signature !== 'string') throw bad(`${where}.signature is required (base64url Ed25519)`);
  const sigRaw = parseSignature(signature);
  if (!sigRaw) throw bad(`${where}.signature must decode to exactly 64 bytes`);
  // No extra/unknown fields: silently accepting fields the client believes to
  // be signed would be dangerous, so reject them explicitly.
  const allowed = new Set(['deviceId', 'sequence', 'eventId', 'occurredAt', 'keyVersion', 'prevDigest', 'payload', 'signature']);
  for (const k of Object.keys(raw)) {
    if (!allowed.has(k)) throw bad(`${where}.${k} is not an allowed event field`);
  }
  return { deviceId, sequence, eventId, occurredAt, keyVersion, prevDigest, payload: raw.payload, signature: sigRaw, signatureB64: signature };
}

export { ZERO_DIGEST };

export function validateRegisterBody(body) {
  requireObject(body);
  const deviceId = asId(body.deviceId, 'deviceId');
  if (typeof body.publicKey !== 'string') throw bad('publicKey is required (base64url raw Ed25519 key, 32 bytes)');
  const pk = parsePublicKey(body.publicKey);
  if (!pk) throw bad('publicKey must decode to exactly 32 Ed25519 bytes');
  return { deviceId, publicKeyB64: body.publicKey, publicKeyRaw: pk.raw };
}

export function validateRotateBody(body) {
  requireObject(body);
  const deviceId = asId(body.deviceId, 'deviceId');
  const commandId = asToken(body.commandId, 'commandId');
  const keyVersion = asRevision(body.keyVersion, 'keyVersion');
  const effectiveSequence = asPositiveInt(body.effectiveSequence, 'effectiveSequence');
  const expectedControlRevision = asRevision(body.expectedControlRevision, 'expectedControlRevision');
  if (typeof body.publicKey !== 'string') throw bad('publicKey is required (base64url raw Ed25519 key, 32 bytes)');
  const pk = parsePublicKey(body.publicKey);
  if (!pk) throw bad('publicKey must decode to exactly 32 Ed25519 bytes');
  return {
    deviceId, commandId, keyVersion, effectiveSequence, expectedControlRevision,
    publicKeyB64: body.publicKey, publicKeyRaw: pk.raw,
  };
}

export function validateIngestBody(body, maxBatch) {
  requireObject(body);
  const deviceId = asId(body.deviceId, 'deviceId');
  const requestId = asToken(body.requestId, 'requestId');
  if (!Array.isArray(body.events)) throw bad('events must be an array');
  if (body.events.length < 1 || body.events.length > maxBatch) {
    throw bad(`events must contain between 1 and ${maxBatch} items`, { size: body.events.length });
  }
  const events = body.events.map((e, i) => validateEvent(e, i));
  // Same sequence twice inside one batch has no deterministic interpretation;
  // reject atomically before any row is written.
  const seenSeq = new Set();
  for (const e of events) {
    if (e.deviceId !== deviceId) throw bad(`event deviceId must equal path/body deviceId`);
    if (seenSeq.has(e.sequence)) throw bad(`duplicate sequence ${e.sequence} inside batch`);
    seenSeq.add(e.sequence);
  }
  return { deviceId, requestId, events };
}

export function validateAdjudicateBody(body) {
  requireObject(body);
  const deviceId = asId(body.deviceId, 'deviceId');
  const sequence = asPositiveInt(body.sequence, 'sequence');
  const commandId = asToken(body.commandId, 'commandId');
  const expectedConflictRevision = asRevision(body.expectedConflictRevision, 'expectedConflictRevision');
  const decision = body.decision;
  requireObject(decision, 'decision');
  let normalized;
  if (decision.type === 'select') {
    if (!isDigest(decision.digest)) throw bad('decision.digest must be 64 lowercase hex characters');
    normalized = { type: 'select', digest: decision.digest };
  } else if (decision.type === 'reject_all') {
    normalized = { type: 'reject_all' };
  } else {
    throw bad("decision.type must be 'select' or 'reject_all'");
  }
  return { deviceId, sequence, commandId, expectedConflictRevision, decision: normalized };
}

export function validateCompactBody(body) {
  requireObject(body);
  const deviceId = asId(body.deviceId, 'deviceId');
  const commandId = body.commandId !== undefined && body.commandId !== null
    ? asToken(body.commandId, 'commandId')
    : null;
  const cutoffSequence = body.cutoffSequence === undefined
    ? null
    : asPositiveInt(body.cutoffSequence, 'cutoffSequence');
  return { deviceId, commandId, cutoffSequence };
}

export function asListLimit(value, dft, max) {
  if (value === undefined) return dft;
  return asPositiveInt(value, 'limit', { min: 1, max });
}
