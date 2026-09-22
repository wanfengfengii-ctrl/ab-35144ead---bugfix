'use strict';
// Server-side Ed25519 signing for compaction checkpoints and page cursors.
// All API instances and workers share one seed so artifacts are mutually
// verifiable. Canonical checkpoint object (JCS is applied before signing and
// before computing the inter-checkpoint hash):
//
//   {
//     "deviceId":             string,
//     "sequence":             integer,   // compaction cutoff sequence
//     "digest":               hex sha256, // digest of the canonical event at cutoff
//     "prevCheckpointDigest": hex sha256, // hash of previous checkpoint bytes, 0*64 if first
//     "generatedAt":          string      // RFC3339 UTC timestamp
//   }

import { createPrivateKey, createPublicKey, timingSafeEqual } from 'node:crypto';
import { canonicalize } from './canonical.js';
import { digestHex } from './envelope.js';
import { signBytes, verifyBytes, publicKeyToRaw, encodeB64Url, decodeB64Url } from './keys.js';

const ED25519_PKCS8_PREFIX = Buffer.from('302e020100300506032b657004220420', 'hex');

export function serverKeyFromSeed(seed) {
  if (!Buffer.isBuffer(seed) || seed.length !== 32) {
    throw new Error('CHECKPOINT_SIGNING_KEY must decode to exactly 32 bytes');
  }
  const privateKey = createPrivateKey({
    key: Buffer.concat([ED25519_PKCS8_PREFIX, seed]),
    format: 'der',
    type: 'pkcs8',
  });
  const publicKey = createPublicKey(privateKey);
  return {
    privateKey,
    publicKey,
    publicRaw: publicKeyToRaw(publicKey),
    publicB64Url: encodeB64Url(publicKeyToRaw(publicKey)),
  };
}

export function canonicalCheckpoint({ deviceId, sequence, digest, prevCheckpointDigest, generatedAt }) {
  const obj = { deviceId, sequence, digest, prevCheckpointDigest, generatedAt };
  const bytes = canonicalize(obj);
  return { obj, bytes, checkpointHash: digestHex(bytes) };
}

export function signCheckpoint(serverKey, fields) {
  const { obj, bytes, checkpointHash } = canonicalCheckpoint(fields);
  const signature = signBytes(serverKey.privateKey, bytes);
  return {
    ...obj,
    signature: encodeB64Url(signature),
  };
}

/** Verify checkpoint signature and (optionally) its link to a previous checkpoint. */
export function verifyCheckpoint(publicKey, cp, expectedPrevCheckpointHash = null) {
  const { bytes } = canonicalCheckpoint(cp);
  const sig = decodeB64Url(cp.signature);
  if (!sig || sig.length !== 64) return false;
  if (!verifyBytes(publicKey, bytes, sig)) return false;
  if (expectedPrevCheckpointHash !== null) {
    if (!timingSafeEqual(Buffer.from(cp.prevCheckpointDigest, 'hex'), Buffer.from(expectedPrevCheckpointHash, 'hex'))) {
      return false;
    }
  }
  return true;
}

// --- Opaque, unforgeable page cursors -------------------------------------
// token = b64url(JCS({v,d,a})) + "." + b64url(Ed25519(part1))
// v = view id, d = device id, a = sequence already consumed (afterSequence)

export function signCursor(serverKey, { viewId, deviceId, afterSequence }) {
  const body = canonicalize({ v: viewId, d: deviceId, a: afterSequence });
  const bodyB64 = encodeB64Url(body);
  const sig = encodeB64Url(signBytes(serverKey.privateKey, Buffer.from(bodyB64, 'ascii')));
  return `${bodyB64}.${sig}`;
}

export function verifyCursor(serverKey, token) {
  if (typeof token !== 'string') return null;
  const dot = token.indexOf('.');
  if (dot <= 0) return null;
  const bodyB64 = token.slice(0, dot);
  const sigB64 = token.slice(dot + 1);
  const body = decodeB64Url(bodyB64);
  const sig = decodeB64Url(sigB64);
  if (!body || !sig || sig.length !== 64) return null;
  if (!verifyBytes(serverKey.publicKey, Buffer.from(bodyB64, 'ascii'), sig)) return null;
  let parsed;
  try {
    parsed = JSON.parse(body.toString('utf8'));
  } catch {
    return null;
  }
  if (
    typeof parsed !== 'object' || parsed === null ||
    typeof parsed.v !== 'string' ||
    typeof parsed.d !== 'string' ||
    !Number.isInteger(parsed.a) || parsed.a < 0
  ) {
    return null;
  }
  return { viewId: parsed.v, deviceId: parsed.d, afterSequence: parsed.a };
}
