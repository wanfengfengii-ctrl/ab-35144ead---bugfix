'use strict';
// Helpers for building and signing events in tests.

import { generateSigningKey, signBytes, publicKeyToRaw, encodeB64Url } from '../../src/crypto/keys.js';
import { buildEnvelope, ZERO_DIGEST } from '../../src/crypto/envelope.js';
import { validateIngestBody } from '../../src/services/validation.mjs';

/** Run an ingest batch through the exact production validation path. */
export function prepareBatch(deviceId, requestId, events, maxBatch = 500) {
  return validateIngestBody({ deviceId, requestId, events }, maxBatch);
}

/** Validate then ingest through the production service. */
export async function ingestValid(pool, deviceId, requestId, events, maxBatch = 500) {
  const { ingestBatch } = await import('../../src/services/ingest.mjs');
  const batch = prepareBatch(deviceId, requestId, events, maxBatch);
  return ingestBatch(pool, batch);
}

export class DeviceSigner {
  constructor(seed) {
    const kp = generateSigningKey();
    this.keyObject = kp;
    this.privateKey = kp.privateKey;
    this.publicRaw = publicKeyToRaw(kp.publicKey);
    this.publicB64Url = encodeB64Url(this.publicRaw);
  }

  /**
   * @param fields {deviceId, sequence, eventId, occurredAt, keyVersion, prevDigest, payload}
   * @returns {{event: object, digest: string}}
   */
  sign(fields) {
    const { bytes, digest } = buildEnvelope(fields);
    const sig = signBytes(this.privateKey, bytes);
    return {
      event: { ...fields, signature: encodeB64Url(sig) },
      digest,
    };
  }
}

export { ZERO_DIGEST, buildEnvelope };

/** Convenience: build a chain 1..n where each event correctly links. */
export function buildChain(signer, deviceId, n, { startAt = 1, prev = ZERO_DIGEST, keyVersion = 1, payloadSeed = 0 } = {}) {
  const out = [];
  let prevDigest = prev;
  for (let i = 0; i < n; i++) {
    const seq = startAt + i;
    const { event, digest } = signer.sign({
      deviceId,
      sequence: seq,
      eventId: `evt-${seq}`,
      occurredAt: `2026-01-01T00:${String(i % 60).padStart(2, '0')}:00Z`,
      keyVersion,
      prevDigest,
      payload: { n: payloadSeed + i, text: `payload-${seq}` },
    });
    out.push(event);
    prevDigest = digest;
  }
  return out;
}
