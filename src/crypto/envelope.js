'use strict';
// Event envelope, signing bytes and digest rules.
//
// NORMALIZED EVENT ENVELOPE (the only representation signed and digested):
//
//   {
//     "deviceId":      string,
//     "sequence":      integer >= 1,
//     "eventId":       string,
//     "occurredAt":    string, RFC 3339 / ISO 8601 UTC timestamp,
//     "keyVersion":    integer >= 1,
//     "prevDigest":    string, lowercase hex SHA-256 digest; "0"*64 for seq 1,
//     "payload":       ANY JSON value (canonicalized inside the envelope)
//   }
//
// The signed/digested bytes are EXACTLY the RFC 8785 (JCS) canonical JSON
// serialization of that envelope encoded as UTF-8. Nothing else is prepended
// or appended, there is no domain separator and no whitespace:
//
//   signedBytes = utf8( JCS(envelope) )
//   digest      = lowercase_hex( SHA-256( signedBytes ) )
//   signature   = Ed25519(signingKey, signedBytes)
//
// Because JCS is used, the bytes are independent of the order in which the
// client placed object fields, of Node.js default serialization, and of any
// floating point formatting luck. The HTTP `signature` field (raw Ed25519
// signature, base64url) is NOT part of the envelope and therefore not signed.

import { createHash } from 'node:crypto';
import { canonicalize } from './canonical.js';

export const ZERO_DIGEST = '0'.repeat(64);
export const DIGEST_ALG = 'sha256';

/**
 * Assemble the normalized envelope from raw event fields and return both the
 * canonical UTF-8 bytes and the hex digest.
 *
 * @param {{deviceId:string, sequence:number, eventId:string, occurredAt:string,
 *          keyVersion:number, prevDigest:string, payload:unknown}} fields
 * @returns {{envelope: Record<string, unknown>, bytes: Buffer, digest: string}}
 */
export function buildEnvelope(fields) {
  const envelope = {
    deviceId: fields.deviceId,
    sequence: fields.sequence,
    eventId: fields.eventId,
    occurredAt: fields.occurredAt,
    keyVersion: fields.keyVersion,
    prevDigest: fields.prevDigest,
    payload: fields.payload,
  };
  const bytes = canonicalize(envelope);
  const digest = createHash(DIGEST_ALG).update(bytes).digest('hex');
  return { envelope, bytes, digest };
}

export function digestHex(buf) {
  return createHash(DIGEST_ALG).update(buf).digest('hex');
}

export function isDigest(s) {
  return typeof s === 'string' && /^[0-9a-f]{64}$/.test(s);
}
