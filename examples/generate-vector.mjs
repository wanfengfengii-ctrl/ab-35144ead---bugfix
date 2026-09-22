'use strict';
// Generates the canonical, fully reproducible worked example used in the
// README. Everything is derived from a FIXED 32-byte Ed25519 seed, so running
// `npm run vector` on any machine prints byte-identical output.
//
// It prints:
//   * the exact JCS normalized envelope (one JSON line)
//   * signedBytes as hex, which is exactly the UTF-8 encoding of that envelope
//   * digest = lowercase hex sha256(signedBytes)
//   * public key and signature in base64url
//   * a second event chaining off the first, showing prevDigest use

import { createPrivateKey, createPublicKey } from 'node:crypto';
import { buildEnvelope } from '../src/crypto/envelope.js';
import { signBytes, publicKeyToRaw, encodeB64Url } from '../src/crypto/keys.js';

const ED25519_PKCS8_PREFIX = Buffer.from('302e020100300506032b657004220420', 'hex');
const FIXED_SEED = Buffer.from('example-fixed-dev-seed-32-bytes!', 'utf8'); // exactly 32 bytes
if (FIXED_SEED.length !== 32) throw new Error('seed must be 32 bytes');

const privateKey = createPrivateKey({
  key: Buffer.concat([ED25519_PKCS8_PREFIX, FIXED_SEED]),
  format: 'der',
  type: 'pkcs8',
});
const publicRaw = publicKeyToRaw(createPublicKey(privateKey));

const line = (label, value) => console.log(`${label.padEnd(22)}${value}`);

console.log('### Fixed identity');
line('privateSeedB64Url', encodeB64Url(FIXED_SEED));
line('publicKeyB64Url', encodeB64Url(publicRaw));

function present(fields) {
  const { bytes, digest } = buildEnvelope(fields);
  const signature = signBytes(privateKey, bytes);
  return { bytes, digest, signature: encodeB64Url(signature) };
}

// Fields are deliberately given out of alphabetical order with an unordered
// nested payload, to demonstrate that canonicalization ignores input order.
const e1Fields = {
  payload: { temperatureC: 21.5, tags: ['motor', 'line-a'], ok: true },
  prevDigest: '0'.repeat(64),
  eventId: 'evt-0001',
  keyVersion: 1,
  deviceId: 'device-example-001',
  occurredAt: '2026-01-15T10:00:00Z',
  sequence: 1,
};
const e1 = present(e1Fields);

console.log('\n### Event sequence 1');
line('envelopeJson', e1.bytes.toString('utf8'));
line('signedBytesHex', e1.bytes.toString('hex'));
line('signedBytesLength', String(e1.bytes.length));
line('digestHex', e1.digest);
line('signatureB64Url', e1.signature);

// Event 2 chains to event 1.
const e2Fields = {
  deviceId: 'device-example-001',
  sequence: 2,
  eventId: 'evt-0002',
  occurredAt: '2026-01-15T10:00:01Z',
  keyVersion: 1,
  prevDigest: e1.digest,
  payload: { temperatureC: 21.6, tags: ['motor', 'line-a'], ok: true },
};
const e2 = present(e2Fields);

console.log('\n### Event sequence 2 (chains to 1)');
line('envelopeJson', e2.bytes.toString('utf8'));
line('digestHex', e2.digest);
line('signatureB64Url', e2.signature);

console.log('\n### Verification recipe');
console.log('canonical = JCS(envelope)');
console.log('assert sha256_hex(utf8(canonical)) === digestHex');
console.log('assert Ed25519.verify(publicKeyB64Url, utf8(canonical), signatureB64Url) === true');
