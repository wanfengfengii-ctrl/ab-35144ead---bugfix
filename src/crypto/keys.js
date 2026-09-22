'use strict';
// Ed25519 signing helpers and base64url codecs.
//
// Public keys are transported as raw 32-byte Ed25519 points, base64url
// encoded without padding (43 chars). Signatures are raw 64-byte Ed25519
// signatures in the same encoding (64 chars).

import {
  createPublicKey,
  generateKeyPairSync,
  sign as cryptoSign,
  verify as cryptoVerify,
  KeyObject,
} from 'node:crypto';

export function generateSigningKey() {
  return generateKeyPairSync('ed25519');
}

/** @param {KeyObject} privateKey */
export function signBytes(privateKey, bytes) {
  return cryptoSign(null, bytes, privateKey);
}

/** @param {KeyObject|Buffer} publicKey */
export function verifyBytes(publicKey, bytes, signature) {
  let keyObj = publicKey;
  if (Buffer.isBuffer(publicKey)) {
    keyObj = createPublicKey({ key: publicKey, format: 'der', type: 'spki' });
  }
  try {
    return cryptoVerify(null, bytes, keyObj, signature);
  } catch {
    return false;
  }
}

export function publicKeyToRaw(keyObj) {
  const der = keyObj.export({ type: 'spki', format: 'der' });
  // SPKI for Ed25519 is a fixed 12-byte algorithm prefix followed by 32 key bytes.
  return der.subarray(der.length - 32);
}

// Fixed SPKI prefix for an Ed25519 public key:
// SEQUENCE { SEQUENCE { OID 1.3.101.112 }, BIT STRING(0, <32 raw bytes>) }
const ED25519_SPKI_PREFIX = Buffer.from('302a300506032b6570032100', 'hex');

export function rawToPublicKeyObject(raw) {
  return createPublicKey({
    key: Buffer.concat([ED25519_SPKI_PREFIX, Buffer.from(raw)]),
    format: 'der',
    type: 'spki',
  });
}

export function encodeB64Url(buf) {
  return Buffer.from(buf).toString('base64url');
}

export function decodeB64Url(s) {
  if (typeof s !== 'string') return null;
  if (!/^[A-Za-z0-9_-]+={0,2}$/.test(s)) return null;
  try {
    return Buffer.from(s, 'base64url');
  } catch {
    return null;
  }
}

export function parsePublicKey(s) {
  const raw = decodeB64Url(s);
  if (!raw || raw.length !== 32) return null;
  try {
    return { raw, keyObject: rawToPublicKeyObject(raw) };
  } catch {
    return null;
  }
}

export function parseSignature(s) {
  const raw = decodeB64Url(s);
  if (!raw || raw.length !== 64) return null;
  return raw;
}
