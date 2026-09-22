'use strict';
// Unit tests for deterministic canonicalization (RFC 8785 corner cases).

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { serialize, canonicalize } from '../src/crypto/canonical.js';

test('object keys are sorted regardless of insertion order', () => {
  assert.equal(serialize({ b: 1, a: 2 }), '{"a":2,"b":1}');
  assert.equal(serialize({ a: { z: 1, a: 2 } }), '{"a":{"a":2,"z":1}}');
});

test('nested objects and arrays', () => {
  assert.equal(serialize([1, 'x', true, null, {}]), '[1,"x",true,null,{}]');
  assert.equal(serialize({ a: [1, 2], b: [] }), '{"a":[1,2],"b":[]}');
});

test('unicode is preserved (not forced to ascii escapes)', () => {
  assert.equal(serialize({ k: 'héllo→€' }), '{"k":"héllo→€"}');
});

test('control characters and quotes are escaped', () => {
  assert.equal(serialize('"'), '"\\u0001\\""');
});

test('numbers: integers never use exponent even >= 1e21', () => {
  assert.equal(serialize(1e21), '1000000000000000000000');
  assert.equal(serialize(-1e21), '-1000000000000000000000');
  assert.equal(serialize(123), '123');
});

test('numbers: floats use shortest round-trip form', () => {
  assert.equal(serialize(0.0001), '0.0001');
  assert.equal(serialize(1.5), '1.5');
});

test('non-finite numbers are rejected', () => {
  assert.throws(() => serialize(NaN));
  assert.throws(() => serialize(Infinity));
});

test('re-keyed identical objects produce identical bytes', () => {
  const a = canonicalize({ x: 1, y: { p: [], q: 's' } });
  const b = canonicalize({ y: { q: 's', p: [] }, x: 1 });
  assert.deepEqual(a, b);
});
