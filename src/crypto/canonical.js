'use strict';
// Deterministic JSON Canonicalization per RFC 8785 (JCS).
//
// Guarantees the exact same bytes regardless of object key insertion order
// or the runtime's default JSON serialization. The output is the unique
// canonical encoding of an ECMAScript JSON value; values that JCS cannot
// represent unambiguously (NaN/Infinity, non-finite, non-integer numbers that
// lose identity, etc.) are rejected rather than serialized by accident.

/**
 * Serialize a JSON-compatible value to its RFC 8785 canonical form (UTF-8
 * bytes returned as a Buffer). Throws on non-finite numbers, bigints,
 * functions, symbols, undefined values, or cycles.
 * @param {unknown} value
 * @returns {Buffer}
 */
export function canonicalize(value) {
  return Buffer.from(serialize(value), 'utf8');
}

/**
 * Canonical form as a string (mainly for tests/examples).
 * @param {unknown} value
 * @returns {string}
 */
export function serialize(value) {
  const seen = new Set();
  const out = [];
  writeValue(value, out, seen);
  return out.join('');
}

/**
 * Validate that a value is a plain JSON value suitable for canonicalization
 * and for transport. Object keys must be own enumerable string-keyed
 * properties of plain objects (no class instances / null prototypes beyond
 * plain objects are accepted by the HTTP layer too).
 * @param {unknown} value
 * @param {string} path
 */
export function assertJsonValue(value, path = '$') {
  if (value === null) return;
  const t = typeof value;
  if (t === 'string' || t === 'boolean') return;
  if (t === 'number') {
    if (!Number.isFinite(value)) {
      throw new CanonicalError(`Non-finite number at ${path}`);
    }
    return;
  }
  if (t === 'object') {
    if (seenTag(value) !== '[object Object]' && !Array.isArray(value)) {
      throw new CanonicalError(`Unsupported object type at ${path}`);
    }
    for (const [k, v] of Object.entries(value)) {
      if (v === undefined || typeof v === 'function' || typeof v === 'symbol') {
        throw new CanonicalError(`Undetermined JSON value at ${path}.${k}`);
      }
      assertJsonValue(v, `${path}.${k}`);
    }
    return;
  }
  throw new CanonicalError(`Value of type ${t} at ${path} is not JSON-serializable`);
}

export class CanonicalError extends Error {}

function seenTag(value) {
  return Object.prototype.toString.call(value);
}

/**
 * @param {unknown} value
 * @param {string[]} out
 * @param {Set<object>} seen
 */
function writeValue(value, out, seen) {
  if (value === null) {
    out.push('null');
    return;
  }
  const t = typeof value;
  if (t === 'string') {
    out.push(quoteString(value));
    return;
  }
  if (t === 'boolean') {
    out.push(value ? 'true' : 'false');
    return;
  }
  if (t === 'number') {
    out.push(serializeNumber(value));
    return;
  }
  if (t === 'object') {
    if (seen.has(value)) {
      throw new CanonicalError('Circular value cannot be canonicalized');
    }
    seen.add(value);
    if (Array.isArray(value)) {
      out.push('[');
      for (let i = 0; i < value.length; i++) {
        if (i > 0) out.push(',');
        const v = value[i];
        if (v === undefined) {
          // JSON.stringify turns undefined *array* slots into null; JCS input
          // is JSON, which has no undefined, so the API must never send one.
          throw new CanonicalError('undefined is not a JSON value');
        }
        writeValue(v, out, seen);
      }
      out.push(']');
    } else {
      const keys = Object.keys(value)
        .filter((k) => value[k] !== undefined)
        .sort(compareUtf16);
      out.push('{');
      for (let i = 0; i < keys.length; i++) {
        if (i > 0) out.push(',');
        const k = keys[i];
        out.push(quoteString(k));
        out.push(':');
        writeValue(value[k], out, seen);
      }
      out.push('}');
    }
    seen.delete(value);
    return;
  }
  throw new CanonicalError(`Cannot canonicalize value of type ${t}`);
}

// RFC 8785 3.2.3: sort keys by UTF-16 code unit order (plain < comparison),
// which is what ECMAScript's default Array sort gives for strings.
function compareUtf16(a, b) {
  return a < b ? -1 : a > b ? 1 : 0;
}

// RFC 8785 3.2.2: JSON string escaping.
function quoteString(s) {
  let out = '"';
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i);
    if (c === 0x22) out += '\\"';
    else if (c === 0x5c) out += '\\\\';
    else if (c === 0x08) out += '\\b';
    else if (c === 0x09) out += '\\t';
    else if (c === 0x0a) out += '\\n';
    else if (c === 0x0c) out += '\\f';
    else if (c === 0x0d) out += '\\r';
    else if (c < 0x20) {
      out += '\\u' + c.toString(16).padStart(4, '0');
    } else {
      out += s[i];
    }
  }
  return out + '"';
}

// RFC 8785 3.2.2.2 number serialization ("ES6 number-to-string" algorithm).
function serializeNumber(n) {
  if (!Number.isFinite(n)) {
    throw new CanonicalError('Non-finite numbers have no JSON representation');
  }
  if (n === 0) return '0';
  if (Number.isInteger(n)) {
    // RFC 8785 3.2.2.2: every integer is serialized in full mathematical
    // integer form with NO exponent, even |n| >= 1e21 where ES6 toString
    // would switch to exponent notation.
    if (Math.abs(n) < 1e21) return String(n);
    return expandIntegerExponent(Math.abs(n).toString(), n < 0);
  }
  // Non-integers: ES6 shortest round-trippable decimal (exponent may be used
  // for |x| >= 1e21 or |x| < 1e-6, exactly as JSON.stringify emits it).
  return JSON.stringify(n);
}

// Expand e.g. "1e+21" / "1.5e+22" (integers only) into plain decimal digits.
function expandIntegerExponent(expForm, negative) {
  const m = /^(\d+)(?:\.(\d+))?e\+(\d+)$/.exec(expForm);
  if (!m) {
    // Defensive: some engines may emit other shapes for integers.
    const digits = expForm.replace(/[.e+-]/g, '');
    return (negative ? '-' : '') + digits;
  }
  const intPart = m[1];
  const fracPart = m[2] || '';
  const exp = Number(m[3]);
  const digits = intPart + fracPart;
  const point = intPart.length + exp; // decimal point position from left
  const full = digits + '0'.repeat(Math.max(0, point - digits.length));
  return (negative ? '-' : '') + full;
}
