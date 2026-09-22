'use strict';
// Minimal structured JSON logger. Every line is one JSON object on stdout so
// container log drivers can index it directly.

export function createLogger(role) {
  const emit = (level) => (entry) => {
    const line = typeof entry === 'string' ? { msg: entry } : entry;
    const out = { ts: new Date().toISOString(), level, role, ...line };
    const stream = level === 'error' ? process.stderr : process.stdout;
    stream.write(JSON.stringify(out) + '\n');
  };
  return {
    info: emit('info'),
    warn: emit('warn'),
    error: emit('error'),
    debug: emit('debug'),
  };
}
