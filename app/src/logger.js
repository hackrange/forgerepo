// Tiny stdout logger. Supervisor and docker pick it up, so no log files to rotate. Bliss.
// Author: Tim Rice

function stamp() {
  return new Date().toISOString().replace('T', ' ').slice(0, 19);
}

function oneLine(text) {
  return String(text).replace(/\r\n|\r|\n/g, '\\n');
}

function write(level, args) {
  const line = args
    .map((a) => {
      // outside newlines could forge a separate log line, so literal \n
      if (typeof a === 'string') return oneLine(a);
      if (a instanceof Error) return a.stack ? a.stack.replace(a.message, oneLine(a.message)) : oneLine(a.message);
      return JSON.stringify(a);
    })
    .join(' ');
  process.stdout.write(`${stamp()} [${level}] ${line}\n`);
}

// break glass key in the query string outlives its grant by a looong way in a log.
// same redaction nginx does
function safeUrl(url) {
  return String(url || '').replace(/([?&]bgt=)[^&]*/gi, '$1[redacted]');
}

module.exports = {
  safeUrl,
  info: (...args) => write('info', args),
  warn: (...args) => write('warn', args),
  error: (...args) => write('error', args),
  debug: (...args) => {
    if (process.env.DEBUG) write('debug', args);
  }
};
