// ForgeRepo portal: cache housekeeping.
// Author: Tim Rice

import { h } from './dom.js';
import { bytes } from './ui.js';
import { api } from './api.js';

// db and disk drift apart like old friends. audit measures, recache refills, purge drops what's now blocked
function cacheMaintenance() {
  var out = h('p', { class: 'hint' }, ['']);
  var cancelBtn = h('button', {
    class: 'danger',
    onclick: function () {
      api('POST', '/cache/maintenance/cancel', {}).then(function (r) { render(r.job); })
        .catch(function (e) { alert(e.message); });
    }
  }, ['Stop']);
  cancelBtn.style.display = 'none';

  function render(j) {
    if (!j) return;
    cancelBtn.style.display = j.running ? '' : 'none';
    if (j.running) {
      out.textContent = (j.kind === 'audit' ? 'Checking' : j.kind === 'recache' ? 'Putting back' : 'Purging') +
        ' - ' + j.done + (j.total ? ' of ' + j.total : '') + (j.current ? ' (' + j.current + ')' : '');
      return;
    }
    if (!j.finishedAt) { out.textContent = ''; return; }
    var parts = [];
    if (j.kind === 'audit') {
      parts.push(j.ok + ' rows match a real file');
      if (j.missing) parts.push(j.missing + ' missing from disk');
      if (j.truncated) parts.push(j.truncated + ' the wrong size');
      if (j.orphans) parts.push(j.orphans + ' orphaned file(s)');
      if (j.blocked) parts.push(j.blocked + ' cached but now blocked');
    } else if (j.kind === 'recache') {
      parts.push(j.repaired + ' put back');
      if (j.removed) parts.push(j.removed + ' dropped as no longer allowed');
      if (j.orphans) parts.push(j.orphans + ' orphaned file(s) cleared');
      if (j.failed) parts.push(j.failed + ' failed');
    } else {
      parts.push(j.removed + ' blocked file(s) removed');
      if (j.bytesFreed) parts.push(bytes(j.bytesFreed) + ' freed');
      if (j.failed) parts.push(j.failed + ' failed');
    }
    out.textContent = 'Finished. ' + parts.join(', ') + '.' +
      (j.notes && j.notes.length ? ' ' + j.notes.slice(0, 3).join(' ') : '') +
      (j.errors && j.errors.length ? ' First error: ' + j.errors[0] : '');
  }

  function poll() {
    if (!out.isConnected) return;
    api('GET', '/cache/maintenance').then(function (r) {
      render(r.job);
      if (r.job && r.job.running) setTimeout(poll, 2000);
    }).catch(function () {});
  }

  function fire(path, confirmText) {
    if (confirmText && !confirm(confirmText)) return;
    api('POST', path, {}).then(function (r) { render(r.job); poll(); })
      .catch(function (e) { alert(e.message); });
  }

  var box = h('fieldset', null, [
    h('legend', null, ['Cache housekeeping']),
    h('p', { class: 'hint' }, [
      'The database records what is cached, the disk holds it, and a restore or a full disk ' +
      'can leave the two disagreeing. Serving copes on its own by fetching again, but with the ' +
      'upstream switched off there is nothing to fall back to, so it pays to find out first.'
    ]),
    h('div', null, [
      h('button', { onclick: function () { fire('/cache/audit'); } }, ['Check for drift']),
      h('button', {
        onclick: function () {
          fire('/cache/recache-missing', 'Put back the cached npm and PyPI files that have gone missing?');
        }
      }, ['Recache missing']),
      h('button', {
        onclick: function () {
          fire('/cache/purge-blocked', 'Remove every cached npm and PyPI file the rules now block? They cannot be served either way.');
        }
      }, ['Purge blocked']),
      cancelBtn
    ]),
    out
  ]);
  poll();
  return box;
}

export { cacheMaintenance };
