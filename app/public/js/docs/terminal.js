// ForgeRepo portal: a terminal in the documentation, typing a real command and showing what it really printed.
// Author: Tim Rice
//
// the output was captured from the command run against a test registry, with that registry's address swapped for the
// reader's. it types itself out once it scrolls into view, and anyone who asked their system for less motion gets it
// all at once. the copy button copies only the commands, never the output

import { h } from '../dom.js';
import { fill } from './vars.js';

var TYPE_MS = 18;
var LINE_MS = 60;

function reducedMotion() {
  return !!(window.matchMedia && window.matchMedia('(prefers-reduced-motion: reduce)').matches);
}

function copyText(text, button) {
  var done = function () {
    var was = button.textContent;
    button.textContent = 'Copied';
    setTimeout(function () { button.textContent = was; }, 1500);
  };
  if (navigator.clipboard && navigator.clipboard.writeText) {
    navigator.clipboard.writeText(text).then(done, function () { button.textContent = 'Select and copy'; });
  } else {
    button.textContent = 'Select and copy';
  }
}

// session: { title, shell, steps: [{ cmd, out }] }
function terminal(session, vars) {
  var steps = (session.steps || []).map(function (s) {
    return { cmd: fill(s.cmd, vars), out: fill(s.out || '', vars) };
  });
  var prompt = session.shell === 'powershell' ? 'PS> ' : '$ ';
  var screen = h('pre', { class: 'term-screen', 'aria-live': 'off' }, []);
  var replay = h('button', { type: 'button', class: 'btn sm term-btn' }, ['Replay']);
  var copy = h('button', { type: 'button', class: 'btn sm term-btn' }, ['Copy commands']);
  var box = h('figure', { class: 'term' }, [
    h('div', { class: 'term-bar' }, [
      h('span', { class: 'term-dots', 'aria-hidden': 'true' }, [h('i'), h('i'), h('i')]),
      h('span', { class: 'term-title' }, [fill(session.title || 'Terminal', vars)]),
      h('span', { class: 'term-actions' }, [replay, copy])
    ]),
    screen
  ]);
  // screen readers and search get the full text straight away
  box.setAttribute('aria-label', steps.map(function (s) { return prompt + s.cmd + '\n' + s.out; }).join('\n'));

  var timer = null;
  var stop = function () {
    if (timer) clearTimeout(timer);
    timer = null;
  };

  function line(kind, text) {
    var el = h('span', { class: 'term-' + kind }, [text]);
    screen.appendChild(el);
    return el;
  }

  function showAll() {
    stop();
    while (screen.firstChild) screen.removeChild(screen.firstChild);
    steps.forEach(function (s) {
      line('prompt', prompt);
      line('cmd', s.cmd + '\n');
      if (s.out) line('out', s.out.replace(/\n?$/, '\n'));
    });
  }

  function play() {
    stop();
    while (screen.firstChild) screen.removeChild(screen.firstChild);
    var i = 0;
    var nextStep = function () {
      if (i >= steps.length) {
        line('prompt', prompt);
        line('cursor', ' ');
        return;
      }
      var s = steps[i];
      i += 1;
      line('prompt', prompt);
      var cmd = line('cmd', '');
      var c = 0;
      var typeChar = function () {
        if (c < s.cmd.length) {
          cmd.textContent += s.cmd[c];
          c += 1;
          timer = setTimeout(typeChar, TYPE_MS);
          return;
        }
        cmd.textContent += '\n';
        var outLines = s.out ? s.out.replace(/\n$/, '').split('\n') : [];
        var o = 0;
        var outLine = function () {
          if (o < outLines.length) {
            line('out', outLines[o] + '\n');
            o += 1;
            timer = setTimeout(outLine, LINE_MS);
            return;
          }
          timer = setTimeout(nextStep, 500);
        };
        timer = setTimeout(outLine, 250);
      };
      typeChar();
    };
    nextStep();
  }

  replay.addEventListener('click', function () {
    if (reducedMotion()) showAll();
    else play();
  });
  copy.addEventListener('click', function () {
    copyText(steps.map(function (s) { return s.cmd; }).join('\n'), copy);
  });

  showAll();
  if (!reducedMotion() && 'IntersectionObserver' in window) {
    var seen = new IntersectionObserver(function (entries) {
      if (entries.some(function (e) { return e.isIntersecting; })) {
        seen.disconnect();
        play();
      }
    }, { threshold: 0.4 });
    seen.observe(box);
  }
  return box;
}

export { terminal, copyText };
