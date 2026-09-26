// ForgeRepo portal: dom helpers.
// Author: Tim Rice

function h(tag, attrs, kids) {
  var el = document.createElement(tag);
  if (attrs) {
    Object.keys(attrs).forEach(function (key) {
      var val = attrs[key];
      if (val === null || val === undefined || val === false) return;
      if (key === 'class') el.className = val;
      else if (key === 'text') el.textContent = val;
      else if (key.indexOf('on') === 0) el.addEventListener(key.slice(2), val);
      else el.setAttribute(key, val);
    });
  }
  (kids || []).forEach(function (kid) {
    if (kid === null || kid === undefined || kid === false) return;
    el.appendChild(typeof kid === 'object' ? kid : document.createTextNode(String(kid)));
  });
  return el;
}

function link(label, onClick, cls) {
  return h('a', { href: '#', class: cls, onclick: function (e) { e.preventDefault(); onClick(); } }, [label]);
}

export { h, link };
