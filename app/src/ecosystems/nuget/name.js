// NuGet package ids. Newtonsoft.Json and newtonsoft.json are one package, so ids are compared lower case.
// Author: Tim Rice
// the same test nuget.org uses: word characters, with dots, dashes or underscores between them, 100 at most

const MAX = 100;
const ID_RE = /^\w+(?:[_.-]\w+)*$/;

function valid(text) {
  const id = String(text || '').trim();
  return !!id && id.length <= MAX && ID_RE.test(id);
}

const fold = (text) => String(text || '').trim().toLowerCase();

module.exports = { MAX, valid, fold };
