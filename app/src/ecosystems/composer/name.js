// Composer package names: vendor/package, lower case, the way Packagist spells them.
// Author: Tim Rice
// the same pattern Composer's schema gives, so monolog/monolog and symfony/http-kernel read and Monolog/Monolog folds

const MAX = 214;
const NAME_RE = /^[a-z0-9]([_.-]?[a-z0-9]+)*\/[a-z0-9](([_.]|-{1,2})?[a-z0-9]+)*$/;

const fold = (text) => String(text || '').trim().toLowerCase();
const valid = (text) => {
  const n = fold(text);
  return !!n && n.length <= MAX && NAME_RE.test(n);
};
const split = (text) => (valid(text) ? { vendor: fold(text).split('/')[0], name: fold(text).split('/')[1] } : null);

module.exports = { MAX, valid, fold, split };
