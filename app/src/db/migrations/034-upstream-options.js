// Mirror registries (RPM, APT) keep a couple of options: whether the index is filtered, and which advisory feed.
// Author: Tim Rice

module.exports = async ({ query, hasColumn, log }) => {
  if (await hasColumn('upstreams', 'options')) return;
  await query('ALTER TABLE upstreams ADD COLUMN options VARCHAR(1000) NULL AFTER fallback');
  log.info('upstreams can keep options');
};
