// where each blob lives once a bucket is in play. everything made before this is on this box's disk only
// Author: Tim Rice

module.exports = async ({ query, hasColumn, log }) => {
  if (await hasColumn('blobs', 'in_bucket')) return;

  await query(
    `ALTER TABLE blobs
       ADD COLUMN in_bucket TINYINT(1) NOT NULL DEFAULT 0 AFTER verified_at,
       ADD COLUMN uploaded_at DATETIME NULL AFTER in_bucket,
       ADD COLUMN upload_attempts INT UNSIGNED NOT NULL DEFAULT 0 AFTER uploaded_at,
       ADD COLUMN upload_error VARCHAR(255) NULL AFTER upload_attempts,
       ADD KEY idx_blobs_bucket (in_bucket, created_at)`
  );
  log.info('blobs record whether they have made it into the bucket now');
};
