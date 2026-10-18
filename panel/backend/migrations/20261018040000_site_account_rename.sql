-- The site account's login name changed from `sftp<uid>` to `usr#####` — a
-- tidy 1-based account number instead of the uid. The uid itself is allocated
-- from a range chosen purely so it can never collide with a system account
-- (`sftp_id_seq` starts at 30000), which makes it a poor thing to put in a
-- login name a human has to read and type.
--
-- Every account that already exists was created under the old name, so the
-- panel would otherwise go on computing a name that does not match it — and
-- the PHP-FPM pool's `user =` is written from this same derivation, so the
-- next vhost rebuild would point a site at an account that is not there.
--
-- Drop the flags instead: each such site reads as needing Enable again, and
-- that Enable re-creates the account under the current name while reclaiming
-- the same uid — so no site burns a second uid, its files stay owned by the
-- same identity, and nothing references the retired name afterwards.
--
-- The accounts themselves are removed by the agent on its next start
-- (`sftp_accounts::purge_retired_accounts`).
UPDATE sites
SET sftp_enabled    = false,
    ssh_shell_enabled = false,
    updated_at      = NOW()
WHERE sftp_uid IS NOT NULL
  AND (sftp_enabled OR ssh_shell_enabled);
