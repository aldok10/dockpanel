-- Per-site jailed interactive SSH shells.
--
-- The per-site SFTP account (20260908110000_sftp_accounts.sql) already owns a
-- uid/gid, a jail (/var/dockpanel-sftp/{domain}) and a bind mount of the site's
-- real content directory. `ssh_shell_enabled` turns that same account from
-- SFTP-only into a real login: the agent lays a userland inside the jail and
-- swaps `ForceCommand internal-sftp` for a shell (see
-- panel/agent/src/services/sftp_accounts.rs).
--
-- It is a flag on the site rather than a separate account on purpose. The shell
-- and the SFTP login are the SAME Linux identity with the SAME files, so there is
-- one password to reset and one set of authorized_keys, and the two can never
-- drift apart. Enabling the shell requires the SFTP account to exist; disabling
-- it leaves the account and files exactly as they were.
--
-- Defaults FALSE, so every site that exists today keeps SFTP-only behaviour and
-- the sshd drop-in's new shell Match block matches nobody until a site opts in.
ALTER TABLE sites ADD COLUMN IF NOT EXISTS ssh_shell_enabled BOOLEAN NOT NULL DEFAULT false;

COMMENT ON COLUMN sites.ssh_shell_enabled IS
    'Whether the site''s Linux (SFTP) account also gets a jailed interactive shell. Requires sftp_enabled; the account and files survive either way.';
