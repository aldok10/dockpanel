-- Per-user OS (SSH) login accounts.
--
-- An administrator may give a panel user a login name when creating it; the
-- agent then provisions the matching Linux account on the panel host so the
-- person can log in over SSH. `os_username` is the source of truth for that
-- account and is NULL for panel-only users — the account is optional, so every
-- existing row keeps working untouched.
--
-- The unique index is partial so the many NULLs do not collide. It is
-- case-sensitive on the stored value; the write path lower-cases before insert,
-- so two logins can never differ only by case.
ALTER TABLE users ADD COLUMN os_username VARCHAR(32);

CREATE UNIQUE INDEX idx_users_os_username
    ON users (os_username)
    WHERE os_username IS NOT NULL;

COMMENT ON COLUMN users.os_username IS
    'Linux login name of the SSH account on the panel host, or NULL for a panel-only account.';
