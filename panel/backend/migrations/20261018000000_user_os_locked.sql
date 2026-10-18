-- The administrator's explicit lock on a user's SSH password.
--
-- `06-…_user_os_accounts.sql` added `os_username`; this adds the one piece of
-- state the SSH screen needs and the panel account does not already carry.
-- Suspending a panel user locks the SSH password too (see `routes::users`), but
-- an operator also wants to shut OFF SSH while leaving the panel login working —
-- a person who should reach the panel but not a shell. That independent lock is
-- this column. The effective lock is `role = 'suspended' OR os_locked`, so a
-- suspended account is locked regardless of what this holds.
--
-- Defaults FALSE, so every account that exists today — none of which has an SSH
-- login unless one was just created — keeps its current, unlocked behaviour.
ALTER TABLE users ADD COLUMN os_locked BOOLEAN NOT NULL DEFAULT FALSE;

COMMENT ON COLUMN users.os_locked IS
    'Administrator''s explicit lock on the SSH password, independent of panel suspension. The effective lock is suspended OR this.';
