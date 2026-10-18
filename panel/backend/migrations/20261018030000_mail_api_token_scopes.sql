-- Finer mail-API permissions, and an optional expiry per token.
--
-- The catalog grows from two entries to four:
--
--   * `send`   — POST /v1/send and /emails: send as the mailbox's own address
--   * `read`   — the GET half of /v1/me/*: mail, folders, contacts, settings
--   * `write`  — the mutating half of /v1/me/*; implies `read`
--   * `domain` — /v1/domains/* and /v1/queue; implies `send`+`read`+`write`
--
-- The point of the split is that a token can now be narrower than "the whole
-- mailbox": a monitoring credential can hold `read` alone, and a contact-form
-- credential `send` alone, so neither can delete mail or change a password.
--
-- `me`, the old single self-service entry, is kept as an *alias* for
-- `send`+`read`+`write`. This migration rewrites every stored array into the new
-- vocabulary so the panel only ever sees the four keys, and the daemon expands the
-- old spelling too, so a row that somehow still carries it is never silently
-- narrowed (which would be the dangerous direction) and never silently widened.
--
-- `expires_at` is optional; NULL means "no expiry". The daemon drops an expired
-- row from its lookup, so an expired token is refused exactly like a revoked one.

ALTER TABLE mail_api_tokens ADD COLUMN IF NOT EXISTS expires_at TIMESTAMPTZ;

COMMENT ON COLUMN mail_api_tokens.expires_at IS
    'Optional expiry. NULL never expires; the daemon refuses a row once this is in the past.';
COMMENT ON COLUMN mail_api_roles.permissions IS
    'Subset of the fixed catalog in panel/mailapi and routes/mail_api.rs: send, read, write, domain.';
COMMENT ON COLUMN mail_api_grants.extra_permissions IS
    'Catalog permissions granted on top of the assigned role, for a one-off without a new role.';
COMMENT ON COLUMN mail_api_tokens.permissions IS
    'Upper bound chosen at mint time. Effective = this ∩ the mailbox''s current allowance.';

-- Rewrite one array from the old vocabulary to the new one, in catalog order.
-- The `&&` is set-overlap: the array is rebuilt in the fixed order
-- send, read, write, domain so two equal sets compare equal as arrays. `me`
-- contributes to send/read/write, `write` pulls in `read`, and `domain` pulls in
-- the whole self-service trio — the same implications `canonicalize` applies in
-- Rust. Unrecognised entries simply match nothing and are dropped.
CREATE OR REPLACE FUNCTION mail_api_expand_permissions(perms TEXT[])
RETURNS TEXT[] AS $$
    SELECT ARRAY(
        SELECT p
          FROM unnest(ARRAY['send', 'read', 'write', 'domain']) AS p
         WHERE CASE p
                 WHEN 'send'   THEN perms && ARRAY['send', 'me', 'domain']
                 WHEN 'read'   THEN perms && ARRAY['read', 'me', 'write', 'domain']
                 WHEN 'write'  THEN perms && ARRAY['write', 'me', 'domain']
                 ELSE               perms && ARRAY['domain']
               END
    );
$$ LANGUAGE sql IMMUTABLE;

UPDATE mail_api_roles  SET permissions         = mail_api_expand_permissions(permissions), updated_at = NOW();
UPDATE mail_api_grants SET extra_permissions   = mail_api_expand_permissions(extra_permissions), updated_at = NOW();
UPDATE mail_api_tokens SET permissions         = mail_api_expand_permissions(permissions);

DROP FUNCTION mail_api_expand_permissions(TEXT[]);

-- Restate the builtin roles in the new vocabulary. Their permissions were already
-- rewritten above; this only refreshes what the two names mean to a reader.
UPDATE mail_api_roles
   SET description = 'Self-service only: send as the mailbox, and read and change that mailbox.',
       updated_at  = NOW()
 WHERE name = 'mail-user';

UPDATE mail_api_roles
   SET description = 'Self-service plus server-wide mail administration: domains, mailboxes, aliases and the queue.',
       updated_at  = NOW()
 WHERE name = 'mail-admin';
