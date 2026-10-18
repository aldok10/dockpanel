-- Roles and permissions for the Mail REST API, and the tokens it hands out.
--
-- Until now a mailbox token (minted in Roundcube) decided what it could do from
-- the *address* it belonged to: being listed in `MAILAPI_ADMIN_EMAILS` gave that
-- mailbox's tokens the whole server-wide surface, and there was no way to hand an
-- administrator mailbox's automation a token that could only touch its own
-- inbox. The address was the grant, and the address is not something a token can
-- narrow.
--
-- These four tables replace that. A token carries its own, smaller set of
-- permissions, drawn from a fixed catalog and bounded at verification time by
-- what the mailbox is *currently* allowed. The mailbox's allowance comes from a
-- role assigned to it here, in the panel, which is also where tokens are minted
-- and revoked. Roundcube no longer mints anything; its Mail API tab only lists.
--
-- Three consequences worth stating, because they are the point of the change:
--
--   * A `/me`-only token stays `/me`-only even for an administrator mailbox. The
--     catalog has two entries — `me` and `domain` — and a token that was not
--     granted `domain` cannot reach `/v1/domains/*` or `/v1/queue`, whatever its
--     address is listed for.
--   * Revoking is immediate: a token's effective permissions are recomputed from
--     these rows on every request, so removing `domain` from a role, or moving a
--     mailbox off `mail-admin`, downgrades tokens that are already out there.
--     The token's own `permissions` are an upper bound, never a floor.
--   * Mail-API tokens no longer live in Roundcube's SQLite database. They live
--     here, and `panel/mailapi` reads them directly over the same Postgres the
--     panel uses. Tokens minted by the old plugin stay valid as `me` only — the
--     daemon keeps reading the old table as a legacy fallback, deliberately
--     granting it nothing wider.

-- Named bundles of permissions. `builtin` rows are seeded below and cannot be
-- renamed, re-scoped or deleted — they are the two levels the product documents,
-- and a rename would silently change what every assignment of them means. Custom
-- roles exist so an operator can carve out something narrower or wider without a
-- release.
CREATE TABLE IF NOT EXISTS mail_api_roles (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name        VARCHAR(64) NOT NULL UNIQUE,
    description TEXT,
    permissions TEXT[] NOT NULL DEFAULT '{}',
    builtin     BOOLEAN NOT NULL DEFAULT FALSE,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

COMMENT ON TABLE mail_api_roles IS
    'Named permission bundles for the Mail REST API. `builtin` rows are seeded and immutable.';
COMMENT ON COLUMN mail_api_roles.permissions IS
    'Subset of the fixed catalog in panel/mailapi and routes/mail_api.rs: me, domain.';

-- Who may do what, by mailbox address. One row per address; an address with no
-- row gets the default (`me` only), which is why this table can be empty and the
-- system is still correct. `email` is stored lowercased — the daemon lowercases
-- before looking anything up, and a mixed-case row here would simply never match.
CREATE TABLE IF NOT EXISTS mail_api_grants (
    email             VARCHAR(255) PRIMARY KEY,
    role_id           UUID REFERENCES mail_api_roles(id) ON DELETE SET NULL,
    extra_permissions TEXT[] NOT NULL DEFAULT '{}',
    created_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_by        UUID REFERENCES users(id) ON DELETE SET NULL
);

COMMENT ON TABLE mail_api_grants IS
    'Per-mailbox Mail-API allowance; absence means the default (me only). email is lowercased.';
COMMENT ON COLUMN mail_api_grants.extra_permissions IS
    'Permissions granted on top of the assigned role, for a one-off without a new role.';

-- Minted tokens. Only the SHA-256 of the secret is kept, so the raw token is
-- shown exactly once, at creation, and a dump of this table cannot be replayed.
-- `permissions` is the subset chosen when the token was minted; the effective set
-- is this intersected with the mailbox's live allowance.
CREATE TABLE IF NOT EXISTS mail_api_tokens (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    email       VARCHAR(255) NOT NULL,
    name        VARCHAR(100),
    token_hash  VARCHAR(64) NOT NULL UNIQUE,
    token_prefix VARCHAR(16) NOT NULL,
    permissions TEXT[] NOT NULL DEFAULT '{}',
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_used_at TIMESTAMPTZ,
    revoked     BOOLEAN NOT NULL DEFAULT FALSE,
    created_by  UUID REFERENCES users(id) ON DELETE SET NULL
);

COMMENT ON TABLE mail_api_tokens IS
    'Mail REST API bearer tokens. Only sha256 is stored; the raw value is shown once.';
COMMENT ON COLUMN mail_api_tokens.permissions IS
    'Upper bound chosen at mint time. Effective = this ∩ the mailbox''s current allowance.';

CREATE INDEX IF NOT EXISTS idx_mail_api_tokens_email ON mail_api_tokens (email);
-- The daemon's hot path is a lookup by hash over the live rows only.
CREATE INDEX IF NOT EXISTS idx_mail_api_tokens_hash ON mail_api_tokens (token_hash) WHERE revoked = FALSE;

-- The credential the Roundcube Mail API tab presents when it lists a mailbox's
-- tokens. It is deliberately NOT an `api_keys` row: those are full panel
-- credentials, and the panel does not read `api_keys.scopes` — handing one to a
-- container would hand it the whole panel. This key can do exactly one thing:
-- read the (prefix, dates, permissions) of tokens for the address it names.
CREATE TABLE IF NOT EXISTS mail_api_webmail_clients (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    key_hash    VARCHAR(64) NOT NULL UNIQUE,
    key_prefix  VARCHAR(16) NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_used_at TIMESTAMPTZ,
    revoked     BOOLEAN NOT NULL DEFAULT FALSE
);

COMMENT ON TABLE mail_api_webmail_clients IS
    'Scoped read-only key the Roundcube Mail API tab uses to list a mailbox''s tokens. Rotated on webmail reinstall.';

-- The two levels the product documents. Seeded, and immutable through the API.
INSERT INTO mail_api_roles (name, description, permissions, builtin) VALUES
    ('mail-user',
     'Self-service only: send as the mailbox and manage the mailbox itself.',
     ARRAY['me'], TRUE),
    ('mail-admin',
     'Self-service plus server-wide mail administration: domains, mailboxes, aliases and the queue.',
     ARRAY['me', 'domain'], TRUE)
ON CONFLICT (name) DO NOTHING;
