import { useEffect, useState } from "react";
import { api } from "../api";

/**
 * Mail API administration: roles, per-mailbox permissions, and tokens.
 *
 * Each token carries its own subset of a four-entry permission catalog —
 * `send`, `read`, `write` (the two halves of managing its own mailbox) and
 * `domain` (the whole server) — and its effective set is that subset
 * *intersected* with what the mailbox is currently allowed, recomputed by the
 * daemon on every request. A token may also carry an expiry, after which it is
 * refused like a revoked one. Two consequences the UI has to make visible
 * rather than hide:
 *
 *   * a token can be narrower than its mailbox — a monitoring credential wants
 *     `read` alone, a contact form `send` alone — and the narrowest useful token
 *     is the safe choice;
 *   * changing a mailbox's role or removing an extra permission downgrades the
 *     tokens already handed out, so it is a revocation, not just a setting.
 *
 * Both tabs are laid out as compact rows rather than forms-and-boxes: the panel
 * sits under a full-width table of host services, and a wall of labelled inputs
 * is the thing that made it hard to read at a glance.
 *
 * Everything here is AdminUser-gated on the backend.
 */

interface PermissionInfo {
  key: string;
  name: string;
  description: string;
}

interface MailApiRole {
  id: string;
  name: string;
  description: string | null;
  permissions: string[];
  builtin: boolean;
}

interface MailApiGrant {
  email: string;
  role_id: string | null;
  role_name: string | null;
  extra_permissions: string[];
  effective_permissions: string[];
}

interface MailApiToken {
  id: string;
  email: string;
  name: string | null;
  token_prefix: string;
  permissions: string[];
  created_at: string;
  expires_at: string | null;
  last_used_at: string | null;
  revoked: boolean;
}

interface Message {
  text: string;
  type: "success" | "error";
}

/**
 * One colour per permission, so `write` reads the same in a token's chips, a
 * role's chips, and the picker. The full sentence lives in the title attribute
 * of every chip instead of in a legend repeated under each list.
 */
const TONE: Record<string, string> = {
  send: "border-rust-500/40 bg-rust-500/10 text-rust-400",
  read: "border-accent-500/40 bg-accent-500/10 text-accent-400",
  write: "border-warn-500/40 bg-warn-500/10 text-warn-400",
  domain: "border-danger-500/40 bg-danger-500/10 text-danger-400",
};

/** A permission as a compact pill — a toggle when given `onClick`. */
function Chip({
  k, on = true, onClick, title,
}: {
  k: string;
  on?: boolean;
  onClick?: () => void;
  title?: string;
}) {
  const skin = on
    ? TONE[k] ?? "border-dark-600 bg-dark-700 text-dark-200"
    : "border-dark-600 text-dark-400";
  const cls = `font-mono text-[10px] leading-4 px-1.5 rounded border transition-colors ${skin}`;
  if (!onClick) {
    return <span className={cls} title={title}>{k}</span>;
  }
  return (
    <button
      type="button"
      onClick={onClick}
      title={title}
      aria-pressed={on}
      className={`${cls} ${on ? "" : "hover:text-dark-200 hover:border-dark-400"}`}
    >
      {k}
    </button>
  );
}

/** A permissions cell: the chips, or a muted dash when there are none. */
function Chips({ keys, note }: { keys: string[]; note?: (k: string) => string | undefined }) {
  if (keys.length === 0) return <span className="text-dark-500">none</span>;
  return (
    <span className="inline-flex flex-wrap gap-1">
      {keys.map((k) => <Chip key={k} k={k} title={note?.(k)} />)}
    </span>
  );
}

/** "3m ago" — compact; the exact timestamp stays in the title attribute. */
function rel(iso: string | null): string {
  if (!iso) return "never";
  const t = new Date(iso).getTime();
  if (Number.isNaN(t)) return "—";
  const s = Math.max(0, Math.round((Date.now() - t) / 1000));
  if (s < 60) return `${s}s ago`;
  const m = Math.round(s / 60);
  if (m < 60) return `${m}m ago`;
  const h = Math.round(m / 60);
  if (h < 24) return `${h}h ago`;
  const d = Math.round(h / 24);
  if (d < 31) return `${d}d ago`;
  return new Date(t).toLocaleDateString();
}

/** Whole days until `iso`, negative once it is behind us. */
function daysLeft(iso: string): number {
  return Math.ceil((new Date(iso).getTime() - Date.now()) / 86400000);
}

/** The expiry options a token can be moved to, shared by mint and renew. */
const EXPIRY_CHOICES: Array<[string, string]> = [
  ["0", "Never"],
  ["30", "30 days"],
  ["90", "90 days"],
  ["180", "180 days"],
  ["365", "1 year"],
];

const iconButton = "p-1 rounded text-dark-400 hover:bg-dark-700 transition-colors";

export default function MailApiPanel({ onMessage }: { onMessage: (m: Message) => void }) {
  const [tab, setTab] = useState<"tokens" | "access">("tokens");
  const [perms, setPerms] = useState<PermissionInfo[]>([]);
  const [roles, setRoles] = useState<MailApiRole[]>([]);
  const [grants, setGrants] = useState<MailApiGrant[]>([]);
  const [tokens, setTokens] = useState<MailApiToken[]>([]);
  const [error, setError] = useState<string | null>(null);

  const load = async () => {
    try {
      const [r, g, t] = await Promise.all([
        api.get<{ roles: MailApiRole[]; permissions: PermissionInfo[] }>("/mail/api/roles"),
        api.get<{ grants: MailApiGrant[] }>("/mail/api/grants"),
        api.get<{ tokens: MailApiToken[] }>("/mail/api/tokens"),
      ]);
      setRoles(r.roles);
      setPerms(r.permissions);
      setGrants(g.grants);
      setTokens(t.tokens);
      setError(null);
    } catch (e) {
      setError(e instanceof Error ? e.message : "Could not load the Mail API settings");
    }
  };

  useEffect(() => {
    load();
  }, []);

  const describe = (key: string) => perms.find((p) => p.key === key);
  const note = (key: string) => describe(key)?.description;

  return (
    <div className="bg-dark-800 rounded-lg border border-dark-500 p-3 elevation-1">
      <div className="flex items-center justify-between gap-2 mb-2">
        <h3 className="text-xs font-medium text-dark-300 uppercase font-mono tracking-widest">
          Mail API — Tokens &amp; Permissions
        </h3>
        <div className="flex border border-dark-600 rounded overflow-hidden shrink-0">
          {([["tokens", "Tokens"], ["access", "Roles & access"]] as const).map(([t, label]) => (
            <button
              key={t}
              onClick={() => setTab(t)}
              className={`px-2 py-1 text-[11px] font-medium uppercase tracking-wider transition-colors ${tab === t ? "bg-dark-600 text-dark-50" : "text-dark-300 hover:text-dark-100"}`}
            >
              {label}
            </button>
          ))}
        </div>
      </div>

      {error && <p className="text-[11px] text-rust-400 mb-2">{error}</p>}

      {tab === "tokens" ? (
        <TokensTab
          tokens={tokens}
          perms={perms}
          grantFor={async (email) => {
            const g = await api.get<MailApiGrant>(`/mail/api/grants/${encodeURIComponent(email)}`);
            return g;
          }}
          onMessage={onMessage}
          onChanged={load}
          note={note}
        />
      ) : (
        <AccessTab
          roles={roles}
          perms={perms}
          grants={grants}
          onMessage={onMessage}
          onChanged={load}
        />
      )}

      {/* One legend for the whole panel, replacing the list of definitions that
          used to sit under the token table — the same four keys describe a
          token, a role, and a mailbox. */}
      {perms.length > 0 && (
        <p className="mt-2 text-[10px] text-dark-400">
          <span className="uppercase tracking-wider">Permissions</span>
          {perms.map((p) => (
            <span key={p.key} className="ml-1.5 font-mono text-dark-200 cursor-help" title={p.description}>
              {p.key}
            </span>
          ))}
          <span className="ml-1.5">— hover a name for what it allows; a token can always be narrower than its mailbox.</span>
        </p>
      )}
    </div>
  );
}

// ── Tokens ──────────────────────────────────────────────────────────────

function TokensTab({
  tokens, perms, grantFor, onMessage, onChanged, note,
}: {
  tokens: MailApiToken[];
  perms: PermissionInfo[];
  grantFor: (email: string) => Promise<MailApiGrant>;
  onMessage: (m: Message) => void;
  onChanged: () => void;
  note: (key: string) => string | undefined;
}) {
  const [email, setEmail] = useState("");
  const [name, setName] = useState("");
  const [allowed, setAllowed] = useState<string[]>([]);
  const [allowedFor, setAllowedFor] = useState("");
  const [chosen, setChosen] = useState<string[]>([]);
  const [lifetime, setLifetime] = useState("0");
  const [minted, setMinted] = useState<{ token: string; email: string } | null>(null);
  const [busy, setBusy] = useState(false);
  const [expiryFor, setExpiryFor] = useState<string | null>(null);
  const [showRevoked, setShowRevoked] = useState(false);

  /** Whether a token is past its expiry and therefore already refused. */
  const expired = (t: MailApiToken) => !!t.expires_at && new Date(t.expires_at).getTime() <= Date.now();

  // Look up what the mailbox is allowed so the picker can only offer that. A
  // token asking for more than the mailbox has is refused by the backend, so
  // offering it would only produce an error to explain away.
  const loadAllowance = async () => {
    const e = email.trim().toLowerCase();
    if (!e.includes("@")) return;
    try {
      const g = await grantFor(e);
      setAllowed(g.effective_permissions);
      setChosen(g.effective_permissions);
      setAllowedFor(e);
    } catch (err) {
      setAllowed([]);
      setAllowedFor("");
      onMessage({ text: err instanceof Error ? err.message : "Could not read the mailbox permissions", type: "error" });
    }
  };

  const mint = async () => {
    setBusy(true);
    try {
      const days = Number(lifetime);
      const r = await api.post<{ token: string; email: string }>("/mail/api/tokens", {
        email: email.trim().toLowerCase(),
        name: name.trim() || undefined,
        permissions: chosen,
        // Omitted (not 0) means "never expires"; the backend refuses a 0.
        expires_in_days: days > 0 ? days : undefined,
      });
      setMinted({ token: r.token, email: r.email });
      setName("");
      setLifetime("0");
      onMessage({ text: "Token created. Copy it now — it is shown only once.", type: "success" });
      onChanged();
    } catch (e) {
      onMessage({ text: e instanceof Error ? e.message : "Could not create the token", type: "error" });
    } finally {
      setBusy(false);
    }
  };

  // `0` clears the expiry, a positive number sets it that many days out — the
  // two states the backend's `expires_in_days` carries.
  const setExpiry = async (id: string, days: string) => {
    try {
      await api.put(`/mail/api/tokens/${id}`, { expires_in_days: Number(days) });
      onMessage({ text: Number(days) > 0 ? `Expiry set to ${days} days` : "Expiry cleared", type: "success" });
      onChanged();
    } catch (e) {
      onMessage({ text: e instanceof Error ? e.message : "Could not change the expiry", type: "error" });
    }
  };

  const revoke = async (id: string) => {
    try {
      await api.delete(`/mail/api/tokens/${id}`);
      onMessage({ text: "Token revoked", type: "success" });
      onChanged();
    } catch (e) {
      onMessage({ text: e instanceof Error ? e.message : "Could not revoke", type: "error" });
    }
  };

  const rotate = async (id: string) => {
    try {
      const r = await api.post<{ token: string; email: string }>(`/mail/api/tokens/${id}/rotate`);
      setMinted({ token: r.token, email: r.email });
      onMessage({ text: "Token rotated. The old secret no longer works.", type: "success" });
      onChanged();
    } catch (e) {
      onMessage({ text: e instanceof Error ? e.message : "Could not rotate", type: "error" });
    }
  };

  const copy = async (text: string) => {
    try {
      await navigator.clipboard.writeText(text);
      onMessage({ text: "Token copied to the clipboard", type: "success" });
    } catch {
      onMessage({ text: "Could not copy — select the token and copy it by hand", type: "error" });
    }
  };

  // The typed address is only mintable once its allowance has been read, so a
  // token can never be created against the previous mailbox's permissions.
  const typed = email.trim().toLowerCase();
  const ready = typed.includes("@") && allowedFor === typed && chosen.length > 0;
  const revokedCount = tokens.filter((t) => t.revoked).length;
  const shown = tokens.filter((t) => showRevoked || !t.revoked);
  const liveCount = tokens.length - revokedCount;

  return (
    <div>
      {minted && (
        <div className="border border-rust-500/60 bg-rust-500/10 rounded-lg p-2.5 mb-2.5">
          <p className="text-[11px] font-semibold text-dark-50 mb-1">
            New token for {minted.email} — copy it now, it is shown only once:
          </p>
          <code className="block text-[11px] text-dark-100 break-all select-all bg-dark-900 rounded p-2">{minted.token}</code>
          <div className="mt-1.5 flex items-center gap-2">
            <button onClick={() => copy(minted.token)} className="px-2 py-1 bg-rust-500 text-white rounded text-[11px] font-medium hover:bg-rust-600">
              Copy
            </button>
            <button onClick={() => setMinted(null)} className="px-2 py-1 bg-dark-700 text-dark-100 rounded text-[11px] font-medium hover:bg-dark-600">
              Dismiss
            </button>
          </div>
        </div>
      )}

      {/* Mint — one row of inputs, one row of permission chips. */}
      <div className="border border-dark-600 rounded-lg p-2.5 mb-2.5">
        <div className="flex flex-wrap items-end gap-2">
          <label className="flex-1 min-w-[200px]">
            <span className="block text-[10px] text-dark-400 uppercase tracking-wider mb-0.5">Mailbox</span>
            <input
              value={email}
              onChange={(e) => { setEmail(e.target.value); setAllowedFor(""); }}
              onBlur={loadAllowance}
              placeholder="user@example.com"
              className="w-full px-2 py-1 bg-dark-900 border border-dark-600 rounded text-xs text-dark-50 focus:border-dark-400 outline-none"
            />
          </label>
          <label className="w-32">
            <span className="block text-[10px] text-dark-400 uppercase tracking-wider mb-0.5">Label</span>
            <input
              value={name}
              onChange={(e) => setName(e.target.value)}
              placeholder="Monitoring"
              className="w-full px-2 py-1 bg-dark-900 border border-dark-600 rounded text-xs text-dark-50 focus:border-dark-400 outline-none"
            />
          </label>
          <label className="w-28">
            <span className="block text-[10px] text-dark-400 uppercase tracking-wider mb-0.5">Expires</span>
            <select
              value={lifetime}
              onChange={(e) => setLifetime(e.target.value)}
              className="w-full px-2 py-1 bg-dark-900 border border-dark-600 rounded text-xs text-dark-50 focus:border-dark-400 outline-none"
            >
              {EXPIRY_CHOICES.map(([v, label]) => (
                <option key={v} value={v}>{v === "0" ? "Never" : `In ${label}`}</option>
              ))}
            </select>
          </label>
          <button
            onClick={mint}
            disabled={busy || !ready}
            title={!typed.includes("@") ? "Enter a mailbox first" : allowedFor !== typed ? "Pick the mailbox out of the field to read its permissions" : chosen.length === 0 ? "Choose at least one permission" : "The token is shown once"}
            className="px-3 py-1 bg-rust-500 text-white rounded text-xs font-medium hover:bg-rust-600 disabled:opacity-40 transition-colors"
          >
            {busy ? "Creating…" : "Create token"}
          </button>
        </div>

        <div className="mt-2 flex flex-wrap items-center gap-1.5">
          <span className="text-[10px] text-dark-400 uppercase tracking-wider">Permissions</span>
          {allowed.length === 0 ? (
            <span className="text-[11px] text-dark-400">Enter a mailbox to see what it may be given.</span>
          ) : (
            <>
              {allowed.map((key) => (
                <Chip
                  key={key}
                  k={key}
                  on={chosen.includes(key)}
                  title={`${perms.find((p) => p.key === key)?.name ?? key} — click to ${chosen.includes(key) ? "withhold" : "grant"} it`}
                  onClick={() => setChosen((c) => (c.includes(key) ? c.filter((k) => k !== key) : [...c, key]))}
                />
              ))}
              <button
                type="button"
                onClick={() => setChosen(allowed)}
                className="text-[10px] text-dark-400 hover:text-dark-100 underline decoration-dotted"
              >
                all
              </button>
              <button
                type="button"
                onClick={() => setChosen([])}
                className="text-[10px] text-dark-400 hover:text-dark-100 underline decoration-dotted"
              >
                none
              </button>
            </>
          )}
        </div>
      </div>

      {tokens.length === 0 ? (
        <p className="text-[11px] text-dark-400">No tokens yet.</p>
      ) : (
        <>
          <div className="flex items-center justify-between text-[10px] text-dark-400 mb-1">
            <span>
              {liveCount} active
              {revokedCount > 0 && ` · ${revokedCount} revoked`}
            </span>
            {revokedCount > 0 && (
              <button onClick={() => setShowRevoked((v) => !v)} className="hover:text-dark-100 underline decoration-dotted">
                {showRevoked ? "hide revoked" : "show revoked"}
              </button>
            )}
          </div>
          <table className="w-full text-[11px]">
            <thead>
              <tr className="text-dark-400 uppercase tracking-wider text-left">
                <th className="py-1 font-medium">Token</th>
                <th className="font-medium">Mailbox</th>
                <th className="font-medium">Permissions</th>
                <th className="font-medium">Expires</th>
                <th className="font-medium">Last used</th>
                <th className="font-medium text-right">Actions</th>
              </tr>
            </thead>
            <tbody>
              {shown.map((t) => (
                <tr key={t.id} className={`border-t border-dark-700 align-middle ${t.revoked ? "opacity-50" : ""}`}>
                  <td className="py-1.5 pr-2">
                    <code className="text-dark-50">{t.token_prefix}…</code>
                    {t.name && <span className="block text-[10px] text-dark-400 truncate max-w-[10rem]" title={t.name}>{t.name}</span>}
                  </td>
                  <td className="text-dark-100 pr-2">{t.email}</td>
                  <td className="pr-2"><Chips keys={t.permissions} note={note} /></td>
                  <td className="pr-2 whitespace-nowrap">
                    {t.revoked ? (
                      <span className="text-dark-500">{t.expires_at ? new Date(t.expires_at).toLocaleDateString() : "never"}</span>
                    ) : expiryFor === t.id ? (
                      <select
                        autoFocus
                        value=""
                        onChange={(e) => { const v = e.target.value; setExpiryFor(null); if (v) setExpiry(t.id, v); }}
                        onBlur={() => setExpiryFor(null)}
                        className="px-1 py-0.5 bg-dark-900 border border-dark-600 rounded text-[11px] text-dark-100"
                      >
                        <option value="">Change…</option>
                        {EXPIRY_CHOICES.map(([v, label]) => <option key={v} value={v}>{label}</option>)}
                      </select>
                    ) : (
                      <button
                        type="button"
                        onClick={() => setExpiryFor(t.id)}
                        title={t.expires_at
                          ? `Expires ${new Date(t.expires_at).toLocaleString()} — click to change`
                          : "Never expires — click to change"}
                        className={`hover:underline decoration-dotted ${expired(t) ? "text-danger-400" : "text-dark-300"}`}
                      >
                        {!t.expires_at ? "never" : expired(t) ? "expired" : `${daysLeft(t.expires_at)}d left`}
                      </button>
                    )}
                  </td>
                  <td className="text-dark-300 pr-2 whitespace-nowrap" title={t.last_used_at ? new Date(t.last_used_at).toLocaleString() : ""}>
                    {rel(t.last_used_at)}
                  </td>
                  <td className="text-right whitespace-nowrap">
                    {t.revoked ? (
                      <span className="text-[10px] uppercase tracking-wider text-dark-500">revoked</span>
                    ) : (
                      <span className="inline-flex items-center gap-0.5">
                        <button onClick={() => rotate(t.id)} title="Rotate — mints a new secret and kills this one" className={`${iconButton} hover:text-accent-400`}>
                          <svg className="w-3.5 h-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.8}>
                            <path strokeLinecap="round" strokeLinejoin="round" d="M16.023 9.348h4.992V4.356m-1.42 9.03a8.25 8.25 0 11-1.403-6.113" />
                          </svg>
                        </button>
                        <button onClick={() => revoke(t.id)} title="Revoke — the secret stops working immediately" className={`${iconButton} hover:text-danger-400`}>
                          <svg className="w-3.5 h-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.8}>
                            <path strokeLinecap="round" strokeLinejoin="round" d="M6 18L18 6M6 6l12 12" />
                          </svg>
                        </button>
                      </span>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </>
      )}
    </div>
  );
}

// ── Roles & per-mailbox permissions ─────────────────────────────────────

function AccessTab({
  roles, perms, grants, onMessage, onChanged,
}: {
  roles: MailApiRole[];
  perms: PermissionInfo[];
  grants: MailApiGrant[];
  onMessage: (m: Message) => void;
  onChanged: () => void;
}) {
  const [newRole, setNewRole] = useState(false);
  const [roleName, setRoleName] = useState("");
  const [roleDesc, setRoleDesc] = useState("");
  const [rolePerms, setRolePerms] = useState<string[]>([]);
  const [assignEmail, setAssignEmail] = useState("");
  const [assignRole, setAssignRole] = useState<string>("");
  const [assignExtras, setAssignExtras] = useState<string[]>([]);

  /** What a permission allows, for the chips' tooltips. */
  const note = (k: string) => perms.find((p) => p.key === k)?.description;

  const createRole = async () => {
    try {
      await api.post("/mail/api/roles", {
        name: roleName.trim(),
        description: roleDesc.trim() || undefined,
        permissions: rolePerms,
      });
      setRoleName(""); setRoleDesc(""); setRolePerms([]); setNewRole(false);
      onMessage({ text: "Role created", type: "success" });
      onChanged();
    } catch (e) {
      onMessage({ text: e instanceof Error ? e.message : "Could not create the role", type: "error" });
    }
  };

  const deleteRole = async (id: string) => {
    try {
      await api.delete(`/mail/api/roles/${id}`);
      onMessage({ text: "Role deleted", type: "success" });
      onChanged();
    } catch (e) {
      onMessage({ text: e instanceof Error ? e.message : "Could not delete the role", type: "error" });
    }
  };

  const assign = async (email: string, roleId: string | null, extras: string[]) => {
    try {
      await api.put(`/mail/api/grants/${encodeURIComponent(email.trim().toLowerCase())}`, {
        role_id: roleId,
        extra_permissions: extras,
      });
      onMessage({ text: "Permissions updated", type: "success" });
      onChanged();
    } catch (e) {
      onMessage({ text: e instanceof Error ? e.message : "Could not update the permissions", type: "error" });
    }
  };

  const unassign = async (email: string) => {
    try {
      await api.delete(`/mail/api/grants/${encodeURIComponent(email)}`);
      onMessage({ text: "Mailbox reset to the default (self-service)", type: "success" });
      onChanged();
    } catch (e) {
      onMessage({ text: e instanceof Error ? e.message : "Could not reset", type: "error" });
    }
  };

  /** Toggle chips over the whole catalog, for the role and extras pickers. */
  const permPicker = (value: string[], onChange: (v: string[]) => void) => (
    <span className="inline-flex flex-wrap items-center gap-1">
      {perms.map((p) => (
        <Chip
          key={p.key}
          k={p.key}
          on={value.includes(p.key)}
          title={`${p.name} — ${p.description}`}
          onClick={() => onChange(value.includes(p.key) ? value.filter((k) => k !== p.key) : [...new Set([...value, p.key])])}
        />
      ))}
    </span>
  );

  const selectCls = "px-1.5 py-0.5 bg-dark-900 border border-dark-600 rounded text-[11px] text-dark-50 outline-none";
  const label = "text-[10px] text-dark-400 uppercase tracking-wider";

  return (
    <div className="space-y-2.5">
      <section className="border border-dark-600 rounded-lg overflow-hidden">
        <header className="flex items-center justify-between px-2.5 py-1.5 border-b border-dark-700 bg-dark-900/40">
          <span className={label}>Roles</span>
          <button onClick={() => setNewRole((v) => !v)} className="text-[10px] text-dark-300 hover:text-dark-50">
            {newRole ? "Cancel" : "+ New role"}
          </button>
        </header>

        <ul className="divide-y divide-dark-700">
          {roles.map((r) => (
            <li key={r.id} className="flex items-center gap-2 px-2.5 py-1.5 text-[11px]">
              <span className="font-mono text-dark-50 truncate max-w-[9rem]" title={r.name}>{r.name}</span>
              {r.builtin && (
                <span className="text-[9px] uppercase tracking-wider text-dark-400 border border-dark-600 rounded px-1 shrink-0">builtin</span>
              )}
              <Chips keys={r.permissions} note={note} />
              {r.description && (
                <span className="ml-auto text-[10px] text-dark-400 truncate max-w-[45%] hidden sm:inline" title={r.description}>
                  {r.description}
                </span>
              )}
              {!r.builtin && (
                <button
                  onClick={() => deleteRole(r.id)}
                  title={`Delete the role "${r.name}"`}
                  className={`ml-auto shrink-0 ${iconButton} hover:text-danger-400`}
                >
                  <svg className="w-3.5 h-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.8}>
                    <path strokeLinecap="round" strokeLinejoin="round" d="M6 18L18 6M6 6l12 12" />
                  </svg>
                </button>
              )}
            </li>
          ))}
        </ul>

        {newRole && (
          <div className="border-t border-dark-700 px-2.5 py-2 space-y-1.5">
            <div className="flex flex-wrap items-end gap-2">
              <label className="w-36">
                <span className={`block ${label} mb-0.5`}>Name</span>
                <input value={roleName} onChange={(e) => setRoleName(e.target.value)} placeholder="mail-auditor"
                  className="w-full px-2 py-1 bg-dark-900 border border-dark-600 rounded text-xs text-dark-50 focus:border-dark-400 outline-none" />
              </label>
              <label className="flex-1 min-w-[160px]">
                <span className={`block ${label} mb-0.5`}>Description</span>
                <input value={roleDesc} onChange={(e) => setRoleDesc(e.target.value)} placeholder="What this role is for"
                  className="w-full px-2 py-1 bg-dark-900 border border-dark-600 rounded text-xs text-dark-50 focus:border-dark-400 outline-none" />
              </label>
              <button onClick={createRole} disabled={!roleName.trim() || rolePerms.length === 0}
                className="px-3 py-1 bg-rust-500 text-white rounded text-xs font-medium hover:bg-rust-600 disabled:opacity-40 transition-colors">
                Create role
              </button>
            </div>
            <div className="flex items-center gap-1.5">
              <span className={label}>Permissions</span>
              {permPicker(rolePerms, setRolePerms)}
            </div>
          </div>
        )}
      </section>

      <section className="border border-dark-600 rounded-lg overflow-hidden">
        <header className="flex flex-wrap items-end gap-2 px-2.5 py-2 border-b border-dark-700 bg-dark-900/40">
          <label className="flex-1 min-w-[200px]">
            <span className={`block ${label} mb-0.5`}>Mailbox</span>
            <input value={assignEmail} onChange={(e) => setAssignEmail(e.target.value)} placeholder="user@example.com"
              className="w-full px-2 py-1 bg-dark-900 border border-dark-600 rounded text-xs text-dark-50 focus:border-dark-400 outline-none" />
          </label>
          <label className="w-44">
            <span className={`block ${label} mb-0.5`}>Role</span>
            <select value={assignRole} onChange={(e) => setAssignRole(e.target.value)} className={`w-full ${selectCls}`}>
              <option value="">Default (self-service)</option>
              {roles.map((r) => <option key={r.id} value={r.id}>{r.name}</option>)}
            </select>
          </label>
          <button onClick={() => assign(assignEmail, assignRole || null, assignExtras)} disabled={!assignEmail.includes("@")}
            className="px-3 py-1 bg-rust-500 text-white rounded text-xs font-medium hover:bg-rust-600 disabled:opacity-40 transition-colors">
            Assign
          </button>
          <div className="w-full flex items-center gap-1.5">
            <span className={label}>Extra</span>
            {permPicker(assignExtras, setAssignExtras)}
          </div>
        </header>

        {grants.length === 0 ? (
          <p className="px-2.5 py-2 text-[11px] text-dark-400">
            No mailbox is assigned yet. Every mailbox gets the default (<span className="font-mono text-dark-300">send, read, write</span>) until it is assigned here.
          </p>
        ) : (
          <table className="w-full text-[11px]">
            <thead>
              <tr className="text-dark-400 uppercase tracking-wider text-left">
                <th className="py-1 px-2.5 font-medium">Mailbox</th>
                <th className="font-medium">Role</th>
                <th className="font-medium">Effective</th>
                <th className="font-medium text-right pr-2.5">Reset</th>
              </tr>
            </thead>
            <tbody>
              {grants.map((g) => (
                <tr key={g.email} className="border-t border-dark-700">
                  <td className="py-1.5 px-2.5 text-dark-100">{g.email}</td>
                  <td className="pr-2">
                    <select value={g.role_id || ""} onChange={(e) => assign(g.email, e.target.value || null, g.extra_permissions)} className={selectCls}>
                      <option value="">Default</option>
                      {roles.map((r) => <option key={r.id} value={r.id}>{r.name}</option>)}
                    </select>
                  </td>
                  <td className="pr-2"><Chips keys={g.effective_permissions} note={note} /></td>
                  <td className="text-right pr-2.5">
                    <button onClick={() => unassign(g.email)} title="Drop the grant — back to the default" className={`${iconButton} hover:text-danger-400`}>
                      <svg className="w-3.5 h-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.8}>
                        <path strokeLinecap="round" strokeLinejoin="round" d="M6 18L18 6M6 6l12 12" />
                      </svg>
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </section>
    </div>
  );
}
