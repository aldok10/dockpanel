import { useEffect, useState } from "react";
import { api } from "../api";

/**
 * Mail API administration: roles, per-mailbox permissions, and tokens.
 *
 * This is where mail-API tokens are minted now. Each token carries its own
 * subset of a four-entry permission catalog — `send`, `read`, `write` (the two
 * halves of managing its own mailbox) and `domain` (the whole server) — and its
 * effective set is that subset *intersected* with what the mailbox is currently
 * allowed, recomputed by the daemon on every request. A token may also carry an
 * expiry, after which it is refused like a revoked one. Two consequences the UI
 * has to make visible rather than hide:
 *
 *   * a token can be narrower than its mailbox — a monitoring credential wants
 *     `read` alone, a contact form `send` alone — and the narrowest useful token
 *     is the safe choice;
 *   * changing a mailbox's role or removing an extra permission downgrades the
 *     tokens already handed out, so it is a revocation, not just a setting.
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

  return (
    <div className="bg-dark-800 rounded-lg border border-dark-500 p-3 elevation-1">
      <div className="flex items-center justify-between mb-2">
        <h3 className="text-xs font-medium text-dark-300 uppercase font-mono tracking-widest">Mail API — Tokens &amp; Permissions</h3>
        <div className="flex border border-dark-600 rounded overflow-hidden">
          {(["tokens", "access"] as const).map((t) => (
            <button key={t} onClick={() => setTab(t)}
              className={`px-2 py-1 text-[11px] font-medium uppercase tracking-wider transition-colors ${tab === t ? "bg-dark-600 text-dark-50" : "text-dark-300 hover:text-dark-100"}`}>
              {t === "tokens" ? "Tokens" : "Roles & permissions"}
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
          describe={describe}
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
    </div>
  );
}

// ── Tokens ──────────────────────────────────────────────────────────────

function TokensTab({
  tokens, perms, grantFor, onMessage, onChanged, describe,
}: {
  tokens: MailApiToken[];
  perms: PermissionInfo[];
  grantFor: (email: string) => Promise<MailApiGrant>;
  onMessage: (m: Message) => void;
  onChanged: () => void;
  describe: (key: string) => PermissionInfo | undefined;
}) {
  const [email, setEmail] = useState("");
  const [name, setName] = useState("");
  const [allowed, setAllowed] = useState<string[]>([]);
  const [chosen, setChosen] = useState<string[]>([]);
  const [lifetime, setLifetime] = useState("0");
  const [minted, setMinted] = useState<{ token: string; email: string } | null>(null);
  const [busy, setBusy] = useState(false);

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
    } catch (err) {
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

  return (
    <div>
      {minted && (
        <div className="border border-rust-500/60 bg-rust-500/10 rounded-lg p-3 mb-3">
          <p className="text-[11px] font-semibold text-dark-50 mb-1">
            New token for {minted.email} — copy it now, it is shown only once:
          </p>
          <code className="block text-[11px] text-dark-100 break-all select-all bg-dark-900 rounded p-2">{minted.token}</code>
          <button onClick={() => setMinted(null)} className="mt-2 px-2 py-1 bg-dark-700 text-dark-100 rounded text-[11px] font-medium hover:bg-dark-600">Dismiss</button>
        </div>
      )}

      <div className="border border-dark-600 rounded-lg p-3 mb-3">
        <p className="text-[11px] text-dark-300 mb-2">Mint a token for a mailbox</p>
        <div className="flex flex-wrap gap-2 items-end">
          <label className="flex-1 min-w-[200px]">
            <span className="block text-[10px] text-dark-400 uppercase tracking-wider mb-1">Mailbox email</span>
            <input value={email} onChange={(e) => setEmail(e.target.value)} onBlur={loadAllowance}
              placeholder="user@example.com"
              className="w-full px-2 py-1.5 bg-dark-900 border border-dark-600 rounded text-xs text-dark-50 focus:border-dark-400 outline-none" />
          </label>
          <label className="w-40">
            <span className="block text-[10px] text-dark-400 uppercase tracking-wider mb-1">Label (optional)</span>
            <input value={name} onChange={(e) => setName(e.target.value)} placeholder="e.g. Monitoring"
              className="w-full px-2 py-1.5 bg-dark-900 border border-dark-600 rounded text-xs text-dark-50 focus:border-dark-400 outline-none" />
          </label>
          <label className="w-36">
            <span className="block text-[10px] text-dark-400 uppercase tracking-wider mb-1">Expires</span>
            <select value={lifetime} onChange={(e) => setLifetime(e.target.value)}
              className="w-full px-2 py-1.5 bg-dark-900 border border-dark-600 rounded text-xs text-dark-50 focus:border-dark-400 outline-none">
              <option value="0">Never</option>
              <option value="30">In 30 days</option>
              <option value="90">In 90 days</option>
              <option value="180">In 180 days</option>
              <option value="365">In 1 year</option>
            </select>
          </label>
          <button onClick={mint} disabled={busy || !email.includes("@") || chosen.length === 0}
            className="px-3 py-1.5 bg-rust-500 text-white rounded text-xs font-medium hover:bg-rust-600 disabled:opacity-40 transition-colors">
            Create token
          </button>
        </div>

        <div className="mt-2">
          {allowed.length === 0 ? (
            <p className="text-[11px] text-dark-400">Enter a mailbox to see which permissions it may be given.</p>
          ) : (
            <div className="flex flex-wrap gap-3">
              {allowed.map((key) => {
                const info = describe(key);
                return (
                  <label key={key} className="flex items-center gap-1.5 text-[11px] text-dark-100" title={info?.description || ""}>
                    <input type="checkbox" checked={chosen.includes(key)}
                      onChange={(e) => setChosen(e.target.checked ? [...new Set([...chosen, key])] : chosen.filter((k) => k !== key))}
                      className="accent-rust-500" />
                    <span className="font-mono">{key}</span>
                    <span className="text-dark-400">— {info?.name}</span>
                  </label>
                );
              })}
            </div>
          )}
        </div>
      </div>

      {tokens.length === 0 ? (
        <p className="text-[11px] text-dark-400">No tokens yet.</p>
      ) : (
        <table className="w-full text-[11px]">
          <thead>
            <tr className="text-dark-400 uppercase tracking-wider text-left">
              <th className="py-1">Token</th><th>Mailbox</th><th>Name</th><th>Permissions</th><th>Expires</th><th>Last used</th><th></th>
            </tr>
          </thead>
          <tbody>
            {tokens.map((t) => (
              <tr key={t.id} className={`border-t border-dark-700 ${t.revoked ? "opacity-40" : ""}`}>
                <td className="py-1 font-mono">{t.token_prefix}…</td>
                <td className="text-dark-100">{t.email}</td>
                <td className="text-dark-300">{t.name || "—"}</td>
                <td className="font-mono text-dark-100">{t.permissions.join(", ") || "—"}</td>
                <td className={expired(t) && !t.revoked ? "text-rust-400" : "text-dark-300"}>
                  {t.expires_at
                    ? `${expired(t) ? "expired " : ""}${new Date(t.expires_at).toLocaleDateString()}`
                    : "never"}
                </td>
                <td className="text-dark-300">{t.last_used_at ? new Date(t.last_used_at).toLocaleString() : "never"}</td>
                <td className="text-right">
                  {t.revoked ? (
                    <span className="text-dark-500">revoked</span>
                  ) : (
                    <span className="inline-flex gap-1 items-center">
                      <select value="" onChange={(e) => { if (e.target.value) setExpiry(t.id, e.target.value); }}
                        className="px-1 py-0.5 bg-dark-900 border border-dark-600 rounded text-[11px] text-dark-100">
                        <option value="">Expiry…</option>
                        <option value="0">Never</option>
                        <option value="30">+30 days</option>
                        <option value="90">+90 days</option>
                        <option value="365">+1 year</option>
                      </select>
                      <button onClick={() => rotate(t.id)} className="px-2 py-0.5 bg-dark-700 text-dark-100 rounded hover:bg-dark-600">Rotate</button>
                      <button onClick={() => revoke(t.id)} className="px-2 py-0.5 bg-dark-700 text-dark-100 rounded hover:bg-dark-600">Revoke</button>
                    </span>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}

      {perms.length > 0 && (
        <dl className="mt-3 space-y-1">
          {perms.map((p) => (
            <div key={p.key} className="text-[10px] text-dark-400">
              <dt className="inline font-mono text-dark-200">{p.key}</dt>
              <dd className="inline"> — {p.description}</dd>
            </div>
          ))}
        </dl>
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
  const [roleName, setRoleName] = useState("");
  const [roleDesc, setRoleDesc] = useState("");
  const [rolePerms, setRolePerms] = useState<string[]>([]);
  const [assignEmail, setAssignEmail] = useState("");
  const [assignRole, setAssignRole] = useState<string>("");
  const [assignExtras, setAssignExtras] = useState<string[]>([]);

  const createRole = async () => {
    try {
      await api.post("/mail/api/roles", {
        name: roleName.trim(),
        description: roleDesc.trim() || undefined,
        permissions: rolePerms,
      });
      setRoleName(""); setRoleDesc(""); setRolePerms([]);
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

  const permPicker = (value: string[], onChange: (v: string[]) => void) => (
    <div className="flex flex-wrap gap-3">
      {perms.map((p) => (
        <label key={p.key} className="flex items-center gap-1.5 text-[11px] text-dark-100" title={p.description}>
          <input type="checkbox" checked={value.includes(p.key)}
            onChange={(e) => onChange(e.target.checked ? [...new Set([...value, p.key])] : value.filter((k) => k !== p.key))}
            className="accent-rust-500" />
          <span className="font-mono">{p.key}</span>
          <span className="text-dark-400">— {p.name}</span>
        </label>
      ))}
    </div>
  );

  return (
    <div className="space-y-3">
      <div className="border border-dark-600 rounded-lg p-3">
        <p className="text-[11px] text-dark-300 mb-2">Roles</p>
        <ul className="space-y-1 mb-3">
          {roles.map((r) => (
            <li key={r.id} className="flex items-center justify-between text-[11px] border-t border-dark-700 pt-1">
              <span className="min-w-0">
                <span className="font-mono text-dark-50">{r.name}</span>
                {r.builtin && <span className="ml-2 text-[10px] text-dark-500 uppercase">builtin</span>}
                <span className="ml-2 font-mono text-dark-300">{r.permissions.join(", ")}</span>
                {r.description && <span className="block text-[10px] text-dark-400 truncate">{r.description}</span>}
              </span>
              {!r.builtin && (
                <button onClick={() => deleteRole(r.id)} className="shrink-0 ml-2 px-2 py-0.5 bg-dark-700 text-dark-100 rounded hover:bg-dark-600">Delete</button>
              )}
            </li>
          ))}
        </ul>
        <div className="flex flex-wrap gap-2 items-end">
          <label className="w-40">
            <span className="block text-[10px] text-dark-400 uppercase tracking-wider mb-1">Name</span>
            <input value={roleName} onChange={(e) => setRoleName(e.target.value)} placeholder="mail-auditor"
              className="w-full px-2 py-1.5 bg-dark-900 border border-dark-600 rounded text-xs text-dark-50 focus:border-dark-400 outline-none" />
          </label>
          <label className="flex-1 min-w-[160px]">
            <span className="block text-[10px] text-dark-400 uppercase tracking-wider mb-1">Description</span>
            <input value={roleDesc} onChange={(e) => setRoleDesc(e.target.value)}
              className="w-full px-2 py-1.5 bg-dark-900 border border-dark-600 rounded text-xs text-dark-50 focus:border-dark-400 outline-none" />
          </label>
          <button onClick={createRole} disabled={!roleName.trim() || rolePerms.length === 0}
            className="px-3 py-1.5 bg-rust-500 text-white rounded text-xs font-medium hover:bg-rust-600 disabled:opacity-40 transition-colors">Create role</button>
        </div>
        <div className="mt-2">{permPicker(rolePerms, setRolePerms)}</div>
      </div>

      <div className="border border-dark-600 rounded-lg p-3">
        <p className="text-[11px] text-dark-300 mb-2">Mailbox permissions</p>
        <div className="flex flex-wrap gap-2 items-end mb-2">
          <label className="flex-1 min-w-[200px]">
            <span className="block text-[10px] text-dark-400 uppercase tracking-wider mb-1">Mailbox email</span>
            <input value={assignEmail} onChange={(e) => setAssignEmail(e.target.value)} placeholder="user@example.com"
              className="w-full px-2 py-1.5 bg-dark-900 border border-dark-600 rounded text-xs text-dark-50 focus:border-dark-400 outline-none" />
          </label>
          <label className="w-48">
            <span className="block text-[10px] text-dark-400 uppercase tracking-wider mb-1">Role</span>
            <select value={assignRole} onChange={(e) => setAssignRole(e.target.value)}
              className="w-full px-2 py-1.5 bg-dark-900 border border-dark-600 rounded text-xs text-dark-50 focus:border-dark-400 outline-none">
              <option value="">Default (self-service)</option>
              {roles.map((r) => <option key={r.id} value={r.id}>{r.name}</option>)}
            </select>
          </label>
          <button onClick={() => assign(assignEmail, assignRole || null, assignExtras)}
            disabled={!assignEmail.includes("@")}
            className="px-3 py-1.5 bg-rust-500 text-white rounded text-xs font-medium hover:bg-rust-600 disabled:opacity-40 transition-colors">Assign</button>
        </div>
        <p className="text-[10px] text-dark-400 uppercase tracking-wider mb-1">Extra permissions</p>
        {permPicker(assignExtras, setAssignExtras)}
      </div>

      <div className="border border-dark-600 rounded-lg p-3">
        <p className="text-[11px] text-dark-300 mb-2">Assigned mailboxes</p>
        {grants.length === 0 ? (
          <p className="text-[11px] text-dark-400">None. Every mailbox gets the default (<span className="font-mono">send, read, write</span>) until assigned here.</p>
        ) : (
          <table className="w-full text-[11px]">
            <thead>
              <tr className="text-dark-400 uppercase tracking-wider text-left">
                <th className="py-1">Mailbox</th><th>Role</th><th>Effective</th><th></th>
              </tr>
            </thead>
            <tbody>
              {grants.map((g) => (
                <tr key={g.email} className="border-t border-dark-700">
                  <td className="py-1 text-dark-100">{g.email}</td>
                  <td>
                    <select value={g.role_id || ""} onChange={(e) => assign(g.email, e.target.value || null, g.extra_permissions)}
                      className="px-1.5 py-0.5 bg-dark-900 border border-dark-600 rounded text-[11px] text-dark-50">
                      <option value="">Default</option>
                      {roles.map((r) => <option key={r.id} value={r.id}>{r.name}</option>)}
                    </select>
                  </td>
                  <td className="font-mono text-dark-100">{g.effective_permissions.join(", ") || "none"}</td>
                  <td className="text-right">
                    <button onClick={() => unassign(g.email)} className="px-2 py-0.5 bg-dark-700 text-dark-100 rounded hover:bg-dark-600">Reset</button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </div>
  );
}
