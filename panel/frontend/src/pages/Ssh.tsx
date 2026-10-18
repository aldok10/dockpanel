import { useState, useEffect, useCallback } from "react";
import { Navigate } from "react-router-dom";
import { useAuth } from "../context/AuthContext";
import { api } from "../api";

/**
 * The SSH screen — the one place for the Linux logins the panel itself made.
 *
 * A panel user may carry an `os_username`; the agent provisions the matching
 * account so its owner can sign in over SSH (see `routes/ssh.rs`). This page is
 * that feature's front door: list the logins, lock and unlock their passwords,
 * change the password, install the authorized keys that let someone in without
 * one, and reach the daemon's own settings. Its own page rather than a tab of
 * Users because keys and daemon state are not user attributes.
 */

interface SshAccount {
  id: string;
  email: string;
  role: string;
  os_username: string;
  os_locked: boolean;
  created_at: string;
}

interface AccountKey {
  key_type: string;
  fingerprint: string;
  comment: string;
  preview: string;
}

interface RootKey {
  type: string;
  fingerprint: string;
  comment: string;
  key: string;
}

interface PanelUser {
  id: string;
  email: string;
  role: string;
  os_username: string | null;
}

interface SecurityOverview {
  ssh_port: number;
  ssh_password_auth: boolean;
  ssh_root_login: boolean;
}

type Flash = { text: string; type: "success" | "error" | "" };

export default function Ssh() {
  const { user: authUser } = useAuth();
  // Ahead of the loader effect, exactly as Users.tsx does: the page is admin-only
  // and a redirect is an effect too.
  if (authUser?.role !== "admin") return <Navigate to="/" replace />;

  const [accounts, setAccounts] = useState<SshAccount[]>([]);
  const [overview, setOverview] = useState<SecurityOverview | null>(null);
  const [rootKeys, setRootKeys] = useState<RootKey[]>([]);
  const [panelUsers, setPanelUsers] = useState<PanelUser[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [message, setMessage] = useState<Flash>({ text: "", type: "" });

  const [busyId, setBusyId] = useState<string | null>(null);
  const [removeTarget, setRemoveTarget] = useState<string | null>(null);

  const [addOpen, setAddOpen] = useState(false);
  const [addUserId, setAddUserId] = useState("");
  const [addUsername, setAddUsername] = useState("");
  const [addPassword, setAddPassword] = useState("");
  const [adding, setAdding] = useState(false);

  const [resetTarget, setResetTarget] = useState<string | null>(null);
  const [resetValue, setResetValue] = useState("");
  const [resetting, setResetting] = useState(false);

  const [keysFor, setKeysFor] = useState<SshAccount | null>(null);
  const [keys, setKeys] = useState<AccountKey[]>([]);
  const [keysLoading, setKeysLoading] = useState(false);
  const [newKey, setNewKey] = useState("");
  const [addingKey, setAddingKey] = useState(false);
  const [keyRemove, setKeyRemove] = useState<string | null>(null);

  const [newRootKey, setNewRootKey] = useState("");
  const [addingRootKey, setAddingRootKey] = useState(false);
  const [portValue, setPortValue] = useState("");
  const [serverBusy, setServerBusy] = useState(false);

  const flash = (text: string, type: "success" | "error") => setMessage({ text, type });

  const load = useCallback(async () => {
    setLoading(true);
    setError("");
    try {
      const [accts, ov, users] = await Promise.all([
        api.get<SshAccount[]>("/ssh/accounts"),
        api.get<SecurityOverview>("/security/overview").catch(() => null),
        api.get<PanelUser[]>("/users").catch(() => [] as PanelUser[]),
      ]);
      setAccounts(accts);
      setOverview(ov);
      if (ov) setPortValue(String(ov.ssh_port));
      setPanelUsers(users);
    } catch (e) {
      setError(e instanceof Error ? e.message : "Failed to load SSH accounts");
    } finally {
      setLoading(false);
    }
    api
      .get<{ keys: RootKey[] }>("/ssh-keys")
      .then((d) => setRootKeys(d.keys || []))
      .catch(() => {});
  }, []);

  useEffect(() => {
    load();
  }, [load]);

  const effectiveLocked = (a: SshAccount) => a.role === "suspended" || a.os_locked;

  const statusOf = (a: SshAccount) => {
    if (a.role === "suspended")
      return { label: "Suspended", cls: "bg-danger-500/15 text-danger-400" };
    if (a.os_locked)
      return { label: "Password off", cls: "bg-warn-500/15 text-warn-400" };
    return { label: "Active", cls: "bg-rust-500/15 text-rust-400" };
  };

  const handleSetState = async (acct: SshAccount, locked: boolean) => {
    setBusyId(acct.id);
    setMessage({ text: "", type: "" });
    try {
      const r = await api.post<{ locked: boolean; suspended: boolean }>(
        `/ssh/accounts/${acct.id}/state`,
        { locked },
      );
      setAccounts((prev) =>
        prev.map((a) => (a.id === acct.id ? { ...a, os_locked: locked } : a)),
      );
      if (r.suspended) {
        flash(
          "The panel account is suspended, so the SSH password stays locked until it is restored.",
          "success",
        );
      } else {
        flash(locked ? "SSH password logins disabled." : "SSH password logins enabled.", "success");
      }
    } catch (e) {
      flash(e instanceof Error ? e.message : "Failed to update SSH access", "error");
    } finally {
      setBusyId(null);
    }
  };

  const handleRemove = async (acct: SshAccount) => {
    setBusyId(acct.id);
    try {
      await api.delete(`/ssh/accounts/${acct.id}`);
      setAccounts((prev) => prev.filter((a) => a.id !== acct.id));
      setRemoveTarget(null);
      flash(
        `SSH login '${acct.os_username}' removed. The panel account is unchanged.`,
        "success",
      );
    } catch (e) {
      flash(e instanceof Error ? e.message : "Failed to remove SSH login", "error");
    } finally {
      setBusyId(null);
    }
  };

  const handleReset = async (acct: SshAccount) => {
    setResetting(true);
    try {
      await api.post(`/users/${acct.id}/reset-password`, { password: resetValue });
      setResetTarget(null);
      setResetValue("");
      flash(`Password updated. The SSH login '${acct.os_username}' uses it too.`, "success");
    } catch (e) {
      flash(e instanceof Error ? e.message : "Failed to reset password", "error");
    } finally {
      setResetting(false);
    }
  };

  const candidates = panelUsers.filter((u) => !u.os_username && u.role !== "suspended");

  const handleAdd = async () => {
    setAdding(true);
    try {
      await api.post("/ssh/accounts", {
        user_id: addUserId,
        username: addUsername.trim(),
        password: addPassword,
      });
      setAddOpen(false);
      setAddUserId("");
      setAddUsername("");
      setAddPassword("");
      await load();
      flash("SSH login created.", "success");
    } catch (e) {
      flash(e instanceof Error ? e.message : "Failed to create SSH login", "error");
    } finally {
      setAdding(false);
    }
  };

  const openKeys = async (acct: SshAccount) => {
    setKeysFor(acct);
    setKeys([]);
    setNewKey("");
    setKeyRemove(null);
    setKeysLoading(true);
    setMessage({ text: "", type: "" });
    try {
      const d = await api.get<{ keys: AccountKey[] }>(`/ssh/accounts/${acct.id}/keys`);
      setKeys(d.keys || []);
    } catch (e) {
      flash(e instanceof Error ? e.message : "Failed to load keys", "error");
      setKeysFor(null);
    } finally {
      setKeysLoading(false);
    }
  };

  const handleAddKey = async () => {
    if (!keysFor) return;
    setAddingKey(true);
    try {
      await api.post(`/ssh/accounts/${keysFor.id}/keys`, { key: newKey.trim() });
      setNewKey("");
      await openKeys(keysFor);
      flash("SSH key installed.", "success");
    } catch (e) {
      flash(e instanceof Error ? e.message : "Failed to add key", "error");
    } finally {
      setAddingKey(false);
    }
  };

  const handleRemoveKey = async (fingerprint: string) => {
    if (!keysFor) return;
    try {
      await api.delete(
        `/ssh/accounts/${keysFor.id}/keys/${encodeURIComponent(fingerprint)}`,
      );
      setKeyRemove(null);
      await openKeys(keysFor);
      flash("SSH key removed.", "success");
    } catch (e) {
      flash(e instanceof Error ? e.message : "Failed to remove key", "error");
    }
  };

  const serverAction = async (path: string, label: string, body?: unknown) => {
    setServerBusy(true);
    setMessage({ text: "", type: "" });
    try {
      await api.post(path, body);
      const ov = await api.get<SecurityOverview>("/security/overview").catch(() => null);
      setOverview(ov);
      if (ov) setPortValue(String(ov.ssh_port));
      flash(label, "success");
    } catch (e) {
      flash(e instanceof Error ? e.message : "Failed to update SSH settings", "error");
    } finally {
      setServerBusy(false);
    }
  };

  if (error) {
    return (
      <div className="p-6 lg:p-8">
        <div className="bg-danger-500/10 text-danger-400 px-4 py-3 rounded-lg border border-danger-500/20">
          {error}
        </div>
      </div>
    );
  }

  return (
    <div>
      <div className="page-header">
        <div>
          <h1 className="page-header-title">SSH</h1>
          <p className="page-header-subtitle">
            Linux logins on this server, their keys, and the SSH daemon
          </p>
        </div>
        <button
          onClick={() => setAddOpen(true)}
          className="px-4 py-2 bg-rust-500 text-white rounded-lg text-sm font-medium hover:bg-rust-600 transition-colors flex items-center gap-2"
        >
          <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
            <path strokeLinecap="round" strokeLinejoin="round" d="M12 4.5v15m7.5-7.5h-15" />
          </svg>
          Add SSH Login
        </button>
      </div>

      <div className="p-6 lg:p-8 space-y-6">
        {message.text && (
          <div
            className={`px-4 py-3 rounded-lg text-sm border ${
              message.type === "success"
                ? "bg-rust-500/10 text-rust-400 border-rust-500/20"
                : "bg-danger-500/10 text-danger-400 border-danger-500/20"
            }`}
          >
            {message.text}
          </div>
        )}

        {/* ── SSH daemon ─────────────────────────────────────────────── */}
        <div className="bg-dark-800 rounded-lg border border-dark-500 overflow-hidden">
          <div className="px-5 py-3 border-b border-dark-600">
            <h3 className="text-xs font-medium text-dark-300 uppercase font-mono tracking-widest">
              SSH Server
            </h3>
            <p className="text-xs text-dark-200 mt-0.5">
              The daemon's own settings, applied with <code>sshd_config</code>
            </p>
          </div>
          <div className="p-5">
            {!overview ? (
              <p className="text-xs text-dark-400">Settings unavailable — the agent did not answer.</p>
            ) : (
              <div className="grid gap-4 sm:grid-cols-3">
                <div>
                  <div className="text-[10px] text-dark-400 uppercase font-mono tracking-widest">Port</div>
                  <div className="text-lg text-dark-50 font-mono">{overview.ssh_port}</div>
                </div>
                <div>
                  <div className="text-[10px] text-dark-400 uppercase font-mono tracking-widest">
                    Password auth
                  </div>
                  <div className={`text-sm font-medium ${overview.ssh_password_auth ? "text-rust-400" : "text-dark-300"}`}>
                    {overview.ssh_password_auth ? "Enabled" : "Disabled"}
                  </div>
                </div>
                <div>
                  <div className="text-[10px] text-dark-400 uppercase font-mono tracking-widest">
                    Root login
                  </div>
                  <div className={`text-sm font-medium ${overview.ssh_root_login ? "text-warn-400" : "text-rust-400"}`}>
                    {overview.ssh_root_login ? "Permitted" : "Disabled"}
                  </div>
                </div>
              </div>
            )}

            {overview && (
              <div className="flex flex-wrap items-center gap-2 mt-5 pt-4 border-t border-dark-600">
                <button
                  disabled={serverBusy}
                  onClick={() =>
                    serverAction(
                      overview.ssh_password_auth
                        ? "/security/ssh/disable-password"
                        : "/security/ssh/enable-password",
                      overview.ssh_password_auth
                        ? "Password authentication disabled."
                        : "Password authentication enabled.",
                    )
                  }
                  className="px-3 py-1.5 text-xs rounded bg-dark-700 text-dark-100 hover:bg-dark-600 disabled:opacity-50"
                >
                  {overview.ssh_password_auth ? "Disable password auth" : "Enable password auth"}
                </button>
                {overview.ssh_root_login && (
                  <button
                    disabled={serverBusy}
                    onClick={() => serverAction("/security/ssh/disable-root", "Root SSH login disabled.")}
                    className="px-3 py-1.5 text-xs rounded bg-dark-700 text-dark-100 hover:bg-dark-600 disabled:opacity-50"
                  >
                    Disable root login
                  </button>
                )}
                <div className="flex items-center gap-1.5 ml-auto">
                  <input
                    type="number"
                    min={1}
                    max={65535}
                    value={portValue}
                    onChange={(e) => setPortValue(e.target.value)}
                    aria-label="SSH port"
                    className="w-24 px-2 py-1.5 bg-dark-900 border border-dark-500 rounded text-xs font-mono text-dark-100 focus:outline-none focus:border-dark-400"
                  />
                  <button
                    disabled={serverBusy || !portValue || Number(portValue) === overview.ssh_port}
                    onClick={() =>
                      serverAction("/security/ssh/change-port", `SSH port set to ${portValue}.`, {
                        port: Number(portValue),
                      })
                    }
                    className="px-3 py-1.5 text-xs rounded bg-dark-700 text-dark-100 hover:bg-dark-600 disabled:opacity-50"
                  >
                    Change port
                  </button>
                </div>
              </div>
            )}
            {overview?.ssh_password_auth && (
              <p className="text-xs text-warn-400 mt-3">
                Turning password authentication off shuts every password login below — including SSH
                logins created from the Users screen. Key-based logins keep working.
              </p>
            )}
          </div>
        </div>

        {/* ── SSH logins ─────────────────────────────────────────────── */}
        <div className="bg-dark-800 rounded-lg border border-dark-500 overflow-x-auto">
          <div className="px-5 py-3 border-b border-dark-600">
            <h3 className="text-xs font-medium text-dark-300 uppercase font-mono tracking-widest">
              SSH Logins
            </h3>
            <p className="text-xs text-dark-200 mt-0.5">
              Linux accounts the panel created. Create one by giving a panel user an SSH username, or
              use Add SSH Login.
            </p>
          </div>
          {loading ? (
            <div className="p-6 space-y-3 animate-pulse">
              {[...Array(3)].map((_, i) => (
                <div key={i} className="h-12 bg-dark-700 rounded w-full" />
              ))}
            </div>
          ) : accounts.length === 0 ? (
            <div className="p-12 text-center">
              <p className="text-dark-200 font-medium">No SSH logins</p>
              <p className="text-dark-400 text-sm mt-1">
                Give a panel user an SSH username, or add one to an existing account.
              </p>
            </div>
          ) : (
            <table className="w-full">
              <thead>
                <tr className="bg-dark-900 border-b border-dark-500">
                  <th scope="col" className="text-left text-xs font-medium text-dark-200 uppercase font-mono tracking-widest px-5 py-3">
                    Login
                  </th>
                  <th scope="col" className="text-left text-xs font-medium text-dark-200 uppercase font-mono tracking-widest px-5 py-3">
                    Panel account
                  </th>
                  <th scope="col" className="text-left text-xs font-medium text-dark-200 uppercase font-mono tracking-widest px-5 py-3 w-36">
                    Status
                  </th>
                  <th scope="col" className="text-right text-xs font-medium text-dark-200 uppercase font-mono tracking-widest px-5 py-3 w-72">
                    Actions
                  </th>
                </tr>
              </thead>
              <tbody className="divide-y divide-dark-600">
                {accounts.map((acct) => {
                  const st = statusOf(acct);
                  return (
                    <tr key={acct.id} className={`table-row-hover ${acct.role === "suspended" ? "opacity-60" : ""}`}>
                      <td className="px-5 py-4">
                        <span className="text-sm text-dark-50 font-mono">{acct.os_username}</span>
                      </td>
                      <td className="px-5 py-4">
                        <span className="text-sm text-dark-200 font-mono">{acct.email}</span>
                        <span className="text-xs text-dark-400 ml-2">{acct.role}</span>
                      </td>
                      <td className="px-5 py-4">
                        <span className={`inline-flex px-2.5 py-0.5 rounded-full text-xs font-medium ${st.cls}`}>
                          {st.label}
                        </span>
                      </td>
                      <td className="px-5 py-4 text-right">
                        {removeTarget === acct.id ? (
                          <div className="flex items-center justify-end gap-1">
                            <span className="text-xs text-dark-300 mr-1">Remove SSH login?</span>
                            <button
                              onClick={() => handleRemove(acct)}
                              disabled={busyId === acct.id}
                              className="px-2 py-1 bg-danger-500 text-white rounded text-xs disabled:opacity-50"
                            >
                              Confirm
                            </button>
                            <button
                              onClick={() => setRemoveTarget(null)}
                              className="px-2 py-1 bg-dark-600 text-dark-200 rounded text-xs"
                            >
                              Cancel
                            </button>
                          </div>
                        ) : (
                          <div className="flex items-center justify-end gap-1">
                            <button
                              onClick={() => handleSetState(acct, !acct.os_locked)}
                              disabled={busyId === acct.id}
                              className={`px-2 py-1 text-xs rounded transition-colors disabled:opacity-50 ${
                                effectiveLocked(acct)
                                  ? "text-rust-400 bg-rust-500/10 hover:bg-rust-500/20"
                                  : "text-warn-400 bg-warn-500/10 hover:bg-warn-500/20"
                              }`}
                              title={
                                effectiveLocked(acct)
                                  ? "Allow password logins again"
                                  : "Refuse new password logins"
                              }
                            >
                              {busyId === acct.id && (
                                <span className="inline-block w-3 h-3 mr-1 border-2 border-current/30 border-t-current rounded-full animate-spin align-middle" />
                              )}
                              {effectiveLocked(acct) ? "Enable" : "Disable"}
                            </button>
                            <button
                              onClick={() => openKeys(acct)}
                              className="px-2 py-1 text-xs text-dark-300 hover:text-dark-50 bg-dark-700 rounded hover:bg-dark-600 transition-colors"
                              title="Manage authorized keys"
                            >
                              Keys
                            </button>
                            <button
                              onClick={() => {
                                setResetTarget(acct.id);
                                setResetValue("");
                              }}
                              className="px-2 py-1 text-xs text-dark-300 hover:text-dark-50 bg-dark-700 rounded hover:bg-dark-600 transition-colors"
                              title="Change the password"
                            >
                              Reset PW
                            </button>
                            <button
                              onClick={() => setRemoveTarget(acct.id)}
                              className="text-dark-300 hover:text-danger-500 transition-colors px-1"
                              title="Remove the SSH login (the panel account stays)"
                            >
                              <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}>
                                <path strokeLinecap="round" strokeLinejoin="round" d="m14.74 9-.346 9m-4.788 0L9.26 9m9.968-3.21c.342.052.682.107 1.022.166m-1.022-.165L18.16 19.673a2.25 2.25 0 0 1-2.244 2.077H8.084a2.25 2.25 0 0 1-2.244-2.077L4.772 5.79m14.456 0a48.108 48.108 0 0 0-3.478-.397m-12 .562c.34-.059.68-.114 1.022-.165m0 0a48.11 48.11 0 0 1 3.478-.397m7.5 0v-.916c0-1.18-.91-2.164-2.09-2.201a51.964 51.964 0 0 0-3.32 0c-1.18.037-2.09 1.022-2.09 2.201v.916m7.5 0a48.667 48.667 0 0 00-7.5 0" />
                              </svg>
                            </button>
                          </div>
                        )}
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          )}
        </div>

        {/* ── Root keys ──────────────────────────────────────────────── */}
        <div className="bg-dark-800 rounded-lg border border-dark-500 overflow-hidden">
          <div className="px-5 py-3 border-b border-dark-600">
            <h3 className="text-xs font-medium text-dark-300 uppercase font-mono tracking-widest">
              Root SSH Keys
            </h3>
            <p className="text-xs text-dark-200 mt-0.5">Authorized keys for the root account</p>
          </div>
          <div className="p-5 space-y-3">
            {rootKeys.length === 0 && (
              <p className="text-xs text-dark-400 text-center py-2">No SSH keys configured</p>
            )}
            {rootKeys.map((k) => (
              <div
                key={k.fingerprint}
                className="flex items-center justify-between bg-dark-900 border border-dark-500 px-4 py-2"
              >
                <div className="min-w-0">
                  <span className="text-xs text-dark-50 font-mono block truncate">{k.comment || k.key}</span>
                  <span className="text-[10px] text-dark-300 font-mono">{k.fingerprint}</span>
                </div>
                <button
                  onClick={async () => {
                    try {
                      await api.delete(`/ssh-keys/${encodeURIComponent(k.fingerprint)}`);
                      setRootKeys(rootKeys.filter((x) => x.fingerprint !== k.fingerprint));
                      flash("Key removed", "success");
                    } catch (e) {
                      flash(e instanceof Error ? e.message : "Failed to remove key", "error");
                    }
                  }}
                  className="p-1 text-dark-300 hover:text-danger-400 shrink-0 ml-2"
                  title="Remove key"
                >
                  <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}>
                    <path strokeLinecap="round" strokeLinejoin="round" d="M6 18L18 6M6 6l12 12" />
                  </svg>
                </button>
              </div>
            ))}
            <div className="flex gap-2">
              <input
                type="text"
                value={newRootKey}
                onChange={(e) => setNewRootKey(e.target.value)}
                placeholder="ssh-ed25519 AAAA... user@host"
                aria-label="New root SSH key"
                className="flex-1 px-3 py-2 border border-dark-500 rounded-lg text-xs font-mono focus:ring-2 focus:ring-accent-500 outline-none"
              />
              <button
                disabled={addingRootKey || !newRootKey.startsWith("ssh-")}
                onClick={async () => {
                  setAddingRootKey(true);
                  try {
                    await api.post("/ssh-keys", { key: newRootKey });
                    setNewRootKey("");
                    const d = await api.get<{ keys: RootKey[] }>("/ssh-keys");
                    setRootKeys(d.keys || []);
                    flash("Key added", "success");
                  } catch (e) {
                    flash(e instanceof Error ? e.message : "Failed", "error");
                  } finally {
                    setAddingRootKey(false);
                  }
                }}
                className="px-3 py-2 bg-rust-500 text-white rounded-lg text-xs font-medium hover:bg-rust-600 disabled:opacity-50 shrink-0"
              >
                {addingRootKey ? "Adding..." : "Add Key"}
              </button>
            </div>
          </div>
        </div>
      </div>

      {/* ── Add SSH login dialog ─────────────────────────────────────── */}
      {addOpen && (
        <div
          className="fixed inset-0 bg-black/30 flex items-center justify-center z-50 dp-modal-overlay"
          role="dialog"
          aria-labelledby="add-ssh-title"
          onKeyDown={(e) => {
            if (e.key === "Escape") setAddOpen(false);
          }}
        >
          <div className="bg-dark-800 rounded-lg shadow-xl p-6 w-[420px] dp-modal">
            <h3 id="add-ssh-title" className="text-xs font-medium text-dark-300 uppercase font-mono tracking-widest mb-4">
              Add SSH Login
            </h3>
            <div className="space-y-4">
              <div>
                <label htmlFor="add-ssh-user" className="block text-sm font-medium text-dark-100 mb-1">
                  Panel account
                </label>
                <select
                  id="add-ssh-user"
                  value={addUserId}
                  onChange={(e) => setAddUserId(e.target.value)}
                  className="w-full px-3 py-2 border border-dark-500 rounded-lg text-sm focus:ring-2 focus:ring-accent-500 focus:border-accent-500"
                >
                  <option value="">Select a user…</option>
                  {candidates.map((u) => (
                    <option key={u.id} value={u.id}>
                      {u.email} ({u.role})
                    </option>
                  ))}
                </select>
                {candidates.length === 0 && (
                  <p className="text-xs text-dark-400 mt-1">
                    Every active panel user already has an SSH login.
                  </p>
                )}
              </div>
              <div>
                <label htmlFor="add-ssh-username" className="block text-sm font-medium text-dark-100 mb-1">
                  SSH username
                </label>
                <input
                  id="add-ssh-username"
                  type="text"
                  value={addUsername}
                  onChange={(e) => setAddUsername(e.target.value)}
                  className="w-full px-3 py-2 border border-dark-500 rounded-lg text-sm font-mono focus:ring-2 focus:ring-accent-500 focus:border-accent-500"
                  placeholder="e.g. alice"
                />
                <p className="text-xs text-dark-400 mt-1">
                  Lowercase letters, digits, <code>_</code> and <code>-</code>. No sudo rights are
                  granted.
                </p>
              </div>
              <div>
                <label htmlFor="add-ssh-password" className="block text-sm font-medium text-dark-100 mb-1">
                  Password
                </label>
                <input
                  id="add-ssh-password"
                  type="password"
                  value={addPassword}
                  onChange={(e) => setAddPassword(e.target.value)}
                  className="w-full px-3 py-2 border border-dark-500 rounded-lg text-sm focus:ring-2 focus:ring-accent-500 focus:border-accent-500"
                  placeholder="Minimum 8 characters"
                />
                <p className="text-xs text-dark-400 mt-1">
                  Also becomes the panel user's password — one credential for both doors.
                </p>
              </div>
            </div>
            <div className="flex justify-end gap-2 mt-6">
              <button
                onClick={() => setAddOpen(false)}
                className="px-4 py-2 text-sm text-dark-300 border border-dark-600 rounded-lg hover:text-dark-100 hover:border-dark-400 transition-colors"
              >
                Cancel
              </button>
              <button
                onClick={handleAdd}
                disabled={adding || !addUserId || !addUsername.trim() || addPassword.length < 8}
                className="flex items-center gap-2 px-4 py-2 bg-rust-500 text-white rounded-lg text-sm font-medium hover:bg-rust-600 disabled:opacity-50"
              >
                {adding && (
                  <span className="w-4 h-4 border-2 border-white/30 border-t-white rounded-full animate-spin" />
                )}
                {adding ? "Creating..." : "Create Login"}
              </button>
            </div>
          </div>
        </div>
      )}

      {/* ── Reset password dialog ────────────────────────────────────── */}
      {resetTarget && (
        <div
          className="fixed inset-0 bg-black/30 flex items-center justify-center z-50 dp-modal-overlay"
          role="dialog"
          aria-labelledby="ssh-reset-title"
          onKeyDown={(e) => {
            if (e.key === "Escape") {
              setResetTarget(null);
              setResetValue("");
            }
          }}
        >
          <div className="bg-dark-800 rounded-lg shadow-xl p-6 w-[420px] dp-modal">
            <h3 id="ssh-reset-title" className="text-xs font-medium text-dark-300 uppercase font-mono tracking-widest mb-4">
              Reset Password
            </h3>
            <p className="text-sm text-dark-200 mb-4">
              New password for{" "}
              <span className="font-mono text-dark-50">
                {accounts.find((a) => a.id === resetTarget)?.os_username}
              </span>
            </p>
            <input
              type="password"
              value={resetValue}
              onChange={(e) => setResetValue(e.target.value)}
              aria-label="New password"
              className="w-full px-3 py-2 border border-dark-500 rounded-lg text-sm focus:ring-2 focus:ring-accent-500 focus:border-accent-500"
              placeholder="Minimum 8 characters"
              autoFocus
              onKeyDown={(e) => {
                if (e.key === "Enter" && resetValue.length >= 8) {
                  const a = accounts.find((x) => x.id === resetTarget);
                  if (a) handleReset(a);
                }
              }}
            />
            <p className="text-xs text-dark-400 mt-2">
              This changes the panel password too — the SSH login and the panel share one credential.
            </p>
            <div className="flex justify-end gap-2 mt-6">
              <button
                onClick={() => {
                  setResetTarget(null);
                  setResetValue("");
                }}
                className="px-4 py-2 text-sm text-dark-300 border border-dark-600 rounded-lg hover:text-dark-100 hover:border-dark-400 transition-colors"
              >
                Cancel
              </button>
              <button
                onClick={() => {
                  const a = accounts.find((x) => x.id === resetTarget);
                  if (a) handleReset(a);
                }}
                disabled={resetting || resetValue.length < 8}
                className="flex items-center gap-2 px-4 py-2 bg-rust-500 text-white rounded-lg text-sm font-medium hover:bg-rust-600 disabled:opacity-50"
              >
                {resetting && (
                  <span className="w-4 h-4 border-2 border-white/30 border-t-white rounded-full animate-spin" />
                )}
                {resetting ? "Resetting..." : "Reset Password"}
              </button>
            </div>
          </div>
        </div>
      )}

      {/* ── Authorized keys dialog ───────────────────────────────────── */}
      {keysFor && (
        <div
          className="fixed inset-0 bg-black/30 flex items-center justify-center z-50 dp-modal-overlay"
          role="dialog"
          aria-labelledby="ssh-keys-title"
          onKeyDown={(e) => {
            if (e.key === "Escape") setKeysFor(null);
          }}
        >
          <div className="bg-dark-800 rounded-lg shadow-xl p-6 w-[560px] max-w-[92vw] dp-modal">
            <h3 id="ssh-keys-title" className="text-xs font-medium text-dark-300 uppercase font-mono tracking-widest mb-1">
              Authorized Keys
            </h3>
            <p className="text-sm text-dark-200 mb-4">
              Public keys for{" "}
              <span className="font-mono text-dark-50">{keysFor.os_username}</span>
            </p>
            {keysLoading ? (
              <div className="space-y-2 animate-pulse">
                {[...Array(2)].map((_, i) => (
                  <div key={i} className="h-12 bg-dark-700 rounded w-full" />
                ))}
              </div>
            ) : keys.length === 0 ? (
              <p className="text-xs text-dark-400 text-center py-4">
                No keys — this account signs in with its password only.
              </p>
            ) : (
              <div className="space-y-2 max-h-64 overflow-y-auto">
                {keys.map((k) => (
                  <div
                    key={k.fingerprint}
                    className="flex items-center justify-between bg-dark-900 border border-dark-500 px-4 py-2"
                  >
                    <div className="min-w-0">
                      <span className="text-xs text-dark-50 font-mono block truncate">
                        {k.comment || k.preview}
                      </span>
                      <span className="text-[10px] text-dark-300 font-mono">{k.fingerprint}</span>
                    </div>
                    {keyRemove === k.fingerprint ? (
                      <div className="flex items-center gap-1 shrink-0 ml-2">
                        <button
                          onClick={() => handleRemoveKey(k.fingerprint)}
                          className="px-2 py-1 bg-danger-500 text-white rounded text-[10px]"
                        >
                          Confirm
                        </button>
                        <button
                          onClick={() => setKeyRemove(null)}
                          className="px-2 py-1 bg-dark-600 text-dark-200 rounded text-[10px]"
                        >
                          Cancel
                        </button>
                      </div>
                    ) : (
                      <button
                        onClick={() => setKeyRemove(k.fingerprint)}
                        className="p-1 text-dark-300 hover:text-danger-400 shrink-0 ml-2"
                        title="Remove key"
                      >
                        <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}>
                          <path strokeLinecap="round" strokeLinejoin="round" d="M6 18L18 6M6 6l12 12" />
                        </svg>
                      </button>
                    )}
                  </div>
                ))}
              </div>
            )}
            <div className="flex gap-2 mt-4">
              <input
                type="text"
                value={newKey}
                onChange={(e) => setNewKey(e.target.value)}
                placeholder="ssh-ed25519 AAAA... user@host"
                aria-label="New public key"
                className="flex-1 px-3 py-2 border border-dark-500 rounded-lg text-xs font-mono focus:ring-2 focus:ring-accent-500 outline-none"
              />
              <button
                disabled={addingKey || !newKey.trim().startsWith("ssh-")}
                onClick={handleAddKey}
                className="px-3 py-2 bg-rust-500 text-white rounded-lg text-xs font-medium hover:bg-rust-600 disabled:opacity-50 shrink-0"
              >
                {addingKey ? "Adding..." : "Add Key"}
              </button>
            </div>
            <div className="flex justify-end mt-6">
              <button
                onClick={() => setKeysFor(null)}
                className="px-4 py-2 text-sm text-dark-300 border border-dark-600 rounded-lg hover:text-dark-100 hover:border-dark-400 transition-colors"
              >
                Close
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
