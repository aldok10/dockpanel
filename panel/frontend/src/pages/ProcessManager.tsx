import { useState, useEffect, useCallback, useMemo } from "react";
import { Navigate } from "react-router-dom";
import { useAuth } from "../context/AuthContext";
import { api } from "../api";
import ConfirmDialog from "../components/ConfirmDialog";

interface ServiceEntry {
  unit: string;
  label: string;
  category: string;
  description: string;
  load_state: string;
  active_state: string;
  sub_state: string;
  enabled: boolean | null;
  main_pid: number | null;
  memory_mb: number | null;
  cpu_pct: number | null;
  uptime_secs: number | null;
  restarts: number | null;
}

interface ServicesResponse {
  init: "systemd" | "openrc" | "none";
  services: ServiceEntry[];
}

interface Process {
  pid: number;
  name: string;
  cpu_pct: number;
  mem_mb: number;
  mem_pct: number;
  user: string;
  cmd: string;
  uptime_secs: number;
  status: string;
}

const CATEGORY_LABELS: Record<string, string> = {
  panel: "DockPanel",
  web: "Web & Runtime",
  data: "Database & Cache",
  mail: "Mail",
  dns: "DNS",
  security: "Security",
  system: "System",
  site: "Site Apps",
};

const CATEGORY_ORDER = ["panel", "site", "web", "data", "mail", "dns", "security", "system"];

function formatUptime(secs: number | null): string {
  if (secs === null || secs < 0) return "—";
  const days = Math.floor(secs / 86400);
  const hours = Math.floor((secs % 86400) / 3600);
  const mins = Math.floor((secs % 3600) / 60);
  if (days > 0) return `${days}d ${hours}h`;
  if (hours > 0) return `${hours}h ${mins}m`;
  if (mins > 0) return `${mins}m`;
  return `${secs}s`;
}

function formatBytesOrDash(mb: number | null): string {
  if (mb === null) return "—";
  if (mb >= 1024) return `${(mb / 1024).toFixed(2)} GB`;
  return `${mb.toFixed(mb < 10 ? 1 : 0)} MB`;
}

function stateTone(active: string): string {
  if (active === "active") return "text-rust-400";
  if (active === "failed") return "text-danger-400";
  if (active === "activating" || active === "deactivating") return "text-warn-400";
  return "text-dark-400";
}

export default function ProcessManager() {
  const { user } = useAuth();
  const [tab, setTab] = useState<"services" | "processes">("services");

  if (!user || user.role !== "admin") return <Navigate to="/" replace />;

  return (
    <div className="p-6 lg:p-8">
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 mb-6 pb-4 border-b border-dark-600">
        <div>
          <h1 className="text-sm font-medium text-dark-300 uppercase font-mono tracking-widest">Process Manager</h1>
          <p className="text-sm text-dark-200 mt-1">
            DockPanel's own daemons, the installed stack, and every running process — with uptime, CPU/RAM and restart counts.
          </p>
        </div>
      </div>
      <div className="flex gap-6 mb-6 text-sm font-mono overflow-x-auto">
        <button
          onClick={() => setTab("services")}
          className={`whitespace-nowrap ${tab === "services" ? "border-b-2 border-rust-500 text-dark-50 pb-2" : "text-dark-300 hover:text-dark-100 pb-2"}`}
        >
          Services
        </button>
        <button
          onClick={() => setTab("processes")}
          className={`whitespace-nowrap ${tab === "processes" ? "border-b-2 border-rust-500 text-dark-50 pb-2" : "text-dark-300 hover:text-dark-100 pb-2"}`}
        >
          All Processes
        </button>
      </div>
      {tab === "services" && <ServicesContent />}
      {tab === "processes" && <ProcessesContent />}
    </div>
  );
}

function ServicesContent() {
  const [data, setData] = useState<ServicesResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  // The unit an action is being run against, so its row can show a spinner and
  // the buttons elsewhere disable for the duration.
  const [busy, setBusy] = useState<string | null>(null);
  // A destructive action the operator has armed but not yet confirmed.
  const [pending, setPending] = useState<{ unit: string; action: "stop" | "restart" } | null>(null);
  const [notice, setNotice] = useState("");

  const load = useCallback(() => {
    api
      .get<ServicesResponse>("/system/services")
      .then((d) => {
        setData(d);
        setError("");
      })
      .catch((e) => setError(e instanceof Error ? e.message : "Failed to load services"))
      .finally(() => setLoading(false));
  }, []);

  useEffect(() => {
    load();
    const id = setInterval(load, 5000);
    return () => clearInterval(id);
  }, [load]);

  const runAction = useCallback(
    async (unit: string, action: "start" | "stop" | "restart") => {
      const verb = action === "restart" ? "Restart" : action === "stop" ? "Stop" : "Start";
      setBusy(unit);
      setNotice("");
      try {
        await api.post("/system/services/action", { unit, action });
        setNotice(`${verb} requested for ${unit}.`);
        // Give systemd/OpenRC a moment to reflect the new state before re-reading.
        setTimeout(load, 1200);
      } catch (e) {
        setNotice(e instanceof Error ? e.message : `${verb} failed for ${unit}`);
      } finally {
        setBusy(null);
      }
    },
    [load],
  );

  // Start takes effect immediately; stop and restart are confirmed first, since
  // both take a service the operator is looking at offline.
  const requestAction = (unit: string, action: "start" | "stop" | "restart") => {
    if (action === "start") {
      void runAction(unit, action);
    } else {
      setPending({ unit, action });
    }
  };

  if (loading && !data) {
    return (
      <div className="space-y-2">
        {[1, 2, 3, 4, 5].map((i) => (
          <div key={i} className="h-12 bg-dark-700 rounded-lg animate-pulse" />
        ))}
      </div>
    );
  }

  if (error && !data) {
    return (
      <div className="bg-dark-800 rounded-lg border border-danger-500/30 p-5">
        <p className="text-sm text-danger-400">{error}</p>
      </div>
    );
  }

  const services = data?.services ?? [];
  const grouped = CATEGORY_ORDER.map((cat) => ({
    cat,
    rows: services.filter((s) => s.category === cat),
  })).filter((g) => g.rows.length > 0);

  return (
    <div className="space-y-5">
      {data?.init === "none" && (
        <div className="bg-dark-800 rounded-lg border border-warn-500/30 p-4">
          <p className="text-sm text-warn-400">
            No systemd or OpenRC detected on this host — service status is unavailable here.
          </p>
        </div>
      )}

      {notice && (
        <div className="bg-dark-800 rounded-lg border border-dark-600 px-4 py-2">
          <p className="text-xs text-dark-200 font-mono">{notice}</p>
        </div>
      )}

      {grouped.map(({ cat, rows }) => (
        <div key={cat} className="bg-dark-800 rounded-lg border border-dark-600 overflow-hidden">
          <div className="px-5 py-3 border-b border-dark-600">
            <h3 className="text-xs font-medium text-dark-300 uppercase font-mono tracking-widest">
              {CATEGORY_LABELS[cat] ?? cat}
            </h3>
          </div>
          <div className="overflow-x-auto">
            <table className="w-full">
              <thead>
                <tr className="bg-dark-900">
                  <th className="text-left text-xs font-medium text-dark-200 uppercase font-mono tracking-widest px-5 py-2">Service</th>
                  <th className="text-left text-xs font-medium text-dark-200 uppercase font-mono tracking-widest px-3 py-2">Status</th>
                  <th className="text-right text-xs font-medium text-dark-200 uppercase font-mono tracking-widest px-3 py-2">Uptime</th>
                  <th className="text-right text-xs font-medium text-dark-200 uppercase font-mono tracking-widest px-3 py-2">CPU</th>
                  <th className="text-right text-xs font-medium text-dark-200 uppercase font-mono tracking-widest px-3 py-2">Memory</th>
                  <th className="text-right text-xs font-medium text-dark-200 uppercase font-mono tracking-widest px-3 py-2">Restarts</th>
                  <th className="text-right text-xs font-medium text-dark-200 uppercase font-mono tracking-widest px-3 py-2">PID</th>
                  <th className="text-right text-xs font-medium text-dark-200 uppercase font-mono tracking-widest px-5 py-2">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-dark-600">
                {rows.map((s) => {
                  const isActive = s.active_state === "active";
                  const isNotFound = s.load_state === "not-found";
                  return (
                    <tr key={s.unit} className="hover:bg-dark-700/30 transition-colors">
                      <td className="px-5 py-2">
                        <div className="text-sm text-dark-50">{s.label}</div>
                        <div className="text-xs text-dark-400 font-mono truncate max-w-[280px]" title={s.description || s.unit}>
                          {s.unit}
                          {s.enabled === false && !isActive ? " · disabled" : ""}
                        </div>
                      </td>
                      <td className="px-3 py-2">
                        <span className={`text-xs font-mono ${stateTone(s.active_state)}`}>
                          {isNotFound ? "not installed" : s.active_state}
                        </span>
                        {isActive && s.sub_state && s.sub_state !== "running" && (
                          <span className="text-xs text-dark-400 font-mono"> · {s.sub_state}</span>
                        )}
                      </td>
                      <td className="px-3 py-2 text-right text-sm text-dark-200 font-mono">{formatUptime(s.uptime_secs)}</td>
                      <td className="px-3 py-2 text-right text-sm font-mono">
                        <span className={s.cpu_pct !== null && s.cpu_pct > 80 ? "text-danger-400" : "text-dark-200"}>
                          {s.cpu_pct === null ? "—" : `${s.cpu_pct.toFixed(1)}%`}
                        </span>
                      </td>
                      <td className="px-3 py-2 text-right text-sm text-dark-200 font-mono">{formatBytesOrDash(s.memory_mb)}</td>
                      <td className="px-3 py-2 text-right text-sm text-dark-200 font-mono">
                        {s.restarts === null ? "—" : s.restarts}
                      </td>
                      <td className="px-3 py-2 text-right text-sm text-dark-300 font-mono">{s.main_pid ?? "—"}</td>
                      <td className="px-5 py-2">
                        <div className="flex items-center justify-end gap-2">
                          {isNotFound ? (
                            <span className="text-xs text-dark-500 font-mono">—</span>
                          ) : (
                            <>
                              {isActive ? (
                                <ActionButton label="Stop" tone="danger" disabled={busy !== null} onClick={() => requestAction(s.unit, "stop")} />
                              ) : (
                                <ActionButton label="Start" tone="accent" disabled={busy !== null} onClick={() => requestAction(s.unit, "start")} />
                              )}
                              <ActionButton label="Restart" tone="default" disabled={busy !== null} onClick={() => requestAction(s.unit, "restart")} />
                            </>
                          )}
                        </div>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        </div>
      ))}

      {pending && (
        <ConfirmDialog
          label={`${pending.action === "restart" ? "Restart" : "Stop"} ${pending.unit}?`}
          confirmLabel={pending.action === "restart" ? "Restart" : "Stop"}
          tone={pending.action === "restart" ? "warn" : "danger"}
          onConfirm={() => {
            const p = pending;
            setPending(null);
            void runAction(p.unit, p.action);
          }}
          onCancel={() => setPending(null)}
        />
      )}
    </div>
  );
}

function ActionButton({
  label,
  tone,
  disabled,
  onClick,
}: {
  label: string;
  tone: "default" | "accent" | "danger";
  disabled: boolean;
  onClick: () => void;
}) {
  const tones = {
    default: "border-dark-500 text-dark-200 hover:text-dark-50 hover:border-dark-300",
    accent: "border-rust-500/40 text-rust-400 hover:bg-rust-500/10",
    danger: "border-danger-500/40 text-danger-400 hover:bg-danger-500/10",
  };
  return (
    <button
      onClick={onClick}
      disabled={disabled}
      className={`px-2.5 py-1 rounded border text-xs font-mono transition-colors disabled:opacity-40 disabled:cursor-not-allowed ${tones[tone]}`}
    >
      {label}
    </button>
  );
}

type SortKey = "cpu" | "mem" | "pid" | "name" | "uptime";

function ProcessesContent() {
  const [processes, setProcesses] = useState<Process[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [query, setQuery] = useState("");
  const [sortKey, setSortKey] = useState<SortKey>("cpu");

  const load = useCallback(() => {
    api
      .get<Process[]>("/system/processes?all=true")
      .then((d) => {
        setProcesses(d);
        setError("");
      })
      .catch((e) => setError(e instanceof Error ? e.message : "Failed to load processes"))
      .finally(() => setLoading(false));
  }, []);

  useEffect(() => {
    load();
    const id = setInterval(load, 5000);
    return () => clearInterval(id);
  }, [load]);

  const rows = useMemo(() => {
    const q = query.trim().toLowerCase();
    const filtered = q
      ? processes.filter(
          (p) =>
            p.name.toLowerCase().includes(q) ||
            p.cmd.toLowerCase().includes(q) ||
            p.user.toLowerCase().includes(q) ||
            String(p.pid) === q
        )
      : processes;
    const sorted = [...filtered];
    sorted.sort((a, b) => {
      switch (sortKey) {
        case "mem":
          return b.mem_mb - a.mem_mb;
        case "pid":
          return a.pid - b.pid;
        case "name":
          return a.name.localeCompare(b.name);
        case "uptime":
          return b.uptime_secs - a.uptime_secs;
        case "cpu":
        default:
          return b.cpu_pct - a.cpu_pct;
      }
    });
    return sorted;
  }, [processes, query, sortKey]);

  if (loading && processes.length === 0) {
    return (
      <div className="space-y-2">
        {[1, 2, 3, 4, 5, 6].map((i) => (
          <div key={i} className="h-10 bg-dark-700 rounded-lg animate-pulse" />
        ))}
      </div>
    );
  }

  if (error && processes.length === 0) {
    return (
      <div className="bg-dark-800 rounded-lg border border-danger-500/30 p-5">
        <p className="text-sm text-danger-400">{error}</p>
      </div>
    );
  }

  return (
    <div className="space-y-4">
      <div className="flex flex-col sm:flex-row sm:items-center gap-3">
        <input
          type="text"
          value={query}
          onChange={(e) => setQuery(e.target.value)}
          placeholder="Filter by name, command, user or PID…"
          className="flex-1 bg-dark-800 border border-dark-600 rounded-lg px-3 py-2 text-sm text-dark-50 font-mono placeholder:text-dark-500 focus:outline-none focus:border-rust-500"
        />
        <div className="flex items-center gap-2 text-xs font-mono">
          <span className="text-dark-400 uppercase tracking-widest">Sort</span>
          {(["cpu", "mem", "pid", "name", "uptime"] as SortKey[]).map((k) => (
            <button
              key={k}
              onClick={() => setSortKey(k)}
              className={`px-2 py-1 rounded border transition-colors ${
                sortKey === k
                  ? "border-rust-500/40 text-rust-400 bg-rust-500/10"
                  : "border-dark-500 text-dark-300 hover:text-dark-100"
              }`}
            >
              {k === "cpu" ? "CPU" : k === "mem" ? "MEM" : k === "pid" ? "PID" : k === "name" ? "Name" : "Uptime"}
            </button>
          ))}
        </div>
      </div>

      <div className="text-xs text-dark-400 font-mono">
        {rows.length} process{rows.length === 1 ? "" : "es"}
        {query && ` matching "${query}"`}
      </div>

      <div className="bg-dark-800 rounded-lg border border-dark-600 overflow-x-auto">
        <table className="w-full">
          <thead>
            <tr className="bg-dark-900">
              <th className="text-right text-xs font-medium text-dark-200 uppercase font-mono tracking-widest px-5 py-2">PID</th>
              <th className="text-left text-xs font-medium text-dark-200 uppercase font-mono tracking-widest px-3 py-2">Process</th>
              <th className="text-left text-xs font-medium text-dark-200 uppercase font-mono tracking-widest px-3 py-2">User</th>
              <th className="text-left text-xs font-medium text-dark-200 uppercase font-mono tracking-widest px-3 py-2">State</th>
              <th className="text-right text-xs font-medium text-dark-200 uppercase font-mono tracking-widest px-3 py-2">CPU</th>
              <th className="text-right text-xs font-medium text-dark-200 uppercase font-mono tracking-widest px-3 py-2">MEM</th>
              <th className="text-right text-xs font-medium text-dark-200 uppercase font-mono tracking-widest px-5 py-2">Uptime</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-dark-600">
            {rows.map((p) => (
              <tr key={p.pid} className="hover:bg-dark-700/30 transition-colors">
                <td className="px-5 py-2 text-right text-sm text-dark-300 font-mono">{p.pid}</td>
                <td className="px-3 py-2">
                  <div className="text-sm text-dark-50 font-mono truncate max-w-[320px]" title={p.cmd || p.name}>
                    {p.name}
                  </div>
                  {p.cmd && p.cmd !== p.name && (
                    <div className="text-xs text-dark-500 font-mono truncate max-w-[420px]" title={p.cmd}>
                      {p.cmd}
                    </div>
                  )}
                </td>
                <td className="px-3 py-2 text-sm text-dark-300 font-mono">{p.user || "—"}</td>
                <td className="px-3 py-2 text-xs text-dark-300 font-mono">{p.status}</td>
                <td className="px-3 py-2 text-right text-sm font-mono">
                  <span className={p.cpu_pct > 50 ? "text-danger-400" : "text-dark-200"}>{p.cpu_pct.toFixed(1)}%</span>
                </td>
                <td className="px-3 py-2 text-right text-sm font-mono text-dark-200">
                  {p.mem_mb.toFixed(0)} MB
                  <span className="text-dark-500"> · {p.mem_pct.toFixed(1)}%</span>
                </td>
                <td className="px-5 py-2 text-right text-sm text-dark-200 font-mono">{formatUptime(p.uptime_secs)}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
