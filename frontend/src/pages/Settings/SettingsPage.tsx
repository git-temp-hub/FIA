import { useEffect, useState } from "react";
import {
  AlertTriangle,
  Brain,
  CheckCircle2,
  Database,
  Info,
  RefreshCw,
  Server,
  ShieldCheck,
} from "lucide-react";

import SystemStatus from "../../components/dashboard/SystemStatus";
import { getDashboardStats } from "../../services/dashboardService";

import type { DashboardStats, SystemHealth } from "../../types/dashboard";

const OK_STATUSES = new Set(["connected", "ready", "online"]);

interface InfoRowProps {
  label: string;
  value: string;
  mono?: boolean;
}

function InfoRow({ label, value, mono = false }: InfoRowProps) {
  return (
    <div className="flex items-center justify-between border-b border-slate-800 py-3 last:border-0">
      <span className="text-slate-400">{label}</span>

      <span
        className={
          mono
            ? "font-mono text-sm text-slate-200"
            : "text-sm text-slate-200"
        }
      >
        {value}
      </span>
    </div>
  );
}

function StatusBadge({ status }: { status: string }) {
  const ok = OK_STATUSES.has(status);

  const label =
    status === "online"
      ? "Online"
      : status === "connected"
        ? "Connected"
        : status === "ready"
          ? "Ready"
          : "Unavailable";

  return (
    <span className="inline-flex items-center gap-2">
      {ok ? (
        <CheckCircle2 className="text-green-500" size={16} />
      ) : (
        <AlertTriangle className="text-red-500" size={16} />
      )}

      <span className={ok ? "text-green-400" : "text-red-400"}>{label}</span>
    </span>
  );
}

interface SettingsCardProps {
  icon: typeof Server;
  title: string;
  children: React.ReactNode;
}

function SettingsCard({ icon: Icon, title, children }: SettingsCardProps) {
  return (
    <div className="rounded-2xl border border-slate-800 bg-slate-900 p-6">
      <div className="mb-4 flex items-center gap-3">
        <Icon className="text-cyan-400" size={22} />

        <h2 className="text-xl font-semibold text-white">{title}</h2>
      </div>

      {children}
    </div>
  );
}

export default function SettingsPage() {
  const [stats, setStats] = useState<DashboardStats | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    getDashboardStats()
      .then(setStats)
      .catch(() => setError("Unable to load settings information."))
      .finally(() => setLoading(false));
  }, []);

  async function handleRefresh() {
    setLoading(true);
    setError(null);

    try {
      const data = await getDashboardStats();
      setStats(data);
    } catch {
      setError("Unable to load settings information.");
    } finally {
      setLoading(false);
    }
  }

  const health: SystemHealth | null = stats?.system_health ?? null;

  return (
    <div className="space-y-8">
      {/* Page Header */}
      <div className="flex flex-wrap items-center justify-between gap-4">
        <div>
          <h1 className="text-4xl font-bold text-white">Settings</h1>

          <p className="mt-2 text-slate-400">
            FIA platform information and system configuration.
          </p>
        </div>

        <button
          type="button"
          onClick={handleRefresh}
          disabled={loading}
          className="inline-flex items-center gap-2 rounded-lg border border-slate-700 bg-slate-900 px-4 py-2 text-sm font-medium text-slate-200 transition hover:border-cyan-500 disabled:cursor-not-allowed disabled:opacity-50"
        >
          <RefreshCw
            className={`h-4 w-4 ${loading ? "animate-spin" : ""}`}
          />
          Refresh
        </button>
      </div>

      {loading && !stats ? (
        <div className="rounded-2xl border border-slate-800 bg-slate-900 p-10 text-center">
          <p className="text-slate-400">Loading settings information...</p>
        </div>
      ) : error && !stats ? (
        <div className="rounded-2xl border border-red-800 bg-slate-900 p-10 text-center">
          <p className="text-red-400">{error}</p>

          <button
            type="button"
            onClick={handleRefresh}
            className="mt-4 rounded-lg bg-cyan-500 px-4 py-2 font-semibold text-black transition hover:bg-cyan-400"
          >
            Retry
          </button>
        </div>
      ) : health ? (
        <>
          {/* System Status */}
          <SystemStatus health={health} />

          <div className="grid gap-6 xl:grid-cols-2">
            {/* Application */}
            <SettingsCard icon={ShieldCheck} title="Application">
              <InfoRow label="Name" value={health.application} />
              <InfoRow label="Version" value={health.version} mono />
              <InfoRow label="Environment" value={health.environment} mono />
            </SettingsCard>

            {/* AI & RAG */}
            <SettingsCard icon={Brain} title="AI & RAG">
              <div className="flex items-center justify-between border-b border-slate-800 py-3 last:border-0">
                <span className="text-slate-400">Ollama Status</span>
                <StatusBadge status={health.ollama} />
              </div>

              <div className="flex items-center justify-between border-b border-slate-800 py-3 last:border-0">
                <span className="text-slate-400">ChromaDB Status</span>
                <StatusBadge status={health.chromadb} />
              </div>

              <p className="pt-3 text-xs text-slate-500">
                AI models and the semantic search index are managed by the
                backend at runtime.
              </p>
            </SettingsCard>

            {/* Database & Storage */}
            <SettingsCard icon={Database} title="Database & Storage">
              <div className="flex items-center justify-between border-b border-slate-800 py-3 last:border-0">
                <span className="text-slate-400">SQLite Status</span>
                <StatusBadge status={health.database} />
              </div>

              <p className="pt-3 text-xs text-slate-500">
                Evidence, investigations, AI conversations, and reports are
                stored locally on this machine.
              </p>
            </SettingsCard>

            {/* About */}
            <SettingsCard icon={Info} title="About">
              <p className="text-slate-300">
                FIA (AI Memory Forensic Investigation Assistant) is a local
                AI-powered platform for analyzing memory dumps, correlating
                evidence, and generating investigation reports.
              </p>

              <p className="mt-3 text-xs text-slate-500">
                All analysis runs locally. No investigation data leaves this
                machine.
              </p>
            </SettingsCard>
          </div>
        </>
      ) : null}
    </div>
  );
}
