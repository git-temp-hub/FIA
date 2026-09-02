import { useEffect, useState } from "react";
import { AlertTriangle, CheckCircle2, Loader2 } from "lucide-react";

import { getDashboardStats } from "../../services/dashboardService";
import type { SystemHealth } from "../../types/dashboard";

const REFRESH_INTERVAL_MS = 30_000;

const OK_STATUSES = new Set(["connected", "ready", "online"]);

interface ServiceView {
  name: string;
  status: string;
}

/**
 * Compact health indicator for the global header.
 *
 * This is the single authoritative place health is surfaced. It replaces the
 * dashboard's "System Healthy" pill, the dashboard's SystemStatus panel, and
 * the Settings page's copy of the same panel, which previously reported the
 * same three checks in three places.
 *
 * "Backend API" is deliberately not listed: it was hardcoded to "online" and
 * could only ever render when the API had already answered, so it conveyed
 * nothing. Backend reachability is instead reflected by this component's own
 * unreachable state.
 */
export default function SystemHealthIndicator() {
  const [health, setHealth] = useState<SystemHealth | null>(null);
  const [loading, setLoading] = useState(true);
  const [reachable, setReachable] = useState(true);
  const [open, setOpen] = useState(false);

  useEffect(() => {
    let cancelled = false;

    async function load() {
      try {
        const stats = await getDashboardStats();
        if (cancelled) return;
        setHealth(stats.system_health);
        setReachable(true);
      } catch {
        if (cancelled) return;
        setReachable(false);
      } finally {
        if (!cancelled) setLoading(false);
      }
    }

    load();
    const timer = window.setInterval(load, REFRESH_INTERVAL_MS);

    return () => {
      cancelled = true;
      window.clearInterval(timer);
    };
  }, []);

  const services: ServiceView[] = health
    ? [
        { name: "Ollama", status: health.ollama },
        { name: "SQLite", status: health.database },
        { name: "ChromaDB", status: health.chromadb },
      ]
    : [];

  const degraded =
    !reachable || services.some((service) => !OK_STATUSES.has(service.status));

  if (loading) {
    return (
      <span className="inline-flex items-center gap-2 rounded-full border border-slate-800 px-3 py-1.5 text-xs text-slate-400">
        <Loader2 className="animate-spin" size={14} />
        Checking
      </span>
    );
  }

  return (
    <div
      className="relative"
      onMouseEnter={() => setOpen(true)}
      onMouseLeave={() => setOpen(false)}
    >
      <button
        type="button"
        onClick={() => setOpen((value) => !value)}
        className={`inline-flex items-center gap-2 rounded-full border px-3 py-1.5 text-xs font-medium transition ${
          degraded
            ? "border-red-900 bg-red-500/10 text-red-400"
            : "border-green-900 bg-green-500/10 text-green-400"
        }`}
      >
        {degraded ? (
          <AlertTriangle size={14} />
        ) : (
          <CheckCircle2 size={14} />
        )}

        {!reachable
          ? "Backend unreachable"
          : degraded
            ? "Degraded"
            : "Healthy"}
      </button>

      {open && reachable && services.length > 0 && (
        <div className="absolute right-0 top-full z-50 mt-2 w-56 rounded-xl border border-slate-800 bg-slate-900 p-3 shadow-xl">
          {services.map((service) => {
            const ok = OK_STATUSES.has(service.status);

            return (
              <div
                key={service.name}
                className="flex items-center justify-between py-1.5 text-xs"
              >
                <span className="text-slate-300">{service.name}</span>

                <span
                  className={`inline-flex items-center gap-1.5 ${
                    ok ? "text-green-400" : "text-red-400"
                  }`}
                >
                  <span
                    className={`h-1.5 w-1.5 rounded-full ${
                      ok ? "bg-green-400" : "bg-red-400"
                    }`}
                  />
                  {service.status}
                </span>
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}
