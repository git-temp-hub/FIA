import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import {
  CalendarDays,
  FileArchive,
  Loader2,
  Plus,
  RefreshCw,
} from "lucide-react";

import { listInvestigations } from "../../services/investigationService";
import { getErrorMessage } from "../../services/api";

import type { InvestigationSummary } from "../../types/investigation";

function formatDate(value: string | null): string {
  if (!value) return "Unknown";

  const date = new Date(value);

  return Number.isNaN(date.getTime())
    ? value
    : date.toLocaleString([], {
        year: "numeric",
        month: "short",
        day: "numeric",
      });
}

function statusStyle(status: string): string {
  if (status === "completed") return "bg-green-500/20 text-green-400";
  if (status === "running" || status === "uploaded") {
    return "bg-yellow-500/20 text-yellow-400";
  }
  if (status === "failed") return "bg-red-500/20 text-red-400";
  return "bg-slate-500/20 text-slate-400";
}

export default function InvestigationListPage() {
  const [items, setItems] = useState<InvestigationSummary[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  async function load() {
    setLoading(true);
    setError(null);

    try {
      setItems(await listInvestigations());
    } catch (err) {
      setError(getErrorMessage(err));
    } finally {
      setLoading(false);
    }
  }

  // The initial fetch resolves state from the promise callbacks rather than
  // calling `load()` synchronously, which would setState during the effect
  // body and trigger a cascading render.
  useEffect(() => {
    let cancelled = false;

    listInvestigations()
      .then((data) => {
        if (!cancelled) setItems(data);
      })
      .catch((err) => {
        if (!cancelled) setError(getErrorMessage(err));
      })
      .finally(() => {
        if (!cancelled) setLoading(false);
      });

    return () => {
      cancelled = true;
    };
  }, []);

  return (
    <div className="space-y-8">
      <div className="flex flex-wrap items-start justify-between gap-4">
        <div>
          <h1 className="text-4xl font-bold text-white">Investigations</h1>

          <p className="mt-2 text-slate-400">
            Every memory dump registered on this platform.
          </p>
        </div>

        <div className="flex items-center gap-3">
          <button
            type="button"
            onClick={load}
            disabled={loading}
            className="inline-flex items-center gap-2 rounded-lg border border-slate-700 bg-slate-900 px-4 py-2 text-sm font-medium text-slate-200 transition hover:border-cyan-500 disabled:cursor-not-allowed disabled:opacity-50"
          >
            <RefreshCw
              className={`h-4 w-4 ${loading ? "animate-spin" : ""}`}
            />
            Refresh
          </button>

          <Link
            to="/upload"
            className="inline-flex items-center gap-2 rounded-lg bg-cyan-500 px-5 py-2 text-sm font-semibold text-black transition hover:bg-cyan-400"
          >
            <Plus size={16} />
            New Investigation
          </Link>
        </div>
      </div>

      {loading && items.length === 0 ? (
        <div className="flex items-center justify-center gap-3 rounded-2xl border border-slate-800 bg-slate-900 py-20 text-slate-400">
          <Loader2 className="animate-spin" size={20} />
          Loading investigations...
        </div>
      ) : error ? (
        <div className="rounded-2xl border border-red-800 bg-slate-900 p-10 text-center">
          <p className="text-red-400">{error}</p>
        </div>
      ) : items.length === 0 ? (
        <div className="rounded-2xl border border-slate-800 bg-slate-900 p-10 text-center">
          <p className="text-slate-400">
            No investigations yet. Upload a memory dump to begin.
          </p>

          <Link
            to="/upload"
            className="mt-6 inline-flex items-center gap-2 rounded-lg bg-cyan-500 px-6 py-3 font-semibold text-black transition hover:bg-cyan-400"
          >
            <Plus size={18} />
            Upload Memory Dump
          </Link>
        </div>
      ) : (
        <div className="space-y-3">
          {items.map((item) => (
            <Link
              key={item.investigation_id}
              to={`/investigation/${encodeURIComponent(
                item.investigation_id,
              )}`}
              className="flex flex-wrap items-center justify-between gap-4 rounded-xl border border-slate-800 bg-slate-900 p-5 transition hover:border-cyan-500"
            >
              <div className="flex min-w-0 items-center gap-4">
                <FileArchive className="shrink-0 text-cyan-400" size={24} />

                <div className="min-w-0">
                  <p className="truncate font-medium text-white">
                    {item.filename}
                  </p>

                  <div className="mt-1 flex flex-wrap items-center gap-x-3 gap-y-1 text-sm text-slate-500">
                    <span className="font-mono text-xs">
                      {item.investigation_id}
                    </span>

                    <span className="flex items-center gap-1">
                      <CalendarDays size={14} />
                      {formatDate(item.uploaded_at)}
                    </span>

                    <span>{item.evidence_count} artifacts</span>

                    <span>{item.plugin_count} plugins</span>
                  </div>
                </div>
              </div>

              <div className="flex items-center gap-4">
                {item.status === "running" && (
                  <div className="hidden w-32 sm:block">
                    <div className="h-2 overflow-hidden rounded-full bg-slate-800">
                      <div
                        className="h-full rounded-full bg-cyan-500 transition-all duration-500"
                        style={{ width: `${item.progress}%` }}
                      />
                    </div>
                    <p className="mt-1 text-right text-xs text-slate-500">
                      {item.progress}%
                    </p>
                  </div>
                )}

                <span
                  className={`shrink-0 rounded-full px-3 py-1 text-xs font-semibold uppercase ${statusStyle(
                    item.status,
                  )}`}
                >
                  {item.status}
                </span>
              </div>
            </Link>
          ))}
        </div>
      )}
    </div>
  );
}
