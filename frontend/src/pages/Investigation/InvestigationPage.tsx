import { useEffect, useState } from "react";
import { Link, useLocation, useSearchParams } from "react-router-dom";
import {
  AlertTriangle,
  FileArchive,
  Loader2,
  Play,
  Upload,
} from "lucide-react";

import { getErrorMessage } from "../../services/api";
import {
  getInvestigationStatus,
  startInvestigation,
} from "../../services/investigationService";
import { useToast } from "../../components/ui/toast-context";

interface InvestigationInfo {
  investigation_id: string;
  stored_path: string;
  filename?: string;
  sha256?: string;
  size?: number;
}

const POLLING_INTERVAL_MS = 1500;

function statusStyle(status: string): string {
  if (status === "completed") return "bg-green-500/20 text-green-400";
  if (status === "running" || status === "uploaded") {
    return "bg-yellow-500/20 text-yellow-400";
  }
  if (status === "failed") return "bg-red-500/20 text-red-400";
  return "bg-slate-500/20 text-slate-400";
}

export default function InvestigationPage() {
  const location = useLocation();
  const [searchParams] = useSearchParams();
  const toast = useToast();

  const stateInfo = (location.state ?? {}) as Partial<InvestigationInfo>;

  const [investigation] = useState<InvestigationInfo | null>(
    stateInfo.investigation_id
      ? (stateInfo as InvestigationInfo)
      : searchParams.get("id")
        ? {
            investigation_id: searchParams.get("id") ?? "",
            stored_path: searchParams.get("path") ?? "",
          }
        : null,
  );

  const [status, setStatus] = useState<string | null>(null);
  const [progress, setProgress] = useState(0);
  const [running, setRunning] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const [currentPlugin, setCurrentPlugin] = useState<string | null>(null);
  const [totalPlugins, setTotalPlugins] = useState(0);
  const [completedPlugins, setCompletedPlugins] = useState(0);
  const [failedPlugins, setFailedPlugins] = useState(0);
  const [lastError, setLastError] = useState<string | null>(null);

  useEffect(() => {
    if (!investigation) return;

    getInvestigationStatus(investigation.investigation_id)
      .then((result) => {
        setStatus(result.status);
        setProgress(result.progress);
        setCurrentPlugin(result.current_plugin ?? null);
        setTotalPlugins(result.total_plugins ?? 0);
        setCompletedPlugins(result.completed_plugins ?? 0);
        setFailedPlugins(result.failed_plugins ?? 0);
        setLastError(result.last_error ?? null);
      })
      .catch(() => setStatus(null));
  }, [investigation]);

  const isRunning = running || status === "running";

  useEffect(() => {
    if (!investigation || !isRunning) return;

    let cancelled = false;

    const poll = async () => {
      try {
        const result = await getInvestigationStatus(
          investigation.investigation_id,
        );

        if (cancelled) return;

        setStatus(result.status);
        setProgress(result.progress);
        setCurrentPlugin(result.current_plugin ?? null);
        setTotalPlugins(result.total_plugins ?? 0);
        setCompletedPlugins(result.completed_plugins ?? 0);
        setFailedPlugins(result.failed_plugins ?? 0);
        setLastError(result.last_error ?? null);
      } catch {
        if (!cancelled) setStatus(null);
      }
    };

    poll();

    const timer = window.setInterval(poll, POLLING_INTERVAL_MS);

    return () => {
      cancelled = true;
      window.clearInterval(timer);
    };
  }, [investigation, isRunning]);

  async function handleStart() {
    if (!investigation || running) return;

    setRunning(true);
    setStatus("running");
    setProgress(0);
    setError(null);
    setCurrentPlugin(null);
    setTotalPlugins(0);
    setCompletedPlugins(0);
    setFailedPlugins(0);
    setLastError(null);

    try {
      const result = await startInvestigation(
        investigation.investigation_id,
        investigation.stored_path,
      );

      toast.success(result.message || "Investigation completed.");

      const fresh = await getInvestigationStatus(
        investigation.investigation_id,
      );

      setStatus(fresh.status);
      setProgress(fresh.progress);
      setCurrentPlugin(fresh.current_plugin ?? null);
      setTotalPlugins(fresh.total_plugins ?? 0);
      setCompletedPlugins(fresh.completed_plugins ?? 0);
      setFailedPlugins(fresh.failed_plugins ?? 0);
      setLastError(fresh.last_error ?? null);
    } catch (err) {
      const detail = getErrorMessage(err);

      setError(detail);
      setStatus("failed");
      toast.error(detail || "Investigation failed to start.");
    } finally {
      setRunning(false);
    }
  }

  if (!investigation) {
    return (
      <div className="space-y-8">
        <h1 className="text-4xl font-bold text-white">Investigation</h1>

        <div className="rounded-2xl border border-slate-800 bg-slate-900 p-10 text-center">
          <p className="text-slate-400">
            No memory dump selected. Upload a memory dump to begin.
          </p>

          <Link
            to="/upload"
            className="mt-6 inline-flex items-center gap-2 rounded-lg bg-cyan-500 px-6 py-3 font-semibold text-black transition hover:bg-cyan-400"
          >
            <Upload size={18} />
            Upload Memory Dump
          </Link>
        </div>
      </div>
    );
  }

  return (
    <div className="space-y-8">
      <div>
        <h1 className="text-4xl font-bold text-white">Investigation</h1>

        <p className="mt-2 text-slate-400">
          Run the forensic analysis pipeline on the uploaded memory dump.
        </p>
      </div>

      <div className="rounded-2xl border border-slate-800 bg-slate-900 p-6">
        <div className="flex flex-wrap items-start justify-between gap-4">
          <div className="flex min-w-0 items-center gap-4">
            <FileArchive className="shrink-0 text-cyan-400" size={32} />

            <div className="min-w-0">
              <p className="truncate text-lg font-medium text-white">
                {investigation.filename ?? "Memory dump"}
              </p>

              <p className="mt-1 font-mono text-sm text-cyan-400">
                {investigation.investigation_id}
              </p>

              {investigation.sha256 && (
                <p className="mt-1 truncate font-mono text-xs text-slate-500">
                  SHA-256: {investigation.sha256}
                </p>
              )}
            </div>
          </div>

          {status && (
            <span
              className={`shrink-0 rounded-full px-4 py-1.5 text-xs font-semibold uppercase ${statusStyle(
                status,
              )}`}
            >
              {status}
            </span>
          )}
        </div>

        {isRunning && (
          <div className="mt-6 space-y-3">
            <div className="flex items-center justify-between text-sm text-slate-400">
              <span className="inline-flex items-center gap-2">
                <Loader2 className="animate-spin" size={16} />
                Running Volatility plugins...
              </span>
              <span>{progress}%</span>
            </div>

            <div className="h-2 w-full overflow-hidden rounded-full bg-slate-800">
              <div
                className="h-full rounded-full bg-cyan-500 transition-all"
                style={{ width: `${progress}%` }}
              />
            </div>

            <div className="grid gap-4 text-sm sm:grid-cols-3">
              <div>
                <p className="text-xs uppercase tracking-wide text-slate-500">
                  Current plugin
                </p>
                <p className="mt-1 font-mono text-cyan-400">
                  {currentPlugin ?? "starting..."}
                </p>
              </div>

              <div>
                <p className="text-xs uppercase tracking-wide text-slate-500">
                  Completed
                </p>
                <p className="mt-1 text-white">
                  {totalPlugins > 0
                    ? `${completedPlugins} / ${totalPlugins} plugins`
                    : "Starting..."}
                </p>
              </div>

              <div>
                <p className="text-xs uppercase tracking-wide text-slate-500">
                  Failed
                </p>
                <p
                  className={`mt-1 ${
                    failedPlugins > 0 ? "text-red-400" : "text-white"
                  }`}
                >
                  {failedPlugins}
                </p>
              </div>
            </div>

            {failedPlugins > 0 && (
              <p className="rounded-lg border border-red-800 bg-red-950/40 px-4 py-3 text-sm text-red-400">
                <AlertTriangle className="mr-2 inline" size={16} />
                {failedPlugins} plugin{failedPlugins === 1 ? "" : "s"} failed
                {lastError ? `: ${lastError}` : "."} Continuing with the
                remaining plugins.
              </p>
            )}
          </div>
        )}

        {error && (
          <p className="mt-4 rounded-lg border border-red-800 bg-red-950/40 px-4 py-3 text-sm text-red-400">
            {error}
          </p>
        )}

        {status !== "completed" && (
          <button
            type="button"
            onClick={handleStart}
            disabled={isRunning}
            className="mt-6 flex items-center gap-2 rounded-lg bg-cyan-500 px-6 py-3 font-semibold text-black transition hover:bg-cyan-400 disabled:cursor-not-allowed disabled:bg-slate-700 disabled:text-slate-400"
          >
            {isRunning ? (
              <Loader2 className="animate-spin" size={18} />
            ) : (
              <Play size={18} />
            )}
            {isRunning ? "Investigating..." : "Start Investigation"}
          </button>
        )}
      </div>

      {status === "completed" && (
        <div className="rounded-2xl border border-green-800 bg-slate-900 p-6">
          <h2 className="text-xl font-semibold text-white">
            Investigation Complete
          </h2>

          <p className="mt-2 text-slate-400">
            The analysis finished successfully. Continue to explore the
            evidence.
          </p>

          <div className="mt-6 grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
            <Link
              to="/evidence"
              className="rounded-xl border border-slate-800 bg-slate-950 p-5 text-center transition hover:border-cyan-500"
            >
              <p className="font-medium text-white">Browse Evidence</p>
              <p className="mt-1 text-sm text-slate-500">
                Explore indexed artifacts
              </p>
            </Link>

            <Link
              to={`/rag?id=${investigation.investigation_id}`}
              className="rounded-xl border border-slate-800 bg-slate-950 p-5 text-center transition hover:border-cyan-500"
            >
              <p className="font-medium text-white">Semantic Search</p>
              <p className="mt-1 text-sm text-slate-500">
                Natural-language queries
              </p>
            </Link>

            <Link
              to={`/ai?id=${investigation.investigation_id}`}
              className="rounded-xl border border-slate-800 bg-slate-950 p-5 text-center transition hover:border-cyan-500"
            >
              <p className="font-medium text-white">AI Investigation Chat</p>
              <p className="mt-1 text-sm text-slate-500">
                Ask the assistant
              </p>
            </Link>

            <Link
              to={`/reports?id=${investigation.investigation_id}`}
              className="rounded-xl border border-slate-800 bg-slate-950 p-5 text-center transition hover:border-cyan-500"
            >
              <p className="font-medium text-white">Generate Report</p>
              <p className="mt-1 text-sm text-slate-500">
                Produce a PDF report
              </p>
            </Link>
          </div>
        </div>
      )}
    </div>
  );
}