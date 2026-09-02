import { useCallback, useEffect, useRef, useState } from "react";
import { Link, useLocation, useParams } from "react-router-dom";
import {
  AlertTriangle,
  ArrowLeft,
  CheckCircle2,
  FileArchive,
  Loader2,
  Play,
  Upload,
  XCircle,
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

const PHASES = {
  VOLATILITY: "volatility",
  INDEXING: "indexing",
  CLASSIFYING: "classifying",
  COMPLETED: "completed",
} as const;

const PHASE_TITLES: Record<string, string> = {
  [PHASES.VOLATILITY]: "Running Volatility plugins",
  [PHASES.INDEXING]: "Indexing evidence",
  [PHASES.CLASSIFYING]: "Classifying risk",
  [PHASES.COMPLETED]: "Post-processing complete",
};

function phaseActive(phase: string | null | undefined): boolean {
  return (
    phase === PHASES.VOLATILITY ||
    phase === PHASES.INDEXING ||
    phase === PHASES.CLASSIFYING
  );
}

function isLive(
  status: string | null,
  phase: string | null | undefined,
): boolean {
  return status === "running" || phaseActive(phase);
}

function statusStyle(status: string): string {
  if (status === "completed") return "bg-green-500/20 text-green-400";
  if (status === "running" || status === "uploaded") {
    return "bg-yellow-500/20 text-yellow-400";
  }
  if (status === "failed") return "bg-red-500/20 text-red-400";
  return "bg-slate-500/20 text-slate-400";
}

function formatDuration(seconds: number): string {
  if (seconds < 60) return `${Math.max(1, Math.round(seconds))}s`;

  const minutes = Math.floor(seconds / 60);
  const remainder = Math.round(seconds % 60);

  if (minutes < 60) {
    return remainder > 0 ? `${minutes}m ${remainder}s` : `${minutes}m`;
  }

  const hours = Math.floor(minutes / 60);

  return `${hours}h ${minutes % 60}m`;
}

type DisplayState = "running" | "completed" | "failed" | "ready";

interface StatusState {
  filename: string | null;
  sha256: string | null;
  status: string | null;
  phase: string | null;
  progress: number;
  currentPlugin: string | null;
  totalPlugins: number;
  finishedPlugins: number;
  completedPlugins: number;
  failedPlugins: number;
  etaSeconds: number | null;
  lastError: string | null;
}

const EMPTY_STATUS: StatusState = {
  filename: null,
  sha256: null,
  status: null,
  phase: null,
  progress: 0,
  currentPlugin: null,
  totalPlugins: 0,
  finishedPlugins: 0,
  completedPlugins: 0,
  failedPlugins: 0,
  etaSeconds: null,
  lastError: null,
};

export default function InvestigationPage() {
  const location = useLocation();
  const params = useParams();
  const toast = useToast();

  const stateInfo = (location.state ?? {}) as Partial<InvestigationInfo>;

  // Derived from the route on every render rather than captured once in a
  // useState initialiser: a initialiser only runs on mount, so navigating
  // between two investigation URLs left the page showing the first one.
  const investigationId =
    params.investigationId ?? stateInfo.investigation_id ?? null;

  const storedPath = stateInfo.stored_path ?? null;

  const [snapshot, setSnapshot] = useState<StatusState>(EMPTY_STATUS);
  const [starting, setStarting] = useState(false);
  const [pollActive, setPollActive] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const mounted = useRef(true);

  useEffect(() => {
    mounted.current = true;
    return () => {
      mounted.current = false;
    };
  }, []);

  const applyStatus = useCallback((result: Awaited<
    ReturnType<typeof getInvestigationStatus>
  >) => {
    setSnapshot({
      filename: result.filename ?? null,
      sha256: result.sha256 ?? null,
      status: result.status,
      phase: result.phase ?? null,
      progress: result.progress ?? 0,
      currentPlugin: result.current_plugin ?? null,
      totalPlugins: result.total_plugins ?? 0,
      finishedPlugins: result.finished_plugins ?? 0,
      completedPlugins: result.completed_plugins ?? 0,
      failedPlugins: result.failed_plugins ?? 0,
      etaSeconds: result.estimated_seconds_remaining ?? null,
      lastError: result.last_error ?? null,
    });

    return result;
  }, []);

  // Initial load: fetch once and start polling if the run is live. Because
  // the start request now returns immediately, a page refresh mid-run
  // reconnects to the in-flight investigation instead of losing it.
  useEffect(() => {
    if (!investigationId) return;

    let cancelled = false;

    getInvestigationStatus(investigationId)
      .then((result) => {
        if (cancelled) return;
        applyStatus(result);
        setPollActive(isLive(result.status, result.phase));
      })
      .catch(() => {
        if (!cancelled) setPollActive(false);
      });

    return () => {
      cancelled = true;
    };
  }, [investigationId, applyStatus]);

  useEffect(() => {
    if (!investigationId || !pollActive) return;

    let cancelled = false;

    async function tick() {
      try {
        const result = await getInvestigationStatus(investigationId!);

        if (cancelled) return;

        applyStatus(result);

        if (!isLive(result.status, result.phase)) {
          setPollActive(false);
        }
      } catch {
        // Transient backend error: keep current state and retry next tick.
      }
    }

    tick();
    const timer = window.setInterval(tick, POLLING_INTERVAL_MS);

    return () => {
      cancelled = true;
      window.clearInterval(timer);
    };
  }, [investigationId, pollActive, applyStatus]);

  async function handleStart() {
    if (!investigationId || starting) return;

    setStarting(true);
    setError(null);
    setSnapshot({ ...EMPTY_STATUS, status: "running", phase: PHASES.VOLATILITY });

    try {
      await startInvestigation(
        investigationId,
        storedPath,
      );

      toast.success("Investigation started.");
      setPollActive(true);
    } catch (err) {
      const detail = getErrorMessage(err);

      setError(detail);
      setSnapshot((current) => ({ ...current, status: "failed" }));
      setPollActive(false);
      toast.error(detail || "The investigation could not be started.");
    } finally {
      setStarting(false);
    }
  }

  if (!investigationId) {
    return (
      <div className="space-y-8">
        <h1 className="text-4xl font-bold text-white">Investigation</h1>

        <div className="rounded-2xl border border-slate-800 bg-slate-900 p-10 text-center">
          <p className="text-slate-400">
            No investigation selected.
          </p>

          <div className="mt-6 flex flex-wrap justify-center gap-3">
            <Link
              to="/investigation"
              className="inline-flex items-center gap-2 rounded-lg border border-slate-700 px-6 py-3 font-semibold text-slate-200 transition hover:border-cyan-500"
            >
              <ArrowLeft size={18} />
              All Investigations
            </Link>

            <Link
              to="/upload"
              className="inline-flex items-center gap-2 rounded-lg bg-cyan-500 px-6 py-3 font-semibold text-black transition hover:bg-cyan-400"
            >
              <Upload size={18} />
              Upload Memory Dump
            </Link>
          </div>
        </div>
      </div>
    );
  }

  const runningState =
    snapshot.status === "running" || phaseActive(snapshot.phase) || pollActive;

  const displayState: DisplayState = runningState
    ? "running"
    : snapshot.status === "completed"
      ? "completed"
      : snapshot.status === "failed"
        ? "failed"
        : "ready";

  const phaseTitle = snapshot.phase
    ? (PHASE_TITLES[snapshot.phase] ?? "Active investigation")
    : "Starting";

  return (
    <div className="space-y-8">
      <div>
        <Link
          to="/investigation"
          className="inline-flex items-center gap-2 text-sm text-slate-400 transition hover:text-cyan-400"
        >
          <ArrowLeft size={16} />
          All Investigations
        </Link>

        <h1 className="mt-3 text-4xl font-bold text-white">Investigation</h1>

        <p className="mt-2 text-slate-400">
          Run the forensic analysis pipeline on this memory dump.
        </p>
      </div>

      <div className="rounded-2xl border border-slate-800 bg-slate-900 p-6">
        <div className="flex flex-wrap items-start justify-between gap-4">
          <div className="flex min-w-0 items-center gap-4">
            <FileArchive className="shrink-0 text-cyan-400" size={32} />

            <div className="min-w-0">
              <p className="truncate text-lg font-medium text-white">
                {snapshot.filename ?? stateInfo.filename ?? "Memory dump"}
              </p>

              <p className="mt-1 font-mono text-sm text-cyan-400">
                {investigationId}
              </p>

              {(snapshot.sha256 ?? stateInfo.sha256) && (
                <p className="mt-1 truncate font-mono text-xs text-slate-500">
                  SHA-256: {snapshot.sha256 ?? stateInfo.sha256}
                </p>
              )}
            </div>
          </div>

          {snapshot.status && (
            <span
              className={`shrink-0 rounded-full px-4 py-1.5 text-xs font-semibold uppercase ${statusStyle(
                snapshot.status,
              )}`}
            >
              {snapshot.status}
            </span>
          )}
        </div>
      </div>

      {displayState === "running" && (
        <div className="rounded-2xl border border-slate-800 bg-slate-900 p-6">
          <div className="flex flex-wrap items-center justify-between gap-3">
            <div className="flex items-center gap-3">
              <Loader2 className="animate-spin text-cyan-400" size={20} />

              <p className="text-lg font-semibold text-white">{phaseTitle}</p>
            </div>

            <p className="font-mono text-2xl font-bold text-cyan-400">
              {snapshot.progress}%
            </p>
          </div>

          <div className="mt-4 h-3 overflow-hidden rounded-full bg-slate-800">
            <div
              className="h-full rounded-full bg-cyan-500 transition-all duration-500"
              style={{ width: `${snapshot.progress}%` }}
            />
          </div>

          <div className="mt-3 flex flex-wrap items-center justify-between gap-2 text-sm">
            <p className="text-slate-400">
              {snapshot.totalPlugins > 0
                ? `${snapshot.finishedPlugins} of ${snapshot.totalPlugins} plugins finished`
                : "Preparing plugin run..."}
            </p>

            {snapshot.etaSeconds !== null && snapshot.etaSeconds > 0 && (
              <p className="text-slate-500">
                ~{formatDuration(snapshot.etaSeconds)} remaining
              </p>
            )}
          </div>

          <div className="mt-6 grid gap-4 border-t border-slate-800 pt-5 text-sm sm:grid-cols-2 xl:grid-cols-4">
            <div>
              <p className="text-xs uppercase tracking-wide text-slate-500">
                Current plugin
              </p>
              <p className="mt-1 truncate font-mono text-cyan-400">
                {snapshot.currentPlugin ?? "Starting"}
              </p>
            </div>

            <div>
              <p className="text-xs uppercase tracking-wide text-slate-500">
                Finished
              </p>
              <p className="mt-1 text-white">
                {snapshot.finishedPlugins}
                {snapshot.totalPlugins > 0 && ` / ${snapshot.totalPlugins}`}
              </p>
            </div>

            <div>
              <p className="text-xs uppercase tracking-wide text-slate-500">
                Succeeded
              </p>
              <p className="mt-1 text-green-400">
                {snapshot.completedPlugins}
              </p>
            </div>

            <div>
              <p className="text-xs uppercase tracking-wide text-slate-500">
                Failed
              </p>
              <p
                className={`mt-1 ${
                  snapshot.failedPlugins > 0 ? "text-red-400" : "text-white"
                }`}
              >
                {snapshot.failedPlugins}
              </p>
            </div>
          </div>

          {snapshot.failedPlugins > 0 && (
            <p className="mt-4 rounded-lg border border-red-800 bg-red-950/40 px-4 py-3 text-sm text-red-400">
              <AlertTriangle className="mr-2 inline" size={16} />
              {snapshot.failedPlugins} plugin
              {snapshot.failedPlugins === 1 ? "" : "s"} failed. The remaining
              plugins are continuing.
            </p>
          )}
        </div>
      )}

      {displayState === "completed" && (
        <div className="rounded-2xl border border-green-800 bg-slate-900 p-6">
          <div className="flex items-center gap-5">
            <span className="flex h-12 w-12 shrink-0 items-center justify-center rounded-full bg-green-500/10">
              <CheckCircle2 className="text-green-400" size={26} />
            </span>

            <div>
              <p className="text-lg font-semibold text-white">
                Investigation completed
              </p>
              <p className="mt-1 text-sm text-slate-400">
                {snapshot.completedPlugins} of {snapshot.totalPlugins} plugins
                succeeded
                {snapshot.failedPlugins > 0 &&
                  `, ${snapshot.failedPlugins} failed`}
                .
              </p>
            </div>
          </div>

          <div className="mt-6 grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
            <Link
              to={`/evidence?id=${investigationId}`}
              className="rounded-xl border border-slate-800 bg-slate-950 p-5 text-center transition hover:border-cyan-500"
            >
              <p className="font-medium text-white">Browse Evidence</p>
              <p className="mt-1 text-sm text-slate-500">
                Explore indexed artifacts
              </p>
            </Link>

            <Link
              to={`/rag?id=${investigationId}`}
              className="rounded-xl border border-slate-800 bg-slate-950 p-5 text-center transition hover:border-cyan-500"
            >
              <p className="font-medium text-white">Semantic Search</p>
              <p className="mt-1 text-sm text-slate-500">
                Query evidence in natural language
              </p>
            </Link>

            <Link
              to={`/ai?id=${investigationId}`}
              className="rounded-xl border border-slate-800 bg-slate-950 p-5 text-center transition hover:border-cyan-500"
            >
              <p className="font-medium text-white">AI Investigation Chat</p>
              <p className="mt-1 text-sm text-slate-500">Ask the assistant</p>
            </Link>

            <Link
              to={`/reports?id=${investigationId}`}
              className="rounded-xl border border-slate-800 bg-slate-950 p-5 text-center transition hover:border-cyan-500"
            >
              <p className="font-medium text-white">Generate Report</p>
              <p className="mt-1 text-sm text-slate-500">Produce a PDF report</p>
            </Link>
          </div>
        </div>
      )}

      {displayState === "failed" && (
        <div className="rounded-2xl border border-red-800 bg-slate-900 p-6">
          <div className="flex items-center gap-5">
            <span className="flex h-12 w-12 shrink-0 items-center justify-center rounded-full bg-red-500/10">
              <XCircle className="text-red-400" size={26} />
            </span>

            <div className="min-w-0 flex-1">
              <p className="text-lg font-semibold text-white">
                Investigation failed
              </p>
              <p className="mt-1 text-sm text-red-400">
                {snapshot.lastError ??
                  error ??
                  "The investigation could not be completed."}
              </p>
            </div>
          </div>

          <button
            type="button"
            onClick={handleStart}
            disabled={starting}
            className="mt-6 flex items-center gap-2 rounded-lg bg-cyan-500 px-6 py-3 font-semibold text-black transition hover:bg-cyan-400 disabled:cursor-not-allowed disabled:bg-slate-700 disabled:text-slate-400"
          >
            <Play size={18} />
            Retry Investigation
          </button>
        </div>
      )}

      {displayState === "ready" && (
        <div className="rounded-2xl border border-slate-800 bg-slate-900 p-6">
          <p className="text-lg font-semibold text-white">
            Ready for investigation
          </p>
          <p className="mt-1 text-sm text-slate-400">
            Start the investigation to run Volatility analysis on this memory
            dump.
          </p>

          <button
            type="button"
            onClick={handleStart}
            disabled={starting}
            className="mt-6 flex items-center gap-2 rounded-lg bg-cyan-500 px-6 py-3 font-semibold text-black transition hover:bg-cyan-400 disabled:cursor-not-allowed disabled:bg-slate-700 disabled:text-slate-400"
          >
            {starting ? (
              <Loader2 className="animate-spin" size={18} />
            ) : (
              <Play size={18} />
            )}
            {starting ? "Starting..." : "Start Investigation"}
          </button>
        </div>
      )}
    </div>
  );
}
