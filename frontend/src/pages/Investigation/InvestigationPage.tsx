import { useEffect, useRef, useState } from "react";
import {
  Link,
  useLocation,
  useNavigate,
  useSearchParams,
} from "react-router-dom";
import {
  AlertTriangle,
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
const MESSAGE_ROTATION_MS = 2600;

const PHASES = {
  VOLATILITY: "volatility",
  INDEXING: "indexing",
  CLASSIFYING: "classifying",
  COMPLETED: "completed",
} as const;

const PHASE_TITLES: Record<string, string> = {
  [PHASES.VOLATILITY]: "Volatility analysis",
  [PHASES.INDEXING]: "Evidence indexing",
  [PHASES.CLASSIFYING]: "Risk classification",
  [PHASES.COMPLETED]: "Post-processing complete",
};

const NEUTRAL_MESSAGES = [
  "Investigation in progress...",
  "Analyzing memory evidence...",
  "Processing investigation data...",
];

const VOLATILITY_MESSAGES = [
  "Scanning memory dump...",
  "Running Volatility plugins...",
  "Analyzing forensic artifacts...",
  "Processing evidence...",
];

const INDEXING_MESSAGES = [
  "Indexing forensic evidence...",
  "Preparing evidence for semantic search...",
];

const CLASSIFYING_MESSAGES = [
  "Classifying evidence risk levels...",
  "Correlating forensic findings...",
];

function messagesForPhase(phase: string | null | undefined): string[] {
  if (phase === PHASES.VOLATILITY) return VOLATILITY_MESSAGES;
  if (phase === PHASES.INDEXING) return INDEXING_MESSAGES;
  if (phase === PHASES.CLASSIFYING) return CLASSIFYING_MESSAGES;
  return NEUTRAL_MESSAGES;
}

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

type DisplayState = "running" | "completed" | "failed" | "ready";

export default function InvestigationPage() {
  const location = useLocation();
  const navigate = useNavigate();
  const [searchParams] = useSearchParams();
  const toast = useToast();

  const stateInfo = (location.state ?? {}) as Partial<InvestigationInfo>;

  const [investigation] = useState<InvestigationInfo | null>(() => {
    if (stateInfo.investigation_id) return stateInfo as InvestigationInfo;

    const id = searchParams.get("id");
    if (id) {
      return {
        investigation_id: id,
        stored_path: searchParams.get("path") ?? "",
      };
    }

    return null;
  });

  const [status, setStatus] = useState<string | null>(null);
  const [phase, setPhase] = useState<string | null>(null);
  const [running, setRunning] = useState(false);
  const [pollActive, setPollActive] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const [currentPlugin, setCurrentPlugin] = useState<string | null>(null);
  const [totalPlugins, setTotalPlugins] = useState(0);
  const [completedPlugins, setCompletedPlugins] = useState(0);
  const [failedPlugins, setFailedPlugins] = useState(0);
  const [lastError, setLastError] = useState<string | null>(null);

  const [messageIndex, setMessageIndex] = useState(0);

  const syncOnce = useRef(false);
  const forcePoll = useRef(false);

  const pathname = location.pathname;

  useEffect(() => {
    if (!investigation || syncOnce.current) return;

    const fromState = (location.state ?? {}) as Partial<InvestigationInfo>;
    if (!fromState.investigation_id || searchParams.has("id")) return;

    syncOnce.current = true;

    const params = new URLSearchParams(searchParams);
    params.set("id", investigation.investigation_id);
    if (investigation.stored_path) {
      params.set("path", investigation.stored_path);
    }

    navigate({ pathname, search: params.toString() }, { replace: true });
  }, [investigation, location.state, searchParams, navigate, pathname]);

  useEffect(() => {
    if (!investigation) return;

    const inv = investigation;
    let cancelled = false;

    async function load() {
      try {
        const result = await getInvestigationStatus(inv.investigation_id);

        if (cancelled) return;

        setStatus(result.status);
        setPhase(result.phase ?? null);
        setCurrentPlugin(result.current_plugin ?? null);
        setTotalPlugins(result.total_plugins ?? 0);
        setCompletedPlugins(result.completed_plugins ?? 0);
        setFailedPlugins(result.failed_plugins ?? 0);
        setLastError(result.last_error ?? null);
        setPollActive(isLive(result.status, result.phase));
      } catch {
        if (cancelled) return;
        setPollActive(false);
      }
    }

    load();

    return () => {
      cancelled = true;
    };
  }, [investigation]);

  useEffect(() => {
    if (!investigation || !pollActive) return;

    const inv = investigation;
    let cancelled = false;
    let timer: number | null = null;

    async function tick() {
      try {
        const result = await getInvestigationStatus(inv.investigation_id);

        if (cancelled) return;

        setStatus(result.status);
        setPhase(result.phase ?? null);
        setCurrentPlugin(result.current_plugin ?? null);
        setTotalPlugins(result.total_plugins ?? 0);
        setCompletedPlugins(result.completed_plugins ?? 0);
        setFailedPlugins(result.failed_plugins ?? 0);
        setLastError(result.last_error ?? null);

        if (!isLive(result.status, result.phase) && !forcePoll.current) {
          setPollActive(false);
        }
      } catch {
        // Transient backend error: keep the current state and retry.
      }
    }

    tick();
    timer = window.setInterval(tick, POLLING_INTERVAL_MS);

    return () => {
      cancelled = true;
      if (timer !== null) window.clearInterval(timer);
    };
  }, [investigation, pollActive]);

  async function handleStart() {
    if (!investigation || running) return;

    forcePoll.current = true;
    setRunning(true);
    setStatus("running");
    setPhase(PHASES.VOLATILITY);
    setPollActive(true);
    setMessageIndex(0);
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
      setPhase(fresh.phase ?? null);
      setCurrentPlugin(fresh.current_plugin ?? null);
      setTotalPlugins(fresh.total_plugins ?? 0);
      setCompletedPlugins(fresh.completed_plugins ?? 0);
      setFailedPlugins(fresh.failed_plugins ?? 0);
      setLastError(fresh.last_error ?? null);
      setPollActive(isLive(fresh.status, fresh.phase));
    } catch (err) {
      const detail = getErrorMessage(err);

      setError(detail);
      setStatus("failed");
      setPollActive(false);
      toast.error(detail || "The investigation could not be started.");
    } finally {
      forcePoll.current = false;
      setRunning(false);
    }
  }

  const runningState =
    status === "running" ||
    phaseActive(phase) ||
    pollActive ||
    running;

  const displayState: DisplayState = runningState
    ? "running"
    : status === "completed"
      ? "completed"
      : status === "failed"
        ? "failed"
        : "ready";

  const messages = messagesForPhase(phase);
  const activityMessage = messages[messageIndex % messages.length];
  const phaseTitle = phase
    ? (PHASE_TITLES[phase] ?? "Active investigation")
    : "Active investigation";

  useEffect(() => {
    if (displayState !== "running") return;

    const bucket = messagesForPhase(phase);
    const timer = window.setInterval(() => {
      setMessageIndex((index) => (index + 1) % bucket.length);
    }, MESSAGE_ROTATION_MS);

    return () => window.clearInterval(timer);
  }, [displayState, phase]);

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

  const showPluginDetails = Boolean(
    currentPlugin ||
      totalPlugins > 0 ||
      phaseActive(phase),
  );

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
      </div>

      {displayState === "running" && (
        <div className="rounded-2xl border border-slate-800 bg-slate-900 p-6">
          <div className="flex items-center gap-5">
            <div className="relative flex h-14 w-14 shrink-0 items-center justify-center">
              <span className="absolute h-14 w-14 animate-ping rounded-full bg-cyan-500/10" />
              <span className="relative flex h-12 w-12 items-center justify-center rounded-full bg-cyan-500/10">
                <Loader2 className="animate-spin text-cyan-400" size={26} />
              </span>
            </div>

            <div className="min-w-0 flex-1">
              <p className="text-lg font-semibold text-white">
                Investigation in progress
              </p>
              <p className="mt-1 text-sm text-slate-400">
                Analyzing memory evidence. This may take some time.
              </p>

              <div className="mt-3 flex items-center gap-2 text-sm text-cyan-300">
                <span className="inline-block h-2 w-2 shrink-0 animate-pulse rounded-full bg-cyan-400" />
                <span className="truncate font-medium">
                  {activityMessage}
                </span>
              </div>
            </div>
          </div>

          {showPluginDetails && (
            <div className="mt-6 grid gap-4 border-t border-slate-800 pt-5 text-sm sm:grid-cols-2 xl:grid-cols-4">
              <div>
                <p className="text-xs uppercase tracking-wide text-slate-500">
                  Phase
                </p>
                <p className="mt-1 text-white">{phaseTitle}</p>
              </div>

              <div>
                <p className="text-xs uppercase tracking-wide text-slate-500">
                  Current plugin
                </p>
                <p className="mt-1 font-mono text-cyan-400">
                  {currentPlugin ?? "Starting"}
                </p>
              </div>

              <div>
                <p className="text-xs uppercase tracking-wide text-slate-500">
                  Plugins completed
                </p>
                <p className="mt-1 text-white">
                  {totalPlugins > 0
                    ? `${completedPlugins} of ${totalPlugins}`
                    : "Pending"}
                </p>
              </div>

              <div>
                <p className="text-xs uppercase tracking-wide text-slate-500">
                  Plugin failures
                </p>
                <p
                  className={`mt-1 ${
                    failedPlugins > 0 ? "text-red-400" : "text-white"
                  }`}
                >
                  {failedPlugins > 0 ? failedPlugins : "None"}
                </p>
              </div>
            </div>
          )}

          {failedPlugins > 0 && (
            <p className="mt-4 rounded-lg border border-red-800 bg-red-950/40 px-4 py-3 text-sm text-red-400">
              <AlertTriangle className="mr-2 inline" size={16} />
              {failedPlugins} plugin
              {failedPlugins === 1 ? "" : "s"} failed
              {lastError ? `: ${lastError}` : "."} The remaining plugins are
              continuing.
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
                Memory forensic analysis is ready.
              </p>
            </div>
          </div>

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
                Query evidence in natural language
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
                {lastError ?? error ?? "The investigation could not be completed."}
              </p>
            </div>
          </div>

          <button
            type="button"
            onClick={handleStart}
            disabled={running}
            className="mt-6 flex items-center gap-2 rounded-lg bg-cyan-500 px-6 py-3 font-semibold text-black transition hover:bg-cyan-400 disabled:cursor-not-allowed disabled:bg-slate-700 disabled:text-slate-400"
          >
            <Play size={18} />
            Start Investigation
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
            disabled={running}
            className="mt-6 flex items-center gap-2 rounded-lg bg-cyan-500 px-6 py-3 font-semibold text-black transition hover:bg-cyan-400 disabled:cursor-not-allowed disabled:bg-slate-700 disabled:text-slate-400"
          >
            {running ? (
              <Loader2 className="animate-spin" size={18} />
            ) : (
              <Play size={18} />
            )}
            {running ? "Investigating..." : "Start Investigation"}
          </button>
        </div>
      )}
    </div>
  );
}