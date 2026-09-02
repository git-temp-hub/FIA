import { Fragment, useEffect, useMemo, useState } from "react";

import { useSearchParams } from "react-router-dom";

import InvestigationPicker from "../../components/investigation/InvestigationPicker";

import {
  AlertCircle,
  ChevronDown,
  ChevronLeft,
  ChevronRight,
  ChevronUp,
  FileSearch,
  Loader2,
  Search,
  X,
} from "lucide-react";

import {
  getEvidenceDetail,
  listEvidence,
} from "../../services/evidenceService";

import type {
  EvidenceDetail,
  EvidenceFilters,
  EvidenceItem,
  EvidenceListResponse,
} from "../../types/evidence";

const SORT_COLUMNS: Array<{
  key: EvidenceFilters["sort_by"];
  label: string;
}> = [
  { key: "id", label: "ID" },
  { key: "artifact_type", label: "Artifact Type" },
  { key: "artifact_name", label: "Artifact Name" },
  { key: "created_at", label: "Created" },
];

const SEVERITY_STYLES: Record<string, string> = {
  high: "bg-red-500/20 text-red-400",
  medium: "bg-yellow-500/20 text-yellow-400",
  low: "bg-slate-500/20 text-slate-300",
  unknown: "bg-slate-600/20 text-slate-400",
  "insufficient-evidence": "bg-slate-600/20 text-slate-400",
};

function formatDate(value: string): string {
  const date = new Date(value);
  return Number.isNaN(date.getTime())
    ? value
    : date.toLocaleString();
}

function SeverityBadge({ severity }: { severity: string }) {
  const style =
    SEVERITY_STYLES[severity] ?? SEVERITY_STYLES.unknown;

  return (
    <span
      className={`inline-block rounded-full px-3 py-1 text-xs font-semibold uppercase ${style}`}
    >
      {severity}
    </span>
  );
}

function PrettyValue({ value }: { value: string }) {
  const text = useMemo(() => {
    try {
      return JSON.stringify(JSON.parse(value), null, 2);
    } catch {
      return value;
    }
  }, [value]);

  return (
    <pre className="max-h-64 overflow-auto whitespace-pre-wrap break-words text-sm text-slate-300">
      {text}
    </pre>
  );
}

export default function EvidencePage() {
  const [searchParams] = useSearchParams();

  const [investigationId, setInvestigationId] = useState(
    searchParams.get("id") ?? "",
  );

  const [plugin, setPlugin] = useState("");
  const [artifactType, setArtifactType] = useState("");
  const [severity, setSeverity] = useState("");

  const [searchInput, setSearchInput] = useState("");
  const [appliedSearch, setAppliedSearch] = useState("");

  const [sortBy, setSortBy] =
    useState<EvidenceFilters["sort_by"]>("id");
  const [sortOrder, setSortOrder] =
    useState<EvidenceFilters["sort_order"]>("desc");

  const [page, setPage] = useState(1);
  const [pageSize, setPageSize] = useState(20);

  const [data, setData] = useState<EvidenceListResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const [expandedId, setExpandedId] = useState<number | null>(null);

  const [detail, setDetail] = useState<EvidenceDetail | null>(null);
  const [detailLoading, setDetailLoading] = useState(false);

  useEffect(() => {
    const timer = setTimeout(
      () => {
        setAppliedSearch(searchInput);
        setPage(1);
      },
      400,
    );
    return () => clearTimeout(timer);
  }, [searchInput]);

  useEffect(() => {
    let cancelled = false;

    const timer = window.setTimeout(() => {
      if (!cancelled) setLoading(true);
    }, 0);

    listEvidence({
      investigation_id: investigationId || undefined,
      plugin: plugin || undefined,
      artifact_type: artifactType || undefined,
      severity: severity || undefined,
      search: appliedSearch || undefined,
      sort_by: sortBy,
      sort_order: sortOrder,
      page,
      page_size: pageSize,
    })
      .then((response) => {
        if (cancelled) return;
        setData(response);
        setError(null);
        setLoading(false);
      })
      .catch(() => {
        if (cancelled) return;
        setError("Failed to load evidence.");
        setData(null);
        setLoading(false);
      });

    return () => {
      cancelled = true;
      window.clearTimeout(timer);
    };
  }, [
    investigationId,
    plugin,
    artifactType,
    severity,
    appliedSearch,
    sortBy,
    sortOrder,
    page,
    pageSize,
  ]);

  function handleInvestigationChange(value: string) {
    setInvestigationId(value);
    setPage(1);
  }

  function handlePluginChange(value: string) {
    setPlugin(value);
    setPage(1);
  }

  function handleArtifactTypeChange(value: string) {
    setArtifactType(value);
    setPage(1);
  }

  function handleSeverityChange(value: string) {
    setSeverity(value);
    setPage(1);
  }

  async function handleSelectEvidence(item: EvidenceItem) {
    setDetailLoading(true);
    setDetail(null);

    try {
      const evidence = await getEvidenceDetail(item.id);
      setDetail(evidence);
    } catch {
      setDetail(null);
    } finally {
      setDetailLoading(false);
    }
  }

  function toggleExpanded(item: EvidenceItem) {
    setExpandedId((current) => (current === item.id ? null : item.id));
  }

  function toggleSort(key: EvidenceFilters["sort_by"]) {
    if (sortBy === key) {
      setSortOrder(sortOrder === "asc" ? "desc" : "asc");
    } else {
      setSortBy(key);
      setSortOrder("asc");
    }
  }

  function resetFilters() {
    setPlugin("");
    setArtifactType("");
    setSeverity("");
    setSearchInput("");
    setAppliedSearch("");
    setPage(1);
  }

  const total = data?.total ?? 0;
  const totalPages = data?.total_pages ?? 0;

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-4xl font-bold text-white">
            Evidence Explorer
          </h1>
          <p className="mt-2 text-slate-400">
            Browse normalized forensic evidence and investigation
            artifacts.
          </p>
        </div>
      </div>

      <div className="rounded-xl border border-slate-700 bg-slate-900 p-4">
        <InvestigationPicker
          value={investigationId}
          onChange={handleInvestigationChange}
          placeholder="All investigations"
          className="sm:w-96"
        />
      </div>

      <div className="grid gap-4 rounded-xl border border-slate-700 bg-slate-900 p-4 md:grid-cols-4">
        <div>
          <label className="mb-2 block text-sm font-medium text-slate-400">
            Plugin
          </label>

          <select
            value={plugin}
            onChange={(event) => handlePluginChange(event.target.value)}
            className="w-full rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-white outline-none focus:border-cyan-500"
          >
            <option value="">All plugins</option>

            {(data?.plugins ?? []).map((name) => (
              <option key={name} value={name}>
                {name}
              </option>
            ))}
          </select>
        </div>

        <div>
          <label className="mb-2 block text-sm font-medium text-slate-400">
            Artifact Type
          </label>

          <select
            value={artifactType}
            onChange={(event) =>
              handleArtifactTypeChange(event.target.value)
            }
            className="w-full rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-white outline-none focus:border-cyan-500"
          >
            <option value="">All types</option>

            {(data?.artifact_types ?? []).map((name) => (
              <option key={name} value={name}>
                {name}
              </option>
            ))}
          </select>
        </div>

        <div>
          <label className="mb-2 block text-sm font-medium text-slate-400">
            Severity
          </label>

          <select
            value={severity}
            onChange={(event) => handleSeverityChange(event.target.value)}
            className="w-full rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-white outline-none focus:border-cyan-500"
          >
            <option value="">All severities</option>
            <option value="high">High</option>
            <option value="medium">Medium</option>
            <option value="low">Low</option>
            <option value="unknown">Unknown</option>
            <option value="insufficient-evidence">Insufficient</option>
          </select>
        </div>

        <div>
          <label className="mb-2 block text-sm font-medium text-slate-400">
            Search
          </label>

          <div className="relative">
            <Search
              className="absolute left-3 top-1/2 -translate-y-1/2 text-slate-500"
              size={16}
            />

            <input
              value={searchInput}
              onChange={(event) => setSearchInput(event.target.value)}
              placeholder="Search artifacts..."
              className="w-full rounded-lg border border-slate-700 bg-slate-950 py-2 pl-9 pr-3 text-white outline-none focus:border-cyan-500"
            />
          </div>
        </div>
      </div>

      <div className="overflow-hidden rounded-xl border border-slate-700 bg-slate-900">
        {loading ? (
          <div className="flex items-center justify-center gap-3 py-20 text-slate-400">
            <Loader2 className="animate-spin" size={20} />
            Loading evidence...
          </div>
        ) : error ? (
          <div className="flex flex-col items-center gap-3 py-20 text-red-400">
            <AlertCircle size={28} />
            <p>{error}</p>
          </div>
        ) : (data?.items.length ?? 0) === 0 ? (
          <div className="flex flex-col items-center gap-3 py-20 text-slate-500">
            <FileSearch size={28} />
            <p>No evidence found for the current filters.</p>

            <button
              onClick={resetFilters}
              className="rounded-lg bg-cyan-500 px-4 py-2 text-sm font-semibold text-black"
            >
              Reset Filters
            </button>
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-sm">
              <thead className="border-b border-slate-700 text-xs uppercase text-slate-400">
                <tr>
                  <th className="w-8 px-2 py-3"></th>

                  {SORT_COLUMNS.map((column) => (
                    <th
                      key={column.key}
                      className="px-4 py-3"
                    >
                      <button
                        onClick={() => toggleSort(column.key)}
                        className={`flex items-center gap-1 hover:text-white ${
                          sortBy === column.key
                            ? "text-cyan-400"
                            : ""
                        }`}
                      >
                        {column.label}

                        <span className="text-[10px]">
                          {sortBy === column.key
                            ? sortOrder === "asc"
                              ? "▲"
                              : "▼"
                            : ""}
                        </span>
                      </button>
                    </th>
                  ))}

                  <th className="px-4 py-3">Confidence</th>
                  <th className="px-4 py-3">Severity</th>
                  <th className="px-4 py-3"></th>
                </tr>
              </thead>

              <tbody className="divide-y divide-slate-800">
                {data?.items.map((item) => {
                  const isExpanded = expandedId === item.id;
                  const reasons = item.risk_reasons ?? [];
                  const indicators = item.risk_indicators ?? [];

                  return (
                    <Fragment key={item.id}>
                      <tr
                        onClick={() => handleSelectEvidence(item)}
                        className="cursor-pointer transition hover:bg-slate-800/60"
                      >
                        <td className="px-2 py-3">
                          <button
                            onClick={(event) => {
                              event.stopPropagation();
                              toggleExpanded(item);
                            }}
                            className="rounded p-1 text-slate-500 transition hover:bg-slate-800 hover:text-white"
                            title={
                              isExpanded
                                ? "Hide reasoning"
                                : "Show reasoning"
                            }
                          >
                            {isExpanded ? (
                              <ChevronUp size={16} />
                            ) : (
                              <ChevronDown size={16} />
                            )}
                          </button>
                        </td>
                        <td className="px-4 py-3 font-mono text-slate-500">
                          {item.id}
                        </td>
                        <td className="px-4 py-3 font-mono text-cyan-400">
                          {item.plugin}
                        </td>
                        <td className="px-4 py-3 text-slate-300">
                          {item.artifact_type}
                        </td>
                        <td className="max-w-xs truncate px-4 py-3 text-slate-200">
                          {item.artifact_name}
                        </td>
                        <td className="px-4 py-3 text-slate-400">
                          {item.confidence_score}%
                        </td>
                        <td className="px-4 py-3">
                          <SeverityBadge severity={item.severity} />
                        </td>
                        <td className="px-4 py-3 text-slate-500">
                          {formatDate(item.created_at)}
                        </td>
                      </tr>

                      {isExpanded && (
                        <tr className="bg-slate-950/60">
                          <td></td>
                          <td colSpan={7} className="px-4 py-3">
                            <div className="space-y-2 text-sm">
                              {reasons.length > 0 ? (
                                <>
                                  <ul className="list-inside list-disc space-y-1 text-slate-300">
                                    {reasons.map((reason, index) => (
                                      <li key={index}>{reason}</li>
                                    ))}
                                  </ul>

                                  {indicators.length > 0 && (
                                    <p className="font-mono text-xs text-slate-500">
                                      Indicators: {indicators.join(", ")}
                                    </p>
                                  )}
                                </>
                              ) : (
                                <p className="text-slate-500">
                                  No risk indicators matched for this
                                  evidence.
                                </p>
                              )}
                            </div>
                          </td>
                        </tr>
                      )}
                    </Fragment>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}

        <div className="flex flex-col items-center justify-between gap-4 border-t border-slate-700 p-4 sm:flex-row">
          <p className="text-sm text-slate-400">
            {total} evidence record{total === 1 ? "" : "s"}
          </p>

          <div className="flex items-center gap-4">
            <div className="flex items-center gap-2">
              <label className="text-sm text-slate-400">Rows</label>

              <select
                value={pageSize}
                onChange={(event) => {
                  setPageSize(Number(event.target.value));
                  setPage(1);
                }}
                className="rounded-lg border border-slate-700 bg-slate-950 px-2 py-1 text-white outline-none focus:border-cyan-500"
              >
                <option value={10}>10</option>
                <option value={20}>20</option>
                <option value={50}>50</option>
                <option value={100}>100</option>
              </select>
            </div>

            <div className="flex items-center gap-2">
              <button
                disabled={page <= 1}
                onClick={() => setPage((value) => value - 1)}
                className="flex items-center gap-1 rounded-lg border border-slate-700 px-3 py-1.5 text-sm text-slate-300 transition hover:bg-slate-800 disabled:cursor-not-allowed disabled:opacity-40"
              >
                <ChevronLeft size={16} />
                Prev
              </button>

              <span className="text-sm text-slate-400">
                Page {page} of {totalPages || 1}
              </span>

              <button
                disabled={page >= totalPages}
                onClick={() => setPage((value) => value + 1)}
                className="flex items-center gap-1 rounded-lg border border-slate-700 px-3 py-1.5 text-sm text-slate-300 transition hover:bg-slate-800 disabled:cursor-not-allowed disabled:opacity-40"
              >
                Next
                <ChevronRight size={16} />
              </button>
            </div>
          </div>
        </div>
      </div>

      {detail && (
        <div
          className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 p-4"
          onClick={() => setDetail(null)}
        >
          <div
            className="max-h-[85vh] w-full max-w-2xl overflow-auto rounded-2xl border border-slate-700 bg-slate-900 p-6"
            onClick={(event) => event.stopPropagation()}
          >
            <div className="flex items-start justify-between">
              <div>
                <h2 className="text-2xl font-bold text-white">
                  Evidence Details
                </h2>

                <p className="mt-1 font-mono text-sm text-cyan-400">
                  #{detail.id} — {detail.plugin}
                </p>
              </div>

              <button
                onClick={() => setDetail(null)}
                className="rounded-lg p-2 text-slate-400 transition hover:bg-slate-800 hover:text-white"
              >
                <X size={20} />
              </button>
            </div>

            <dl className="mt-6 grid gap-4 sm:grid-cols-2">
              <div>
                <dt className="text-sm text-slate-500">
                  Investigation ID
                </dt>
                <dd className="mt-1 font-mono text-slate-200">
                  {detail.investigation_id ?? "—"}
                </dd>
              </div>

              <div>
                <dt className="text-sm text-slate-500">
                  Plugin Execution ID
                </dt>
                <dd className="mt-1 font-mono text-slate-200">
                  {detail.plugin_execution_id}
                </dd>
              </div>

              <div>
                <dt className="text-sm text-slate-500">
                  Artifact Type
                </dt>
                <dd className="mt-1 text-slate-200">
                  {detail.artifact_type}
                </dd>
              </div>

              <div>
                <dt className="text-sm text-slate-500">
                  Artifact Name
                </dt>
                <dd className="mt-1 break-words text-slate-200">
                  {detail.artifact_name}
                </dd>
              </div>

              <div>
                <dt className="text-sm text-slate-500">
                  Confidence Score
                </dt>
                <dd className="mt-1 text-slate-200">
                  {detail.confidence_score}%
                </dd>
              </div>

              <div>
                <dt className="text-sm text-slate-500">Severity</dt>
                <dd className="mt-1">
                  <SeverityBadge severity={detail.severity} />
                </dd>
              </div>

              <div>
                <dt className="text-sm text-slate-500">Created</dt>
                <dd className="mt-1 text-slate-200">
                  {formatDate(detail.created_at)}
                </dd>
              </div>
            </dl>

            <div className="mt-6">
              <p className="mb-2 block text-sm text-slate-500">
                Risk Reasoning
              </p>

              <div className="rounded-lg border border-slate-700 bg-slate-950 p-4">
                {(detail.risk_reasons ?? []).length > 0 ? (
                  <ul className="list-inside list-disc space-y-1 text-sm text-slate-300">
                    {(detail.risk_reasons ?? []).map((reason, index) => (
                      <li key={index}>{reason}</li>
                    ))}
                  </ul>
                ) : (
                  <p className="text-sm text-slate-500">
                    No risk indicators matched for this evidence.
                  </p>
                )}

                {(detail.risk_indicators ?? []).length > 0 && (
                  <p className="mt-3 font-mono text-xs text-slate-500">
                    Indicators:{" "}
                    {(detail.risk_indicators ?? []).join(", ")}
                  </p>
                )}
              </div>
            </div>

            <div className="mt-6">
              <p className="mb-2 block text-sm text-slate-500">
                Artifact Value
              </p>

              <div className="rounded-lg border border-slate-700 bg-slate-950 p-4">
                {detailLoading ? (
                  <Loader2
                    className="animate-spin text-slate-500"
                    size={20}
                  />
                ) : (
                  <PrettyValue value={detail.artifact_value} />
                )}
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
