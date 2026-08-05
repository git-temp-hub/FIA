import { useEffect, useMemo, useState } from "react";

import { useSearchParams } from "react-router-dom";

import {
  AlertCircle,
  Loader2,
  RefreshCw,
  Search,
  Sparkles,
} from "lucide-react";

import { listEvidenceInvestigations } from "../../services/evidenceService";
import { indexInvestigation, searchRag } from "../../services/ragService";

import type { EvidenceInvestigationSummary } from "../../types/evidence";
import type { RAGSearchItem, RAGSearchResponse } from "../../types/rag";

function PrettyDocument({ document }: { document: string }) {
  const text = useMemo(() => {
    try {
      const parsed: Record<string, unknown> = JSON.parse(document);
      const jsonKeys = Object.keys(parsed);

      if (jsonKeys.some((key) => key.includes("value"))) {
        return document;
      }

      return JSON.stringify(parsed, null, 2);
    } catch {
      return document;
    }
  }, [document]);

  return (
    <pre className="whitespace-pre-wrap break-words text-sm text-slate-300">
      {text}
    </pre>
  );
}

function ResultCard({ item, rank }: { item: RAGSearchItem; rank: number }) {
  return (
    <div className="rounded-xl border border-slate-700 bg-slate-900 p-5">
      <div className="flex flex-wrap items-center gap-3">
        <span className="rounded-full bg-cyan-500/20 px-3 py-1 text-xs font-semibold text-cyan-400">
          #{rank}
        </span>

        {item.score !== null && (
          <span className="rounded-full bg-green-500/20 px-3 py-1 text-xs font-semibold text-green-400">
            {Math.round(item.score * 100)}% match
          </span>
        )}

        {item.plugin_name && (
          <span className="rounded-full bg-slate-700/60 px-3 py-1 font-mono text-xs text-slate-300">
            {item.plugin_name}
          </span>
        )}

        {item.artifact_type && (
          <span className="rounded-full bg-slate-700/60 px-3 py-1 text-xs text-slate-300">
            {item.artifact_type}
          </span>
        )}

        {item.confidence_score !== null && (
          <span className="rounded-full bg-slate-700/60 px-3 py-1 text-xs text-slate-300">
            confidence {item.confidence_score}%
          </span>
        )}
      </div>

      {item.investigation_id && (
        <p className="mt-3 font-mono text-xs text-slate-500">
          Investigation: {item.investigation_id}
          {item.evidence_id !== null ? ` · evidence #${item.evidence_id}` : ""}
        </p>
      )}

      <div className="mt-3 rounded-lg border border-slate-800 bg-slate-950 p-4">
        <PrettyDocument document={item.document} />
      </div>
    </div>
  );
}

export default function RagSearchPage() {
  const [searchParams] = useSearchParams();

  const [investigations, setInvestigations] = useState<
    EvidenceInvestigationSummary[]
  >([]);

  const [query, setQuery] = useState("");
  const [investigationId, setInvestigationId] = useState(
    searchParams.get("id") ?? "",
  );

  const [data, setData] = useState<RAGSearchResponse | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [indexing, setIndexing] = useState(false);
  const [indexMessage, setIndexMessage] = useState<string | null>(null);

  useEffect(() => {
    listEvidenceInvestigations()
      .then(setInvestigations)
      .catch(() => setInvestigations([]));
  }, []);

  async function handleSearch(event?: { preventDefault: () => void }) {
    event?.preventDefault();

    const trimmed = query.trim();
    if (!trimmed) return;

    setLoading(true);
    setError(null);
    setIndexMessage(null);

    try {
      const response = await searchRag(
        trimmed,
        investigationId || undefined,
        10,
      );
      setData(response);
    } catch {
      setError("Search failed. Make sure the investigation has been indexed.");
      setData(null);
    } finally {
      setLoading(false);
    }
  }

  async function handleIndex() {
    if (!investigationId) return;

    setIndexing(true);
    setIndexMessage(null);

    try {
      const response = await indexInvestigation(investigationId);
      setIndexMessage(
        `Indexed ${response.indexed} evidence record(s) (removed ${response.removed} old).`,
      );
    } catch {
      setIndexMessage("Re-indexing failed.");
    } finally {
      setIndexing(false);
    }
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center gap-3">
        <Sparkles className="text-cyan-400" size={32} />

        <div>
          <h1 className="text-4xl font-bold text-white">
            Semantic Evidence Search
          </h1>

          <p className="mt-2 text-slate-400">
            Search indexed evidence using natural language.
          </p>
        </div>
      </div>

      <form
        onSubmit={handleSearch}
        className="rounded-xl border border-slate-700 bg-slate-900 p-4"
      >
        <div className="grid gap-4 md:grid-cols-[1fr_240px_auto]">
          <div>
            <label className="mb-2 block text-sm font-medium text-slate-400">
              Question
            </label>

            <div className="relative">
              <Search
                className="absolute left-3 top-1/2 -translate-y-1/2 text-slate-500"
                size={16}
              />

              <input
                value={query}
                onChange={(event) => setQuery(event.target.value)}
                placeholder="e.g. Which processes are running suspicious commands?"
                className="w-full rounded-lg border border-slate-700 bg-slate-950 py-3 pl-9 pr-3 text-white outline-none focus:border-cyan-500"
              />
            </div>
          </div>

          <div>
            <label className="mb-2 block text-sm font-medium text-slate-400">
              Investigation
            </label>

            <select
              value={investigationId}
              onChange={(event) => setInvestigationId(event.target.value)}
              className="w-full rounded-lg border border-slate-700 bg-slate-950 px-3 py-3 text-white outline-none focus:border-cyan-500"
            >
              <option value="">All investigations</option>

              {investigations.map((item) => (
                <option
                  key={item.investigation_id}
                  value={item.investigation_id}
                >
                  {item.investigation_id} — {item.filename}
                </option>
              ))}
            </select>
          </div>

          <div className="flex items-end gap-2">
            <button
              type="submit"
              disabled={!query.trim() || loading}
              className="rounded-lg bg-cyan-500 px-6 py-3 font-semibold text-black transition hover:bg-cyan-400 disabled:cursor-not-allowed disabled:opacity-40"
            >
              Search
            </button>

            <button
              type="button"
              onClick={handleIndex}
              disabled={!investigationId || indexing}
              className="flex items-center gap-2 rounded-lg border border-slate-700 px-4 py-3 text-sm text-slate-300 transition hover:bg-slate-800 disabled:cursor-not-allowed disabled:opacity-40"
            >
              <RefreshCw
                size={15}
                className={indexing ? "animate-spin" : ""}
              />
              Re-index
            </button>
          </div>
        </div>

        {indexMessage && (
          <p className="mt-3 text-sm text-cyan-400">{indexMessage}</p>
        )}
      </form>

      {loading ? (
        <div className="flex items-center justify-center gap-3 py-20 text-slate-400">
          <Loader2 className="animate-spin" size={20} />
          Searching...
        </div>
      ) : error ? (
        <div className="flex items-center justify-center gap-3 py-20 text-red-400">
          <AlertCircle size={28} />
          <p>{error}</p>
        </div>
      ) : data ? (
        data.count === 0 ? (
          <div className="py-20 text-center text-slate-500">
            <p>No matching evidence found.</p>
          </div>
        ) : (
          <div className="space-y-4">
            <p className="text-sm text-slate-400">
              {data.count} ranked result{data.count === 1 ? "" : "s"} for{" "}
              <span className="font-semibold text-white">
                "{data.query}"
              </span>
            </p>

            {data.items.map((item, index) => (
              <ResultCard key={item.evidence_id ?? index} item={item} rank={index + 1} />
            ))}
          </div>
        )
      ) : (
        <div className="flex flex-col items-center gap-3 py-20 text-slate-600">
          <Sparkles size={28} />
          <p>
            Ask a question to retrieve the most relevant forensic evidence.
          </p>
        </div>
      )}
    </div>
  );
}
