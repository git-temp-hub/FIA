import { useEffect, useState } from "react";

import { useSearchParams } from "react-router-dom";

import {
  AlertCircle,
  Download,
  Eye,
  FilePlus2,
  FileText,
  Loader2,
  X,
} from "lucide-react";

import { listEvidenceInvestigations } from "../../services/evidenceService";
import { getStoredSessionId } from "../../services/chatSession";
import {
  downloadReport,
  generateReport,
  getReportDetail,
  listReports,
} from "../../services/reportService";

import type { EvidenceInvestigationSummary } from "../../types/evidence";
import type { ReportDetailResponse, ReportInfo } from "../../types/report";

const STATUS_STYLES: Record<string, string> = {
  generated: "bg-green-500/20 text-green-400",
  failed: "bg-red-500/20 text-red-400",
  pending: "bg-yellow-500/20 text-yellow-400",
};

function formatFileSize(bytes: number): string {
  const units = ["B", "KB", "MB", "GB", "TB"];
  let value = bytes;
  let unit = units[0];

  for (let index = 1; index < units.length && value >= 1024; index += 1) {
    value /= 1024;
    unit = units[index];
  }

  return `${value.toFixed(value >= 100 ? 0 : 1)} ${unit}`;
}

function formatDuration(seconds: number): string {
  if (!seconds || seconds <= 0) return "N/A";

  const minutes = Math.floor(seconds / 60);
  const remaining = Math.round(seconds % 60);

  if (minutes > 0) return `${minutes}m ${remaining}s`;

  return `${seconds.toFixed(1)}s`;
}

function formatDate(value: string): string {
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? value : date.toLocaleString();
}

function shortSha(value: string | null): string {
  if (!value) return "N/A";
  if (value.length <= 16) return value;
  return `${value.slice(0, 8)}...${value.slice(-8)}`;
}

function StatusBadge({ status }: { status: string }) {
  const style = STATUS_STYLES[status] ?? STATUS_STYLES.pending;

  return (
    <span
      className={`inline-block rounded-full px-3 py-1 text-xs font-semibold uppercase ${style}`}
    >
      {status}
    </span>
  );
}

function DetailStat({
  label,
  value,
}: {
  label: string;
  value: string | number;
}) {
  return (
    <div className="rounded-lg border border-slate-800 bg-slate-950 p-4">
      <p className="text-xs font-medium uppercase tracking-wide text-slate-500">
        {label}
      </p>

      <p className="mt-1 break-words font-mono text-sm text-white">
        {value}
      </p>
    </div>
  );
}

function ReportDetailModal({
  detail,
  onClose,
  onDownload,
  downloading,
}: {
  detail: ReportDetailResponse;
  onClose: () => void;
  onDownload: (id: number) => void;
  downloading: boolean;
}) {
  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 p-6">
      <div className="max-h-[85vh] w-full max-w-2xl overflow-y-auto rounded-2xl border border-slate-700 bg-slate-900 p-6">
        <div className="flex items-center justify-between">
          <h2 className="text-xl font-bold text-white">
            Report Details
          </h2>

          <button
            type="button"
            onClick={onClose}
            className="rounded-lg p-2 text-slate-400 transition hover:bg-slate-800 hover:text-white"
          >
            <X size={20} />
          </button>
        </div>

        <div className="mt-4 grid gap-3 sm:grid-cols-2">
          <DetailStat label="Report ID" value={detail.id} />
          <DetailStat
            label="Investigation"
            value={detail.investigation_id}
          />
          <DetailStat label="Case Name" value={detail.case_name} />
          <DetailStat
            label="Dump Filename"
            value={detail.memory_dump_filename ?? detail.dump_filename ?? "N/A"}
          />
          <DetailStat
            label="SHA-256"
            value={detail.sha256_hash ?? "N/A"}
          />
          <DetailStat
            label="File Size"
            value={formatFileSize(detail.file_size)}
          />
          <DetailStat
            label="Generated"
            value={formatDate(detail.generated_at)}
          />
          <DetailStat label="Status" value={detail.status} />
        </div>

        <h3 className="mt-6 text-sm font-semibold uppercase tracking-wide text-slate-400">
          Investigation Statistics
        </h3>

        <div className="mt-3 grid gap-3 sm:grid-cols-2">
          <DetailStat
            label="Investigation Status"
            value={detail.investigation_status ?? "N/A"}
          />
          <DetailStat
            label="Total Plugins"
            value={detail.total_plugins}
          />
          <DetailStat
            label="Successful Plugins"
            value={detail.successful_plugins}
          />
          <DetailStat label="Failed Plugins" value={detail.failed_plugins} />
          <DetailStat label="Total Evidence" value={detail.total_evidence} />
          <DetailStat
            label="Investigation Duration"
            value={formatDuration(detail.investigation_duration)}
          />
        </div>

        {detail.error_message && (
          <div className="mt-6 flex items-start gap-2 rounded-lg border border-red-800 bg-red-950/40 p-4 text-sm text-red-300">
            <AlertCircle size={16} className="mt-0.5 shrink-0" />
            <p className="break-words whitespace-pre-wrap">
              {detail.error_message}
            </p>
          </div>
        )}

        <div className="mt-6 flex justify-end gap-3">
          <button
            type="button"
            onClick={onClose}
            className="rounded-lg border border-slate-700 px-5 py-2.5 text-sm text-slate-300 transition hover:bg-slate-800"
          >
            Close
          </button>

          <button
            type="button"
            onClick={() => onDownload(detail.id)}
            disabled={downloading}
            className="flex items-center gap-2 rounded-lg bg-cyan-500 px-5 py-2.5 text-sm font-semibold text-black transition hover:bg-cyan-400 disabled:cursor-not-allowed disabled:opacity-40"
          >
            {downloading ? (
              <Loader2 className="animate-spin" size={16} />
            ) : (
              <Download size={16} />
            )}
            Download PDF
          </button>
        </div>
      </div>
    </div>
  );
}

export default function ReportsPage() {
  const [searchParams] = useSearchParams();

  const [investigations, setInvestigations] = useState<
    EvidenceInvestigationSummary[]
  >([]);

  const [investigationId, setInvestigationId] = useState(
    searchParams.get("id") ?? "",
  );

  const [reports, setReports] = useState<ReportInfo[]>([]);
  const [loading, setLoading] = useState(true);
  const [generating, setGenerating] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [message, setMessage] = useState<string | null>(null);

  const [downloading, setDownloading] = useState<number | null>(null);

  const [detail, setDetail] = useState<ReportDetailResponse | null>(null);
  const [detailLoading, setDetailLoading] = useState(false);

  useEffect(() => {
    listEvidenceInvestigations()
      .then(setInvestigations)
      .catch(() => setInvestigations([]));

    listReports()
      .then((response) => setReports(response.items))
      .catch(() => setError("Failed to load report history."))
      .finally(() => setLoading(false));
  }, []);

  async function handleGenerate() {
    if (!investigationId || generating) return;

    setGenerating(true);
    setError(null);
    setMessage(null);

    try {
      const result = await generateReport(
        investigationId,
        getStoredSessionId(investigationId),
      );
      setMessage(result.message);

      const list = await listReports();
      setReports(list.items);
    } catch {
      setError(
        "Report generation failed. Make sure the investigation exists and has completed a run.",
      );
    } finally {
      setGenerating(false);
    }
  }

  async function handleDownload(reportId: number) {
    setDownloading(reportId);
    setError(null);

    try {
      await downloadReport(reportId);
    } catch {
      setError("Failed to download the report PDF.");
    } finally {
      setDownloading(null);
    }
  }

  async function handleView(reportId: number) {
    setDetailLoading(true);
    setError(null);

    try {
      const data = await getReportDetail(reportId);
      setDetail(data);
    } catch {
      setError("Failed to load report details.");
    } finally {
      setDetailLoading(false);
    }
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center gap-3">
        <FileText className="text-cyan-400" size={32} />

        <div>
          <h1 className="text-4xl font-bold text-white">Reports</h1>

          <p className="mt-2 text-slate-400">
            Generate, download, and review forensic investigation reports.
          </p>
        </div>
      </div>

      <div className="grid gap-6 lg:grid-cols-[340px_1fr]">
        <div className="h-fit rounded-xl border border-slate-700 bg-slate-900 p-5">
          <div className="flex items-center gap-2">
            <FilePlus2 className="text-cyan-400" size={18} />
            <h2 className="font-semibold text-white">Generate Report</h2>
          </div>

          <p className="mt-2 text-sm text-slate-400">
            Select an investigation and generate a complete PDF report.
          </p>

          <label className="mb-2 mt-4 block text-sm font-medium text-slate-400">
            Investigation
          </label>

          <select
            value={investigationId}
            onChange={(event) => setInvestigationId(event.target.value)}
            className="w-full rounded-lg border border-slate-700 bg-slate-950 px-3 py-3 text-white outline-none focus:border-cyan-500"
          >
            <option value="">Select an investigation</option>

            {investigations.map((item) => (
              <option
                key={item.investigation_id}
                value={item.investigation_id}
              >
                {item.investigation_id} — {item.filename}
              </option>
            ))}
          </select>

          <button
            type="button"
            onClick={handleGenerate}
            disabled={!investigationId || generating}
            className="mt-4 flex w-full items-center justify-center gap-2 rounded-lg bg-cyan-500 px-6 py-3 font-semibold text-black transition hover:bg-cyan-400 disabled:cursor-not-allowed disabled:opacity-40"
          >
            {generating ? (
              <>
                <Loader2 className="animate-spin" size={18} />
                Generating...
              </>
            ) : (
              <>
                <FilePlus2 size={18} />
                Generate Report
              </>
            )}
          </button>

          {message && (
            <p className="mt-3 text-sm text-green-400">{message}</p>
          )}

          {error && (
            <div className="mt-3 flex items-start gap-2 text-sm text-red-400">
              <AlertCircle size={16} className="mt-0.5 shrink-0" />
              <p>{error}</p>
            </div>
          )}
        </div>

        <div className="rounded-xl border border-slate-700 bg-slate-900">
          <div className="border-b border-slate-800 px-5 py-4">
            <h2 className="font-semibold text-white">Report History</h2>
            <p className="mt-1 text-sm text-slate-400">
              {reports.length} report{reports.length === 1 ? "" : "s"} generated
            </p>
          </div>

          <div className="divide-y divide-slate-800">
            {loading ? (
              <div className="flex items-center justify-center gap-3 py-16 text-slate-400">
                <Loader2 className="animate-spin" size={20} />
                Loading reports...
              </div>
            ) : reports.length === 0 ? (
              <div className="flex flex-col items-center gap-3 py-16 text-slate-500">
                <FileText size={28} />
                <p>No reports have been generated yet.</p>
              </div>
            ) : (
              reports.map((report) => (
                <div
                  key={report.id}
                  className="flex flex-wrap items-center gap-4 px-5 py-4"
                >
                  <div className="rounded-lg bg-slate-800 p-3 text-cyan-400">
                    <FileText size={20} />
                  </div>

                  <div className="min-w-0 flex-1">
                    <p className="truncate font-mono text-sm font-semibold text-white">
                      {report.filename}
                    </p>

                    <p className="mt-0.5 font-mono text-xs text-slate-500">
                      {report.investigation_id}
                      {report.case_name ? ` · ${report.case_name}` : ""}
                    </p>

                    <p className="mt-0.5 text-xs text-slate-500">
                      {report.dump_filename ?? "Unknown dump"} ·{" "}
                      {shortSha(report.sha256_hash)} ·{" "}
                      {formatFileSize(report.file_size)} ·{" "}
                      {formatDate(report.generated_at)}
                    </p>
                  </div>

                  <StatusBadge status={report.status} />

                  <div className="flex items-center gap-2">
                    <button
                      type="button"
                      onClick={() => handleView(report.id)}
                      disabled={detailLoading}
                      className="flex items-center gap-2 rounded-lg border border-slate-700 px-3 py-2 text-sm text-slate-300 transition hover:bg-slate-800"
                    >
                      <Eye size={15} />
                      Details
                    </button>

                    <button
                      type="button"
                      onClick={() => handleDownload(report.id)}
                      disabled={downloading === report.id}
                      className="flex items-center gap-2 rounded-lg bg-cyan-500 px-3 py-2 text-sm font-semibold text-black transition hover:bg-cyan-400 disabled:cursor-not-allowed disabled:opacity-40"
                    >
                      {downloading === report.id ? (
                        <Loader2 className="animate-spin" size={15} />
                      ) : (
                        <Download size={15} />
                      )}
                      Download
                    </button>
                  </div>
                </div>
              ))
            )}
          </div>
        </div>
      </div>

      {detail && (
        <ReportDetailModal
          detail={detail}
          onClose={() => setDetail(null)}
          onDownload={handleDownload}
          downloading={downloading === detail.id}
        />
      )}
    </div>
  );
}
