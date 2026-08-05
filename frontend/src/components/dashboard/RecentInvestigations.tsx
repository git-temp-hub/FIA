import { CalendarDays, FileArchive } from "lucide-react";

import type { DashboardRecentInvestigation } from "../../types/dashboard";

interface RecentInvestigationsProps {
  items: DashboardRecentInvestigation[];
}

function formatDate(value: string): string {
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

export default function RecentInvestigations({
  items,
}: RecentInvestigationsProps) {
  return (
    <div className="rounded-2xl border border-slate-800 bg-slate-900 p-6">
      <h2 className="mb-6 text-xl font-semibold text-white">
        Recent Investigations
      </h2>

      {items.length === 0 ? (
        <p className="rounded-xl bg-slate-950 p-6 text-center text-slate-500">
          No investigations have been uploaded yet.
        </p>
      ) : (
        <div className="space-y-4">
          {items.map((item) => (
            <div
              key={item.investigation_id}
              className="flex items-center justify-between gap-4 rounded-xl bg-slate-950 p-4"
            >
              <div className="flex min-w-0 items-center gap-4">
                <FileArchive className="shrink-0 text-cyan-400" size={22} />

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
                  </div>
                </div>
              </div>

              <span
                className={`shrink-0 rounded-full px-3 py-1 text-xs font-semibold uppercase ${statusStyle(
                  item.status,
                )}`}
              >
                {item.status}
              </span>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
