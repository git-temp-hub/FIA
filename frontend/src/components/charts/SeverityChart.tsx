import {
  Bar,
  BarChart,
  Cell,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";

import type { DashboardSeverityDistribution } from "../../types/dashboard";

interface SeverityChartProps {
  data: DashboardSeverityDistribution[];
}

/** Severity ordering and colour, most severe first. */
const SEVERITY_META: Record<string, { label: string; color: string }> = {
  high: { label: "High", color: "#ef4444" },
  medium: { label: "Medium", color: "#f59e0b" },
  low: { label: "Low", color: "#22c55e" },
  unknown: { label: "Unknown", color: "#64748b" },
  "insufficient-evidence": {
    label: "Insufficient",
    color: "#475569",
  },
  unclassified: { label: "Unclassified", color: "#334155" },
};

const ORDER = [
  "high",
  "medium",
  "low",
  "unknown",
  "insufficient-evidence",
  "unclassified",
];

export default function SeverityChart({ data }: SeverityChartProps) {
  const chartData = [...data]
    .sort((a, b) => ORDER.indexOf(a.severity) - ORDER.indexOf(b.severity))
    .map((item) => ({
      severity:
        SEVERITY_META[item.severity]?.label ?? item.severity,
      count: item.count,
      color: SEVERITY_META[item.severity]?.color ?? "#64748b",
    }));

  const total = chartData.reduce((sum, item) => sum + item.count, 0);

  return (
    <div className="rounded-2xl border border-slate-800 bg-slate-900 p-6">
      <div className="mb-6 flex items-baseline justify-between gap-3">
        <h2 className="text-xl font-semibold text-white">
          Evidence by Severity
        </h2>

        <span className="text-sm text-slate-500">
          {total.toLocaleString()} artifacts
        </span>
      </div>

      {chartData.length === 0 ? (
        <div className="flex h-72 items-center justify-center text-slate-500">
          No classified evidence yet.
        </div>
      ) : (
        <div className="h-72">
          <ResponsiveContainer width="100%" height="100%">
            <BarChart
              data={chartData}
              margin={{ top: 8, right: 8, bottom: 8, left: 0 }}
            >
              <XAxis
                dataKey="severity"
                stroke="#64748b"
                tickLine={false}
                axisLine={false}
                fontSize={12}
              />

              <YAxis
                stroke="#64748b"
                tickLine={false}
                axisLine={false}
                fontSize={12}
                allowDecimals={false}
              />

              <Tooltip
                cursor={{ fill: "rgba(148,163,184,0.08)" }}
                contentStyle={{
                  background: "#0f172a",
                  border: "1px solid #1e293b",
                  borderRadius: "0.75rem",
                  color: "#e2e8f0",
                }}
              />

              <Bar dataKey="count" radius={[6, 6, 0, 0]}>
                {chartData.map((entry) => (
                  <Cell key={entry.severity} fill={entry.color} />
                ))}
              </Bar>
            </BarChart>
          </ResponsiveContainer>
        </div>
      )}
    </div>
  );
}
