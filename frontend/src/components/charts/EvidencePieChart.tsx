import {
  PieChart,
  Pie,
  Cell,
  Tooltip,
  ResponsiveContainer,
  Legend,
} from "recharts";

import type { DashboardEvidenceDistribution } from "../../types/dashboard";

interface EvidencePieChartProps {
  data: DashboardEvidenceDistribution[];
}

const colors = [
  "#06b6d4",
  "#3b82f6",
  "#8b5cf6",
  "#14b8a6",
  "#f59e0b",
  "#ef4444",
  "#22c55e",
  "#ec4899",
];

export default function EvidencePieChart({ data }: EvidencePieChartProps) {
  const chartData = data.map((item) => ({
    name: item.artifact_type,
    value: item.count,
  }));

  if (chartData.length === 0) {
    return (
      <div className="rounded-2xl border border-slate-800 bg-slate-900 p-6">
        <h2 className="mb-6 text-xl font-semibold text-white">
          Evidence Distribution
        </h2>

        <div className="flex h-80 items-center justify-center">
          <p className="text-slate-500">No evidence has been indexed yet.</p>
        </div>
      </div>
    );
  }

  return (
    <div className="rounded-2xl border border-slate-800 bg-slate-900 p-6">
      <h2 className="mb-6 text-xl font-semibold text-white">
        Evidence Distribution by Artifact Type
      </h2>

      <div className="h-80">
        <ResponsiveContainer>
          <PieChart>
            <Pie
              data={chartData}
              dataKey="value"
              nameKey="name"
              outerRadius={110}
              label
            >
              {chartData.map((_, index) => (
                <Cell key={index} fill={colors[index % colors.length]} />
              ))}
            </Pie>

            <Tooltip />

            <Legend />
          </PieChart>
        </ResponsiveContainer>
      </div>
    </div>
  );
}
