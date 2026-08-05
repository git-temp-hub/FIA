import {
  ResponsiveContainer,
  AreaChart,
  Area,
  CartesianGrid,
  Tooltip,
  XAxis,
} from "recharts";

import type { DashboardTrendPoint } from "../../types/dashboard";

interface InvestigationChartProps {
  data: DashboardTrendPoint[];
}

export default function InvestigationChart({
  data,
}: InvestigationChartProps) {
  const chartData = data.map((point) => ({
    day: point.label,
    investigations: point.investigations,
  }));

  return (
    <div className="rounded-2xl border border-slate-800 bg-slate-900 p-6">
      <h2 className="mb-6 text-xl font-semibold text-white">
        Investigations (Last 7 Days)
      </h2>

      <div className="h-80">
        <ResponsiveContainer>
          <AreaChart data={chartData}>
            <CartesianGrid stroke="#1e293b" />

            <XAxis dataKey="day" stroke="#94a3b8" />

            <Tooltip />

            <Area
              type="monotone"
              dataKey="investigations"
              stroke="#06b6d4"
              fill="#0891b2"
            />
          </AreaChart>
        </ResponsiveContainer>
      </div>
    </div>
  );
}
