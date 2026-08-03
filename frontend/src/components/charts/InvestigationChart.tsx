import {
  ResponsiveContainer,
  AreaChart,
  Area,
  CartesianGrid,
  Tooltip,
  XAxis,
} from "recharts";

const data = [
  { day: "Mon", investigations: 2 },
  { day: "Tue", investigations: 5 },
  { day: "Wed", investigations: 4 },
  { day: "Thu", investigations: 8 },
  { day: "Fri", investigations: 6 },
  { day: "Sat", investigations: 9 },
  { day: "Sun", investigations: 7 },
];

export default function InvestigationChart() {
  return (
    <div className="rounded-2xl border border-slate-800 bg-slate-900 p-6">

      <h2 className="mb-6 text-xl font-semibold text-white">
        Weekly Investigation Trend
      </h2>

      <div className="h-80">

        <ResponsiveContainer>

          <AreaChart data={data}>

            <CartesianGrid stroke="#1e293b" />

            <XAxis
              dataKey="day"
              stroke="#94a3b8"
            />

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