import type { LucideIcon } from "lucide-react";

interface StatisticCardProps {
  title: string;
  value: string | number;
  subtitle: string;
  icon: LucideIcon;
}

export default function StatisticCard({
  title,
  value,
  subtitle,
  icon: Icon,
}: StatisticCardProps) {
  return (
    <div className="rounded-2xl border border-slate-800 bg-slate-900 p-6 shadow-lg transition-all duration-300 hover:border-cyan-500 hover:shadow-cyan-900/20">

      <div className="flex items-center justify-between">

        <div>

          <p className="text-sm uppercase tracking-wide text-slate-400">
            {title}
          </p>

          <h2 className="mt-3 text-4xl font-bold text-white">
            {value}
          </h2>

          <p className="mt-2 text-sm text-slate-500">
            {subtitle}
          </p>

        </div>

        <div className="rounded-xl bg-cyan-500/10 p-4">

          <Icon
            size={34}
            className="text-cyan-400"
          />

        </div>

      </div>

    </div>
  );
}