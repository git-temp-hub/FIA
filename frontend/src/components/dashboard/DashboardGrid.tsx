import {
  Brain,
  Database,
  FileSearch,
  FileText,
  Gauge,
  Search,
} from "lucide-react";

import StatisticCard from "./StatisticCard";

import type { DashboardStats } from "../../types/dashboard";

interface DashboardGridProps {
  stats: DashboardStats;
}

function formatNumber(value: number): string {
  return value.toLocaleString();
}

export default function DashboardGrid({ stats }: DashboardGridProps) {
  return (
    <div className="grid gap-6 md:grid-cols-2 xl:grid-cols-3 2xl:grid-cols-6">
      <StatisticCard
        title="Investigations"
        value={formatNumber(stats.total_investigations)}
        subtitle="Registered investigations"
        icon={Search}
      />

      <StatisticCard
        title="Memory Dumps"
        value={formatNumber(stats.total_memory_dumps)}
        subtitle="Uploaded memory images"
        icon={Database}
      />

      <StatisticCard
        title="Evidence"
        value={formatNumber(stats.total_evidence)}
        subtitle="Indexed artifacts"
        icon={FileSearch}
      />

      <StatisticCard
        title="Reports"
        value={formatNumber(stats.total_reports)}
        subtitle="Generated PDF reports"
        icon={FileText}
      />

      <StatisticCard
        title="AI Queries"
        value={formatNumber(stats.total_ai_queries)}
        subtitle="Questions answered"
        icon={Brain}
      />

      <StatisticCard
        title="Plugin Success"
        value={`${stats.plugin_execution_success_rate.toFixed(1)}%`}
        subtitle={`${stats.plugin_executions_total} total executions`}
        icon={Gauge}
      />
    </div>
  );
}
