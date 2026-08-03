import {
  Brain,
  Database,
  Search,
  FileSearch,
} from "lucide-react";

import StatisticCard from "./StatisticCard";

export default function DashboardGrid() {
  return (
    <div className="grid gap-6 md:grid-cols-2 xl:grid-cols-4">

      <StatisticCard
        title="Memory Dumps"
        value="12"
        subtitle="Uploaded investigations"
        icon={Database}
      />

      <StatisticCard
        title="Investigations"
        value="8"
        subtitle="Completed analyses"
        icon={Search}
      />

      <StatisticCard
        title="AI Queries"
        value="56"
        subtitle="Questions answered"
        icon={Brain}
      />

      <StatisticCard
        title="Evidence"
        value="1,284"
        subtitle="Indexed artifacts"
        icon={FileSearch}
      />

    </div>
  );
}