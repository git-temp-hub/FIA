import DashboardGrid from "../../components/dashboard/DashboardGrid";
import RecentInvestigations from "../../components/dashboard/RecentInvestigations";
import SystemStatus from "../../components/dashboard/SystemStatus";
import QuickActions from "../../components/dashboard/QuickActions";

import InvestigationChart from "../../components/charts/InvestigationChart";
import EvidencePieChart from "../../components/charts/EvidencePieChart";

export default function DashboardPage() {
  return (
    <div className="space-y-8">

      {/* ====================================================== */}
      {/* Page Header */}
      {/* ====================================================== */}

      <div className="flex items-center justify-between">

        <div>

          <h1 className="text-4xl font-bold text-white">
            Dashboard
          </h1>

          <p className="mt-2 text-slate-400">
            AI-powered memory forensic investigation platform.
          </p>

        </div>

        <div className="rounded-full bg-green-500/20 px-5 py-2">

          <span className="font-semibold text-green-400">
            ● System Healthy
          </span>

        </div>

      </div>

      {/* ====================================================== */}
      {/* Statistics */}
      {/* ====================================================== */}

      <DashboardGrid />

      {/* ====================================================== */}
      {/* Recent Investigations + System Status */}
      {/* ====================================================== */}

      <div className="grid gap-6 xl:grid-cols-2">

        <RecentInvestigations />

        <SystemStatus />

      </div>

      {/* ====================================================== */}
      {/* Quick Actions */}
      {/* ====================================================== */}

      <QuickActions />

      {/* ====================================================== */}
      {/* Analytics Charts */}
      {/* ====================================================== */}

      <div className="grid gap-6 xl:grid-cols-2">

        <InvestigationChart />

        <EvidencePieChart />

      </div>

    </div>
  );
}