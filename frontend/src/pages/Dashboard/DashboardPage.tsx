import { useEffect, useState } from "react";
import { RefreshCw } from "lucide-react";

import DashboardGrid from "../../components/dashboard/DashboardGrid";
import RecentInvestigations from "../../components/dashboard/RecentInvestigations";
import QuickActions from "../../components/dashboard/QuickActions";

import InvestigationChart from "../../components/charts/InvestigationChart";
import EvidencePieChart from "../../components/charts/EvidencePieChart";
import SeverityChart from "../../components/charts/SeverityChart";

import { getDashboardStats } from "../../services/dashboardService";

import type { DashboardStats } from "../../types/dashboard";

export default function DashboardPage() {
  const [stats, setStats] = useState<DashboardStats | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    getDashboardStats()
      .then(setStats)
      .catch(() => setError("Unable to load dashboard statistics."))
      .finally(() => setLoading(false));
  }, []);

  async function handleRefresh() {
    setLoading(true);
    setError(null);

    try {
      const data = await getDashboardStats();
      setStats(data);
    } catch {
      setError("Unable to load dashboard statistics.");
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="space-y-8">
      {/* Page Header */}
      <div className="flex flex-wrap items-center justify-between gap-4">
        <div>
          <h1 className="text-4xl font-bold text-white">Dashboard</h1>
          <p className="mt-2 text-slate-400">
            AI-powered memory forensic investigation platform.
          </p>
        </div>

        <div className="flex items-center gap-4">
          {/* Health lives in the global header now — see
              components/navigation/SystemHealthIndicator. */}
          <button
            type="button"
            onClick={handleRefresh}
            disabled={loading}
            className="inline-flex items-center gap-2 rounded-lg border border-slate-700 bg-slate-900 px-4 py-2 text-sm font-medium text-slate-200 transition hover:border-cyan-500 disabled:cursor-not-allowed disabled:opacity-50"
          >
            <RefreshCw
              className={`h-4 w-4 ${loading ? "animate-spin" : ""}`}
            />
            Refresh
          </button>
        </div>
      </div>

      {loading && !stats ? (
        <div className="rounded-2xl border border-slate-800 bg-slate-900 p-10 text-center">
          <p className="text-slate-400">Loading dashboard statistics...</p>
        </div>
      ) : error && !stats ? (
        <div className="rounded-2xl border border-red-800 bg-slate-900 p-10 text-center">
          <p className="text-red-400">{error}</p>
          <button
            type="button"
            onClick={handleRefresh}
            className="mt-4 rounded-lg bg-cyan-500 px-4 py-2 font-semibold text-black transition hover:bg-cyan-400"
          >
            Retry
          </button>
        </div>
      ) : stats ? (
        <>
          {/* Statistics */}
          <DashboardGrid stats={stats} />

          {/* Charts are the visual anchor of the page: investigation data
              occupies the primary area, not status text. */}
          <div className="grid gap-6 xl:grid-cols-2">
            <InvestigationChart data={stats.investigation_trend} />
            <SeverityChart data={stats.severity_distribution} />
          </div>

          <div className="grid gap-6 xl:grid-cols-2">
            <EvidencePieChart data={stats.evidence_distribution} />
            <RecentInvestigations items={stats.recent_investigations} />
          </div>

          {/* Quick Actions */}
          <QuickActions />
        </>
      ) : null}
    </div>
  );
}
