import { lazy, Suspense } from "react";
import { BrowserRouter, Routes, Route, Navigate } from "react-router-dom";

import DashboardPage from "../pages/Dashboard/DashboardPage";
import UploadPage from "../pages/Upload/UploadPage";
import InvestigationListPage from "../pages/Investigation/InvestigationListPage";
import InvestigationPage from "../pages/Investigation/InvestigationPage";
import SettingsPage from "../pages/Settings/SettingsPage";

import AppLayout from "../components/layout/AppLayout";
import NotFoundPage from "../pages/NotFound/NotFoundPage";

const EvidencePage = lazy(
  () => import("../pages/Evidence/EvidencePage"),
);
const RagSearchPage = lazy(
  () => import("../pages/RagSearch/RagSearchPage"),
);
const ChatPage = lazy(() => import("../pages/Chat/ChatPage"));
const ReportsPage = lazy(
  () => import("../pages/Reports/ReportsPage"),
);

function PageLoader() {
  return (
    <div className="rounded-2xl border border-slate-800 bg-slate-900 p-10 text-center">
      <p className="text-slate-400">Loading...</p>
    </div>
  );
}

export default function AppRouter() {
  return (
    <BrowserRouter>
      <AppLayout>
        <Suspense fallback={<PageLoader />}>
          <Routes>
            <Route path="/" element={<Navigate to="/dashboard" replace />} />
            <Route path="/dashboard" element={<DashboardPage />} />
            <Route path="/upload" element={<UploadPage />} />
            <Route path="/investigation" element={<InvestigationListPage />} />
            <Route
              path="/investigation/:investigationId"
              element={<InvestigationPage />}
            />
            <Route path="/evidence" element={<EvidencePage />} />
            <Route path="/rag" element={<RagSearchPage />} />
            <Route path="/ai" element={<ChatPage />} />
            <Route path="/reports" element={<ReportsPage />} />
            <Route path="/settings" element={<SettingsPage />} />
            <Route path="*" element={<NotFoundPage />} />
          </Routes>
        </Suspense>
      </AppLayout>
    </BrowserRouter>
  );
}
