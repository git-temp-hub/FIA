import { BrowserRouter, Routes, Route, Navigate } from "react-router-dom";

import DashboardPage from "../pages/Dashboard/DashboardPage";
import UploadPage from "../pages/Upload/UploadPage";
import InvestigationPage from "../pages/Investigation/InvestigationPage";
import EvidencePage from "../pages/Evidence/EvidencePage";
import ReportsPage from "../pages/Reports/ReportsPage";
import SettingsPage from "../pages/Settings/SettingsPage";

import AppLayout from "../components/layout/AppLayout";

export default function AppRouter() {
  return (
    <BrowserRouter>
      <AppLayout>
        <Routes>
          <Route path="/" element={<Navigate to="/dashboard" replace />} />

          <Route path="/dashboard" element={<DashboardPage />} />

          <Route path="/upload" element={<UploadPage />} />

          <Route
            path="/investigation"
            element={<InvestigationPage />}
          />

          <Route
            path="/evidence"
            element={<EvidencePage />}
          />

          <Route
            path="/reports"
            element={<ReportsPage />}
          />

          <Route
            path="/settings"
            element={<SettingsPage />}
          />
        </Routes>
      </AppLayout>
    </BrowserRouter>
  );
}