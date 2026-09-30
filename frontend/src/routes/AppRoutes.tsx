import { Routes, Route, Navigate } from "react-router-dom";
import MainLayout from "../layouts/MainLayout";
import OverviewPage from "../pages/OverviewPage";
import NetworkStatePage from "../pages/NetworkStatePage";
import ForecastingPage from "../pages/ForecastingPage";
import AttackAnalysisPage from "../pages/AttackAnalysisPage";
import ExplainabilityPage from "../pages/ExplainabilityPage";
import MitrePage from "../pages/MitrePage";
import GeneralizationPage from "../pages/GeneralizationPage";
import MitigationPage from "../pages/MitigationPage";
import VerificationPage from "../pages/VerificationPage";
import DemoPage from "../pages/DemoPage";
import ModelsPage from "../pages/ModelsPage";
import DatasetsPage from "../pages/DatasetsPage";
import ResearchPage from "../pages/ResearchPage";
import SettingsPage from "../pages/SettingsPage";

export default function AppRoutes() {
  return (
    <Routes>
      <Route element={<MainLayout />}>
        <Route index element={<Navigate to="/overview" replace />} />
        <Route path="/overview" element={<OverviewPage />} />
        <Route path="/network-state" element={<NetworkStatePage />} />
        <Route path="/forecasting" element={<ForecastingPage />} />
        <Route path="/attack-analysis" element={<AttackAnalysisPage />} />
        <Route path="/explainability" element={<ExplainabilityPage />} />
        <Route path="/mitre" element={<MitrePage />} />
        <Route path="/generalization" element={<GeneralizationPage />} />
        <Route path="/mitigation" element={<MitigationPage />} />
        <Route path="/verification" element={<VerificationPage />} />
        <Route path="/demo" element={<DemoPage />} />
        <Route path="/models" element={<ModelsPage />} />
        <Route path="/datasets" element={<DatasetsPage />} />
        <Route path="/research" element={<ResearchPage />} />
        <Route path="/settings" element={<SettingsPage />} />
        <Route path="*" element={<Navigate to="/overview" replace />} />
      </Route>
    </Routes>
  );
}
