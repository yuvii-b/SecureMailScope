import { Route, Routes } from "react-router-dom";
import { Layout } from "./components/Layout";
import { CapturesListPage } from "./pages/CapturesListPage";
import { CaptureDashboardPage } from "./pages/CaptureDashboardPage";
import { SessionDetailPage } from "./pages/SessionDetailPage";

export default function App() {
  return (
    <Layout>
      <Routes>
        <Route path="/" element={<CapturesListPage />} />
        <Route path="/captures/:captureId" element={<CaptureDashboardPage />} />
        <Route path="/captures/:captureId/sessions/:sessionId" element={<SessionDetailPage />} />
      </Routes>
    </Layout>
  );
}
