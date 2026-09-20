import { BrowserRouter, Navigate, Route, Routes } from 'react-router-dom';
import { AuthProvider, RequireAuth, useAuth } from './auth';
import Layout from './Layout';
import Login from './pages/Login';
import Overview from './pages/Overview';
import Incidents from './pages/Incidents';
import IncidentDetail from './pages/IncidentDetail';
import Approvals from './pages/Approvals';
import Intel from './pages/Intel';
import Assets from './pages/Assets';
import Playbooks from './pages/Playbooks';
import AIModels from './pages/AIModels';
import System from './pages/System';
import Admin from './pages/Admin';

function AppRoutes() {
  const { user, loading } = useAuth();
  if (loading) return <div className="loading-container"><div className="spinner" /><span>Loading…</span></div>;
  return (
    <Routes>
      <Route path="/login" element={user ? <Navigate to="/" replace /> : <Login />} />
      <Route element={<RequireAuth><Layout /></RequireAuth>}>
        <Route index element={<Overview />} />
        <Route path="incidents" element={<Incidents />} />
        <Route path="incidents/:id" element={<IncidentDetail />} />
        <Route path="approvals" element={<Approvals />} />
        <Route path="intel" element={<Intel />} />
        <Route path="assets" element={<Assets />} />
        <Route path="playbooks" element={<Playbooks />} />
        <Route path="ai" element={<AIModels />} />
        <Route path="system" element={<System />} />
        <Route path="admin" element={<Admin />} />
        <Route path="*" element={<Navigate to="/" replace />} />
      </Route>
    </Routes>
  );
}

export default function App() {
  return (
    <BrowserRouter>
      <AuthProvider>
        <AppRoutes />
      </AuthProvider>
    </BrowserRouter>
  );
}
