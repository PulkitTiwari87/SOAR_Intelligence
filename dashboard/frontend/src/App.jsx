import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom';
import { AuthProvider, useAuth } from './context/AuthContext';
import ProtectedRoute from './components/ProtectedRoute';
import Navbar from './components/Navbar';
import Sidebar from './components/Sidebar';
import Login from './pages/Login';
import CommandCenter from './pages/CommandCenter';
import IncidentResponse from './pages/IncidentResponse';
import AIIntelligence from './pages/AIIntelligence';
import PhishingAnalyzer from './pages/PhishingAnalyzer';
import VulnerabilityScanner from './pages/VulnerabilityScanner';
import NetworkTopology from './pages/NetworkTopology';
import Reports from './pages/Reports';
import SystemHealth from './pages/SystemHealth';
import AuditLog from './pages/AuditLog';
import SOARIntegration from './pages/SOARIntegration';
import Settings from './pages/Settings';

function AppLayout({ children }) {
  return (
    <div className="app-layout">
      <Sidebar />
      <div className="main-content">
        <Navbar />
        {children}
      </div>
    </div>
  );
}

function AppRoutes() {
  const { user, loading } = useAuth();

  if (loading) {
    return <div className="loading-container"><div className="spinner" /><span>Initializing SOAR...</span></div>;
  }

  return (
    <Routes>
      <Route path="/login" element={user ? <Navigate to="/dashboard" /> : <Login />} />

      <Route path="/dashboard" element={
        <ProtectedRoute><AppLayout><CommandCenter /></AppLayout></ProtectedRoute>
      } />
      <Route path="/incidents" element={
        <ProtectedRoute requiredRole="analyst"><AppLayout><IncidentResponse /></AppLayout></ProtectedRoute>
      } />
      <Route path="/ai-intelligence" element={
        <ProtectedRoute><AppLayout><AIIntelligence /></AppLayout></ProtectedRoute>
      } />
      <Route path="/phishing" element={
        <ProtectedRoute><AppLayout><PhishingAnalyzer /></AppLayout></ProtectedRoute>
      } />
      <Route path="/vulnerabilities" element={
        <ProtectedRoute><AppLayout><VulnerabilityScanner /></AppLayout></ProtectedRoute>
      } />
      <Route path="/network" element={
        <ProtectedRoute requiredRole="analyst"><AppLayout><NetworkTopology /></AppLayout></ProtectedRoute>
      } />
      <Route path="/reports" element={
        <ProtectedRoute><AppLayout><Reports /></AppLayout></ProtectedRoute>
      } />
      <Route path="/system" element={
        <ProtectedRoute><AppLayout><SystemHealth /></AppLayout></ProtectedRoute>
      } />
      <Route path="/audit" element={
        <ProtectedRoute requiredRole="analyst"><AppLayout><AuditLog /></AppLayout></ProtectedRoute>
      } />
      <Route path="/soar" element={
        <ProtectedRoute><AppLayout><SOARIntegration /></AppLayout></ProtectedRoute>
      } />
      <Route path="/settings" element={
        <ProtectedRoute><AppLayout><Settings /></AppLayout></ProtectedRoute>
      } />
      <Route path="*" element={<Navigate to="/dashboard" replace />} />
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
