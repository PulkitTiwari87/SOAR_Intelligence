import { Navigate } from 'react-router-dom';
import { useAuth } from '../context/AuthContext';

export default function ProtectedRoute({ children, requiredRole }) {
  const { user, loading } = useAuth();

  if (loading) {
    return <div className="loading-container"><div className="spinner" /><span>Loading...</span></div>;
  }

  if (!user) return <Navigate to="/login" replace />;

  if (requiredRole && user.role !== requiredRole) {
    return (
      <div className="page-container">
        <div className="card" style={{ textAlign: 'center', padding: '60px' }}>
          <h2 style={{ color: 'var(--danger)', marginBottom: '12px' }}>Access Denied</h2>
          <p style={{ color: 'var(--text-secondary)' }}>This page requires <strong>{requiredRole}</strong> privileges.</p>
        </div>
      </div>
    );
  }

  return children;
}
