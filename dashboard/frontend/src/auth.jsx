import { createContext, useCallback, useContext, useEffect, useMemo, useState } from 'react';
import { Navigate } from 'react-router-dom';
import { api } from './api';

const AuthContext = createContext(null);

export function AuthProvider({ children }) {
  const [user, setUser] = useState(null);
  const [permissions, setPermissions] = useState([]);
  const [loading, setLoading] = useState(true);

  // Fetch the session after login (called from an event handler).
  const load = useCallback(async () => {
    try {
      const { data } = await api.get('/auth/me');
      setUser(data.user);
      setPermissions(data.permissions);
      return true;
    } catch {
      setUser(null);
      setPermissions([]);
      return false;
    }
  }, []);

  useEffect(() => {
    let alive = true;
    api.get('/auth/me')
      .then(({ data }) => { if (alive) { setUser(data.user); setPermissions(data.permissions); } })
      .catch(() => { if (alive) { setUser(null); setPermissions([]); } })
      .finally(() => { if (alive) setLoading(false); });
    const onUnauthorized = () => { setUser(null); setPermissions([]); };
    window.addEventListener('soar:unauthorized', onUnauthorized);
    return () => { alive = false; window.removeEventListener('soar:unauthorized', onUnauthorized); };
  }, []);

  const value = useMemo(() => ({
    user, loading, permissions,
    can: (perm) => permissions.includes(perm),
    login: async (username, password) => {
      await api.post('/auth/login', { username, password });
      // The password was accepted, but without a usable session cookie (e.g. COOKIE_SECURE=true over
      // plain HTTP) the follow-up request is anonymous. Say so instead of leaving the form stuck.
      if (!(await load())) {
        throw new Error('Signed in, but the browser did not keep the session. If the UI is served over plain HTTP, set COOKIE_SECURE=false.');
      }
    },
    logout: async () => {
      try { await api.post('/auth/logout'); } finally { setUser(null); setPermissions([]); }
    },
  }), [user, loading, permissions, load]);

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

// eslint-disable-next-line react-refresh/only-export-components
export const useAuth = () => useContext(AuthContext);

/** Route guard: needs a session, and optionally a permission (the API enforces it as well). */
export function RequireAuth({ perm, children }) {
  const { user, loading, can } = useAuth();
  if (loading) return <div className="loading-container"><div className="spinner" /><span>Loading…</span></div>;
  if (!user) return <Navigate to="/login" replace />;
  if (perm && !can(perm)) {
    return (
      <div className="page-container">
        <div className="card" style={{ textAlign: 'center', padding: 48 }}>
          <h2 style={{ color: 'var(--danger)', marginBottom: 8 }}>Access denied</h2>
          <p style={{ color: 'var(--text-secondary)' }}>Your role does not include the <code>{perm}</code> permission.</p>
        </div>
      </div>
    );
  }
  return children;
}
