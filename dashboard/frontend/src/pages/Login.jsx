import { useState } from 'react';
import { Activity } from 'lucide-react';
import { errMsg } from '../api';
import { useAuth } from '../auth';

export default function Login() {
  const { login } = useAuth();
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);

  const submit = async (e) => {
    e.preventDefault();
    setBusy(true);
    setError('');
    try {
      await login(username.trim(), password);
    } catch (err) {
      setError(errMsg(err));
      setBusy(false);
    }
  };

  return (
    <div className="login-page">
      <form className="login-card" onSubmit={submit} aria-label="Sign in">
        <div style={{ textAlign: 'center', marginBottom: 20 }}>
          <Activity size={36} color="var(--accent)" />
          <h1 style={{ fontSize: 22, marginTop: 8 }}>SOAR Intelligence</h1>
          <p style={{ color: 'var(--text-secondary)' }}>Sign in to continue</p>
        </div>
        {error && <div className="login-error" role="alert">{error}</div>}
        <label htmlFor="u" style={{ fontSize: 12, color: 'var(--text-secondary)' }}>Username</label>
        <input id="u" className="input" autoComplete="username" autoFocus value={username} onChange={(e) => setUsername(e.target.value)} required maxLength={64} />
        <label htmlFor="p" style={{ fontSize: 12, color: 'var(--text-secondary)', marginTop: 12, display: 'block' }}>Password</label>
        <input id="p" className="input" type="password" autoComplete="current-password" value={password} onChange={(e) => setPassword(e.target.value)} required maxLength={256} />
        <button className="btn btn-primary" style={{ width: '100%', marginTop: 20 }} disabled={busy}>{busy ? 'Signing in…' : 'Sign in'}</button>
        <p style={{ color: 'var(--text-muted)', fontSize: 12, marginTop: 16, textAlign: 'center' }}>
          Accounts are created by an administrator. See the README for creating the first one.
        </p>
      </form>
    </div>
  );
}
