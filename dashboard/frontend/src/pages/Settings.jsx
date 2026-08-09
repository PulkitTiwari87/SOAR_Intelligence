import { useState } from 'react';
import axios from 'axios';
import { useAuth } from '../context/AuthContext';
import { API_URL } from '../config';
import { User, Lock, Save, ShieldCheck, UserCheck } from 'lucide-react';

const API = API_URL;

export default function Settings() {
  const { user, updateUser } = useAuth();
  const [username, setUsername] = useState(user?.username || '');
  const [newPassword, setNewPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [status, setStatus] = useState({ type: '', msg: '' });
  const [loading, setLoading] = useState(false);

  const handleSubmit = async (e) => {
    e.preventDefault();
    if (newPassword && newPassword !== confirmPassword) {
      setStatus({ type: 'error', msg: 'Passwords do not match.' });
      return;
    }

    setLoading(true);
    setStatus({ type: '', msg: '' });

    try {
      const res = await axios.put(`${API}/auth/profile`, { username, newPassword });
      updateUser(res.data.user);
      setStatus({ type: 'success', msg: 'Profile updated successfully!' });
      setNewPassword('');
      setConfirmPassword('');
    } catch (err) {
      setStatus({ type: 'error', msg: err.response?.data?.error || 'Update failed.' });
    } finally {
      setLoading(false);
    }
  };

  const handleSuggestUsername = () => {
    const rolePrefix = user?.role === 'analyst' ? 'analyst-' : 'user-';
    const random = Math.floor(1000 + Math.random() * 9000);
    setUsername(`${rolePrefix}${random}`);
  };

  const isAnalyst = user?.role === 'analyst';

  return (
    <div className="page-container">
      <div className="page-header">
        <h1>Account Settings</h1>
        <p>Manage your profile and security credentials</p>
      </div>

      <div className="card" style={{ maxWidth: '600px', margin: '0 auto' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '15px', marginBottom: '30px', padding: '15px', background: 'var(--bg-secondary)', borderRadius: 'var(--radius-md)' }}>
          <div style={{ width: '50px', height: '50px', borderRadius: '50%', background: 'var(--accent)', display: 'flex', alignItems: 'center', justifyItems: 'center', justifyContent: 'center' }}>
             {isAnalyst ? <ShieldCheck size={24} color="white" /> : <UserCheck size={24} color="white" />}
          </div>
          <div>
            <div style={{ fontWeight: 700, fontSize: '1.1rem' }}>{user?.username}</div>
            <div style={{ fontSize: '0.85rem', color: 'var(--text-muted)', textTransform: 'capitalize' }}>
               Role: <strong>{user?.role}</strong>
            </div>
          </div>
        </div>

        <form onSubmit={handleSubmit} style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>
          <div>
            <label style={{ display: 'block', fontSize: '0.85rem', fontWeight: 600, marginBottom: '8px', color: 'var(--text-secondary)' }}>
              Username
            </label>
            <div style={{ position: 'relative' }}>
              <User size={18} style={{ position: 'absolute', left: '12px', top: '50%', transform: 'translateY(-50%)', color: 'var(--text-muted)' }} />
              <input
                type="text"
                className="input-field"
                style={{ paddingLeft: '40px' }}
                value={username}
                onChange={(e) => setUsername(e.target.value)}
                placeholder="New username"
                required
              />
              <button 
                type="button" 
                onClick={handleSuggestUsername}
                style={{
                  position: 'absolute',
                  right: '8px',
                  top: '50%',
                  transform: 'translateY(-50%)',
                  fontSize: '0.7rem',
                  padding: '4px 8px',
                  background: 'var(--bg-secondary)',
                  border: '1px solid var(--glass-border)',
                  borderRadius: '4px',
                  color: 'var(--text-secondary)',
                  cursor: 'pointer'
                }}
              >
                Suggest Role-Based
              </button>
            </div>
          </div>

          <div style={{ borderTop: '1px solid var(--glass-border)', paddingTop: '20px', marginTop: '10px' }}>
            <label style={{ display: 'block', fontSize: '0.85rem', fontWeight: 600, marginBottom: '8px', color: 'var(--text-secondary)' }}>
              Change Password (Leave blank to keep current)
            </label>
            <div style={{ display: 'flex', flexDirection: 'column', gap: '15px' }}>
              <div style={{ position: 'relative' }}>
                <Lock size={18} style={{ position: 'absolute', left: '12px', top: '50%', transform: 'translateY(-50%)', color: 'var(--text-muted)' }} />
                <input
                  type="password"
                  className="input-field"
                  style={{ paddingLeft: '40px' }}
                  value={newPassword}
                  onChange={(e) => setNewPassword(e.target.value)}
                  placeholder="New password"
                />
              </div>
              <div style={{ position: 'relative' }}>
                <Lock size={18} style={{ position: 'absolute', left: '12px', top: '50%', transform: 'translateY(-50%)', color: 'var(--text-muted)' }} />
                <input
                  type="password"
                  className="input-field"
                  style={{ paddingLeft: '40px' }}
                  value={confirmPassword}
                  onChange={(e) => setConfirmPassword(e.target.value)}
                  placeholder="Confirm new password"
                />
              </div>
            </div>
          </div>

          {status.msg && (
            <div style={{ 
              padding: '12px', 
              borderRadius: 'var(--radius-md)', 
              fontSize: '0.9rem',
              background: status.type === 'success' ? 'rgba(34, 197, 94, 0.1)' : 'rgba(239, 68, 68, 0.1)',
              color: status.type === 'success' ? 'var(--success)' : 'var(--danger)',
              border: `1px solid ${status.type === 'success' ? 'var(--success)' : 'var(--danger)'}40`
            }}>
              {status.msg}
            </div>
          )}

          <button type="submit" className="btn btn-primary" disabled={loading} style={{ marginTop: '10px' }}>
            <Save size={18} style={{ verticalAlign: 'middle', marginRight: '8px' }} />
            {loading ? 'Updating...' : 'Save Changes'}
          </button>
        </form>
      </div>
    </div>
  );
}
