import { useState } from 'react';
import { api, errMsg } from '../api';
import { useAuth } from '../auth';
import { Async, fmtDate, Header, Pager, Tabs, useLoad } from '../ui';

const ROLES = ['VIEWER', 'SOC_ANALYST', 'INCIDENT_RESPONDER', 'ADMIN'];

function Audit() {
  const [page, setPage] = useState(1);
  const [action, setAction] = useState('');
  const state = useLoad(async () => (await api.get('/system/audit', { params: { page, limit: 25, ...(action ? { action } : {}) } })).data, [page, action]);
  return (
    <div className="card">
      <div className="flex-between"><h3 className="section-title">Audit log</h3>
        <input className="input" style={{ maxWidth: 220 }} placeholder="Filter by action (e.g. login)" value={action} onChange={(e) => { setPage(1); setAction(e.target.value); }} aria-label="Action filter" /></div>
      <Async state={state} empty={(d) => d.logs.length === 0} emptyText="No audit entries match.">
        {(d) => (<>
          <div className="table-container"><table>
            <thead><tr><th>Time</th><th>Actor</th><th>Action</th><th>Target</th><th>Result</th><th>IP</th><th>Detail</th></tr></thead>
            <tbody>{d.logs.map((l) => (
              <tr key={l.id}><td style={{ whiteSpace: 'nowrap' }}>{fmtDate(l.timestamp)}</td><td>{l.actor}{l.actor_role ? ` (${l.actor_role.toLowerCase()})` : ''}</td><td>{l.action}</td>
                <td>{l.target_type ? `${l.target_type}/${String(l.target_id).slice(0, 12)}` : '—'}</td>
                <td><span className={`badge ${l.result === 'success' ? 'badge-resolved' : 'badge-critical'}`}>{l.result}</span></td><td>{l.ip_address || '—'}</td>
                <td style={{ fontSize: 11, maxWidth: 240, wordBreak: 'break-all' }}>{Object.keys(l.data || {}).length ? JSON.stringify(l.data) : ''}</td></tr>
            ))}</tbody></table></div>
          <Pager page={d.pagination.page} pages={d.pagination.pages} onPage={setPage} />
        </>)}
      </Async>
    </div>
  );
}

function Users() {
  const [form, setForm] = useState({ username: '', password: '', role: 'VIEWER' });
  const [msg, setMsg] = useState(null);
  const state = useLoad(async () => (await api.get('/users')).data.users, []);
  const run = async (fn, ok) => { setMsg(null); try { await fn(); setMsg({ ok: true, text: ok }); state.reload(); } catch (e) { setMsg({ ok: false, text: errMsg(e) }); } };
  return (
    <>
      {msg && <div className="card" role="status" style={{ borderColor: msg.ok ? 'var(--success)' : 'var(--danger)', marginBottom: 12 }}>{msg.text}</div>}
      <form className="card" style={{ marginBottom: 16 }} aria-label="Create user"
        onSubmit={(e) => { e.preventDefault(); run(async () => { await api.post('/users', form); setForm({ username: '', password: '', role: 'VIEWER' }); }, 'User created'); }}>
        <h3 className="section-title">Create user</h3>
        <div className="grid-4" style={{ gap: 8 }}>
          <input className="input" placeholder="username" value={form.username} required minLength={3} maxLength={64} onChange={(e) => setForm({ ...form, username: e.target.value })} aria-label="Username" />
          <input className="input" type="password" placeholder="password (min 10)" value={form.password} required minLength={10} maxLength={72} autoComplete="new-password" onChange={(e) => setForm({ ...form, password: e.target.value })} aria-label="Password" />
          <select className="input" value={form.role} onChange={(e) => setForm({ ...form, role: e.target.value })} aria-label="Role">{ROLES.map((r) => <option key={r}>{r}</option>)}</select>
          <button className="btn btn-primary btn-sm">Create</button>
        </div>
      </form>
      <div className="card"><h3 className="section-title">Users</h3>
        <Async state={state}>{(rows) => (
          <table><thead><tr><th>User</th><th>Role</th><th>Active</th><th>Last login</th><th /></tr></thead>
            <tbody>{rows.map((u) => (
              <tr key={u.id}><td>{u.username}</td>
                <td><select className="input" value={u.role} aria-label={`Role of ${u.username}`} onChange={(e) => run(() => api.patch(`/users/${u.id}`, { role: e.target.value }), 'Role updated')}>{ROLES.map((r) => <option key={r}>{r}</option>)}</select></td>
                <td>{u.is_active ? 'yes' : 'disabled'}</td><td>{fmtDate(u.last_login)}</td>
                <td><button className="btn btn-ghost btn-sm" onClick={() => run(() => api.patch(`/users/${u.id}`, { is_active: !u.is_active }), u.is_active ? 'User disabled' : 'User enabled')}>{u.is_active ? 'Disable' : 'Enable'}</button></td></tr>
            ))}</tbody></table>)}</Async></div>
    </>
  );
}

function Account() {
  const { user } = useAuth();
  const [form, setForm] = useState({ current_password: '', new_password: '' });
  const [msg, setMsg] = useState(null);
  const submit = async (e) => {
    e.preventDefault(); setMsg(null);
    try { await api.put('/auth/profile', form); setForm({ current_password: '', new_password: '' }); setMsg({ ok: true, text: 'Password changed' }); }
    catch (err) { setMsg({ ok: false, text: errMsg(err) }); }
  };
  return (
    <form className="card" onSubmit={submit} style={{ maxWidth: 460 }} aria-label="Change password">
      <h3 className="section-title">My account</h3>
      <p style={{ color: 'var(--text-secondary)', marginBottom: 12 }}>{user.username} · {user.role.replace('_', ' ').toLowerCase()}</p>
      <input className="input" style={{ marginBottom: 8 }} type="password" placeholder="Current password" autoComplete="current-password" value={form.current_password} required onChange={(e) => setForm({ ...form, current_password: e.target.value })} aria-label="Current password" />
      <input className="input" type="password" placeholder="New password (min 10 characters)" autoComplete="new-password" value={form.new_password} required minLength={10} maxLength={72} onChange={(e) => setForm({ ...form, new_password: e.target.value })} aria-label="New password" />
      {msg && <p role="status" style={{ color: msg.ok ? 'var(--success)' : 'var(--danger)', marginTop: 8 }}>{msg.text}</p>}
      <button className="btn btn-primary btn-sm" style={{ marginTop: 10 }}>Change password</button>
    </form>
  );
}

export default function Admin() {
  const { can } = useAuth();
  const tabs = ['My account', ...(can('audit:view') ? ['Audit log'] : []), ...(can('user:admin') ? ['Users'] : [])];
  const [tab, setTab] = useState('My account');
  return (
    <div className="page-container">
      <Header title="Administration" sub="Account, audit trail and user management (by permission)" />
      <Tabs tabs={tabs} active={tab} onChange={setTab} />
      {tab === 'My account' && <Account />}
      {tab === 'Audit log' && <Audit />}
      {tab === 'Users' && <Users />}
    </div>
  );
}
