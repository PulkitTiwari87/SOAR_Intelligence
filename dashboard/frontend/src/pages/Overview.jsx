import { Link } from 'react-router-dom';
import { Bar as RBar, BarChart, Cell, Pie, PieChart, ResponsiveContainer, Tooltip, XAxis, YAxis } from 'recharts';
import { AlertTriangle, Bot, Clock, ClipboardCheck, Flame, ShieldAlert, Timer } from 'lucide-react';
import { api } from '../api';
import { Async, fmtDate, fmtDuration, Header, SEV_COLOR, SevBadge, StatusBadge, useLoad } from '../ui';

function Stat({ label, value, icon: Icon, color = 'blue', hint }) {
  return (
    <div className={`stat-card ${color}`} title={hint}>
      <div className={`stat-icon ${color}`}><Icon size={22} /></div>
      <div className="stat-info"><h3>{label}</h3><div className="stat-value">{value}</div></div>
    </div>
  );
}

export default function Overview() {
  const state = useLoad(async () => {
    const [stats, recent] = await Promise.all([api.get('/incidents/stats'), api.get('/incidents?limit=8')]);
    return { stats: stats.data, recent: recent.data.incidents };
  });
  return (
    <div className="page-container">
      <Header title="Overview" sub="Live security operations picture, computed from stored incidents" />
      <Async state={state}>
        {({ stats: s, recent }) => (
          <>
            {s.pending_approvals > 0 && (
              <Link to="/approvals" className="card" style={{ display: 'block', borderColor: 'var(--warning)', marginBottom: 16 }}>
                <strong>{s.pending_approvals}</strong> response action(s) are waiting for a human decision →
              </Link>
            )}
            <div className="grid-3" style={{ marginBottom: 16 }}>
              <Stat label="Active incidents" value={s.active} icon={ShieldAlert} color="blue" />
              <Stat label="Critical (open)" value={s.critical} icon={Flame} color="red" />
              <Stat label="Alerts today" value={s.alerts_today} icon={AlertTriangle} color="yellow" hint="Events of severity medium or higher received today (UTC)" />
            </div>
            <div className="grid-3" style={{ marginBottom: 24 }}>
              <Stat label="Automated responses" value={s.automated_responses} icon={Bot} color="green" hint="Playbook steps that succeeded without a human decision" />
              <Stat label="MTTD" value={fmtDuration(s.mttd_seconds)} icon={Timer} color="blue" hint={s.mttd_definition} />
              <Stat label="MTTR" value={fmtDuration(s.mttr_seconds)} icon={Clock} color="blue" hint={s.mttr_definition} />
            </div>
            <div className="grid-2" style={{ marginBottom: 24 }}>
              <div className="card">
                <h3 className="section-title">Incidents by severity</h3>
                {s.total === 0 ? <p style={{ color: 'var(--text-muted)' }}>No incidents yet.</p> : (
                  <ResponsiveContainer width="100%" height={220}>
                    <PieChart>
                      <Pie data={Object.entries(s.by_severity).map(([name, value]) => ({ name, value }))} dataKey="value" nameKey="name" outerRadius={80} label>
                        {Object.keys(s.by_severity).map((k) => <Cell key={k} fill={SEV_COLOR[k]} />)}
                      </Pie>
                      <Tooltip />
                    </PieChart>
                  </ResponsiveContainer>
                )}
              </div>
              <div className="card">
                <h3 className="section-title">Top ATT&amp;CK techniques</h3>
                {s.top_mitre.length === 0 ? <p style={{ color: 'var(--text-muted)' }}>No techniques mapped yet.</p> : (
                  <ResponsiveContainer width="100%" height={220}>
                    <BarChart data={s.top_mitre} layout="vertical" margin={{ left: 30 }}>
                      <XAxis type="number" allowDecimals={false} stroke="#64748b" />
                      <YAxis type="category" dataKey="id" stroke="#64748b" width={70} />
                      <Tooltip />
                      <RBar dataKey="count" fill="#3b82f6" />
                    </BarChart>
                  </ResponsiveContainer>
                )}
              </div>
            </div>
            <div className="card">
              <div className="flex-between"><h3 className="section-title">Latest incidents</h3><Link to="/incidents">View all →</Link></div>
              {recent.length === 0 ? <p style={{ color: 'var(--text-muted)' }}>No incidents yet. Send events to <code>/api/events</code> or run <code>python -m soar.cli simulate brute_force</code>.</p> : (
                <div className="table-container"><table>
                  <thead><tr><th>ID</th><th>Title</th><th>Severity</th><th>Status</th><th>Risk</th><th>Detected</th></tr></thead>
                  <tbody>{recent.map((i) => (
                    <tr key={i.id}>
                      <td><Link to={`/incidents/${i.number}`}>{i.number}</Link></td><td>{i.title}</td>
                      <td><SevBadge level={i.severity} /></td><td><StatusBadge status={i.status} /></td>
                      <td>{i.risk_score}</td><td>{fmtDate(i.detected_at)}</td>
                    </tr>
                  ))}</tbody>
                </table></div>
              )}
            </div>
            <p style={{ color: 'var(--text-muted)', fontSize: 12, marginTop: 12 }}><ClipboardCheck size={12} /> Figures are computed from the incident database; “—” means there is nothing to average yet.</p>
          </>
        )}
      </Async>
    </div>
  );
}
