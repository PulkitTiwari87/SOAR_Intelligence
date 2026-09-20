import { useState } from 'react';
import { Link } from 'react-router-dom';
import { api } from '../api';
import { Async, fmtDate, Header, StatusBadge, Tabs, useLoad } from '../ui';

const RISK = { low: 'badge-resolved', medium: 'badge-medium', high: 'badge-critical' };

export default function Playbooks() {
  const [tab, setTab] = useState('playbooks');
  const defs = useLoad(async () => (await api.get('/playbooks')).data, []);
  const execs = useLoad(async () => (await api.get('/executions?limit=50')).data.executions, [tab]);
  const stats = useLoad(async () => (await api.get('/playbooks/stats')).data, [tab]);

  return (
    <div className="page-container">
      <Header title="Playbooks" sub="Trigger → conditions → steps → approval → execution → verification → rollback" />
      <Tabs tabs={['playbooks', 'executions', 'effectiveness']} active={tab} onChange={setTab} />
      {tab === 'playbooks' && (
        <Async state={defs}>
          {(d) => (
            <>
              {d.playbooks.map((p) => (
                <div className="card" key={p.name} style={{ marginBottom: 12 }}>
                  <div className="flex-between"><h3>{p.name} <span style={{ color: 'var(--text-muted)', fontSize: 12 }}>v{p.version}</span></h3>
                    <span className={`badge ${p.enabled ? 'badge-resolved' : 'badge-info'}`}>{p.enabled ? 'enabled' : 'disabled'}</span></div>
                  <p style={{ color: 'var(--text-secondary)', margin: '4px 0 10px' }}>{p.description}</p>
                  <p style={{ fontSize: 12 }}><strong>Trigger:</strong> {p.trigger && Object.keys(p.trigger).length ? JSON.stringify(p.trigger) : 'manual only'} ·{' '}
                    <strong>Conditions:</strong> {p.conditions.length ? p.conditions.map((c) => `${c.field} ${c.op || 'eq'} ${c.value}`).join('; ') : 'none'}</p>
                  <ol style={{ marginLeft: 18, marginTop: 8 }}>{p.steps.map((s) => (
                    <li key={s.id}><strong>{s.action}</strong> <span className={`badge ${RISK[s.risk]}`}>{s.risk}</span>{' '}
                      {s.approval === 'required' && <span className="badge badge-medium">approval required</span>}
                      {s.params && <code style={{ fontSize: 11, marginLeft: 6 }}>{JSON.stringify(s.params)}</code>}</li>))}</ol>
                </div>
              ))}
              <div className="card">
                <h3 className="section-title">Available actions</h3>
                <table><thead><tr><th>Action</th><th>Risk</th><th>Reversible</th><th>What it does</th></tr></thead>
                  <tbody>{d.actions.map((a) => (<tr key={a.name}><td>{a.name}</td><td><span className={`badge ${RISK[a.risk]}`}>{a.risk}</span></td><td>{a.reversible ? 'yes' : 'no'}</td><td>{a.description}</td></tr>))}</tbody></table>
                <p style={{ color: 'var(--text-muted)', fontSize: 12, marginTop: 8 }}>Low-risk actions run automatically. Higher-risk actions wait for approval (see <code>AUTO_EXECUTE_MAX_RISK</code>); high-risk always do. Actions that need an unconfigured connector are reported as “skipped”, never as success.</p>
              </div>
            </>
          )}
        </Async>
      )}
      {tab === 'executions' && (
        <div className="card"><Async state={execs} empty={(d) => d.length === 0} emptyText="No playbook has run yet.">
          {(rows) => rows.map((x) => (
            <div key={x.id} style={{ marginBottom: 14 }}>
              <div className="flex-gap"><strong>{x.playbook}</strong> <StatusBadge status={x.status} />
                <Link to={`/incidents/${x.incident_number}`}>{x.incident_number}</Link>
                <span style={{ color: 'var(--text-muted)', fontSize: 12 }}>{fmtDate(x.created_at)} · {x.requested_by}</span></div>
              <div className="flex-gap" style={{ flexWrap: 'wrap', marginTop: 4 }}>{x.steps.map((s) => (
                <span key={s.id} title={s.result?.detail}><StatusBadge status={s.status} /> {s.action}{s.verified === true ? ' ✓' : s.verified === false ? ' ✗' : ''}</span>))}</div>
              {x.error && <p style={{ color: 'var(--danger)', fontSize: 12 }}>{x.error}</p>}
            </div>
          ))}
        </Async></div>
      )}
      {tab === 'effectiveness' && (
        <Async state={stats}>
          {(s) => (
            <div className="card">
              <p>{s.totals.executions} execution(s), {s.totals.steps} step(s), {s.totals.approvals} approval(s). {s.approvals.avg_seconds_to_decision !== null && `Average time to decision: ${s.approvals.avg_seconds_to_decision}s.`}</p>
              <table><thead><tr><th>Action</th><th>Runs</th><th>Succeeded</th><th>Skipped</th><th>Failed</th><th>Verified</th></tr></thead>
                <tbody>{Object.entries(s.actions).map(([k, a]) => (<tr key={k}><td>{k}</td><td>{a.runs}</td><td>{a.succeeded || 0}</td><td>{a.skipped || 0}</td><td>{a.failed || 0}</td><td>{a.verified || 0}</td></tr>))}</tbody></table>
              {s.recommendations.map((r, i) => <p key={i} style={{ marginTop: 8, color: 'var(--text-secondary)' }}>• {r}</p>)}
            </div>
          )}
        </Async>
      )}
    </div>
  );
}
