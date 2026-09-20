import { useState } from 'react';
import { Link } from 'react-router-dom';
import { api } from '../api';
import { Async, fmtDate, Header, Pager, SevBadge, StatusBadge, useLoad } from '../ui';

const STATUSES = ['new', 'investigating', 'awaiting_approval', 'responding', 'monitoring', 'resolved', 'false_positive', 'closed'];
const EMPTY = { severity: '', status: '', source: '', mitre: '', asset: '', q: '', date_from: '', date_to: '' };

export default function Incidents() {
  const [form, setForm] = useState(EMPTY);
  const [applied, setApplied] = useState(EMPTY);
  const [page, setPage] = useState(1);
  const state = useLoad(async () => {
    const params = { page, limit: 15 };
    Object.entries(applied).forEach(([k, v]) => { if (v) params[k] = k.startsWith('date') ? new Date(v).toISOString() : v; });
    return (await api.get('/incidents', { params })).data;
  }, [applied, page]);

  const set = (k) => (e) => setForm({ ...form, [k]: e.target.value });
  const submit = (e) => { e.preventDefault(); setPage(1); setApplied(form); };
  const reset = () => { setForm(EMPTY); setApplied(EMPTY); setPage(1); };

  return (
    <div className="page-container">
      <Header title="Incidents" sub="Correlated alerts, scored and triaged" />
      <form className="card" onSubmit={submit} style={{ marginBottom: 16 }} aria-label="Filter incidents">
        <div className="grid-4" style={{ gap: 10 }}>
          <input className="input" placeholder="Search title or INC-…" value={form.q} onChange={set('q')} aria-label="Search" />
          <select className="input" value={form.severity} onChange={set('severity')} aria-label="Severity">
            <option value="">Any severity</option>
            {[4, 3, 2, 1].map((n) => <option key={n} value={n}>{['', 'low', 'medium', 'high', 'critical'][n]}</option>)}
          </select>
          <select className="input" value={form.status} onChange={set('status')} aria-label="Status">
            <option value="">Any status</option>
            {STATUSES.map((s) => <option key={s} value={s}>{s.replace(/_/g, ' ')}</option>)}
          </select>
          <select className="input" value={form.source} onChange={set('source')} aria-label="Source">
            <option value="">Any source</option>
            {['wazuh', 'syslog', 'network', 'email', 'generic'].map((s) => <option key={s}>{s}</option>)}
          </select>
          <input className="input" placeholder="MITRE technique (T1110)" value={form.mitre} onChange={set('mitre')} aria-label="MITRE technique" />
          <input className="input" placeholder="Asset (host or IP)" value={form.asset} onChange={set('asset')} aria-label="Asset" />
          <input className="input" type="date" value={form.date_from} onChange={set('date_from')} aria-label="From date" />
          <input className="input" type="date" value={form.date_to} onChange={set('date_to')} aria-label="To date" />
        </div>
        <div className="flex-gap" style={{ marginTop: 12 }}>
          <button className="btn btn-primary btn-sm">Apply filters</button>
          <button type="button" className="btn btn-ghost btn-sm" onClick={reset}>Reset</button>
        </div>
      </form>
      <div className="card">
        <Async state={state} empty={(d) => d.incidents.length === 0} emptyText="No incidents match these filters.">
          {(d) => (
            <>
              <div className="table-container"><table>
                <thead><tr><th>ID</th><th>Title</th><th>Sev.</th><th>Status</th><th>Risk</th><th>Source</th><th>Host / IP</th><th>Events</th><th>MITRE</th><th>Detected</th></tr></thead>
                <tbody>{d.incidents.map((i) => (
                  <tr key={i.id}>
                    <td><Link to={`/incidents/${i.number}`}>{i.number}</Link></td>
                    <td style={{ maxWidth: 280 }}>{i.title}</td>
                    <td><SevBadge level={i.severity} /></td><td><StatusBadge status={i.status} /></td>
                    <td>{i.risk_score}</td><td>{i.source}</td><td>{i.primary_host || i.primary_source_ip || '—'}</td>
                    <td>{i.event_count}</td><td>{i.mitre.join(', ') || '—'}</td><td>{fmtDate(i.detected_at)}</td>
                  </tr>
                ))}</tbody>
              </table></div>
              <p style={{ color: 'var(--text-muted)', fontSize: 12, marginTop: 8 }}>{d.pagination.total} incident(s)</p>
              <Pager page={d.pagination.page} pages={d.pagination.pages} onPage={setPage} />
            </>
          )}
        </Async>
      </div>
    </div>
  );
}
