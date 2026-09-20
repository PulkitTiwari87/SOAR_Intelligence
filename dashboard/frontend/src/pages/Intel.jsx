import { useState } from 'react';
import { Link } from 'react-router-dom';
import { api, errMsg } from '../api';
import { useAuth } from '../auth';
import { Async, fmtDate, Header, StatusBadge, useLoad } from '../ui';

const VERDICT_STATUS = { malicious: 'failed', suspicious: 'pending', benign: 'succeeded', unknown: 'skipped', not_enriched: 'skipped' };

export default function Intel() {
  const { can } = useAuth();
  const [verdict, setVerdict] = useState('');
  const [form, setForm] = useState({ type: 'ip', value: '' });
  const [result, setResult] = useState(null);
  const [error, setError] = useState('');
  const state = useLoad(async () => (await api.get('/intel/iocs', { params: verdict ? { verdict } : {} })).data.iocs, [verdict]);
  const integ = useLoad(async () => (await api.get('/system/integrations')).data.integrations.find((i) => i.name === 'misp'), []);

  const enrich = async (e) => {
    e.preventDefault(); setError(''); setResult(null);
    try { setResult((await api.post('/intel/enrich', { ...form, value: form.value.trim(), force: true })).data); state.reload(); }
    catch (err) { setError(errMsg(err)); }
  };

  return (
    <div className="page-container">
      <Header title="Threat intelligence" sub="Indicators extracted from incidents and their enrichment results">
        <span className="badge badge-info">MISP: {integ.data?.status || '…'}</span>
      </Header>
      <div className="card" style={{ marginBottom: 16 }}>
        <p style={{ color: 'var(--text-secondary)', fontSize: 13 }}>
          Providers: private/reserved-address scope (built in), local feed files in <code>data/intel/*.txt</code>, and MISP when configured.
          <strong> “unknown” means no provider had data. It is treated as missing evidence, never as safe.</strong>
        </p>
        {can('analyze:adhoc') && (
          <form onSubmit={enrich} className="flex-gap" style={{ marginTop: 12, flexWrap: 'wrap' }} aria-label="Enrich an indicator">
            <select className="input" style={{ maxWidth: 120 }} value={form.type} onChange={(e) => setForm({ ...form, type: e.target.value })} aria-label="Type">
              {['ip', 'domain', 'url', 'hash'].map((t) => <option key={t}>{t}</option>)}
            </select>
            <input className="input" style={{ flex: 1, minWidth: 220 }} placeholder="Indicator value" value={form.value} required maxLength={1000}
              onChange={(e) => setForm({ ...form, value: e.target.value })} aria-label="Value" />
            <button className="btn btn-primary btn-sm">Enrich now</button>
          </form>
        )}
        {error && <p role="alert" style={{ color: 'var(--danger)', marginTop: 8 }}>{error}</p>}
        {result && (
          <div style={{ marginTop: 12 }}>
            <strong>{result.ioc.value}</strong>
            <table><tbody>{result.results.map((r) => (
              <tr key={r.provider}><td>{r.provider}</td><td><StatusBadge status={VERDICT_STATUS[r.verdict]} /> {r.verdict}</td>
                <td>score {r.score} · confidence {r.confidence}</td><td style={{ fontSize: 12 }}>{JSON.stringify(r.context)}</td></tr>
            ))}</tbody></table>
          </div>
        )}
      </div>
      <div className="card">
        <div className="flex-between"><h3 className="section-title">Indicators</h3>
          <select className="input" style={{ maxWidth: 180 }} value={verdict} onChange={(e) => setVerdict(e.target.value)} aria-label="Verdict filter">
            <option value="">Any verdict</option>
            {['malicious', 'suspicious', 'benign', 'unknown', 'not_enriched'].map((v) => <option key={v} value={v}>{v.replace('_', ' ')}</option>)}
          </select>
        </div>
        <Async state={state} empty={(d) => d.length === 0} emptyText="No indicators yet. They appear when incidents contain public IPs, domains, URLs or file hashes.">
          {(rows) => (
            <div className="table-container"><table>
              <thead><tr><th>Type</th><th>Value</th><th>Verdict</th><th>Score</th><th>Provider</th><th>Incidents</th><th>Last seen</th></tr></thead>
              <tbody>{rows.map((o) => (
                <tr key={o.id}><td>{o.type}</td><td style={{ fontFamily: 'monospace', wordBreak: 'break-all' }}>{o.value}</td>
                  <td><StatusBadge status={VERDICT_STATUS[o.verdict]} /> {o.verdict.replace('_', ' ')}</td>
                  <td>{o.score ?? '—'}</td><td>{o.provider || '—'}</td>
                  <td>{o.incidents.map((n) => <Link key={n} to={`/incidents/${n}`} style={{ marginRight: 6 }}>{n}</Link>)}</td><td>{fmtDate(o.last_seen)}</td></tr>
              ))}</tbody>
            </table></div>
          )}
        </Async>
      </div>
    </div>
  );
}
