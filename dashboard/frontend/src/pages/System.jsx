import { useState } from 'react';
import { api, errMsg } from '../api';
import { useAuth } from '../auth';
import { Async, fmtDate, fmtDuration, Header, KV, StatusBadge, useLoad } from '../ui';

const OK = { reachable: 'succeeded', configured: 'succeeded', not_configured: 'skipped', unreachable: 'failed', error: 'failed' };

export default function System() {
  const { can } = useAuth();
  const [msg, setMsg] = useState(null);
  const health = useLoad(async () => (await api.get('/system/health')).data, []);
  const integ = useLoad(async () => (await api.get('/system/integrations')).data.integrations, []);
  const metrics = useLoad(async () => (await api.get('/system/metrics')).data, []);
  const blocks = useLoad(async () => (await api.get('/blocklist')).data.blocklist, []);

  const unblock = async (ip) => {
    setMsg(null);
    try { await api.delete(`/blocklist/${ip}`); blocks.reload(); } catch (e) { setMsg(errMsg(e)); }
  };

  return (
    <div className="page-container">
      <Header title="System" sub="Measured status of this deployment: nothing on this page is hardcoded">
        <button className="btn btn-ghost btn-sm" onClick={() => { health.reload(); integ.reload(); metrics.reload(); blocks.reload(); }}>Refresh</button>
      </Header>
      <div className="grid-2" style={{ marginBottom: 16 }}>
        <div className="card"><h3 className="section-title">Health</h3>
          <Async state={health}>{(h) => (
            <KV rows={[['Status', <span className={`badge ${h.status === 'healthy' ? 'badge-resolved' : 'badge-critical'}`}>{h.status}</span>], ['Environment', h.environment], ['Uptime', fmtDuration(h.uptime_seconds)],
              ['Database', `${h.database.dialect}: ${h.database.ok ? 'ok' : `error (${h.database.error})`}`], ['Migration revision', h.database.migration],
              ...Object.entries(h.models).map(([k, v]) => [`Model: ${k}`, v.loaded ? `${v.version} (trained on ${v.trained_on})` : 'not trained'])]} />)}</Async></div>
        <div className="card"><h3 className="section-title">Integrations</h3>
          <Async state={integ}>{(rows) => (
            <table><tbody>{rows.map((i) => (
              <tr key={i.name}><td>{i.name.replace('_', ' ')}</td><td><StatusBadge status={OK[i.status] || 'skipped'} /> {i.status.replace('_', ' ')}</td>
                <td style={{ fontSize: 12, color: 'var(--text-muted)' }}>{i.latency_ms ? `${i.latency_ms} ms` : ''}{i.error || ''}{i.provider ? ` ${i.provider} ${i.model || ''}` : ''}</td></tr>
            ))}</tbody></table>)}</Async>
          <p style={{ color: 'var(--text-muted)', fontSize: 12, marginTop: 8 }}>“Not configured” means the variable is unset in <code>.env</code>. Integrations are optional.</p></div>
      </div>
      <div className="card" style={{ marginBottom: 16 }}><h3 className="section-title">Pipeline metrics (since API start)</h3>
        <Async state={metrics}>{(m) => (
          <div className="grid-2">
            <KV rows={Object.entries(m.counters).sort().map(([k, v]) => [k.replace(/_/g, ' '), v])} />
            <table><thead><tr><th>Latency (ms)</th><th>avg</th><th>p95</th><th>max</th><th>n</th></tr></thead>
              <tbody>{Object.entries(m.latency_ms).sort().map(([k, v]) => (<tr key={k}><td>{k}</td><td>{v.avg}</td><td>{v.p95}</td><td>{v.max}</td><td>{v.count}</td></tr>))}</tbody></table>
          </div>)}</Async></div>
      <div className="card"><h3 className="section-title">Blocklist</h3>
        <p style={{ color: 'var(--text-muted)', fontSize: 12 }}>State written by the <code>block_ip</code> action. Enforcement requires a firewall or agent that consumes <code>/api/blocklist.txt</code> (send the ingest API key), or Wazuh active response when configured.</p>
        {msg && <p role="alert" style={{ color: 'var(--danger)' }}>{msg}</p>}
        <Async state={blocks} empty={(d) => d.length === 0} emptyText="No IPs are blocked.">{(rows) => (
          <table><thead><tr><th>IP</th><th>Reason</th><th>By</th><th>Expires</th><th /></tr></thead>
            <tbody>{rows.map((b) => (<tr key={b.ip}><td style={{ fontFamily: 'monospace' }}>{b.ip}</td><td>{b.reason}</td><td>{b.created_by}</td><td>{fmtDate(b.expires_at)}</td>
              <td>{can('approve:medium') && <button className="btn btn-ghost btn-sm" onClick={() => unblock(b.ip)}>Remove</button>}</td></tr>))}</tbody></table>)}</Async></div>
    </div>
  );
}
