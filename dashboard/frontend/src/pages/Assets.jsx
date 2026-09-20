import { useMemo, useState } from 'react';
import { api, errMsg } from '../api';
import { useAuth } from '../auth';
import { Async, Header, useLoad } from '../ui';

/** Layered layout: BFS depth from the highlighted (or first) node picks the column; no extra dependency. */
function layout(nodes, edges, root) {
  const depth = { [root]: 0 };
  const queue = [root];
  while (queue.length) {
    const cur = queue.shift();
    edges.filter((e) => e.source === cur && depth[e.target] === undefined).forEach((e) => { depth[e.target] = depth[cur] + 1; queue.push(e.target); });
  }
  nodes.forEach((n) => { if (depth[n.id] === undefined) depth[n.id] = 0; });
  const cols = {};
  nodes.forEach((n) => { (cols[depth[n.id]] = cols[depth[n.id]] || []).push(n); });
  const pos = {};
  Object.entries(cols).forEach(([d, list]) => list.forEach((n, i) => { pos[n.id] = { x: 90 + Number(d) * 190, y: 50 + i * 80 + (Number(d) % 2) * 20 }; }));
  return pos;
}

function Graph({ graph, highlight }) {
  const pos = useMemo(() => layout(graph.nodes, graph.edges, highlight || graph.nodes[0]?.id), [graph, highlight]);
  const w = Math.max(...Object.values(pos).map((p) => p.x), 300) + 120;
  const h = Math.max(...Object.values(pos).map((p) => p.y), 200) + 60;
  return (
    <svg viewBox={`0 0 ${w} ${h}`} style={{ width: '100%', maxHeight: 520, background: 'var(--bg-secondary)', borderRadius: 8 }} role="img" aria-label="Asset network graph">
      <defs><marker id="arr" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="6" markerHeight="6" orient="auto"><path d="M0,0 L10,5 L0,10 z" fill="#64748b" /></marker></defs>
      {graph.edges.map((e, i) => {
        const a = pos[e.source]; const b = pos[e.target];
        if (!a || !b) return null;
        return (<g key={i}><line x1={a.x} y1={a.y} x2={b.x} y2={b.y} stroke="#475569" strokeWidth="1.5" markerEnd="url(#arr)" />
          <text x={(a.x + b.x) / 2} y={(a.y + b.y) / 2 - 4} fill="#94a3b8" fontSize="9" textAnchor="middle">{e.protocol}/{e.port}</text></g>);
      })}
      {graph.nodes.map((n) => {
        const p = pos[n.id];
        const color = n.compromised ? '#ef4444' : n.criticality >= 8 ? '#f97316' : n.criticality >= 5 ? '#f59e0b' : '#22c55e';
        return (<g key={n.id}><circle cx={p.x} cy={p.y} r="18" fill={color} opacity="0.9" />
          <text x={p.x} y={p.y + 4} textAnchor="middle" fontSize="10" fill="#0a0e1a" fontWeight="700">{n.criticality}</text>
          <text x={p.x} y={p.y + 34} textAnchor="middle" fontSize="10" fill="#e2e8f0">{n.id}</text></g>);
      })}
    </svg>
  );
}

export default function Assets() {
  const { can } = useAuth();
  const [highlight, setHighlight] = useState('');
  const [asset, setAsset] = useState({ hostname: '', ip: '', os: '', role: '', criticality: 3 });
  const [link, setLink] = useState({ src: '', dst: '', protocol: 'tcp', port: 0 });
  const [msg, setMsg] = useState(null);
  const state = useLoad(async () => {
    const [a, g] = await Promise.all([api.get('/assets'), api.get('/assets/graph', { params: highlight ? { highlight } : {} })]);
    return { assets: a.data.assets, graph: g.data };
  }, [highlight]);

  const submit = (fn) => async (e) => {
    e.preventDefault(); setMsg(null);
    try { await fn(); setMsg({ ok: true, text: 'Saved' }); state.reload(); } catch (err) { setMsg({ ok: false, text: errMsg(err) }); }
  };

  return (
    <div className="page-container">
      <Header title="Assets" sub="Inventory and network relationships used for asset criticality and blast-radius analysis" />
      {msg && <div className="card" role="status" style={{ borderColor: msg.ok ? 'var(--success)' : 'var(--danger)', marginBottom: 12 }}>{msg.text}</div>}
      <Async state={state} empty={(d) => d.assets.length === 0}
        emptyText="No assets registered. Add assets below (or run `python -m soar.cli seed-demo` in development) to enable blast-radius analysis.">
        {({ assets, graph }) => (
          <>
            <div className="card" style={{ marginBottom: 16 }}>
              <div className="flex-between"><h3 className="section-title">Network graph</h3>
                <select className="input" style={{ maxWidth: 220 }} value={highlight} onChange={(e) => setHighlight(e.target.value)} aria-label="Highlight compromised host">
                  <option value="">Highlight a host…</option>{assets.map((a) => <option key={a.id}>{a.hostname}</option>)}
                </select></div>
              <p style={{ color: 'var(--text-muted)', fontSize: 12 }}>Node number = criticality (1–10). Arrows = “can reach”. Red = highlighted host; layout is by hop distance from it.</p>
              <Graph graph={graph} highlight={highlight} />
            </div>
            <div className="card" style={{ marginBottom: 16 }}>
              <h3 className="section-title">Inventory</h3>
              <div className="table-container"><table>
                <thead><tr><th>Host</th><th>IP</th><th>OS</th><th>Role</th><th>Criticality</th><th>Source</th></tr></thead>
                <tbody>{assets.map((a) => (<tr key={a.id}><td>{a.hostname}</td><td>{a.ip || '—'}</td><td>{a.os || '—'}</td><td>{a.role || '—'}</td><td>{a.criticality}</td><td>{a.source}</td></tr>))}</tbody>
              </table></div>
            </div>
          </>
        )}
      </Async>
      {can('asset:write') && (
        <div className="grid-2">
          <form className="card" onSubmit={submit(() => api.post('/assets', { ...asset, ip: asset.ip || null, os: asset.os || null, role: asset.role || null, criticality: Number(asset.criticality) }))} aria-label="Add asset">
            <h3 className="section-title">Add / update asset</h3>
            {['hostname', 'ip', 'os', 'role'].map((k) => (
              <input key={k} className="input" style={{ marginBottom: 8 }} placeholder={k} value={asset[k]} required={k === 'hostname'} maxLength={255}
                onChange={(e) => setAsset({ ...asset, [k]: e.target.value })} aria-label={k} />))}
            <label style={{ fontSize: 12 }}>Criticality {asset.criticality}/10
              <input type="range" min="1" max="10" value={asset.criticality} onChange={(e) => setAsset({ ...asset, criticality: e.target.value })} style={{ width: '100%' }} /></label>
            <button className="btn btn-primary btn-sm" style={{ marginTop: 8 }}>Save asset</button>
          </form>
          <form className="card" onSubmit={submit(() => api.post('/assets/links', { ...link, port: Number(link.port) }))} aria-label="Add link">
            <h3 className="section-title">Add relationship (source can reach target)</h3>
            <input className="input" style={{ marginBottom: 8 }} placeholder="source hostname" value={link.src} required onChange={(e) => setLink({ ...link, src: e.target.value })} aria-label="Source host" />
            <input className="input" style={{ marginBottom: 8 }} placeholder="target hostname" value={link.dst} required onChange={(e) => setLink({ ...link, dst: e.target.value })} aria-label="Target host" />
            <div className="flex-gap"><input className="input" placeholder="protocol" value={link.protocol} onChange={(e) => setLink({ ...link, protocol: e.target.value })} aria-label="Protocol" />
              <input className="input" type="number" min="0" max="65535" value={link.port} onChange={(e) => setLink({ ...link, port: e.target.value })} aria-label="Port" /></div>
            <button className="btn btn-primary btn-sm" style={{ marginTop: 8 }}>Save link</button>
          </form>
        </div>
      )}
    </div>
  );
}
