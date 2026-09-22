import { useState } from 'react';
import { Link, useParams } from 'react-router-dom';
import { Download, FileText, RefreshCw, Sparkles } from 'lucide-react';
import { api, errMsg } from '../api';
import { useAuth } from '../auth';
import { Async, Bar, fmtDate, Header, KV, SevBadge, StatusBadge, Timeline, useLoad } from '../ui';

const ANALYST_ACTIONS = [['investigate', 'Investigate'], ['monitor', 'Monitor'], ['false_positive', 'False positive'],
  ['resolve', 'Resolve'], ['close', 'Close'], ['reopen', 'Reopen']];
const POLICY_COLOR = { auto: 'badge-resolved', approval: 'badge-medium', deny: 'badge-critical' };

function Section({ title, children, right }) {
  return (
    <div className="card" style={{ marginBottom: 16 }}>
      <div className="flex-between"><h3 className="section-title">{title}</h3>{right}</div>
      {children}
    </div>
  );
}

export default function IncidentDetail() {
  const { id } = useParams();
  const { can } = useAuth();
  const state = useLoad(async () => (await api.get(`/incidents/${id}`)).data, [id]);
  const playbooks = useLoad(async () => (await api.get('/playbooks')).data.playbooks, []);
  const [busy, setBusy] = useState('');
  const [msg, setMsg] = useState(null);
  const [note, setNote] = useState('');
  const [picked, setPicked] = useState({});

  const act = async (label, fn) => {
    setBusy(label); setMsg(null);
    try { await fn(); await state.reload(); setMsg({ ok: true, text: `${label}: done` }); }
    catch (e) { setMsg({ ok: false, text: `${label}: ${errMsg(e)}` }); }
    setBusy('');
  };
  const post = (url, body) => () => api.post(url, body);
  const download = async () => {
    const r = await api.get(`/incidents/${id}/report/download`, { responseType: 'blob' });
    const a = document.createElement('a');
    a.href = URL.createObjectURL(r.data); a.download = `${id}.pdf`; a.click();
    URL.revokeObjectURL(a.href);
  };

  return (
    <div className="page-container">
      <Async state={state}>
        {(inc) => {
          const canWrite = can('incident:write');
          const triage = inc.analysis.triage;
          const llm = inc.llm?.result;
          const recs = llm?.recommended_actions || [];
          const selected = recs.filter((_, i) => picked[i]);
          return (
            <>
              <Header title={`${inc.number}`} sub={inc.title}>
                <SevBadge level={inc.severity} /> <StatusBadge status={inc.status} />
                <span className="badge badge-info">risk {inc.risk_score}</span>
                {inc.auto_handled && <span className="badge badge-resolved">auto-handled</span>}
              </Header>
              {msg && <div className="card" role="status" style={{ borderColor: msg.ok ? 'var(--success)' : 'var(--danger)', marginBottom: 12 }}>{msg.text}</div>}

              <Section title="Actions">
                <div className="flex-gap" style={{ flexWrap: 'wrap' }}>
                  {canWrite && ANALYST_ACTIONS.map(([a, label]) => (
                    <button key={a} className="btn btn-ghost btn-sm" disabled={!!busy}
                      onClick={() => act(label, post(`/incidents/${id}/action`, { action: a, notes: note }))}>{label}</button>
                  ))}
                  {canWrite && <button className="btn btn-ghost btn-sm" disabled={!!busy} onClick={() => act('Re-analyze', post(`/incidents/${id}/analyze`))}><RefreshCw size={14} /> Re-analyze</button>}
                  {canWrite && <button className="btn btn-primary btn-sm" disabled={!!busy} onClick={() => act('LLM analysis', post(`/incidents/${id}/analyze?llm=true`))}><Sparkles size={14} /> {busy === 'LLM analysis' ? 'Analyzing…' : 'Run LLM analysis'}</button>}
                  {canWrite && <button className="btn btn-ghost btn-sm" disabled={!!busy} onClick={() => act('Generate report', post(`/incidents/${id}/report`))}><FileText size={14} /> Generate report</button>}
                  {inc.has_report && <button className="btn btn-ghost btn-sm" onClick={download}><Download size={14} /> Download report</button>}
                </div>
                {can('playbook:run') && playbooks.data && (
                  <div className="flex-gap" style={{ marginTop: 12 }}>
                    <select className="input" id="pb" defaultValue="" aria-label="Playbook" style={{ maxWidth: 280 }}>
                      <option value="" disabled>Run a playbook…</option>
                      {playbooks.data.map((p) => <option key={p.name} value={p.name}>{p.name}</option>)}
                    </select>
                    <button className="btn btn-warning btn-sm" disabled={!!busy}
                      onClick={() => { const v = document.getElementById('pb').value; if (v) act(`Playbook ${v}`, post(`/incidents/${id}/playbooks/${v}/run`)); }}>Run</button>
                  </div>
                )}
                {canWrite && (
                  <div className="flex-gap" style={{ marginTop: 12 }}>
                    <input className="input" placeholder="Note (also attached to status actions)" value={note} onChange={(e) => setNote(e.target.value)} maxLength={2000} aria-label="Note" />
                    <button className="btn btn-ghost btn-sm" disabled={!note || !!busy}
                      onClick={() => act('Add note', async () => { await api.post(`/incidents/${id}/notes`, { text: note }); setNote(''); })}>Add note</button>
                  </div>
                )}
              </Section>

              <div className="grid-2" style={{ marginBottom: 16 }}>
                <Section title="Summary">
                  <p style={{ marginBottom: 10 }}>{inc.summary}</p>
                  <KV rows={[['Source', inc.source], ['Category', inc.category], ['Source IP', inc.primary_source_ip], ['Host', inc.primary_host],
                    ['User', inc.primary_user], ['First event', fmtDate(inc.first_event_at)], ['Detected', fmtDate(inc.detected_at)],
                    ['Resolved', fmtDate(inc.resolved_at)], ['Events', inc.event_count]]} />
                </Section>
                <Section title="Risk score breakdown">
                  <p style={{ color: 'var(--text-muted)', fontSize: 12, marginBottom: 8 }}>Heuristic weights, not validated. Missing signals are excluded, not counted as zero. Evidence coverage {Math.round(inc.confidence * 100)}%.</p>
                  <table><tbody>{Object.entries(inc.risk_breakdown).map(([k, v]) => (
                    <tr key={k}><td style={{ width: 110 }}>{k}</td><td><Bar value={v.available ? v.value : 0} /></td>
                      <td style={{ width: 90, color: 'var(--text-secondary)' }}>{v.available ? `${v.points} pts` : 'n/a'}</td></tr>
                  ))}</tbody></table>
                </Section>
              </div>

              <div className="grid-2" style={{ marginBottom: 16 }}>
                <Section title="ML analysis">
                  {triage ? (
                    <>
                      <p><strong>Triage:</strong> {triage.prediction} (p = {triage.confidence}) · model {triage.version}</p>
                      <p style={{ color: 'var(--text-muted)', fontSize: 12 }}>Trained on {triage.result.trained_on}: not validated on real incidents.</p>
                      <table>
                        <thead><tr><th>Feature</th><th>Value</th><th>Contribution</th><th>Polarity</th></tr></thead>
                        <tbody>{triage.result.top_features.map((f) => (
                          <tr key={f.feature}>
                            <td style={{ fontFamily: 'var(--font-mono)', fontSize: '0.85em' }}>{f.feature}</td>
                            <td>{f.value}</td>
                            <td style={{ color: f.contribution > 0 ? 'var(--danger)' : 'var(--success)' }}>{f.contribution > 0 ? '+' : ''}{f.contribution} log-odds</td>
                            <td><span className={`badge ${f.contribution > 0 ? 'badge-critical' : 'badge-low'}`}>{f.contribution > 0 ? 'malicious' : 'benign'}</span></td>
                          </tr>
                        ))}</tbody>
                      </table>
                    </>
                  ) : <p style={{ color: 'var(--text-muted)' }}>No triage result yet.</p>}
                  {inc.analysis.anomaly && <p style={{ marginTop: 10 }}><strong>Anomaly:</strong> {inc.analysis.anomaly.prediction} (percentile {inc.analysis.anomaly.result.anomaly_score}{inc.analysis.anomaly.result.trigger ? `, trigger ${inc.analysis.anomaly.result.trigger}` : ''})</p>}
                  {inc.analysis.blast_radius && <p style={{ marginTop: 10 }}><strong>Blast radius:</strong> {inc.analysis.blast_radius.prediction}. Highest-risk path: {inc.analysis.blast_radius.result.highest_risk_path || '—'} <Link to="/assets">(asset graph)</Link></p>}
                </Section>
                <Section title="MITRE ATT&CK">
                  {inc.mitre.length === 0 ? <p style={{ color: 'var(--text-muted)' }}>No techniques mapped.</p> : (
                    <table><thead><tr><th>Technique</th><th>Tactic</th><th>Source</th><th>Conf.</th></tr></thead>
                      <tbody>{inc.mitre.map((m) => (
                        <tr key={`${m.technique_id}${m.source}`} title={m.evidence}>
                          <td>{m.technique_id} {m.technique}{m.subtechnique ? ` / ${m.subtechnique}` : ''}</td><td>{m.tactic}</td>
                          <td>{m.source}{m.inferred && <span className="badge badge-medium" style={{ marginLeft: 4 }}>inferred</span>}</td><td>{Math.round(m.confidence * 100)}%</td>
                        </tr>
                      ))}</tbody></table>
                  )}
                </Section>
              </div>

              <Section title="Indicators and threat intelligence">
                {inc.iocs.length === 0 ? <p style={{ color: 'var(--text-muted)' }}>No indicators extracted.</p> : (
                  <div className="table-container"><table><thead><tr><th>Type</th><th>Value</th><th>Verdict</th><th>Provider</th><th>Detail</th></tr></thead>
                    <tbody>{inc.iocs.map((o) => {
                      const best = o.intel.find((i) => i.verdict !== 'unknown') || o.intel[0];
                      return (
                        <tr key={o.id}><td>{o.type}</td><td style={{ fontFamily: 'monospace', wordBreak: 'break-all' }}>{o.value}</td>
                          <td>{best ? <StatusBadge status={best.verdict === 'malicious' ? 'failed' : best.verdict === 'benign' ? 'succeeded' : 'skipped'} /> : 'not enriched'} {best?.verdict}</td>
                          <td>{best?.provider || '—'}</td><td style={{ fontSize: 12 }}>{best ? `score ${best.score}, confidence ${best.confidence}` : ''}</td></tr>
                      );
                    })}</tbody></table></div>
                )}
              </Section>

              <Section title="LLM analysis (decision support)">
                {!llm ? <p style={{ color: 'var(--text-muted)' }}>Not run yet. Use “Run LLM analysis”; without a configured provider a labelled rule-based summary is produced.</p> : (
                  <>
                    <p><span className={`badge ${llm.llm_used ? 'badge-resolved' : 'badge-medium'}`}>{llm.llm_used ? `LLM: ${llm.provider} / ${llm.model}` : 'rule-based fallback (no LLM used)'}</span>
                      {' '}confidence {llm.confidence} · severity {llm.severity}</p>
                    {llm.notes?.length > 0 && <p style={{ color: 'var(--text-muted)', fontSize: 12 }}>{llm.notes.join(' · ')}</p>}
                    <p style={{ margin: '10px 0' }}>{llm.summary}</p>
                    {llm.evidence?.length > 0 && <ul style={{ marginLeft: 18 }}>{llm.evidence.map((e, i) => <li key={i}>{e}</li>)}</ul>}
                    <h4 style={{ margin: '12px 0 6px' }}>Recommended actions (recommendations only; nothing has been executed)</h4>
                    {recs.length === 0 ? <p style={{ color: 'var(--text-muted)' }}>None.</p> : (
                      <table><tbody>{recs.map((r, i) => (
                        <tr key={i}>
                          <td>{can('playbook:run') && r.policy.outcome !== 'deny' && <input type="checkbox" aria-label={`Select ${r.action}`} checked={!!picked[i]} onChange={(e) => setPicked({ ...picked, [i]: e.target.checked })} />}</td>
                          <td><strong>{r.action}</strong> {r.target || ''}</td>
                          <td><span className={`badge ${POLICY_COLOR[r.policy.outcome]}`}>{r.policy.outcome}</span></td>
                          <td style={{ fontSize: 12 }}>{r.rationale} <em style={{ color: 'var(--text-muted)' }}>({r.policy.reason})</em></td>
                        </tr>
                      ))}</tbody></table>
                    )}
                    {selected.length > 0 && (
                      <button className="btn btn-warning btn-sm" style={{ marginTop: 10 }} disabled={!!busy}
                        onClick={() => act('Run selected actions', post(`/incidents/${id}/actions/run`, { actions: selected.map((r) => ({ action: r.action, target: r.target })) }))}>
                        Run {selected.length} selected through policy
                      </button>
                    )}
                  </>
                )}
              </Section>

              <Section title="Response executions">
                {inc.executions.length === 0 ? <p style={{ color: 'var(--text-muted)' }}>No playbook has run for this incident.</p> : inc.executions.map((x) => (
                  <div key={x.id} style={{ marginBottom: 14 }}>
                    <div className="flex-gap"><strong>{x.playbook}</strong> <StatusBadge status={x.status} /> <span style={{ color: 'var(--text-muted)', fontSize: 12 }}>by {x.requested_by}</span>
                      {can('approve:medium') && ['completed', 'failed'].includes(x.status) && (
                        <button className="btn btn-ghost btn-sm" disabled={!!busy} onClick={() => act('Rollback', post(`/executions/${x.id}/rollback`))}>Roll back</button>)}
                    </div>
                    <table><thead><tr><th>Step</th><th>Status</th><th>Verified</th><th>Result</th></tr></thead>
                      <tbody>{x.steps.map((s) => (
                        <tr key={s.id}><td>{s.action}</td><td><StatusBadge status={s.status} /></td>
                          <td>{s.verified === true ? 'yes' : s.verified === false ? 'FAILED' : 'n/a'}</td>
                          <td style={{ fontSize: 12 }}>{s.result?.detail || ''}{s.verification?.detail ? ` — ${s.verification.detail}` : ''}{s.rollback?.detail ? ` · rollback: ${s.rollback.detail}` : ''}</td></tr>
                      ))}</tbody></table>
                  </div>
                ))}
              </Section>

              <div className="grid-2" style={{ marginBottom: 16 }}>
                <Section title="Approvals">
                  {inc.approvals.length === 0 ? <p style={{ color: 'var(--text-muted)' }}>No approvals requested.</p> : (
                    <table><tbody>{inc.approvals.map((a) => (
                      <tr key={a.id}><td><strong>{a.action}</strong><div style={{ fontSize: 12, color: 'var(--text-secondary)' }}>{a.reason}</div></td>
                        <td><StatusBadge status={a.status} /> <span className={`badge badge-${a.risk === 'high' ? 'critical' : 'medium'}`}>{a.risk}</span></td>
                        <td style={{ fontSize: 12 }}>{a.decided_by ? `${a.decided_by}: ${a.decision_note || ''}` : <Link to="/approvals">Decide →</Link>}</td></tr>
                    ))}</tbody></table>
                  )}
                </Section>
                <Section title="Analyst actions">
                  {inc.analyst_actions.length === 0 ? <p style={{ color: 'var(--text-muted)' }}>None yet.</p> : (
                    <ul style={{ marginLeft: 18 }}>{inc.analyst_actions.map((a, i) => <li key={i}><strong>{a.username}</strong> {a.action} — {fmtDate(a.created_at)} {a.notes && `(${a.notes})`}</li>)}</ul>
                  )}
                </Section>
              </div>

              <div className="grid-2">
                <Section title="Timeline"><Timeline items={inc.timeline} /></Section>
                <Section title={`Correlated events (${inc.events.length})`}>
                  <div className="table-container"><table><thead><tr><th>Time</th><th>Type</th><th>Sev.</th><th>Detail</th></tr></thead>
                    <tbody>{inc.events.map((e) => (
                      <tr key={e.id}><td style={{ whiteSpace: 'nowrap' }}>{fmtDate(e.timestamp)}</td><td>{e.event_type}</td><td><SevBadge level={e.severity} /></td>
                        <td style={{ fontSize: 12 }}>{e.title}{e.command && <div style={{ fontFamily: 'monospace' }}>{e.command}</div>}
                          <details><summary>raw event</summary><pre style={{ whiteSpace: 'pre-wrap', fontSize: 11 }}>{JSON.stringify(e.raw_event, null, 2)}</pre></details></td></tr>
                    ))}</tbody></table></div>
                </Section>
              </div>
            </>
          );
        }}
      </Async>
    </div>
  );
}
