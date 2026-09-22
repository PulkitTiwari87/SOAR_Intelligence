import { useState } from 'react';
import { api, errMsg } from '../api';
import { useAuth } from '../auth';
import { Async, useLoad } from '../ui';

/* ─── Shared ─── */
const METRIC_LABELS = {
  accuracy: 'ACCURACY', precision: 'PRECISION', recall: 'RECALL',
  f1: 'F1 SCORE', roc_auc: 'ROC-AUC', pr_auc: 'PR-AUC',
};

function MetricGrid({ metrics }) {
  if (!metrics) return null;
  const entries = Object.entries(METRIC_LABELS).filter(([k]) => metrics[k] !== undefined);
  if (!entries.length) return null;
  return (
    <div className="ai-metric-grid">
      {entries.map(([k, label]) => (
        <div key={k} className="ai-metric-cell">
          <span className="ai-metric-label">{label}</span>
          <span className="ai-metric-value">{typeof metrics[k] === 'number' ? metrics[k].toFixed(3) : metrics[k]}</span>
        </div>
      ))}
    </div>
  );
}

function Provenance({ training_data, evaluation }) {
  if (!training_data && !evaluation?.note) return null;
  return (
    <p className="ai-model-desc" style={{ fontStyle: 'italic' }}>
      {training_data && (
        <>Trained on {training_data.source}{training_data.n_samples != null ? ` (${training_data.n_samples.toLocaleString()} samples)` : ''}
        {training_data.real_data === false ? '; real data: no' : ''}. </>
      )}
      {evaluation?.note}
    </p>
  );
}

/* ─── LLM Incident Commander ─── */
function LLMSection({ llm }) {
  if (!llm) return null;
  return (
    <div className="ai-model-block">
      <div className="ai-model-block-header">
        <div className="ai-model-block-title-row">
          <span className="ai-model-name">LLM incident commander</span>
          {llm.configured && <span className="ai-model-version">{llm.provider} / {llm.model}</span>}
        </div>
        <div className={`ai-model-state-badge ${llm.configured ? 'active' : 'skipped'}`}>
          {llm.configured ? 'CONFIGURED' : 'SKIPPED'}
        </div>
      </div>
      {!llm.configured && (
        <div className="ai-info-box">
          <span className="ai-info-icon">ℹ</span>
          <span>{llm.reason || `LLM_PROVIDER is '${llm.provider || 'none'}'`}. Decision support only. Output is schema-validated and every recommended action passes the response policy; the model cannot execute anything.</span>
        </div>
      )}
    </div>
  );
}

/* ─── ML Triage ─── */
function MLTriageSection({ m }) {
  if (!m || m.status === 'not_trained') return (
    <div className="ai-model-block">
      <div className="ai-model-block-header">
        <span className="ai-model-name">ML triage</span>
        <span className="ai-model-state-badge">NOT TRAINED</span>
      </div>
      <p className="ai-model-desc">No model trained yet.</p>
    </div>
  );

  return (
    <div className="ai-model-block">
      <div className="ai-model-block-header">
        <div className="ai-model-block-title-row">
          <span className="ai-model-name">ML triage</span>
          <span className="ai-model-version">v{m.version}</span>
        </div>
      </div>
      {m.algorithm && <p className="ai-model-desc">{m.algorithm}</p>}
      <Provenance training_data={m.training_data} evaluation={m.evaluation} />
      <MetricGrid metrics={m.evaluation?.xgboost} />
      <p className="ai-model-hint">Per-incident classification and feature contributions are shown on that incident&apos;s page (ML analysis section) — this is model-level evaluation only.</p>
    </div>
  );
}

/* ─── Anomaly Detector ─── */
function AnomalySection({ m }) {
  if (!m || m.status === 'not_trained') return (
    <div className="ai-model-block">
      <span className="ai-model-name">Anomaly detector</span>
      <p className="ai-model-desc">Not trained yet.</p>
    </div>
  );

  const ev = m.evaluation || {};
  const metrics = {
    'false positive rate': ev.false_positive_rate_on_holdout_baseline,
    'detection rate': ev.detection_rate_overall,
    'roc-auc': ev.roc_auc_baseline_vs_attacks,
  };

  return (
    <div className="ai-model-block">
      <div className="ai-model-block-header">
        <div className="ai-model-block-title-row">
          <span className="ai-model-name">Anomaly detector</span>
          <span className="ai-model-version">v{m.version}</span>
        </div>
      </div>
      {m.algorithm && <p className="ai-model-desc">{m.algorithm}</p>}
      <Provenance training_data={m.training_data} evaluation={m.evaluation} />
      <div className="ai-metric-grid">
        {Object.entries(metrics).filter(([, v]) => v != null).map(([label, v]) => (
          <div key={label} className="ai-metric-cell">
            <span className="ai-metric-label">{label.toUpperCase()}</span>
            <span className="ai-metric-value">{v}</span>
          </div>
        ))}
      </div>
    </div>
  );
}

/* ─── Phishing tab ─── */
function Phishing() {
  const [form, setForm] = useState({ subject: '', from: '', reply_to: '', emailText: '' });
  const [res, setRes] = useState(null);
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);
  const run = async (e) => {
    e.preventDefault(); setBusy(true); setError(''); setRes(null);
    try { setRes((await api.post('/ai/phishing', Object.fromEntries(Object.entries(form).filter(([, v]) => v)))).data); }
    catch (err) { setError(errMsg(err)); }
    setBusy(false);
  };
  const set = (k) => (e) => setForm({ ...form, [k]: e.target.value });
  return (
    <div className="grid-2">
      <form className="card" onSubmit={run} aria-label="Analyze an email">
        <h3 className="section-title">Analyze an email</h3>
        <input className="input" style={{ marginBottom: 8 }} placeholder="Subject" value={form.subject} onChange={set('subject')} maxLength={1000} aria-label="Subject" />
        <input className="input" style={{ marginBottom: 8 }} placeholder='From' value={form.from} onChange={set('from')} maxLength={500} aria-label="From" />
        <input className="input" style={{ marginBottom: 8 }} placeholder="Reply-To" value={form.reply_to} onChange={set('reply_to')} maxLength={500} aria-label="Reply-To" />
        <textarea className="input" rows={9} placeholder="Email body" value={form.emailText} onChange={set('emailText')} required maxLength={200000} aria-label="Email body" />
        <button className="btn btn-primary btn-sm" style={{ marginTop: 8 }} disabled={busy}>{busy ? 'Analyzing…' : 'Analyze'}</button>
      </form>
      <div className="card">
        <h3 className="section-title">Result</h3>
        {error && <p role="alert" style={{ color: 'var(--danger)' }}>{error}</p>}
        {!res && !error && <p style={{ color: 'var(--text-muted)' }}>Submit an email to see the verdict.</p>}
        {res && (
          <>
            <p style={{ fontSize: 22, fontWeight: 700 }}>{res.phishing_score} <span className={`badge ${res.verdict === 'phishing' ? 'badge-critical' : res.verdict === 'suspicious' ? 'badge-medium' : 'badge-resolved'}`}>{res.verdict}</span></p>
            <p style={{ color: 'var(--text-secondary)', fontSize: 12 }}>text {res.text_score} · indicators {res.indicator_score} · {res.action}</p>
          </>
        )}
      </div>
    </div>
  );
}

/* ─── Log Clusters tab ─── */
function Clusters() {
  const state = useLoad(async () => (await api.get('/ai/clusters')).data, []);
  return (
    <div className="card">
      <h3 className="section-title">Log clusters</h3>
      <p style={{ color: 'var(--text-muted)', fontSize: 12 }}>Recent events grouped by message template (TF-IDF + KMeans). Unusual = small or high-severity clusters.</p>
      <Async state={state} empty={(d) => d.status !== 'ok'} emptyText="Not enough distinct events to cluster yet.">
        {(d) => (<>
          <p style={{ margin: '8px 0' }}>{d.n_events} events → {d.k} clusters (silhouette {d.silhouette})</p>
          <div className="table-container"><table>
            <thead><tr><th>Size</th><th>Template</th><th>Max sev.</th><th>Incidents</th><th>Unattached</th><th>Flag</th></tr></thead>
            <tbody>{d.clusters.map((c) => (
              <tr key={c.cluster}>
                <td>{c.size} ({Math.round(c.share * 100)}%)</td>
                <td style={{ fontFamily: 'var(--font-mono)', fontSize: 12 }}>{c.template}</td>
                <td>{c.max_severity}</td>
                <td>{c.incidents.join(', ') || '—'}</td>
                <td>{c.unattached_events}</td>
                <td>{c.unusual ? <span className="badge badge-medium">{c.reason}</span> : ''}</td>
              </tr>
            ))}</tbody>
          </table></div>
        </>)}
      </Async>
    </div>
  );
}

/* ─── Main AI page ─── */
export default function AIModels() {
  const { can } = useAuth();
  const [tab, setTab] = useState('Models');
  const models = useLoad(async () => (await api.get('/ai/models')).data, []);
  const stats = useLoad(async () => (await api.get('/ai/stats')).data, []);
  const [retrain, setRetrain] = useState(null);

  const TABS = ['Models', 'Phishing', 'Log clusters'];

  return (
    <div className="page-container ai-page">
      <div className="ai-page-header">
        <div>
          <h1 className="ai-page-title">AI &amp; analysis</h1>
          <p className="ai-page-sub">Models, their real evaluation numbers, and analysis tools</p>
        </div>
      </div>

      <div className="ai-tabs" role="tablist">
        {TABS.map((id) => (
          <button key={id} role="tab" aria-selected={tab === id} className={`ai-tab ${tab === id ? 'active' : ''}`} onClick={() => setTab(id)}>
            {id}
          </button>
        ))}
      </div>

      {tab === 'Models' && (
        <Async state={models}>
          {(m) => (
            <>
              <LLMSection llm={m.llm} />
              <MLTriageSection m={m.triage} />
              <AnomalySection m={m.anomaly} />

              {can('user:admin') && (
                <Async state={stats}>
                  {(s) => (
                    <div className="card" style={{ marginTop: 16 }}>
                      <h3 className="section-title">Analyst feedback loop</h3>
                      <p style={{ fontSize: 13, color: 'var(--text-secondary)' }}>
                        Labeled: {s.feedback.labeled_incidents} incidents · Agreement: {s.feedback.model_agreement_with_analysts ?? 'n/a'} · Retrain ready: {s.feedback.retrain_ready ? 'yes' : `no (needs ${s.feedback.requirement})`}
                      </p>
                      <button className="btn btn-warning btn-sm" style={{ marginTop: 10 }} onClick={async () => { try { setRetrain((await api.post('/ai/retrain')).data); } catch (e) { setRetrain({ status: errMsg(e) }); } }}>
                        Retrain from feedback
                      </button>
                      {retrain && <pre style={{ fontSize: 11, marginTop: 8 }}>{JSON.stringify(retrain, null, 2)}</pre>}
                    </div>
                  )}
                </Async>
              )}
            </>
          )}
        </Async>
      )}
      {tab === 'Phishing' && <Phishing />}
      {tab === 'Log clusters' && <Clusters />}
    </div>
  );
}
