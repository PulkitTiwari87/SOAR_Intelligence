import { useState } from 'react';
import { api, errMsg } from '../api';
import { useAuth } from '../auth';
import { Async, Header, KV, StatusBadge, Tabs, useLoad } from '../ui';

const METRIC_LABELS = { accuracy: 'Accuracy', precision: 'Precision', recall: 'Recall', f1: 'F1', roc_auc: 'ROC-AUC', pr_auc: 'PR-AUC', brier: 'Brier score (lower is better)' };

function ModelCard({ name, m }) {
  if (!m?.version) return <div className="card"><h3>{name}</h3><p style={{ color: 'var(--text-muted)' }}>Not trained yet.</p></div>;
  const ev = m.evaluation || {};
  const main = ev.xgboost || ev;
  return (
    <div className="card" style={{ marginBottom: 16 }}>
      <div className="flex-between"><h3>{name}</h3><span className="badge badge-info">{m.version}</span></div>
      <p style={{ color: 'var(--text-secondary)', fontSize: 13, margin: '4px 0 10px' }}>{m.algorithm}</p>
      <div className="card" style={{ borderColor: 'var(--warning)', padding: 10, marginBottom: 10, fontSize: 12 }}>
        Trained on <strong>{m.training_data.source.replace(/_/g, ' ')}</strong> ({m.training_data.n_samples} samples; real data: {m.training_data.real_data ? 'yes' : 'no'}).
        {' '}{ev.note}
      </div>
      <KV rows={[['Trained at', new Date(m.trained_at).toLocaleString()], ['Evaluation', ev.kind],
        ...Object.entries(METRIC_LABELS).filter(([k]) => main[k] !== undefined).map(([k, label]) => [label, main[k]]),
        ...(ev.baseline_rule_level_ge_10 ? [['Baseline: rule level ≥ 10', `accuracy ${ev.baseline_rule_level_ge_10.accuracy}, F1 ${ev.baseline_rule_level_ge_10.f1}`]] : []),
        ...(ev.cv_roc_auc_5fold ? [['5-fold CV ROC-AUC', `${ev.cv_roc_auc_5fold.mean} ± ${ev.cv_roc_auc_5fold.std}`]] : []),
        ...(ev.false_positive_rate_on_holdout_baseline !== undefined ? [['False-positive rate (held-out baseline)', ev.false_positive_rate_on_holdout_baseline], ['Detection rate (synthetic attacks)', ev.detection_rate_overall], ['…Isolation Forest alone', ev.isolation_forest_only?.detection_rate_overall]] : []),
        ...(m.threshold ? [['Threshold', m.threshold.rule]] : [])]} />
      {m.limitations && <ul style={{ marginLeft: 18, marginTop: 8, fontSize: 12, color: 'var(--text-secondary)' }}>{m.limitations.map((l) => <li key={l}>{l}</li>)}</ul>}
    </div>
  );
}

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
        <input className="input" style={{ marginBottom: 8 }} placeholder='From, e.g. PayPal <help@paypa1.top>' value={form.from} onChange={set('from')} maxLength={500} aria-label="From" />
        <input className="input" style={{ marginBottom: 8 }} placeholder="Reply-To" value={form.reply_to} onChange={set('reply_to')} maxLength={500} aria-label="Reply-To" />
        <textarea className="input" rows={9} placeholder="Email body (plain text or HTML)" value={form.emailText} onChange={set('emailText')} required maxLength={200000} aria-label="Email body" />
        <button className="btn btn-primary btn-sm" style={{ marginTop: 8 }} disabled={busy}>{busy ? 'Analyzing…' : 'Analyze'}</button>
        <p style={{ color: 'var(--text-muted)', fontSize: 12, marginTop: 8 }}>Analysis only: nothing is fetched or executed. To open an incident, send the raw email to <code>/api/events</code> with source <code>email</code>.</p>
      </form>
      <div className="card">
        <h3 className="section-title">Result</h3>
        {error && <p role="alert" style={{ color: 'var(--danger)' }}>{error}</p>}
        {!res && !error && <p style={{ color: 'var(--text-muted)' }}>Submit an email to see the verdict, indicators and extracted IOCs.</p>}
        {res && (
          <>
            <p style={{ fontSize: 22, fontWeight: 700 }}>{res.phishing_score} <span className={`badge ${res.verdict === 'phishing' ? 'badge-critical' : res.verdict === 'suspicious' ? 'badge-medium' : 'badge-resolved'}`}>{res.verdict}</span></p>
            <p style={{ color: 'var(--text-secondary)', fontSize: 12 }}>text model {res.text_score} · indicators {res.indicator_score} · {res.action} · model {res.model_version}</p>
            <h4 style={{ margin: '10px 0 4px' }}>Indicators</h4>
            {res.indicators.length === 0 ? <p style={{ color: 'var(--text-muted)' }}>None triggered.</p> : <ul style={{ marginLeft: 18 }}>{res.indicators.map((i, k) => <li key={k}><strong>{i.name}</strong> — {i.detail}</li>)}</ul>}
            <h4 style={{ margin: '10px 0 4px' }}>Top text terms</h4>
            <p style={{ fontSize: 12 }}>{res.top_terms.map((t) => `${t.term} (${t.contribution})`).join(', ') || '—'}</p>
            <h4 style={{ margin: '10px 0 4px' }}>Extracted IOCs</h4>
            <ul style={{ marginLeft: 18, fontFamily: 'monospace', fontSize: 12 }}>{res.iocs.map((o, k) => <li key={k}>{o.type}: {o.value}</li>)}</ul>
            <p style={{ color: 'var(--text-muted)', fontSize: 11, marginTop: 8 }}>Evidence SHA-256: {res.evidence_sha256}</p>
          </>
        )}
      </div>
    </div>
  );
}

function Clusters() {
  const state = useLoad(async () => (await api.get('/ai/clusters')).data, []);
  return (
    <div className="card">
      <h3 className="section-title">Log clusters</h3>
      <p style={{ color: 'var(--text-muted)', fontSize: 12 }}>Recent events grouped by message template (TF-IDF + KMeans, k by silhouette). Unusual = small or high-severity clusters.</p>
      <Async state={state} empty={(d) => d.status !== 'ok'} emptyText="Not enough distinct events to cluster yet.">
        {(d) => (<>
          <p style={{ margin: '8px 0' }}>{d.n_events} events → {d.k} clusters (silhouette {d.silhouette})</p>
          <table><thead><tr><th>Size</th><th>Template</th><th>Max sev.</th><th>Incidents</th><th>Unattached</th><th>Flag</th></tr></thead>
            <tbody>{d.clusters.map((c) => (<tr key={c.cluster}><td>{c.size} ({Math.round(c.share * 100)}%)</td><td style={{ fontFamily: 'monospace', fontSize: 12 }}>{c.template}</td><td>{c.max_severity}</td>
              <td>{c.incidents.join(', ') || '—'}</td><td>{c.unattached_events}</td><td>{c.unusual ? <span className="badge badge-medium">{c.reason}</span> : ''}</td></tr>))}</tbody></table>
        </>)}
      </Async>
    </div>
  );
}

export default function AIModels() {
  const { can } = useAuth();
  const [tab, setTab] = useState('Models');
  const models = useLoad(async () => (await api.get('/ai/models')).data, []);
  const stats = useLoad(async () => (await api.get('/ai/stats')).data, []);
  const [retrain, setRetrain] = useState(null);
  return (
    <div className="page-container">
      <Header title="AI & analysis" sub="Models, their real evaluation numbers, and analysis tools" />
      <Tabs tabs={['Models', 'Phishing', 'Log clusters']} active={tab} onChange={setTab} />
      {tab === 'Models' && (
        <Async state={models}>
          {(m) => (
            <>
              <div className="card" style={{ marginBottom: 16 }}>
                <h3 className="section-title">LLM incident commander</h3>
                <p><StatusBadge status={m.llm.configured ? 'succeeded' : 'skipped'} /> {m.llm.configured ? `${m.llm.provider} / ${m.llm.model}` : m.llm.reason}</p>
                <p style={{ color: 'var(--text-muted)', fontSize: 12 }}>Decision support only. Output is schema-validated and every recommended action passes the response policy; the model cannot execute anything.</p>
              </div>
              <ModelCard name="ML triage" m={m.triage} />
              <ModelCard name="Anomaly detection" m={m.anomaly} />
              <ModelCard name="Phishing text model" m={m.phishing} />
              <Async state={stats}>
                {(s) => (
                  <div className="card">
                    <h3 className="section-title">Analyst feedback loop</h3>
                    <KV rows={[['Labeled incidents', s.feedback.labeled_incidents], ['Malicious / benign labels', `${s.feedback.malicious_labels} / ${s.feedback.benign_labels}`],
                      ['Model agreement with analysts', s.feedback.model_agreement_with_analysts ?? 'n/a (no labels yet)'], ['Retrain ready', s.feedback.retrain_ready ? 'yes' : `no: needs ${s.feedback.requirement}`],
                      ['Predictions stored', Object.entries(s.predictions_by_kind).map(([k, v]) => `${k}: ${v}`).join(', ') || 'none']]} />
                    {can('user:admin') && (
                      <button className="btn btn-warning btn-sm" style={{ marginTop: 10 }} onClick={async () => { try { setRetrain((await api.post('/ai/retrain')).data); } catch (e) { setRetrain({ status: errMsg(e) }); } }}>Retrain from feedback</button>
                    )}
                    {retrain && <pre style={{ fontSize: 11, marginTop: 8 }}>{JSON.stringify(retrain, null, 2)}</pre>}
                  </div>
                )}
              </Async>
            </>
          )}
        </Async>
      )}
      {tab === 'Phishing' && <Phishing />}
      {tab === 'Log clusters' && <Clusters />}
    </div>
  );
}
