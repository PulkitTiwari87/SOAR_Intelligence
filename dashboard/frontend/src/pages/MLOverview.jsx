// Public, unauthenticated ML overview (route /ml). Static: everything shown comes from files exported from
// the trained Python models (scripts/export_ml_demo.py). The triage demo runs the real XGBoost trees in
// the browser; the phishing and anomaly demos replay outputs recorded from the real Python models.
import { useEffect, useMemo, useState } from 'react';
import { loadModel, predictProba, shap } from '../ml/xgb';
import '../ml/ml.css';

const base = import.meta.env.BASE_URL;
const pct = (v, d = 1) => `${(v * 100).toFixed(d)}%`;
const three = (v) => v.toFixed(3);

const TRIAGE_INFO = {
  rule_level: 'Wazuh rule severity (0–15)',
  failed_logins: 'Failed authentications in the incident',
  src_ip_is_internal: 'Source IP is in a private range',
  ioc_score: 'Threat-intel score (0–100); 0 if no result',
  ioc_known: 'A threat-intel result exists',
  event_count: 'Events correlated into the incident',
  is_fim_event: 'File-integrity-monitoring event',
  has_mitre_tag: 'Rule carries an ATT&CK tag',
  off_hours: 'Outside business hours',
};
const THRESH = { malicious: 0.7, benign: 0.3 }; // ai/triage/ml_triage_analyzer.py
const labelOf = (p) => (p >= THRESH.malicious ? 'malicious' : p <= THRESH.benign ? 'benign' : 'uncertain');
const ACTION = { malicious: 'Actionable: raise priority', benign: 'Not actionable: deprioritise', uncertain: 'Uncertain: analyst review' };

const FLOW = [
  ['Sources', 'Wazuh alerts, syslog, network events, raw email, MISP attributes via POST /api/events', 'soar/api/events.py'],
  ['Normalize', 'Common event schema, raw payload kept, hash-based event_id makes re-sends idempotent', 'soar/pipeline/normalizer.py'],
  ['Correlate', 'Weighted entity matching (IP, host, user, hash, domain) in a time window opens or joins an incident', 'soar/pipeline/correlation.py'],
  ['Features + ML', 'Incident → 9 triage features; host behaviour → 10 anomaly metrics; emails → text + indicators', 'soar/pipeline/analysis.py', true],
  ['Risk score', 'Weighted blend of ML, severity, IOC, asset criticality, correlation, anomaly, ATT&CK; missing signals excluded', 'soar/pipeline/risk.py'],
  ['Response policy', 'Low-risk steps run automatically; the rest wait for a human approval; every step verified and audited', 'soar/playbooks/'],
];

function Metric({ label, value }) {
  return <div className="ml-metric"><b>{value}</b><span>{label}</span></div>;
}

function Dl({ rows }) {
  return <dl className="ml-dl">{rows.map(([k, v]) => <div key={k} style={{ display: 'contents' }}><dt>{k}</dt><dd>{v}</dd></div>)}</dl>;
}

/* ─── Model showcase ─── */
function Models({ m }) {
  const t = m.triage, a = m.anomaly, p = m.phishing;
  const tx = t.evaluation.xgboost, ae = a.evaluation;
  return (
    <div className="ml-models">
      <article className="ml-card" id="m-triage">
        <div className="ml-card-head"><h3>ML alert triage</h3><span className="ml-tag">XGBoost · v{t.version}</span></div>
        <p className="ml-note" style={{ marginTop: 0 }}>Trained on {t.training_data.n_samples.toLocaleString()} synthetic scenarios ({pct(t.training_data.malicious_rate, 0)} actionable, {pct(t.training_data.label_noise, 0)} label noise). Evaluated on {t.evaluation.n_test.toLocaleString()} independently seeded, distribution-shifted synthetic rows.</p>
        <Dl rows={[
          ['Problem', 'Estimate the probability that a correlated alert set is actionable, so analysts see likely incidents first.'],
          ['Input', <span className="ml-mono" key="i">{t.features.join(' · ')}</span>],
          ['Output', 'Probability, label (malicious ≥ 0.70, benign ≤ 0.30, otherwise uncertain) and exact TreeSHAP contribution per feature.'],
          ['Role in SOAR', 'Feeds 25% of the incident risk score, the largest single weight.'],
          ['Baselines', `Logistic regression on the same features scored F1 ${three(t.evaluation.baseline_logistic_regression.f1)}; the rule “rule_level ≥ 10” scored F1 ${three(t.evaluation.baseline_rule_level_ge_10.f1)}.`],
        ]} />
        <div className="ml-metrics">
          <Metric label="Accuracy" value={three(tx.accuracy)} /><Metric label="Precision" value={three(tx.precision)} />
          <Metric label="Recall" value={three(tx.recall)} /><Metric label="F1" value={three(tx.f1)} />
          <Metric label="ROC-AUC" value={three(tx.roc_auc)} /><Metric label="5-fold CV AUC" value={`${three(t.evaluation.cv_roc_auc_5fold.mean)} ± ${three(t.evaluation.cv_roc_auc_5fold.std)}`} />
        </div>
      </article>

      <article className="ml-card" id="m-anomaly">
        <div className="ml-card-head"><h3>Host anomaly detection</h3><span className="ml-tag">Isolation Forest · v{a.version}</span></div>
        <p className="ml-note" style={{ marginTop: 0 }}>Baseline of {a.training_data.n_samples.toLocaleString()} synthetic normal host-behaviour rows; attacks are hand-specified synthetic profiles.</p>
        <Dl rows={[
          ['Problem', 'Flag hosts whose behaviour departs from their baseline.'],
          ['Input', <span className="ml-mono" key="i">{a.features.join(' · ')}</span>],
          ['Output', 'Anomaly percentile, is_anomaly, which rule fired, and the features that deviated (z-scores).'],
          ['Design note', `Forest scores saturate for extreme values, so the forest alone detected only ${pct(ae.isolation_forest_only.detection_rate_overall)} of the synthetic attacks. A second rule (any feature ≥ ${ae.z_limit}σ from baseline) lifts that to ${pct(ae.detection_rate_overall)}.`],
          ['Role in SOAR', 'Feeds 5% of the risk score.'],
        ]} />
        <div className="ml-metrics">
          <Metric label="False-positive rate" value={pct(ae.false_positive_rate_on_holdout_baseline, 2)} />
          <Metric label="Detection (forest + rule)" value={pct(ae.detection_rate_overall)} />
          <Metric label="Detection (forest only)" value={pct(ae.isolation_forest_only.detection_rate_overall)} />
          <Metric label="ROC-AUC" value={three(ae.roc_auc_baseline_vs_attacks)} />
        </div>
      </article>

      <article className="ml-card" id="m-phishing">
        <div className="ml-card-head"><h3>Phishing analysis</h3><span className="ml-tag">TF-IDF + logistic regression · v{p.version}</span></div>
        <p className="ml-note" style={{ marginTop: 0 }}>Text model trained on {p.training_data.n_samples} short hand-written messages ({p.training_data.n_phishing} phishing).</p>
        <Dl rows={[
          ['Problem', 'Score an email for phishing and extract IOCs for the incident.'],
          ['Input', 'Subject, sender, Reply-To, body, optional auth headers.'],
          ['Method', 'Score = 0.5 × text probability + 0.5 × rule-based indicator score (look-alike domains, risky TLDs, punycode, shorteners, Reply-To mismatch, SPF/DKIM/DMARC failure, link text ≠ target).'],
          ['Output', 'Score, verdict, indicators, top terms, URLs, domains, IOCs, SHA-256 of the analysed input.'],
        ]} />
        <div className="ml-metrics">
          <Metric label="CV accuracy" value={three(p.evaluation.accuracy)} /><Metric label="Precision" value={three(p.evaluation.precision)} />
          <Metric label="Recall" value={three(p.evaluation.recall)} /><Metric label="F1" value={three(p.evaluation.f1)} />
        </div>
        <p className="ml-note">5-fold cross-validation on the templated corpus. The repository states these scores are optimistic and not a real-world estimate.</p>
      </article>

      <div className="ml-cols">
        <article className="ml-card">
          <div className="ml-card-head"><h4>Log clustering</h4><span className="ml-tag">KMeans</span></div>
          <p>Template normalisation (IPs, numbers, users, paths → placeholders), TF-IDF, KMeans with k chosen by silhouette. Flags small or high-severity clusters. Lexical, not semantic. Runs on the events in the database, so no benchmark is reported.</p>
        </article>
        <article className="ml-card">
          <div className="ml-card-head"><h4>Blast radius</h4><span className="ml-tag warn">heuristic, not learned</span></div>
          <p>Bounded BFS over the asset graph; risk = 100 · criticality/10 / hops. A prioritisation heuristic, not a probability, and it reports “no inventory” rather than inventing a topology.</p>
        </article>
        <article className="ml-card">
          <div className="ml-card-head"><h4>LLM incident commander</h4><span className="ml-tag warn">not verified live</span></div>
          <p>Decision support only. Output is schema-validated, recommended actions are limited to the action registry and pass the response policy; it has no execution path. Tested with mock transports; no live provider was available.</p>
        </article>
      </div>
    </div>
  );
}

/* ─── Results ─── */
function Results({ m }) {
  const e = m.triage.evaluation;
  const rows = [
    ['XGBoost', e.xgboost.accuracy, e.xgboost.f1, true],
    ['Logistic regression', e.baseline_logistic_regression.accuracy, e.baseline_logistic_regression.f1],
    ['Rule: rule_level ≥ 10', e.baseline_rule_level_ge_10.accuracy, e.baseline_rule_level_ge_10.f1],
  ];
  return (
    <div className="ml-card">
      <h4>Triage: model vs. baselines (synthetic hold-out, n = {e.n_test.toLocaleString()})</h4>
      {['Accuracy', 'F1'].map((metric, mi) => (
        <div key={metric}>
          <div className="ml-sub-h">{metric}</div>
          <div className="ml-cmp">
            {rows.map((r) => (
              <div className="ml-cmp-row" key={r[0]}>
                <span>{r[0]}</span>
                <div className="ml-cmp-track" role="img" aria-label={`${r[0]} ${metric} ${three(r[mi + 1])}`}><div className={`ml-cmp-fill ${r[3] ? 'on' : ''}`} style={{ width: `${r[mi + 1] * 100}%` }} /></div>
                <span className="ml-mono">{three(r[mi + 1])}</span>
              </div>
            ))}
          </div>
        </div>
      ))}
      <p className="ml-note">All figures are read from the models’ <span className="ml-mono">metadata.json</span> files. They measure how well each model recovers the assumptions of its own synthetic data generator, so they show that the mechanisms work and are reproducible, not how accurate they would be on real Wazuh alerts.</p>
    </div>
  );
}

/* ─── Interactive demo ─── */
function TriageDemo({ demo, model }) {
  const samples = demo.samples.triage;
  const feats = demo.models.triage.features;
  const [x, setX] = useState(samples[0].input);
  const [pick, setPick] = useState(0);
  const set = (k, v) => { setPick(-1); setX((o) => ({ ...o, [k]: v })); };
  const key = feats.map((f) => Number(x[f]) || 0).join(',');
  const res = useMemo(() => {
    const vec = key.split(',').map(Number);
    const p = predictProba(model, vec);
    const phi = shap(model, vec);
    return { p, label: labelOf(p), contrib: feats.map((f, i) => ({ f, v: phi[i] })).sort((a, b) => Math.abs(b.v) - Math.abs(a.v)) };
  }, [model, key, feats]);
  const max = Math.max(...res.contrib.map((c) => Math.abs(c.v)), 0.001);
  const num = (k, lo, hi) => (
    <div className="ml-field"><label htmlFor={`t-${k}`}>{k}<span className="ml-mono">{TRIAGE_INFO[k]}</span></label>
      <input id={`t-${k}`} className="ml-in" type="number" min={lo} max={hi} value={x[k]} onChange={(e) => set(k, Math.min(hi, Math.max(lo, Number(e.target.value) || 0)))} /></div>
  );
  const bool = (k, label) => (
    <label className="ml-check"><input type="checkbox" checked={!!x[k]} onChange={(e) => set(k, e.target.checked ? 1 : 0)} />{label}</label>
  );
  return (
    <div className="ml-demo">
      <div className="ml-panel">
        <h3>Input: correlated alert features</h3>
        <select className="ml-select" aria-label="Sample scenario" value={pick} onChange={(e) => { const i = Number(e.target.value); if (i >= 0) { setPick(i); setX(samples[i].input); } }}>
          {pick < 0 && <option value={-1}>Custom values</option>}
          {samples.map((s, i) => <option key={s.title} value={i}>{s.title}</option>)}
        </select>
        {num('rule_level', 0, 15)}{num('failed_logins', 0, 500)}{num('event_count', 1, 1000)}
        <div className="ml-field"><label htmlFor="t-ioc">ioc_score<span className="ml-mono">{TRIAGE_INFO.ioc_score}</span></label>
          <input id="t-ioc" className="ml-in" type="number" min={0} max={100} value={x.ioc_score} onChange={(e) => { const v = Math.min(100, Math.max(0, Number(e.target.value) || 0)); setPick(-1); setX((o) => ({ ...o, ioc_score: v, ioc_known: v > 0 ? 1 : 0 })); }} /></div>
        {bool('src_ip_is_internal', 'Source IP is internal')}{bool('is_fim_event', 'File-integrity event')}
        {bool('has_mitre_tag', 'Rule has ATT&CK tag')}{bool('off_hours', 'Off-hours')}
        <p className="ml-note">ioc_known is derived: it is 1 when ioc_score &gt; 0 (the backend sets it when a threat-intel result exists).</p>
      </div>
      <div className="ml-panel" aria-live="polite">
        <h3>Prediction</h3>
        <span className="ml-src live">LIVE · real XGBoost trees running in your browser</span>
        <div className="ml-verdict"><span className="ml-prob">{pct(res.p)}</span><span className={`ml-label ${res.label}`}>{res.label}</span></div>
        <p className="ml-note" style={{ marginTop: 6 }}>Probability the alert set is actionable · Triage category: <b>{ACTION[res.label]}</b> · model {demo.models.triage.version}</p>
        <div className="ml-sub-h">Why: TreeSHAP contribution (log-odds)</div>
        <div className="ml-shap">
          {res.contrib.map((c) => (
            <div className="ml-shap-row" key={c.f}>
              <span className="ml-mono" title={TRIAGE_INFO[c.f]}>{c.f}={x[c.f]}</span>
              <div className="ml-shap-axis"><div className={`ml-shap-bar ${c.v >= 0 ? 'pos' : 'neg'}`} style={{ width: `${(Math.abs(c.v) / max) * 50}%` }} /></div>
              <span className="val">{c.v >= 0 ? '+' : ''}{c.v.toFixed(2)}</span>
            </div>
          ))}
        </div>
        <p className="ml-note">Red pushes toward actionable, green toward benign. This is the shipped model, run through a small JavaScript evaluator whose probabilities and SHAP values are tested against the Python backend for the sample scenarios.</p>
      </div>
    </div>
  );
}

function Recorded({ demo, kind, render }) {
  const samples = demo.samples[kind];
  const [i, setI] = useState(0);
  const s = samples[i];
  return (
    <div className="ml-demo">
      <div className="ml-panel">
        <h3>Input</h3>
        <select className="ml-select" aria-label="Sample" value={i} onChange={(e) => setI(Number(e.target.value))}>
          {samples.map((x, n) => <option key={x.title} value={n}>{x.title}</option>)}
        </select>
        <div style={{ marginTop: 12 }}>{render.input(s.input)}</div>
      </div>
      <div className="ml-panel">
        <h3>Model output</h3>
        <span className="ml-src pre">PRECOMPUTED · recorded from the real Python model, not run live</span>
        {render.output(s.output)}
      </div>
    </div>
  );
}

const phishingIO = {
  input: (e) => (
    <>
      <div className="ml-kv"><span>from</span><span>{e.from}</span><span>reply-to</span><span>{e.reply_to || '—'}</span><span>subject</span><span>{e.subject}</span></div>
      <pre className="ml-pre" style={{ marginTop: 10 }}>{e.body}</pre>
      {Object.keys(e.headers).length > 0 && <pre className="ml-pre">{JSON.stringify(e.headers)}</pre>}
    </>
  ),
  output: (o) => (
    <>
      <div className="ml-verdict"><span className="ml-prob">{o.phishing_score}</span><span className={`ml-label ${o.verdict}`}>{o.verdict}</span></div>
      <p className="ml-note" style={{ marginTop: 6 }}>text model {o.text_score} · indicators {o.indicator_score} · model {o.model_version} · suggested action: <b>{o.action}</b></p>
      <div className="ml-sub-h">Indicators</div>
      <ul className="ml-list">{o.indicators.map((n) => <li key={n.name + n.detail}><span className="ml-mono">{n.name}</span> · {n.detail}</li>)}</ul>
      <div className="ml-sub-h">Top text terms</div>
      <div className="ml-chips">{o.top_terms.map((t) => <span className="ml-chip" key={t.term}>{t.term} {t.contribution.toFixed(2)}</span>)}</div>
      {o.iocs.length > 0 && <><div className="ml-sub-h">Extracted IOCs</div><div className="ml-chips">{o.iocs.map((c) => <span className="ml-chip" key={c.value}>{c.type}: {c.value}</span>)}</div></>}
    </>
  ),
};

const anomalyIO = {
  input: (m) => <div className="ml-kv">{Object.entries(m).flatMap(([k, v]) => [<span key={k}>{k}</span>, <span key={k + 'v'}>{v.toLocaleString()}</span>])}</div>,
  output: (o) => (
    <>
      <div className="ml-verdict"><span className="ml-prob">{o.anomaly_score}</span><span className={`ml-label ${o.is_anomaly ? 'malicious' : 'benign'}`}>{o.is_anomaly ? 'anomalous' : 'normal'}</span></div>
      <p className="ml-note" style={{ marginTop: 6 }}>Percentile of the model’s training baseline · pattern hint: <b>{o.threat_type}</b> (a rule of thumb, not a classifier output) · model {o.model_version}</p>
      <div className="ml-kv"><span>raw forest score</span><span>{o.raw_score}</span><span>forest threshold (p99)</span><span>{o.threshold}</span><span>rule that fired</span><span>{o.trigger || '—'}</span></div>
      {o.trigger === 'extreme_deviation' && o.raw_score < o.threshold && (
        <p className="ml-note">The forest score is below its own threshold; the extreme-deviation rule is what flagged this host. That gap is why the second rule exists.</p>
      )}
      {Object.keys(o.deviating_features).length > 0 && <><div className="ml-sub-h">Deviating features (σ from baseline)</div>
        <div className="ml-kv">{Object.entries(o.deviating_features).flatMap(([k, v]) => [<span key={k}>{k}</span>, <span key={k + 'v'}>{v}σ</span>])}</div></>}
    </>
  ),
};

function Demo({ demo, model }) {
  const [tab, setTab] = useState('triage');
  const TABS = [['triage', 'Alert triage (XGBoost)'], ['phishing', 'Phishing'], ['anomaly', 'Host anomaly']];
  return (
    <>
      <div className="ml-tabs" role="tablist">
        {TABS.map(([id, name]) => <button key={id} role="tab" aria-selected={tab === id} className="ml-tab" onClick={() => setTab(id)}>{name}</button>)}
      </div>
      {tab === 'triage' && <TriageDemo demo={demo} model={model} />}
      {tab === 'phishing' && <Recorded demo={demo} kind="phishing" render={phishingIO} />}
      {tab === 'anomaly' && <Recorded demo={demo} kind="anomaly" render={anomalyIO} />}
    </>
  );
}

/* ─── Page ─── */
export default function MLOverview() {
  const [demo, setDemo] = useState(null);
  const [model, setModel] = useState(null);
  const [err, setErr] = useState('');
  useEffect(() => {
    const get = (f) => fetch(`${base}ml-data/${f}`).then((r) => { if (!r.ok) throw new Error(`${f}: ${r.status}`); return r.json(); });
    Promise.all([get('demo-data.json'), get('triage_model.json')])
      .then(([d, j]) => { setDemo(d); setModel(loadModel(j)); })
      .catch((e) => setErr(e.message));
  }, []);

  const env = demo?.models.triage.environment;
  return (
    <div className="ml-page">
      <header className="ml-bar"><div className="ml-bar-in">
        <span className="ml-brand">SOAR Intelligence</span>
        <nav className="ml-nav" aria-label="Sections">
          <a href="#architecture">Architecture</a><a href="#models">Models</a><a href="#results">Results</a><a href="#demo">Live demo</a><a href="#stack">Stack</a><a href="#limits">Limitations</a>
        </nav>
      </div></header>

      <main className="ml-wrap">
        <section className="ml-hero">
          <span className="ml-eyebrow">Machine learning overview</span>
          <h1>SOAR Intelligence</h1>
          <p className="ml-sub">ML-Driven Security Automation Platform</p>
          <p className="ml-lede">Ingests security events, correlates them into incidents, and scores them with ML triage, host anomaly detection and phishing analysis, alongside MITRE ATT&amp;CK mapping and threat-intel enrichment. Response playbooks run behind a policy gate with human approval, verification and an audit trail.</p>
          <div className="ml-notice"><strong>Read this first.</strong> No labelled Wazuh incident data ships with this project. Every model is trained on synthetic or hand-written data, and every metric below was measured on that same kind of data. They demonstrate working, reproducible mechanisms; they are not production accuracy estimates.</div>
          <div className="ml-facts">
            <div className="ml-fact"><b>3</b><span>trained models (XGBoost, Isolation Forest, TF-IDF + LR)</span></div>
            <div className="ml-fact"><b>9</b><span>triage features, TreeSHAP explanations</span></div>
            <div className="ml-fact"><b>2</b><span>further analysers (log clustering, blast-radius heuristic)</span></div>
            <div className="ml-fact"><b>0</b><span>real-world labelled datasets shipped</span></div>
          </div>
        </section>

        <section className="ml-section" id="architecture">
          <h2>Architecture</h2>
          <p className="ml-lede">One Python service (FastAPI), a React dashboard and PostgreSQL. Ingestion is synchronous; the stages below run in order for each event that opens or joins an incident.</p>
          <div className="ml-flow">
            {FLOW.map(([h, p, f, hot], i) => (
              <div className={`ml-step ${hot ? 'ml-hot' : ''}`} key={h}><span className="ml-n">{String(i + 1).padStart(2, '0')}</span><h4>{h}</h4><p>{p}</p><p className="ml-file" style={{ marginTop: 8 }}>{f}</p></div>
            ))}
          </div>
          <p className="ml-note">Pipeline: raw data → normalisation → feature engineering (in <span className="ml-mono">analysis.py</span>) → model → prediction with explanation → risk score → policy-gated response. Each model’s output is stored in <span className="ml-mono">model_predictions</span> with its version, and analyst decisions are stored for the feedback loop.</p>
        </section>

        {err && <div className="ml-notice" role="alert" style={{ marginTop: 40 }}>Could not load the exported model data ({err}). Run <span className="ml-mono">python -m scripts.export_ml_demo</span> and rebuild.</div>}
        {!err && !demo && <p className="ml-note" style={{ marginTop: 40 }}>Loading exported model data…</p>}

        {demo && model && (
          <>
            <section className="ml-section" id="models"><h2>Models</h2>
              <p className="ml-lede">Only components that exist in the repository are listed. Numbers come from each model’s recorded metadata.</p>
              <Models m={demo.models} /></section>

            <section className="ml-section" id="results"><h2>Results</h2>
              <p className="ml-lede">The triage model beats both baselines on held-out synthetic data. The anomaly and phishing figures are on each model’s card above.</p>
              <Results m={demo.models} /></section>

            <section className="ml-section" id="demo"><h2>Live demo</h2>
              <p className="ml-lede">Change the alert features and watch the real triage model respond. The phishing and anomaly tabs replay real outputs, because scikit-learn cannot run in a static Vercel deployment; each panel is labelled accordingly.</p>
              <Demo demo={demo} model={model} /></section>

            <section className="ml-section" id="stack"><h2>Technical stack</h2>
              <div className="ml-cols">
                <article className="ml-card"><h4>ML</h4><div className="ml-chips">
                  {['Python ' + env.python, 'XGBoost ' + env.xgboost, 'scikit-learn ' + env.sklearn, 'pandas', 'NumPy', 'joblib', 'networkx'].map((c) => <span className="ml-chip" key={c}>{c}</span>)}</div>
                  <ul><li>XGBoost saved as native JSON (no pickle)</li><li>scikit-learn bundles load only if their SHA-256 matches</li><li>Seeded training, versioned artifacts</li></ul></article>
                <article className="ml-card"><h4>Platform</h4><div className="ml-chips">
                  {['FastAPI', 'SQLAlchemy', 'Alembic', 'PostgreSQL', 'React', 'Vite', 'Docker Compose', 'pytest', 'Vitest'].map((c) => <span className="ml-chip" key={c}>{c}</span>)}</div>
                  <ul><li>JWT cookie sessions, RBAC, CSRF header, audit log</li><li>Playbooks with approval, verification, rollback</li></ul></article>
                <article className="ml-card"><h4>Optional integrations</h4><div className="ml-chips">
                  {['Wazuh', 'TheHive', 'Cortex', 'MISP'].map((c) => <span className="ml-chip" key={c}>{c}</span>)}</div>
                  <ul><li>None is required to run the platform</li><li>Redis is not used by the platform (only by MISP in the optional SIEM overlay)</li></ul></article>
              </div>
              <div className="ml-card" style={{ marginTop: 14 }}><h4>Reproduce</h4>
                <pre className="ml-code">{`pip install -r requirements-dev.txt
python -m soar.cli train-models          # seeded; writes models/<name>/metadata.json
python -m ai.triage.ml_triage_analyzer --test
python -m pytest tests/test_ml.py
python -m scripts.export_ml_demo         # refreshes this page's data`}</pre></div>
            </section>

            <section className="ml-section" id="limits"><h2>Limitations</h2>
              <div className="ml-card"><ul>
                <li>All training and evaluation data is synthetic or hand-written; there are no real-incident accuracy claims.</li>
                <li>The triage label means “worth acting on”, a policy statement, so background internet scanning is labelled benign.</li>
                <li>The phishing text model saw 121 templated messages; the indicator rules carry half the score.</li>
                <li>The blast-radius score and the risk-score weights are expert defaults, not validated against labelled incidents.</li>
                <li>Playbook steps are at-most-once and the API defaults to a single worker; multi-worker behaviour is not load-tested.</li>
                <li>This page is static. The full platform, with authentication and a database, runs from Docker Compose; the hosted page does not include a backend.</li>
              </ul></div>
            </section>
          </>
        )}

        <footer className="ml-foot">Model data exported {demo ? new Date(demo.generated_at).toUTCString() : '…'}. Source: AI_MODELS.md and models/*/metadata.json in the repository.</footer>
      </main>
    </div>
  );
}
