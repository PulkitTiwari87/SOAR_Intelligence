import { useState } from 'react';
import { Link } from 'react-router-dom';
import { Copy, Search } from 'lucide-react';
import { api, errMsg } from '../api';
import { useAuth } from '../auth';
import { Async, useLoad } from '../ui';

/* ─── Verdict config ─── */
const VERDICT_CFG = {
  malicious:    { cls: 'verdict-malicious',    label: 'MALICIOUS' },
  suspicious:   { cls: 'verdict-suspicious',   label: 'SUSPICIOUS' },
  benign:       { cls: 'verdict-benign',        label: 'BENIGN' },
  unknown:      { cls: 'verdict-unknown',       label: 'UNKNOWN' },
  not_enriched: { cls: 'verdict-not-enriched', label: 'NOT ENRICHED' },
  queued:       { cls: 'verdict-queued',        label: 'QUEUED' },
};

function VerdictBadge({ verdict }) {
  const cfg = VERDICT_CFG[verdict] || { cls: 'verdict-unknown', label: verdict?.toUpperCase() || '—' };
  return <span className={`ioc-verdict ${cfg.cls}`}>{cfg.label}</span>;
}

function TypeBadge({ type }) {
  const t = (type || 'IOC').toUpperCase().replace('IPV4', 'IP').replace('IPV6', 'IP').replace('SHA256', 'HASH').replace('SHA-256', 'HASH');
  return <span className="ioc-type-badge">{t}</span>;
}

function ScoreBar({ score, conf }) {
  // score/confidence are 0..1 from the backend
  const pct = score != null ? Math.round(Math.max(0, Math.min(1, score)) * 100) : null;
  const confPct = conf != null ? Math.round(Math.max(0, Math.min(1, conf)) * 100) : null;
  const color = pct >= 70 ? 'var(--critical)' : pct >= 40 ? 'var(--warning)' : 'var(--success)';
  return (
    <div className="ioc-score-cell">
      <span className="ioc-score-main">{pct ?? 'N/A'}</span>
      {pct != null && <span className="ioc-score-denom">/100</span>}
      {confPct != null && <span className="ioc-score-conf">({confPct}%<br/>cf)</span>}
      {pct != null && (
        <div className="ioc-score-bar">
          <div style={{ width: `${pct}%`, background: color, height: '100%', borderRadius: 2 }} />
        </div>
      )}
    </div>
  );
}

function CopyBtn({ value }) {
  const [copied, setCopied] = useState(false);
  return (
    <button
      className="ioc-copy-btn"
      aria-label="Copy"
      onClick={() => { navigator.clipboard.writeText(value).catch(() => {}); setCopied(true); setTimeout(() => setCopied(false), 1200); }}
    >
      {copied ? '✓' : <Copy size={11} />}
    </button>
  );
}

/* ─── Actionable table ─── */
function ActionableTable({ rows }) {
  if (!rows.length) return null;
  return (
    <div className="ioc-table-wrap">
      <table className="ioc-table">
        <thead>
          <tr>
            <th>TYPE</th>
            <th>INDICATOR VALUE</th>
            <th>VERDICT</th>
            <th>SCORE / CONF</th>
            <th>PRIMARY<br/>PROVIDER</th>
            <th>REFERENCED<br/>INC.</th>
            <th>LAST SEEN<br/>(UTC)</th>
          </tr>
        </thead>
        <tbody>
          {rows.map((o) => {
            const ls = o.last_seen ? new Date(o.last_seen) : null;
            return (
              <tr key={o.id} className="ioc-row">
                <td><TypeBadge type={o.type} /></td>
                <td className="ioc-value-cell">
                  <span className="ioc-value">{o.value}</span>
                  <CopyBtn value={o.value} />
                  {o.context?.note && <span className="ioc-value-note">{o.context.note}</span>}
                </td>
                <td><VerdictBadge verdict={o.verdict} /></td>
                <td><ScoreBar score={o.score} conf={o.confidence} /></td>
                <td className="ioc-provider-cell">
                  <span className="ioc-provider-name">{o.provider || '—'}</span>
                  {o.context?.event_id && <span className="ioc-provider-detail">{o.context.event_id}</span>}
                </td>
                <td>
                  {o.incidents?.length > 0
                    ? o.incidents.map((n) => (
                        <Link key={n} to={`/incidents/${n}`} className="ioc-inc-link">{n}</Link>
                      ))
                    : <span className="ioc-muted">None</span>
                  }
                </td>
                <td className="ioc-date-cell">
                  {ls ? (
                    <>
                      <span>{ls.toISOString().slice(0, 10)}</span>
                      <span className="ioc-muted">{ls.toISOString().slice(11, 16)}</span>
                    </>
                  ) : '—'}
                </td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}

/* ─── Observational table ─── */
function ObservationalTable({ rows, onRecheck, rechecking }) {
  if (!rows.length) return null;
  return (
    <div className="ioc-table-wrap">
      <table className="ioc-table">
        <thead>
          <tr>
            <th>TYPE</th>
            <th>INDICATOR VALUE</th>
            <th>VERDICT</th>
            <th>SCORE / CONF</th>
            <th>PRIMARY PROVIDER</th>
            <th>REFERENCED INC.</th>
            <th>LAST SEEN (UTC)</th>
            <th>ACTIONS</th>
          </tr>
        </thead>
        <tbody>
          {rows.map((o) => {
            const ls = o.last_seen ? new Date(o.last_seen) : null;
            return (
              <tr key={o.id} className="ioc-row">
                <td><TypeBadge type={o.type} /></td>
                <td className="ioc-value-cell">
                  <span className="ioc-value">{o.value}</span>
                  <CopyBtn value={o.value} />
                </td>
                <td><VerdictBadge verdict={o.verdict} /></td>
                <td><ScoreBar score={o.score} conf={o.confidence} /></td>
                <td>
                  <span className="ioc-provider-name">{o.provider || '—'}</span>
                </td>
                <td>
                  {o.incidents?.length > 0
                    ? o.incidents.map((n) => <Link key={n} to={`/incidents/${n}`} className="ioc-inc-link">{n}</Link>)
                    : <span className="ioc-muted">None</span>
                  }
                </td>
                <td className="ioc-date-cell">
                  {ls ? (
                    <>
                      <span>{ls.toISOString().slice(0, 10)}</span>
                      <span className="ioc-muted">{ls.toISOString().slice(11, 16)}</span>
                    </>
                  ) : '—'}
                </td>
                <td>
                  {onRecheck && (
                    <button className="ioc-ghost-btn" disabled={rechecking === o.id} onClick={() => onRecheck(o)}>
                      {rechecking === o.id ? '…' : (o.verdict === 'not_enriched' || o.verdict === 'unknown') ? 'Deep query' : 'Re-check'}
                    </button>
                  )}
                </td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}

/* ─── Main Page ─── */
export default function Intel() {
  const { can } = useAuth();
  const [verdict, setVerdict] = useState('');
  const [form, setForm] = useState({ type: 'ip', value: '' });
  const [result, setResult] = useState(null);
  const [enrichError, setEnrichError] = useState('');
  const [rechecking, setRechecking] = useState(null);
  const state = useLoad(async () => (await api.get('/intel/iocs', { params: verdict ? { verdict } : {} })).data.iocs, [verdict]);
  const integ = useLoad(async () => (await api.get('/system/integrations')).data.integrations.find((i) => i.name === 'misp'), []);

  const enrich = async (e) => {
    e.preventDefault(); setEnrichError(''); setResult(null);
    try {
      setResult((await api.post('/intel/enrich', { type: form.type, value: form.value.trim(), force: true })).data);
      state.reload();
    } catch (err) { setEnrichError(errMsg(err)); }
  };

  const recheck = async (o) => {
    setRechecking(o.id);
    try { await api.post('/intel/enrich', { type: o.type, value: o.value, force: true }); state.reload(); }
    catch { /* surfaced via the row staying unenriched */ }
    setRechecking(null);
  };

  return (
    <div className="page-container intel-page">

      {/* ─── Pipeline header ─── */}
      <div className="intel-pipeline-header">
        <div className="intel-pipeline-left">
          <div className="intel-pipeline-title-row">
            <h1 className="intel-pipeline-title">Threat intelligence</h1>
            <span className="intel-pipeline-badges">
              <span className="intel-tag">RFC 1918 scope</span>
              <span className="intel-tag">Local feed files</span>
              <span className="intel-tag">MISP: {integ.data ? integ.data.status.replace('_', ' ') : '…'}</span>
            </span>
          </div>
          <p className="intel-pipeline-desc">
            Providers are evaluated in order: a private/reserved-address scope check (built in), local feed files
            in <code>data/intel/*.txt</code>, and MISP when configured.
          </p>
        </div>
        <div className="intel-unknown-note">
          <span className="intel-unknown-icon">ℹ</span>
          <span>
            <code>'unknown'</code> means no provider had data. It is treated as{' '}
            <strong>missing evidence</strong>, never as safe.
          </span>
        </div>
      </div>

      {/* ─── Enrichment input ─── */}
      {can('analyze:adhoc') && (
        <form onSubmit={enrich} className="intel-enrich-form" aria-label="Enrich an indicator">
          <select
            className="intel-type-select"
            value={form.type}
            onChange={(e) => setForm({ ...form, type: e.target.value })}
            aria-label="Indicator type"
          >
            {[['ip', 'IP address'], ['domain', 'Domain'], ['url', 'URL'], ['hash', 'File hash']].map(([v, label]) => (
              <option key={v} value={v}>{label}</option>
            ))}
          </select>
          <input
            className="intel-value-input"
            placeholder="e.g. 198.51.100.24, payload.exe hash, evil-domain.org"
            value={form.value}
            required maxLength={1000}
            onChange={(e) => setForm({ ...form, value: e.target.value })}
            aria-label="Indicator value"
          />
          <button className="intel-enrich-btn" type="submit">
            <Search size={13} />
            Enrich now
          </button>
        </form>
      )}
      {enrichError && <p role="alert" className="intel-enrich-error">{enrichError}</p>}
      {result && (
        <div className="card" style={{ marginBottom: 16 }}>
          <strong>{result.ioc.value}</strong>
          <table><tbody>{result.results.map((r) => (
            <tr key={r.provider}>
              <td>{r.provider}</td>
              <td><VerdictBadge verdict={r.verdict} /></td>
              <td style={{ fontSize: 12 }}>score {r.score != null ? Math.round(r.score * 100) : 'n/a'} · confidence {r.confidence != null ? Math.round(r.confidence * 100) : 'n/a'}%</td>
            </tr>
          ))}</tbody></table>
        </div>
      )}

      {/* ─── Filters row ─── */}
      <Async state={state} empty={(d) => d.length === 0} emptyText="No indicators yet. They appear when incidents contain public IPs, domains, URLs or file hashes.">
        {(rows) => {
          const flagged = rows.filter((o) => o.verdict === 'malicious' || o.verdict === 'suspicious');
          const other = rows.filter((o) => o.verdict !== 'malicious' && o.verdict !== 'suspicious');

          const counts = {
            all: rows.length,
            malicious: rows.filter((o) => o.verdict === 'malicious').length,
            suspicious: rows.filter((o) => o.verdict === 'suspicious').length,
            benign: rows.filter((o) => o.verdict === 'benign').length,
            unknown: rows.filter((o) => o.verdict === 'unknown').length,
          };

          return (
            <>
              {/* Filters */}
              <div className="intel-filters-row">
                <div className="intel-verdict-pills">
                  <span className="intel-filter-label">Verdict:</span>
                  {[
                    { v: '', label: `All (${counts.all})` },
                    { v: 'malicious', label: `Malicious (${counts.malicious})`, dot: 'var(--critical)' },
                    { v: 'suspicious', label: `Suspicious (${counts.suspicious})`, dot: 'var(--warning)' },
                    { v: 'benign', label: `Benign (${counts.benign})`, dot: 'var(--success)' },
                    { v: 'unknown', label: `Unknown (${counts.unknown})` },
                  ].map(({ v, label, dot }) => (
                    <button
                      key={v}
                      className={`intel-verdict-pill ${verdict === v ? 'active' : ''}`}
                      onClick={() => setVerdict(v)}
                    >
                      {dot && <span style={{ display: 'inline-block', width: 6, height: 6, borderRadius: '50%', background: dot, marginRight: 4 }} />}
                      {label}
                    </button>
                  ))}
                </div>
                <span className="intel-filter-label">{rows.length} indicator{rows.length === 1 ? '' : 's'}</span>
              </div>

              {/* ─── Actionable section ─── */}
              {(verdict === '' || verdict === 'malicious' || verdict === 'suspicious') && flagged.length > 0 && (
                <div className="intel-section">
                  <div className="intel-section-header actionable">
                    <div className="intel-section-header-left">
                      <span className="intel-section-dot critical" />
                      <span className="intel-section-title">Needs attention</span>
                      <span className="intel-triage-badge">{flagged.length}</span>
                    </div>
                  </div>
                  <ActionableTable rows={verdict ? flagged.filter((o) => o.verdict === verdict) : flagged} />
                </div>
              )}

              {/* ─── Observational section ─── */}
              {(verdict === '' || verdict === 'benign' || verdict === 'unknown' || verdict === 'not_enriched') && other.length > 0 && (
                <div className="intel-section" style={{ marginTop: 24 }}>
                  <div className="intel-section-header observational">
                    <div className="intel-section-header-left">
                      <span className="intel-section-dot neutral" />
                      <span className="intel-section-title">Benign / unclassified</span>
                      <span className="intel-triage-badge">{other.length}</span>
                    </div>
                  </div>
                  <ObservationalTable rows={verdict ? other.filter((o) => o.verdict === verdict) : other} onRecheck={can('analyze:adhoc') ? recheck : null} rechecking={rechecking} />
                </div>
              )}
            </>
          );
        }}
      </Async>
    </div>
  );
}
