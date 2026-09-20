/* Shared UI helpers: this module intentionally exports components, constants and a hook together. */
/* eslint-disable react-refresh/only-export-components */
import { useEffect, useState } from 'react';
import { errMsg } from './api';

export const SEV = { 1: 'low', 2: 'medium', 3: 'high', 4: 'critical' };
export const SEV_COLOR = { low: '#22c55e', medium: '#f59e0b', high: '#f97316', critical: '#ef4444' };

/**
 * Fetch on mount and whenever `deps` change; `reload()` refetches. Returns {data, error, loading, reload}.
 * State is only set after the request settles (never synchronously in the effect), stale responses
 * from a superseded request are ignored, and the previous data stays visible while refetching.
 */
export function useLoad(fn, deps = []) {
  const [state, setState] = useState({ data: null, error: null, loading: true });
  const [tick, setTick] = useState(0);
  useEffect(() => {
    let alive = true;
    (async () => {
      try {
        const data = await fn();
        if (alive) setState({ data, error: null, loading: false });
      } catch (e) {
        if (alive) setState({ data: null, error: errMsg(e), loading: false });
      }
    })();
    return () => { alive = false; };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [...deps, tick]);
  return { ...state, reload: () => setTick((t) => t + 1) };
}

export const Loading = ({ text = 'Loading…' }) => (
  <div className="loading-container"><div className="spinner" /><span>{text}</span></div>
);

export const ErrorBox = ({ error, retry }) => (
  <div className="card" role="alert" style={{ borderColor: 'var(--danger)', padding: 20 }}>
    <strong style={{ color: 'var(--danger)' }}>Something went wrong.</strong>
    <p style={{ color: 'var(--text-secondary)', margin: '6px 0 12px' }}>{error}</p>
    {retry && <button className="btn btn-ghost btn-sm" onClick={retry}>Retry</button>}
  </div>
);

export const Empty = ({ text, children }) => (
  <div style={{ textAlign: 'center', padding: '32px 12px', color: 'var(--text-muted)' }}>
    <p>{text}</p>{children}
  </div>
);

/** Renders loading / error / data (with an optional empty check) so pages stay small. */
export function Async({ state, empty, emptyText = 'Nothing here yet.', children }) {
  if (state.loading && !state.data) return <Loading />;
  if (state.error) return <ErrorBox error={state.error} retry={state.reload} />;
  if (empty && empty(state.data)) return <Empty text={emptyText} />;
  return children(state.data);
}

export const SevBadge = ({ level }) => {
  const label = typeof level === 'number' ? SEV[level] : level;
  return <span className={`badge badge-${label}`}>{label}</span>;
};

const STATUS_CLASS = { new: 'open', investigating: 'investigating', awaiting_approval: 'medium', responding: 'high',
  monitoring: 'monitoring', resolved: 'resolved', false_positive: 'false_positive', closed: 'resolved',
  succeeded: 'resolved', completed: 'resolved', failed: 'critical', rejected: 'critical', skipped: 'info',
  pending: 'medium', approved: 'resolved', running: 'investigating', rolled_back: 'info', cancelled: 'info' };
export const StatusBadge = ({ status }) => (
  <span className={`badge badge-${STATUS_CLASS[status] || 'info'}`}>{String(status).replace(/_/g, ' ')}</span>
);

export const fmtDate = (d) => (d ? new Date(d).toLocaleString() : '—');

export function fmtDuration(seconds) {
  if (seconds === null || seconds === undefined) return '—';
  const s = Math.round(seconds);
  if (s < 60) return `${s}s`;
  if (s < 3600) return `${Math.floor(s / 60)}m ${s % 60}s`;
  return `${Math.floor(s / 3600)}h ${Math.floor((s % 3600) / 60)}m`;
}

export const Pager = ({ page, pages, onPage }) => pages > 1 && (
  <div className="flex-gap" style={{ justifyContent: 'center', marginTop: 16 }}>
    <button className="btn btn-ghost btn-sm" disabled={page <= 1} onClick={() => onPage(page - 1)}>Prev</button>
    <span style={{ color: 'var(--text-secondary)' }}>Page {page} of {pages}</span>
    <button className="btn btn-ghost btn-sm" disabled={page >= pages} onClick={() => onPage(page + 1)}>Next</button>
  </div>
);

export const Header = ({ title, sub, children }) => (
  <div className="page-header flex-between" style={{ alignItems: 'flex-start', flexWrap: 'wrap', gap: 12 }}>
    <div><h1>{title}</h1>{sub && <p>{sub}</p>}</div>
    <div className="flex-gap">{children}</div>
  </div>
);

export const Bar = ({ value, color = 'var(--accent)' }) => (
  <div style={{ background: 'var(--bg-input)', borderRadius: 4, height: 8, minWidth: 80 }}>
    <div style={{ width: `${Math.max(0, Math.min(1, value ?? 0)) * 100}%`, background: color, height: 8, borderRadius: 4 }} />
  </div>
);

export const Tabs = ({ tabs, active, onChange }) => (
  <div className="flex-gap" style={{ marginBottom: 16, flexWrap: 'wrap' }} role="tablist">
    {tabs.map((t) => (
      <button key={t} role="tab" aria-selected={active === t} className={`btn btn-sm ${active === t ? 'btn-primary' : 'btn-ghost'}`}
        onClick={() => onChange(t)}>{t}</button>
    ))}
  </div>
);

export const KV = ({ rows }) => (
  <table><tbody>{rows.map(([k, v]) => (
    <tr key={k}><td style={{ color: 'var(--text-secondary)', width: '38%' }}>{k}</td><td>{v ?? '—'}</td></tr>
  ))}</tbody></table>
);

export function Timeline({ items }) {
  return (
    <ol style={{ listStyle: 'none', borderLeft: '2px solid var(--border)', marginLeft: 6, paddingLeft: 16 }}>
      {items.map((t) => (
        <li key={t.id} style={{ marginBottom: 14, position: 'relative' }}>
          <span style={{ position: 'absolute', left: -23, top: 6, width: 10, height: 10, borderRadius: 5, background: 'var(--accent)' }} />
          <div style={{ fontSize: 12, color: 'var(--text-muted)' }}>{fmtDate(t.timestamp)} · {t.kind.replace(/_/g, ' ')} · {t.actor}</div>
          <div style={{ fontWeight: 600 }}>{t.title}</div>
          {t.detail && <div style={{ color: 'var(--text-secondary)', fontSize: 13 }}>{t.detail}</div>}
        </li>
      ))}
    </ol>
  );
}
