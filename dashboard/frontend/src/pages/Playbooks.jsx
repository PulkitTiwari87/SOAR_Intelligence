import { useState } from 'react';
import { Link } from 'react-router-dom';
import { GitBranch } from 'lucide-react';
import { api } from '../api';
import { Async, fmtDate, StatusBadge, useLoad } from '../ui';

const RISK_CLASS = { low: 'step-risk-low', medium: 'step-risk-med', high: 'step-risk-high' };
const RISK_LABEL = { low: 'LOW', medium: 'MED', high: 'HIGH' };

function RiskBadge({ risk }) {
  return <span className={`step-risk ${RISK_CLASS[risk] || 'step-risk-low'}`}>{RISK_LABEL[risk] || (risk || '').toUpperCase()}</span>;
}

function EnabledBadge({ enabled }) {
  return <span className={`pb-state-badge ${enabled ? 'enabled' : 'disabled'}`}>{enabled ? 'ENABLED' : 'DISABLED'}</span>;
}

/* Horizontal execution chain */
function ExecChain({ steps }) {
  return (
    <div className="pb-chain">
      {steps.map((s, i) => {
        const gated = s.approval === 'required';
        return (
          <span key={s.id} className="pb-chain-item">
            {i > 0 && <span className="pb-chain-plus">+</span>}
            <span className={`pb-step ${gated ? 'gated' : ''}`} title={s.params ? JSON.stringify(s.params) : undefined}>
              <span className="pb-step-num">{i + 1}.</span>
              <strong className="pb-step-action">{s.action}</strong>
              <RiskBadge risk={s.risk} />
              {gated && <span className="pb-gate-badge"><GitBranch size={9} /> awaits approval</span>}
            </span>
          </span>
        );
      })}
    </div>
  );
}

function PlaybookCard({ p }) {
  return (
    <div className="pb-card">
      {/* Row 1: Title + Version + State */}
      <div className="pb-card-header">
        <div className="pb-card-header-left">
          <span className="pb-title">{p.name}</span>
          <span className="pb-version">v{p.version}</span>
          <EnabledBadge enabled={p.enabled} />
        </div>
      </div>

      {/* Description */}
      <p className="pb-desc">{p.description}</p>

      {/* Trigger */}
      {p.trigger && Object.keys(p.trigger).length > 0 && (
        <div className="pb-trigger-row">
          <span className="pb-trigger-label">TRIGGER:</span>
          <code className="pb-trigger-value">{JSON.stringify(p.trigger)}</code>
          {p.conditions?.length > 0 && (
            <>
              <span className="pb-trigger-label" style={{ marginLeft: 8 }}>CONDITIONS:</span>
              <code className="pb-trigger-value">{p.conditions.map((c) => `${c.field} ${c.op || 'eq'} ${c.value}`).join('; ')}</code>
            </>
          )}
        </div>
      )}

      {/* Execution chain */}
      {p.steps?.length > 0 && (
        <>
          <div className="pb-chain-label">STEPS ({p.steps.length}):</div>
          <ExecChain steps={p.steps} />
        </>
      )}
    </div>
  );
}

/* ─── Executions tab ─── */
function ExecutionsTab({ execs }) {
  return (
    <Async state={execs} empty={(d) => d.length === 0} emptyText="No playbook has run yet.">
      {(rows) => (
        <div className="table-container">
          <table>
            <thead>
              <tr>
                <th>Playbook</th><th>Status</th><th>Incident</th><th>Started</th><th>By</th><th>Steps</th>
              </tr>
            </thead>
            <tbody>
              {rows.map((x) => (
                <tr key={x.id}>
                  <td><strong>{x.playbook}</strong></td>
                  <td><StatusBadge status={x.status} /></td>
                  <td><Link to={`/incidents/${x.incident_number}`}>{x.incident_number}</Link></td>
                  <td style={{ fontFamily: 'var(--font-mono)', fontSize: 12 }}>{fmtDate(x.created_at)}</td>
                  <td style={{ color: 'var(--text-secondary)' }}>{x.requested_by}</td>
                  <td>
                    <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap' }}>
                      {x.steps.map((s) => (
                        <span key={s.id} title={s.result?.detail}>
                          <StatusBadge status={s.status} /> {s.action}
                        </span>
                      ))}
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </Async>
  );
}

/* ─── Effectiveness tab ─── */
function EffectivenessTab({ stats }) {
  return (
    <Async state={stats}>
      {(s) => (
        <div className="card">
          <div className="grid-4" style={{ marginBottom: 16 }}>
            {[
              ['Executions', s.totals.executions],
              ['Steps', s.totals.steps],
              ['Approvals', s.totals.approvals],
              ['Avg decision', s.approvals.avg_seconds_to_decision ? `${s.approvals.avg_seconds_to_decision}s` : '—'],
            ].map(([label, val]) => (
              <div key={label} className="stat-card">
                <div className="stat-info">
                  <h3>{label}</h3>
                  <span className="stat-value">{val}</span>
                </div>
              </div>
            ))}
          </div>
          <div className="table-container">
            <table>
              <thead><tr><th>Action</th><th>Runs</th><th>Succeeded</th><th>Skipped</th><th>Failed</th><th>Verified</th></tr></thead>
              <tbody>
                {Object.entries(s.actions).map(([k, a]) => (
                  <tr key={k}>
                    <td style={{ fontFamily: 'var(--font-mono)', fontSize: 12 }}>{k}</td>
                    <td>{a.runs}</td>
                    <td style={{ color: 'var(--success)' }}>{a.succeeded || 0}</td>
                    <td style={{ color: 'var(--text-muted)' }}>{a.skipped || 0}</td>
                    <td style={{ color: 'var(--critical)' }}>{a.failed || 0}</td>
                    <td>{a.verified || 0}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          {s.recommendations.map((r, i) => <p key={i} style={{ marginTop: 8, color: 'var(--text-secondary)', fontSize: 13 }}>• {r}</p>)}
        </div>
      )}
    </Async>
  );
}

/* ─── Main Page ─── */
export default function Playbooks() {
  const [tab, setTab] = useState('Playbooks');
  const [filter, setFilter] = useState('');
  const [stateFilter, setStateFilter] = useState('all');
  const defs = useLoad(async () => (await api.get('/playbooks')).data, []);
  const execs = useLoad(async () => (await api.get('/executions?limit=50')).data.executions, [tab]);
  const stats = useLoad(async () => (await api.get('/playbooks/stats')).data, [tab]);

  return (
    <div className="page-container pb-page">

      {/* ── Page header ── */}
      <div className="pb-page-header">
        <div className="pb-page-header-left">
          <h1 className="pb-page-title">Playbooks</h1>
          <div className="pb-page-meta">
            <span className="pb-lifecycle">
              Lifecycle: <span className="pb-lifecycle-chain">trigger → conditions → steps → approval → execution → verification → rollback</span>
            </span>
          </div>
        </div>
        {defs.data && (
          <div className="pb-page-stats">
            <div className="pb-stat-block">
              <span className="pb-stat-label">Enabled:</span>
              <span className="pb-stat-value">{defs.data.playbooks.filter((p) => p.enabled).length}</span>
            </div>
            <div className="pb-stat-block">
              <span className="pb-stat-label">Disabled:</span>
              <span className="pb-stat-value">{defs.data.playbooks.filter((p) => !p.enabled).length}</span>
            </div>
          </div>
        )}
      </div>

      {/* ── Tabs ── */}
      <div className="pb-tabs" role="tablist">
        {[
          { id: 'Playbooks', count: defs.data?.playbooks?.length },
          { id: 'Executions', count: execs.data?.length },
          { id: 'Effectiveness & ROI', count: null },
        ].map(({ id, count }) => (
          <button
            key={id}
            role="tab"
            aria-selected={tab === id}
            className={`pb-tab ${tab === id ? 'active' : ''}`}
            onClick={() => setTab(id)}
          >
            {id}{count != null && <span className="pb-tab-count">{count}</span>}
          </button>
        ))}
      </div>

      {/* ── Playbooks tab ── */}
      {tab === 'Playbooks' && (
        <Async state={defs}>
          {(d) => {
            const all = d.playbooks || [];
            const filtered = all.filter((p) => {
              const matchSearch = !filter || p.name.toLowerCase().includes(filter.toLowerCase()) || p.description?.toLowerCase().includes(filter.toLowerCase());
              const matchState = stateFilter === 'all' || (stateFilter === 'enabled' && p.enabled) || (stateFilter === 'disabled' && !p.enabled);
              return matchSearch && matchState;
            });
            const enabledCount = all.filter((p) => p.enabled).length;
            const disabledCount = all.filter((p) => !p.enabled).length;

            return (
              <>
                {/* Filter bar */}
                <div className="pb-filter-row">
                  <input
                    className="pb-filter-input"
                    placeholder="Filter by keyword…"
                    value={filter}
                    onChange={(e) => setFilter(e.target.value)}
                    aria-label="Filter playbooks"
                  />
                  <div className="pb-state-pills">
                    {[
                      { v: 'all', label: `All (${all.length})` },
                      { v: 'enabled', label: `Enabled (${enabledCount})` },
                      { v: 'disabled', label: `Disabled (${disabledCount})` },
                    ].map(({ v, label }) => (
                      <button
                        key={v}
                        className={`pb-state-pill ${stateFilter === v ? 'active' : ''}`}
                        onClick={() => setStateFilter(v)}
                      >{label}</button>
                    ))}
                  </div>
                </div>

                {/* Cards */}
                <div className="pb-cards-list">
                  {filtered.length === 0 ? (
                    <div style={{ textAlign: 'center', padding: '32px', color: 'var(--text-muted)' }}>No playbooks match the filter.</div>
                  ) : (
                    filtered.map((p) => <PlaybookCard key={p.name} p={p} />)
                  )}
                </div>

                {/* Footer */}
                <div className="pb-footer">
                  <span>Showing {filtered.length} of {all.length} playbooks</span>
                </div>
              </>
            );
          }}
        </Async>
      )}

      {tab === 'Executions' && <ExecutionsTab execs={execs} />}
      {tab === 'Effectiveness & ROI' && <EffectivenessTab stats={stats} />}
    </div>
  );
}
