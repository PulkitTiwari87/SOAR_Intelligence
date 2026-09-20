import { useState } from 'react';
import { Link } from 'react-router-dom';
import { api, errMsg } from '../api';
import { useAuth } from '../auth';
import { Async, fmtDate, Header, StatusBadge, Tabs, useLoad } from '../ui';

export default function Approvals() {
  const { can } = useAuth();
  const [tab, setTab] = useState('pending');
  const [notes, setNotes] = useState({});
  const [msg, setMsg] = useState(null);
  const state = useLoad(async () => (await api.get(`/approvals?status=${tab === 'history' ? '' : 'pending'}`)).data.approvals, [tab]);

  const decide = async (a, approve) => {
    setMsg(null);
    try {
      await api.post(`/approvals/${a.id}/decide`, { approve, note: notes[a.id] || '' });
      setMsg({ ok: true, text: `${a.action} ${approve ? 'approved' : 'rejected'}` });
      state.reload();
    } catch (e) { setMsg({ ok: false, text: errMsg(e) }); }
  };
  const mayDecide = (a) => can(a.risk === 'high' ? 'approve:high' : 'approve:medium');

  return (
    <div className="page-container">
      <Header title="Approvals" sub="Response actions above the auto-execute ceiling wait here for a human decision. Every decision is recorded." />
      <Tabs tabs={['pending', 'history']} active={tab} onChange={setTab} />
      {msg && <div className="card" role="status" style={{ borderColor: msg.ok ? 'var(--success)' : 'var(--danger)', marginBottom: 12 }}>{msg.text}</div>}
      <Async state={state} empty={(d) => d.length === 0} emptyText={tab === 'pending' ? 'No approvals are waiting. 🎉' : 'No approval history yet.'}>
        {(rows) => rows.map((a) => (
          <div key={a.id} className="card" style={{ marginBottom: 12 }}>
            <div className="flex-between" style={{ flexWrap: 'wrap', gap: 8 }}>
              <div>
                <strong style={{ fontSize: 16 }}>{a.action}</strong>{' '}
                <span className={`badge badge-${a.risk === 'high' ? 'critical' : 'medium'}`}>{a.risk} risk</span>{' '}
                <StatusBadge status={a.status} />
                <div style={{ color: 'var(--text-secondary)', margin: '6px 0' }}>{a.reason}</div>
                <div style={{ fontSize: 12, color: 'var(--text-muted)' }}>
                  Incident <Link to={`/incidents/${a.incident_number}`}>{a.incident_number}</Link> · requested by {a.requested_by} · {fmtDate(a.requested_at)}
                  {a.status === 'pending' && ` · expires ${fmtDate(a.expires_at)}`}
                  {a.decided_by && ` · ${a.status} by ${a.decided_by} ${fmtDate(a.decided_at)}${a.decision_note ? `: ${a.decision_note}` : ''}`}
                </div>
                <pre style={{ fontSize: 11, marginTop: 6 }}>{JSON.stringify(a.params)}</pre>
              </div>
              {a.status === 'pending' && (
                mayDecide(a) ? (
                  <div style={{ minWidth: 260 }}>
                    <input className="input" placeholder="Decision note" aria-label="Decision note" value={notes[a.id] || ''} maxLength={1000}
                      onChange={(e) => setNotes({ ...notes, [a.id]: e.target.value })} />
                    <div className="flex-gap" style={{ marginTop: 8 }}>
                      <button className="btn btn-success btn-sm" onClick={() => decide(a, true)}>Approve</button>
                      <button className="btn btn-danger btn-sm" onClick={() => decide(a, false)}>Reject</button>
                    </div>
                  </div>
                ) : <span style={{ color: 'var(--text-muted)', fontSize: 12 }}>Your role cannot decide {a.risk}-risk approvals.</span>
              )}
            </div>
          </div>
        ))}
      </Async>
    </div>
  );
}
