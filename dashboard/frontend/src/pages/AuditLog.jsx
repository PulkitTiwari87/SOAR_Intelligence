import { API_URL } from '../config';
import { useState, useEffect } from 'react';
import axios from 'axios';
import { ClipboardList } from 'lucide-react';

const API = API_URL;

export default function AuditLog() {
  const [logs, setLogs] = useState([]);
  useEffect(() => {
    axios.get(`${API}/system/audit`).then(r => setLogs(r.data.logs)).catch(() => {});
  }, []);

  return (
    <div className="page-container">
      <div className="page-header">
        <h1><ClipboardList size={28} style={{ verticalAlign: 'middle', marginRight: '10px' }} />Audit Log</h1>
        <p>Complete record of all analyst actions and system events</p>
      </div>

      <div className="card">
        <div className="table-container">
          <table>
            <thead>
              <tr><th>Timestamp</th><th>User</th><th>Action</th><th>Details</th><th>IP</th></tr>
            </thead>
            <tbody>
              {logs.length === 0 ? (
                <tr><td colSpan="5" style={{ textAlign: 'center', color: 'var(--text-muted)', padding: '40px' }}>No audit logs yet</td></tr>
              ) : logs.map(log => (
                <tr key={log._id}>
                  <td style={{ fontSize: '0.8rem', color: 'var(--text-muted)', whiteSpace: 'nowrap' }}>
                    {new Date(log.timestamp).toLocaleString()}
                  </td>
                  <td><span className="badge badge-analyst">{log.username}</span></td>
                  <td style={{ fontFamily: 'monospace', fontSize: '0.85rem', color: 'var(--accent)' }}>{log.action}</td>
                  <td style={{ fontSize: '0.85rem', maxWidth: '300px', overflow: 'hidden', textOverflow: 'ellipsis' }}>{log.details}</td>
                  <td style={{ fontFamily: 'monospace', fontSize: '0.8rem', color: 'var(--text-muted)' }}>{log.ipAddress}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
