import { API_URL } from '../config';
import { useState } from 'react';
import axios from 'axios';
import { Fish, Send, AlertTriangle, CheckCircle, Shield, Globe, Lock, Clock, Info } from 'lucide-react';

const API = API_URL;

const SAMPLE_EMAILS = [
  { label: '| CEO Fraud BEC', text: 'Hi John, I need you to urgently wire $45,000 to our new vendor. This is time-sensitive and confidential. Do not discuss with anyone. Use account 4829103847 at Swiss National Bank. Reply when done. - CEO' },
  { label: 'Check Legitimate IT', text: 'Hi team, This is a reminder that we will be performing scheduled server maintenance this Saturday from 2 AM to 6 AM EST. Please save your work before then. Contact the IT helpdesk if you have questions. Thanks, IT Department' },
  { label: 'Phishing Link', text: 'URGENT: Your account has been compromised! Click here immediately to verify your identity: http://secure-login.fake-bank.com/verify. You must act within 24 hours or your account will be permanently locked.' },
];

export default function PhishingAnalyzer() {
  const [activeTab, setActiveTab] = useState('email');
  const [emailText, setEmailText] = useState('');
  const [url, setUrl] = useState('');
  const [result, setResult] = useState(null);
  const [certResult, setCertResult] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');

  const handleAnalyze = async () => {
    if (!emailText.trim()) return;
    setLoading(true);
    setError('');
    setResult(null);
    try {
      const res = await axios.post(`${API}/ai/phishing`, { emailText });
      setResult(res.data);
    } catch (err) {
      setError(err.response?.data?.error || 'Analysis failed');
    }
    setLoading(false);
  };

  const handleCheckCert = async () => {
    if (!url.trim()) return;
    setLoading(true);
    setError('');
    setCertResult(null);
    try {
      const res = await axios.post(`${API}/ai/certificate`, { url });
      setCertResult(res.data);
    } catch (err) {
      setError(err.response?.data?.error || 'Certificate check failed');
    }
    setLoading(false);
  };

  const score = result?.confidence_score || result?.phishing_score || 0;
  const isPhishing = score > 50;

  return (
    <div className="page-container">
      <div className="page-header">
        <h1><Fish size={28} style={{ verticalAlign: 'middle', marginRight: '10px' }} />Phishing & SSL Analyzer</h1>
        <p>Analyze suspicious emails and verify website security certificates</p>
      </div>

      {/* Tabs */}
      <div style={{ display: 'flex', gap: '12px', marginBottom: '24px' }}>
        <button 
          className={`btn ${activeTab === 'email' ? 'btn-primary' : 'btn-ghost'}`}
          onClick={() => setActiveTab('email')}
        >
          <Send size={16} /> Email Analyzer
        </button>
        <button 
          className={`btn ${activeTab === 'cert' ? 'btn-primary' : 'btn-ghost'}`}
          onClick={() => setActiveTab('cert')}
        >
          <Globe size={16} /> Certificate Checker
        </button>
      </div>

      <div className="grid-2">
        {/* Input Column */}
        <div className="card">
          {activeTab === 'email' ? (
            <>
              <h3 className="section-title">Email Content</h3>
              <div style={{ display: 'flex', gap: '8px', marginBottom: '12px', flexWrap: 'wrap' }}>
                {SAMPLE_EMAILS.map(s => (
                  <button key={s.label} className="btn btn-ghost btn-sm" onClick={() => setEmailText(s.text)}>
                    {s.label}
                  </button>
                ))}
              </div>
              <textarea
                className="input"
                placeholder="Paste the full email text here..."
                value={emailText}
                onChange={(e) => setEmailText(e.target.value)}
                style={{ minHeight: '280px' }}
              />
              <button className="btn btn-primary" onClick={handleAnalyze} disabled={loading || !emailText.trim()}
                style={{ marginTop: '16px', width: '100%' }}>
                {loading ? <><div className="spinner" style={{ width: '16px', height: '16px', borderWidth: '2px' }} /> Analyzing...</> : <><Send size={16} /> Analyze Email</>}
              </button>
            </>
          ) : (
            <>
              <h3 className="section-title">Target URL / Hostname</h3>
              <p style={{ color: 'var(--text-secondary)', fontSize: '0.85rem', marginBottom: '16px' }}>
                Enter a domain (e.g., google.com) or URL to check its SSL/TLS certificate status.
              </p>
              <input
                className="input"
                placeholder="e.g., google.com or https://example.com"
                value={url}
                onChange={(e) => setUrl(e.target.value)}
                style={{ marginBottom: '16px' }}
              />
              <button className="btn btn-primary" onClick={handleCheckCert} disabled={loading || !url.trim()}
                style={{ width: '100%' }}>
                {loading ? <><div className="spinner" style={{ width: '16px', height: '16px', borderWidth: '2px' }} /> Checking...</> : <><Globe size={16} /> Check Certificate</>}
              </button>
              
              <div style={{ marginTop: '24px', padding: '16px', background: 'rgba(59, 130, 246, 0.05)', borderRadius: 'var(--radius-md)', border: '1px solid rgba(59, 130, 246, 0.2)' }}>
                <h4 style={{ display: 'flex', alignItems: 'center', gap: '8px', fontSize: '0.9rem', color: 'var(--accent)', marginBottom: '8px' }}>
                  <Info size={16} /> Why check SSL?
                </h4>
                <p style={{ fontSize: '0.8rem', color: 'var(--text-secondary)', lineHeight: 1.5 }}>
                  Phishing sites often use free, short-lived certificates or certificates with mismatched hostnames. Checking the issuer and validity period helps identify suspicious sites.
                </p>
              </div>
            </>
          )}
        </div>

        {/* Result Column */}
        <div className="card">
          <h3 className="section-title">Result</h3>

          {error && <div className="login-error" style={{ marginBottom: '16px' }}>{error}</div>}

          {/* Empty State */}
          {activeTab === 'email' && !result && !error && (
            <div style={{ textAlign: 'center', padding: '80px 0', color: 'var(--text-muted)' }}>
              <Shield size={48} style={{ marginBottom: '12px', opacity: 0.3 }} />
              <p>Analyze an email to see phishing detection details</p>
            </div>
          )}
          {activeTab === 'cert' && !certResult && !error && (
            <div style={{ textAlign: 'center', padding: '80px 0', color: 'var(--text-muted)' }}>
              <Lock size={48} style={{ marginBottom: '12px', opacity: 0.3 }} />
              <p>Check a URL to see SSL/TLS certificate details</p>
            </div>
          )}

          {/* Email Result */}
          {activeTab === 'email' && result && (
            <div style={{ animation: 'fadeIn 0.3s ease' }}>
              <div style={{
                textAlign: 'center', padding: '32px', marginBottom: '20px',
                background: isPhishing ? 'rgba(239, 68, 68, 0.08)' : 'rgba(34, 197, 94, 0.08)',
                borderRadius: 'var(--radius-lg)', border: `1px solid ${isPhishing ? 'rgba(239, 68, 68, 0.2)' : 'rgba(34, 197, 94, 0.2)'}`,
              }}>
                {isPhishing ?
                  <AlertTriangle size={40} style={{ color: 'var(--danger)', marginBottom: '8px' }} /> :
                  <CheckCircle size={40} style={{ color: 'var(--success)', marginBottom: '8px' }} />
                }
                <div style={{ fontSize: '3rem', fontWeight: 800, color: isPhishing ? 'var(--danger)' : 'var(--success)' }}>
                  {score}%
                </div>
                <div style={{ fontSize: '1.1rem', fontWeight: 600, color: isPhishing ? 'var(--danger)' : 'var(--success)', marginTop: '4px' }}>
                  {isPhishing ? '⚠ PHISHING DETECTED' : '✓ LEGITIMATE'}
                </div>
              </div>

              <div style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
                {result.category && (
                  <div className="flex-between" style={{ padding: '10px 0', borderBottom: '1px solid var(--glass-border)' }}>
                    <span style={{ color: 'var(--text-secondary)' }}>Category</span>
                    <span className="badge badge-critical">{result.category}</span>
                  </div>
                )}
                {result.prediction && (
                  <div className="flex-between" style={{ padding: '10px 0', borderBottom: '1px solid var(--glass-border)' }}>
                    <span style={{ color: 'var(--text-secondary)' }}>Prediction</span>
                    <strong>{result.prediction}</strong>
                  </div>
                )}
                {result.indicators && result.indicators.length > 0 && (
                  <div>
                    <span style={{ color: 'var(--text-secondary)', fontSize: '0.85rem' }}>Key Indicators:</span>
                    <ul style={{ marginTop: '8px', paddingLeft: '20px', color: 'var(--text-primary)', fontSize: '0.85rem' }}>
                      {result.indicators.map((ind, i) => <li key={i} style={{ marginBottom: '4px' }}>{ind}</li>)}
                    </ul>
                  </div>
                )}
              </div>
            </div>
          )}

          {/* Certificate Result */}
          {activeTab === 'cert' && certResult && (
            <div style={{ animation: 'fadeIn 0.3s ease' }}>
              <div style={{
                textAlign: 'center', padding: '32px', marginBottom: '20px',
                background: certResult.valid ? 'rgba(34, 197, 94, 0.08)' : 'rgba(239, 68, 68, 0.08)',
                borderRadius: 'var(--radius-lg)', border: `1px solid ${certResult.valid ? 'rgba(34, 197, 94, 0.2)' : 'rgba(239, 68, 68, 0.2)'}`,
              }}>
                {certResult.valid ? 
                  <CheckCircle size={40} style={{ color: 'var(--success)', marginBottom: '8px' }} /> :
                  <AlertTriangle size={40} style={{ color: 'var(--danger)', marginBottom: '8px' }} />
                }
                <div style={{ fontSize: '1.5rem', fontWeight: 800, color: certResult.valid ? 'var(--success)' : 'var(--danger)' }}>
                  {certResult.valid ? 'SECURE CONNECTION' : 'INSECURE / FAILED'}
                </div>
                <div style={{ fontSize: '0.9rem', color: 'var(--text-secondary)', marginTop: '4px' }}>
                  {certResult.valid ? `TLS Protocol: ${certResult.protocol}` : certResult.error}
                </div>
              </div>

              {certResult.valid && (
                <div style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
                  <div className="flex-between" style={{ padding: '10px 0', borderBottom: '1px solid var(--glass-border)' }}>
                    <span style={{ color: 'var(--text-secondary)', display: 'flex', alignItems: 'center', gap: '6px' }}><Globe size={14} /> Hostname</span>
                    <strong>{certResult.hostname}</strong>
                  </div>
                  <div className="flex-between" style={{ padding: '10px 0', borderBottom: '1px solid var(--glass-border)' }}>
                    <span style={{ color: 'var(--text-secondary)', display: 'flex', alignItems: 'center', gap: '6px' }}><Shield size={14} /> Subject / CN</span>
                    <strong>{certResult.subject}</strong>
                  </div>
                  <div className="flex-between" style={{ padding: '10px 0', borderBottom: '1px solid var(--glass-border)' }}>
                    <span style={{ color: 'var(--text-secondary)', display: 'flex', alignItems: 'center', gap: '6px' }}><Lock size={14} /> Issuer</span>
                    <strong>{certResult.issuer}</strong>
                  </div>
                  <div className="flex-between" style={{ padding: '10px 0', borderBottom: '1px solid var(--glass-border)' }}>
                    <span style={{ color: 'var(--text-secondary)', display: 'flex', alignItems: 'center', gap: '6px' }}><Clock size={14} /> Expiration</span>
                    <span style={{ color: certResult.days_left < 30 ? 'var(--danger)' : 'var(--success)', fontWeight: 600 }}>
                      {certResult.expires}
                    </span>
                  </div>
                  <div style={{ 
                    padding: '12px', 
                    background: certResult.days_left < 30 ? 'rgba(239, 68, 68, 0.1)' : 'rgba(34, 197, 94, 0.1)',
                    borderRadius: 'var(--radius-md)',
                    marginTop: '8px',
                    textAlign: 'center',
                    fontSize: '0.9rem',
                    fontWeight: 600,
                    color: certResult.days_left < 30 ? 'var(--danger)' : 'var(--success)'
                  }}>
                    {certResult.days_left < 0 ? 'Certificate Expired!' : `Expires in ${certResult.days_left} days`}
                  </div>
                </div>
              )}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

