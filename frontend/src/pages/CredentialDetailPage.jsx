import { useState, useEffect } from 'react';
import { useParams, Link } from 'react-router-dom';
import { credentialAPI } from '../services/api';
import { useAuth } from '../context/AuthContext';

export default function CredentialDetailPage() {
  const { id } = useParams();
  const { user } = useAuth();
  const [credential, setCredential] = useState(null);
  const [versions, setVersions] = useState([]);
  const [timeline, setTimeline] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [revokeReason, setRevokeReason] = useState('');
  const [revoking, setRevoking] = useState(false);

  const load = () => {
    setLoading(true);
    Promise.all([
      credentialAPI.get(id),
      credentialAPI.getVersions(id).catch(() => null),
      credentialAPI.getTimeline(id).catch(() => null),
    ])
      .then(([cRes, vRes, tRes]) => {
        setCredential(cRes.data.credential);
        if (vRes) setVersions(vRes.data.versions || []);
        if (tRes) setTimeline(tRes.data.timeline || []);
      })
      .catch((err) => setError(err.message))
      .finally(() => setLoading(false));
  };

  useEffect(load, [id]);

  const handleRevoke = async () => {
    if (!revokeReason.trim()) return;
    setRevoking(true);
    try {
      await credentialAPI.revoke(id, { reason: revokeReason });
      setRevokeReason('');
      load();
    } catch (err) {
      setError(err.message);
    } finally {
      setRevoking(false);
    }
  };

  if (loading) return <div className="page"><div className="loading">Loading...</div></div>;
  if (error) return <div className="page"><div className="alert alert-error">{error}</div></div>;
  if (!credential) return <div className="page"><div className="empty-state">Credential not found.</div></div>;

  const c = credential;

  return (
    <div className="page">
      <div className="page-header">
        <Link to="/credentials" className="btn btn-sm btn-outline">← Back</Link>
        <h1>Credential Details</h1>
      </div>

      <div className="info-card">
        <div className="info-row"><span className="info-label">Title</span><span>{c.title}</span></div>
        <div className="info-row"><span className="info-label">Type</span><span>{c.credentialType}</span></div>
        <div className="info-row"><span className="info-label">Status</span><span className={`status-pill ${c.status === 'ACTIVE' ? 'status-verified' : 'status-danger'}`}>{c.status}</span></div>
        <div className="info-row"><span className="info-label">Description</span><span>{c.description || '—'}</span></div>
        <div className="info-row"><span className="info-label">Document Hash</span><span className="mono">{c.documentHash || '—'}</span></div>
        <div className="info-row"><span className="info-label">Signature</span><span className="mono truncate">{c.signature || '—'}</span></div>
        <div className="info-row"><span className="info-label">Issued</span><span>{new Date(c.createdAt).toLocaleString()}</span></div>
        {c.expiresAt && <div className="info-row"><span className="info-label">Expires</span><span>{new Date(c.expiresAt).toLocaleString()}</span></div>}
        {c.revokedAt && <div className="info-row"><span className="info-label">Revoked</span><span>{new Date(c.revokedAt).toLocaleString()}</span></div>}
        {c.revocationReason && <div className="info-row"><span className="info-label">Revocation Reason</span><span>{c.revocationReason}</span></div>}
      </div>

      {/* Revoke (ISSUER only, own credentials, not already revoked) */}
      {user?.role === 'ISSUER' && c.status === 'ACTIVE' && (
        <div className="action-section">
          <h3>Revoke Credential</h3>
          <div className="inline-form">
            <input
              type="text"
              placeholder="Reason for revocation (required)"
              value={revokeReason}
              onChange={(e) => setRevokeReason(e.target.value)}
            />
            <button className="btn btn-danger" disabled={revoking || !revokeReason.trim()} onClick={handleRevoke}>
              {revoking ? 'Revoking...' : 'Revoke'}
            </button>
          </div>
        </div>
      )}

      {/* Versions */}
      {versions.length > 0 && (
        <div className="section">
          <h3>Version History</h3>
          <div className="table-container">
            <table>
              <thead>
                <tr><th>Version</th><th>Date</th><th>Change Reason</th><th>Hash</th></tr>
              </thead>
              <tbody>
                {versions.map((v, i) => (
                  <tr key={v._id || i}>
                    <td>{v.versionNumber || i + 1}</td>
                    <td>{new Date(v.createdAt).toLocaleString()}</td>
                    <td>{v.changeReason || '—'}</td>
                    <td className="mono truncate">{v.documentHash || '—'}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* Timeline */}
      {timeline.length > 0 && (
        <div className="section">
          <h3>Lifecycle Timeline</h3>
          <div className="timeline">
            {timeline.map((t, i) => (
              <div key={t._id || i} className="timeline-item">
                <div className="timeline-marker"></div>
                <div className="timeline-content">
                  <strong>{t.action}</strong>
                  <span className="text-muted"> — {new Date(t.createdAt).toLocaleString()}</span>
                  {t.performedBy && <p className="text-muted">By: {t.performedBy.name || t.performedBy.email || '—'}</p>}
                </div>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}
