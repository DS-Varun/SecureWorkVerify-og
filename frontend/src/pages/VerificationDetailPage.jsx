import { useState, useEffect } from 'react';
import { useParams, Link } from 'react-router-dom';
import { verificationAPI } from '../services/api';

export default function VerificationDetailPage() {
  const { id } = useParams();
  const [verification, setVerification] = useState(null);
  const [evidence, setEvidence] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');

  useEffect(() => {
    Promise.all([
      verificationAPI.get(id),
      verificationAPI.getEvidence(id).catch(() => null),
    ])
      .then(([vRes, eRes]) => {
        setVerification(vRes.data.verification);
        if (eRes) setEvidence(eRes.data.evidence);
      })
      .catch((err) => setError(err.message))
      .finally(() => setLoading(false));
  }, [id]);

  if (loading) return <div className="page"><div className="loading">Loading...</div></div>;
  if (error) return <div className="page"><div className="alert alert-error">{error}</div></div>;
  if (!verification) return <div className="page"><div className="empty-state">Verification not found.</div></div>;

  const v = verification;

  return (
    <div className="page">
      <div className="page-header">
        <Link to="/verifications" className="btn btn-sm btn-outline">← Back</Link>
        <h1>Verification Details</h1>
      </div>

      <div className={`result-banner ${v.result === 'VERIFIED' ? 'status-verified' : v.result === 'NOT_FOUND' || v.result === 'ALTERED' ? 'status-danger' : 'status-warning'}`}>
        <h2>{v.result}</h2>
        {v.trustLevel && <span className="trust-level">Trust Level: {v.trustLevel}</span>}
      </div>

      <div className="info-card">
        <div className="info-row"><span className="info-label">Verification ID</span><span className="mono">{v._id}</span></div>
        <div className="info-row"><span className="info-label">Date</span><span>{new Date(v.createdAt).toLocaleString()}</span></div>
        <div className="info-row"><span className="info-label">Document</span><span>{v.credentialId?.title || '—'}</span></div>
        <div className="info-row"><span className="info-label">Document Hash</span><span className="mono">{v.uploadedDocumentHash || '—'}</span></div>
        <div className="info-row"><span className="info-label">Result</span><span className="status-pill">{v.result}</span></div>
        <div className="info-row"><span className="info-label">Trust Level</span><span>{v.trustLevel || '—'}</span></div>
      </div>

      {/* Five Checks */}
      <div className="five-checks">
        <h3>Five Verification Checks</h3>
        {[
          { key: 'integrityCheck',         label: '1. HASH_MATCH' },
          { key: 'signatureCheck',          label: '2. DIGITAL_SIGNATURE' },
          { key: 'organizationTrustCheck',  label: '3. DOMAIN_VERIFICATION' },
          { key: 'issuerTrustCheck',        label: '4. ISSUER_STATUS' },
          { key: 'credentialStatusCheck',   label: '5. CREDENTIAL_STATUS' },
        ].map((item) => {
          const check = v[item.key];
          if (!check) return null;
          return (
            <div key={item.key} className={`check-item ${check.passed ? 'check-pass' : 'check-fail'}`}>
              <div className="check-header">
                <span className="check-icon">{check.passed ? '✓' : '✗'}</span>
                <strong>{item.label}</strong>
              </div>
              <p className="check-detail">{check.detail || check.message || '—'}</p>
            </div>
          );
        })}
      </div>

      {/* Evidence Trail */}
      {evidence && evidence.length > 0 && (
        <div className="evidence-section">
          <h3>Evidence Trail</h3>
          {evidence.map((e, i) => (
            <div key={i} className="evidence-item">
              <div className="evidence-header">
                <strong>{e.type || e.evidenceType || 'Evidence'}</strong>
                <span className={`status-pill ${e.evidenceStatus === 'VALID' ? 'status-verified' : 'status-danger'}`}>
                  {e.evidenceStatus === 'VALID' ? 'PASS' : 'FAIL'}
                </span>
              </div>
              {e.detail && <p>{e.detail}</p>}
              {e.expected && <p><span className="info-label">Expected:</span> <span className="mono">{e.expected}</span></p>}
              {e.actual && <p><span className="info-label">Actual:</span> <span className="mono">{e.actual}</span></p>}
              {e.message && <p>{e.message}</p>}
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
