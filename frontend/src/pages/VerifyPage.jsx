import { useState, useRef } from 'react';
import { useNavigate } from 'react-router-dom';
import { verificationAPI } from '../services/api';

const STATUS_COLORS = {
  VERIFIED: 'status-verified',
  SOURCE_VERIFIED: 'status-verified',
  SOURCE_FOUND: 'status-warning',
  ALTERED: 'status-danger',
  NOT_FOUND: 'status-danger',
  CREDENTIAL_REVOKED: 'status-danger',
  CREDENTIAL_EXPIRED: 'status-warning',
  ISSUER_SUSPENDED: 'status-warning',
  ISSUER_REVOKED: 'status-danger',
  SIGNATURE_INVALID: 'status-danger',
  KEY_COMPROMISED: 'status-danger',
  MANUAL_REVIEW: 'status-warning',
  UNSUPPORTED_SOURCE: 'status-muted',
};

const STATUS_LABELS = {
  VERIFIED: 'Document Verified — Fully Trusted',
  SOURCE_VERIFIED: 'Source Verified',
  SOURCE_FOUND: 'Source Found (Reduced Trust)',
  ALTERED: 'Document Altered — Integrity Failure',
  NOT_FOUND: 'Document Not Found',
  CREDENTIAL_REVOKED: 'Credential Has Been Revoked',
  CREDENTIAL_EXPIRED: 'Credential Has Expired',
  ISSUER_SUSPENDED: 'Issuer Is Suspended',
  ISSUER_REVOKED: 'Issuer Has Been Revoked',
  SIGNATURE_INVALID: 'Digital Signature Invalid',
  KEY_COMPROMISED: 'Signing Key Compromised',
  MANUAL_REVIEW: 'Manual Review Required',
  UNSUPPORTED_SOURCE: 'Unsupported Source',
};

function FiveChecks({ verification }) {
  if (!verification) return null;

  // Backend returns flat fields: integrityCheck, signatureCheck, issuerTrustCheck,
  // organizationTrustCheck, credentialStatusCheck
  const items = [
    {
      label: '1. Hash Integrity',
      desc: 'SHA-256 file hash matches stored credential hash',
      check: verification.integrityCheck,
    },
    {
      label: '2. Digital Signature',
      desc: 'Ed25519 cryptographic signature is valid',
      check: verification.signatureCheck,
    },
    {
      label: '3. Issuer Trust',
      desc: 'Issuer is active and signing key is not compromised',
      check: verification.issuerTrustCheck,
    },
    {
      label: '4. Organization Trust',
      desc: 'Issuing organization is verified and active',
      check: verification.organizationTrustCheck,
    },
    {
      label: '5. Credential Status',
      desc: 'Credential is active, not revoked, not expired',
      check: verification.credentialStatusCheck,
    },
  ];

  return (
    <div className="five-checks">
      <h3>Verification Checks</h3>
      {items.map((item) => {
        if (!item.check) return null;
        const passed = item.check.passed;
        return (
          <div key={item.label} className={`check-item ${passed ? 'check-pass' : 'check-fail'}`}>
            <div className="check-header">
              <span className="check-icon">{passed ? '✓' : '✗'}</span>
              <strong>{item.label}</strong>
            </div>
            <p className="check-detail">{item.desc}</p>
          </div>
        );
      })}
    </div>
  );
}

export default function VerifyPage() {
  const [file, setFile] = useState(null);
  const [dragOver, setDragOver] = useState(false);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [result, setResult] = useState(null);
  const fileRef = useRef(null);
  const navigate = useNavigate();

  const ALLOWED = ['application/pdf', 'image/png', 'image/jpeg'];
  const MAX_SIZE = 10 * 1024 * 1024;

  const validateFile = (f) => {
    if (!ALLOWED.includes(f.type)) {
      setError('Unsupported file type. Allowed: PDF, PNG, JPEG.');
      return false;
    }
    if (f.size > MAX_SIZE) {
      setError('File too large. Maximum 10 MB.');
      return false;
    }
    return true;
  };

  const handleDrop = (e) => {
    e.preventDefault();
    setDragOver(false);
    const f = e.dataTransfer.files[0];
    if (f && validateFile(f)) {
      setFile(f);
      setError('');
    }
  };

  const handleFileChange = (e) => {
    const f = e.target.files[0];
    if (f && validateFile(f)) {
      setFile(f);
      setError('');
    }
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    if (!file) return setError('Please select a file.');
    setLoading(true);
    setError('');
    setResult(null);
    try {
      const formData = new FormData();
      formData.append('document', file);
      const res = await verificationAPI.verify(formData);
      setResult(res.data.verification);
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="page">
      <div className="page-header">
        <h1>Verify Document</h1>
        <p className="subtitle">Upload a document to verify against stored credentials</p>
      </div>

      <form onSubmit={handleSubmit}>
        <div
          className={`drop-zone ${dragOver ? 'drag-over' : ''} ${file ? 'has-file' : ''}`}
          onDragOver={(e) => { e.preventDefault(); setDragOver(true); }}
          onDragLeave={() => setDragOver(false)}
          onDrop={handleDrop}
          onClick={() => fileRef.current?.click()}
        >
          {file ? (
            <div className="file-info">
              <span className="file-name">{file.name}</span>
              <span className="file-size">({(file.size / 1024).toFixed(1)} KB)</span>
              <button type="button" className="btn btn-sm btn-outline" onClick={(e) => { e.stopPropagation(); setFile(null); setResult(null); }}>
                Remove
              </button>
            </div>
          ) : (
            <div className="drop-text">
              <p><strong>Drop file here</strong> or click to browse</p>
              <p className="text-muted">PDF, PNG, JPEG — max 10 MB</p>
            </div>
          )}
          <input
            ref={fileRef}
            type="file"
            accept=".pdf,.png,.jpg,.jpeg"
            onChange={handleFileChange}
            hidden
          />
        </div>

        {error && <div className="alert alert-error">{error}</div>}

        <button type="submit" className="btn btn-primary" disabled={loading || !file}>
          {loading ? 'Verifying...' : 'Verify Document'}
        </button>
      </form>

      {result && (
        <div className="verification-result">
          <div className={`result-banner ${STATUS_COLORS[result.result] || 'status-muted'}`}>
            <h2>{result.result}</h2>
            <p>{STATUS_LABELS[result.result] || result.result}</p>
            {result.trustLevel && (
              <span className="trust-level">Trust Level: {result.trustLevel}</span>
            )}
          </div>

          <FiveChecks verification={result} />

          {result.explanation && (
            <div className="info-card" style={{marginTop:'1rem'}}>
              <p className="text-muted">{result.explanation}</p>
            </div>
          )}

          <div className="result-actions">
            <button className="btn btn-outline" onClick={() => navigate(`/verifications/${result._id}`)}>
              View Full Details &amp; Evidence
            </button>
          </div>
        </div>
      )}
    </div>
  );
}
