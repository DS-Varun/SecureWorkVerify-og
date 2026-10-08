import { useState, useEffect } from 'react';
import { auditAPI } from '../services/api';

export default function AuditLogPage() {
  const [data, setData] = useState({ entries: [], total: 0, page: 1, totalPages: 1 });
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [page, setPage] = useState(1);
  const [actionFilter, setActionFilter] = useState('');
  const [chainResult, setChainResult] = useState(null);
  const [validating, setValidating] = useState(false);

  useEffect(() => {
    setLoading(true);
    const params = [`page=${page}`, `limit=20`];
    if (actionFilter) params.push(`action=${actionFilter}`);
    auditAPI.list(params.join('&'))
      .then((res) => setData(res.data))
      .catch((err) => setError(err.message))
      .finally(() => setLoading(false));
  }, [page, actionFilter]);

  const handleValidate = async () => {
    setValidating(true);
    setChainResult(null);
    try {
      const res = await auditAPI.validate();
      setChainResult(res.data);
    } catch (err) {
      setError(err.message);
    } finally {
      setValidating(false);
    }
  };

  return (
    <div className="page">
      <div className="page-header">
        <h1>Audit Logs</h1>
        <button className="btn btn-outline" onClick={handleValidate} disabled={validating}>
          {validating ? 'Validating...' : 'Validate Chain'}
        </button>
      </div>

      {chainResult && (
        <div className={`alert ${chainResult.valid ? 'alert-success' : 'alert-error'}`}>
          <strong>Chain Validation: {chainResult.valid ? '✓ VALID' : '✗ BROKEN'}</strong>
          <span> — {chainResult.count} entries checked</span>
          {chainResult.error && <p>{chainResult.error}</p>}
        </div>
      )}

      <div className="filter-bar">
        <select value={actionFilter} onChange={(e) => { setActionFilter(e.target.value); setPage(1); }}>
          <option value="">All Actions</option>
          <option value="USER_REGISTERED">USER_REGISTERED</option>
          <option value="USER_LOGIN">USER_LOGIN</option>
          <option value="ORGANIZATION_CREATED">ORGANIZATION_CREATED</option>
          <option value="ORGANIZATION_VERIFIED">ORGANIZATION_VERIFIED</option>
          <option value="ORGANIZATION_SUSPENDED">ORGANIZATION_SUSPENDED</option>
          <option value="ORGANIZATION_REVOKED">ORGANIZATION_REVOKED</option>
          <option value="ISSUER_REGISTERED">ISSUER_REGISTERED</option>
          <option value="ISSUER_APPROVED">ISSUER_APPROVED</option>
          <option value="ISSUER_SUSPENDED">ISSUER_SUSPENDED</option>
          <option value="ISSUER_REVOKED">ISSUER_REVOKED</option>
          <option value="ISSUER_KEY_GENERATED">ISSUER_KEY_GENERATED</option>
          <option value="ISSUER_KEY_COMPROMISED">ISSUER_KEY_COMPROMISED</option>
          <option value="DOCUMENT_UPLOADED">DOCUMENT_UPLOADED</option>
          <option value="CREDENTIAL_ISSUED">CREDENTIAL_ISSUED</option>
          <option value="CREDENTIAL_REVOKED">CREDENTIAL_REVOKED</option>
          <option value="CREDENTIAL_VERSION_CREATED">CREDENTIAL_VERSION_CREATED</option>
          <option value="VERIFICATION_PERFORMED">VERIFICATION_PERFORMED</option>
          <option value="VERIFICATION_EVIDENCE_CREATED">VERIFICATION_EVIDENCE_CREATED</option>
        </select>
      </div>

      {error && <div className="alert alert-error">{error}</div>}
      {loading && <div className="loading">Loading...</div>}

      {!loading && data.entries?.length === 0 && (
        <div className="empty-state"><p>No audit log entries found.</p></div>
      )}

      {!loading && data.entries?.length > 0 && (
        <>
          <div className="table-container">
            <table>
              <thead>
                <tr>
                  <th>Seq</th>
                  <th>Action</th>
                  <th>Target</th>
                  <th>Performed By</th>
                  <th>Date</th>
                  <th>Hash</th>
                </tr>
              </thead>
              <tbody>
                {data.entries.map((e) => (
                  <tr key={e._id}>
                    <td>{e.sequenceNumber}</td>
                    <td><span className="action-tag">{e.action}</span></td>
                    <td>{e.targetType}<br /><span className="mono text-muted">{e.targetId?.toString().slice(-8)}</span></td>
                    <td>{e.performedBy?.name || e.performedBy?.email || '—'}</td>
                    <td>{new Date(e.createdAt).toLocaleString()}</td>
                    <td className="mono truncate">{e.currentHash?.slice(0, 16)}...</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>

          <div className="pagination">
            <button disabled={page <= 1} onClick={() => setPage(page - 1)} className="btn btn-sm btn-outline">Previous</button>
            <span>Page {data.page} of {data.totalPages} ({data.total} total)</span>
            <button disabled={page >= data.totalPages} onClick={() => setPage(page + 1)} className="btn btn-sm btn-outline">Next</button>
          </div>
        </>
      )}
    </div>
  );
}
