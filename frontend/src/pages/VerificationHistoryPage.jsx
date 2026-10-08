import { useState, useEffect } from 'react';
import { Link } from 'react-router-dom';
import { verificationAPI } from '../services/api';

export default function VerificationHistoryPage() {
  const [data, setData] = useState({ verifications: [], total: 0, page: 1, totalPages: 1 });
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [page, setPage] = useState(1);

  useEffect(() => {
    setLoading(true);
    verificationAPI.list(`page=${page}&limit=15`)
      .then((res) => setData(res.data))
      .catch((err) => setError(err.message))
      .finally(() => setLoading(false));
  }, [page]);

  return (
    <div className="page">
      <div className="page-header">
        <h1>Verification History</h1>
      </div>

      {error && <div className="alert alert-error">{error}</div>}
      {loading && <div className="loading">Loading...</div>}

      {!loading && data.verifications?.length === 0 && (
        <div className="empty-state">
          <p>No verifications found.</p>
          <Link to="/verify" className="btn btn-primary">Verify a Document</Link>
        </div>
      )}

      {!loading && data.verifications?.length > 0 && (
        <>
          <div className="table-container">
            <table>
              <thead>
                <tr>
                  <th>Date</th>
                  <th>Result</th>
                  <th>Trust Level</th>
                  <th>Document</th>
                  <th>Actions</th>
                </tr>
              </thead>
              <tbody>
                {data.verifications.map((v) => (
                  <tr key={v._id}>
                    <td>{new Date(v.createdAt).toLocaleString()}</td>
                    <td><span className={`status-pill ${v.result === 'VERIFIED' ? 'status-verified' : v.result === 'NOT_FOUND' || v.result === 'ALTERED' ? 'status-danger' : 'status-warning'}`}>{v.result}</span></td>
                    <td>{v.trustLevel || '—'}</td>
                    <td>{v.originalFilename || '—'}</td>
                    <td>
                      <Link to={`/verifications/${v._id}`} className="btn btn-sm btn-outline">Details</Link>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>

          <div className="pagination">
            <button disabled={page <= 1} onClick={() => setPage(page - 1)} className="btn btn-sm btn-outline">Previous</button>
            <span>Page {data.page} of {data.totalPages}</span>
            <button disabled={page >= data.totalPages} onClick={() => setPage(page + 1)} className="btn btn-sm btn-outline">Next</button>
          </div>
        </>
      )}
    </div>
  );
}
