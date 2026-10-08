import { useState, useEffect } from 'react';
import { Link } from 'react-router-dom';
import { credentialAPI } from '../services/api';
import { useAuth } from '../context/AuthContext';

export default function CredentialListPage() {
  const { user } = useAuth();
  const [data, setData] = useState({ credentials: [], total: 0, page: 1, totalPages: 1 });
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [page, setPage] = useState(1);

  useEffect(() => {
    setLoading(true);
    credentialAPI.list(`page=${page}&limit=15`)
      .then((res) => setData(res.data))
      .catch((err) => setError(err.message))
      .finally(() => setLoading(false));
  }, [page]);

  return (
    <div className="page">
      <div className="page-header">
        <h1>Credentials</h1>
        {user?.role === 'ISSUER' && (
          <Link to="/credentials/issue" className="btn btn-primary">Issue Credential</Link>
        )}
      </div>

      {error && <div className="alert alert-error">{error}</div>}
      {loading && <div className="loading">Loading...</div>}

      {!loading && data.credentials?.length === 0 && (
        <div className="empty-state"><p>No credentials found.</p></div>
      )}

      {!loading && data.credentials?.length > 0 && (
        <>
          <div className="table-container">
            <table>
              <thead>
                <tr>
                  <th>Title</th>
                  <th>Type</th>
                  <th>Status</th>
                  <th>Issued</th>
                  <th>Actions</th>
                </tr>
              </thead>
              <tbody>
                {data.credentials.map((c) => (
                  <tr key={c._id}>
                    <td>{c.title || '—'}</td>
                    <td>{c.credentialType || '—'}</td>
                    <td>
                      <span className={`status-pill ${c.status === 'ACTIVE' ? 'status-verified' : c.status === 'REVOKED' ? 'status-danger' : 'status-warning'}`}>
                        {c.status}
                      </span>
                    </td>
                    <td>{new Date(c.createdAt).toLocaleDateString()}</td>
                    <td>
                      <Link to={`/credentials/${c._id}`} className="btn btn-sm btn-outline">View</Link>
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
