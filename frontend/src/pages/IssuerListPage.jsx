import { useState, useEffect } from 'react';
import { Link } from 'react-router-dom';
import { issuerAPI } from '../services/api';

export default function IssuerListPage() {
  const [data, setData] = useState({ issuers: [], total: 0 });
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');

  useEffect(() => {
    issuerAPI.list()
      .then((res) => setData(res.data))
      .catch((err) => setError(err.message))
      .finally(() => setLoading(false));
  }, []);

  return (
    <div className="page">
      <div className="page-header">
        <h1>Issuers</h1>
      </div>

      {error && <div className="alert alert-error">{error}</div>}
      {loading && <div className="loading">Loading...</div>}

      {!loading && (!data.issuers || data.issuers.length === 0) && (
        <div className="empty-state"><p>No issuers found.</p></div>
      )}

      {!loading && data.issuers?.length > 0 && (
        <div className="table-container">
          <table>
            <thead>
              <tr><th>Name</th><th>Organization</th><th>Status</th><th>Actions</th></tr>
            </thead>
            <tbody>
              {data.issuers.map((is) => (
                <tr key={is._id}>
                  <td>{is.user?.name || is.userId?.name || '—'}</td>
                  <td>{is.organization?.name || is.organizationId?.name || '—'}</td>
                  <td>
                    <span className={`status-pill ${is.status === 'ACTIVE' ? 'status-verified' : is.status === 'REVOKED' ? 'status-danger' : 'status-warning'}`}>
                      {is.status}
                    </span>
                  </td>
                  <td><Link to={`/issuers/${is._id}`} className="btn btn-sm btn-outline">View</Link></td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
