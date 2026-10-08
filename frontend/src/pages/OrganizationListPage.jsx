import { useState, useEffect } from 'react';
import { Link } from 'react-router-dom';
import { orgAPI } from '../services/api';

export default function OrganizationListPage() {
  const [data, setData] = useState({ organizations: [], total: 0 });
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');

  useEffect(() => {
    orgAPI.list()
      .then((res) => setData(res.data))
      .catch((err) => setError(err.message))
      .finally(() => setLoading(false));
  }, []);

  return (
    <div className="page">
      <div className="page-header">
        <h1>Organizations</h1>
      </div>

      {error && <div className="alert alert-error">{error}</div>}
      {loading && <div className="loading">Loading...</div>}

      {!loading && (!data.organizations || data.organizations.length === 0) && (
        <div className="empty-state"><p>No organizations found.</p></div>
      )}

      {!loading && data.organizations?.length > 0 && (
        <div className="table-container">
          <table>
            <thead>
              <tr><th>Name</th><th>Type</th><th>Status</th><th>Actions</th></tr>
            </thead>
            <tbody>
              {data.organizations.map((o) => (
                <tr key={o._id}>
                  <td>{o.name}</td>
                  <td>{o.type}</td>
                  <td>
                    <span className={`status-pill ${o.organizationVerificationStatus === 'VERIFIED' ? 'status-verified' : o.organizationVerificationStatus === 'REVOKED' ? 'status-danger' : 'status-warning'}`}>
                      {o.organizationVerificationStatus || o.status || 'PENDING'}
                    </span>
                  </td>
                  <td><Link to={`/organizations/${o._id}`} className="btn btn-sm btn-outline">View</Link></td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
