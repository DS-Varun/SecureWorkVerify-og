import { useAuth } from '../context/AuthContext';
import { Link } from 'react-router-dom';

const ROLE_ACTIONS = {
  ADMIN: [
    { to: '/organizations', label: 'Manage Organizations', desc: 'Create, approve, suspend organizations' },
    { to: '/issuers', label: 'Manage Issuers', desc: 'Approve, suspend, revoke issuers' },
    { to: '/credentials', label: 'View All Credentials', desc: 'Browse credentials across the platform' },
    { to: '/verifications', label: 'All Verifications', desc: 'Review all verification records' },
    { to: '/audit-logs', label: 'Audit Logs', desc: 'Review hash-chained audit trail' },
  ],
  ISSUER: [
    { to: '/credentials', label: 'My Credentials', desc: 'View and manage issued credentials' },
    { to: '/credentials/issue', label: 'Issue Credential', desc: 'Issue a new signed credential' },
  ],
  HR: [
    { to: '/verify', label: 'Verify Document', desc: 'Upload and verify a document' },
    { to: '/verifications', label: 'Verification History', desc: 'Review past verifications' },
    { to: '/credentials', label: 'Credentials', desc: 'View organization credentials' },
  ],
  USER: [
    { to: '/verify', label: 'Verify Document', desc: 'Upload and verify a document' },
    { to: '/verifications', label: 'My Verifications', desc: 'View your verification history' },
    { to: '/credentials', label: 'My Credentials', desc: 'View credentials issued to you' },
  ],
  AUDITOR: [
    { to: '/audit-logs', label: 'Audit Logs', desc: 'Review hash-chained audit trail' },
    { to: '/verifications', label: 'All Verifications', desc: 'Review all verification records' },
  ],
};

export default function DashboardPage() {
  const { user } = useAuth();
  const actions = ROLE_ACTIONS[user?.role] || [];

  return (
    <div className="page">
      <div className="page-header">
        <h1>Dashboard</h1>
        <p className="subtitle">
          Welcome back, <strong>{user?.name}</strong>
        </p>
      </div>

      <div className="info-card">
        <div className="info-row">
          <span className="info-label">Name</span>
          <span>{user?.name}</span>
        </div>
        <div className="info-row">
          <span className="info-label">Email</span>
          <span>{user?.email}</span>
        </div>
        <div className="info-row">
          <span className="info-label">Role</span>
          <span className="role-badge">{user?.role}</span>
        </div>
      </div>

      <h2>Available Actions</h2>
      <div className="action-grid">
        {actions.map((a) => (
          <Link key={a.to} to={a.to} className="action-card">
            <h3>{a.label}</h3>
            <p>{a.desc}</p>
          </Link>
        ))}
      </div>
    </div>
  );
}
