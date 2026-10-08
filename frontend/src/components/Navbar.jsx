import { NavLink, useNavigate } from 'react-router-dom';
import { useAuth } from '../context/AuthContext';

export default function Navbar() {
  const { user, logout } = useAuth();
  const navigate = useNavigate();

  const handleLogout = () => {
    logout();
    navigate('/login');
  };

  if (!user) return null;

  const links = [
    { to: '/dashboard', label: 'Dashboard', roles: ['ADMIN', 'ISSUER', 'HR', 'USER', 'AUDITOR'] },
    { to: '/verify', label: 'Verify Document', roles: ['HR', 'USER'] },
    { to: '/verifications', label: 'Verification History', roles: ['HR', 'USER', 'ADMIN', 'AUDITOR'] },
    { to: '/credentials', label: 'Credentials', roles: ['ADMIN', 'ISSUER', 'HR', 'USER'] },
    { to: '/organizations', label: 'Organizations', roles: ['ADMIN'] },
    { to: '/issuers', label: 'Issuers', roles: ['ADMIN'] },
    { to: '/audit-logs', label: 'Audit Logs', roles: ['ADMIN', 'AUDITOR'] },
  ];

  return (
    <nav className="navbar">
      <div className="navbar-brand">
        <NavLink to="/dashboard">SecureWork Verify</NavLink>
      </div>
      <div className="navbar-links">
        {links
          .filter((l) => l.roles.includes(user.role))
          .map((l) => (
            <NavLink key={l.to} to={l.to} className={({ isActive }) => isActive ? 'active' : ''}>
              {l.label}
            </NavLink>
          ))}
      </div>
      <div className="navbar-user">
        <span className="user-info">
          {user.name} <span className="role-badge">{user.role}</span>
        </span>
        <button onClick={handleLogout} className="btn btn-sm btn-outline">Logout</button>
      </div>
    </nav>
  );
}
