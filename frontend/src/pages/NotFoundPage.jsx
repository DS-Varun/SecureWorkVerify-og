import { Link } from 'react-router-dom';

export default function NotFoundPage() {
  return (
    <div className="auth-page">
      <div className="auth-card">
        <h1>404</h1>
        <p className="subtitle">Page not found</p>
        <p>The page you're looking for doesn't exist.</p>
        <Link to="/dashboard" className="btn btn-primary">Go to Dashboard</Link>
      </div>
    </div>
  );
}
