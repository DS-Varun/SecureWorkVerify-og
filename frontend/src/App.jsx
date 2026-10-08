import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom';
import { AuthProvider } from './context/AuthContext';
import ProtectedRoute from './components/ProtectedRoute';
import Navbar from './components/Navbar';

import LoginPage from './pages/LoginPage';
import RegisterPage from './pages/RegisterPage';
import DashboardPage from './pages/DashboardPage';
import VerifyPage from './pages/VerifyPage';
import VerificationHistoryPage from './pages/VerificationHistoryPage';
import VerificationDetailPage from './pages/VerificationDetailPage';
import CredentialListPage from './pages/CredentialListPage';
import CredentialDetailPage from './pages/CredentialDetailPage';
import CredentialIssuePage from './pages/CredentialIssuePage';
import OrganizationListPage from './pages/OrganizationListPage';
import IssuerListPage from './pages/IssuerListPage';
import AuditLogPage from './pages/AuditLogPage';
import NotFoundPage from './pages/NotFoundPage';

export default function App() {
  return (
    <BrowserRouter>
      <AuthProvider>
        <Navbar />
        <main className="main-content">
          <Routes>
            {/* Public */}
            <Route path="/login" element={<LoginPage />} />
            <Route path="/register" element={<RegisterPage />} />

            {/* Protected — all roles */}
            <Route path="/dashboard" element={<ProtectedRoute><DashboardPage /></ProtectedRoute>} />

            {/* Verify — HR, USER */}
            <Route path="/verify" element={<ProtectedRoute roles={['HR', 'USER']}><VerifyPage /></ProtectedRoute>} />

            {/* Verifications — HR, USER, ADMIN, AUDITOR */}
            <Route path="/verifications" element={<ProtectedRoute roles={['HR', 'USER', 'ADMIN', 'AUDITOR']}><VerificationHistoryPage /></ProtectedRoute>} />
            <Route path="/verifications/:id" element={<ProtectedRoute roles={['HR', 'USER', 'ADMIN', 'AUDITOR']}><VerificationDetailPage /></ProtectedRoute>} />

            {/* Credentials — ADMIN, ISSUER, HR, USER */}
            <Route path="/credentials" element={<ProtectedRoute roles={['ADMIN', 'ISSUER', 'HR', 'USER']}><CredentialListPage /></ProtectedRoute>} />
            <Route path="/credentials/issue" element={<ProtectedRoute roles={['ISSUER']}><CredentialIssuePage /></ProtectedRoute>} />
            <Route path="/credentials/:id" element={<ProtectedRoute roles={['ADMIN', 'ISSUER', 'HR', 'USER']}><CredentialDetailPage /></ProtectedRoute>} />

            {/* Organizations — ADMIN */}
            <Route path="/organizations" element={<ProtectedRoute roles={['ADMIN']}><OrganizationListPage /></ProtectedRoute>} />

            {/* Issuers — ADMIN */}
            <Route path="/issuers" element={<ProtectedRoute roles={['ADMIN']}><IssuerListPage /></ProtectedRoute>} />

            {/* Audit Logs — ADMIN, AUDITOR */}
            <Route path="/audit-logs" element={<ProtectedRoute roles={['ADMIN', 'AUDITOR']}><AuditLogPage /></ProtectedRoute>} />

            {/* Redirects */}
            <Route path="/" element={<Navigate to="/dashboard" replace />} />

            {/* 404 */}
            <Route path="*" element={<NotFoundPage />} />
          </Routes>
        </main>
      </AuthProvider>
    </BrowserRouter>
  );
}
