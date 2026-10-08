/**
 * Centralized API service layer.
 * Handles base URL, JWT headers, error handling, and 401 auto-logout.
 */

const API_URL = import.meta.env.VITE_API_URL || 'http://localhost:5000/api';

/**
 * Get stored JWT token.
 */
export const getToken = () => localStorage.getItem('sw_token');

/**
 * Get stored user object.
 */
export const getUser = () => {
  const raw = localStorage.getItem('sw_user');
  return raw ? JSON.parse(raw) : null;
};

/**
 * Save auth data to localStorage.
 */
export const saveAuth = (user, token) => {
  localStorage.setItem('sw_token', token);
  localStorage.setItem('sw_user', JSON.stringify(user));
};

/**
 * Clear auth data.
 */
export const clearAuth = () => {
  localStorage.removeItem('sw_token');
  localStorage.removeItem('sw_user');
};

/**
 * Build headers with optional JWT.
 */
const authHeaders = () => {
  const token = getToken();
  const headers = {};
  if (token) headers['Authorization'] = `Bearer ${token}`;
  return headers;
};

/**
 * Generic fetch wrapper with error handling.
 */
const request = async (endpoint, options = {}) => {
  const url = `${API_URL}${endpoint}`;
  const config = {
    ...options,
    headers: {
      ...authHeaders(),
      ...options.headers,
    },
  };

  // Don't set Content-Type for FormData (browser sets boundary automatically)
  if (!(options.body instanceof FormData)) {
    config.headers['Content-Type'] = config.headers['Content-Type'] || 'application/json';
  }

  const res = await fetch(url, config);
  const data = await res.json().catch(() => ({}));

  if (!res.ok) {
    // Auto-logout on 401
    if (res.status === 401) {
      clearAuth();
      window.location.href = '/login';
    }
    const msg = data?.error?.message || data?.message || `Request failed (${res.status})`;
    throw new Error(msg);
  }

  return data;
};

// ─── Auth ───────────────────────────────────────────────────────────────────

export const authAPI = {
  register: (body) =>
    request('/auth/register', { method: 'POST', body: JSON.stringify(body) }),

  login: (body) =>
    request('/auth/login', { method: 'POST', body: JSON.stringify(body) }),

  me: () => request('/auth/me'),
};

// ─── Organizations ──────────────────────────────────────────────────────────

export const orgAPI = {
  list: (params = '') => request(`/organizations${params ? '?' + params : ''}`),
  get: (id) => request(`/organizations/${id}`),
  create: (body) =>
    request('/organizations', { method: 'POST', body: JSON.stringify(body) }),
  approve: (id) =>
    request(`/organizations/${id}/approve`, { method: 'PATCH' }),
  suspend: (id, body) =>
    request(`/organizations/${id}/suspend`, { method: 'PATCH', body: JSON.stringify(body) }),
  revoke: (id, body) =>
    request(`/organizations/${id}/revoke`, { method: 'PATCH', body: JSON.stringify(body) }),
  verify: (id, body) =>
    request(`/organizations/${id}/verify`, { method: 'PATCH', body: JSON.stringify(body) }),
};

// ─── Issuers ────────────────────────────────────────────────────────────────

export const issuerAPI = {
  list: (params = '') => request(`/issuers${params ? '?' + params : ''}`),
  get: (id) => request(`/issuers/${id}`),
  getMe: () => request('/issuers/me'),
  register: (body) =>
    request('/issuers/register', { method: 'POST', body: JSON.stringify(body) }),
  approve: (id) =>
    request(`/issuers/${id}/approve`, { method: 'PATCH' }),
  suspend: (id, body) =>
    request(`/issuers/${id}/suspend`, { method: 'PATCH', body: JSON.stringify(body) }),
  revoke: (id, body) =>
    request(`/issuers/${id}/revoke`, { method: 'PATCH', body: JSON.stringify(body) }),
};

// ─── Credentials ────────────────────────────────────────────────────────────

export const credentialAPI = {
  list: (params = '') => request(`/credentials${params ? '?' + params : ''}`),
  get: (id) => request(`/credentials/${id}`),
  getVersions: (id) => request(`/credentials/${id}/versions`),
  getTimeline: (id) => request(`/credentials/${id}/timeline`),

  issue: (formData) =>
    request('/credentials/issue', { method: 'POST', body: formData }),

  addVersion: (id, formData) =>
    request(`/credentials/${id}/versions`, { method: 'POST', body: formData }),

  revoke: (id, body) =>
    request(`/credentials/${id}/revoke`, { method: 'PATCH', body: JSON.stringify(body) }),
};

// ─── Verifications ──────────────────────────────────────────────────────────

export const verificationAPI = {
  verify: (formData) =>
    request('/verifications/verify', { method: 'POST', body: formData }),

  list: (params = '') => request(`/verifications${params ? '?' + params : ''}`),
  get: (id) => request(`/verifications/${id}`),
  getEvidence: (id) => request(`/verifications/${id}/evidence`),
};

// ─── Audit Logs ─────────────────────────────────────────────────────────────

export const auditAPI = {
  list: (params = '') => request(`/audit-logs${params ? '?' + params : ''}`),
  validate: () => request('/audit-logs/validate'),
};
