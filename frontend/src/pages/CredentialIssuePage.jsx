import { useState, useRef } from 'react';
import { useNavigate } from 'react-router-dom';
import { credentialAPI } from '../services/api';

export default function CredentialIssuePage() {
  const navigate = useNavigate();
  const fileRef = useRef(null);
  const [form, setForm] = useState({
    recipientId: '',
    credentialType: 'DEGREE',
    title: '',
    description: '',
    expiresAt: '',
  });
  const [file, setFile] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [success, setSuccess] = useState('');

  const handleSubmit = async (e) => {
    e.preventDefault();
    if (!file) return setError('Document file is required.');
    setLoading(true);
    setError('');
    setSuccess('');

    const formData = new FormData();
    formData.append('document', file);
    formData.append('recipientId', form.recipientId);
    formData.append('credentialType', form.credentialType);
    formData.append('title', form.title);
    if (form.description) formData.append('description', form.description);
    if (form.expiresAt) formData.append('expiresAt', form.expiresAt);

    try {
      const res = await credentialAPI.issue(formData);
      setSuccess('Credential issued successfully!');
      setTimeout(() => navigate('/credentials'), 1500);
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="page">
      <div className="page-header">
        <h1>Issue Credential</h1>
        <p className="subtitle">Sign and issue a new credential</p>
      </div>

      {error && <div className="alert alert-error">{error}</div>}
      {success && <div className="alert alert-success">{success}</div>}

      <form onSubmit={handleSubmit} className="form-card">
        <div className="form-group">
          <label htmlFor="recipientId">Recipient User ID</label>
          <input id="recipientId" type="text" required value={form.recipientId}
            onChange={(e) => setForm({ ...form, recipientId: e.target.value })}
            placeholder="MongoDB ObjectId of the recipient user" />
        </div>

        <div className="form-group">
          <label htmlFor="title">Title</label>
          <input id="title" type="text" required value={form.title}
            onChange={(e) => setForm({ ...form, title: e.target.value })}
            placeholder="e.g. Bachelor of Computer Science" />
        </div>

        <div className="form-group">
          <label htmlFor="credentialType">Credential Type</label>
          <select id="credentialType" value={form.credentialType}
            onChange={(e) => setForm({ ...form, credentialType: e.target.value })}>
            <option value="DEGREE">Degree</option>
            <option value="CERTIFICATE">Certificate</option>
            <option value="LICENSE">License</option>
            <option value="TRANSCRIPT">Transcript</option>
            <option value="LETTER">Letter</option>
            <option value="OTHER">Other</option>
          </select>
        </div>

        <div className="form-group">
          <label htmlFor="description">Description (optional)</label>
          <textarea id="description" value={form.description}
            onChange={(e) => setForm({ ...form, description: e.target.value })}
            placeholder="Additional details..." rows={3} />
        </div>

        <div className="form-group">
          <label htmlFor="expiresAt">Expiry Date (optional)</label>
          <input id="expiresAt" type="date" value={form.expiresAt}
            onChange={(e) => setForm({ ...form, expiresAt: e.target.value })} />
        </div>

        <div className="form-group">
          <label>Document File</label>
          <div className="file-select" onClick={() => fileRef.current?.click()}>
            {file ? <span>{file.name} ({(file.size / 1024).toFixed(1)} KB)</span> : <span>Click to select PDF, PNG, or JPEG</span>}
          </div>
          <input ref={fileRef} type="file" accept=".pdf,.png,.jpg,.jpeg" hidden
            onChange={(e) => setFile(e.target.files[0])} />
        </div>

        <button type="submit" className="btn btn-primary" disabled={loading}>
          {loading ? 'Issuing...' : 'Issue Credential'}
        </button>
      </form>
    </div>
  );
}
