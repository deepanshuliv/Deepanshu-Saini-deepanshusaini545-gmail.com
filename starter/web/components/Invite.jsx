import React, { useEffect, useState } from 'react';
import { publicApi } from '../api.js';

// The public invite page. The token in the URL is the credential; the server returns
// only the org name, the role and the email — nothing about the org's contents.
export function Invite({ token, onDone }) {
  const [invite, setInvite] = useState(null);
  const [error, setError] = useState(null);
  const [name, setName] = useState('');
  const [password, setPassword] = useState('');
  const [submitError, setSubmitError] = useState(null);

  useEffect(() => {
    publicApi('GET', `/invites/${encodeURIComponent(token)}`)
      .then(setInvite)
      .catch((e) => setError(e));
  }, [token]);

  async function accept(e) {
    e.preventDefault();
    setSubmitError(null);
    try {
      await publicApi('POST', `/invites/${encodeURIComponent(token)}/accept`, { name, password });
      onDone('Your account is ready. Sign in to continue.');
    } catch (err) {
      setSubmitError(err);
    }
  }

  if (error) {
    return (
      <main className="login">
        <div className="login-card">
          <div className="brand">RemoteOps</div>
          <h1>Invitation unavailable</h1>
          <p className="error" data-testid="invite-error" data-error-code={error.code} role="alert">
            {error.status === 404 ? 'This invitation link is not valid.' : error.message}
          </p>
          <a href="/">Go to sign in</a>
        </div>
      </main>
    );
  }
  if (!invite) return <div className="boot">Checking invitation…</div>;

  return (
    <main className="login">
      <form className="login-card" onSubmit={accept}>
        <div className="brand">RemoteOps</div>
        <h1>Join {invite.orgName}</h1>
        <p>
          You have been invited as <strong data-testid="invite-role">{invite.role}</strong>.
        </p>
        <label>
          Email
          <input data-testid="invite-email" value={invite.email} readOnly />
        </label>
        <label>
          Your name
          <input data-testid="invite-name" value={name} onChange={(e) => setName(e.target.value)} />
        </label>
        <label>
          Password <span className="hint">(at least 8 characters; your existing password if you already have an account)</span>
          <input data-testid="invite-password" type="password" value={password} onChange={(e) => setPassword(e.target.value)} />
        </label>
        {submitError && (
          <p className="error" data-testid="invite-submit-error" data-error-code={submitError.code} role="alert">
            {submitError.message}
          </p>
        )}
        <button data-testid="invite-submit" type="submit" className="primary">Accept invitation</button>
      </form>
    </main>
  );
}
