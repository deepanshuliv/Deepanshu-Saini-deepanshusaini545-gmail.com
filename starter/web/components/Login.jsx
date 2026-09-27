import React, { useState } from 'react';
import { login } from '../api.js';

// The first screen, and the one most likely to be reached in a broken state. Every
// failure is stated on the page, in words, and stays until the next attempt. The text
// is the server's: a wrong password and an unknown account read the same.
export function Login({ notice }) {
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState(null);
  const [busy, setBusy] = useState(false);

  async function submit(e) {
    e.preventDefault();
    setError(null);
    if (!email.trim() || !password) {
      const missing = [!email.trim() && 'email', !password && 'password'].filter(Boolean).join(' and ');
      setError({ code: 'VALIDATION', message: `Enter your ${missing} to sign in.` });
      return;
    }
    setBusy(true);
    try {
      await login(email, password);
    } catch (err) {
      setError({ code: err.code, message: err.message });
      setBusy(false);
    }
  }

  return (
    <main className="login">
      <form className="login-card" data-testid="login-form" onSubmit={submit} noValidate>
        <div className="brand">RemoteOps</div>
        <h1>Sign in</h1>
        {notice && <p className="ok-note">{notice}</p>}
        <label>
          Email
          <input data-testid="login-email" type="email" autoComplete="username" value={email} onChange={(e) => setEmail(e.target.value)} />
        </label>
        <label>
          Password
          <input data-testid="login-password" type="password" autoComplete="current-password" value={password} onChange={(e) => setPassword(e.target.value)} />
        </label>
        {error && (
          <p className="error" data-testid="login-error" data-error-code={error.code} role="alert" aria-live="assertive">
            {error.message}
          </p>
        )}
        <button data-testid="login-submit" type="submit" className="primary" disabled={busy}>
          {busy ? 'Signing in…' : 'Sign in'}
        </button>
      </form>
    </main>
  );
}
