import React, { useEffect, useState } from 'react';
import { refresh, onSessionChange } from './api.js';
import { Login } from './components/Login.jsx';
import { Invite } from './components/Invite.jsx';
import { Shell } from './components/Shell.jsx';

const inviteTokenFromUrl = () => /^\/invite\/([^/]+)$/.exec(window.location.pathname)?.[1] ?? null;

export function App() {
  const [inviteToken, setInviteToken] = useState(inviteTokenFromUrl);
  const [session, setSession] = useState(undefined); // undefined = still asking the server
  const [notice, setNotice] = useState(null);

  useEffect(() => onSessionChange((s) => setSession(s ?? null)), []);

  // A reload has no token in memory; the httpOnly refresh cookie is the only way back.
  useEffect(() => {
    if (inviteToken) return;
    refresh(null).catch(() => setSession(null));
  }, []); // eslint-disable-line react-hooks/exhaustive-deps

  if (inviteToken) {
    return (
      <Invite
        token={inviteToken}
        onDone={(message) => {
          // Joining is not signing in: go to the sign-in form, in place.
          window.history.replaceState(null, '', '/');
          setNotice(message);
          setSession(null);
          setInviteToken(null);
        }}
      />
    );
  }
  if (session === undefined) return <div className="boot">Loading…</div>;
  if (!session) return <Login notice={notice} />;
  return <Shell key={session.orgId ?? 'none'} session={session} />;
}
