import React, { useCallback, useEffect, useState } from 'react';
import { api, switchOrg, logout } from '../api.js';
import { allowed, ErrorNote } from './Gate.jsx';
import { Devices } from './Devices.jsx';
import { People } from './People.jsx';
import { Grants } from './Grants.jsx';
import { Sessions } from './Sessions.jsx';
import { Audit } from './Audit.jsx';
import { Admin } from './Admin.jsx';

// The cards and the permission that governs each (UI-INVENTORY.md §2). This is a list
// of which question to ask the server's answer — not a role table.
const CARDS = [
  { key: 'devices', label: 'Devices', gate: ['device:list'], View: Devices },
  { key: 'people', label: 'People', gate: ['user:read'], View: People },
  { key: 'grants', label: 'Grants', gate: ['user:read'], View: Grants },
  { key: 'sessions', label: 'Sessions', gate: ['session:view'], View: Sessions },
  { key: 'audit', label: 'Audit', gate: ['audit:read'], View: Audit },
  { key: 'admin', label: 'Admin', gate: ['org:update', 'org:delete'], View: Admin },
];

// Keyed by org in App.jsx: switching orgs unmounts this whole tree, so nothing from the
// previous org survives in state or in the DOM.
export function Shell({ session }) {
  const [me, setMe] = useState(null);
  const [error, setError] = useState(null);
  const [card, setCard] = useState(null);

  const loadMe = useCallback(() => api('GET', '/auth/me').then(setMe).catch(setError), []);
  useEffect(() => { loadMe(); }, [loadMe]);

  const perms = me?.permissions ?? {};
  const cards = CARDS.map((c) => ({ ...c, held: c.gate.find((p) => allowed(perms, p)) })).filter((c) => c.held);
  const active = cards.find((c) => c.key === card) ?? cards[0] ?? null;
  const report = useCallback((e) => setError(e), []);

  async function createOrg() {
    const name = window.prompt('Name of the new organization');
    if (name === null) return;
    try {
      const org = await api('POST', '/orgs', { name });
      await switchOrg(org.id);
    } catch (e) {
      setError(e);
    }
  }

  async function choose(orgId) {
    if (orgId === session.orgId) return;
    try {
      await switchOrg(orgId);
    } catch (e) {
      setError(e);
    }
  }

  const orgs = me?.orgs ?? session.orgs ?? [];
  const org = me?.org;

  return (
    <div className="shell" data-testid="app-shell" data-org-id={session.orgId ?? ''} data-org-theme={org?.theme ?? orgs.find((o) => o.id === session.orgId)?.theme ?? 'none'}>
      <header className="topbar">
        <div className="brand">RemoteOps</div>
        <nav className="orgs" aria-label="Organizations">
          {orgs.map((o) => (
            <button
              key={o.id}
              type="button"
              data-testid="org-option"
              data-org-id={o.id}
              data-org-theme={o.theme}
              aria-pressed={o.id === session.orgId}
              className={`org-option theme-${o.theme}`}
              onClick={() => choose(o.id)}
            >
              <span className="swatch" aria-hidden="true" />
              {o.name}
            </button>
          ))}
          <button type="button" data-testid="create-org" className="ghost" onClick={createOrg}>+ New organization</button>
        </nav>
        <div className="who">
          <span className="user">{me?.user?.email ?? session.user?.email}</span>
          <span className="role-badge" data-testid="active-role">{me?.role ?? session.role ?? 'no org'}</span>
          <button type="button" data-testid="sign-out" className="ghost" onClick={() => logout()}>Sign out</button>
        </div>
      </header>

      <div className="org-banner">
        <h1>{org?.name ?? 'No organization'}</h1>
        {me?.status === 'suspended' && <p className="error">Your membership in this organization is suspended.</p>}
      </div>

      <ErrorNote error={error} onDismiss={() => setError(null)} />

      {!session.orgId && <p className="empty">You are not a member of any organization yet. Create one to get started.</p>}

      {me && session.orgId && (
        <div className="workspace">
          <nav className="cards" aria-label="Sections">
            {cards.map((c) => (
              <button
                key={c.key}
                type="button"
                data-testid={`nav-${c.key}`}
                data-permission={c.held}
                data-state="unlocked"
                aria-current={active?.key === c.key ? 'page' : undefined}
                onClick={() => setCard(c.key)}
              >
                {c.label}
              </button>
            ))}
          </nav>
          <section className="panel">
            {active ? (
              <active.View key={active.key} me={me} perms={perms} orgId={session.orgId} report={report} reloadMe={loadMe} />
            ) : (
              <p className="empty">You have no sections available in this organization.</p>
            )}
          </section>
        </div>
      )}
    </div>
  );
}
