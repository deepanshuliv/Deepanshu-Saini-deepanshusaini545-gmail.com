import React, { useCallback, useEffect, useState } from 'react';
import { api } from '../api.js';
import { Action, allowed } from './Gate.jsx';

export function People({ me, perms, orgId, report }) {
  const [members, setMembers] = useState(null);
  const [roles, setRoles] = useState([]);
  const [invites, setInvites] = useState([]);
  const [inviting, setInviting] = useState(false);
  const [link, setLink] = useState(null);

  const canInvite = allowed(perms, 'user:invite');
  const load = useCallback(() => {
    api('GET', `/orgs/${orgId}/members`).then((b) => setMembers(b.members)).catch(report);
    if (canInvite) api('GET', `/orgs/${orgId}/invites`).then((b) => setInvites(b.invites)).catch(report);
  }, [orgId, report, canInvite]);
  useEffect(load, [load]);
  useEffect(() => { api('GET', '/roles').then((b) => setRoles(b.roles)).catch(report); }, [report]);

  const run = (fn) => async () => {
    try {
      await fn();
      load();
    } catch (e) {
      report(e);
    }
  };

  if (!members) return <p className="muted">Loading people…</p>;

  return (
    <div>
      <div className="panel-head">
        <h2>People</h2>
        <Action perms={perms} perm="user:invite" testId="invite-user" className="primary" onClick={() => setInviting((v) => !v)}>
          Invite
        </Action>
      </div>
      {inviting && (
        <InviteForm orgId={orgId} roles={roles} report={report}
          onCreated={(inv) => { setInviting(false); setLink(`${window.location.origin}/invite/${inv.inviteToken}`); load(); }} />
      )}
      {link && (
        <p className="ok-note" role="status">
          Invite created. This link is shown once — send it to the person: <code data-testid="invite-link">{link}</code>
        </p>
      )}

      <table>
        <thead><tr><th>Name</th><th>Email</th><th>Role</th><th>Status</th><th>Actions</th></tr></thead>
        <tbody>
          {members.map((m) => {
            const self = m.userId === me.user.id;
            return (
              <tr key={m.userId} data-testid="user-row" data-user-id={m.userId}>
                <td>{m.name}{self && <span className="hint"> (you)</span>}</td>
                <td>{m.email}</td>
                <td>
                  {!self && allowed(perms, 'user:role:update') ? (
                    <select data-testid="role-select" data-permission="user:role:update" data-state="unlocked" value={m.role}
                      onChange={(e) => run(() => api('PATCH', `/orgs/${orgId}/members/${m.userId}`, { role: e.target.value }))()}>
                      {roles.map((r) => <option key={r.key} value={r.key}>{r.key}</option>)}
                    </select>
                  ) : (
                    m.role
                  )}
                </td>
                <td className={m.status === 'suspended' ? 'warn' : ''}>{m.status}</td>
                <td className="actions">
                  {!self && (
                    <>
                      <Action perms={perms} perm="user:remove" testId="suspend-user"
                        onClick={run(() => api(m.status === 'suspended' ? 'DELETE' : 'POST', `/orgs/${orgId}/members/${m.userId}/suspend`))}>
                        {m.status === 'suspended' ? 'Reinstate' : 'Suspend'}
                      </Action>
                      <Action perms={perms} perm="user:remove" testId="remove-user" className="danger"
                        onClick={() => { if (window.confirm(`Remove ${m.email} from this organization?`)) run(() => api('DELETE', `/orgs/${orgId}/members/${m.userId}`))(); }}>
                        Remove
                      </Action>
                    </>
                  )}
                </td>
              </tr>
            );
          })}
        </tbody>
      </table>

      {canInvite && invites.length > 0 && (
        <>
          <h3>Invitations</h3>
          <table>
            <thead><tr><th>Email</th><th>Role</th><th>Status</th><th>Expires</th><th /></tr></thead>
            <tbody>
              {invites.map((i) => (
                <tr key={i.id} data-testid="invite-row">
                  <td>{i.email}</td><td>{i.role}</td><td>{i.status}</td><td>{new Date(i.expiresAt).toLocaleString()}</td>
                  <td>
                    {i.status === 'pending' && (
                      <Action perms={perms} perm="user:invite" testId="cancel-invite" onClick={run(() => api('DELETE', `/orgs/${orgId}/invites/${i.id}`))}>
                        Cancel
                      </Action>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </>
      )}
    </div>
  );
}

function InviteForm({ orgId, roles, report, onCreated }) {
  const [email, setEmail] = useState('');
  const [role, setRole] = useState('');
  async function submit(e) {
    e.preventDefault();
    try {
      onCreated(await api('POST', `/orgs/${orgId}/invites`, { email, role: role || roles[roles.length - 1]?.key }));
    } catch (err) {
      report(err);
    }
  }
  return (
    <form className="inline-form" onSubmit={submit}>
      <input data-testid="invite-email-input" type="email" placeholder="email@example.com" value={email} onChange={(e) => setEmail(e.target.value)} />
      <select data-testid="invite-role-select" value={role} onChange={(e) => setRole(e.target.value)}>
        <option value="">role…</option>
        {roles.map((r) => <option key={r.key} value={r.key}>{r.key}</option>)}
      </select>
      <button type="submit" className="primary">Send invite</button>
    </form>
  );
}
