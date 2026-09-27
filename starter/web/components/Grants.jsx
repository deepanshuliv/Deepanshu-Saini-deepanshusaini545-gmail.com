import React, { useCallback, useEffect, useState } from 'react';
import { api } from '../api.js';
import { Action, allowed } from './Gate.jsx';

export function Grants({ me, perms, orgId, report }) {
  const [grants, setGrants] = useState(null);
  const [creating, setCreating] = useState(false);

  const load = useCallback(() => {
    api('GET', `/orgs/${orgId}/grants`).then((b) => setGrants(b.grants)).catch(report);
  }, [orgId, report]);
  useEffect(load, [load]);

  if (!grants) return <p className="muted">Loading grants…</p>;

  return (
    <div>
      <div className="panel-head">
        <h2>Grants</h2>
        <Action perms={perms} perm="grant:create" testId="new-grant" className="primary" onClick={() => setCreating((v) => !v)}>
          New grant
        </Action>
      </div>
      {creating && allowed(perms, 'grant:create') && (
        <GrantForm me={me} orgId={orgId} report={report} onCreated={() => { setCreating(false); load(); }} />
      )}
      {grants.length === 0 ? (
        <p className="empty">No grants. Everyone has exactly their role's permissions.</p>
      ) : (
        <table>
          <thead><tr><th>Person</th><th>Effect</th><th>Permissions</th><th>Scope</th><th>Window</th><th /></tr></thead>
          <tbody>
            {grants.map((g) => (
              <tr key={g.id} data-testid="grant-row" data-grant-id={g.id} data-effect={g.effect}>
                <td>{g.userName}<div className="hint">{g.userEmail}</div></td>
                <td><span className={`pill ${g.effect}`}>{g.effect}</span></td>
                <td>{g.permissions.map((p) => <code key={p} className="perm">{p}</code>)}</td>
                <td>{g.deviceName ?? 'whole organization'}</td>
                <td className="hint">
                  {g.startsAt ? `from ${new Date(g.startsAt).toLocaleString()} ` : ''}
                  {g.expiresAt ? `until ${new Date(g.expiresAt).toLocaleString()}` : g.startsAt ? '' : 'no expiry'}
                </td>
                <td>
                  <Action perms={perms} perm="grant:revoke" testId="revoke-grant" className="danger"
                    onClick={async () => {
                      try {
                        await api('DELETE', `/orgs/${orgId}/grants/${g.id}`);
                        load();
                      } catch (e) {
                        report(e);
                      }
                    }}>
                    Revoke
                  </Action>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </div>
  );
}

// The permission list is the keys of the caller's own resolved set, i.e. the server's
// catalogue — so a permission no document mentions still appears here.
function GrantForm({ me, orgId, report, onCreated }) {
  const [members, setMembers] = useState([]);
  const [devices, setDevices] = useState([]);
  const [userId, setUserId] = useState('');
  const [deviceId, setDeviceId] = useState('');
  const [effect, setEffect] = useState('allow');
  const [expiresAt, setExpiresAt] = useState('');
  const [chosen, setChosen] = useState(() => new Set());
  const catalogue = Object.keys(me.permissions).sort();

  useEffect(() => {
    api('GET', `/orgs/${orgId}/members`).then((b) => setMembers(b.members.filter((m) => m.userId !== me.user.id && m.status === 'active'))).catch(report);
    api('GET', `/orgs/${orgId}/devices`).then((b) => setDevices(b.devices)).catch(() => setDevices([]));
  }, [orgId, me.user.id, report]);

  const toggle = (p) => setChosen((s) => { const n = new Set(s); n.has(p) ? n.delete(p) : n.add(p); return n; });

  async function submit(e) {
    e.preventDefault();
    try {
      await api('POST', `/orgs/${orgId}/grants`, {
        userId,
        deviceId: deviceId || null,
        effect,
        permissions: [...chosen],
        ...(expiresAt ? { expiresAt: new Date(expiresAt).toISOString() } : {}),
      });
      onCreated();
    } catch (err) {
      report(err);
    }
  }

  return (
    <form className="grant-form" onSubmit={submit}>
      <div className="row">
        <label>Person
          <select data-testid="grant-user" value={userId} onChange={(e) => setUserId(e.target.value)}>
            <option value="">choose…</option>
            {members.map((m) => <option key={m.userId} value={m.userId}>{m.name} ({m.role})</option>)}
          </select>
        </label>
        <label>Scope
          <select data-testid="grant-device" value={deviceId} onChange={(e) => setDeviceId(e.target.value)}>
            <option value="">Whole organization</option>
            {devices.map((d) => <option key={d.id} value={d.id}>{d.name}</option>)}
          </select>
        </label>
        <label>Effect
          <select data-testid="grant-effect" value={effect} onChange={(e) => setEffect(e.target.value)}>
            <option value="allow">allow</option>
            <option value="deny">deny</option>
          </select>
        </label>
        <label>Expires (optional)
          <input type="datetime-local" data-testid="grant-expires" value={expiresAt} onChange={(e) => setExpiresAt(e.target.value)} />
        </label>
      </div>
      <fieldset>
        <legend>Permissions</legend>
        {catalogue.map((p) => (
          <label key={p} className="check">
            <input type="checkbox" data-permission-key={p} checked={chosen.has(p)} onChange={() => toggle(p)} /> {p}
          </label>
        ))}
      </fieldset>
      <button type="submit" className="primary" data-testid="grant-submit">Create grant</button>
    </form>
  );
}
