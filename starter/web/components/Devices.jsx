import React, { useCallback, useEffect, useState } from 'react';
import { api } from '../api.js';
import { Action, explain } from './Gate.jsx';

const KINDS = ['macos', 'windows', 'linux', 'android', 'ios'];
const MODES = [
  ['view', 'device:view', 'start-view', 'View'],
  ['control', 'device:control', 'start-control', 'Control'],
  ['terminal', 'device:terminal', 'start-terminal', 'Terminal'],
];

// Every row's buttons come from that row's own `permissions`, resolved by the server
// for that device. No follow-up request per row, no rule re-derived here.
export function Devices({ perms, orgId, report }) {
  const [devices, setDevices] = useState(null);
  const [adding, setAdding] = useState(false);
  const [message, setMessage] = useState(null);

  const load = useCallback(() => {
    api('GET', `/orgs/${orgId}/devices`).then((b) => setDevices(b.devices)).catch(report);
  }, [orgId, report]);
  useEffect(load, [load]);

  const act = (fn, done) => async () => {
    setMessage(null);
    try {
      const out = await fn();
      if (done) setMessage(done(out));
      load();
    } catch (e) {
      report(e);
    }
  };

  if (!devices) return <p className="muted">Loading devices…</p>;

  return (
    <div>
      <div className="panel-head">
        <h2>Devices</h2>
        <Action perms={perms} perm="device:provision" testId="add-device" className="primary" onClick={() => setAdding((v) => !v)}>
          Add device
        </Action>
      </div>
      {adding && <AddDevice orgId={orgId} report={report} onAdded={() => { setAdding(false); load(); }} />}
      {message && <p className="ok-note" role="status">{message}</p>}

      {devices.length === 0 ? (
        <p className="empty" data-testid="devices-empty">No devices yet.</p>
      ) : (
        <table>
          <thead>
            <tr><th>Name</th><th>Kind</th><th>Status</th><th>Actions</th></tr>
          </thead>
          <tbody>
            {devices.map((d) => (
              <tr key={d.id} data-testid="device-row" data-device-id={d.id}>
                <td>
                  <strong>{d.name}</strong>
                  <MissingActions permissions={d.permissions} />
                </td>
                <td>{d.kind}</td>
                <td><span className={d.online ? 'dot on' : 'dot'} />{d.online ? 'online' : 'offline'}</td>
                <td className="actions">
                  {MODES.map(([mode, perm, testId, label]) => (
                    <Action key={mode} perms={d.permissions} perm={perm} testId={testId}
                      onClick={act(() => api('POST', `/orgs/${orgId}/sessions`, { deviceId: d.id, mode }), (s) => `Started a ${mode} session on ${d.name} (${s.id}). Sessions are records only.`)}>
                      {label}
                    </Action>
                  ))}
                  <Action perms={d.permissions} perm="device:file_transfer" testId="transfer-files"
                    onClick={() => setMessage(`File transfer on ${d.name} is permitted. No files move in this console — sessions are records.`)}>
                    Transfer files
                  </Action>
                  <Action perms={d.permissions} perm="device:update" testId="rename-device"
                    onClick={() => {
                      const name = window.prompt('New name', d.name);
                      if (name !== null) act(() => api('PATCH', `/orgs/${orgId}/devices/${d.id}`, { name }))();
                    }}>
                    Rename
                  </Action>
                  <Action perms={d.permissions} perm="device:provision" testId="decommission-device" className="danger"
                    onClick={() => {
                      if (window.confirm(`Decommission ${d.name}? Live sessions on it will end.`)) {
                        act(() => api('DELETE', `/orgs/${orgId}/devices/${d.id}`), () => `${d.name} was decommissioned.`)();
                      }
                    }}>
                    Decommission
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

// The absent buttons can't explain themselves, so the row does: which device actions
// are missing and why, straight from the server's provenance.
function MissingActions({ permissions }) {
  const missing = Object.entries(permissions).filter(([k, v]) => k.startsWith('device:') && v.effect !== 'allow');
  if (missing.length === 0) return null;
  return (
    <details className="why">
      <summary>{missing.length} action{missing.length > 1 ? 's' : ''} unavailable</summary>
      <ul>
        {missing.map(([k, v]) => (
          <li key={k}><code>{k}</code> — {explain(v)}</li>
        ))}
      </ul>
    </details>
  );
}

function AddDevice({ orgId, report, onAdded }) {
  const [name, setName] = useState('');
  const [kind, setKind] = useState('linux');
  async function submit(e) {
    e.preventDefault();
    try {
      await api('POST', `/orgs/${orgId}/devices`, { name, kind });
      onAdded();
    } catch (err) {
      report(err);
    }
  }
  return (
    <form className="inline-form" onSubmit={submit}>
      <input data-testid="device-name" placeholder="Device name" value={name} onChange={(e) => setName(e.target.value)} />
      <select data-testid="device-kind" value={kind} onChange={(e) => setKind(e.target.value)}>
        {KINDS.map((k) => <option key={k}>{k}</option>)}
      </select>
      <button type="submit" className="primary" data-testid="device-submit">Add</button>
    </form>
  );
}
