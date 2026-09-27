import React, { useCallback, useEffect, useState } from 'react';
import { api } from '../api.js';
import { Action, allowed } from './Gate.jsx';

// A session row can read "active" while that device's Control button is absent: the
// session was authorized when it started (grandfathered); the button answers "could you
// start one now". Different questions — deliberately not reconciled here.
export function Sessions({ me, perms, orgId, report }) {
  const [sessions, setSessions] = useState(null);
  const [starting, setStarting] = useState(false);

  const load = useCallback(() => {
    api('GET', `/orgs/${orgId}/sessions`).then((b) => setSessions(b.sessions)).catch(report);
  }, [orgId, report]);
  useEffect(load, [load]);

  if (!sessions) return <p className="muted">Loading sessions…</p>;

  return (
    <div>
      <div className="panel-head">
        <h2>Sessions</h2>
        <Action perms={perms} perm="session:start" testId="new-session" className="primary" onClick={() => setStarting((v) => !v)}>
          Start a session
        </Action>
      </div>
      {starting && <StartSession orgId={orgId} report={report} onStarted={() => { setStarting(false); load(); }} />}
      {sessions.length === 0 ? (
        <p className="empty">No sessions yet.</p>
      ) : (
        <table>
          <thead><tr><th>Device</th><th>Mode</th><th>Person</th><th>State</th><th>Started</th><th>Expires / ended</th><th /></tr></thead>
          <tbody>
            {sessions.map((s) => {
              const own = s.user_id === me.user.id;
              const live = s.state !== 'ended';
              return (
                <tr key={s.id} data-testid="session-row" data-session-id={s.id} data-state-value={s.state}>
                  <td>{s.device_name}</td>
                  <td>{s.mode}</td>
                  <td>{s.user_email}{own && <span className="hint"> (you)</span>}</td>
                  <td><span className={`pill ${s.state}`}>{s.state}</span>{s.end_reason && <div className="hint">{s.end_reason.replaceAll('_', ' ')}</div>}</td>
                  <td>{new Date(s.started_at).toLocaleString()}</td>
                  <td>{new Date(s.ended_at ?? s.expires_at).toLocaleString()}</td>
                  <td>
                    {live && (own ? (
                      <button type="button" data-testid="stop-session" data-state="unlocked" onClick={stop(s.id)}>Stop</button>
                    ) : (
                      <Action perms={perms} perm="session:terminate" testId="stop-session" className="danger" onClick={stop(s.id)}>Terminate</Action>
                    ))}
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      )}
    </div>
  );

  function stop(id) {
    return async () => {
      try {
        await api('DELETE', `/sessions/${id}`);
        load();
      } catch (e) {
        report(e);
      }
    };
  }
}

function StartSession({ orgId, report, onStarted }) {
  const [devices, setDevices] = useState([]);
  const [deviceId, setDeviceId] = useState('');
  const [mode, setMode] = useState('view');
  useEffect(() => {
    api('GET', `/orgs/${orgId}/devices`).then((b) => setDevices(b.devices)).catch(report);
  }, [orgId, report]);
  const device = devices.find((d) => d.id === deviceId);
  async function submit(e) {
    e.preventDefault();
    try {
      await api('POST', `/orgs/${orgId}/sessions`, { deviceId, mode });
      onStarted();
    } catch (err) {
      report(err);
    }
  }
  return (
    <form className="inline-form" onSubmit={submit}>
      <select data-testid="session-device" value={deviceId} onChange={(e) => setDeviceId(e.target.value)}>
        <option value="">device…</option>
        {devices.map((d) => <option key={d.id} value={d.id}>{d.name}</option>)}
      </select>
      <select data-testid="session-mode" value={mode} onChange={(e) => setMode(e.target.value)}>
        {['view', 'control', 'terminal'].map((m) => (
          <option key={m} value={m}>{m}{device && !allowed(device.permissions, `device:${m}`) ? ' (not permitted on this device)' : ''}</option>
        ))}
      </select>
      <button type="submit" className="primary">Start</button>
    </form>
  );
}
