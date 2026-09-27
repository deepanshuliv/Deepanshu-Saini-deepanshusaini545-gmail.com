import React from 'react';
import { api, refresh } from '../api.js';
import { Action } from './Gate.jsx';

export function Admin({ me, perms, orgId, report, reloadMe }) {
  async function rename() {
    const name = window.prompt('New organization name', me.org?.name);
    if (name === null) return;
    try {
      await api('PATCH', `/orgs/${orgId}`, { name });
      reloadMe();
    } catch (e) {
      report(e);
    }
  }

  async function remove() {
    if (!window.confirm(`Delete ${me.org?.name}? Everyone loses access and live sessions end.`)) return;
    try {
      await api('DELETE', `/orgs/${orgId}`);
      await refresh(null); // lands in another org, or none
    } catch (e) {
      report(e);
    }
  }

  return (
    <div>
      <div className="panel-head"><h2>Organization</h2></div>
      <dl className="facts">
        <dt>Name</dt><dd>{me.org?.name}</dd>
        <dt>Theme</dt><dd>{me.org?.theme}</dd>
        <dt>Session limit</dt><dd>{me.org?.maxSessionMinutes} minutes</dd>
      </dl>
      <div className="actions">
        <Action perms={perms} perm="org:update" testId="rename-org" onClick={rename}>Rename organization</Action>
        <Action perms={perms} perm="org:delete" testId="delete-org" className="danger" onClick={remove}>Delete organization</Action>
      </div>
    </div>
  );
}
