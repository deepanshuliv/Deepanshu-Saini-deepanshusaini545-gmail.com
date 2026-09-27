import React from 'react';

// Presence, not state. An element either renders — carrying data-permission and
// data-state="unlocked" — or is not in the DOM. There is no disabled variant.
// `perms` is always a set the SERVER resolved; nothing here knows what a role means.

export const allowed = (perms, key) => perms?.[key]?.effect === 'allow';

export function Action({ perms, perm, testId, children, className = '', ...rest }) {
  if (!allowed(perms, perm)) return null;
  return (
    <button type="button" data-testid={testId} data-permission={perm} data-state="unlocked" className={className} {...rest}>
      {children}
    </button>
  );
}

// How a missing entry explains itself: the server's provenance, in words.
export function explain(entry) {
  if (!entry) return 'Not part of the permission catalogue.';
  if (entry.effect === 'allow') return entry.source?.startsWith('grant:') ? `Allowed by ${entry.source}` : `Allowed by your role`;
  switch (entry.reason) {
    case 'explicit_deny': return `Blocked by an explicit deny (${entry.source})`;
    case 'suspended': return 'Your membership here is suspended';
    case 'not_a_member': return 'You are not a member of this organization';
    default: return 'Nobody has granted you this';
  }
}

export function ErrorNote({ error, onDismiss }) {
  if (!error) return null;
  return (
    <div className="error banner" role="alert" aria-live="assertive" data-testid="action-error" data-error-code={error.code}>
      <span>
        <strong>{error.status ? `${error.status} ${error.code}` : error.code}</strong> — {error.message}
        {error.reason ? <span className="hint"> ({error.reason})</span> : null}
      </span>
      {onDismiss && <button type="button" className="link" onClick={onDismiss} aria-label="Dismiss">×</button>}
    </div>
  );
}
