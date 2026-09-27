// Per-request context: turn a bearer token into an authenticated caller.
//
// The token's `org` claim is the ONLY org the caller may address. A path that names any
// other org is invisible — 404, before any permission is looked at. Isolation is
// structural: the caller cannot name another org, rather than being filtered afterwards.
//
// Order matters and is: signature/claims -> membership -> freshness -> org in the path.
// A suspended membership passes through with its status intact; the engine resolves it
// to an empty set (reason `suspended`), so routes answer 403 rather than 401.

import { verifyAccessToken, assertFresh } from './auth.js';
import { unauthenticated, notFound } from './http.js';

const BEARER = /^Bearer ([^\s]+)$/;

export function authenticate(db, secret) {
  const findMembership = db.prepare(
    `SELECT m.id, m.org_id, m.user_id, m.role, m.status, m.perm_version
       FROM memberships m
       JOIN organizations o ON o.id = m.org_id AND o.deleted_at IS NULL
      WHERE m.user_id = ? AND m.org_id = ?`
  );

  return function buildContext(req, params) {
    const match = BEARER.exec(req.headers.authorization ?? '');
    if (!match) throw unauthenticated('missing bearer token');
    const claims = verifyAccessToken(match[1], secret);

    // A user with no active org (removed everywhere, or brand new) holds an org-less
    // token: it can list and create orgs, and address nothing else.
    if (claims.org === null) {
      if (params.org !== undefined) throw notFound();
      return { userId: claims.sub, orgId: null, role: null, membership: null, claims };
    }

    const membership = findMembership.get(claims.sub, claims.org);
    if (!membership || membership.status === 'removed' || membership.status === 'invited') {
      throw unauthenticated('not a member of this org');
    }
    assertFresh(claims, membership);

    if (params.org !== undefined && params.org !== claims.org) throw notFound();

    return { userId: claims.sub, orgId: claims.org, role: membership.role, membership, claims };
  };
}
