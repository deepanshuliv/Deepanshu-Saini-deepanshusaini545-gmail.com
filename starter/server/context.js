// Per-request context: turn a bearer token into an authenticated caller.
//
// The token's `org` claim is the ONLY org the caller may address. A path that names any
// other org is invisible — 404, before any permission is looked at. Isolation is
// structural: the caller cannot name another org, rather than being filtered afterwards.
//
// Order matters and is: signature/claims -> membership -> freshness -> org in the path
// -> suspension. A removed membership is 401 (the token speaks for nobody); a suspended
// one still identifies the caller, so it is 403 `suspended` on everything in the org
// except the identity routes, and the engine resolves it to an empty set regardless.

import { verifyAccessToken, assertFresh } from './auth.js';
import { unauthenticated, notFound, forbidden } from './http.js';

// The auth scheme is case-insensitive (RFC 7235); the token itself is one opaque word.
const BEARER = /^bearer\s+(\S+)\s*$/i;

// Identity routes a suspended member can still use: see who they are, switch to another
// org, list or create orgs. Everything else in the org is refused with `suspended`.
const OPEN_WHEN_SUSPENDED = [/^\/v1\/auth\//, /^\/v1\/orgs\/?$/, /^\/v1\/roles\/?$/];

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

    // Routes with no permission check (your own session, leaving, your own effective
    // set) would otherwise still answer a suspended member. Suspension is total inside
    // the org, so it is enforced here, once, rather than remembered in each route.
    if (membership.status === 'suspended') {
      const path = new URL(req.url, 'http://x').pathname;
      if (!OPEN_WHEN_SUSPENDED.some((re) => re.test(path))) {
        throw forbidden('your membership in this organization is suspended', 'suspended');
      }
    }

    return { userId: claims.sub, orgId: claims.org, role: membership.role, membership, claims };
  };
}
