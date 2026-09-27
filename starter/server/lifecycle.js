// Shared domain rules: role ranks, last-owner protection, ending sessions.
//
// `roles.rank` is MODIFICATION AUTHORITY ONLY (D8). It never answers a can() question —
// that is permissions.js. And a permission change never ends a session in flight;
// suspension, membership removal and device transfer do (PERMISSIONS.md §7).

import { forbidden, badRequest, lastOwner } from './http.js';
import { nowIso } from './db.js';

// The one role the schema's rules name: creators become it, and an org must keep one.
export const OWNER = 'owner';

export function roleRanks(db) {
  return Object.fromEntries(db.prepare('SELECT key, rank FROM roles').all().map((r) => [r.key, r.rank]));
}

export function assertRoleExists(db, role) {
  if (typeof role !== 'string' || !(role in roleRanks(db))) throw badRequest('unknown role', 'unknown_role');
}

// May `callerRole` act on a member holding `targetRole` (and, if given, give them
// `newRole`)? Strictly lower targets only — except owner-on-owner, which is how an org
// with several owners hands ownership around. Nobody confers a role above their own,
// and only an owner confers owner.
export function assertCanModify(db, callerRole, targetRole, newRole = null) {
  const rank = roleRanks(db);
  if (targetRole !== null) {
    const peerOwners = callerRole === OWNER && targetRole === OWNER;
    if (!peerOwners && !(rank[callerRole] > rank[targetRole])) {
      throw forbidden(`a ${callerRole} cannot modify a ${targetRole}`, 'insufficient_rank');
    }
  }
  if (newRole !== null) {
    if (newRole === OWNER && callerRole !== OWNER) throw forbidden('only an owner can confer owner', 'insufficient_rank');
    if (rank[newRole] > rank[callerRole]) throw forbidden(`a ${callerRole} cannot confer ${newRole}`, 'insufficient_rank');
  }
}

// Throws LAST_OWNER if `userId` is the only active owner of `orgId`. Call it inside the
// same transaction as the change, so the count and the write cannot interleave.
export function assertNotLastOwner(db, orgId, userId) {
  const target = db.prepare('SELECT role, status FROM memberships WHERE org_id = ? AND user_id = ?').get(orgId, userId);
  if (target?.role !== OWNER || target.status !== 'active') return;
  const others = db
    .prepare(`SELECT COUNT(*) FROM memberships WHERE org_id = ? AND role = ? AND status = 'active' AND user_id != ?`)
    .pluck()
    .get(orgId, OWNER, userId);
  if (others === 0) throw lastOwner();
}

// End every live session matching the filters. Returns how many ended.
export function endActiveSessions(db, { orgId, userId = null, deviceId = null, reason, exceptSessionId = null }) {
  return db
    .prepare(
      `UPDATE sessions SET state = 'ended', end_reason = ?, ended_at = ?
        WHERE org_id = ? AND state IN ('connecting', 'active')
          AND (? IS NULL OR user_id = ?)
          AND (? IS NULL OR device_id = ?)
          AND (? IS NULL OR id != ?)`
    )
    .run(reason, nowIso(), orgId, userId, userId, deviceId, deviceId, exceptSessionId, exceptSessionId).changes;
}

// TTL is enforced lazily: any read or write of sessions first ends the ones past their
// expiry, so an expired session never holds a device or reads as active.
export function expireSessions(db, orgId) {
  const now = nowIso();
  db.prepare(
    `UPDATE sessions SET state = 'ended', end_reason = 'session_expired', ended_at = expires_at
      WHERE org_id = ? AND state IN ('connecting', 'active') AND expires_at <= ?`
  ).run(orgId, now);
}

// The authority a session starts with, frozen for its lifetime (grandfathering).
export function snapshotAuthority(permissions, { userId, orgId, deviceId, role, mode, modePermission }) {
  return JSON.stringify({
    userId, orgId, deviceId, role, mode,
    'session:start': permissions['session:start'],
    [modePermission]: permissions[modePermission],
    at: nowIso(),
  });
}

export function sessionExpiry(db, orgId, from = new Date()) {
  const minutes = db.prepare('SELECT max_session_minutes FROM organizations WHERE id = ?').pluck().get(orgId) ?? 60;
  return new Date(from.getTime() + minutes * 60_000).toISOString();
}
