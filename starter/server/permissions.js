// The permission resolution engine. THE ONLY PLACE allow-vs-deny is decided.
//
// If you ever find yourself writing `if (role === 'admin')` outside this file — and
// especially under web/ — that is the bug this module exists to prevent. The console
// renders what this returns; it must never re-derive it.
//
// Everything is read from the database per call: the catalogue (`permissions`), the
// baseline (`role_permissions`) and the grants. Nothing here knows how many roles or
// permissions exist — the database is personalised, so a hardcoded matrix is wrong.
//
// roles.rank is deliberately never read here (D2). It lives in lifecycle.js.

import { forbidden, badRequest } from './http.js';

export const MODE_PERMISSION = { view: 'device:view', control: 'device:control', terminal: 'device:terminal' };

// ---------------------------------------------------------------------------
// Loading. A fixed number of queries per call, however many devices or grants.

function loadInputs(db, userId, orgId, now) {
  const membership = db
    .prepare(
      `SELECT m.role, m.status FROM memberships m
         JOIN organizations o ON o.id = m.org_id AND o.deleted_at IS NULL
        WHERE m.user_id = ? AND m.org_id = ?`
    )
    .get(userId, orgId);

  const catalogue = db.prepare('SELECT key, resource FROM permissions ORDER BY key').all();
  if (!membership || membership.status !== 'active') return { membership, catalogue };

  const baseline = new Set(
    db.prepare('SELECT permission FROM role_permissions WHERE role = ?').pluck().all(membership.role)
  );

  // Applicable = this user, this org, not revoked, inside the half-open window (D7).
  // A device-scoped grant only counts while its device is live in THIS org — a grant
  // left behind on a transferred or decommissioned device must not leak into the union.
  const at = now.toISOString();
  const grants = db
    .prepare(
      `SELECT g.id, g.device_id AS deviceId, g.effect, gp.permission AS pattern
         FROM grants g
         JOIN grant_permissions gp ON gp.grant_id = g.id
         LEFT JOIN devices d ON d.id = g.device_id
        WHERE g.user_id = ? AND g.org_id = ? AND g.revoked_at IS NULL
          AND (g.starts_at  IS NULL OR g.starts_at <= ?)
          AND (g.expires_at IS NULL OR g.expires_at > ?)
          AND (g.device_id IS NULL OR (d.org_id = g.org_id AND d.deleted_at IS NULL))
        ORDER BY g.created_at, g.id`
    )
    .all(userId, orgId, at, at);

  return { membership, catalogue, baseline, grants };
}

// ---------------------------------------------------------------------------
// Deciding.

// Wildcards match through the catalogue's `resource` column, not a string prefix.
const covers = (pattern, perm) =>
  pattern === '*' || pattern === perm.key || pattern === `${perm.resource}:*`;

const entry = (effect, source, reason) => ({ effect, source, reason });

// The whole algorithm for one permission against one set of applicable grants.
// The order is the rule: deny first (D1), then baseline, then allow grants (D3), then
// implicit (D4).
function decide(perm, grants, baseline, role) {
  const deny = grants.find((g) => g.effect === 'deny' && covers(g.pattern, perm));
  if (deny) return entry('deny', `grant:${deny.id}`, 'explicit_deny');
  if (baseline.has(perm.key)) return entry('allow', `role:${role}`, null);
  const allow = grants.find((g) => g.effect === 'allow' && covers(g.pattern, perm));
  if (allow) return entry('allow', `grant:${allow.id}`, null);
  return entry('deny', null, 'implicit');
}

const decideAll = (inputs, grants) =>
  Object.fromEntries(
    inputs.catalogue.map((p) => [p.key, decide(p, grants, inputs.baseline, inputs.membership.role)])
  );

const blanket = (catalogue, reason) =>
  Object.fromEntries(catalogue.map((p) => [p.key, entry('deny', null, reason)]));

// At one device: every org-wide grant plus that device's own.
const permissionsAtDevice = (inputs, deviceId) =>
  decideAll(inputs, inputs.grants.filter((g) => g.deviceId === null || g.deviceId === deviceId));

// Org scope only: org-wide grants, no device-scoped ones. The floor of the org-level
// view, and the scope an org-wide grant is issued at (assertMayGrant).
const permissionsOrgOnly = (inputs) =>
  decideAll(inputs, inputs.grants.filter((g) => g.deviceId === null));

// The org-level view (nav, page gating): the union across devices. Start from org
// scope; an implicit deny there becomes allow if a device-scoped allow survives at its
// device. An org-wide deny is never overturned — it also applies at every device.
function permissionsOrgLevel(inputs) {
  const result = permissionsOrgOnly(inputs);
  const scoped = [...new Set(inputs.grants.filter((g) => g.deviceId !== null).map((g) => g.deviceId))];
  const perDevice = scoped.map((d) => permissionsAtDevice(inputs, d));

  for (const { key } of inputs.catalogue) {
    if (result[key].reason !== 'implicit') continue;
    const allowed = perDevice.find((set) => set[key].effect === 'allow');
    if (allowed) result[key] = allowed[key];
  }
  return result;
}

// Why the membership yields nothing at all, or null if it is active.
function blockedReason({ membership }) {
  if (!membership) return 'not_a_member';
  if (membership.status === 'suspended') return 'suspended';
  if (membership.status !== 'active') return 'not_a_member'; // invited, removed
  return null;
}

// ---------------------------------------------------------------------------
// Public API.

// Resolve one user's permission set in one org. deviceId === null means the org-level
// view; a deviceId means the exact per-device check.
export function resolve(db, { userId, orgId, deviceId = null, now = new Date() }) {
  const inputs = loadInputs(db, userId, orgId, now);
  const blocked = blockedReason(inputs);
  const role = blocked === 'not_a_member' ? null : inputs.membership.role;
  if (blocked) return { role, permissions: blanket(inputs.catalogue, blocked) };

  const permissions = deviceId === null ? permissionsOrgLevel(inputs) : permissionsAtDevice(inputs, deviceId);
  return { role, permissions };
}

// Batched form for list endpoints: { role, byDevice: { [deviceId]: permissions } }.
// The same queries as a single resolve, however many devices.
export function resolveDevices(db, { userId, orgId, deviceIds, now = new Date() }) {
  const inputs = loadInputs(db, userId, orgId, now);
  const blocked = blockedReason(inputs);
  const role = blocked === 'not_a_member' ? null : inputs.membership.role;
  const byDevice = {};
  for (const id of deviceIds) {
    byDevice[id] = blocked ? blanket(inputs.catalogue, blocked) : permissionsAtDevice(inputs, id);
  }
  return { role, byDevice };
}

function lookup(db, ctx, permission, deviceId) {
  const { permissions } = resolve(db, { userId: ctx.userId, orgId: ctx.orgId, deviceId: deviceId ?? null });
  return permissions[permission] ?? entry('deny', null, 'implicit');
}

export function can(db, ctx, permission, deviceId) {
  return lookup(db, ctx, permission, deviceId).effect === 'allow';
}

// On the wire, the engine's `implicit` ("nobody granted it") is `missing_permission`.
const refusalReason = (e) => (e.reason === 'implicit' ? 'missing_permission' : e.reason);

// Throws 403 carrying the reason code, so a refusal is debuggable.
export function assertCan(db, ctx, permission, deviceId) {
  const e = lookup(db, ctx, permission, deviceId);
  if (e.effect !== 'allow') throw forbidden(`missing ${permission}`, refusalReason(e));
  return e;
}

// For actions that have no device yet (provisioning one): the org scope alone. The
// union would let a device-scoped grant on one device authorize an org-wide action.
export function assertCanOrgWide(db, ctx, permission) {
  const inputs = loadInputs(db, ctx.userId, ctx.orgId, new Date());
  const blocked = blockedReason(inputs);
  if (blocked) throw forbidden(`missing ${permission}`, blocked);
  const e = permissionsOrgOnly(inputs)[permission] ?? entry('deny', null, 'implicit');
  if (e.effect !== 'allow') throw forbidden(`missing ${permission}`, refusalReason(e));
  return e;
}

// No privilege laundering (D9): every permission a pattern expands to must be held by
// the caller at the scope being granted. An org-wide grant is checked at org scope
// only — holding something on one device does not let you hand it out org-wide.
export function assertMayGrant(db, ctx, patterns, deviceId = null) {
  const inputs = loadInputs(db, ctx.userId, ctx.orgId, new Date());
  const blocked = blockedReason(inputs);
  if (blocked) throw forbidden('you cannot grant permissions in this org', blocked);
  const held = deviceId === null ? permissionsOrgOnly(inputs) : permissionsAtDevice(inputs, deviceId);

  for (const pattern of patterns) {
    const missing = inputs.catalogue.find((p) => covers(pattern, p) && held[p.key].effect !== 'allow');
    if (missing) throw forbidden(`you cannot grant ${missing.key} at this scope`, 'missing_permission');
  }
}

// The compound check: session:start AND the permission for the requested mode, both on
// the same device, and a refusal says WHICH of the two was missing.
export function assertCanStartSession(db, ctx, mode, deviceId) {
  const modePermission = MODE_PERMISSION[mode];
  if (!modePermission) throw badRequest(`mode must be one of ${Object.keys(MODE_PERMISSION).join(', ')}`);

  const { permissions } = resolve(db, { userId: ctx.userId, orgId: ctx.orgId, deviceId });
  if (permissions['session:start']?.effect !== 'allow') {
    throw forbidden('missing session:start', 'missing_permission');
  }
  if (permissions[modePermission]?.effect !== 'allow') {
    throw forbidden(`missing ${modePermission} on this device`, 'missing_device_permission');
  }
  return permissions;
}
