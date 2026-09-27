// Devices, grants, and effective permissions.
//
// Every device row carries the caller's resolved permissions for THAT device, computed
// in one batched resolve — the console needs no follow-up request per row and never
// re-derives the rules. device:list gates the endpoint; device:view decides whether a
// row is in the response at all (absent, never redacted).

import { send, badRequest, notFound, forbidden, normalizeTs, HttpError } from '../http.js';
import { newId, nowIso, bumpPermVersion } from '../db.js';
import { resolve, resolveDevices, assertCan, assertCanOrgWide, assertMayGrant } from '../permissions.js';
import { auditDenials, audit } from '../audit.js';
import { assertCanModify, endActiveSessions } from '../lifecycle.js';

const KINDS = ['macos', 'windows', 'linux', 'android', 'ios'];

function deviceName(value) {
  const name = typeof value === 'string' ? value.trim() : '';
  if (name.length < 1 || name.length > 80) throw badRequest('name must be 1–80 characters');
  return name;
}

// A live device in this org, or 404 — "doesn't exist" and "belongs to another org" are
// the same answer.
function findDevice(db, orgId, id) {
  const d = db
    .prepare('SELECT id, org_id, name, kind, online, created_at FROM devices WHERE id = ? AND org_id = ? AND deleted_at IS NULL')
    .get(id, orgId);
  if (!d) throw notFound();
  return d;
}

const deviceBody = (d, permissions) => ({
  id: d.id, name: d.name, kind: d.kind, online: d.online === 1, createdAt: d.created_at, permissions,
});

// Grants are read back with their permissions folded in, one query for the whole list.
function listGrants(db, orgId, { userId = null, id = null } = {}) {
  return db
    .prepare(
      `SELECT g.id, g.user_id AS userId, u.email AS userEmail, u.name AS userName,
              g.device_id AS deviceId, d.name AS deviceName, g.effect,
              g.starts_at AS startsAt, g.expires_at AS expiresAt,
              g.created_by AS createdBy, g.created_at AS createdAt,
              json_group_array(gp.permission) AS permissions
         FROM grants g
         JOIN users u ON u.id = g.user_id
         JOIN grant_permissions gp ON gp.grant_id = g.id
         LEFT JOIN devices d ON d.id = g.device_id
        WHERE g.org_id = ? AND g.revoked_at IS NULL
          AND (? IS NULL OR g.user_id = ?)
          AND (? IS NULL OR g.id = ?)
        GROUP BY g.id
        ORDER BY g.created_at, g.id`
    )
    .all(orgId, userId, userId, id, id)
    .map((g) => ({ ...g, permissions: JSON.parse(g.permissions).sort() }));
}

export function registerDeviceRoutes(router, { db }) {
  // --- devices ---------------------------------------------------------------

  router.get('/v1/orgs/:org/devices', (ctx, params, res) => {
    auditDenials(db, ctx, { action: 'device.list', quiet: true }, () => assertCan(db, ctx, 'device:list'));
    const rows = db
      .prepare('SELECT id, org_id, name, kind, online, created_at FROM devices WHERE org_id = ? AND deleted_at IS NULL ORDER BY name')
      .all(params.org);
    const { byDevice } = resolveDevices(db, { userId: ctx.userId, orgId: params.org, deviceIds: rows.map((d) => d.id) });
    const devices = rows
      .filter((d) => byDevice[d.id]['device:view'].effect === 'allow')
      .map((d) => deviceBody(d, byDevice[d.id]));
    send(res, 200, { devices });
  });

  router.get('/v1/orgs/:org/devices/:id', (ctx, params, res) => {
    const d = findDevice(db, params.org, params.id);
    auditDenials(db, ctx, { action: 'device.view', targetType: 'device', targetId: d.id, quiet: true }, () =>
      assertCan(db, ctx, 'device:view', d.id)
    );
    send(res, 200, deviceBody(d, resolve(db, { userId: ctx.userId, orgId: params.org, deviceId: d.id }).permissions));
  });

  router.post('/v1/orgs/:org/devices', (ctx, params, res) => {
    const { kind, online = false } = ctx.body;
    const id = newId('dev');
    auditDenials(db, ctx, { action: 'device.provision', targetType: 'device', targetId: id }, () => {
      assertCanOrgWide(db, ctx, 'device:provision');
      const name = deviceName(ctx.body.name);
      if (!KINDS.includes(kind)) throw badRequest(`kind must be one of ${KINDS.join(', ')}`);
      if (typeof online !== 'boolean') throw badRequest('online must be a boolean');
      db.prepare('INSERT INTO devices (id, org_id, name, kind, online) VALUES (?, ?, ?, ?, ?)').run(id, params.org, name, kind, online ? 1 : 0);
    });
    const d = findDevice(db, params.org, id);
    send(res, 201, deviceBody(d, resolve(db, { userId: ctx.userId, orgId: params.org, deviceId: id }).permissions));
  });

  router.patch('/v1/orgs/:org/devices/:id', (ctx, params, res) => {
    const d = findDevice(db, params.org, params.id);
    auditDenials(db, ctx, { action: 'device.update', targetType: 'device', targetId: d.id }, () => {
      assertCan(db, ctx, 'device:update', d.id);
      if (ctx.body.name !== undefined) db.prepare('UPDATE devices SET name = ? WHERE id = ?').run(deviceName(ctx.body.name), d.id);
      if (ctx.body.online !== undefined) {
        if (typeof ctx.body.online !== 'boolean') throw badRequest('online must be a boolean');
        db.prepare('UPDATE devices SET online = ? WHERE id = ?').run(ctx.body.online ? 1 : 0, d.id);
      }
    });
    send(res, 200, deviceBody(findDevice(db, params.org, d.id), resolve(db, { userId: ctx.userId, orgId: params.org, deviceId: d.id }).permissions));
  });

  // Decommission: soft delete, and a tenancy event — live sessions on it end.
  router.delete('/v1/orgs/:org/devices/:id', (ctx, params, res) => {
    const d = findDevice(db, params.org, params.id);
    auditDenials(db, ctx, { action: 'device.decommission', targetType: 'device', targetId: d.id }, () => {
      assertCan(db, ctx, 'device:provision', d.id);
      db.prepare('UPDATE devices SET deleted_at = ? WHERE id = ?').run(nowIso(), d.id);
      endActiveSessions(db, { orgId: params.org, deviceId: d.id, reason: 'device_transferred' });
    });
    send(res, 204);
  });

  // Transfer needs device:provision here (on this device) and in the destination (org
  // scope — the device does not exist there yet). The caller's token only speaks for
  // this org, so the destination is checked against their membership there directly.
  router.post('/v1/orgs/:org/devices/:id/transfer', (ctx, params, res) => {
    const d = findDevice(db, params.org, params.id);
    const { orgId: toOrg } = ctx.body;
    auditDenials(db, ctx, { action: 'device.transfer', targetType: 'device', targetId: d.id }, () => {
      assertCan(db, ctx, 'device:provision', d.id);
      if (typeof toOrg !== 'string' || !toOrg) throw badRequest('orgId is required');
      if (toOrg === params.org) throw badRequest('the device is already in this organization');
      const dest = db
        .prepare(`SELECT 1 FROM memberships m JOIN organizations o ON o.id = m.org_id AND o.deleted_at IS NULL
                   WHERE m.org_id = ? AND m.user_id = ? AND m.status = 'active'`)
        .get(toOrg, ctx.userId);
      if (!dest) throw notFound();
      assertCanOrgWide(db, { userId: ctx.userId, orgId: toOrg }, 'device:provision');

      endActiveSessions(db, { orgId: params.org, deviceId: d.id, reason: 'device_transferred' });
      db.prepare('UPDATE grants SET revoked_at = ? WHERE org_id = ? AND device_id = ? AND revoked_at IS NULL').run(nowIso(), params.org, d.id);
      db.prepare('UPDATE devices SET org_id = ? WHERE id = ?').run(toOrg, d.id);
      audit(db, { orgId: toOrg, actorId: ctx.userId, action: 'device.transfer_in', targetType: 'device', targetId: d.id, result: 'allow', requestId: ctx.requestId });
    });
    send(res, 200, { id: d.id, orgId: toOrg });
  });

  // --- grants ----------------------------------------------------------------

  router.get('/v1/orgs/:org/grants', (ctx, params, res) => {
    auditDenials(db, ctx, { action: 'grant.list', quiet: true }, () => assertCan(db, ctx, 'user:read'));
    send(res, 200, { grants: listGrants(db, params.org, { userId: ctx.query.get('userId') }) });
  });

  router.post('/v1/orgs/:org/grants', (ctx, params, res) => {
    const { userId, deviceId = null, effect, permissions } = ctx.body;
    const id = newId('grt');

    auditDenials(db, ctx, { action: 'grant.create', targetType: 'grant', targetId: id }, () => {
      assertCan(db, ctx, 'grant:create');
      if (!Array.isArray(permissions) || permissions.length === 0 || !permissions.every((p) => typeof p === 'string')) {
        throw badRequest('permissions must be a non-empty array of strings');
      }
      if (effect !== 'allow' && effect !== 'deny') throw badRequest("effect must be 'allow' or 'deny'");
      const startsAt = normalizeTs(ctx.body.startsAt, 'startsAt');
      const expiresAt = normalizeTs(ctx.body.expiresAt, 'expiresAt');
      if (expiresAt !== null && expiresAt <= nowIso()) {
        throw new HttpError(400, 'GRANT_EXPIRED', 'expiresAt is already in the past', 'expired_grant');
      }
      if (startsAt !== null && expiresAt !== null && expiresAt <= startsAt) throw badRequest('expiresAt must be after startsAt');

      if (typeof userId !== 'string') throw badRequest('userId is required');
      if (deviceId !== null && typeof deviceId !== 'string') throw badRequest('deviceId must be a string or null');
      const target = db
        .prepare(`SELECT role FROM memberships WHERE org_id = ? AND user_id = ? AND status = 'active'`)
        .get(params.org, userId);
      if (!target) throw notFound('no such member');
      if (deviceId !== null) findDevice(db, params.org, deviceId);
      if (userId === ctx.userId) throw forbidden('you cannot grant permissions to yourself', 'self_grant');
      assertCanModify(db, ctx.role, target.role);
      assertMayGrant(db, ctx, permissions, deviceId);

      db.prepare(
        `INSERT INTO grants (id, org_id, user_id, device_id, effect, starts_at, expires_at, created_by) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`
      ).run(id, params.org, userId, deviceId, effect, startsAt, expiresAt, ctx.userId);
      // The foreign key to permission_patterns is the validation: an unknown string is
      // refused by the database, never silently stored as a no-op. OR IGNORE only folds
      // duplicates in the request; it does not suppress foreign-key failures.
      const addPermission = db.prepare('INSERT OR IGNORE INTO grant_permissions (grant_id, permission) VALUES (?, ?)');
      for (const p of permissions) {
        try {
          addPermission.run(id, p);
        } catch (e) {
          if (e?.code === 'SQLITE_CONSTRAINT_FOREIGNKEY') throw badRequest(`unknown permission: ${p}`, 'unknown_permission');
          throw e;
        }
      }
      bumpPermVersion(db, { orgId: params.org, userId });
    });

    send(res, 201, listGrants(db, params.org, { id })[0]);
  });

  router.delete('/v1/orgs/:org/grants/:id', (ctx, params, res) => {
    auditDenials(db, ctx, { action: 'grant.revoke', targetType: 'grant', targetId: params.id }, () => {
      assertCan(db, ctx, 'grant:revoke');
      const g = db.prepare('SELECT user_id FROM grants WHERE id = ? AND org_id = ? AND revoked_at IS NULL').get(params.id, params.org);
      if (!g) throw notFound();
      db.prepare('UPDATE grants SET revoked_at = ? WHERE id = ?').run(nowIso(), params.id);
      bumpPermVersion(db, { orgId: params.org, userId: g.user_id });
    });
    send(res, 204);
  });

  // --- effective permissions ---------------------------------------------------

  // Self, or user:read. Org-level by default; ?deviceId= for the exact per-device set.
  router.get('/v1/orgs/:org/users/:userId/effective', (ctx, params, res) => {
    if (params.userId !== ctx.userId) {
      auditDenials(db, ctx, { action: 'user.effective', targetType: 'user', targetId: params.userId, quiet: true }, () =>
        assertCan(db, ctx, 'user:read')
      );
    }
    const member = db
      .prepare(`SELECT 1 FROM memberships WHERE org_id = ? AND user_id = ? AND status IN ('active', 'suspended')`)
      .get(params.org, params.userId);
    if (!member) throw notFound();
    const deviceId = ctx.query.get('deviceId');
    if (deviceId) findDevice(db, params.org, deviceId);
    const { role, permissions } = resolve(db, { userId: params.userId, orgId: params.org, deviceId: deviceId || null });
    send(res, 200, { role, permissions });
  });
}

