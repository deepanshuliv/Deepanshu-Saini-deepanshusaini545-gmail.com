// Sessions are records. Nothing streams, nothing is injected, nothing is executed.
//
// A session's authority is the snapshot taken when it starts (`authorized_by`), and it
// lives until its TTL. Permission changes don't end it; tenancy events do (lifecycle.js).
// Exclusivity is the partial unique index `one_exclusive_session_per_device`, not a
// check-then-insert: two parallel control requests cannot both commit.

import { send, notFound, forbidden, conflict, deviceBusy, badRequest } from '../http.js';
import { newId, nowIso } from '../db.js';
import { can, assertCanStartSession, MODE_PERMISSION } from '../permissions.js';
import { auditDenials } from '../audit.js';
import { expireSessions, snapshotAuthority, sessionExpiry } from '../lifecycle.js';

const SESSION_COLUMNS = `s.id, s.org_id, s.user_id, u.email AS user_email, u.name AS user_name,
  s.device_id, d.name AS device_name, s.mode, s.state, s.end_reason,
  s.started_at, s.expires_at, s.ended_at, s.authorized_by`;

const shape = (row) => row && { ...row, authorized_by: JSON.parse(row.authorized_by) };

function findSession(db, orgId, id) {
  const row = db
    .prepare(
      `SELECT ${SESSION_COLUMNS} FROM sessions s
         JOIN users u ON u.id = s.user_id JOIN devices d ON d.id = s.device_id
        WHERE s.id = ? AND s.org_id = ?`
    )
    .get(id, orgId);
  if (!row) throw notFound();
  return shape(row);
}

export function registerSessionRoutes(router, { db }) {
  router.post('/v1/orgs/:org/sessions', (ctx, params, res) => {
    const { deviceId, mode } = ctx.body;
    if (!(mode in MODE_PERMISSION)) throw badRequest(`mode must be one of ${Object.keys(MODE_PERMISSION).join(', ')}`);
    expireSessions(db, params.org);
    if (typeof deviceId !== 'string') throw badRequest('deviceId is required');
    const device = db.prepare('SELECT id FROM devices WHERE id = ? AND org_id = ? AND deleted_at IS NULL').get(deviceId, params.org);
    if (!device) throw notFound();

    const id = newId('ses');
    auditDenials(db, ctx, { action: `session.start.${mode}`, targetType: 'device', targetId: device.id }, () => {
      const permissions = assertCanStartSession(db, ctx, mode, device.id);
      const now = new Date();
      try {
        db.prepare(
          `INSERT INTO sessions (id, org_id, user_id, device_id, mode, state, authorized_by, started_at, expires_at)
           VALUES (?, ?, ?, ?, ?, 'active', ?, ?, ?)`
        ).run(
          id, params.org, ctx.userId, device.id, mode,
          snapshotAuthority(permissions, { userId: ctx.userId, orgId: params.org, deviceId: device.id, role: ctx.role, mode, modePermission: MODE_PERMISSION[mode] }),
          now.toISOString(), sessionExpiry(db, params.org, now)
        );
      } catch (e) {
        if (e?.code !== 'SQLITE_CONSTRAINT_UNIQUE') throw e;
        const holder = db
          .prepare(`SELECT id FROM sessions WHERE device_id = ? AND state = 'active' AND mode IN ('control', 'terminal')`)
          .pluck()
          .get(device.id);
        throw deviceBusy(`device is held by session ${holder}`);
      }
    });
    send(res, 201, findSession(db, params.org, id));
  });

  router.get('/v1/orgs/:org/sessions', (ctx, params, res) => {
    auditDenials(db, ctx, { action: 'session.list', quiet: true }, () => {
      if (!can(db, ctx, 'session:view')) throw forbidden('missing session:view');
    });
    expireSessions(db, params.org);
    const sessions = db
      .prepare(
        `SELECT ${SESSION_COLUMNS} FROM sessions s
           JOIN users u ON u.id = s.user_id JOIN devices d ON d.id = s.device_id
          WHERE s.org_id = ?
          ORDER BY (s.state = 'active') DESC, s.started_at DESC
          LIMIT 200`
      )
      .all(params.org)
      .map(shape);
    send(res, 200, { sessions });
  });

  // No :org in these paths: the token's org is the scope. A session in any other org
  // is simply not found.
  router.get('/v1/sessions/:id', (ctx, params, res) => {
    if (!ctx.orgId) throw notFound();
    expireSessions(db, ctx.orgId);
    const s = findSession(db, ctx.orgId, params.id);
    if (s.user_id !== ctx.userId) {
      auditDenials(db, ctx, { action: 'session.view', targetType: 'session', targetId: s.id, quiet: true }, () => {
        if (!can(db, ctx, 'session:view')) throw forbidden('missing session:view');
      });
    }
    send(res, 200, s);
  });

  router.delete('/v1/sessions/:id', (ctx, params, res) => {
    if (!ctx.orgId) throw notFound();
    expireSessions(db, ctx.orgId);
    const s = findSession(db, ctx.orgId, params.id);
    const own = s.user_id === ctx.userId;
    auditDenials(db, ctx, { action: own ? 'session.stop' : 'session.terminate', targetType: 'session', targetId: s.id }, () => {
      if (!own && !can(db, ctx, 'session:terminate')) throw forbidden('missing session:terminate');
      if (s.state === 'ended') throw conflict('the session has already ended');
      db.prepare(`UPDATE sessions SET state = 'ended', end_reason = ?, ended_at = ? WHERE id = ? AND state != 'ended'`)
        .run(own ? 'user_stopped' : 'admin_terminated', nowIso(), s.id);
    });
    send(res, 200, findSession(db, ctx.orgId, s.id));
  });
}

