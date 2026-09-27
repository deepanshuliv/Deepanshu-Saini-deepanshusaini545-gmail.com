// Orgs and members.
//
// Every org-scoped route runs behind context.js, which has already 404'd any :org that
// is not the token's org — so `ctx.orgId` and `params.org` are the same org here.
// Mutations run inside auditDenials(): one transaction, one audit row, denials recorded.

import { send, badRequest, conflict, notFound, forbidden, selfRoleChange } from '../http.js';
import { newId, nowIso, bumpPermVersion } from '../db.js';
import { assertCan } from '../permissions.js';
import { auditDenials } from '../audit.js';
import { activeOrgs } from './auth.js';
import {
  OWNER, assertRoleExists, assertCanModify, assertNotLastOwner, endActiveSessions,
} from '../lifecycle.js';

export const THEMES = ['cobalt', 'amber', 'moss', 'plum', 'rust', 'teal'];

function orgName(value) {
  const name = typeof value === 'string' ? value.trim() : '';
  if (name.length < 1 || name.length > 80) throw badRequest('name must be 1–80 characters');
  return name;
}

// A fresh org gets the theme its creator sees least, so switching is always visible.
function pickTheme(db, userId, requested) {
  if (requested !== undefined) {
    if (!THEMES.includes(requested)) throw badRequest(`theme must be one of ${THEMES.join(', ')}`);
    return requested;
  }
  const used = activeOrgs(db, userId).map((o) => o.theme);
  return THEMES.reduce((best, t) => (used.filter((u) => u === t).length < used.filter((u) => u === best).length ? t : best));
}

function assertNameFree(db, userId, name, exceptOrgId = null) {
  const clash = activeOrgs(db, userId).some((o) => o.id !== exceptOrgId && o.name.toLowerCase() === name.toLowerCase());
  if (clash) throw conflict('you already belong to an organization with that name');
}

const orgRow = (db, id) =>
  db.prepare('SELECT id, name, theme, max_session_minutes AS maxSessionMinutes, created_at AS createdAt FROM organizations WHERE id = ?').get(id);

// A member the caller can act on: in this org and not removed. Anything else is invisible.
function findMember(db, orgId, userId) {
  const m = db
    .prepare(
      `SELECT m.user_id AS userId, m.role, m.status FROM memberships m
        WHERE m.org_id = ? AND m.user_id = ? AND m.status IN ('active', 'suspended')`
    )
    .get(orgId, userId);
  if (!m) throw notFound();
  return m;
}

// Removal is a membership change: status, version bump, sessions ended, and the
// person's grants revoked — so a later re-invite starts from the baseline, not from
// whatever they held before.
function removeMembership(db, orgId, userId) {
  db.prepare(`UPDATE memberships SET status = 'removed' WHERE org_id = ? AND user_id = ?`).run(orgId, userId);
  bumpPermVersion(db, { orgId, userId });
  db.prepare('UPDATE grants SET revoked_at = ? WHERE org_id = ? AND user_id = ? AND revoked_at IS NULL').run(nowIso(), orgId, userId);
  endActiveSessions(db, { orgId, userId, reason: 'membership_removed' });
}

export function registerOrgRoutes(router, { db }) {
  // --- orgs ----------------------------------------------------------------

  router.get('/v1/orgs', (ctx, _p, res) => send(res, 200, { orgs: activeOrgs(db, ctx.userId) }));

  // The role catalogue, for pickers. Read from the table: the console never lists roles
  // itself, and a personalised database has roles no document mentions.
  router.get('/v1/roles', (_ctx, _p, res) =>
    send(res, 200, { roles: db.prepare('SELECT key, label FROM roles ORDER BY rank DESC').all() })
  );

  router.post('/v1/orgs', (ctx, _p, res) => {
    const name = orgName(ctx.body.name);
    assertNameFree(db, ctx.userId, name);
    const theme = pickTheme(db, ctx.userId, ctx.body.theme);
    const id = newId('org');
    const now = nowIso();

    auditDenials(db, { ...ctx, orgId: id }, { action: 'org.create', targetType: 'org', targetId: id }, () => {
      db.prepare('INSERT INTO organizations (id, name, theme) VALUES (?, ?, ?)').run(id, name, theme);
      db.prepare(`INSERT INTO memberships (id, org_id, user_id, role, status, joined_at) VALUES (?, ?, ?, ?, 'active', ?)`)
        .run(newId('mem'), id, ctx.userId, OWNER, now);
    });
    send(res, 201, { ...orgRow(db, id), role: OWNER });
  });

  router.patch('/v1/orgs/:org', (ctx, params, res) => {
    const { name, theme, maxSessionMinutes } = ctx.body;
    auditDenials(db, ctx, { action: 'org.update', targetType: 'org', targetId: params.org }, () => {
      assertCan(db, ctx, 'org:update');
      if (name !== undefined) {
        const clean = orgName(name);
        assertNameFree(db, ctx.userId, clean, params.org);
        db.prepare('UPDATE organizations SET name = ? WHERE id = ?').run(clean, params.org);
      }
      if (theme !== undefined) {
        if (!THEMES.includes(theme)) throw badRequest(`theme must be one of ${THEMES.join(', ')}`);
        db.prepare('UPDATE organizations SET theme = ? WHERE id = ?').run(theme, params.org);
      }
      if (maxSessionMinutes !== undefined) {
        if (!Number.isInteger(maxSessionMinutes) || maxSessionMinutes < 1 || maxSessionMinutes > 1440) {
          throw badRequest('maxSessionMinutes must be an integer from 1 to 1440');
        }
        db.prepare('UPDATE organizations SET max_session_minutes = ? WHERE id = ?').run(maxSessionMinutes, params.org);
      }
    });
    send(res, 200, orgRow(db, params.org));
  });

  router.delete('/v1/orgs/:org', (ctx, params, res) => {
    auditDenials(db, ctx, { action: 'org.delete', targetType: 'org', targetId: params.org }, () => {
      assertCan(db, ctx, 'org:delete');
      db.prepare('UPDATE organizations SET deleted_at = ? WHERE id = ?').run(nowIso(), params.org);
      endActiveSessions(db, { orgId: params.org, reason: 'admin_terminated' });
    });
    send(res, 204);
  });

  // --- members -------------------------------------------------------------

  router.get('/v1/orgs/:org/members', (ctx, params, res) => {
    auditDenials(db, ctx, { action: 'member.list', targetType: 'org', targetId: params.org, quiet: true }, () =>
      assertCan(db, ctx, 'user:read')
    );
    const members = db
      .prepare(
        `SELECT u.id, u.id AS userId, u.email, u.name, m.role, m.status, m.joined_at AS joinedAt
           FROM memberships m JOIN users u ON u.id = m.user_id
          WHERE m.org_id = ? AND m.status IN ('active', 'suspended')
          ORDER BY m.joined_at, u.email`
      )
      .all(params.org);
    send(res, 200, { members });
  });

  // Registered before /members/:userId: first match wins.
  router.delete('/v1/orgs/:org/members/me', (ctx, params, res) => {
    auditDenials(db, ctx, { action: 'member.leave', targetType: 'user', targetId: ctx.userId }, () => {
      assertNotLastOwner(db, params.org, ctx.userId);
      removeMembership(db, params.org, ctx.userId);
    });
    send(res, 204);
  });

  router.patch('/v1/orgs/:org/members/:userId', (ctx, params, res) => {
    const { role } = ctx.body;
    auditDenials(db, ctx, { action: 'member.role', targetType: 'user', targetId: params.userId }, () => {
      assertCan(db, ctx, 'user:role:update');
      const target = findMember(db, params.org, params.userId);
      if (params.userId === ctx.userId) throw selfRoleChange();
      assertRoleExists(db, role);
      assertCanModify(db, ctx.role, target.role, role);
      if (target.role === role) return;
      if (target.role === OWNER) assertNotLastOwner(db, params.org, params.userId);
      db.prepare('UPDATE memberships SET role = ? WHERE org_id = ? AND user_id = ?').run(role, params.org, params.userId);
      bumpPermVersion(db, { orgId: params.org, userId: params.userId });
      // No session is ended here: a role change is a permission tweak (grandfathered).
    });
    send(res, 200, findMember(db, params.org, params.userId));
  });

  router.post('/v1/orgs/:org/members/:userId/suspend', (ctx, params, res) => {
    auditDenials(db, ctx, { action: 'member.suspend', targetType: 'user', targetId: params.userId }, () => {
      assertCan(db, ctx, 'user:remove');
      const target = findMember(db, params.org, params.userId);
      if (params.userId === ctx.userId) throw forbidden('you cannot suspend yourself', 'self');
      assertCanModify(db, ctx.role, target.role);
      if (target.status === 'suspended') return;
      assertNotLastOwner(db, params.org, params.userId);
      db.prepare(`UPDATE memberships SET status = 'suspended' WHERE org_id = ? AND user_id = ?`).run(params.org, params.userId);
      bumpPermVersion(db, { orgId: params.org, userId: params.userId });
      endActiveSessions(db, { orgId: params.org, userId: params.userId, reason: 'user_suspended' });
    });
    send(res, 200, findMember(db, params.org, params.userId));
  });

  router.delete('/v1/orgs/:org/members/:userId/suspend', (ctx, params, res) => {
    auditDenials(db, ctx, { action: 'member.reinstate', targetType: 'user', targetId: params.userId }, () => {
      assertCan(db, ctx, 'user:remove');
      const target = findMember(db, params.org, params.userId);
      assertCanModify(db, ctx.role, target.role);
      if (target.status === 'active') return;
      db.prepare(`UPDATE memberships SET status = 'active' WHERE org_id = ? AND user_id = ?`).run(params.org, params.userId);
      bumpPermVersion(db, { orgId: params.org, userId: params.userId });
    });
    send(res, 200, findMember(db, params.org, params.userId));
  });

  router.delete('/v1/orgs/:org/members/:userId', (ctx, params, res) => {
    auditDenials(db, ctx, { action: 'member.remove', targetType: 'user', targetId: params.userId }, () => {
      assertCan(db, ctx, 'user:remove');
      const target = findMember(db, params.org, params.userId);
      if (params.userId !== ctx.userId) assertCanModify(db, ctx.role, target.role);
      assertNotLastOwner(db, params.org, params.userId);
      removeMembership(db, params.org, params.userId);
    });
    send(res, 204);
  });
}
