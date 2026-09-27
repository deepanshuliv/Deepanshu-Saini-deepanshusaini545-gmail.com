// Invites: the only way to add a person to an org.
//
// The raw token is a bearer credential: generated here, returned exactly once in the
// create response, stored only as a keyed hash, and never logged. Single use and the
// "one live invite per email" rule are held by the database — the partial unique index
// on create, and a conditional UPDATE on accept — not by check-then-act code.

import {
  send, badRequest, conflict, notFound, gone, unauthenticated,
} from '../http.js';
import { newId, nowIso, bumpPermVersion } from '../db.js';
import { newInviteToken, hashInviteToken, hashPassword, verifyPassword } from '../auth.js';
import { assertCan } from '../permissions.js';
import { auditDenials, audit } from '../audit.js';
import { assertRoleExists, assertCanModify } from '../lifecycle.js';
import { normalizeEmail, sessionBody, issueRefresh } from './auth.js';

const INVITE_TTL_MS = 7 * 24 * 60 * 60 * 1000;
const EMAIL = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

const isUniqueViolation = (e) => e?.code === 'SQLITE_CONSTRAINT_UNIQUE';

function inviteStatus(inv, now = nowIso()) {
  if (inv.accepted_at) return 'accepted';
  if (inv.revoked_at) return 'revoked';
  if (inv.expires_at <= now) return 'expired';
  return 'pending';
}

// Map a token that is not claimable to the right refusal: unknown 404, used 409,
// cancelled or lapsed 410.
function refuse(inv) {
  if (!inv) return notFound('invite not found');
  const status = inviteStatus(inv);
  if (status === 'accepted') return conflict('this invite has already been used');
  return gone(status === 'revoked' ? 'this invite was cancelled' : 'this invite has expired');
}

const findByToken = (db, raw) =>
  db.prepare('SELECT * FROM invites WHERE token_hash = ?').get(hashInviteToken(String(raw)));

export function registerInviteRoutes(router, { db, secret }) {
  // --- org-scoped ----------------------------------------------------------

  router.post('/v1/orgs/:org/invites', (ctx, params, res) => {
    const email = normalizeEmail(ctx.body.email);
    const { role } = ctx.body;
    const raw = newInviteToken();
    const expiresAt = new Date(Date.now() + INVITE_TTL_MS).toISOString();

    const invite = auditDenials(db, ctx, { action: 'invite.create', targetType: 'invite' }, (row) => {
      assertCan(db, ctx, 'user:invite');
      if (!EMAIL.test(email)) throw badRequest('a valid email is required');
      assertRoleExists(db, role);
      assertCanModify(db, ctx.role, null, role);

      const member = db
        .prepare(
          `SELECT 1 FROM memberships m JOIN users u ON u.id = m.user_id
            WHERE m.org_id = ? AND u.email = ? AND m.status IN ('active', 'suspended')`
        )
        .get(params.org, email);
      if (member) throw conflict('that person is already a member of this organization');

      // An invite that lapsed is dead but still "live" to the unique index (it only
      // excludes accepted and revoked rows). Retire it so the email can be re-invited.
      db.prepare(
        `UPDATE invites SET revoked_at = ? WHERE org_id = ? AND email = ?
            AND accepted_at IS NULL AND revoked_at IS NULL AND expires_at <= ?`
      ).run(nowIso(), params.org, email, nowIso());

      const id = newId('inv');
      row.targetId = id;
      try {
        db.prepare(
          `INSERT INTO invites (id, org_id, email, role, token_hash, invited_by, expires_at) VALUES (?, ?, ?, ?, ?, ?, ?)`
        ).run(id, params.org, email, role, hashInviteToken(raw), ctx.userId, expiresAt);
      } catch (e) {
        if (isUniqueViolation(e)) throw conflict('there is already a pending invite for that email');
        throw e;
      }
      return { id, email, role, expiresAt, status: 'pending' };
    });

    send(res, 201, { ...invite, inviteToken: raw });
  });

  router.get('/v1/orgs/:org/invites', (ctx, params, res) => {
    auditDenials(db, ctx, { action: 'invite.list', quiet: true }, () => assertCan(db, ctx, 'user:invite'));
    const now = nowIso();
    const invites = db
      .prepare(
        `SELECT id, email, role, expires_at, accepted_at, revoked_at, invited_by AS invitedBy, created_at AS createdAt
           FROM invites WHERE org_id = ? ORDER BY created_at DESC`
      )
      .all(params.org)
      .map((inv) => ({
        id: inv.id, email: inv.email, role: inv.role, expiresAt: inv.expires_at,
        invitedBy: inv.invitedBy, createdAt: inv.createdAt, status: inviteStatus(inv, now),
      }));
    send(res, 200, { invites });
  });

  router.delete('/v1/orgs/:org/invites/:id', (ctx, params, res) => {
    auditDenials(db, ctx, { action: 'invite.revoke', targetType: 'invite', targetId: params.id }, () => {
      assertCan(db, ctx, 'user:invite');
      const changed = db
        .prepare(
          `UPDATE invites SET revoked_at = ? WHERE id = ? AND org_id = ? AND accepted_at IS NULL AND revoked_at IS NULL`
        )
        .run(nowIso(), params.id, params.org).changes;
      if (changed === 0) throw notFound();
    });
    send(res, 204);
  });

  // --- public: the token is the credential -----------------------------------

  // Just enough to render "You've been invited to Acme Robotics as operator". No org id,
  // no member list, no devices — the holder is not a member yet.
  router.get('/v1/invites/:token', (ctx, params, res) => {
    const inv = findByToken(db, params.token);
    if (!inv || inviteStatus(inv) !== 'pending') throw refuse(inv);
    const orgName = db.prepare('SELECT name FROM organizations WHERE id = ? AND deleted_at IS NULL').pluck().get(inv.org_id);
    if (!orgName) throw notFound('invite not found');
    send(res, 200, { orgName, role: inv.role, email: inv.email, expiresAt: inv.expires_at });
  });

  router.post('/v1/invites/:token/accept', (ctx, params, res) => {
    const { name, password } = ctx.body;
    const inv = findByToken(db, params.token);
    if (!inv) throw notFound('invite not found');
    const existing = db.prepare('SELECT id, password_hash FROM users WHERE email = ?').get(inv.email);

    // An existing account is attached, never duplicated — and attaching it requires
    // that account's password, so holding a token is not enough to act as someone.
    if (existing) {
      if (typeof password !== 'string' || !verifyPassword(password, existing.password_hash)) {
        throw unauthenticated('sign in with the password for this account to accept');
      }
    } else {
      if (typeof name !== 'string' || !name.trim() || name.trim().length > 100) throw badRequest('name is required');
      if (typeof password !== 'string' || password.length < 8) throw badRequest('password must be at least 8 characters');
    }
    const passwordHash = existing ? null : hashPassword(password);

    const userId = db.transaction(() => {
      const now = nowIso();
      // The arbiter: of two concurrent accepts, exactly one changes the row.
      const claimed = db
        .prepare(
          `UPDATE invites SET accepted_at = ? WHERE id = ? AND accepted_at IS NULL AND revoked_at IS NULL AND expires_at > ?`
        )
        .run(now, inv.id, now).changes;
      if (claimed === 0) throw refuse(db.prepare('SELECT * FROM invites WHERE id = ?').get(inv.id));

      const uid = existing?.id ?? newId('usr');
      if (!existing) {
        db.prepare('INSERT INTO users (id, email, name, password_hash) VALUES (?, ?, ?, ?)').run(uid, inv.email, name.trim(), passwordHash);
      }
      db.prepare('UPDATE invites SET accepted_by = ? WHERE id = ?').run(uid, inv.id);

      // Rehire: a removed membership is reactivated with the invited role; its old
      // grants were revoked at removal, so nothing carries over.
      const prior = db.prepare('SELECT status FROM memberships WHERE org_id = ? AND user_id = ?').get(inv.org_id, uid);
      if (prior && (prior.status === 'active' || prior.status === 'suspended')) {
        throw conflict('you are already a member of this organization');
      }
      if (prior) {
        db.prepare(`UPDATE memberships SET role = ?, status = 'active', invited_by = ?, joined_at = ? WHERE org_id = ? AND user_id = ?`)
          .run(inv.role, inv.invited_by, now, inv.org_id, uid);
        bumpPermVersion(db, { orgId: inv.org_id, userId: uid });
      } else {
        db.prepare(`INSERT INTO memberships (id, org_id, user_id, role, status, invited_by, joined_at) VALUES (?, ?, ?, ?, 'active', ?, ?)`)
          .run(newId('mem'), inv.org_id, uid, inv.role, inv.invited_by, now);
      }
      audit(db, { orgId: inv.org_id, actorId: uid, action: 'invite.accept', targetType: 'invite', targetId: inv.id, result: 'allow', requestId: ctx.requestId });
      return uid;
    })();

    issueRefresh(db, res, userId);
    send(res, 200, sessionBody(db, secret, userId, inv.org_id));
  });
}
