// Auth: login, refresh (rotating), switch org, me, logout.
//
// Access token: returned in the body, held in memory by the client.
// Refresh token: opaque, hashed at rest, sent only as an httpOnly cookie scoped to
// /v1/auth. It carries no org — the org is chosen per exchange, from the request or the
// user's earliest-joined active membership.

import { randomUUID } from 'node:crypto';
import {
  issueAccessToken, verifyPassword, hashPassword,
  newRefreshToken, hashRefreshToken, REFRESH_TTL_SECONDS,
} from '../auth.js';
import { send, unauthenticated, notFound, badRequest } from '../http.js';
import { newId, nowIso } from '../db.js';
import { resolve } from '../permissions.js';

const COOKIE = 'ro_refresh';

// Compared against when the email is unknown, so an unknown account costs the same
// scrypt as a wrong password and the two are indistinguishable by timing too.
const DUMMY_HASH = hashPassword(randomUUID());

export const normalizeEmail = (email) => (typeof email === 'string' ? email.trim().toLowerCase() : '');

export function activeOrgs(db, userId) {
  return db
    .prepare(
      `SELECT o.id, o.name, o.theme, m.role
         FROM memberships m
         JOIN organizations o ON o.id = m.org_id AND o.deleted_at IS NULL
        WHERE m.user_id = ? AND m.status = 'active'
        ORDER BY m.joined_at, o.created_at, o.id`
    )
    .all(userId);
}

// The body every token-issuing endpoint returns. `orgId` null or unknown falls back to
// the earliest-joined active org; a user with none gets an org-less token.
export function sessionBody(db, secret, userId, orgId = null) {
  const orgs = activeOrgs(db, userId);
  const org = orgs.find((o) => o.id === orgId) ?? orgs[0] ?? null;
  const membership = org
    ? db.prepare('SELECT role, perm_version FROM memberships WHERE user_id = ? AND org_id = ?').get(userId, org.id)
    : null;

  const token = issueAccessToken(
    { userId, orgId: org?.id ?? null, role: membership?.role ?? null, permVersion: membership?.perm_version ?? 0 },
    secret
  );
  const user = db.prepare('SELECT id, email, name FROM users WHERE id = ?').get(userId);
  return { token, user, orgId: org?.id ?? null, role: membership?.role ?? null, orgs };
}

// Mint a refresh token in `familyId` (a new family on login) and set it as the cookie.
export function issueRefresh(db, res, userId, familyId = randomUUID()) {
  const raw = newRefreshToken();
  db.prepare(
    `INSERT INTO refresh_tokens (id, user_id, token_hash, family_id, expires_at) VALUES (?, ?, ?, ?, ?)`
  ).run(newId('rt'), userId, hashRefreshToken(raw), familyId, new Date(Date.now() + REFRESH_TTL_SECONDS * 1000).toISOString());
  res.setHeader('set-cookie', cookie(raw, REFRESH_TTL_SECONDS));
}

const cookie = (value, maxAge) =>
  `${COOKIE}=${value}; HttpOnly; Secure; SameSite=Strict; Path=/v1/auth; Max-Age=${maxAge}`;

function readCookie(req, name) {
  for (const part of (req.headers.cookie ?? '').split(';')) {
    const [k, ...v] = part.trim().split('=');
    if (k === name) return v.join('=');
  }
  return null;
}

export function registerAuthRoutes(router, { db, secret }) {
  router.post('/v1/auth/login', (ctx, _params, res) => {
    const { password, orgId } = ctx.body;
    const user = db.prepare('SELECT id, password_hash FROM users WHERE email = ?').get(normalizeEmail(ctx.body.email));

    // One outcome for "no such account" and "wrong password": no enumeration oracle.
    const ok = verifyPassword(typeof password === 'string' ? password : '', user?.password_hash ?? DUMMY_HASH);
    if (!user || !ok) throw unauthenticated('email or password is incorrect');

    issueRefresh(db, res, user.id);
    send(res, 200, sessionBody(db, secret, user.id, orgId));
  });

  // Rotation. The UPDATE ... WHERE revoked_at IS NULL is the arbiter: of two concurrent
  // refreshes with the same token exactly one changes a row; the other is a replay.
  router.post('/v1/auth/refresh', (ctx, _params, res) => {
    const raw = readCookie(ctx.req, COOKIE);
    const row = raw && db.prepare('SELECT * FROM refresh_tokens WHERE token_hash = ?').get(hashRefreshToken(raw));
    if (!row) throw unauthenticated('no valid refresh token');

    const now = nowIso();
    const rotated = db.transaction(() => {
      const claimed = db
        .prepare('UPDATE refresh_tokens SET revoked_at = ? WHERE id = ? AND revoked_at IS NULL AND expires_at > ?')
        .run(now, row.id, now).changes === 1;
      if (!claimed && row.revoked_at !== null) {
        // Replay of a rotated token: someone else holds the family. Kill all of it.
        db.prepare('UPDATE refresh_tokens SET revoked_at = ? WHERE family_id = ? AND revoked_at IS NULL').run(now, row.family_id);
      }
      return claimed;
    })();
    if (!rotated) {
      res.setHeader('set-cookie', cookie('', 0));
      throw unauthenticated('refresh token is no longer valid');
    }

    issueRefresh(db, res, row.user_id, row.family_id);
    send(res, 200, sessionBody(db, secret, row.user_id, ctx.body.orgId));
  });

  router.post('/v1/auth/logout', (ctx, _params, res) => {
    const raw = readCookie(ctx.req, COOKIE);
    if (raw) {
      const row = db.prepare('SELECT family_id FROM refresh_tokens WHERE token_hash = ?').get(hashRefreshToken(raw));
      if (row) db.prepare('UPDATE refresh_tokens SET revoked_at = ? WHERE family_id = ? AND revoked_at IS NULL').run(nowIso(), row.family_id);
    }
    res.setHeader('set-cookie', cookie('', 0));
    send(res, 204);
  });

  // Switch org: a new token scoped to another org the caller is an active member of.
  router.post('/v1/auth/token', (ctx, _params, res) => {
    const { orgId } = ctx.body;
    if (typeof orgId !== 'string' || !orgId) throw badRequest('orgId is required');
    if (!activeOrgs(db, ctx.userId).some((o) => o.id === orgId)) throw notFound();
    send(res, 200, sessionBody(db, secret, ctx.userId, orgId));
  });

  router.get('/v1/auth/me', (ctx, _params, res) => {
    const user = db.prepare('SELECT id, email, name FROM users WHERE id = ?').get(ctx.userId);
    const org = ctx.orgId
      ? db.prepare('SELECT id, name, theme, max_session_minutes AS maxSessionMinutes FROM organizations WHERE id = ?').get(ctx.orgId)
      : null;
    const resolved = ctx.orgId ? resolve(db, { userId: ctx.userId, orgId: ctx.orgId }) : { permissions: {} };
    send(res, 200, {
      user,
      org,
      orgId: ctx.orgId,
      role: ctx.role,
      status: ctx.membership?.status ?? null,
      orgs: activeOrgs(db, ctx.userId),
      permissions: resolved.permissions,
    });
  });
}
