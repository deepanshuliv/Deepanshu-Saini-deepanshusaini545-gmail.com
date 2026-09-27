// The audit log, read side. Writes live in ../audit.js.
//
// Pagination bounds are defined, not clamped: a limit outside 1..500 or a negative or
// non-integer offset is a 400, so a client learns its request was wrong rather than
// silently getting a different page than it asked for.

import { send, badRequest } from '../http.js';
import { assertCan } from '../permissions.js';
import { auditDenials } from '../audit.js';

const MAX_LIMIT = 500;

function intParam(query, name, fallback, min, max) {
  const raw = query.get(name);
  if (raw === null) return fallback;
  if (!/^-?\d+$/.test(raw)) throw badRequest(`${name} must be an integer`);
  const n = Number(raw);
  if (n < min || n > max) throw badRequest(`${name} must be between ${min} and ${max}`);
  return n;
}

export function registerAuditRoutes(router, { db }) {
  router.get('/v1/orgs/:org/audit', (ctx, params, res) => {
    auditDenials(db, ctx, { action: 'audit.read', quiet: true }, () => assertCan(db, ctx, 'audit:read'));
    const limit = intParam(ctx.query, 'limit', 50, 1, MAX_LIMIT);
    const offset = intParam(ctx.query, 'offset', 0, 0, Number.MAX_SAFE_INTEGER);

    const events = db
      .prepare(
        `SELECT a.id, a.org_id, a.actor_id, u.email AS actor_email, a.action, a.target_type, a.target_id,
                a.result, a.reason_code, a.request_id, a.at
           FROM audit_events a LEFT JOIN users u ON u.id = a.actor_id
          WHERE a.org_id = ?
          ORDER BY a.at DESC, a.id DESC
          LIMIT ? OFFSET ?`
      )
      .all(params.org, limit, offset);
    const total = db.prepare('SELECT COUNT(*) FROM audit_events WHERE org_id = ?').pluck().get(params.org);
    send(res, 200, { events, limit, offset, total });
  });
}
