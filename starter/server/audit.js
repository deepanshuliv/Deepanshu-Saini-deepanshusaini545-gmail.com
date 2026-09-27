// Append-only audit writes.
//
// audit_events has BEFORE UPDATE / BEFORE DELETE triggers, so this module only ever
// INSERTs. Denied attempts are recorded as well as successes, and one action produces
// exactly one row: the allow row is written inside the same transaction as the change
// it describes, the deny row after that transaction has rolled back.

import { HttpError } from './http.js';
import { newId } from './db.js';

export function audit(db, { orgId, actorId, action, targetType = null, targetId = null, result, reasonCode = null, requestId = null }) {
  db.prepare(
    `INSERT INTO audit_events (id, org_id, actor_id, action, target_type, target_id, result, reason_code, request_id)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`
  ).run(newId('aud'), orgId, actorId, action, targetType, targetId, result, reasonCode, requestId);
}

// Refusals worth recording: the caller could see the thing and was told no. A 404 is
// not recorded — the caller never learned the target exists, and recording it against
// this org would say otherwise.
const isRefusal = (e) => e instanceof HttpError && (e.status === 403 || e.status === 409);

// Run fn(meta) in a transaction and write the allow row inside it. fn may fill in
// meta.targetId (e.g. an id it just created). If fn refuses, record the denial before
// rethrowing. `quiet: true` (reads) records denials only — a list call that succeeded
// changed nothing worth a row.
export function auditDenials(db, ctx, { quiet = false, ...meta }, fn) {
  const row = { orgId: ctx.orgId, actorId: ctx.userId, requestId: ctx.requestId, ...meta };
  try {
    return db.transaction(() => {
      const out = fn(row);
      if (!quiet) audit(db, { ...row, result: 'allow' });
      return out;
    })();
  } catch (e) {
    if (isRefusal(e) && row.orgId) {
      audit(db, { ...row, result: 'deny', reasonCode: e.reason ?? e.code });
    }
    throw e;
  }
}
