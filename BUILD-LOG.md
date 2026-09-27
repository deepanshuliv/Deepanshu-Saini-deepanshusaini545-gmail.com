# BUILD-LOG

Append to this as you go. Commit it with the code it describes — the timestamps are part of the
evidence, and a log that arrives in one commit at the end reads as what it is.

Five lines is a real entry. Short and dated is better than long and reconstructed.

The categories we look for are listed in `DISCOVERY-BRIEF.md`. The example below shows the
*shape* of a good entry; it is a recreation of something already printed in `README.md`, so it
gives nothing away.

---

<!-- EXAMPLE — delete this block, keep the shape.

## 2026-03-04 · Phase 0 — orientation

Expected the unknown-permission test to fail on my validation code.
Observed: it passed, with foreign_keys ON, and *also* passed with the pragma removed — so the
check was never running, and the "pass" was the schema loading fine while enforcing nothing.
Changed: moved `foreign_keys = ON` to connection open and re-ran; now it raises
`FOREIGN KEY constraint failed` as the README said it would.
Note: this is the failure mode where a passing test is worse than a failing one.

-->

## Phase 0 — orientation

_Installed, reset the database, read the documents, ran the suites against the untouched skeleton.
What did the starting line actually look like, and which failure surprised you?_

### 2026-09-27 · starting line

Environment: Homebrew `node` aborts on launch (`libsimdutf.34.dylib` not found, since simdutf was
upgraded under it). Using nvm's v22.23.3, which matches `.nvmrc`.

Suites on the untouched skeleton:
- `check-jwt.js`: 0 passed / 43 failed, all on the `NOT_IMPLEMENTED` stub.
- `check-permissions.js`: crashes on the first `resolve()` call, so no count.
- `check-personalisation.js`: "could not resolve at all".
- `check-api.js`: `dana logs in` got 404 and the suite aborts. There are no routes registered.
- `playwright test`: **timed out after 30s** instead of failing. This surprised me; I expected
  red tests. The cause is that `webServer.url` polls `/v1/auth/me`, and Playwright only treats
  2xx or 400–403 as "up". An empty router returns 404, so the server never counts as started.
  The UI suite can't produce a single result until `/v1/auth/me` exists and returns 401.

Personalisation (fingerprint `bb339819425c`): extra role `reviewer` at rank 35, which sits
*between* operator (30) and admin (40). Extra permission `device:reboot`. Baseline:
`device:list, device:view, user:invite, user:remove`. A reviewer can remove users but cannot
control a device, so this is another bundle that is not a level. It also means `permissions`
holds 20 rows, not the 19 the docs state.

Seed grants: 6 rows, 4 documented and 2 personalised. Sam has an **org-wide** deny on
`device:terminal` in Acme. The viewer has a device-scoped deny on `device:view` for the lobby
kiosk and a device-scoped allow of `device:view, session:start` on lab-mac-01. Dana has a
device-scoped allow of `device:control` on one Globex desk.

Docs vs code, first findings (for `DECISIONS.md` § argues with itself): `schema.sql` cites D11,
D12, D15 and D19, and `seed/orgs.json` cites "PERMISSIONS.md §11" and "§7.1", but
PERMISSIONS.md stops at D10 and §10. The seed calls audit-of-denials "invariant 10", while
PERMISSIONS.md §9 lists it as #9. The citations point at a longer version of the doc that we
don't have.

## Phase 1 — token verification

_What did you expect each failure mode to look like before you ran it? Which one behaved
differently from your expectation, and what did that tell you?_

### 2026-09-27 · predictions, written before implementing

- Malformed shapes (null, 1/2/4 segments): caught by the split. No surprises expected.
- `header is not JSON` / `payload is not JSON`: `JSON.parse` throws a `SyntaxError`. If I don't
  wrap it, the test sees `SyntaxError`, not a 401. So every decode goes through one try/catch.
- JSON that parses to a non-object (`null`, `"HS256"`, `[]`): I expect `null` to crash with a
  `TypeError` on `header.alg` unless I check that the value is a plain object first.
- `signature is not base64url`: I predict `Buffer.from(s, 'base64url')` does **not** throw. Node
  silently drops invalid characters. So this case has to be caught by the length and compare
  step, not by the decode.
- `timingSafeEqual` throws `RangeError` on unequal lengths, which would hit the truncated and
  empty signature cases. It needs a length guard in front of it.
- `exp exactly now` must be rejected: the check is `exp <= now`, not `exp < now`.

### 2026-09-27 · result

Checked the two library predictions in isolation first. Both held:
`Buffer.from('!!!not-base64!!!', 'base64url')` returns 7 bytes and does not throw, and
`timingSafeEqual` on 32 vs 6 bytes throws `RangeError`.

The first prediction changed the design. If invalid characters are dropped silently, then
comparing *decoded* signature bytes means more than one string maps to the same signature. I
tested it: flipping a padding bit in the last character of a real signature decodes to identical
bytes (`same bytes after decode: true`). A byte comparison would accept that token. So
`verifyAccessToken` re-encodes the expected HMAC and compares the **encoded strings** in
constant time, with a length guard in front. The mutated token is rejected with
`401 UNAUTHENTICATED`. `check-jwt.js` doesn't test this, so the check lives only here.

`decodeObject()` returns null for anything that isn't a plain object: bad base64url, bad JSON,
`null`, arrays, primitives. That covers the `null.alg` crash I predicted.

Every failure returns the same message ("invalid or expired token"). The reason for a rejection
isn't returned to the caller, because telling an attacker "right signature, wrong aud" helps them.

`node scripts/check-jwt.js`: **43 passed, 0 failed** on the first run.
`pv` staleness is deliberately not checked here, because it needs the DB. It belongs in
`context.js` (M2) via the existing `assertFresh`.

## Phase 2 — caller context and the resolution engine

_This is where most people's first model is wrong. Write down the model you started with, the
observation that broke it, and the model you moved to. Be specific about the observation._

### 2026-09-27 · the engine

Model: no membership → `not_a_member`; not active → `suspended`; any applicable deny →
`explicit_deny`; role baseline → allow `role:<key>`; applicable allow grant → allow
`grant:<id>`; else `implicit`. The baseline is checked before allow grants, so when both apply
the source is the role, the more stable explanation.

Wildcards match through `permissions.resource` (`device:*` ↔ `resource = 'device'`), not a string
prefix, so the catalogue decides what `user:*` covers. `device:* does NOT allow audit:read` passes.

The part the docs leave open is the org-level view. "Union across devices" I built as: org-wide
grants are the floor. An `implicit` deny there becomes allow if a device-scoped allow survives at
its own device. An org-wide deny can't be overturned, because the same deny applies at every
device. Consequence: the acme viewer's `session:start` grant on one device makes `session:start`
allow at org level, so the "start session" entry exists for them. A device-scoped deny doesn't
remove a role permission at org level.

Found while writing the grants query: a device-scoped grant on a device that was later
transferred keeps its old `org_id`. A plain union would count it in the old org. The query joins
`devices` and requires `d.org_id = g.org_id AND d.deleted_at IS NULL`.

`check-permissions.js` 35/35 and `npm run personalisation` 18/18, both on the first run (`65ac8e0`).
Every call is 3–4 queries whatever the grant count; `resolveDevices` shares them across N devices.

### 2026-09-27 · context and auth routes

`check-api.js` expects Dana and Sam to land in Acme on login, with no `orgId` sent. Nothing in
the docs says which org a login picks. I chose the earliest `joined_at` active membership, which
matches the fixture without naming a seed id.

`refresh_tokens` has no `org_id`, so a refresh can't restore the org it was issued for. The
client sends `orgId` with the refresh, and the server falls back to earliest-joined.

Refresh rotation: `UPDATE ... SET revoked_at WHERE id = ? AND revoked_at IS NULL`. The statement
that changes the row wins. If a token is presented again after rotation, `changes === 0` and
`revoked_at` is already set, so the whole `family_id` is revoked. Checked by hand: rotate → 200,
replay the old token → 401, and the rotated child → 401 too.

Login: an unknown email runs scrypt against a dummy hash, so it costs the same as a wrong
password. The response bodies are byte-identical.

The first `check-api.js` run after this commit: all auth checks pass. `no token -> 401` still
fails with 404, because `/orgs/:org/devices` isn't registered and the router 404s before
authentication runs. That's expected until M4, and it means "unknown route" and "unauthenticated"
aren't distinguishable yet.

## Phase 3 — orgs, members, invites

_Anything you had to work out that no document states. Invite lifecycle states are a common
source of this._

### 2026-09-27 · orgs, members, invites

**Docs vs test on equal rank.** PERMISSIONS.md §6 says modifying a user of equal role is `403`.
`check-api.js` has `demoting a NON-last owner is allowed`, which is Dana (owner) demoting
owner@acme (owner). Both can't hold for owners. I built "strictly lower, except owner-on-owner"
(`assertCanModify` in `lifecycle.js`). An admin→admin change is still 403. Otherwise a
multi-owner org could never hand ownership around, and LAST_OWNER would have nothing to protect.

**Invite index gap.** `one_live_invite_per_email` only excludes `accepted_at` and `revoked_at`
rows. An invite that simply **expired** still counts as live, so re-inviting that email a week
later would hit a UNIQUE violation. Create now retires lapsed invites (`revoked_at = now`) in the
same transaction, before inserting.

**Double accept.** The partial index doesn't stop two accepts of one token; both would update
the same row. The arbiter is the accept itself:
`UPDATE invites SET accepted_at WHERE id = ? AND accepted_at IS NULL AND revoked_at IS NULL AND expires_at > ?`.
Tested with two parallel accepts via `Promise.all`: one 200, one 409.

**Accepting as an existing user.** The docs say existing users get "attached, never
duplicated", but not how they prove who they are. With only the token, anyone holding the link
could attach someone else's account to an org. I now require that account's password: wrong
password → 401, right one → attached (`orgs.length` 1 → 2, same user id).

**Rehire.** A removed membership keeps its row, so on re-accept the row is reactivated, not
inserted (`UNIQUE (org_id, user_id)`). The trap: the user's old grants would come back with it.
Removal now revokes that user's grants in the org.

**Suspension and login.** A suspended membership is excluded from `orgs`, so Sam, suspended in
Acme, lands in Globex on the next login. His old Acme token → `401 TOKEN_STALE`, because suspend
bumps `perm_version`.

Audit was pulled forward from Phase 6. `auditDenials()` wraps each mutation in one transaction
and writes the allow row inside it. A 403 or 409 writes a deny row with the reason after the
rollback. 404s are not recorded: the caller never learned the target exists.

Scripted check (scratch, not committed): 49/49 across orgs, members, suspend/reinstate, invites,
revoke, concurrent accept and rehire. The audit table showed e.g. `member.role|deny|SELF_ROLE_CHANGE`
and `invite.create|deny|insufficient_rank`.

## Phase 4 — devices and grants

_What happens at the boundary where two grants disagree, or where a grant's scope and the
question's scope differ? Say what you predicted and what you got._

### 2026-09-27 · devices, grants, effective

**Scope mismatch I nearly shipped.** `assertCan(db, ctx, 'device:provision')` with no device
resolves the org-level **union**. So a device-scoped `allow device:provision` on one box would
let the holder create new devices org-wide. The union is right for nav gating and wrong for
authorizing an org-wide action. I added `assertCanOrgWide` (org-wide grants only) and use it for
provisioning and for the destination side of a transfer. `assertMayGrant` already used org scope
for org-wide grants, for the same reason.

**Unknown permission, left to the FK.** I predicted `device:teleport` would pass the laundering
check vacuously, because it expands to no catalogue rows, and then fail at insert. It does:
`SQLITE_CONSTRAINT_FOREIGNKEY` → `400 unknown_permission`, and the grant row inserted just
before it rolls back with the transaction (grant count still 3). `INSERT OR IGNORE` folds
duplicate permissions in one request (`['device:terminal','device:terminal']` → one row). I
checked that OR IGNORE does not swallow the FK error: it applies to UNIQUE/PK conflicts, not
foreign keys.

**Grants follow rank rules too.** Not stated for grants in the docs. An admin creating a
`deny org:delete` on an owner is modifying someone above them, so it goes through the same
`assertCanModify` as role changes (403).

**Device detail when `device:view` is denied.** The list omits the row. For
`GET /devices/:id` I followed the three gates in PERMISSIONS.md §5: the device is in your org
(visible), you lack the permission → 403, not 404.

**Observed:** creating a grant bumps the grantee's `perm_version`, so their existing token
becomes `TOKEN_STALE` on the very next request (`viewer old token stale after grant`). That's the
"next request reflects the change" guarantee. It also means the console must refresh and retry
on `TOKEN_STALE` rather than log the user out.

Transfer revokes the old org's grants on the device and ends its sessions
(`device_transferred`). Scripted check 44/44 (fixture rows, validation matrix, laundering,
transfer, effective per org). Earlier suites still green.

## Phase 5 — sessions

_Two permissions, one device. What did you have to resolve, and in what order, to keep the two
failure reasons distinguishable?_

### 2026-09-27 · sessions

One `resolve()` at the device, then two checks in a fixed order: `session:start` first →
`missing_permission`, then the mode permission → `missing_device_permission`. The order is the
point. The viewer on qa-android-01 lacks **both**, and the test expects `missing_permission`
("you can't open sessions at all") rather than the device-specific reason. The only exception is
suspension: a suspended caller gets `suspended`, not "missing".

Exclusivity is the partial unique index. The insert is attempted, and a
`SQLITE_CONSTRAINT_UNIQUE` is mapped to `409 DEVICE_BUSY`, naming the holder's session id in the
message. Two parallel exclusive starts (control + terminal on qa-android-01, via `Promise.all`)
gave exactly one 201 and one 409.

**TTL was a trap I only saw by writing it.** An active session past its `expires_at` still sits
in the partial unique index (`WHERE state = 'active'`), so an expired control session would keep
the device busy forever. `expireSessions(org)` runs before every session read or write and ends
those rows with `session_expired`. I tested it by moving `expires_at` into the past directly in
SQLite: the session then reads `ended/session_expired`, and a new control session on that device → 201.

Stopping one session: my first draft reused `endActiveSessions` with a user+device filter, which
would also have ended that user's other sessions on the same device (a view and a control can
coexist). I changed it to a single-row `UPDATE ... WHERE id = ?`.

Grandfathering holds without extra code: nothing in role or grant changes touches `sessions`, so
the live control session stays `active` after Sam's demotion (check-api §7.1). Suspend and
removal end sessions through `endActiveSessions`.

`check-api.js` **66/66 on the first full run**. Extra scripted checks 23/23 (concurrency, TTL,
stop vs terminate, cross-org 404, removal cascade, audit trigger refuses DELETE).

## Phase 6 — audit

_What did you decide counts as an auditable event, and what pushed you to that line?_

## Phase 7 — the console

_Where did the server's answer and your instinct disagree about what should be on screen?_

### 2026-09-27 · the console

`npx playwright test` **25/25 on the first run** (after `npm run build`: the Playwright web server
runs in production mode and serves `dist/`, so a stale or missing build fails every test).

**Where my instinct and the server disagreed:** Sam as auditor in Globex gets a **View** button
on every row, because `start-view` is governed by `device:view` (UI-INVENTORY §3). But he has no
`session:start`, so clicking it gets `403 missing_permission`. My instinct was to hide the button
unless both permissions hold, which means computing the compound rule in React. That's exactly
the re-derivation the inventory forbids. I left it as specified. The refusal shows on screen with
its code and reason (the `ErrorNote` banner), and a Sessions-card user never sees a "Start"
without `session:start`.

**Refresh replay vs. the client.** The server revokes a whole refresh family when a rotated token
is replayed. Two refreshes in flight from one page (a React StrictMode double effect, or a stale
retry racing a reload) would present the same cookie twice and log the user out. `api.js` keeps
one in-flight refresh promise; StrictMode isn't used. Two tabs in the *same* browser reloading
at the same instant can still trip it (see Open threads).

**TOKEN_STALE is routine, not an error.** A grant or role change bumps `perm_version`, so the next
call from the affected user is a 401. `api()` refreshes once and retries. If the refresh lands in
a *different* org (the membership was suspended or removed), it raises `ORG_CHANGED`, and the
keyed `Shell` remounts in the new org rather than calling the old org's URLs with the new token.

**Isolation in the DOM** comes from `<Shell key={orgId}>`: switching orgs unmounts every view, so
no state from the previous org survives. The "no other org's content" test found nothing.

**Nothing in the console knows a role.** The roles for pickers come from a new `GET /v1/roles`
(read from the table, so `reviewer` appears). The grant form's permission checkboxes are the keys
of the caller's own resolved set, so `device:reboot` appears in the form without being named in `web/`.

Joining through an invite goes to the sign-in form, not straight in (the test expects
`login-form`). The accept response's token is deliberately not adopted.

Screenshots of Sam in both orgs confirm the swap visually: Acme is cobalt with Control present
and no Audit card; Globex is amber with the Audit card and View only.

## Phase 8 — hardening

_What did you measure, what did you fix, and what did you deliberately leave alone? Anything you
chose not to build belongs here with its reason._

## Open threads

_Things you know are wrong, unfinished, or that you would do differently with another day. Listing
these honestly is worth more than pretending they do not exist — we will find them anyway._
