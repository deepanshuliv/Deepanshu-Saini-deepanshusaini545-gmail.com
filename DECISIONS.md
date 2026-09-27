# DECISIONS

One section per decision that a reviewer might reasonably have made differently. Every section has
the same four parts, and the third and fourth are the ones we weigh most.

Rules, from `DISCOVERY-BRIEF.md`:

- cite something real in `Why` — a commit, a test, an error string, a file and line
- do not restate what a document says; describe what you did when the documents ran out
- six to twelve decisions is the expected range

---

### The org-level view counts device-scoped allows, but only on top of an org-scope floor

**What I chose:** org-level answers (nav, `/auth/me`) start from org-wide grants only. An
`implicit` deny there becomes allow if some device-scoped allow survives at its own device
(`permissionsOrgLevel`, `starter/server/permissions.js:98`). An org-wide deny is never overturned.
**Why:** the docs say "union across all devices" but not how deny interacts with it. With this
rule, the fixture viewer's `session:start` grant on lab-mac-01 puts "Start a session" in their
Sessions card, and `check-permissions.js` stays 35/35 (`65ac8e0`), including
`device-scoped ALLOW does NOT carve out org-wide DENY`.
**What I rejected:** (a) org-level = org-wide grants only: the viewer could never find the one
action they were granted. (b) A literal union where any device-scoped deny also removes the
permission at org level: one blocked kiosk would hide Control from an operator's whole nav.
**What would change my mind:** a UI case expecting a nav entry to disappear because of a
device-scoped deny on one device.

### The union is for showing things; org-wide actions are authorized at org scope only

**What I chose:** `assertCanOrgWide` (`permissions.js:168`) for provisioning and for the
destination side of a transfer; `assertMayGrant` checks org-wide grants against the org scope,
not the union.
**Why:** while wiring `POST /devices` I saw that `assertCan(..., 'device:provision')` with no
device resolves the union, so an allow on one device would authorize creating devices anywhere.
Logged under Phase 4 (`b84e69e`).
**What I rejected:** one `assertCan` for everything. It is simpler, but it turns a device-scoped
grant into org-wide authority, which is the laundering D9 exists to stop.
**What would change my mind:** a spec statement that device-scoped provision grants are meant
to confer org-wide provisioning.

### Refusals, single use and exclusivity are decided by the database write, not a prior read

**What I chose:** every "exactly one wins" rule is a statement whose row count or constraint
decides:
- refresh rotation: `UPDATE ... WHERE revoked_at IS NULL` (`routes/auth.js:97`);
- invite accept: conditional `UPDATE` (`routes/invites.js:149`);
- one live invite: `one_live_invite_per_email`;
- exclusive sessions: `one_exclusive_session_per_device`, mapped from `SQLITE_CONSTRAINT_UNIQUE`
  to 409 (`routes/sessions.js:55`);
- unknown permission: the FK to `permission_patterns` → 400 `unknown_permission` (`routes/devices.js:191`).

**Why:** tested with parallel requests: two accepts → one 200 / one 409; control+terminal →
one 201 / one 409; three invite creates → one 201 / two 409 (BUILD-LOG Phases 3, 5, 8).
**What I rejected:** check-then-insert (`SELECT` for a live session, then `INSERT`). It passes
every sequential test and fails the concurrent one.
**What would change my mind:** moving off a single SQLite writer to something where these
statements don't serialize, e.g. multiple processes without the partial indexes.

### An expired session must stop holding its device, so TTL is enforced lazily on every session touch

**What I chose:** `expireSessions(org)` (`lifecycle.js:66`) ends overdue sessions before any
session read or write.
**Why:** the exclusivity index is `WHERE state = 'active'`, and nothing flips `state` when
`expires_at` passes. An expired control session would keep the device `DEVICE_BUSY` forever.
Shown by moving `expires_at` into the past: the session then reads `ended/session_expired` and a
new control start → 201 (BUILD-LOG Phase 5).
**What I rejected:** a background timer (a second moving part, and a window between expiry and
the sweep); computing "effectively active" only at read time (the unique index would still see
the row as active).
**What would change my mind:** a requirement to show sessions as ended the instant they expire,
with no request in between. That needs a scheduler.

### Suspension is enforced once, in the request context, not only in the engine

**What I chose:** `context.js:55` refuses every org-scoped route for a suspended membership with
`403 suspended`, except identity routes (`/auth/*`, `GET/POST /orgs`, `/roles`).
**Why:** routes with no permission check (your own session, leaving, your own effective set)
never consult the engine's empty set. With a hand-signed current-`pv` token they returned 200;
after the guard, 403 (`92036a5`, BUILD-LOG Phase 8).
**What I rejected:** adding the check to each ungated route. It works today, but the next ungated
route forgets it.
**What would change my mind:** a need for suspended members to still see their own session history.

### Owners may modify owners; everyone else only modifies strictly lower ranks

**What I chose:** `assertCanModify` (`lifecycle.js:28`): strictly lower, except owner→owner. A
new role may not outrank the caller, and only an owner confers owner. Grants go through the same
rule.
**Why:** `check-api.js` requires `demoting a NON-last owner is allowed` (owner demoting owner),
while PERMISSIONS §6 forbids equal-rank changes (see the next section).
**What I rejected:** the literal "strictly lower". With it, an org with two owners can never
change either owner's role, and `LAST_OWNER` can never trigger through a demotion.
**What would change my mind:** a statement that owner changes must go through a separate
ownership-transfer flow.

### An existing user accepting an invite must prove they own the account

**What I chose:** accepting as an email that already has an account requires that account's
password (`routes/invites.js:138`); new accounts set one.
**Why:** the docs say existing users are "attached, never duplicated" but say nothing about
proof. With only the token, anyone holding a forwarded link could attach someone else's account.
Tested: wrong password → 401, right password → attached, same user id (BUILD-LOG Phase 3).
**What I rejected:** token-only acceptance, which is simpler and what the docs literally
describe.
**What would change my mind:** invite tokens delivered only to a verified mailbox. Then the
token already proves control of the email.

### Removal revokes the person's grants in that org

**What I chose:** `removeMembership` sets `revoked_at` on all of the user's grants in the org.
Rehire reactivates the same membership row with the invited role.
**Why:** `UNIQUE (org_id, user_id)` forces rehire to reuse the row. Without revocation, a person
rehired as viewer would silently get back every allow they held before offboarding.
**What I rejected:** leaving the grants and relying on `status = 'removed'`. It's correct while
they're gone and wrong the moment they come back.
**What would change my mind:** a product rule that a rehire restores previous access.

### Resolve fresh every request; no cache

**What I chose:** no resolution cache. Each call is 4 queries (membership, catalogue, baseline,
grants) whatever the number of devices, and `resolveDevices` shares them across rows.
**Why:** measured (BUILD-LOG Phase 8 · speed): 5 devices → 4 queries, 0.09 ms; 1,005 devices and 200
grants → still 4 queries, 2.5 ms; `GET /devices` over HTTP about 10 ms at 1,005 rows. There's no
latency to buy back, and with no cache there is no path to stale authority (D7 expiry, `pv` bumps).
**What I rejected:** a `(userId, orgId)` cache keyed on `perm_version`. It is correct for grants
and roles but not for time-window expiry, which changes the answer with no write at all.
**What would change my mind:** resolution showing up in a profile. Then a cache keyed on
`(userId, orgId, perm_version)` with a TTL bounded by the next `starts_at`/`expires_at`.

### The console asks the server what exists: no role names, no permission list in `web/`

**What I chose:** every gated element renders from a server-resolved set (`web/components/Gate.jsx`).
Role options come from `GET /v1/roles`; the grant form's checkboxes are the keys of the caller's
resolved set.
**Why:** the personalised DB has `reviewer` and `device:reboot`, which no document names. Both
appear in the pickers without appearing in the code. Playwright's "element vanishes when the
server withdraws the permission" passes (25/25, `51745ee`).
**What I rejected:** hiding "View" unless both `device:view` and `session:start` hold. It's
friendlier, but it recomputes the compound rule in React. The button follows the inventory and
the server's 403 explains the rest.
**What would change my mind:** the server sending a resolved `can_start:{view,control,terminal}`
per row. Then the console could show exactly that, without deriving it.

---

## Where this repo argues with itself

1. **Equal-rank modification.** PERMISSIONS.md §6: *"modify a user of equal role (admin → admin) |
   `403`"*. `scripts/check-api.js`: *"demoting a NON-last owner is allowed"*, where Dana (owner)
   demotes owner@acme (owner) and expects 200. **Built against:** the test, as "strictly lower,
   except owner→owner". admin→admin is still 403. The written rule, applied to owners, makes
   `LAST_OWNER` unreachable by demotion.
2. **How many permissions exist.** BRIEF.md §2 and PERMISSIONS.md §2: *"the 19 permissions"*,
   and PERMISSIONS §4 says `*` expands to "all nineteen". The database (personalised) has 20
   (`device:reboot`), and a sixth role. **Built against:** the database. The catalogue is read
   per call, and `*` expands through `permissions.resource`.
3. **Citations to sections that don't exist.** `db/schema.sql` cites D11, D12, D15, D19;
   `seed/orgs.json` cites "PERMISSIONS.md §11" and "§7.1"; `scripts/check-permissions.js` says
   its cases come from "§11 or §12". PERMISSIONS.md stops at D10 and §10. The seed calls audit
   of denials "invariant 10", while §9 lists it as #9. **Built against:** the rules as stated in
   the sections that do exist. Nothing depended on the missing ones.
4. **Invite uniqueness vs. expiry.** AUTH-DATA-MODEL §6: *"seven days sets the expiry. Both leave
   a dead token"*. The index `one_live_invite_per_email` treats an unaccepted, unrevoked invite
   as live even after it expires, so re-inviting after expiry violates it. **Built against:**
   the schema (not edited). Creation retires lapsed invites in the same transaction first.
5. **Where a suspended member stands.** AUTH-DATA-MODEL §10: *"a token for a suspended
   membership → `403` with an empty permission set"*. Yet suspend bumps `perm_version`, so every
   token the API issued is `TOKEN_STALE` (401) first, and login and switch never mint a token
   into a suspended org. The 403 path is only reachable with a token signed outside the API.
   **Built against:** both. Stale → 401 as tested; a current-`pv` suspended token → 403
   `suspended` on every org route.

## Deliberately not built

- **Pagination on members, devices and grants.** `GET /devices` at 1,005 rows is about 10 ms
  and 1.5 MB, because each row carries the full resolved set, which the spec requires. That's
  fine at the fixture scale the brief targets. Audit, the only unbounded list, is paginated with
  strict bounds.
- **Search, bulk operations, theme editing beyond the six palettes.** None of them change the
  permission model, and the brief asks for depth there.
- **Real file transfer / remote access.** "Transfer files" is a permission-gated entry that says
  what it would do; sessions are records (ground rule).
- **Email delivery.** The invite link is shown once to the inviter to pass on, as the README says.
- **Rate limiting** on login and invite accept. Out of scope per the README; scrypt cost is the
  only brake.
- **Audit rows for 401/404.** A 404 is not recorded against the org the caller asked about: the
  caller never learned the target exists, and a row would say otherwise. Suspended-member
  refusals from the context guard aren't audited either (no request id at that layer); noted
  under Open threads.

## Tools used

- **Claude Code (Anthropic's AI coding assistant)** was used throughout to draft code, tests and
  log entries. I directed the work milestone by milestone, reviewed each change, ran the suites
  myself, and edited the write-up. No code was taken from the reference implementation or any
  public solution; the organiser-only reference tree was removed from this repository unread
  (`23fd29d`).
- No runtime libraries beyond those the starter ships (`better-sqlite3`, React, Vite, Playwright).
