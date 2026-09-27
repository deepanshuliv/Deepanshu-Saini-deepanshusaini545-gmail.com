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

## Phase 2 — caller context and the resolution engine

_This is where most people's first model is wrong. Write down the model you started with, the
observation that broke it, and the model you moved to. Be specific about the observation._

## Phase 3 — orgs, members, invites

_Anything you had to work out that no document states. Invite lifecycle states are a common
source of this._

## Phase 4 — devices and grants

_What happens at the boundary where two grants disagree, or where a grant's scope and the
question's scope differ? Say what you predicted and what you got._

## Phase 5 — sessions

_Two permissions, one device. What did you have to resolve, and in what order, to keep the two
failure reasons distinguishable?_

## Phase 6 — audit

_What did you decide counts as an auditable event, and what pushed you to that line?_

## Phase 7 — the console

_Where did the server's answer and your instinct disagree about what should be on screen?_

## Phase 8 — hardening

_What did you measure, what did you fix, and what did you deliberately leave alone? Anything you
chose not to build belongs here with its reason._

## Open threads

_Things you know are wrong, unfinished, or that you would do differently with another day. Listing
these honestly is worth more than pretending they do not exist — we will find them anyway._
