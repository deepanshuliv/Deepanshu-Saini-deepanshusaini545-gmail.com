# RemoteOps — multi-org permission console

Submission for the Rhinostream full-stack hackathon.

## Run it (from a clean checkout)

```sh
cd starter && npm install && npm run db:reset && npm run dev   # http://localhost:8080
```

Node 22 (see `starter/.nvmrc`).

## Where things are

| Path | What |
|---|---|
| `starter/` | the application: `server/` (API) and `web/` (React console) |
| `BUILD-LOG.md` | the build log, written as the work happened |
| `DECISIONS.md` | decisions, rejected alternatives, and where the docs disagree |
| `BRIEF.md`, `PERMISSIONS.md`, `AUTH-DATA-MODEL.md`, `UI-INVENTORY.md`, `WORKFLOW.md` | the task documents as handed out |

## Tests

```sh
cd starter
node scripts/check-jwt.js
node scripts/check-permissions.js
npm run personalisation
node scripts/check-api.js
npx playwright test
```
