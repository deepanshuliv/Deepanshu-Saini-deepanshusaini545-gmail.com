// The console's only door to the server.
//
// The access token lives in this module's memory and nowhere else — never localStorage,
// never sessionStorage. The refresh token is an httpOnly cookie the page cannot read.
// A reload therefore starts with no token and asks /auth/refresh for one.

export class ApiError extends Error {
  constructor(status, code, message, reason = null) {
    super(message);
    this.status = status;
    this.code = code;
    this.reason = reason;
  }
}

let accessToken = null;
let currentOrg = null;
let inflightRefresh = null;
const listeners = new Set();

// The app subscribes here, so a session that changes underneath it (a refresh that lands
// in a different org, or a refresh that fails) re-renders the shell.
export function onSessionChange(fn) {
  listeners.add(fn);
  return () => listeners.delete(fn);
}

function adopt(session) {
  accessToken = session?.token ?? null;
  currentOrg = session?.orgId ?? null;
  for (const fn of listeners) fn(session);
  return session;
}

async function request(method, path, body, token) {
  let res;
  try {
    res = await fetch(`/v1${path}`, {
      method,
      headers: {
        ...(token ? { authorization: `Bearer ${token}` } : {}),
        ...(body !== undefined ? { 'content-type': 'application/json' } : {}),
      },
      body: body !== undefined ? JSON.stringify(body) : undefined,
      credentials: 'same-origin',
    });
  } catch {
    throw new ApiError(0, 'NETWORK', 'The server is not responding. Check that it is running, then try again.');
  }

  const text = await res.text();
  let json = null;
  try {
    json = text ? JSON.parse(text) : null;
  } catch {
    // A non-JSON body (a proxy page, a crash) still has to surface as a readable error.
  }
  if (!res.ok) {
    const e = json?.error;
    throw new ApiError(res.status, e?.code ?? `HTTP_${res.status}`, e?.message ?? `The server answered ${res.status}.`, e?.reason ?? null);
  }
  return json;
}

// One refresh at a time. Refresh tokens rotate and a replayed one revokes the whole
// family, so two concurrent refreshes from the same page would log the user out.
export function refresh(orgId = currentOrg) {
  if (!inflightRefresh) {
    inflightRefresh = request('POST', '/auth/refresh', { orgId })
      .then(adopt)
      .catch((e) => {
        adopt(null);
        throw e;
      })
      .finally(() => {
        inflightRefresh = null;
      });
  }
  return inflightRefresh;
}

export async function login(email, password) {
  return adopt(await request('POST', '/auth/login', { email, password }));
}

export async function logout() {
  try {
    await request('POST', '/auth/logout');
  } finally {
    adopt(null);
  }
}

export async function switchOrg(orgId) {
  return adopt(await api('POST', '/auth/token', { orgId }));
}

// Authenticated call. A stale token (a permission changed) or an expired one is
// refreshed once and the call retried; the server's answer after that is final.
export async function api(method, path, body) {
  try {
    return await request(method, path, body, accessToken);
  } catch (e) {
    if (e.status !== 401 || !accessToken) throw e;
    const before = currentOrg;
    await refresh();
    if (currentOrg !== before) throw new ApiError(409, 'ORG_CHANGED', 'Your access to that organization changed, so the console moved you.');
    return request(method, path, body, accessToken);
  }
}

// Unauthenticated calls for the public invite flow.
export const publicApi = (method, path, body) => request(method, path, body, null);
