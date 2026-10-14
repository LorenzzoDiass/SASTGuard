# Authentication & Session Management

SASTGuard protects its API and dashboard with JWT-based authentication.

## Model

* **Stateless JWT (HS256).** On login the backend returns a signed access token
  carrying the user id (`sub`), username and admin flag. The dashboard stores it
  in `localStorage` and sends it as `Authorization: Bearer <token>` on every
  request. "Logout" discards the token client-side (the `/api/auth/logout`
  endpoint exists for a clean contract and future revocation).
* **Password hashing** uses bcrypt via passlib; only the hash is persisted
  (`users` table). There is no public sign-up — users are created by the startup
  bootstrap or, later, by an admin.
* **Route protection**: `scans`, `findings`, `dashboard` and `security-gate`
  routers require a valid token. `/health`, `/` and `/api/auth/login` are public.

## Configuration (env)

| Variable | Default | Meaning |
|----------|---------|---------|
| `AUTH_ENABLED` | `true` | When `false`, the API is open (CLI/CI/demo). |
| `SECRET_KEY` | dev placeholder | HS256 signing secret. **Must** be a long random value in production. |
| `JWT_ALGORITHM` | `HS256` | Token algorithm. |
| `ACCESS_TOKEN_EXPIRE_MINUTES` | `480` | Session lifetime. |
| `ADMIN_USERNAME` | `admin` | Bootstrap admin username (label only, not a credential). |
| `ADMIN_PASSWORD` | *(empty)* | **Required** to create the first admin. If empty, no admin is created. Never logged, never defaulted. |
| `CORS_ORIGINS` | localhost:3000,5173 | Comma-separated allowed dashboard origins. |

### Production fail-closed guarantees

When `APP_ENV=production`, the app **refuses to start** if:
* `AUTH_ENABLED` is not `true` (no accidental open-API bypass in production), or
* `SECRET_KEY` is the insecure default or shorter than 16 characters.

In non-production environments these become warnings so local dev, the CLI and
the test suite keep working. `AUTH_ENABLED=false` is therefore only usable
outside production (CLI/CI/demo), never in a production deployment.

> `AUTH_ENABLED` exists so the CLI/CI pipeline and local engine tests — which do
> not go through HTTP — are never blocked. Production keeps it `true` with a
> strong `SECRET_KEY`, enforced by the startup guard above.

## Endpoints

* `POST /api/auth/login` — `{username, password}` -> `{access_token, token_type,
  expires_in, user}`.
* `GET /api/auth/me` — current user (requires token).
* `POST /api/auth/logout` — stateless acknowledgement.

## Bootstrap

On first startup, if no user exists and auth is enabled, an admin is created from
`ADMIN_USERNAME`/`ADMIN_PASSWORD` **only when `ADMIN_PASSWORD` is set**. There
are no default credentials, and the password is never generated or logged. If
`ADMIN_PASSWORD` is unset, the app logs that no admin was created and continues;
set the variable and restart to create the first administrator.

## Frontend

* `AuthProvider` (`src/auth/AuthContext.tsx`) holds the token (localStorage) and
  resolves the current user via `/api/auth/me`.
* `ProtectedRoute` redirects unauthenticated users to `/login` and preserves the
  intended destination.
* The API layer attaches the Bearer header and, on any `401`, clears the session
  (global `onUnauthorized` handler), so expired tokens send the user back to
  login.

## Token storage: decision & limitation (honest)

The dashboard stores the JWT in `localStorage` and sends it as a Bearer header.

We evaluated moving to an **HttpOnly + Secure cookie with CSRF protection**, which
is the stronger option because JavaScript cannot read an HttpOnly cookie (so an
XSS cannot exfiltrate the token). We are **not** adopting it in this iteration for
an honest architectural reason: the planned deployment is **split-origin**
(frontend on Vercel, backend on Render — different registrable domains). An
HttpOnly session cookie would then be a **third-party cookie** requiring
`SameSite=None; Secure`, exact-origin CORS with credentials, and an added CSRF
token flow. Third-party cookies are increasingly blocked by browsers, which
would make logins unreliable in exactly the target environment.

Current honest posture and its limitation:

* **Limitation:** a successful XSS in the dashboard could read the token from
  `localStorage`. We do not claim otherwise.
* **Mitigations that genuinely apply:** short token lifetime
  (`ACCESS_TOKEN_EXPIRE_MINUTES`, default 8h — reduce for higher security), the
  token carries no secret beyond identity claims, the client clears it on logout
  and on any `401`, and the CSP/escaping practices of the SPA reduce XSS surface.
* **When to switch to HttpOnly cookies:** if frontend and backend are served
  from the **same site** (e.g. the dashboard behind the same domain/reverse
  proxy as the API, as in the Docker Compose setup), a `SameSite=Strict/Lax`
  HttpOnly cookie + CSRF token becomes viable and is the recommended upgrade.

## What must be configured outside this repo

* A strong `SECRET_KEY` (e.g. `openssl rand -hex 32`) in the deploy environment.
* `ADMIN_PASSWORD` (and optionally `ADMIN_USERNAME`) for a known first login,
  or read the generated password from the first-boot logs.
* `CORS_ORIGINS` set to the deployed dashboard origin (e.g. the Vercel URL).
* On the frontend host (Vercel), `VITE_API_BASE_URL` pointing at the backend.
