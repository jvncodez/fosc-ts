# Cognito login for the FOSC/TS dashboard

This project’s operational dashboard is the Python viewer started by
`bin/fosc -v -p <port>`. It serves the implemented frontend in `web/` plus the
real `/api/*` endpoints. The separate `web/src/server.js` server is only a
static preview and does not include this authentication boundary.

When `SENTINELA_COGNITO_ENABLED=1`, the viewer remains bound to `127.0.0.1`
and requires Cognito Managed Login before it serves dashboard files, APIs, or
SSE. It uses Authorization Code + PKCE and verifies the Cognito ID token on the
server. The browser gets only an opaque, HttpOnly, SameSite=Lax local session
cookie. No Cognito token is stored in JavaScript, localStorage, or a file.

## Cognito app-client requirements

Create or use a User Pool app client with:

- **Public client:** no client secret.
- OAuth flow: **Authorization Code** (`code`).
- OAuth scopes: `openid profile email`.
- A Cognito Managed Login domain.
- Exact callback URL: `http://127.0.0.1:5555/auth/callback`.
- Exact logout URL: `http://127.0.0.1:5555/`.

If you use another port, register that exact port in both URLs and use it in
the environment config. Cognito callback URLs are exact matches.

## Configure this repository

```bash
cp .env.cognito.example .env.cognito
```

Edit the untracked `.env.cognito` file:

```bash
SENTINELA_COGNITO_ENABLED=1
SENTINELA_COGNITO_DOMAIN=https://YOUR_DOMAIN_PREFIX.auth.us-east-1.amazoncognito.com
SENTINELA_COGNITO_USER_POOL_ID=us-east-1_XXXXXXXXX
SENTINELA_COGNITO_CLIENT_ID=YOUR_PUBLIC_APP_CLIENT_ID
SENTINELA_PUBLIC_URL=http://127.0.0.1:5555
SENTINELA_COGNITO_REDIRECT_URI=http://127.0.0.1:5555/auth/callback
SENTINELA_COGNITO_SCOPES="openid profile email"
```

Install dependencies, load the settings into the current terminal, and start
the actual dashboard server:

```bash
./scripts/install.sh --no-tools
set -a
source .env.cognito
set +a
bin/fosc -v -p 5555
```

Open `http://127.0.0.1:5555`. The server redirects you through Cognito, then
returns to the dashboard.

### Using the Kiro CloudFront port proxy

When the browser opens a URL such as
`https://YOUR_KIRO_HOST.cloudfront.net/proxy/5555/`, register that exact HTTPS
base path with Cognito and configure both values together:

```bash
SENTINELA_PUBLIC_URL=https://YOUR_KIRO_HOST.cloudfront.net/proxy/5555
SENTINELA_COGNITO_REDIRECT_URI=https://YOUR_KIRO_HOST.cloudfront.net/proxy/5555/auth/callback
```

The app client must allow that exact callback URL and
`https://YOUR_KIRO_HOST.cloudfront.net/proxy/5555/` as a logout URL. The viewer
still listens only on `127.0.0.1`; the trusted Kiro proxy is the only external
route. Cookies are automatically marked `Secure` and scoped to the proxy path.

## Do not put secrets in `.env.cognito`

The file has only public configuration identifiers. Keep these elsewhere:

| Value | Where it belongs |
|---|---|
| `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, `AWS_SESSION_TOKEN` | Terminal environment only while using AWS CLI or Bedrock |
| Shared demo email and password | Cognito Managed Login only |
| Cognito app client secret | Nowhere. This app client must not have one |

Visit `/auth/logout` to clear the local session and the Cognito login session.
Restarting the viewer also invalidates its in-memory local sessions.
