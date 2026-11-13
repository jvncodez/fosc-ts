# Cognito login for the local FOSC/TS viewer

The local viewer remains bound to `127.0.0.1`. Cognito authenticates the person
using the browser; it does **not** expose the panel to the network or replace the
existing Host, Origin, and `X-FOSC` request guards.

The integration uses Cognito managed login with the Authorization Code flow +
PKCE. The browser never sees an access token, ID token, refresh token, or client
secret. After Cognito completes sign-in, the viewer validates the ID token against
the User Pool JWKS and sends the browser an opaque, `HttpOnly`, `SameSite=Lax`
local session cookie, valid for one hour and held only in the running viewer
process.

## 1. Create a demo User Pool

Use the temporary **AWS CLI credentials** from AWS Workshop Studio only in your
terminal, not in this repository. Set the AWS values in the same shell in which
you run these commands, then verify the account:

```bash
aws sts get-caller-identity
```

Create a basic demo pool that signs in with email:

```bash
aws cognito-idp create-user-pool \
  --pool-name fosc-ts-demo-users \
  --auto-verified-attributes email \
  --username-attributes email \
  --policies '{"PasswordPolicy":{"MinimumLength":12,"RequireUppercase":true,"RequireLowercase":true,"RequireNumbers":true,"RequireSymbols":true}}'
```

Record the returned `UserPool.Id` as `<POOL_ID>`. For a short hackathon demo,
you may leave MFA off. Require TOTP MFA before this shared account protects any
non-demo environment:

```bash
aws cognito-idp set-user-pool-mfa-config \
  --user-pool-id <POOL_ID> \
  --mfa-configuration ON \
  --software-token-mfa-configuration Enabled=true
```

## 2. Create the public browser app client

The viewer uses a **public** client: it must have **no client secret**. Register
the callback URL exactly, including `127.0.0.1`, port, and path.

```bash
aws cognito-idp create-user-pool-client \
  --user-pool-id <POOL_ID> \
  --client-name fosc-ts-local-viewer \
  --no-generate-secret \
  --allowed-o-auth-flows-user-pool-client \
  --allowed-o-auth-flows code \
  --allowed-o-auth-scopes openid profile email \
  --callback-urls http://127.0.0.1:5555/auth/callback \
  --logout-urls http://127.0.0.1:5555/ \
  --supported-identity-providers COGNITO
```

Record the returned `UserPoolClient.ClientId` as `<CLIENT_ID>`.

## 3. Create a Cognito managed-login domain

Choose a globally unique `<DOMAIN_PREFIX>` and create the managed-login domain:

```bash
aws cognito-idp create-user-pool-domain \
  --user-pool-id <POOL_ID> \
  --domain <DOMAIN_PREFIX> \
  --managed-login-version 2

aws cognito-idp create-managed-login-branding \
  --user-pool-id <POOL_ID> \
  --client-id <CLIENT_ID> \
  --use-cognito-provided-values
```

The domain is:

```text
https://<DOMAIN_PREFIX>.auth.<AWS_REGION>.amazoncognito.com
```

For example, in `us-east-1`, `demo-fosc-ts` becomes
`https://demo-fosc-ts.auth.us-east-1.amazoncognito.com`.

## 4. Create the shared demo user

Use a demo-only email inbox that your team can access. Do not use an employee's
personal password or a production password. Create the user in the Cognito
console, or create it with the CLI and set the password through the managed-login
page on its first sign-in.

Because this is a shared account, the application audit trail cannot identify an
individual operator. Do not use this model outside the time-boxed demonstration.
Create individual users before real use.

## 5. Put the viewer configuration in a local env file

Copy the tracked template. The copied file is ignored by Git:

```bash
cp .env.cognito.example .env.cognito
```

Edit `.env.cognito` with only the values returned by Cognito:

```bash
SENTINELA_COGNITO_ENABLED=1
SENTINELA_COGNITO_DOMAIN=https://<DOMAIN_PREFIX>.auth.us-east-1.amazoncognito.com
SENTINELA_COGNITO_USER_POOL_ID=<POOL_ID>
SENTINELA_COGNITO_CLIENT_ID=<CLIENT_ID>
SENTINELA_COGNITO_REDIRECT_URI=http://127.0.0.1:5555/auth/callback
SENTINELA_COGNITO_SCOPES="openid profile email"
```

Load it only into the terminal session, then start the panel:

```bash
set -a
source .env.cognito
set +a
bin/fosc -v -p 5555
```

Open `http://127.0.0.1:5555`. The viewer sends you to Cognito login and returns
to the local callback after the shared demo account signs in.

## Credentials: what goes where

| Credential/value | Where it belongs | Never put it in |
|---|---|---|
| `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, `AWS_SESSION_TOKEN` from Workshop Studio | Exported in the terminal only, while you create/manage AWS resources or run Bedrock | `.env.cognito`, source code, Git, screenshots, chat |
| User Pool ID, Client ID, managed-login domain | `.env.cognito` on each demo machine | Source code or Git |
| Demo user's email/password | Cognito managed login only | Any env file, code, or documentation |
| Cognito client secret | Nowhere. This app client must not have one. | Browser, env file, source code |

## Validation checklist

1. Run `pip install -r requirements.txt` in the project virtual environment.
2. Start the viewer. It must print `Cognito login required`; missing/malformed
   Cognito settings make it fail before opening the port.
3. Visit `http://127.0.0.1:5555` in a private browser window. It should redirect
   to Cognito.
4. Sign in, then confirm the viewer loads.
5. Visit `http://127.0.0.1:5555/auth/logout`, sign out, then revisit the panel.
   It should require login again.
6. Stop the Python viewer and start it again. The opaque local session is in
   memory and must be invalidated; the user signs in again.

If you choose another port, change both the Cognito app-client callback/logout
URLs and `SENTINELA_COGNITO_REDIRECT_URI` to that exact port before starting the
viewer.
