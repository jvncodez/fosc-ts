const OAUTH_TRANSACTION_KEY = 'fosc.oauth.transaction';
const OAUTH_TOKEN_KEY = 'fosc.oauth.access-token';
const CLOCK_SKEW_SECONDS = 30;
let configPromise;
let bootstrapPromise;

function base64Url(bytes) {
  let binary = '';
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function randomUrlSafe(size = 32) {
  const bytes = new Uint8Array(size);
  crypto.getRandomValues(bytes);
  return base64Url(bytes);
}

async function sha256UrlSafe(value) {
  const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(value));
  return base64Url(new Uint8Array(digest));
}

function readJson(key) {
  try { return JSON.parse(sessionStorage.getItem(key) || 'null'); }
  catch { return null; }
}

function decodeJwtPayload(token) {
  try {
    const encoded = token.split('.')[1];
    const padded = encoded.replace(/-/g, '+').replace(/_/g, '/').padEnd(Math.ceil(encoded.length / 4) * 4, '=');
    return JSON.parse(atob(padded));
  } catch { return {}; }
}

function clearCallbackParameters() {
  const url = new URL(location.href);
  ['code', 'state', 'error', 'error_description'].forEach(name => url.searchParams.delete(name));
  history.replaceState({}, document.title, `${url.pathname}${url.search}${url.hash}`);
}

export async function getOAuthConfig() {
  if (!configPromise) {
    configPromise = fetch('/auth/config', { headers: { Accept: 'application/json' }, cache: 'no-store' })
      .then(async response => {
        if (!response.ok) throw new Error(`Configuração de login indisponível (HTTP ${response.status}).`);
        const config = await response.json();
        if (!config.enabled || !config.domain || !config.client_id || !config.redirect_uri || !config.issuer) {
          throw new Error('Configuração pública do Cognito está incompleta.');
        }
        return config;
      });
  }
  return configPromise;
}

function validStoredAccessToken() {
  const stored = readJson(OAUTH_TOKEN_KEY);
  if (!stored?.access_token || !stored.expires_at) return null;
  if (stored.expires_at <= Math.floor(Date.now() / 1000) + CLOCK_SKEW_SECONDS) {
    sessionStorage.removeItem(OAUTH_TOKEN_KEY);
    return null;
  }
  return stored.access_token;
}

async function beginLogin(config) {
  const verifier = randomUrlSafe(64);
  const state = randomUrlSafe();
  const nonce = randomUrlSafe();
  sessionStorage.setItem(OAUTH_TRANSACTION_KEY, JSON.stringify({
    verifier, state, nonce, created_at: Date.now(),
  }));

  const authorize = new URL('/oauth2/authorize', config.domain);
  authorize.search = new URLSearchParams({
    response_type: 'code',
    client_id: config.client_id,
    redirect_uri: config.redirect_uri,
    scope: (config.scopes || ['openid']).join(' '),
    state,
    nonce,
    code_challenge: await sha256UrlSafe(verifier),
    code_challenge_method: 'S256',
    lang: 'pt-BR',
  });
  location.assign(authorize);
  return new Promise(() => {});
}

async function exchangeCallback(config, code, returnedState) {
  const transaction = readJson(OAUTH_TRANSACTION_KEY);
  sessionStorage.removeItem(OAUTH_TRANSACTION_KEY);
  if (!transaction || Date.now() - Number(transaction.created_at || 0) > 10 * 60 * 1000) {
    clearCallbackParameters();
    throw new Error('A tentativa de login expirou. Inicie o login novamente.');
  }
  if (!returnedState || returnedState !== transaction.state) {
    clearCallbackParameters();
    throw new Error('O estado retornado pelo Cognito não confere. Login cancelado.');
  }

  const response = await fetch(new URL('/oauth2/token', config.domain), {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      grant_type: 'authorization_code',
      client_id: config.client_id,
      code,
      redirect_uri: config.redirect_uri,
      code_verifier: transaction.verifier,
    }),
  });
  if (!response.ok) {
    clearCallbackParameters();
    throw new Error(`O Cognito recusou a troca do código (HTTP ${response.status}).`);
  }

  const tokens = await response.json();
  const accessClaims = decodeJwtPayload(tokens.access_token || '');
  const idClaims = decodeJwtPayload(tokens.id_token || '');
  const now = Math.floor(Date.now() / 1000);
  if (!tokens.access_token || accessClaims.token_use !== 'access' ||
      accessClaims.client_id !== config.client_id || accessClaims.iss !== config.issuer ||
      Number(accessClaims.exp || 0) <= now) {
    clearCallbackParameters();
    throw new Error('O Cognito retornou um access token inválido.');
  }
  if (idClaims.nonce !== transaction.nonce || idClaims.iss !== config.issuer ||
      idClaims.aud !== config.client_id || Number(idClaims.exp || 0) <= now) {
    clearCallbackParameters();
    throw new Error('O Cognito retornou uma identidade que não corresponde à tentativa de login.');
  }

  // O API Gateway valida criptograficamente o access token em toda chamada.
  // O browser mantém somente o access token nesta aba; refresh token e ID token
  // não são persistidos, reduzindo o impacto de uma eventual injeção de script.
  sessionStorage.setItem(OAUTH_TOKEN_KEY, JSON.stringify({
    access_token: tokens.access_token,
    expires_at: Number(accessClaims.exp),
  }));
  clearCallbackParameters();
  return tokens.access_token;
}

async function bootstrap() {
  const config = await getOAuthConfig();
  const url = new URL(location.href);
  const oauthError = url.searchParams.get('error');
  if (oauthError) {
    const description = url.searchParams.get('error_description') || oauthError;
    clearCallbackParameters();
    throw new Error(`Login cancelado ou recusado: ${description}`);
  }

  const code = url.searchParams.get('code');
  if (code) return exchangeCallback(config, code, url.searchParams.get('state'));
  return validStoredAccessToken() || beginLogin(config);
}

export async function getAccessToken() {
  const existing = validStoredAccessToken();
  if (existing) return existing;
  if (!bootstrapPromise) bootstrapPromise = bootstrap();
  try { return await bootstrapPromise; }
  finally { bootstrapPromise = null; }
}

export async function authenticatedFetch(input, options = {}) {
  const token = await getAccessToken();
  const headers = new Headers(options.headers || {});
  headers.set('Authorization', `Bearer ${token}`);
  const response = await fetch(input, { ...options, headers });
  if (response.status === 401) {
    sessionStorage.removeItem(OAUTH_TOKEN_KEY);
    await beginLogin(await getOAuthConfig());
  }
  return response;
}

export async function logout() {
  sessionStorage.removeItem(OAUTH_TOKEN_KEY);
  sessionStorage.removeItem(OAUTH_TRANSACTION_KEY);
  const config = await getOAuthConfig();
  const endpoint = new URL('/logout', config.domain);
  endpoint.search = new URLSearchParams({
    client_id: config.client_id,
    logout_uri: config.redirect_uri,
  });
  location.assign(endpoint);
}
