import assert from 'node:assert/strict';
import { createHash, createPublicKey, randomBytes, verify } from 'node:crypto';

const base = process.argv[2];
assert.ok(base, 'Set the running provider URL');
const issuer = `${base}/test`;
const oid = '00000000-0000-0000-0000-000000000001';

const health = await fetch(`${base}/health`);
assert.equal(health.status, 200);
assert.deepEqual(await health.json(), { status: 'up' });

const discovery = await fetch(`${issuer}/.well-known/openid-configuration`);
assert.equal(discovery.status, 200);
const metadata = await discovery.json();
assert.equal(metadata.issuer, issuer);
assert.equal(metadata.authorization_endpoint, `${issuer}/authorize`);
assert.equal(metadata.token_endpoint, `${issuer}/token`);
assert.equal(metadata.jwks_uri, `${issuer}/jwks`);
assert.deepEqual(metadata.code_challenge_methods_supported, ['S256']);

const jwksResponse = await fetch(metadata.jwks_uri);
assert.equal(jwksResponse.status, 200);
const { keys } = await jwksResponse.json();
assert.equal(keys.length, 1);
assert.equal(keys[0].kid, 'test');
assert.equal(keys[0].alg, 'RS256');
const key = createPublicKey({ key: keys[0], format: 'jwk' });

function claims(token, audience) {
  const parts = token.split('.');
  assert.equal(parts.length, 3);
  assert.equal(JSON.parse(Buffer.from(parts[0], 'base64url')).alg, 'RS256');
  assert.ok(verify('RSA-SHA256', Buffer.from(`${parts[0]}.${parts[1]}`), key, Buffer.from(parts[2], 'base64url')));
  const payload = JSON.parse(Buffer.from(parts[1], 'base64url'));
  assert.equal(payload.iss, issuer);
  assert.equal(payload.sub, 'test-user');
  assert.equal(payload.oid, oid);
  assert.equal(payload.aud, audience);
  assert.equal(payload.nonce, 'test-nonce');
  assert.ok(payload.exp > Math.floor(Date.now() / 1000));
  return payload;
}

function tokenRequest(parameters) {
  return fetch(metadata.token_endpoint, {
    method: 'POST',
    body: new URLSearchParams(parameters),
  });
}

const verifier = randomBytes(32).toString('base64url');
const authorize = new URL(metadata.authorization_endpoint);
authorize.search = new URLSearchParams({
  response_type: 'code',
  client_id: 'mock-client',
  redirect_uri: 'https://client.example.invalid/callback',
  code_challenge: createHash('sha256').update(verifier).digest('base64url'),
  code_challenge_method: 'S256',
  state: 'test-state',
  nonce: 'test-nonce',
  scope: 'openid profile',
});
const authorization = await fetch(authorize, { redirect: 'manual' });
assert.equal(authorization.status, 302);
const redirect = new URL(authorization.headers.get('location'));
assert.equal(redirect.origin, 'https://client.example.invalid');
assert.equal(redirect.searchParams.get('state'), 'test-state');
const code = redirect.searchParams.get('code');
assert.ok(code);

const invalidPkce = await tokenRequest({ grant_type: 'authorization_code', code, code_verifier: 'invalid' });
assert.equal(invalidPkce.status, 400);
assert.equal((await invalidPkce.json()).error, 'invalid_grant');

const tokenResponse = await tokenRequest({ grant_type: 'authorization_code', code, code_verifier: verifier });
assert.equal(tokenResponse.status, 200);
const tokens = await tokenResponse.json();
assert.equal(tokens.token_type, 'Bearer');
assert.deepEqual(claims(tokens.access_token, 'mock-api').roles, ['reader', 'writer']);
assert.equal(claims(tokens.access_token, 'mock-api').scp, 'openid profile');
claims(tokens.id_token, 'mock-client');

const refreshResponse = await tokenRequest({ grant_type: 'refresh_token', refresh_token: tokens.refresh_token });
assert.equal(refreshResponse.status, 200);
const refreshed = await refreshResponse.json();
assert.notEqual(refreshed.refresh_token, tokens.refresh_token);
claims(refreshed.access_token, 'mock-api');
claims(refreshed.id_token, 'mock-client');
const reusedRefresh = await tokenRequest({ grant_type: 'refresh_token', refresh_token: tokens.refresh_token });
assert.equal(reusedRefresh.status, 400);
assert.equal((await reusedRefresh.json()).error, 'invalid_grant');

console.log('Verified production-image health, discovery, JWKS, PKCE, signed JWT claims, and refresh-token rotation.');
