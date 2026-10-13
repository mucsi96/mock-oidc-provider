import assert from 'node:assert/strict';
import { createHash, createPublicKey, randomBytes, verify } from 'node:crypto';

const base = process.argv[2];
assert.ok(base, 'Set the running provider URL');
const issuer = `${base}/test`;
const oid = '00000000-0000-0000-0000-000000000001';

const health = await fetch(`${base}/health`);
assert.equal(health.status, 200);
assert.equal(health.headers.get('access-control-allow-origin'), '*');
assert.deepEqual(await health.json(), { status: 'up' });

const preflight = await fetch(`${issuer}/token`, {
  method: 'OPTIONS',
  headers: {
    origin: 'https://client.example.invalid',
    'access-control-request-method': 'POST',
    'access-control-request-headers': 'authorization,x-test',
  },
});
assert.equal(preflight.status, 204);
assert.equal(preflight.headers.get('access-control-allow-origin'), '*');
assert.equal(preflight.headers.get('access-control-allow-methods'), 'GET, POST, OPTIONS');
assert.equal(preflight.headers.get('access-control-allow-headers'), 'authorization,x-test');

const discovery = await fetch(`${issuer}/.well-known/openid-configuration`);
assert.equal(discovery.status, 200);
const metadata = await discovery.json();
assert.deepEqual(metadata.grant_types_supported, ['authorization_code', 'refresh_token']);
assert.deepEqual(metadata.token_endpoint_auth_methods_supported, ['none']);
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

const unsupported = await fetch(`${metadata.authorization_endpoint}?response_type=token`);
assert.equal(unsupported.status, 400);
assert.equal((await unsupported.json()).error, 'unsupported_response_type');
const unsupportedGrant = await tokenRequest({ grant_type: 'password' });
assert.equal(unsupportedGrant.status, 400);
assert.equal((await unsupportedGrant.json()).error, 'unsupported_grant_type');
const unknownCode = await tokenRequest({ grant_type: 'authorization_code', code: 'unknown' });
assert.equal(unknownCode.status, 400);
assert.equal((await unknownCode.json()).error, 'invalid_grant');

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
const reusedCode = await tokenRequest({ grant_type: 'authorization_code', code, code_verifier: verifier });
assert.equal(reusedCode.status, 400);
assert.equal((await reusedCode.json()).error, 'invalid_grant');

const refreshResponse = await tokenRequest({ grant_type: 'refresh_token', refresh_token: tokens.refresh_token });
assert.equal(refreshResponse.status, 200);
const refreshed = await refreshResponse.json();
assert.notEqual(refreshed.refresh_token, tokens.refresh_token);
claims(refreshed.access_token, 'mock-api');
claims(refreshed.id_token, 'mock-client');
const reusedRefresh = await tokenRequest({ grant_type: 'refresh_token', refresh_token: tokens.refresh_token });
assert.equal(reusedRefresh.status, 400);
assert.equal((await reusedRefresh.json()).error, 'invalid_grant');

const jsonRefresh = await fetch(metadata.token_endpoint, {
  method: 'POST',
  headers: { 'content-type': 'application/json; charset=utf-8' },
  body: JSON.stringify({ grant_type: 'refresh_token', refresh_token: refreshed.refresh_token }),
});
assert.equal(jsonRefresh.status, 200);
const jsonTokens = await jsonRefresh.json();
claims(jsonTokens.access_token, 'mock-api');
claims(jsonTokens.id_token, 'mock-client');

const noPkce = new URL(metadata.authorization_endpoint);
noPkce.search = new URLSearchParams({
  response_type: 'code',
  client_id: 'mock-client',
  redirect_uri: 'https://client.example.invalid/callback?code=old&state=old&keep=value',
  state: 'test-state',
  nonce: 'test-nonce',
});
const noPkceResponse = await fetch(noPkce, { redirect: 'manual' });
assert.equal(noPkceResponse.status, 302);
const noPkceRedirect = new URL(noPkceResponse.headers.get('location'));
assert.equal(noPkceRedirect.searchParams.getAll('code').length, 1);
assert.equal(noPkceRedirect.searchParams.get('state'), 'test-state');
assert.equal(noPkceRedirect.searchParams.get('keep'), 'value');
const noPkceTokensResponse = await fetch(metadata.token_endpoint, {
  method: 'POST',
  headers: { 'content-type': 'application/json' },
  body: JSON.stringify({ grant_type: 'authorization_code', code: noPkceRedirect.searchParams.get('code') }),
});
assert.equal(noPkceTokensResponse.status, 200);
const noPkceTokens = await noPkceTokensResponse.json();
claims(noPkceTokens.access_token, 'mock-api');
claims(noPkceTokens.id_token, 'mock-client');

console.log('Verified production-image health, CORS, discovery, JWKS, PKCE, signed JWT claims, form/JSON grants, replay rejection, and refresh-token rotation.');
