import assert from 'node:assert/strict';
import { createHash, createPublicKey, randomBytes, verify } from 'node:crypto';

const base = process.argv[2];
const issuer = 'https://issuer.example.invalid/test';
const metadata = await (await fetch(`${base}/test/.well-known/openid-configuration`)).json();
assert.equal(metadata.issuer, issuer);
assert.deepEqual(metadata.token_endpoint_auth_methods_supported, ['client_secret_post']);
const { keys } = await (await fetch(`${base}/test/jwks`)).json();
const key = createPublicKey({ key: keys[0], format: 'jwk' });
const verifier = randomBytes(32).toString('base64url');
const redirect = 'https://hello.example.invalid/callback';
const query = new URLSearchParams({ response_type: 'code', client_id: 'hello-web', redirect_uri: redirect,
  nonce: 'fixture-nonce', state: 'fixture-state', code_challenge_method: 'S256',
  code_challenge: createHash('sha256').update(verifier).digest('base64url'), scope: 'openid offline_access api://hello-api/api-access' });
const response = await fetch(`${base}/test/authorize?${query}`, { redirect: 'manual' });
assert.equal(response.status, 302);
const code = new URL(response.headers.get('location')).searchParams.get('code');
const tokenRequest = parameters => fetch(`${base}/test/token`, { method: 'POST', body: new URLSearchParams(parameters) });
const grant = { grant_type: 'authorization_code', client_id: 'hello-web', client_secret: 'hello-test-secret',
  redirect_uri: redirect, code, code_verifier: verifier };
for (const wrong of [{ client_secret: 'wrong' }, { redirect_uri: 'https://cooking.example.invalid/callback' },
  { client_id: 'cooking-web', client_secret: 'cooking-test-secret' }, { code_verifier: 'wrong' }]) {
  assert.equal((await tokenRequest({ ...grant, ...wrong })).status, 400);
}
const successful = await tokenRequest(grant);
assert.equal(successful.status, 200);
const tokens = await successful.json();
function claims(token, audience) {
  const [header, payload, signature] = token.split('.');
  assert.equal(JSON.parse(Buffer.from(header, 'base64url')).alg, 'RS256');
  assert.ok(verify('RSA-SHA256', Buffer.from(`${header}.${payload}`), key, Buffer.from(signature, 'base64url')));
  const data = JSON.parse(Buffer.from(payload, 'base64url'));
  assert.equal(data.iss, issuer);
  assert.equal(data.aud, audience);
  assert.equal(data.sub, 'owner');
  return data;
}
assert.deepEqual(claims(tokens.access_token, 'hello-api').roles, ['read']);
assert.equal(claims(tokens.id_token, 'hello-web').nonce, 'fixture-nonce');
assert.equal(tokens.expires_in, 5);
assert.equal((await tokenRequest({ grant_type: 'refresh_token', client_id: 'cooking-web', client_secret: 'cooking-test-secret', refresh_token: tokens.refresh_token })).status, 400);
const refreshed = await tokenRequest({ grant_type: 'refresh_token', client_id: 'hello-web', client_secret: 'hello-test-secret', refresh_token: tokens.refresh_token });
assert.equal(refreshed.status, 200);
claims((await refreshed.json()).access_token, 'hello-api');
const stats = await (await fetch(`${base}/test/stats`)).json();
assert.deepEqual(stats, { authorizations: 1, redemptions: 1, refreshes: 1 });
console.log('Verified confidential-client secrets, redirect/PKCE binding, distinct signed audiences, short lifetimes and client-bound refresh.');
