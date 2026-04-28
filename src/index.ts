import express from "express";
import crypto from "crypto";
import { getJwks } from "./keys";
import { createAccessToken, createIdToken } from "./token";

function requireEnv(name: string): string {
  const value = process.env[name];
  if (!value) {
    console.error(`Missing required environment variable: ${name}`);
    process.exit(1);
  }
  return value;
}

const issuerId = requireEnv("ISSUER_ID");
const port = parseInt(requireEnv("PORT"), 10);
const sub = requireEnv("SUB");
const name = requireEnv("NAME");
const roles = requireEnv("ROLES").split(",");
const scp = requireEnv("SCP");
const preferredUsername = requireEnv("PREFERRED_USERNAME");
const aud = requireEnv("AUD");
const oid = requireEnv("OID");

const app = express();
app.use((req, res, next) => {
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
  res.setHeader(
    "Access-Control-Allow-Headers",
    req.headers["access-control-request-headers"] || "*"
  );
  if (req.method === "OPTIONS") {
    res.status(204).end();
    return;
  }
  next();
});
app.use(express.urlencoded({ extended: true }));
app.use(express.json());

const authCodes = new Map<
  string,
  {
    codeChallenge: string;
    codeChallengeMethod: string;
    redirectUri: string;
    clientId: string;
    nonce?: string;
    scope?: string;
  }
>();

const refreshTokens = new Map<string, { clientId: string; nonce?: string }>();

// Health endpoint
app.get("/health", (_req, res) => {
  res.json({ status: "up" });
});

// Discovery endpoint
app.get(`/${issuerId}/.well-known/openid-configuration`, (req, res) => {
  const baseUrl = `${req.protocol}://${req.get("host")}/${issuerId}`;
  res.json({
    issuer: baseUrl,
    authorization_endpoint: `${baseUrl}/authorize`,
    token_endpoint: `${baseUrl}/token`,
    jwks_uri: `${baseUrl}/jwks`,
    response_types_supported: ["code"],
    subject_types_supported: ["public"],
    id_token_signing_alg_values_supported: ["RS256"],
    token_endpoint_auth_methods_supported: ["none"],
    grant_types_supported: ["authorization_code", "refresh_token"],
    code_challenge_methods_supported: ["S256"],
    scopes_supported: ["openid", "profile", "email"],
  });
});

// JWKS endpoint
app.get(`/${issuerId}/jwks`, (_req, res) => {
  res.json(getJwks(issuerId));
});

// Authorization endpoint - auto-approves for testing
app.get(`/${issuerId}/authorize`, (req, res) => {
  const {
    response_type,
    client_id,
    redirect_uri,
    code_challenge,
    code_challenge_method,
    nonce,
    state,
    scope,
  } = req.query as Record<string, string>;

  if (response_type !== "code") {
    res.status(400).json({ error: "unsupported_response_type" });
    return;
  }

  const code = crypto.randomBytes(32).toString("hex");
  authCodes.set(code, {
    codeChallenge: code_challenge,
    codeChallengeMethod: code_challenge_method || "S256",
    redirectUri: redirect_uri,
    clientId: client_id,
    nonce,
    scope,
  });

  const redirectUrl = new URL(redirect_uri);
  redirectUrl.searchParams.set("code", code);
  if (state) {
    redirectUrl.searchParams.set("state", state);
  }

  res.redirect(redirectUrl.toString());
});

// Token endpoint
app.post(`/${issuerId}/token`, (req, res) => {
  const { grant_type, code, code_verifier, client_id } = req.body;
  const issuer = `${req.protocol}://${req.get("host")}/${issuerId}`;

  if (grant_type === "refresh_token") {
    const { refresh_token } = req.body;
    const stored = refreshTokens.get(refresh_token);
    if (!stored) {
      res.status(400).json({ error: "invalid_grant" });
      return;
    }

    refreshTokens.delete(refresh_token);

    const access_token = createAccessToken({
      kid: issuerId,
      issuer,
      sub,
      name,
      roles,
      scp,
      aud,
      oid,
      nonce: stored.nonce,
    });

    const id_token = createIdToken({
      kid: issuerId,
      issuer,
      sub,
      name,
      preferredUsername,
      oid,
      nonce: stored.nonce,
      aud: stored.clientId,
    });

    const newRefreshToken = crypto.randomBytes(32).toString("hex");
    refreshTokens.set(newRefreshToken, {
      clientId: stored.clientId,
      nonce: stored.nonce,
    });

    res.json({
      access_token,
      id_token,
      refresh_token: newRefreshToken,
      token_type: "Bearer",
      expires_in: 3600,
    });
    return;
  }

  if (grant_type !== "authorization_code") {
    res.status(400).json({ error: "unsupported_grant_type" });
    return;
  }

  const stored = authCodes.get(code);
  if (!stored) {
    res.status(400).json({ error: "invalid_grant" });
    return;
  }

  // Validate PKCE
  if (stored.codeChallenge) {
    const expectedChallenge = crypto
      .createHash("sha256")
      .update(code_verifier || "")
      .digest("base64url");

    if (expectedChallenge !== stored.codeChallenge) {
      res.status(400).json({
        error: "invalid_grant",
        error_description: "PKCE validation failed",
      });
      return;
    }
  }

  authCodes.delete(code);

  const access_token = createAccessToken({
    kid: issuerId,
    issuer,
    sub,
    name,
    roles,
    scp,
    aud,
    oid,
    nonce: stored.nonce,
  });

  const id_token = createIdToken({
    kid: issuerId,
    issuer,
    sub,
    name,
    preferredUsername,
    oid,
    nonce: stored.nonce,
    aud: stored.clientId || client_id,
  });

  const refresh_token = crypto.randomBytes(32).toString("hex");
  refreshTokens.set(refresh_token, {
    clientId: stored.clientId || client_id,
    nonce: stored.nonce,
  });

  res.json({
    access_token,
    id_token,
    refresh_token,
    token_type: "Bearer",
    expires_in: 3600,
  });
});

app.listen(port, () => {
  console.log(`Mock OIDC Provider listening on port ${port}`);
  console.log(`Issuer: http://localhost:${port}/${issuerId}`);
  console.log(
    `Discovery: http://localhost:${port}/${issuerId}/.well-known/openid-configuration`
  );
});
