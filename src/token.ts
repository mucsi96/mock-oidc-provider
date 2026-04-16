import crypto from "crypto";
import { getPrivateKey } from "./keys";

function base64url(data: Buffer): string {
  return data.toString("base64url");
}

function createJwt(
  header: object,
  payload: object,
  privateKey: crypto.KeyObject
): string {
  const headerB64 = base64url(Buffer.from(JSON.stringify(header)));
  const payloadB64 = base64url(Buffer.from(JSON.stringify(payload)));
  const data = `${headerB64}.${payloadB64}`;
  const signature = crypto.sign("SHA256", Buffer.from(data), privateKey);
  return `${data}.${base64url(signature)}`;
}

export function createAccessToken(options: {
  kid: string;
  issuer: string;
  sub: string;
  name: string;
  roles: string[];
  scp: string;
  nonce?: string;
}): string {
  const now = Math.floor(Date.now() / 1000);
  const header = {
    kid: options.kid,
    typ: "JWT",
    alg: "RS256",
  };
  const payload = {
    sub: options.sub,
    scp: options.scp,
    nbf: now,
    roles: options.roles,
    iss: options.issuer,
    name: options.name,
    exp: now + 3600,
    iat: now,
    nonce: options.nonce || crypto.randomBytes(20).toString("hex"),
    jti: crypto.randomUUID(),
  };
  return createJwt(header, payload, getPrivateKey());
}

export function createIdToken(options: {
  kid: string;
  issuer: string;
  sub: string;
  name: string;
  nonce?: string;
  aud: string;
}): string {
  const now = Math.floor(Date.now() / 1000);
  const header = {
    kid: options.kid,
    typ: "JWT",
    alg: "RS256",
  };
  const payload = {
    sub: options.sub,
    iss: options.issuer,
    aud: options.aud,
    name: options.name,
    exp: now + 3600,
    iat: now,
    nonce: options.nonce,
    jti: crypto.randomUUID(),
  };
  return createJwt(header, payload, getPrivateKey());
}
