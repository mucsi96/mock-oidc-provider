import crypto from "crypto";

const { publicKey, privateKey } = crypto.generateKeyPairSync("rsa", {
  modulusLength: 2048,
});

export function getPrivateKey(): crypto.KeyObject {
  return privateKey;
}

export function getJwks(kid: string) {
  const jwk = publicKey.export({ format: "jwk" });
  return {
    keys: [
      {
        ...jwk,
        kid,
        use: "sig",
        alg: "RS256",
      },
    ],
  };
}
