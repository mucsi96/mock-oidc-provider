# mock-oidc-provider

A lightweight Rust mock OpenID Connect provider for testing. Implements the OIDC Authorization Code Flow with PKCE support, auto-approves all authorization requests, and issues signed JWTs — no real identity provider needed.

## Quick start

```bash
podman run -p 8090:8090 \
  -e PORT=8090 \
  -e ISSUER_ID=default \
  -e SUB=test-user \
  -e NAME="Test User" \
  -e PREFERRED_USERNAME=test-user@example.com \
  -e ROLES=reader \
  -e SCP="read write" \
  -e AUD=my-app \
  -e OID=00000000-0000-0000-0000-000000000000 \
  ghcr.io/mucsi96/mock-oidc-provider:latest
```

Verify it's running:

```bash
curl http://localhost:8090/health
```

## Environment variables

The variables below are **required**. The provider will refuse to start if any are missing.

| Variable | Description |
|---|---|
| `PORT` | HTTP server listening port |
| `ISSUER_ID` | Issuer identifier, used as the URL path prefix |
| `SUB` | Subject claim (user ID) in tokens |
| `NAME` | User's full name claim |
| `PREFERRED_USERNAME` | Preferred username claim in the ID token |
| `ROLES` | Comma-separated list of roles included in the access token |
| `SCP` | Space-separated OAuth scopes included in the access token |
| `AUD` | Audience claim included in the access token |
| `OID` | Object identifier (GUID) claim included in the access token and ID token, immutable identifier for the user/service principal |

## Endpoints

All endpoints are prefixed with `/{ISSUER_ID}`:

| Endpoint | Method | Description |
|---|---|---|
| `/{ISSUER_ID}/.well-known/openid-configuration` | GET | OIDC discovery metadata |
| `/{ISSUER_ID}/jwks` | GET | JSON Web Key Set (RSA-2048 public key) |
| `/{ISSUER_ID}/authorize` | GET | Authorization endpoint (auto-approves, redirects with code) |
| `/{ISSUER_ID}/token` | POST | Token endpoint (authorization_code and refresh_token grants) |
| `/health` | GET | Health check endpoint, returns `{"status":"up"}` |

## Token details

- **Signing algorithm:** RS256 (asymmetric, 2048-bit RSA)
- **Token lifetime:** 3600 seconds (1 hour)
- **Key generation:** A fresh RSA key pair is generated on each startup
- **Client authentication:** None required (`token_endpoint_auth_methods_supported: ["none"]`)
- **PKCE:** Supported via S256 challenge method

The token endpoint returns `access_token`, `id_token`, and `refresh_token` for both `authorization_code` and `refresh_token` grant types.

## Confidential-client / BFF fixtures

Set the optional `FIXTURE_CONFIG_FILE` to enable registered clients and a public
issuer URL behind a TLS reverse proxy such as Traefik. The environment-based mode
above is used by the existing SPA tests. This is a test provider with disposable
keys and auto-approval, not a production identity service.

```json
{
  "issuer_url": "https://issuer.example.test/default",
  "access_token_ttl_secs": 5,
  "clients": {
    "hello-web": {
      "secret": "hello-test-secret",
      "redirect_uri": "https://hello.example.test/oauth2/callback",
      "api_audience": "hello-api",
      "api_scope": "api://hello-api/api-access",
      "allowed_users": ["owner"],
      "roles": {"owner": ["read"]}
    }
  }
}
```

This mode requires `client_secret_post`, an exact registered redirect, S256 PKCE,
state/nonce and the registered API scope. Authorization codes and refresh grants
are bound to their client. Each API gets its configured audience and user roles;
`allowed_users` simulates Entra Web-app assignment. `api_audience` and `api_scope`
can be `null` for a login-gated app that does not consume an API token.

Refresh responses rotate the returned token, while older refresh tokens remain
usable in this opt-in mode, matching Entra's documented behavior. The default SPA
mode still rejects reused refresh tokens.

The following control endpoints exist **only** when a fixture config is loaded:

- `POST /test/reset`: `{ "user": "owner", "mode": "normal" }`; resets grants/counters.
- `POST /test/mode`: `{ "mode": "refresh_outage" }`; changes fault injection.
- `GET /test/stats`: successful authorization/redemption/refresh counts, no credentials.

Modes cover invalid nonce/signature/audience/issuer/subject, expired or future-dated
ID tokens, wrong authorized party, HMAC downgrade, missing API roles, and refresh
revocation/outage/delay. They are exercised by the TypeScript/Playwright Podman
suite in [oidc-bff](https://github.com/mucsi96/oidc-bff).

`scripts/check-image.sh` verifies both the existing SPA behavior and the registered
confidential-client grants against the production container image.

## Example: Podman pod YAML

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: my-app-pod
spec:
  containers:
    - name: mock-oidc-provider
      image: ghcr.io/mucsi96/mock-oidc-provider:latest
      ports:
        - containerPort: 8090
          hostPort: 8090
      env:
        - name: PORT
          value: "8090"
        - name: ISSUER_ID
          value: "myapp"
        - name: SUB
          value: "john.doe"
        - name: NAME
          value: "John Doe"
        - name: PREFERRED_USERNAME
          value: "john@example.com"
        - name: ROLES
          value: "admin,editor"
        - name: SCP
          value: "read write"
        - name: AUD
          value: "my-app"
        - name: OID
          value: "00000000-0000-0000-0000-000000000000"
      livenessProbe:
        httpGet:
          path: /health
          port: 8090
        initialDelaySeconds: 2
        periodSeconds: 2
        failureThreshold: 5
    - name: my-app
      image: my-app-image:latest
      ports:
        - containerPort: 8080
          hostPort: 8080
      env:
        - name: OIDC_ISSUER
          value: "http://localhost:8090/myapp"
```

## License

MIT
