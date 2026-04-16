# mock-oidc-provider

A lightweight mock OpenID Connect provider for testing. Implements the OIDC Authorization Code Flow with PKCE support, auto-approves all authorization requests, and issues signed JWTs — no real identity provider needed.

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
  docker.io/mucsi96/mock-oidc-provider:latest
```

Verify it's running:

```bash
curl http://localhost:8090/health
```

## Environment variables

All environment variables are **required**. The provider will refuse to start if any are missing.

| Variable | Description |
|---|---|
| `PORT` | HTTP server listening port |
| `ISSUER_ID` | Issuer identifier, used as the URL path prefix |
| `SUB` | Subject claim (user ID) in tokens |
| `NAME` | User's full name claim |
| `PREFERRED_USERNAME` | Preferred username claim in the ID token |
| `ROLES` | Comma-separated list of roles included in the access token |
| `SCP` | Space-separated OAuth scopes included in the access token |

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

## Example: Podman pod YAML

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: my-app-pod
spec:
  containers:
    - name: mock-oidc-provider
      image: docker.io/mucsi96/mock-oidc-provider:latest
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
