# mock-oidc-provider

A lightweight mock OpenID Connect provider for testing. Implements the OIDC Authorization Code Flow with PKCE support, auto-approves all authorization requests, and issues signed JWTs — no real identity provider needed.

## Quick start

```bash
podman run -p 8090:8090 docker.io/mucsi96/mock-oidc-provider:1
```

The provider starts immediately with sensible defaults. Verify it's running:

```bash
curl http://localhost:8090/default/.well-known/openid-configuration
```

## Environment variables

| Variable | Default | Description |
|---|---|---|
| `PORT` | `8090` | HTTP server listening port |
| `ISSUER_ID` | `default` | Issuer identifier, used as the URL path prefix |
| `SUB` | `test-user` | Subject claim (user ID) in tokens |
| `NAME` | `Test User` | User's full name claim |
| `PREFERRED_USERNAME` | `test-user@example.com` | Preferred username claim in the ID token |
| `ROLES` | `GreetingReader` | Comma-separated list of roles included in the access token |
| `SCP` | `readGreetings createGreeting` | Space-separated OAuth scopes included in the access token |

## Endpoints

All endpoints are prefixed with `/{ISSUER_ID}`:

| Endpoint | Method | Description |
|---|---|---|
| `/{ISSUER_ID}/.well-known/openid-configuration` | GET | OIDC discovery metadata |
| `/{ISSUER_ID}/jwks` | GET | JSON Web Key Set (RSA-2048 public key) |
| `/{ISSUER_ID}/authorize` | GET | Authorization endpoint (auto-approves, redirects with code) |
| `/{ISSUER_ID}/token` | POST | Token endpoint (authorization_code and refresh_token grants) |

## Token details

- **Signing algorithm:** RS256 (asymmetric, 2048-bit RSA)
- **Token lifetime:** 3600 seconds (1 hour)
- **Key generation:** A fresh RSA key pair is generated on each startup
- **Client authentication:** None required (`token_endpoint_auth_methods_supported: ["none"]`)
- **PKCE:** Supported via S256 challenge method

The token endpoint returns `access_token`, `id_token`, and `refresh_token` for both `authorization_code` and `refresh_token` grant types.

## Example: Podman pod with your application

Run the mock provider alongside your application in a shared pod so they can communicate via `localhost`:

```bash
# Create a pod exposing your app's port
podman pod create --name my-app-pod -p 8080:8080

# Start the mock OIDC provider inside the pod
podman run -d --pod my-app-pod \
  --name mock-oidc \
  -e ISSUER_ID=myapp \
  -e SUB=john.doe \
  -e NAME="John Doe" \
  -e PREFERRED_USERNAME=john@example.com \
  -e ROLES=admin,editor \
  -e SCP="read write" \
  docker.io/mucsi96/mock-oidc-provider:1

# Start your application inside the same pod
# Your app can reach the provider at http://localhost:8090/myapp
podman run -d --pod my-app-pod \
  --name my-app \
  -e OIDC_ISSUER=http://localhost:8090/myapp \
  my-app-image:latest

# Discovery endpoint is available at:
# http://localhost:8090/myapp/.well-known/openid-configuration
```

Within the pod, all containers share the same network namespace, so your application can discover and validate tokens using `http://localhost:8090/myapp` as the issuer.

### Cleanup

```bash
podman pod stop my-app-pod
podman pod rm my-app-pod
```

## Running locally without containers

```bash
npm ci
ISSUER_ID=myapp PORT=8090 npm start
```

## License

MIT
