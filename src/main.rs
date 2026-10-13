use std::collections::HashMap;
use std::env;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, bail};
use axum::body::to_bytes;
use axum::extract::{Query, Request, State};
use axum::http::{HeaderMap, HeaderValue, Method, StatusCode, header};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use rand::{RngCore, rngs::OsRng};
use rsa::pkcs1v15::SigningKey;
use rsa::signature::{SignatureEncoding, Signer};
use rsa::traits::PublicKeyParts;
use rsa::{RsaPrivateKey, RsaPublicKey};
use serde::Deserialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use tokio::net::TcpListener;
use url::Url;
use uuid::Uuid;

struct Config {
    port: u16,
    issuer_id: String,
    sub: String,
    name: String,
    preferred_username: String,
    roles: Vec<String>,
    scp: String,
    aud: String,
    oid: String,
}

impl Config {
    fn from_env() -> Result<Self> {
        fn required(name: &str) -> Result<String> {
            match env::var(name) {
                Ok(value) if !value.is_empty() => Ok(value),
                _ => bail!("Missing required environment variable: {name}"),
            }
        }

        Ok(Self {
            port: required("PORT")?
                .parse()
                .context("PORT must be a valid TCP port")?,
            issuer_id: required("ISSUER_ID")?,
            sub: required("SUB")?,
            name: required("NAME")?,
            preferred_username: required("PREFERRED_USERNAME")?,
            roles: required("ROLES")?.split(',').map(str::to_owned).collect(),
            scp: required("SCP")?,
            aud: required("AUD")?,
            oid: required("OID")?,
        })
    }
}

#[derive(Clone)]
struct Session {
    client_id: Option<String>,
    nonce: Option<String>,
}

struct AuthorizationCode {
    challenge: Option<String>,
    session: Session,
}

struct Provider {
    config: Config,
    signing_key: SigningKey<Sha256>,
    jwks: Value,
    codes: Mutex<HashMap<String, AuthorizationCode>>,
    refresh_tokens: Mutex<HashMap<String, Session>>,
}

impl Provider {
    fn new(config: Config) -> Result<Self> {
        let private = RsaPrivateKey::new(&mut OsRng, 2048)?;
        let public = RsaPublicKey::from(&private);
        let jwks = json!({ "keys": [{
            "kty": "RSA",
            "n": URL_SAFE_NO_PAD.encode(public.n().to_bytes_be()),
            "e": URL_SAFE_NO_PAD.encode(public.e().to_bytes_be()),
            "kid": config.issuer_id,
            "use": "sig",
            "alg": "RS256",
        }] });
        Ok(Self {
            config,
            signing_key: SigningKey::new(private),
            jwks,
            codes: Mutex::new(HashMap::new()),
            refresh_tokens: Mutex::new(HashMap::new()),
        })
    }

    fn sign(&self, payload: Value) -> Result<String, OAuthError> {
        let header = json!({ "kid": self.config.issuer_id, "typ": "JWT", "alg": "RS256" });
        let message = format!(
            "{}.{}",
            URL_SAFE_NO_PAD
                .encode(serde_json::to_vec(&header).map_err(|_| OAuthError::internal())?),
            URL_SAFE_NO_PAD
                .encode(serde_json::to_vec(&payload).map_err(|_| OAuthError::internal())?),
        );
        let signature = self.signing_key.sign(message.as_bytes());
        Ok(format!(
            "{message}.{}",
            URL_SAFE_NO_PAD.encode(signature.to_bytes())
        ))
    }

    fn tokens(&self, session: Session, issuer: &str) -> Result<Value, OAuthError> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| OAuthError::internal())?
            .as_secs();
        let nonce = session
            .nonce
            .as_ref()
            .filter(|value| !value.is_empty())
            .cloned()
            .unwrap_or_else(|| random_token(20));
        let access_token = self.sign(json!({
            "sub": self.config.sub,
            "oid": self.config.oid,
            "scp": self.config.scp,
            "aud": self.config.aud,
            "nbf": now,
            "roles": self.config.roles,
            "iss": issuer,
            "name": self.config.name,
            "exp": now + 3600,
            "iat": now,
            "nonce": nonce,
            "jti": Uuid::new_v4().to_string(),
        }))?;
        let mut id_claims = json!({
            "sub": self.config.sub,
            "oid": self.config.oid,
            "iss": issuer,
            "name": self.config.name,
            "preferred_username": self.config.preferred_username,
            "exp": now + 3600,
            "iat": now,
            "jti": Uuid::new_v4().to_string(),
        });
        if let Some(client_id) = &session.client_id {
            id_claims["aud"] = json!(client_id);
        }
        if let Some(nonce) = &session.nonce {
            id_claims["nonce"] = json!(nonce);
        }
        let id_token = self.sign(id_claims)?;
        let refresh_token = random_token(32);
        self.refresh_tokens
            .lock()
            .map_err(|_| OAuthError::internal())?
            .insert(refresh_token.clone(), session);
        Ok(json!({
            "access_token": access_token,
            "id_token": id_token,
            "refresh_token": refresh_token,
            "token_type": "Bearer",
            "expires_in": 3600,
        }))
    }
}

struct OAuthError {
    status: StatusCode,
    error: &'static str,
    description: Option<&'static str>,
}

impl OAuthError {
    fn bad_request(error: &'static str) -> Self {
        Self {
            status: StatusCode::BAD_REQUEST,
            error,
            description: None,
        }
    }

    fn internal() -> Self {
        Self {
            status: StatusCode::INTERNAL_SERVER_ERROR,
            error: "server_error",
            description: None,
        }
    }
}

impl IntoResponse for OAuthError {
    fn into_response(self) -> Response {
        let mut body = json!({ "error": self.error });
        if let Some(description) = self.description {
            body["error_description"] = json!(description);
        }
        (self.status, Json(body)).into_response()
    }
}

fn random_token(length: usize) -> String {
    let mut bytes = vec![0; length];
    OsRng.fill_bytes(&mut bytes);
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn issuer(headers: &HeaderMap, id: &str) -> Result<String, OAuthError> {
    let host = headers
        .get(header::HOST)
        .and_then(|value| value.to_str().ok())
        .ok_or_else(|| OAuthError::bad_request("invalid_request"))?;
    Ok(format!("http://{host}/{id}"))
}

async fn cors(request: Request, next: Next) -> Response {
    let allowed_headers = request
        .headers()
        .get(header::ACCESS_CONTROL_REQUEST_HEADERS)
        .cloned()
        .unwrap_or_else(|| HeaderValue::from_static("*"));
    let mut response = if request.method() == Method::OPTIONS {
        StatusCode::NO_CONTENT.into_response()
    } else {
        next.run(request).await
    };
    let headers = response.headers_mut();
    headers.insert(
        header::ACCESS_CONTROL_ALLOW_ORIGIN,
        HeaderValue::from_static("*"),
    );
    headers.insert(
        header::ACCESS_CONTROL_ALLOW_METHODS,
        HeaderValue::from_static("GET, POST, OPTIONS"),
    );
    headers.insert(header::ACCESS_CONTROL_ALLOW_HEADERS, allowed_headers);
    response
}

async fn discovery(
    State(provider): State<Arc<Provider>>,
    headers: HeaderMap,
) -> Result<Json<Value>, OAuthError> {
    let issuer = issuer(&headers, &provider.config.issuer_id)?;
    Ok(Json(json!({
        "issuer": issuer,
        "authorization_endpoint": format!("{issuer}/authorize"),
        "token_endpoint": format!("{issuer}/token"),
        "jwks_uri": format!("{issuer}/jwks"),
        "response_types_supported": ["code"],
        "subject_types_supported": ["public"],
        "id_token_signing_alg_values_supported": ["RS256"],
        "token_endpoint_auth_methods_supported": ["none"],
        "grant_types_supported": ["authorization_code", "refresh_token"],
        "code_challenge_methods_supported": ["S256"],
        "scopes_supported": ["openid", "profile", "email"],
    })))
}

#[derive(Deserialize)]
struct Authorize {
    response_type: Option<String>,
    client_id: Option<String>,
    redirect_uri: Option<String>,
    code_challenge: Option<String>,
    nonce: Option<String>,
    state: Option<String>,
}

async fn authorize(
    State(provider): State<Arc<Provider>>,
    Query(query): Query<Authorize>,
) -> Result<Response, OAuthError> {
    if query.response_type.as_deref() != Some("code") {
        return Err(OAuthError::bad_request("unsupported_response_type"));
    }
    let mut redirect = query
        .redirect_uri
        .as_deref()
        .and_then(|value| Url::parse(value).ok())
        .ok_or_else(|| OAuthError::bad_request("invalid_request"))?;
    let code = random_token(32);
    let replace_state = query.state.as_ref().is_some_and(|value| !value.is_empty());
    let existing: Vec<_> = redirect
        .query_pairs()
        .filter(|(key, _)| key != "code" && (!replace_state || key != "state"))
        .map(|(key, value)| (key.into_owned(), value.into_owned()))
        .collect();
    redirect
        .query_pairs_mut()
        .clear()
        .extend_pairs(existing)
        .append_pair("code", &code);
    if replace_state {
        redirect
            .query_pairs_mut()
            .append_pair("state", query.state.as_deref().unwrap_or_default());
    }
    provider
        .codes
        .lock()
        .map_err(|_| OAuthError::internal())?
        .insert(
            code,
            AuthorizationCode {
                challenge: query.code_challenge.filter(|value| !value.is_empty()),
                session: Session {
                    client_id: query.client_id.filter(|value| !value.is_empty()),
                    nonce: query.nonce,
                },
            },
        );
    Ok((
        StatusCode::FOUND,
        [(header::LOCATION, redirect.to_string())],
    )
        .into_response())
}

#[derive(Deserialize, Default)]
struct TokenRequest {
    grant_type: Option<String>,
    code: Option<String>,
    code_verifier: Option<String>,
    client_id: Option<String>,
    refresh_token: Option<String>,
}

async fn token(
    State(provider): State<Arc<Provider>>,
    request: Request,
) -> Result<Json<Value>, OAuthError> {
    let issuer = issuer(request.headers(), &provider.config.issuer_id)?;
    let json_body = request
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| value.split(';').next() == Some("application/json"));
    let bytes = to_bytes(request.into_body(), 100 * 1024)
        .await
        .map_err(|_| OAuthError::bad_request("invalid_request"))?;
    let parameters: TokenRequest = if json_body {
        serde_json::from_slice(&bytes).map_err(|_| OAuthError::bad_request("invalid_request"))?
    } else {
        serde_urlencoded::from_bytes(&bytes)
            .map_err(|_| OAuthError::bad_request("invalid_request"))?
    };
    let session = match parameters.grant_type.as_deref() {
        Some("refresh_token") => provider
            .refresh_tokens
            .lock()
            .map_err(|_| OAuthError::internal())?
            .remove(parameters.refresh_token.as_deref().unwrap_or_default())
            .ok_or_else(|| OAuthError::bad_request("invalid_grant"))?,
        Some("authorization_code") => {
            let mut codes = provider.codes.lock().map_err(|_| OAuthError::internal())?;
            let code = parameters.code.as_deref().unwrap_or_default();
            let stored = codes
                .get(code)
                .ok_or_else(|| OAuthError::bad_request("invalid_grant"))?;
            if let Some(challenge) = &stored.challenge {
                let actual = URL_SAFE_NO_PAD.encode(Sha256::digest(
                    parameters
                        .code_verifier
                        .as_deref()
                        .unwrap_or_default()
                        .as_bytes(),
                ));
                if actual != *challenge {
                    return Err(OAuthError {
                        status: StatusCode::BAD_REQUEST,
                        error: "invalid_grant",
                        description: Some("PKCE validation failed"),
                    });
                }
            }
            let mut session = codes.remove(code).ok_or_else(OAuthError::internal)?.session;
            if session.client_id.is_none() {
                session.client_id = parameters.client_id.filter(|value| !value.is_empty());
            }
            session
        }
        _ => return Err(OAuthError::bad_request("unsupported_grant_type")),
    };
    Ok(Json(provider.tokens(session, &issuer)?))
}

async fn shutdown() {
    #[cfg(unix)]
    {
        let mut terminate =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
                .expect("Could not register termination signal");
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {},
            _ = terminate.recv() => {},
        }
    }
    #[cfg(not(unix))]
    let _ = tokio::signal::ctrl_c().await;
}

#[tokio::main]
async fn main() -> Result<()> {
    let provider = Arc::new(Provider::new(Config::from_env()?)?);
    let base = format!("/{}", provider.config.issuer_id);
    let app = Router::new()
        .route("/health", get(|| async { Json(json!({ "status": "up" })) }))
        .route(
            &format!("{base}/.well-known/openid-configuration"),
            get(discovery),
        )
        .route(
            &format!("{base}/jwks"),
            get(|State(provider): State<Arc<Provider>>| async move { Json(provider.jwks.clone()) }),
        )
        .route(&format!("{base}/authorize"), get(authorize))
        .route(&format!("{base}/token"), post(token))
        .layer(middleware::from_fn(cors))
        .with_state(provider.clone());
    let listener = TcpListener::bind(("0.0.0.0", provider.config.port)).await?;
    let port = listener.local_addr()?.port();
    println!("Mock OIDC Provider listening on port {port}");
    println!("Issuer: http://localhost:{port}{base}");
    println!("Discovery: http://localhost:{port}{base}/.well-known/openid-configuration");
    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown())
        .await?;
    Ok(())
}
