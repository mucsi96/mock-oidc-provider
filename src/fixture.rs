//! Opt-in confidential-client fixtures for backend-for-frontend E2E tests.
use std::collections::HashMap;

use anyhow::{Result, ensure};
use serde::{Deserialize, Serialize};
use url::Url;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub issuer_url: String,
    pub access_token_ttl_secs: u64,
    pub clients: HashMap<String, Client>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Client {
    pub secret: String,
    pub redirect_uri: String,
    pub api_audience: Option<String>,
    pub api_scope: Option<String>,
    pub allowed_users: Vec<String>,
    pub roles: HashMap<String, Vec<String>>,
}

impl Config {
    pub fn load() -> Result<Option<Self>> {
        let Ok(path) = std::env::var("FIXTURE_CONFIG_FILE") else {
            return Ok(None);
        };
        let config: Self = serde_json::from_slice(&std::fs::read(path)?)?;
        let issuer = Url::parse(&config.issuer_url)?;
        ensure!(
            matches!(issuer.scheme(), "http" | "https") && issuer.host_str().is_some(),
            "invalid fixture issuer"
        );
        ensure!(
            config.access_token_ttl_secs > 0 && !config.clients.is_empty(),
            "invalid fixture configuration"
        );
        for client in config.clients.values() {
            ensure!(
                !client.secret.is_empty() && Url::parse(&client.redirect_uri).is_ok(),
                "invalid fixture client"
            );
        }
        Ok(Some(config))
    }
}

#[derive(Clone, Copy, Default, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum Mode {
    #[default]
    Normal,
    BadNonce,
    BadSignature,
    BadAudience,
    BadIssuer,
    ExpiredId,
    BadSubject,
    FutureNbf,
    FutureIat,
    BadAzp,
    HmacId,
    MissingApiRole,
    RefreshOutage,
    RefreshInvalidGrant,
    RefreshSlow,
    RefreshSlowInvalidGrant,
}

#[derive(Default, Clone, Serialize)]
pub struct Counts {
    pub authorizations: u64,
    pub redemptions: u64,
    pub refreshes: u64,
}

pub struct State {
    pub mode: Mode,
    pub user: String,
    pub counts: Counts,
}

impl Default for State {
    fn default() -> Self {
        Self {
            mode: Mode::Normal,
            user: "owner".into(),
            counts: Counts::default(),
        }
    }
}

#[derive(Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Control {
    #[serde(default)]
    pub mode: Mode,
    pub user: Option<String>,
}
