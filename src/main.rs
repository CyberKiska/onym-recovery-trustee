//! The trustee service: `serve`, `keygen <path>`, `invite [lifetime]`.
//!
//! HTTP binding, proposed: public `GET /manifest.json` and `GET /health`, and
//! one `POST /v1/trustee` taking a canonical request object. Every request
//! runs as one synchronous [`Store::handle`] call under one global lock, so
//! state changes serialize and nothing awaits while the lock is held. The
//! log records route, status, error code and duration; never a body, an
//! identifier or a key.

#![forbid(unsafe_code)]

use std::fs::OpenOptions;
use std::io::Write as _;
use std::net::SocketAddr;
use std::os::unix::fs::OpenOptionsExt as _;
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::{Arc, Mutex};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use axum::Router;
use axum::body::Bytes;
use axum::extract::rejection::BytesRejection;
use axum::extract::{DefaultBodyLimit, State};
use axum::http::{StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use ed25519_dalek::SigningKey;
use onym_recovery_trustee::store::Store;
use onym_recovery_trustee::wire::{self, Code};
use onym_recovery_trustee::{Limits, Service, Trustee, crypto};
use zeroize::Zeroizing;

const USAGE: &str = "usage: onym-recovery-trustee serve | keygen <path> | invite [lifetime]

Environment:
  TRUSTEE_COMPONENT_ID   onym:component:<id> (serve)
  TRUSTEE_PUBLIC_URL     origin clients reach, https:// or http://127.0.0.1 (serve)
  TRUSTEE_KEY_FILE       key file written by `keygen` (serve)
  TRUSTEE_STORE_PATH     SQLite database, default trustee.sqlite
  TRUSTEE_BIND           listen address, default 127.0.0.1:8080
  TRUSTEE_TRUST_DOMAIN   declared administrative domain, default the URL's host
  TRUSTEE_JURISDICTION   declared jurisdiction, default none
  TRUSTEE_CONTACT        complaint path, default none
  TRUSTEE_MIN_COOLDOWN   shortest cooldown a policy may set, default PT1M";

const DAY: i64 = 86_400;

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let result = match args.iter().map(String::as_str).collect::<Vec<_>>()[..] {
        ["serve"] => serve(),
        ["keygen", path] => keygen(path),
        ["invite"] => invite("P7D"),
        ["invite", lifetime] => invite(lifetime),
        _ => Err(USAGE.into()),
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(message) => {
            eprintln!("{message}");
            ExitCode::FAILURE
        }
    }
}

// ---------------------------------------------------------------------------
// Commands

fn serve() -> Result<(), String> {
    let config = Config::from_env()?;
    let trustee = config.trustee()?;
    // Fail at startup, not at the first seal (see `crypto::seal`).
    getrandom::fill(&mut [0u8; 32]).map_err(|_| "the OS random number generator failed")?;
    let store = Store::open(&config.store_path)
        .map_err(|error| format!("{}: {error}", config.store_path.display()))?;
    let manifest = trustee
        .manifest(&config.service, now().map_err(|code| code.to_string())?)
        .map_err(|code| code.to_string())?;
    eprintln!(
        "{} {} trusteeKeyId {} listening on {}",
        trustee.component_id,
        trustee.operator(),
        trustee.key_id(),
        config.bind
    );

    let body_limit = trustee.limits.max_request_bytes();
    let app = Arc::new(App {
        trustee,
        // Deliberate global lock: one connection serializes every request.
        // Enough for a reference trustee; lock per enrollment if it is not.
        store: Mutex::new(store),
        manifest,
    });
    let router = Router::new()
        .route("/health", get(health))
        .route("/manifest.json", get(manifest_json))
        .route("/v1/trustee", post(endpoint))
        .layer(DefaultBodyLimit::max(body_limit))
        .with_state(app);

    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_io()
        .build()
        .map_err(|error| error.to_string())?;
    runtime.block_on(async {
        let listener = tokio::net::TcpListener::bind(config.bind)
            .await
            .map_err(|error| format!("{}: {error}", config.bind))?;
        axum::serve(listener, router)
            .await
            .map_err(|error| error.to_string())
    })
}

/// Write a new key file: an Ed25519 operator seed and an X25519 enrollment
/// key, owner-readable only. Refuses to overwrite.
fn keygen(path: &str) -> Result<(), String> {
    let mut seeds = Zeroizing::new([0u8; 64]);
    getrandom::fill(seeds.as_mut()).map_err(|_| "the OS random number generator failed")?;
    let operator = Zeroizing::new(hex::encode(&seeds[..32]));
    let enrollment = Zeroizing::new(hex::encode(&seeds[32..]));
    let text = Zeroizing::new(format!(
        "operator-ed25519 {}\nenrollment-x25519 {}\n",
        *operator, *enrollment
    ));
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .map_err(|error| format!("{path}: {error}"))?;
    file.write_all(text.as_bytes())
        .and_then(|()| file.sync_all())
        .map_err(|error| format!("{path}: {error}"))?;

    let (signing_key, hpke_key) = parse_keys(&text)?;
    let trustee = Trustee {
        component_id: String::new(),
        hpke_key,
        signing_key,
        limits: limits(0),
    };
    println!("operator {}", trustee.operator());
    println!("trusteeKeyId {}", trustee.key_id());
    Ok(())
}

/// Mint one invitation code and print it; the operator hands it to one
/// holder for one enrollment.
fn invite(lifetime: &str) -> Result<(), String> {
    let lifetime = wire::duration(lifetime)
        .filter(|&seconds| seconds > 0)
        .ok_or("lifetime: an ISO 8601 duration such as P7D")?;
    let path = store_path();
    let mut store = Store::open(&path).map_err(|error| format!("{}: {error}", path.display()))?;
    let code = now()
        .and_then(|now| store.create_invitation(lifetime, now))
        .map_err(|code| code.to_string())?;
    println!("{code}");
    Ok(())
}

// ---------------------------------------------------------------------------
// HTTP

struct App {
    trustee: Trustee,
    store: Mutex<Store>,
    manifest: Vec<u8>,
}

impl App {
    /// One request under the global lock. Synchronous: nothing awaits here.
    fn handle(&self, body: &[u8]) -> Result<Vec<u8>, Code> {
        let mut store = self
            .store
            .lock()
            .map_err(|_| Code::TemporarilyUnavailable)?;
        // Read under the lock, so time never runs backwards between requests.
        store.handle(&self.trustee, body, now()?)
    }
}

async fn endpoint(State(app): State<Arc<App>>, body: Result<Bytes, BytesRejection>) -> Response {
    let started = Instant::now();
    let result = body
        .map_err(|_| Code::InvalidRequest)
        .and_then(|body| app.handle(&body));
    let (status, code, body) = match result {
        Ok(body) => (StatusCode::OK, "-", body),
        Err(code) => (
            status(code),
            code.as_str(),
            wire::canonical(&serde_json::json!({ "error": code.as_str() })),
        ),
    };
    eprintln!(
        "POST /v1/trustee {} {code} {}ms",
        status.as_u16(),
        started.elapsed().as_millis()
    );
    (status, [(header::CONTENT_TYPE, "application/json")], body).into_response()
}

async fn manifest_json(State(app): State<Arc<App>>) -> Response {
    let headers = [(header::CONTENT_TYPE, "application/json")];
    (headers, app.manifest.clone()).into_response()
}

async fn health() -> Response {
    let headers = [(header::CONTENT_TYPE, "application/json")];
    (headers, r#"{"status":"ok"}"#).into_response()
}

/// Proposed status classes: 400 invalid object, 409 state conflict, 429
/// attempts spent, 501 declared unsupported, 503 unable to decide safely.
fn status(code: Code) -> StatusCode {
    use Code::*;
    match code {
        InvalidRequest
        | UnsupportedProfile
        | InvalidManifest
        | InvalidPolicy
        | InvalidEnrollment
        | ArtifactMismatch
        | InvalidDestination
        | InvalidCandidateFactor
        | InvalidContribution => StatusCode::BAD_REQUEST,
        RequestConflict
        | EnrollmentPending
        | EnrollmentExpired
        | EnrollmentRevoked
        | StaleEnrollmentSequence
        | RecoveryCoolingDown
        | RecoveryVetoed
        | RecoveryRefused
        | RecoveryExpired
        | InsufficientContributions
        | ServiceLapsed => StatusCode::CONFLICT,
        RecoveryRateLimited => StatusCode::TOO_MANY_REQUESTS,
        PaymentRequired => StatusCode::PAYMENT_REQUIRED,
        BootstrapUnavailable | ExportUnavailable => StatusCode::NOT_IMPLEMENTED,
        TemporarilyUnavailable => StatusCode::SERVICE_UNAVAILABLE,
    }
}

// ---------------------------------------------------------------------------
// Configuration

struct Config {
    component_id: String,
    key_file: PathBuf,
    store_path: PathBuf,
    bind: SocketAddr,
    min_cooldown_secs: i64,
    service: Service,
}

impl Config {
    fn from_env() -> Result<Config, String> {
        let required =
            |name: &str| std::env::var(name).map_err(|_| format!("{name} is required\n\n{USAGE}"));
        let optional =
            |name: &str, default: &str| std::env::var(name).unwrap_or_else(|_| default.into());

        let component_id = required("TRUSTEE_COMPONENT_ID")?;
        if !wire::is_component_id(&component_id) {
            return Err("TRUSTEE_COMPONENT_ID: onym:component: and 1-64 of [a-z0-9-]".into());
        }
        let public_url = required("TRUSTEE_PUBLIC_URL")?;
        let host = public_host(&public_url).ok_or(
            "TRUSTEE_PUBLIC_URL: an https:// origin, or http://127.0.0.1 or http://localhost \
             for local use; no path",
        )?;
        let bind = optional("TRUSTEE_BIND", "127.0.0.1:8080");
        let min_cooldown = optional("TRUSTEE_MIN_COOLDOWN", "PT1M");
        Ok(Config {
            key_file: required("TRUSTEE_KEY_FILE")?.into(),
            store_path: store_path(),
            bind: bind.parse().map_err(|_| format!("TRUSTEE_BIND: {bind}"))?,
            min_cooldown_secs: wire::duration(&min_cooldown)
                .filter(|&seconds| seconds > 0)
                .ok_or("TRUSTEE_MIN_COOLDOWN: an ISO 8601 duration such as PT1M")?,
            service: Service {
                endpoint: format!("{public_url}/v1/trustee"),
                trust_domain: optional("TRUSTEE_TRUST_DOMAIN", host),
                jurisdiction: optional("TRUSTEE_JURISDICTION", "none"),
                contact: optional("TRUSTEE_CONTACT", "none"),
            },
            component_id,
        })
    }

    fn trustee(&self) -> Result<Trustee, String> {
        let text = std::fs::read_to_string(&self.key_file)
            .map(Zeroizing::new)
            .map_err(|error| format!("{}: {error}", self.key_file.display()))?;
        let (signing_key, hpke_key) = parse_keys(&text)?;
        Ok(Trustee {
            component_id: self.component_id.clone(),
            hpke_key,
            signing_key,
            limits: limits(self.min_cooldown_secs),
        })
    }
}

/// The published bounds; only the cooldown floor is configurable.
fn limits(min_cooldown_secs: i64) -> Limits {
    Limits {
        skew_secs: 300,
        min_cooldown_secs,
        max_cooldown_secs: 30 * DAY,
        max_session_lifetime_secs: 30 * DAY,
        max_attempts: 10,
        max_enrollment_term_secs: 2 * 365 * DAY,
        max_artifact_bytes: 64 * 1024,
    }
}

fn store_path() -> PathBuf {
    std::env::var("TRUSTEE_STORE_PATH")
        .unwrap_or_else(|_| "trustee.sqlite".into())
        .into()
}

/// The host of an https origin, or of a loopback http one.
fn public_host(url: &str) -> Option<&str> {
    let (scheme, authority) = url.split_once("://")?;
    let host = authority.split(':').next()?;
    let loopback = matches!(host, "127.0.0.1" | "localhost");
    let valid = (scheme == "https" || scheme == "http" && loopback)
        && !host.is_empty()
        && !authority.contains(['/', '?', '#', '@']);
    valid.then_some(host)
}

/// Exactly the two lines `keygen` writes. Errors never echo the file.
fn parse_keys(text: &str) -> Result<(SigningKey, crypto::HpkePrivateKey), String> {
    let mut lines = text.lines();
    let mut key = |label: &str| {
        lines
            .next()
            .and_then(|line| line.strip_prefix(label))
            .and_then(wire::hex32)
            .map(Zeroizing::new)
    };
    let (Some(operator), Some(enrollment)) = (key("operator-ed25519 "), key("enrollment-x25519 "))
    else {
        return Err("key file: expected the two lines `keygen` writes".into());
    };
    if lines.next().is_some() {
        return Err("key file: expected the two lines `keygen` writes".into());
    }
    let hpke_key = crypto::hpke_private_key(&enrollment).map_err(|_| "key file: enrollment key")?;
    Ok((SigningKey::from_bytes(&operator), hpke_key))
}

fn now() -> Result<i64, Code> {
    let elapsed = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| Code::TemporarilyUnavailable)?;
    i64::try_from(elapsed.as_secs()).map_err(|_| Code::TemporarilyUnavailable)
}

#[cfg(test)]
mod tests {
    use super::public_host;

    #[test]
    fn public_urls_are_https_or_loopback_origins() {
        assert_eq!(
            public_host("https://trustee.example"),
            Some("trustee.example")
        );
        assert_eq!(
            public_host("https://trustee.example:8443"),
            Some("trustee.example")
        );
        assert_eq!(public_host("http://127.0.0.1:8080"), Some("127.0.0.1"));
        assert_eq!(public_host("http://localhost"), Some("localhost"));
        for rejected in [
            "http://trustee.example",
            "http://127.0.0.1.trustee.example",
            "https://trustee.example/",
            "https://user@trustee.example",
            "https://",
            "trustee.example",
        ] {
            assert_eq!(public_host(rejected), None, "{rejected}");
        }
    }
}
