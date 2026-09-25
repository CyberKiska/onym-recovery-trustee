//! The trustee service: `serve`, `keygen <path>`, `invite [lifetime]`.
//!
//! HTTP binding, proposed: public `GET /manifest.json`, `GET /health`
//! (liveness) and `GET /ready`, and one `POST /v1/trustee` taking a
//! canonical request object. A request is parsed on the event loop, takes
//! one of a bounded number of places, and runs as one synchronous
//! [`Store::handle_request`] call on a blocking thread under one global
//! lock, so state changes serialize and nothing awaits while the lock is
//! held. The log records route, status, error code and duration; never a
//! body, an identifier or a key.

#![forbid(unsafe_code)]

use std::fs::{File, OpenOptions};
use std::io::{Read as _, Write as _};
use std::net::SocketAddr;
use std::os::unix::fs::{OpenOptionsExt as _, PermissionsExt as _};
use std::path::{Path, PathBuf};
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
use onym_recovery_trustee::store::{self, Store};
use onym_recovery_trustee::wire::{self, Code};
use onym_recovery_trustee::{Limits, Service, Trustee, crypto};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
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

/// Read limit for the key file, whose valid form is two short lines.
const KEY_FILE_BYTES: usize = 512;

/// Requests admitted to the store at once, and the extra places kept for
/// [`store::PROTECTIVE`] operations.
const ADMITTED: usize = 32;
const RESERVED: usize = 8;

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
    let mut store = open_store(&config.store_path)?;
    let bound = store
        .bind(&trustee)
        .map_err(|error| format!("{}: {error}", config.store_path.display()))?;
    if !bound {
        return Err(format!(
            "{}: this database belongs to another component or key, or holds custody from \
             before databases were bound to one; refusing to serve it",
            config.store_path.display()
        ));
    }
    // Fail at startup, not at the first manifest request.
    trustee
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
        service: config.service,
        clock: Clock::start().map_err(|code| code.to_string())?,
        admission: Admission::new(ADMITTED, RESERVED),
    });
    let router = Router::new()
        .route("/health", get(health))
        .route("/ready", get(ready))
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
        let stop = stop_signal().map_err(|error| format!("signals: {error}"))?;
        axum::serve(listener, router)
            .with_graceful_shutdown(stop)
            .await
            .map_err(|error| error.to_string())
    })?;
    eprintln!("stopped");
    Ok(())
}

/// Resolves on SIGTERM (`docker stop`) or SIGINT. The service is PID 1 in
/// its container, where an unhandled SIGTERM is ignored, so it must listen.
/// Shutdown stops accepting, lets requests in flight finish, then returns.
fn stop_signal() -> std::io::Result<impl Future<Output = ()>> {
    use tokio::signal::unix::{SignalKind, signal};
    let mut terminate = signal(SignalKind::terminate())?;
    let mut interrupt = signal(SignalKind::interrupt())?;
    Ok(async move {
        tokio::select! {
            _ = terminate.recv() => {}
            _ = interrupt.recv() => {}
        }
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
    let mut store = open_store(&store_path())?;
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
    service: Service,
    clock: Clock,
    admission: Admission,
}

impl App {
    /// Parse, take a place, then serve the request on a blocking thread
    /// under the global lock, off the event loop. Nothing awaits under it.
    async fn handle(self: Arc<Self>, body: Bytes) -> Result<Vec<u8>, Code> {
        let request = wire::parse(&body).ok_or(Code::InvalidRequest)?;
        let operation = request["operation"].as_str().unwrap_or_default();
        let place = self
            .admission
            .admit(operation)
            .ok_or(Code::TemporarilyUnavailable)?;
        tokio::task::spawn_blocking(move || {
            let _place = place;
            let mut store = self
                .store
                .lock()
                .map_err(|_| Code::TemporarilyUnavailable)?;
            // Read under the lock, so time never runs backwards between requests.
            store.handle_request(&self.trustee, request, self.clock.now()?)
        })
        .await
        .map_err(|_| Code::TemporarilyUnavailable)?
    }

    /// Ready for custody decisions, or why not: saturated, a clock release
    /// cannot use, or a store that does not answer.
    async fn readiness(self: Arc<Self>) -> Result<(), &'static str> {
        if self.clock.ahead().map_err(|_| "clock_unreadable")? {
            return Err("clock_ahead");
        }
        let place = self.admission.admit("").ok_or("busy")?;
        tokio::task::spawn_blocking(move || {
            let _place = place;
            let store = self.store.lock().map_err(|_| "unavailable")?;
            let floor = store.clock_floor().map_err(|_| "unavailable")?;
            let now = self.clock.now().map_err(|_| "clock_unreadable")?;
            if now < floor {
                return Err("clock_behind");
            }
            Ok(())
        })
        .await
        .map_err(|_| "unavailable")?
    }
}

/// Bounded places for requests on their way to the store. A request that
/// finds none is refused at once rather than queued without bound, and a
/// flood of other operations cannot take the reserve kept for a veto.
struct Admission {
    places: Arc<Semaphore>,
    reserve: Arc<Semaphore>,
}

impl Admission {
    fn new(places: usize, reserve: usize) -> Admission {
        Admission {
            places: Arc::new(Semaphore::new(places)),
            reserve: Arc::new(Semaphore::new(reserve)),
        }
    }

    fn admit(&self, operation: &str) -> Option<OwnedSemaphorePermit> {
        let reserved = || {
            store::PROTECTIVE
                .contains(&operation)
                .then(|| self.reserve.clone().try_acquire_owned().ok())
                .flatten()
        };
        self.places
            .clone()
            .try_acquire_owned()
            .ok()
            .or_else(reserved)
    }
}

async fn endpoint(State(app): State<Arc<App>>, body: Result<Bytes, BytesRejection>) -> Response {
    let started = Instant::now();
    let result = match body {
        Ok(body) => app.handle(body).await,
        Err(_) => Err(Code::InvalidRequest),
    };
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
    // Receipts and contributions are private: no cache may keep them.
    let headers = [
        (header::CONTENT_TYPE, "application/json"),
        (header::CACHE_CONTROL, "no-store"),
    ];
    (status, headers, body).into_response()
}

/// Signed on each read; the bytes change only when `validUntil` moves on.
async fn manifest_json(State(app): State<Arc<App>>) -> Response {
    match app
        .clock
        .now()
        .and_then(|now| app.trustee.manifest(&app.service, now))
    {
        Ok(manifest) => ([(header::CONTENT_TYPE, "application/json")], manifest).into_response(),
        Err(code) => status(code).into_response(),
    }
}

/// Liveness only: the process answers.
async fn health() -> Response {
    let headers = [(header::CONTENT_TYPE, "application/json")];
    (headers, r#"{"status":"ok"}"#).into_response()
}

/// Readiness, with a reason and no identifier: `ready`, or 503 with `busy`,
/// `clock_behind`, `clock_ahead`, `clock_unreadable` or `unavailable`.
async fn ready(State(app): State<Arc<App>>) -> Response {
    let (status, text) = match app.readiness().await {
        Ok(()) => (StatusCode::OK, "ready"),
        Err(reason) => (StatusCode::SERVICE_UNAVAILABLE, reason),
    };
    let headers = [
        (header::CONTENT_TYPE, "application/json"),
        (header::CACHE_CONTROL, "no-store"),
    ];
    let body = wire::canonical(&serde_json::json!({ "status": text }));
    (status, headers, body).into_response()
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
        let file = open_private(&self.key_file, OpenOptions::new().read(true))?;
        // A valid key file is under 200 bytes: reserve enough that reading
        // never reallocates and leaves an unzeroed copy, and read no more.
        let mut text = Zeroizing::new(String::with_capacity(KEY_FILE_BYTES));
        file.take(KEY_FILE_BYTES as u64)
            .read_to_string(&mut text)
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

/// Open the database, creating it owner-only first: SQLite gives its WAL
/// and shared-memory files the database file's mode.
fn open_store(path: &Path) -> Result<Store, String> {
    open_private(
        path,
        OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600),
    )?;
    Store::open(path).map_err(|error| format!("{}: {error}", path.display()))
}

/// Open a file holding keys or custody, refusing anything but a regular
/// file only its owner can reach. The checks apply to the handle opened, so
/// the file cannot be swapped between check and use. Symbolic links are
/// followed, as mounted secrets often are.
fn open_private(path: &Path, options: &OpenOptions) -> Result<File, String> {
    let fail = |error: &dyn std::fmt::Display| format!("{}: {error}", path.display());
    // Checked before opening too: opening a FIFO would block.
    if std::fs::metadata(path).is_ok_and(|metadata| !metadata.is_file()) {
        return Err(fail(&"not a regular file"));
    }
    let file = options.open(path).map_err(|error| fail(&error))?;
    let metadata = file.metadata().map_err(|error| fail(&error))?;
    if !metadata.is_file() {
        return Err(fail(&"not a regular file"));
    }
    if metadata.permissions().mode() & 0o077 != 0 {
        return Err(fail(
            &"group or others have access; make it owner-only (chmod 600)",
        ));
    }
    Ok(file)
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

/// Seconds the wall clock may run ahead of the monotonic one: whole-second
/// rounding of both, and small corrections.
const CLOCK_SLACK_SECS: i64 = 5;

/// Wall time that never runs faster than the monotonic clock since startup,
/// so a wall clock stepped forward while the service runs cannot shorten a
/// cooldown. A step back is the store's high-water mark's to handle.
struct Clock {
    started_at: i64,
    started: Instant,
}

impl Clock {
    fn start() -> Result<Clock, Code> {
        Ok(Clock {
            started_at: now()?,
            started: Instant::now(),
        })
    }

    fn now(&self) -> Result<i64, Code> {
        Ok(now()?.min(self.limit()))
    }

    /// The wall clock is ahead of the monotonic one: time follows the
    /// monotonic clock until an operator checks the clock and restarts.
    fn ahead(&self) -> Result<bool, Code> {
        Ok(now()? > self.limit())
    }

    fn limit(&self) -> i64 {
        let elapsed = i64::try_from(self.started.elapsed().as_secs()).unwrap_or(i64::MAX);
        self.started_at
            .saturating_add(elapsed)
            .saturating_add(CLOCK_SLACK_SECS)
    }
}

#[cfg(test)]
mod tests {
    use super::{Admission, CLOCK_SLACK_SECS, Clock, now, open_private, public_host};
    use std::fs::{OpenOptions, Permissions};
    use std::os::unix::fs::PermissionsExt as _;
    use std::time::Instant;

    #[test]
    fn only_owner_only_regular_files_hold_keys() {
        let dir = std::env::temp_dir().join(format!("trustee-keys-{}", std::process::id()));
        std::fs::create_dir(&dir).unwrap();
        let file = |name: &str, mode: u32| {
            let path = dir.join(name);
            std::fs::write(&path, "key").unwrap();
            std::fs::set_permissions(&path, Permissions::from_mode(mode)).unwrap();
            path
        };
        let read = OpenOptions::new().read(true).clone();
        let private = file("private", 0o600);
        std::os::unix::fs::symlink(&private, dir.join("link")).unwrap();
        assert!(open_private(&private, &read).is_ok());
        assert!(open_private(&dir.join("link"), &read).is_ok());
        assert!(open_private(&file("shared", 0o640), &read).is_err());
        assert!(open_private(&dir, &read).is_err());
        let fifo = std::process::Command::new("mkfifo")
            .arg(dir.join("fifo"))
            .status();
        if fifo.is_ok_and(|status| status.success()) {
            // Refused before opening, so the open cannot block.
            assert!(open_private(&dir.join("fifo"), &read).is_err());
        }
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn admission_is_bounded_and_keeps_a_reserve_for_protection() {
        let admission = Admission::new(1, 1);
        let held = admission.admit("begin-recovery").unwrap();
        assert!(admission.admit("enroll").is_none());
        let reserved = admission.admit("cancel-recovery").unwrap();
        assert!(admission.admit("close-enrollment").is_none());
        drop((held, reserved));
        assert!(admission.admit("enroll").is_some());
    }

    #[test]
    fn time_never_runs_faster_than_the_monotonic_clock() {
        let wall = now().unwrap();
        // The wall clock stepped an hour forward since startup: capped.
        let stepped_forward = Clock {
            started_at: wall - 3600,
            started: Instant::now(),
        };
        assert!(stepped_forward.now().unwrap() <= wall - 3600 + CLOCK_SLACK_SECS);
        assert!(stepped_forward.ahead().unwrap());
        // Stepped back: the wall clock is followed, and the store refuses it.
        let stepped_back = Clock {
            started_at: wall + 3600,
            started: Instant::now(),
        };
        assert!(stepped_back.now().unwrap() <= wall + 1);
        assert!(!stepped_back.ahead().unwrap());
        let steady = Clock::start().unwrap();
        assert!((steady.now().unwrap() - wall).abs() <= 1 && !steady.ahead().unwrap());
    }

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
