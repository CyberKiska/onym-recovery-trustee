//! Durable trustee state in SQLite: custody, challenges, sessions, replay
//! nonces and idempotency records.
//!
//! [`Store::handle`] serves one request as one synchronous call inside one
//! IMMEDIATE transaction, so every state change serializes. Receipts are
//! rebuilt from committed rows and signed only after commit and read-back;
//! Ed25519 is deterministic, so an identical retry gets identical bytes. The
//! only stored signed object is a contribution, persisted before it is
//! returned. Callers must never hold the store across an `.await`.

use std::path::Path;
use std::time::Duration;

use rusqlite::types::Type;
use rusqlite::{Connection, OptionalExtension, Row, Transaction, TransactionBehavior, params};
use serde::Deserialize;
use serde_json::{Value, json};

use crate::state::{self, EnrollmentState, EnrollmentStatus, Release, SessionState, SessionStatus};
use crate::wire::{self, Code, Notice, Receipt, Signed};
use crate::{Enrollment, Trustee, crypto};

/// Operations [`Store::handle`] serves.
pub const OPERATIONS: [&str; 8] = [
    "issue-challenge",
    "enroll",
    "read-enrollment",
    "begin-recovery",
    "read-recovery",
    "cancel-recovery",
    "revoke-enrollment",
    "close-enrollment",
];

/// Contract operations this trustee declares unsupported, with the code it
/// answers them with.
pub const REFUSED: [(&str, Code); 4] = [
    ("bootstrap-recovery", Code::BootstrapUnavailable),
    ("export-enrollment", Code::ExportUnavailable),
    ("finalize-recovery", Code::InvalidRequest),
    ("rotate-enrollment", Code::InvalidRequest),
];

const CHALLENGE_LIFETIME_SECS: i64 = 15 * 60;
/// Unused challenges one invitation may have outstanding.
const MAX_OPEN_CHALLENGES: i64 = 4;

/// Schema migrations: entry `i` takes version `i` to `i + 1`, each in its
/// own transaction. Only ever append.
const MIGRATIONS: [&str; 2] = [
    "
-- Highest time any transaction has seen: a clock behind it moved backwards.
CREATE TABLE clock (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    high_water INTEGER NOT NULL
);
INSERT INTO clock VALUES (1, 0);

-- One invitation authorizes one enrollment. Only the code's digest is kept.
CREATE TABLE invitations (
    digest TEXT PRIMARY KEY,
    expires_at INTEGER NOT NULL,
    used_at INTEGER
);

-- Single-use, expiring enrollment challenges (Shamir §5.1).
CREATE TABLE challenges (
    challenge TEXT PRIMARY KEY,
    invitation TEXT NOT NULL REFERENCES invitations (digest),
    expires_at INTEGER NOT NULL,
    used_at INTEGER
);

-- One row per accepted sequence. `record` is the non-secret `Enrollment`:
-- bindings, policy and public keys. Revoked and closed rows are tombstones
-- whose sealed envelope and artifact are deleted.
CREATE TABLE enrollments (
    enrollment_id TEXT NOT NULL,
    sequence INTEGER NOT NULL,
    status TEXT NOT NULL
        CHECK (status IN ('accepted', 'superseded', 'revoked', 'closed')),
    challenge TEXT NOT NULL UNIQUE REFERENCES challenges (challenge),
    request_digest TEXT NOT NULL,
    record TEXT NOT NULL,
    attempts_used INTEGER NOT NULL DEFAULT 0,
    stored_at INTEGER NOT NULL,
    sealed_envelope BLOB,
    protected_artifact BLOB,
    PRIMARY KEY (enrollment_id, sequence)
);

-- One row per admitted session, refused ones included: each was an attempt.
CREATE TABLE sessions (
    session_id TEXT PRIMARY KEY,
    enrollment_id TEXT NOT NULL,
    sequence INTEGER NOT NULL,
    status TEXT NOT NULL CHECK (status IN
        ('cooling_down', 'released', 'finalized', 'cancelled', 'vetoed', 'refused')),
    request BLOB NOT NULL,
    proof_key BLOB NOT NULL,
    destination_keys_digest TEXT NOT NULL,
    cooldown_ends_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL,
    remaining_attempts INTEGER NOT NULL,
    created_at INTEGER NOT NULL,
    contribution BLOB,
    FOREIGN KEY (enrollment_id, sequence) REFERENCES enrollments (enrollment_id, sequence)
);

-- Replay nonces of signed reads, purged after twice the clock skew.
CREATE TABLE nonces (
    scope TEXT NOT NULL,
    request_id TEXT NOT NULL,
    seen_at INTEGER NOT NULL,
    PRIMARY KEY (scope, request_id)
);

-- Outcomes of signed state changes, kept as long as what they changed.
CREATE TABLE outcomes (
    scope TEXT NOT NULL,
    request_id TEXT NOT NULL,
    request_digest TEXT NOT NULL,
    operation TEXT NOT NULL,
    old_state TEXT NOT NULL,
    new_state TEXT NOT NULL,
    recorded_at INTEGER NOT NULL,
    PRIMARY KEY (scope, request_id)
);
",
    "
-- The one trustee this database serves (`Store::bind`).
CREATE TABLE identity (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    component_id TEXT NOT NULL,
    operator TEXT NOT NULL,
    trustee_key_id TEXT NOT NULL
);
",
];

/// Database failures never reach a response in detail.
impl From<rusqlite::Error> for Code {
    fn from(_: rusqlite::Error) -> Code {
        Code::TemporarilyUnavailable
    }
}

pub struct Store {
    connection: Connection,
}

impl Store {
    /// Open or create the database: WAL, `synchronous=FULL`, foreign keys,
    /// `secure_delete`, so deleted custody is zeroed in the database file,
    /// and temporaries in memory, never in a file of their own. Older
    /// schemas are migrated; a newer one is refused.
    pub fn open(path: impl AsRef<Path>) -> rusqlite::Result<Store> {
        Store::setup(Connection::open(path)?)
    }

    pub fn open_in_memory() -> rusqlite::Result<Store> {
        Store::setup(Connection::open_in_memory()?)
    }

    fn setup(mut connection: Connection) -> rusqlite::Result<Store> {
        connection.busy_timeout(Duration::from_secs(5))?;
        connection.execute_batch(
            "PRAGMA journal_mode = WAL;
             PRAGMA synchronous = FULL;
             PRAGMA foreign_keys = ON;
             PRAGMA secure_delete = ON;
             PRAGMA temp_store = MEMORY;",
        )?;
        // The version is read inside each write transaction, so two processes
        // opening a new database never both apply the same step.
        loop {
            let tx = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
            let version: usize = tx.query_row("PRAGMA user_version", [], |row| row.get(0))?;
            match MIGRATIONS.get(version) {
                Some(migration) => {
                    tx.execute_batch(migration)?;
                    tx.pragma_update(None, "user_version", version + 1)?;
                    tx.commit()?;
                }
                None if version == MIGRATIONS.len() => break,
                // Never guess at a layout this build does not know.
                None => {
                    return Err(rusqlite::Error::SqliteFailure(
                        rusqlite::ffi::Error::new(rusqlite::ffi::SQLITE_MISMATCH),
                        Some(format!("unsupported schema version {version}")),
                    ));
                }
            }
        }
        Ok(Store { connection })
    }

    /// Tie the database to one trustee. The first call records its
    /// component, operator key and enrollment key; later calls return
    /// false for any other, so a wrong key file or component ID never
    /// serves custody sealed to, or bound to, another. A database that
    /// already holds custody but was never bound (schema 1) cannot show
    /// whose it is, so it is refused under every key rather than adopted.
    pub fn bind(&mut self, trustee: &Trustee) -> rusqlite::Result<bool> {
        let identity = (
            trustee.component_id.clone(),
            trustee.operator(),
            trustee.key_id(),
        );
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let unbound_custody: bool = tx.query_row(
            "SELECT NOT EXISTS (SELECT 1 FROM identity) AND EXISTS (SELECT 1 FROM enrollments)",
            [],
            |row| row.get(0),
        )?;
        if unbound_custody {
            return Ok(false);
        }
        tx.execute(
            "INSERT OR IGNORE INTO identity (id, component_id, operator, trustee_key_id)
             VALUES (1, ?1, ?2, ?3)",
            params![identity.0, identity.1, identity.2],
        )?;
        let stored: (String, String, String) = tx.query_row(
            "SELECT component_id, operator, trustee_key_id FROM identity",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )?;
        tx.commit()?;
        Ok(stored == identity)
    }

    /// Mint an invitation for one enrollment. Only its digest is stored; the
    /// operator hands the returned code to the holder once.
    pub fn create_invitation(&mut self, lifetime_secs: i64, now: i64) -> Result<String, Code> {
        let code = random_id()?;
        let (tx, _) = self.transaction(now)?;
        tx.execute(
            "INSERT INTO invitations (digest, expires_at) VALUES (?1, ?2)",
            params![wire::digest(code.as_bytes()), now + lifetime_secs],
        )?;
        tx.commit()?;
        Ok(code)
    }

    /// Serve one request of the trustee endpoint.
    pub fn handle(&mut self, trustee: &Trustee, body: &[u8], now: i64) -> Result<Vec<u8>, Code> {
        let request = wire::parse(body).ok_or(Code::InvalidRequest)?;
        let operation = request["operation"].as_str().unwrap_or_default().to_owned();
        let signed =
            |request| Signed::parse(request, &trustee.component_id).ok_or(Code::InvalidRequest);
        match operation.as_str() {
            "issue-challenge" => self.issue_challenge(trustee, request, now),
            "enroll" => self.enroll(trustee, request, now),
            "read-enrollment" => self.read_enrollment(trustee, signed(request)?, now),
            "begin-recovery" => self.begin_recovery(trustee, request, now),
            "read-recovery" => self.read_recovery(trustee, signed(request)?, now),
            "cancel-recovery" => self.cancel_recovery(trustee, signed(request)?, now),
            "revoke-enrollment" | "close-enrollment" => {
                self.end_enrollment(trustee, signed(request)?, now)
            }
            other => Err(REFUSED
                .iter()
                .find(|(name, _)| *name == other)
                .map_or(Code::InvalidRequest, |&(_, code)| code)),
        }
    }

    /// The write transaction every operation runs in. Refuses a clock behind
    /// the highest time already recorded, and returns that floor.
    fn transaction(&mut self, now: i64) -> Result<(Transaction<'_>, i64), Code> {
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let floor: i64 = tx.query_row("SELECT high_water FROM clock", [], |row| row.get(0))?;
        if now < floor {
            return Err(Code::TemporarilyUnavailable);
        }
        tx.execute("UPDATE clock SET high_water = ?1", [now])?;
        Ok((tx, floor))
    }

    fn issue_challenge(
        &mut self,
        trustee: &Trustee,
        request: Value,
        now: i64,
    ) -> Result<Vec<u8>, Code> {
        let request =
            wire::ChallengeRequest::deserialize(&request).map_err(|_| Code::InvalidRequest)?;
        let well_formed = request.request_version == 1
            && request.component_id == trustee.component_id
            && wire::hex32(&request.invitation).is_some();
        if !well_formed {
            return Err(Code::InvalidRequest);
        }
        let invitation = wire::digest(request.invitation.as_bytes());
        let challenge = random_id()?;
        let expires_at = now + CHALLENGE_LIFETIME_SECS;

        let (tx, _) = self.transaction(now)?;
        let open: Option<i64> = tx
            .query_row(
                "SELECT (SELECT count(*) FROM challenges
                         WHERE invitation = ?1 AND used_at IS NULL AND expires_at > ?2)
                 FROM invitations WHERE digest = ?1 AND used_at IS NULL AND expires_at > ?2",
                params![invitation, now],
                |row| row.get(0),
            )
            .optional()?;
        // Unknown, used, expired and exhausted invitations look the same.
        if !open.is_some_and(|open| open < MAX_OPEN_CHALLENGES) {
            return Err(Code::InvalidRequest);
        }
        tx.execute(
            "INSERT INTO challenges (challenge, invitation, expires_at) VALUES (?1, ?2, ?3)",
            params![challenge, invitation, expires_at],
        )?;
        tx.commit()?;
        Ok(wire::canonical(&json!({
            "challenge": challenge,
            "componentId": trustee.component_id,
            "expiresAt": time(expires_at)?,
            "trusteeKeyId": trustee.key_id(),
        })))
    }

    fn enroll(&mut self, trustee: &Trustee, request: Value, now: i64) -> Result<Vec<u8>, Code> {
        let request_digest = wire::digest(&wire::canonical(&request));
        let request =
            wire::EnrollRequest::deserialize(&request).map_err(|_| Code::InvalidRequest)?;
        let sealed = wire::base64(&request.sealed_envelope)
            .filter(|_| request.request_version == 1)
            .ok_or(Code::InvalidRequest)?;
        let artifact = wire::canonical(&request.protected_artifact);
        let context = request.context;
        let challenge = context.trustee_challenge.clone();

        let (tx, _) = self.transaction(now)?;
        // The challenge is the request ID: a retry gets the recorded outcome.
        let recorded: Option<(String, String)> = tx
            .query_row(
                "SELECT request_digest, status FROM enrollments WHERE challenge = ?1",
                [&challenge],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()?;
        if let Some((digest, status)) = recorded {
            drop(tx);
            return match (digest == request_digest, status.as_str()) {
                (false, _) => Err(Code::RequestConflict),
                // A tombstone never answers as live custody.
                (true, "revoked" | "closed") => Err(Code::EnrollmentRevoked),
                (true, _) => self.enrollment_receipt(trustee, &challenge, &sealed, &artifact),
            };
        }

        // Only a challenge this trustee issued, unexpired and unused, for an
        // invitation still open: a published key alone cannot create custody.
        let invitation: Option<String> = tx
            .query_row(
                "SELECT c.invitation FROM challenges c JOIN invitations i ON i.digest = c.invitation
                 WHERE c.challenge = ?1 AND c.used_at IS NULL AND c.expires_at > ?2
                   AND i.used_at IS NULL AND i.expires_at > ?2",
                params![challenge, now],
                |row| row.get(0),
            )
            .optional()?;
        let invitation = invitation.ok_or(Code::InvalidEnrollment)?;
        if request.trustee_key_id != trustee.key_id() {
            return Err(Code::InvalidEnrollment);
        }

        let enrollment = trustee.accept_enrollment(&context, &sealed, now)?;
        trustee.check_artifact(&enrollment, &artifact)?;
        // A known enrollment ID is a tombstone or a rotation, and rotation
        // needs lineage this draft does not define yet. Its state is told
        // only to the key that holds it; any other signer is refused like a
        // bad envelope and spends the invitation, as enrolling would.
        if let Some(existing) = load_current_enrollment(&tx, &context.enrollment_id)? {
            if existing.enrollment.authorization_key != enrollment.authorization_key {
                spend_challenge(&tx, &challenge, &invitation, now)?;
                tx.commit()?;
                return Err(Code::InvalidEnrollment);
            }
            return Err(match existing.status {
                EnrollmentStatus::Revoked | EnrollmentStatus::Closed => Code::EnrollmentRevoked,
                _ if context.enrollment_sequence <= existing.state().sequence => {
                    Code::StaleEnrollmentSequence
                }
                _ => Code::InvalidEnrollment,
            });
        }
        let record =
            serde_json::to_string(&enrollment).map_err(|_| Code::TemporarilyUnavailable)?;
        tx.execute(
            "INSERT INTO enrollments (enrollment_id, sequence, status, challenge, request_digest,
                                      record, stored_at, sealed_envelope, protected_artifact)
             VALUES (?1, ?2, 'accepted', ?3, ?4, ?5, ?6, ?7, ?8)",
            params![
                context.enrollment_id,
                context.enrollment_sequence,
                challenge,
                request_digest,
                record,
                now,
                sealed,
                artifact
            ],
        )?;
        spend_challenge(&tx, &challenge, &invitation, now)?;
        tx.commit()?;
        self.enrollment_receipt(trustee, &challenge, &sealed, &artifact)
    }

    /// Read a committed enrollment back, confirm it holds exactly the bytes
    /// received, and only then sign its receipt.
    fn enrollment_receipt(
        &self,
        trustee: &Trustee,
        challenge: &str,
        sealed: &[u8],
        artifact: &[u8],
    ) -> Result<Vec<u8>, Code> {
        let row = self.connection.query_row(
            &format!(
                "SELECT {} FROM enrollments WHERE challenge = ?1",
                EnrollmentRow::COLUMNS
            ),
            [challenge],
            EnrollmentRow::read,
        )?;
        if row.sealed_envelope.as_deref() != Some(sealed)
            || row.protected_artifact.as_deref() != Some(artifact)
        {
            return Err(Code::TemporarilyUnavailable);
        }
        let enrollment = &row.enrollment;
        let context = &enrollment.context;
        let mut receipt = Receipt::about(&trustee.component_id, context, "enroll");
        receipt.request_id = challenge.to_owned();
        receipt.old_state = "none".into();
        receipt.new_state = "active".into();
        receipt.recorded_at = time(row.stored_at)?;
        receipt.expires_at = time(enrollment.expires_at)?;
        receipt.artifact_id = Some(context.artifact_id.clone());
        receipt.artifact_digest = Some(context.artifact_digest.clone());
        receipt.slot = Some(context.slot.clone());
        receipt.sealed_contribution_digest = Some(wire::digest(sealed));
        receipt.storage_class = Some(wire::STORAGE_CLASS);
        Ok(wire::sign_object(&receipt, &trustee.signing_key))
    }

    /// The holder's poll: enrollment state and every session of the current
    /// sequence, so a healthy device sees a recovery attempt in time to veto.
    fn read_enrollment(
        &mut self,
        trustee: &Trustee,
        signed: Signed,
        now: i64,
    ) -> Result<Vec<u8>, Code> {
        let (tx, _) = self.transaction(now)?;
        let row = load_current_enrollment(&tx, &signed.target)?.ok_or(Code::InvalidRequest)?;
        let enrollment = &row.enrollment;
        verify_signature(&signed, &enrollment.authorization_key)?;
        check_fresh(&signed, trustee, now)?;
        spend_nonce(&tx, &Scope::enrollment(enrollment), &signed, trustee, now)?;
        let sessions = load_sessions(&tx, enrollment)?
            .into_iter()
            .map(|session| {
                Ok(Notice {
                    state: wire::session_state(
                        session.status,
                        session.cooldown_ends_at,
                        session.expires_at,
                        now,
                    ),
                    reason: wire::session_reason(session.status),
                    released: session.contribution.is_some(),
                    session_id: session.session_id,
                    cooldown_ends_at: time(session.cooldown_ends_at)?,
                    expires_at: time(session.expires_at)?,
                })
            })
            .collect::<Result<Vec<_>, Code>>()?;
        tx.commit()?;

        let state = wire::enrollment_state(row.status, enrollment.expires_at, now);
        let mut receipt = Receipt::about(
            &trustee.component_id,
            &enrollment.context,
            "read-enrollment",
        );
        receipt.request_id = signed.request_id;
        receipt.old_state = state.into();
        receipt.new_state = state.into();
        receipt.recorded_at = time(now)?;
        receipt.expires_at = time(enrollment.expires_at)?;
        receipt.sessions = Some(sessions);
        Ok(wire::sign_object(&receipt, &trustee.signing_key))
    }

    fn begin_recovery(
        &mut self,
        trustee: &Trustee,
        request: Value,
        now: i64,
    ) -> Result<Vec<u8>, Code> {
        let request =
            wire::BeginRequest::deserialize(&request).map_err(|_| Code::InvalidRequest)?;
        if request.request_version != 1 {
            return Err(Code::InvalidRequest);
        }
        // Verified before any lookup, so the answer cannot reveal an enrollment.
        let session = trustee.verify_session(&wire::canonical(&request.session))?;

        let (tx, _) = self.transaction(now)?;
        // The session ID is the request ID: a retry gets the recorded outcome
        // and spends no attempt.
        if let Some(recorded) = load_session(&tx, &session.session_id)? {
            drop(tx);
            if recorded.request != session.canonical {
                return Err(Code::RequestConflict);
            }
            return self.session_receipt(trustee, &session.session_id);
        }
        let row = load_current_enrollment(&tx, &session.enrollment_id)?
            .filter(|row| session.binds(&row.enrollment.context))
            .ok_or(Code::InvalidRequest)?;
        let enrollment = &row.enrollment;
        let admission = state::admit(
            &row.state(),
            &enrollment.policy,
            row.attempts_used,
            session.requested_at,
            session.expires_at,
            now,
            trustee.limits.skew_secs,
        )?;
        // From here the request is an attempt, whether the factor holds or not.
        let status = match trustee.check_factor(enrollment, &session) {
            Ok(()) => SessionStatus::CoolingDown,
            Err(_) => SessionStatus::Refused,
        };
        let context = &enrollment.context;
        tx.execute(
            "UPDATE enrollments SET attempts_used = attempts_used + 1
             WHERE enrollment_id = ?1 AND sequence = ?2",
            params![context.enrollment_id, context.enrollment_sequence],
        )?;
        tx.execute(
            "INSERT INTO sessions (session_id, enrollment_id, sequence, status, request, proof_key,
                                   destination_keys_digest, cooldown_ends_at, expires_at,
                                   remaining_attempts, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
            params![
                session.session_id,
                context.enrollment_id,
                context.enrollment_sequence,
                status.name(),
                session.canonical,
                session.proof_key,
                session.destination_keys_digest,
                admission.cooldown_ends_at,
                admission.expires_at,
                enrollment.policy.maximum_attempts - row.attempts_used - 1,
                now
            ],
        )?;
        tx.commit()?;
        self.session_receipt(trustee, &session.session_id)
    }

    /// The recorded outcome of `begin-recovery`, rebuilt from its row: a
    /// session cooling down, or one refused for its factor. Both spent an
    /// attempt, so both are signed.
    fn session_receipt(&self, trustee: &Trustee, session_id: &str) -> Result<Vec<u8>, Code> {
        let session =
            load_session(&self.connection, session_id)?.ok_or(Code::TemporarilyUnavailable)?;
        let row = session.enrollment(&self.connection)?;
        let mut receipt = session.receipt(trustee, &row.enrollment, "begin-recovery")?;
        receipt.request_id = session_id.to_owned();
        receipt.old_state = "none".into();
        // What begin decided, never what happened later: retries are identical.
        let refused = session.status == SessionStatus::Refused;
        receipt.new_state = if refused { "refused" } else { "cooling_down" }.into();
        receipt.reason = wire::session_reason(session.status).filter(|_| refused);
        receipt.recorded_at = time(session.created_at)?;
        receipt.remaining_attempts = Some(session.remaining_attempts);
        receipt.evidence_digest = Some(wire::digest(&session.request));
        Ok(wire::sign_object(&receipt, &trustee.signing_key))
    }

    /// The candidate's poll. The first read after the release predicate holds
    /// seals, persists and returns this slot's contribution; later reads
    /// resend the same bytes until a terminal state or expiry.
    fn read_recovery(
        &mut self,
        trustee: &Trustee,
        signed: Signed,
        now: i64,
    ) -> Result<Vec<u8>, Code> {
        let (tx, floor) = self.transaction(now)?;
        let session = load_session(&tx, &signed.target)?.ok_or(Code::InvalidRequest)?;
        verify_signature(&signed, &session.proof_key)?;
        check_fresh(&signed, trustee, now)?;
        spend_nonce(&tx, &Scope::session(&signed.target), &signed, trustee, now)?;
        let row = session.enrollment(&tx)?;

        let old_state = wire::session_state(
            session.status,
            session.cooldown_ends_at,
            session.expires_at,
            now,
        );
        let mut status = session.status;
        let contribution = match state::release(&row.state(), &session.state(), now, floor) {
            Ok(Release::Emit) => {
                let sealed = row
                    .sealed_envelope
                    .as_deref()
                    .ok_or(Code::TemporarilyUnavailable)?;
                let verified = trustee
                    .verify_session(&session.request)
                    .map_err(|_| Code::TemporarilyUnavailable)?;
                let contribution = trustee
                    .release(&row.enrollment, sealed, &verified, now)?
                    .canonical;
                tx.execute(
                    "UPDATE sessions SET status = 'released', contribution = ?2 WHERE session_id = ?1",
                    params![signed.target, contribution],
                )?;
                status = SessionStatus::Released;
                Some(contribution)
            }
            Ok(Release::Resend) => session.contribution.clone(),
            // Not releasable: report the state and hand out nothing.
            Err(
                Code::RecoveryCoolingDown
                | Code::RecoveryVetoed
                | Code::RecoveryRefused
                | Code::RecoveryExpired,
            ) => None,
            Err(code) => return Err(code),
        };
        tx.commit()?;

        let new_state =
            wire::session_state(status, session.cooldown_ends_at, session.expires_at, now);
        let mut receipt = session.receipt(trustee, &row.enrollment, "read-recovery")?;
        receipt.request_id = signed.request_id;
        receipt.old_state = old_state.into();
        receipt.new_state = new_state.into();
        receipt.reason = wire::session_reason(status);
        receipt.recorded_at = time(now)?;
        receipt.contribution = contribution
            .map(|bytes| wire::parse(&bytes).ok_or(Code::TemporarilyUnavailable))
            .transpose()?;
        Ok(wire::sign_object(&receipt, &trustee.signing_key))
    }

    /// Candidate cancellation (proof key) or holder veto (authorization key).
    /// Either stops any later release; neither can recall one delivered.
    fn cancel_recovery(
        &mut self,
        trustee: &Trustee,
        signed: Signed,
        now: i64,
    ) -> Result<Vec<u8>, Code> {
        let by_holder = match signed.by.as_deref() {
            Some("holder") => true,
            Some("candidate") => false,
            _ => return Err(Code::InvalidRequest),
        };
        let scope = Scope::session(&signed.target);
        let (tx, _) = self.transaction(now)?;
        let session = load_session(&tx, &signed.target)?.ok_or(Code::InvalidRequest)?;
        let row = session.enrollment(&tx)?;
        let key = if by_holder {
            row.enrollment.authorization_key
        } else {
            session.proof_key
        };
        verify_signature(&signed, &key)?;
        if let Some(digest) = recorded_outcome(&tx, &scope, &signed)? {
            drop(tx);
            return self.replayed_outcome(trustee, &scope, &signed, &digest);
        }
        check_fresh(&signed, trustee, now)?;

        let live = matches!(
            session.status,
            SessionStatus::CoolingDown | SessionStatus::Released
        ) && now < session.expires_at;
        let status = match (live, by_holder) {
            (true, true) => SessionStatus::Vetoed,
            (true, false) => SessionStatus::Cancelled,
            (false, _) => session.status,
        };
        tx.execute(
            "UPDATE sessions SET status = ?2 WHERE session_id = ?1",
            params![signed.target, status.name()],
        )?;
        let state =
            |status| wire::session_state(status, session.cooldown_ends_at, session.expires_at, now);
        record_outcome(
            &tx,
            &scope,
            &signed,
            state(session.status),
            state(status),
            now,
        )?;
        tx.commit()?;
        self.outcome_receipt(trustee, &scope, &signed.request_id)
    }

    /// `revoke-enrollment` and `close-enrollment`: leave a tombstone that
    /// keeps the bindings and deletes the custody.
    fn end_enrollment(
        &mut self,
        trustee: &Trustee,
        signed: Signed,
        now: i64,
    ) -> Result<Vec<u8>, Code> {
        let (tx, _) = self.transaction(now)?;
        let row = load_current_enrollment(&tx, &signed.target)?.ok_or(Code::InvalidRequest)?;
        let enrollment = &row.enrollment;
        let scope = Scope::enrollment(enrollment);
        verify_signature(&signed, &enrollment.authorization_key)?;
        if let Some(digest) = recorded_outcome(&tx, &scope, &signed)? {
            drop(tx);
            return self.replayed_outcome(trustee, &scope, &signed, &digest);
        }
        check_fresh(&signed, trustee, now)?;

        let status = match (signed.operation.as_str(), row.status) {
            ("close-enrollment", _) | (_, EnrollmentStatus::Closed) => EnrollmentStatus::Closed,
            _ => EnrollmentStatus::Revoked,
        };
        let context = &enrollment.context;
        tx.execute(
            "UPDATE enrollments SET status = ?3, sealed_envelope = NULL, protected_artifact = NULL
             WHERE enrollment_id = ?1 AND sequence = ?2",
            params![
                context.enrollment_id,
                context.enrollment_sequence,
                status.name()
            ],
        )?;
        let state = |status| wire::enrollment_state(status, enrollment.expires_at, now);
        record_outcome(&tx, &scope, &signed, state(row.status), state(status), now)?;
        tx.commit()?;
        // Best effort: move the deletion into the database file and empty the
        // WAL, which still holds the enrolled pages. Freed disk blocks remain.
        let _ = self
            .connection
            .query_row("PRAGMA wal_checkpoint(TRUNCATE)", [], |_| Ok(()));
        self.outcome_receipt(trustee, &scope, &signed.request_id)
    }

    /// An identical retry gets the recorded receipt, however late it comes;
    /// a changed body under the same request ID is a conflict.
    fn replayed_outcome(
        &self,
        trustee: &Trustee,
        scope: &Scope,
        signed: &Signed,
        recorded_digest: &str,
    ) -> Result<Vec<u8>, Code> {
        if recorded_digest != signed.digest {
            return Err(Code::RequestConflict);
        }
        self.outcome_receipt(trustee, scope, &signed.request_id)
    }

    /// The receipt of a recorded state change, rebuilt from its outcome row.
    fn outcome_receipt(
        &self,
        trustee: &Trustee,
        scope: &Scope,
        request_id: &str,
    ) -> Result<Vec<u8>, Code> {
        let (operation, old_state, new_state, recorded_at): (String, String, String, i64) =
            self.connection.query_row(
                "SELECT operation, old_state, new_state, recorded_at FROM outcomes
                 WHERE scope = ?1 AND request_id = ?2",
                params![scope.key(), request_id],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
            )?;
        let mut receipt = match scope {
            Scope::Session(session_id) => {
                let session = load_session(&self.connection, session_id)?
                    .ok_or(Code::TemporarilyUnavailable)?;
                let row = session.enrollment(&self.connection)?;
                let mut receipt = session.receipt(trustee, &row.enrollment, &operation)?;
                // Terminal once recorded, so a retry signs the same reason.
                receipt.reason = wire::session_reason(session.status);
                receipt
            }
            Scope::Enrollment(enrollment_id, sequence) => {
                let row = load_enrollment(&self.connection, enrollment_id, *sequence)?;
                let mut receipt =
                    Receipt::about(&trustee.component_id, &row.enrollment.context, &operation);
                receipt.expires_at = time(row.enrollment.expires_at)?;
                receipt
            }
        };
        receipt.request_id = request_id.to_owned();
        receipt.old_state = old_state;
        receipt.new_state = new_state;
        receipt.recorded_at = time(recorded_at)?;
        Ok(wire::sign_object(&receipt, &trustee.signing_key))
    }
}

// ---------------------------------------------------------------------------
// Rows

struct EnrollmentRow {
    enrollment: Enrollment,
    status: EnrollmentStatus,
    attempts_used: u32,
    stored_at: i64,
    sealed_envelope: Option<Vec<u8>>,
    protected_artifact: Option<Vec<u8>>,
}

impl EnrollmentRow {
    const COLUMNS: &str =
        "record, status, attempts_used, stored_at, sealed_envelope, protected_artifact";

    fn read(row: &Row) -> rusqlite::Result<EnrollmentRow> {
        let record: String = row.get(0)?;
        Ok(EnrollmentRow {
            enrollment: serde_json::from_str(&record).map_err(|error| {
                rusqlite::Error::FromSqlConversionFailure(0, Type::Text, error.into())
            })?,
            status: EnrollmentStatus::from_name(&row.get::<_, String>(1)?)
                .ok_or_else(|| invalid(1))?,
            attempts_used: row.get(2)?,
            stored_at: row.get(3)?,
            sealed_envelope: row.get(4)?,
            protected_artifact: row.get(5)?,
        })
    }

    fn state(&self) -> EnrollmentState {
        EnrollmentState {
            status: self.status,
            sequence: self.enrollment.context.enrollment_sequence,
            expires_at: self.enrollment.expires_at,
        }
    }
}

struct SessionRow {
    session_id: String,
    enrollment_id: String,
    sequence: u64,
    status: SessionStatus,
    request: Vec<u8>,
    proof_key: [u8; 32],
    destination_keys_digest: String,
    cooldown_ends_at: i64,
    expires_at: i64,
    remaining_attempts: u32,
    created_at: i64,
    contribution: Option<Vec<u8>>,
}

impl SessionRow {
    const COLUMNS: &str = "session_id, enrollment_id, sequence, status, request, proof_key,
        destination_keys_digest, cooldown_ends_at, expires_at, remaining_attempts, created_at,
        contribution";

    fn read(row: &Row) -> rusqlite::Result<SessionRow> {
        Ok(SessionRow {
            session_id: row.get(0)?,
            enrollment_id: row.get(1)?,
            sequence: row.get(2)?,
            status: SessionStatus::from_name(&row.get::<_, String>(3)?)
                .ok_or_else(|| invalid(3))?,
            request: row.get(4)?,
            proof_key: row.get(5)?,
            destination_keys_digest: row.get(6)?,
            cooldown_ends_at: row.get(7)?,
            expires_at: row.get(8)?,
            remaining_attempts: row.get(9)?,
            created_at: row.get(10)?,
            contribution: row.get(11)?,
        })
    }

    fn state(&self) -> SessionState {
        SessionState {
            status: self.status,
            sequence: self.sequence,
            cooldown_ends_at: self.cooldown_ends_at,
            expires_at: self.expires_at,
        }
    }

    /// The enrollment sequence this session was admitted under.
    fn enrollment(&self, connection: &Connection) -> Result<EnrollmentRow, Code> {
        load_enrollment(connection, &self.enrollment_id, self.sequence)
    }

    /// The fields every receipt about this session carries.
    fn receipt(
        &self,
        trustee: &Trustee,
        enrollment: &Enrollment,
        operation: &str,
    ) -> Result<Receipt, Code> {
        let mut receipt = Receipt::about(&trustee.component_id, &enrollment.context, operation);
        receipt.session_id = Some(self.session_id.clone());
        receipt.expires_at = time(self.expires_at)?;
        receipt.cooldown_ends_at = Some(time(self.cooldown_ends_at)?);
        receipt.destination_keys_digest = Some(self.destination_keys_digest.clone());
        Ok(receipt)
    }
}

fn load_enrollment(
    connection: &Connection,
    enrollment_id: &str,
    sequence: u64,
) -> Result<EnrollmentRow, Code> {
    let query = format!(
        "SELECT {} FROM enrollments WHERE enrollment_id = ?1 AND sequence = ?2",
        EnrollmentRow::COLUMNS
    );
    Ok(connection.query_row(
        &query,
        params![enrollment_id, sequence],
        EnrollmentRow::read,
    )?)
}

/// The highest sequence stored for an enrollment ID, tombstones included.
fn load_current_enrollment(
    connection: &Connection,
    enrollment_id: &str,
) -> rusqlite::Result<Option<EnrollmentRow>> {
    connection
        .query_row(
            &format!(
                "SELECT {} FROM enrollments WHERE enrollment_id = ?1 ORDER BY sequence DESC LIMIT 1",
                EnrollmentRow::COLUMNS
            ),
            [enrollment_id],
            EnrollmentRow::read,
        )
        .optional()
}

fn load_session(connection: &Connection, session_id: &str) -> rusqlite::Result<Option<SessionRow>> {
    connection
        .query_row(
            &format!(
                "SELECT {} FROM sessions WHERE session_id = ?1",
                SessionRow::COLUMNS
            ),
            [session_id],
            SessionRow::read,
        )
        .optional()
}

fn load_sessions(
    connection: &Connection,
    enrollment: &Enrollment,
) -> rusqlite::Result<Vec<SessionRow>> {
    let context = &enrollment.context;
    let mut statement = connection.prepare(&format!(
        "SELECT {} FROM sessions WHERE enrollment_id = ?1 AND sequence = ?2
         ORDER BY created_at, session_id",
        SessionRow::COLUMNS
    ))?;
    let rows = statement.query_map(
        params![context.enrollment_id, context.enrollment_sequence],
        SessionRow::read,
    )?;
    rows.collect()
}

/// Mark a challenge and its invitation used.
fn spend_challenge(
    tx: &Transaction,
    challenge: &str,
    invitation: &str,
    now: i64,
) -> rusqlite::Result<()> {
    tx.execute(
        "UPDATE challenges SET used_at = ?2 WHERE challenge = ?1",
        params![challenge, now],
    )?;
    tx.execute(
        "UPDATE invitations SET used_at = ?2 WHERE digest = ?1",
        params![invitation, now],
    )?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Signed requests: signature, freshness, replay, idempotency

/// What a signed request acts on: one enrollment sequence or one session.
/// Its key namespaces nonces and outcomes.
enum Scope {
    Enrollment(String, u64),
    Session(String),
}

impl Scope {
    fn enrollment(enrollment: &Enrollment) -> Scope {
        let context = &enrollment.context;
        Scope::Enrollment(context.enrollment_id.clone(), context.enrollment_sequence)
    }

    fn session(session_id: &str) -> Scope {
        Scope::Session(session_id.to_owned())
    }

    fn key(&self) -> String {
        match self {
            Scope::Enrollment(id, sequence) => format!("enrollment:{id}:{sequence}"),
            Scope::Session(id) => format!("session:{id}"),
        }
    }
}

fn verify_signature(signed: &Signed, key: &[u8; 32]) -> Result<(), Code> {
    crypto::verify(key, &signed.message, &signed.signature).map_err(|_| Code::InvalidRequest)
}

/// First acceptance only: a recorded outcome answers retries at any age.
fn check_fresh(signed: &Signed, trustee: &Trustee, now: i64) -> Result<(), Code> {
    if (signed.issued_at - now).abs() > trustee.limits.skew_secs {
        return Err(Code::InvalidRequest);
    }
    Ok(())
}

/// Reads are single use within the freshness window. Nonces older than
/// twice the skew are purged; by then `issuedAt` alone refuses a replay.
fn spend_nonce(
    tx: &Transaction,
    scope: &Scope,
    signed: &Signed,
    trustee: &Trustee,
    now: i64,
) -> Result<(), Code> {
    tx.execute(
        "DELETE FROM nonces WHERE seen_at < ?1",
        [now - 2 * trustee.limits.skew_secs],
    )?;
    let inserted = tx.execute(
        "INSERT OR IGNORE INTO nonces (scope, request_id, seen_at) VALUES (?1, ?2, ?3)",
        params![scope.key(), signed.request_id, now],
    )?;
    if inserted == 0 {
        return Err(Code::InvalidRequest);
    }
    Ok(())
}

/// The request digest recorded under this request ID, if any.
fn recorded_outcome(
    tx: &Transaction,
    scope: &Scope,
    signed: &Signed,
) -> rusqlite::Result<Option<String>> {
    tx.query_row(
        "SELECT request_digest FROM outcomes WHERE scope = ?1 AND request_id = ?2",
        params![scope.key(), signed.request_id],
        |row| row.get(0),
    )
    .optional()
}

fn record_outcome(
    tx: &Transaction,
    scope: &Scope,
    signed: &Signed,
    old_state: &str,
    new_state: &str,
    now: i64,
) -> rusqlite::Result<()> {
    tx.execute(
        "INSERT INTO outcomes (scope, request_id, request_digest, operation, old_state, new_state,
                               recorded_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        params![
            scope.key(),
            signed.request_id,
            signed.digest,
            signed.operation,
            old_state,
            new_state,
            now
        ],
    )?;
    Ok(())
}

// ---------------------------------------------------------------------------

/// 256 bits from the OS, through an interface that can fail cleanly.
fn random_id() -> Result<String, Code> {
    let mut bytes = [0u8; 32];
    getrandom::fill(&mut bytes).map_err(|_| Code::TemporarilyUnavailable)?;
    Ok(hex::encode(bytes))
}

fn time(unix_seconds: i64) -> Result<String, Code> {
    wire::format_timestamp(unix_seconds).ok_or(Code::TemporarilyUnavailable)
}

fn invalid(column: usize) -> rusqlite::Error {
    rusqlite::Error::InvalidColumnType(column, "unknown state".into(), Type::Text)
}
