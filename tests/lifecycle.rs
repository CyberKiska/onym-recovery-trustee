//! The durable lifecycle, end to end through `Store::handle`: enrollment by
//! invitation and challenge, recovery with a cooldown, holder veto,
//! tombstones, retries and replays, restarts and concurrent writers.
//!
//! Requests reuse the pinned binding fixtures, re-signed where a test needs
//! a store-issued challenge or a fresh session. Test keys only.

use std::path::PathBuf;
use std::sync::Barrier;
use std::sync::atomic::{AtomicUsize, Ordering};

use base64::{Engine as _, engine::general_purpose::STANDARD};
use ed25519_dalek::SigningKey;
use onym_recovery_trustee::store::Store;
use onym_recovery_trustee::wire::{self, Code, EnrollmentContext};
use onym_recovery_trustee::{Limits, Trustee, crypto};
use serde_json::{Value, json};

const DAY: i64 = 86_400;
const COMPONENT: &str = "onym:component:reference-trustee";
const ENROLLED_AT: &str = "2026-09-23T12:00:00Z";
/// The fixture session's `requestedAt`; its cooldown is two days.
const BEGUN_AT: &str = "2026-10-01T00:00:00Z";
const COOLDOWN_ENDS_AT: &str = "2026-10-03T00:00:00Z";
const RELEASED_AT: &str = "2026-10-03T12:00:00Z";

fn at(text: &str) -> i64 {
    wire::timestamp(text).unwrap()
}

fn later(text: &str, seconds: i64) -> String {
    wire::format_timestamp(at(text) + seconds).unwrap()
}

fn fixture(path: &str) -> Value {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(path);
    wire::parse(&std::fs::read(path).unwrap()).unwrap()
}

fn holder() -> SigningKey {
    SigningKey::from_bytes(&[0x11; 32])
}

fn factor() -> SigningKey {
    SigningKey::from_bytes(&[0x22; 32])
}

fn proof() -> SigningKey {
    SigningKey::from_bytes(&[0x66; 32])
}

fn impostor() -> SigningKey {
    SigningKey::from_bytes(&[0x77; 32])
}

fn trustee() -> Trustee {
    Trustee {
        component_id: COMPONENT.to_owned(),
        hpke_key: crypto::hpke_private_key(&[0x44; 32]).unwrap(),
        signing_key: SigningKey::from_bytes(&[0x33; 32]),
        limits: Limits {
            skew_secs: 300,
            min_cooldown_secs: 60,
            max_cooldown_secs: 30 * DAY,
            max_session_lifetime_secs: 30 * DAY,
            max_attempts: 10,
            max_enrollment_term_secs: 2 * 365 * DAY,
            max_artifact_bytes: 64 * 1024,
        },
    }
}

/// Sign `value` over its canonical bytes into `field`.
fn sign(value: &mut Value, field: &str, key: &SigningKey) {
    let signature = crypto::sign(key, &wire::canonical(value));
    value[field] = json!(STANDARD.encode(signature));
}

fn session_id(n: u8) -> String {
    hex::encode([n; 32])
}

// ---------------------------------------------------------------------------
// Requests

/// The pinned envelope, re-signed for `challenge`, and its context.
fn envelope(challenge: &str) -> (Vec<u8>, EnrollmentContext) {
    envelope_by(&holder(), challenge)
}

/// The pinned envelope with `key` as its authorization key.
fn envelope_by(key: &SigningKey, challenge: &str) -> (Vec<u8>, EnrollmentContext) {
    let public = key.verifying_key().to_bytes();
    let mut envelope = fixture("binding/envelope.json");
    envelope
        .as_object_mut()
        .unwrap()
        .remove("holderAuthorization");
    envelope["trusteeChallenge"] = json!(challenge);
    envelope["authorizationPublicKey"] = json!(hex::encode(public));
    sign(&mut envelope, "holderAuthorization", key);
    let mut context = fixture("binding/enrollment.json")["context"].clone();
    context["trusteeChallenge"] = json!(challenge);
    context["authorizationKeyDigest"] = json!(wire::key_digest(&public));
    (
        wire::canonical(&envelope),
        serde_json::from_value(context).unwrap(),
    )
}

/// A freshly sealed enrollment request; each call seals anew.
fn enroll_request(challenge: &str) -> Vec<u8> {
    enroll_request_by(&holder(), challenge)
}

fn enroll_request_by(key: &SigningKey, challenge: &str) -> Vec<u8> {
    let (envelope, context) = envelope_by(key, challenge);
    let trustee = trustee();
    let sealed = crypto::seal(&trustee.hpke_public_key(), &context.info(), &envelope).unwrap();
    wire::canonical(&json!({
        "requestVersion": 1,
        "operation": "enroll",
        "context": context,
        "trusteeKeyId": trustee.key_id(),
        "sealedEnvelope": STANDARD.encode(sealed),
        "protectedArtifact": fixture("binding/protected-artifact.json"),
    }))
}

/// This trustee's variant of a session, its evidence signed by `signer`.
fn begin_request(id: &str, signer: &SigningKey, edit: fn(&mut Value)) -> Vec<u8> {
    let mut session = fixture("binding/session.json");
    let fields = session.as_object_mut().unwrap();
    fields.remove("candidateProof");
    fields.remove("candidateEvidence");
    session["sessionId"] = json!(id);
    edit(&mut session);
    let context = fixture("binding/enrollment.json")["context"].clone();
    let commitment = wire::digest(&wire::canonical(&session));
    let message = wire::factor_message(&commitment, COMPONENT, context["slot"].as_str().unwrap());
    session["candidateEvidence"] = json!([{
        "factor": format!("{}{}", wire::FACTOR_ED25519_SESSION, hex::encode(factor().verifying_key().to_bytes())),
        "signature": STANDARD.encode(crypto::sign(signer, &message)),
    }]);
    sign(&mut session, "candidateProof", &proof());
    wire::canonical(
        &json!({"requestVersion": 1, "operation": "begin-recovery", "session": session}),
    )
}

fn begin(id: &str) -> Vec<u8> {
    begin_request(id, &factor(), |_| {})
}

/// A signed request acting on `target`: `("enrollmentId" | "sessionId", id)`.
fn signed(
    operation: &str,
    target: (&str, &str),
    by: Option<&str>,
    key: &SigningKey,
    request: u8,
    issued_at: &str,
) -> Vec<u8> {
    let mut value = json!({
        "requestVersion": 1,
        "operation": operation,
        "requestId": hex::encode([request; 32]),
        "componentId": COMPONENT,
        "issuedAt": issued_at,
    });
    value[target.0] = json!(target.1);
    if let Some(by) = by {
        value["by"] = json!(by);
    }
    sign(&mut value, "signature", key);
    wire::canonical(&value)
}

fn enrollment_id() -> String {
    "e1".repeat(32)
}

fn read_enrollment(request: u8, issued_at: &str) -> Vec<u8> {
    signed(
        "read-enrollment",
        ("enrollmentId", &enrollment_id()),
        None,
        &holder(),
        request,
        issued_at,
    )
}

fn read_recovery(session: &str, request: u8, issued_at: &str) -> Vec<u8> {
    signed(
        "read-recovery",
        ("sessionId", session),
        None,
        &proof(),
        request,
        issued_at,
    )
}

fn veto(session: &str, request: u8, issued_at: &str) -> Vec<u8> {
    signed(
        "cancel-recovery",
        ("sessionId", session),
        Some("holder"),
        &holder(),
        request,
        issued_at,
    )
}

fn close(request: u8, issued_at: &str) -> Vec<u8> {
    signed(
        "close-enrollment",
        ("enrollmentId", &enrollment_id()),
        None,
        &holder(),
        request,
        issued_at,
    )
}

/// Open a released contribution with the destination key: the envelope.
fn released_envelope(contribution: &Value, context: &EnrollmentContext) -> Vec<u8> {
    let text = |field: &str| contribution[field].as_str().unwrap();
    let info = wire::recovery_info(
        text("sessionId"),
        context,
        text("destinationKeysDigest"),
        text("expiresAt"),
    );
    let sealed = STANDARD.decode(text("sealedContribution")).unwrap();
    let destination = crypto::hpke_private_key(&[0x55; 32]).unwrap();
    crypto::open(&destination, &info, &sealed).unwrap().to_vec()
}

// ---------------------------------------------------------------------------
// Harness

struct Harness {
    store: Store,
    trustee: Trustee,
}

impl Harness {
    fn new() -> Harness {
        Harness::with(Store::open_in_memory().unwrap())
    }

    fn with(store: Store) -> Harness {
        Harness {
            store,
            trustee: trustee(),
        }
    }

    fn raw(&mut self, body: &[u8], now: &str) -> Result<Vec<u8>, Code> {
        self.store.handle(&self.trustee, body, at(now))
    }

    /// A call whose receipt, if any, must carry the operator's signature.
    fn call(&mut self, body: &[u8], now: &str) -> Result<Value, Code> {
        let mut response = wire::parse(&self.raw(body, now)?).unwrap();
        if response.get("receiptVersion").is_some() {
            assert_signed_by_operator(&mut response);
        }
        Ok(response)
    }

    /// A challenge redeemed from a fresh invitation.
    fn challenge(&mut self, now: &str) -> String {
        let invitation = self.store.create_invitation(7 * DAY, at(now)).unwrap();
        self.redeem(&invitation, now).unwrap()
    }

    fn redeem(&mut self, invitation: &str, now: &str) -> Result<String, Code> {
        let request = json!({
            "requestVersion": 1,
            "operation": "issue-challenge",
            "componentId": COMPONENT,
            "invitation": invitation,
        });
        let response = self.call(&wire::canonical(&request), now)?;
        Ok(response["challenge"].as_str().unwrap().to_owned())
    }

    /// Enroll the pinned envelope; returns the request and its context.
    fn enroll(&mut self) -> (Vec<u8>, EnrollmentContext) {
        let challenge = self.challenge(ENROLLED_AT);
        let request = enroll_request(&challenge);
        self.call(&request, ENROLLED_AT).unwrap();
        (request, envelope(&challenge).1)
    }
}

fn assert_signed_by_operator(value: &mut Value) {
    let signature = value.as_object_mut().unwrap().remove("signature").unwrap();
    let signature: [u8; 64] = STANDARD
        .decode(signature.as_str().unwrap())
        .unwrap()
        .try_into()
        .unwrap();
    let operator = SigningKey::from_bytes(&[0x33; 32])
        .verifying_key()
        .to_bytes();
    assert_eq!(
        crypto::verify(&operator, &wire::canonical(value), &signature),
        Ok(())
    );
}

/// A database file removed with its WAL when dropped.
struct TempDb(PathBuf);

impl TempDb {
    fn new() -> TempDb {
        static NEXT: AtomicUsize = AtomicUsize::new(0);
        let name = format!(
            "onym-trustee-{}-{}.sqlite",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        );
        TempDb(std::env::temp_dir().join(name))
    }

    fn store(&self) -> Store {
        Store::open(&self.0).unwrap()
    }
}

impl Drop for TempDb {
    fn drop(&mut self) {
        for suffix in ["", "-wal", "-shm"] {
            let _ = std::fs::remove_file(format!("{}{suffix}", self.0.display()));
        }
    }
}

// ---------------------------------------------------------------------------
// Enrollment

#[test]
fn enrollment_needs_an_issued_unused_challenge() {
    let mut h = Harness::new();
    // A published key alone never creates custody.
    assert_eq!(
        h.raw(&enroll_request(&"c1".repeat(32)), ENROLLED_AT),
        Err(Code::InvalidEnrollment)
    );

    let invitation = h.store.create_invitation(7 * DAY, at(ENROLLED_AT)).unwrap();
    let challenge = h.redeem(&invitation, ENROLLED_AT).unwrap();
    let request = enroll_request(&challenge);
    let first = h.raw(&request, ENROLLED_AT).unwrap();

    let mut receipt = wire::parse(&first).unwrap();
    assert_signed_by_operator(&mut receipt);
    let sealed = STANDARD
        .decode(
            wire::parse(&request).unwrap()["sealedEnvelope"]
                .as_str()
                .unwrap(),
        )
        .unwrap();
    assert_eq!(receipt["operation"], "enroll");
    assert_eq!(receipt["requestId"], json!(challenge));
    assert_eq!(
        (receipt["oldState"].as_str(), receipt["newState"].as_str()),
        (Some("none"), Some("active"))
    );
    assert_eq!(
        receipt["sealedContributionDigest"],
        json!(wire::digest(&sealed))
    );
    assert_eq!(receipt["storageClass"], json!(wire::STORAGE_CLASS));
    assert_eq!(receipt["recordedAt"], json!(ENROLLED_AT));

    // An identical retry, a day later, gets the identical receipt; a
    // re-sealed request under the same challenge is a conflict.
    let next_day = later(ENROLLED_AT, DAY);
    assert_eq!(h.raw(&request, &next_day), Ok(first));
    assert_eq!(
        h.raw(&enroll_request(&challenge), &next_day),
        Err(Code::RequestConflict)
    );

    // The invitation is spent, and a challenge expires after 15 minutes.
    assert_eq!(h.redeem(&invitation, &next_day), Err(Code::InvalidRequest));
    let stale = h.challenge(&next_day);
    assert_eq!(
        h.raw(&enroll_request(&stale), &later(&next_day, 15 * 60)),
        Err(Code::InvalidEnrollment)
    );
}

#[test]
fn enrollment_state_is_told_only_to_its_holder() {
    let mut h = Harness::new();
    h.enroll();
    let now = later(ENROLLED_AT, 60);

    // An envelope that does not open looks the same for known and unknown IDs.
    let challenge = h.challenge(&now);
    for id in [enrollment_id(), "e2".repeat(32)] {
        let mut request = wire::parse(&enroll_request(&challenge)).unwrap();
        request["context"]["enrollmentId"] = json!(id);
        request["sealedEnvelope"] = json!(STANDARD.encode([0u8; 64]));
        let request = wire::canonical(&request);
        assert_eq!(h.raw(&request, &now), Err(Code::InvalidEnrollment));
    }

    // A valid envelope signed by another key gets the same refusal, and
    // spends the invitation as an enrollment would.
    let invitation = h.store.create_invitation(7 * DAY, at(&now)).unwrap();
    let challenge = h.redeem(&invitation, &now).unwrap();
    let request = enroll_request_by(&impostor(), &challenge);
    assert_eq!(h.raw(&request, &now), Err(Code::InvalidEnrollment));
    assert_eq!(h.raw(&request, &now), Err(Code::InvalidEnrollment));
    assert_eq!(h.redeem(&invitation, &now), Err(Code::InvalidRequest));

    // The holder's own key learns the state; after closure, nobody else.
    let challenge = h.challenge(&now);
    assert_eq!(
        h.raw(&enroll_request(&challenge), &now),
        Err(Code::StaleEnrollmentSequence)
    );
    h.call(&close(1, &now), &now).unwrap();
    let challenge = h.challenge(&now);
    assert_eq!(
        h.raw(&enroll_request_by(&impostor(), &challenge), &now),
        Err(Code::InvalidEnrollment)
    );
    let challenge = h.challenge(&now);
    assert_eq!(
        h.raw(&enroll_request(&challenge), &now),
        Err(Code::EnrollmentRevoked)
    );
}

#[test]
fn concurrent_enrollments_on_one_challenge_yield_one() {
    let db = TempDb::new();
    let challenge = Harness::with(db.store()).challenge(ENROLLED_AT);
    let barrier = Barrier::new(2);
    let outcomes: Vec<_> = std::thread::scope(|scope| {
        let workers: Vec<_> = (0..2)
            .map(|_| {
                scope.spawn(|| {
                    let mut h = Harness::with(db.store());
                    let request = enroll_request(&challenge);
                    barrier.wait();
                    h.raw(&request, ENROLLED_AT).map(|_| ())
                })
            })
            .collect();
        workers
            .into_iter()
            .map(|worker| worker.join().unwrap())
            .collect()
    });
    assert!(outcomes.contains(&Ok(())), "{outcomes:?}");
    assert!(
        outcomes.contains(&Err(Code::RequestConflict)),
        "{outcomes:?}"
    );

    let rows: i64 = rusqlite::Connection::open(&db.0)
        .unwrap()
        .query_row("SELECT count(*) FROM enrollments", [], |row| row.get(0))
        .unwrap();
    assert_eq!(rows, 1);
}

// ---------------------------------------------------------------------------
// Recovery

#[test]
fn a_restart_during_cooldown_keeps_the_deadline() {
    let db = TempDb::new();
    let session = session_id(0x5e);
    let context = {
        let mut h = Harness::with(db.store());
        let (_, context) = h.enroll();
        let receipt = h.call(&begin(&session), BEGUN_AT).unwrap();
        assert_eq!(receipt["newState"], "cooling_down");
        assert_eq!(receipt["cooldownEndsAt"], COOLDOWN_ENDS_AT);
        assert_eq!(receipt["remainingAttempts"], 2);
        context
    };

    // Reopened: the persisted deadline still holds.
    let mut h = Harness::with(db.store());
    let early = h
        .call(
            &read_recovery(&session, 1, &later(COOLDOWN_ENDS_AT, -1)),
            &later(COOLDOWN_ENDS_AT, -1),
        )
        .unwrap();
    assert_eq!(early["newState"], "cooling_down");
    assert_eq!(early["cooldownEndsAt"], COOLDOWN_ENDS_AT);
    assert!(early.get("contribution").is_none());

    // After it: this slot's contribution, carrying the enrolled envelope.
    let released = h
        .call(&read_recovery(&session, 2, RELEASED_AT), RELEASED_AT)
        .unwrap();
    let mut contribution = released["contribution"].clone();
    assert_eq!(
        released_envelope(&contribution, &context),
        envelope(&context.trustee_challenge).0
    );
    assert_signed_by_operator(&mut contribution);

    // Later reads resend the persisted bytes, not a new sealing.
    let again = h
        .call(
            &read_recovery(&session, 3, &later(RELEASED_AT, 60)),
            &later(RELEASED_AT, 60),
        )
        .unwrap();
    assert_eq!(again["contribution"], released["contribution"]);
    assert_eq!(again["newState"], "collecting");

    // The holder's poll says the contribution has left.
    let poll = h
        .call(
            &read_enrollment(4, &later(RELEASED_AT, 60)),
            &later(RELEASED_AT, 60),
        )
        .unwrap();
    assert_eq!(poll["sessions"][0]["state"], "collecting");
    assert_eq!(poll["sessions"][0]["released"], true);
}

#[test]
fn retries_replay_outcomes_and_reads_are_single_use() {
    let mut h = Harness::new();
    h.enroll();
    let session = session_id(0x5e);

    // begin-recovery: identical retry, an hour later, identical bytes and no
    // extra attempt; a different session under the same ID conflicts.
    let first = h.raw(&begin(&session), BEGUN_AT).unwrap();
    let hour = later(BEGUN_AT, 3_600);
    assert_eq!(h.raw(&begin(&session), &hour), Ok(first));
    let changed = begin_request(&session, &factor(), |s| {
        s["expiresAt"] = json!("2026-10-05T00:00:00Z")
    });
    assert_eq!(h.raw(&changed, &hour), Err(Code::RequestConflict));

    // Reads are single use, and stale ones are refused outright.
    let read = read_recovery(&session, 1, &hour);
    assert!(h.raw(&read, &hour).is_ok());
    assert_eq!(h.raw(&read, &hour), Err(Code::InvalidRequest));
    assert_eq!(h.raw(&read, &later(&hour, 601)), Err(Code::InvalidRequest));
    let old = read_recovery(&session, 2, &later(&hour, 700));
    assert_eq!(h.raw(&old, &later(&hour, 1_001)), Err(Code::InvalidRequest));

    // A state change: its retry after the nonce window returns the same
    // receipt; a different body under the same request ID conflicts.
    let cancel = signed(
        "cancel-recovery",
        ("sessionId", &session),
        Some("candidate"),
        &proof(),
        7,
        &hour,
    );
    let receipt = h.raw(&cancel, &later(&hour, 1_100)).unwrap_err();
    assert_eq!(
        receipt,
        Code::InvalidRequest,
        "a stale first request is refused"
    );
    let cancel = signed(
        "cancel-recovery",
        ("sessionId", &session),
        Some("candidate"),
        &proof(),
        7,
        &later(&hour, 1_200),
    );
    let recorded = h.raw(&cancel, &later(&hour, 1_200)).unwrap();
    assert_eq!(h.raw(&cancel, &later(&hour, 5 * 3_600)), Ok(recorded));
    let different = veto(&session, 7, &later(&hour, 5 * 3_600));
    assert_eq!(
        h.raw(&different, &later(&hour, 5 * 3_600)),
        Err(Code::RequestConflict)
    );
}

#[test]
fn a_holder_veto_blocks_release() {
    let mut h = Harness::new();
    h.enroll();
    let session = session_id(0x5e);
    h.call(&begin(&session), BEGUN_AT).unwrap();

    let during = later(BEGUN_AT, DAY);
    let vetoed = h.call(&veto(&session, 1, &during), &during).unwrap();
    assert_eq!(vetoed["operation"], "cancel-recovery");
    assert_eq!(
        (vetoed["oldState"].as_str(), vetoed["newState"].as_str()),
        (Some("cooling_down"), Some("cancelled"))
    );
    assert_eq!(vetoed["reason"], "recovery_vetoed");

    let read = h
        .call(&read_recovery(&session, 2, RELEASED_AT), RELEASED_AT)
        .unwrap();
    assert_eq!(read["newState"], "cancelled");
    assert_eq!(read["reason"], "recovery_vetoed");
    assert!(read.get("contribution").is_none());

    // The holder's poll shows the attempt and the veto.
    let poll = h
        .call(&read_enrollment(3, RELEASED_AT), RELEASED_AT)
        .unwrap();
    assert_eq!(poll["newState"], "active");
    assert_eq!(poll["sessions"][0]["sessionId"], json!(session));
    assert_eq!(poll["sessions"][0]["reason"], "recovery_vetoed");
    assert_eq!(poll["sessions"][0]["released"], false);
}

#[test]
fn veto_and_release_serialize() {
    for _ in 0..8 {
        let db = TempDb::new();
        let session = session_id(0x5e);
        {
            let mut h = Harness::with(db.store());
            h.enroll();
            h.call(&begin(&session), BEGUN_AT).unwrap();
        }
        let barrier = Barrier::new(2);
        let (read, veto) = std::thread::scope(|scope| {
            let reader = scope.spawn(|| {
                let mut h = Harness::with(db.store());
                barrier.wait();
                h.call(&read_recovery(&session, 1, RELEASED_AT), RELEASED_AT)
                    .unwrap()
            });
            let holder = scope.spawn(|| {
                let mut h = Harness::with(db.store());
                barrier.wait();
                h.call(&veto(&session, 2, RELEASED_AT), RELEASED_AT)
                    .unwrap()
            });
            (reader.join().unwrap(), holder.join().unwrap())
        });
        // Exactly one order happened: a release then a veto, or a veto that
        // left nothing to release. Never both, never neither.
        let released = read.get("contribution").is_some();
        assert_eq!(read["reason"] == "recovery_vetoed", !released, "{read}");
        assert_eq!(veto["newState"], "cancelled");

        // Either way nothing is handed out any more.
        let mut h = Harness::with(db.store());
        let after = h
            .call(
                &read_recovery(&session, 3, &later(RELEASED_AT, 1)),
                &later(RELEASED_AT, 1),
            )
            .unwrap();
        assert!(after.get("contribution").is_none());
    }
}

// ---------------------------------------------------------------------------
// Tombstones, attempts, clock

#[test]
fn tombstones_refuse_replays() {
    let db = TempDb::new();
    let mut h = Harness::with(db.store());
    let (enroll, _) = h.enroll();
    let session = session_id(0x5e);
    h.call(&begin(&session), BEGUN_AT).unwrap();

    let revoke = signed(
        "revoke-enrollment",
        ("enrollmentId", &enrollment_id()),
        None,
        &holder(),
        1,
        BEGUN_AT,
    );
    let revoked = h.call(&revoke, BEGUN_AT).unwrap();
    assert_eq!(
        (revoked["oldState"].as_str(), revoked["newState"].as_str()),
        (Some("active"), Some("revoked"))
    );
    let closed = h.call(&close(4, BEGUN_AT), BEGUN_AT).unwrap();
    assert_eq!(
        (closed["oldState"].as_str(), closed["newState"].as_str()),
        (Some("revoked"), Some("closed"))
    );

    // Gone from the live files too, the WAL included: the database is
    // checkpointed and `secure_delete` zeroes freed pages.
    let sealed = STANDARD
        .decode(
            wire::parse(&enroll).unwrap()["sealedEnvelope"]
                .as_str()
                .unwrap(),
        )
        .unwrap();
    for suffix in ["", "-wal"] {
        let bytes = std::fs::read(format!("{}{suffix}", db.0.display())).unwrap_or_default();
        let found = bytes.windows(64).any(|window| window == &sealed[..64]);
        assert!(!found, "sealed envelope left in the database{suffix} file");
    }

    let (sealed, artifact): (Option<Vec<u8>>, Option<Vec<u8>>) = rusqlite::Connection::open(&db.0)
        .unwrap()
        .query_row(
            "SELECT sealed_envelope, protected_artifact FROM enrollments",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap();
    assert_eq!((sealed, artifact), (None, None), "custody is deleted");

    let next = later(BEGUN_AT, 60);
    assert_eq!(h.raw(&enroll, &next), Err(Code::EnrollmentRevoked));
    let challenge = h.challenge(&next);
    assert_eq!(
        h.raw(&enroll_request(&challenge), &next),
        Err(Code::EnrollmentRevoked)
    );
    assert_eq!(
        h.raw(&read_recovery(&session, 2, RELEASED_AT), RELEASED_AT),
        Err(Code::EnrollmentRevoked)
    );
    let poll = h
        .call(&read_enrollment(3, RELEASED_AT), RELEASED_AT)
        .unwrap();
    assert_eq!(poll["newState"], "closed");
}

#[test]
fn attempts_are_bounded_and_counted_at_factor_evaluation() {
    let mut h = Harness::new();
    h.enroll();

    // A wrong factor spends an attempt and gets a signed refusal; its retry
    // replays the same bytes.
    let wrong = begin_request(&session_id(1), &impostor(), |_| {});
    let refusal = h.raw(&wrong, BEGUN_AT).unwrap();
    assert_eq!(h.raw(&wrong, BEGUN_AT), Ok(refusal.clone()));
    let refusal = h.call(&wrong, BEGUN_AT).unwrap();
    assert_eq!(
        (&refusal["newState"], &refusal["reason"]),
        (&json!("refused"), &json!("invalid_candidate_factor"))
    );
    assert_eq!(refusal["remainingAttempts"], 2);
    assert!(refusal["evidenceDigest"].is_string());

    // A session for another enrollment gets the uniform refusal and spends
    // nothing.
    let other = begin_request(&session_id(2), &factor(), |s| {
        s["enrollmentId"] = json!("e2".repeat(32))
    });
    assert_eq!(h.raw(&other, BEGUN_AT), Err(Code::InvalidRequest));

    // So does a fractional expiry, which would change the signed binding.
    let fractional = begin_request(&session_id(2), &factor(), |s| {
        s["expiresAt"] = json!("2026-10-05T00:00:00.5Z")
    });
    assert_eq!(h.raw(&fractional, BEGUN_AT), Err(Code::InvalidRequest));

    let second = h.call(&begin(&session_id(3)), BEGUN_AT).unwrap();
    assert_eq!(second["remainingAttempts"], 1);
    let third = h.call(&begin(&session_id(4)), BEGUN_AT).unwrap();
    assert_eq!(third["remainingAttempts"], 0);
    assert_eq!(
        h.raw(&begin(&session_id(5)), BEGUN_AT),
        Err(Code::RecoveryRateLimited)
    );

    let poll = h.call(&read_enrollment(1, BEGUN_AT), BEGUN_AT).unwrap();
    let states: Vec<_> = poll["sessions"]
        .as_array()
        .unwrap()
        .iter()
        .map(|s| (s["state"].clone(), s["reason"].clone()))
        .collect();
    assert_eq!(
        states,
        [
            (json!("refused"), json!("invalid_candidate_factor")),
            (json!("cooling_down"), Value::Null),
            (json!("cooling_down"), Value::Null),
        ]
    );
}

#[test]
fn requests_must_be_addressed_and_signed_correctly() {
    let mut h = Harness::new();
    h.enroll();
    let now = later(ENROLLED_AT, 60);

    // A clock behind the highest recorded time refuses every change.
    assert_eq!(
        h.raw(&read_enrollment(1, ENROLLED_AT), &later(ENROLLED_AT, -1)),
        Err(Code::TemporarilyUnavailable)
    );

    // Unknown enrollments and wrong keys look the same.
    let unknown = signed(
        "read-enrollment",
        ("enrollmentId", &"e2".repeat(32)),
        None,
        &holder(),
        2,
        &now,
    );
    let forged = signed(
        "read-enrollment",
        ("enrollmentId", &enrollment_id()),
        None,
        &impostor(),
        3,
        &now,
    );
    let elsewhere = {
        let mut value = wire::parse(&read_enrollment(4, &now)).unwrap();
        value.as_object_mut().unwrap().remove("signature");
        value["componentId"] = json!("onym:component:other");
        sign(&mut value, "signature", &holder());
        wire::canonical(&value)
    };
    for request in [unknown, forged, elsewhere] {
        assert_eq!(h.raw(&request, &now), Err(Code::InvalidRequest));
    }
    assert!(h.call(&read_enrollment(5, &now), &now).is_ok());

    let operation = |name: &str| wire::canonical(&json!({"requestVersion": 1, "operation": name}));
    assert_eq!(
        h.raw(&operation("bootstrap-recovery"), &now),
        Err(Code::BootstrapUnavailable)
    );
    assert_eq!(
        h.raw(&operation("export-enrollment"), &now),
        Err(Code::ExportUnavailable)
    );
    assert_eq!(
        h.raw(&operation("sign-anything"), &now),
        Err(Code::InvalidRequest)
    );
    assert_eq!(h.raw(b"not json", &now), Err(Code::InvalidRequest));
}

#[test]
fn an_unknown_schema_version_is_refused() {
    let db = TempDb::new();
    drop(db.store());
    rusqlite::Connection::open(&db.0)
        .unwrap()
        .execute_batch("PRAGMA user_version = 999")
        .unwrap();
    assert!(Store::open(&db.0).is_err());
}

#[test]
fn a_database_serves_one_trustee() {
    let db = TempDb::new();
    let mut store = db.store();
    assert_eq!(store.bind(&trustee()), Ok(true));
    assert_eq!(store.bind(&trustee()), Ok(true));

    // Another operator key, enrollment key or component is refused.
    let other_operator = Trustee {
        signing_key: impostor(),
        ..trustee()
    };
    let other_key = Trustee {
        hpke_key: crypto::hpke_private_key(&[0x45; 32]).unwrap(),
        ..trustee()
    };
    let other_component = Trustee {
        component_id: "onym:component:other".into(),
        ..trustee()
    };
    for other in [other_operator, other_key, other_component] {
        assert_eq!(db.store().bind(&other), Ok(false));
    }
}

#[test]
fn a_version_one_database_is_migrated() {
    let db = TempDb::new();
    drop(db.store());
    rusqlite::Connection::open(&db.0)
        .unwrap()
        .execute_batch("DROP TABLE identity; PRAGMA user_version = 1;")
        .unwrap();
    let mut store = db.store();
    assert_eq!(store.bind(&trustee()), Ok(true));
    let version: i64 = rusqlite::Connection::open(&db.0)
        .unwrap()
        .query_row("PRAGMA user_version", [], |row| row.get(0))
        .unwrap();
    assert_eq!(version, 2);
}
