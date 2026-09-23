//! Wire binding `draft-1`: canonical JSON, field encodings, digests, HPKE
//! `info` tuples and the objects a trustee reads or writes. Every byte-level
//! choice the recovery contracts leave open lives in this module, so revising
//! the binding means revising this file and regenerating the fixtures.

use std::fmt;

use base64::{Engine as _, engine::general_purpose::STANDARD};
use ed25519_dalek::SigningKey;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use time::{OffsetDateTime, format_description::well_known::Rfc3339};
use zeroize::Zeroize;

use crate::crypto;
use crate::state::{EnrollmentStatus, SessionStatus};

pub const BINDING_VERSION: &str = "draft-1";
pub const IMPLEMENTATION_PROFILE_ID: &str =
    "onym:recovery-implementation:shamir-trustees-slip39-v1";
/// The only recovery mode the identity profile supports today.
pub const RECOVERY_MODE: &str = "secret-restoration";
pub const ENCRYPTION_SUITE: &str = "hpke-base-x25519-hkdf-sha256-aes-256-gcm";
pub const PROOF_SUITE: &str = "ed25519";
pub const ARTIFACT_AEAD: &str = "aes-256-gcm";

// The proposed first factor and notification profile: the only values a
// trustee policy may carry under this binding.
pub const FACTOR_ED25519_SESSION: &str = "onym:recovery-factor:ed25519-session-v1:";
pub const NOTICE_HOLDER_POLL: &str = "onym:recovery-notice:holder-poll-v1";
pub const VETO_AUTHORIZATION_KEY: &str = "onym:recovery-veto:authorization-key-v1";
pub const LAPSE_NONE: &str = "onym:recovery-lapse:none-v1";

// Domain tags opening every canonical tuple. The recovery tag is the Shamir
// profile's own (§6.2); the others are this binding's.
const ENROLLMENT_INFO: &str = "onym-shamir-enrollment-v1";
const RECOVERY_INFO: &str = "onym-shamir-recovery-contribution-v1";
const DESTINATION_KEYS: &str = "onym-recovery-destination-keys-v1";
const FACTOR_EVIDENCE: &str = "onym-recovery-factor-ed25519-session-v1";

/// Largest integer every JSON implementation represents exactly.
const MAX_SAFE_INTEGER: u64 = (1 << 53) - 1;

/// Stable error codes: the abstract contract's §15 vocabulary plus two
/// binding-level codes. A code carries no data, so no secret can leak
/// through an error.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Code {
    UnsupportedProfile,
    InvalidManifest,
    InvalidPolicy,
    InvalidEnrollment,
    EnrollmentPending,
    EnrollmentExpired,
    EnrollmentRevoked,
    StaleEnrollmentSequence,
    ArtifactMismatch,
    InvalidDestination,
    BootstrapUnavailable,
    InvalidCandidateFactor,
    RecoveryCoolingDown,
    RecoveryRateLimited,
    RecoveryVetoed,
    RecoveryRefused,
    RecoveryExpired,
    InsufficientContributions,
    InvalidContribution,
    PaymentRequired,
    ServiceLapsed,
    ExportUnavailable,
    TemporarilyUnavailable,
    /// Malformed, unauthenticated or stale: the one uniform refusal.
    InvalidRequest,
    /// A request ID reused with a different body.
    RequestConflict,
}

impl Code {
    pub fn as_str(self) -> &'static str {
        match self {
            Code::UnsupportedProfile => "unsupported_profile",
            Code::InvalidManifest => "invalid_manifest",
            Code::InvalidPolicy => "invalid_policy",
            Code::InvalidEnrollment => "invalid_enrollment",
            Code::EnrollmentPending => "enrollment_pending",
            Code::EnrollmentExpired => "enrollment_expired",
            Code::EnrollmentRevoked => "enrollment_revoked",
            Code::StaleEnrollmentSequence => "stale_enrollment_sequence",
            Code::ArtifactMismatch => "artifact_mismatch",
            Code::InvalidDestination => "invalid_destination",
            Code::BootstrapUnavailable => "bootstrap_unavailable",
            Code::InvalidCandidateFactor => "invalid_candidate_factor",
            Code::RecoveryCoolingDown => "recovery_cooling_down",
            Code::RecoveryRateLimited => "recovery_rate_limited",
            Code::RecoveryVetoed => "recovery_vetoed",
            Code::RecoveryRefused => "recovery_refused",
            Code::RecoveryExpired => "recovery_expired",
            Code::InsufficientContributions => "insufficient_contributions",
            Code::InvalidContribution => "invalid_contribution",
            Code::PaymentRequired => "payment_required",
            Code::ServiceLapsed => "service_lapsed",
            Code::ExportUnavailable => "export_unavailable",
            Code::TemporarilyUnavailable => "temporarily_unavailable",
            Code::InvalidRequest => "invalid_request",
            Code::RequestConflict => "request_conflict",
        }
    }
}

impl fmt::Display for Code {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl std::error::Error for Code {}

// ---------------------------------------------------------------------------
// Canonical JSON (the Discovery §3 rules)

/// Parse a document whose top level is an object, refusing duplicate keys
/// at any depth; serde_json alone would keep the last one silently.
pub fn parse(raw: &[u8]) -> Option<Value> {
    reject_duplicate_keys(raw)?;
    serde_json::from_slice(raw).ok().filter(Value::is_object)
}

/// Compact bytes with object keys sorted by UTF-8 byte order at every level
/// (serde_json's `BTreeMap`; a test pins that no dependency turns on
/// `preserve_order`), arrays in order, and serde_json's minimal escaping.
pub fn canonical(value: &Value) -> Vec<u8> {
    serde_json::to_vec(value).expect("a JSON value always serializes")
}

/// `sha256:<lowercase hex>`, the one digest syntax of the binding.
pub fn digest(bytes: &[u8]) -> String {
    format!("sha256:{}", hex::encode(crypto::sha256(bytes)))
}

/// Remove a top-level field structurally (never by string surgery).
pub(crate) fn take(value: &mut Value, field: &str) -> Option<Value> {
    value.as_object_mut()?.remove(field)
}

pub(crate) fn take_string(value: &mut Value, field: &str) -> Option<String> {
    match take(value, field)? {
        Value::String(text) => Some(text),
        _ => None,
    }
}

fn reject_duplicate_keys(raw: &[u8]) -> Option<()> {
    use serde::de::{DeserializeSeed, Deserializer, MapAccess, SeqAccess, Visitor};

    struct Unique;

    impl<'de> DeserializeSeed<'de> for Unique {
        type Value = ();
        fn deserialize<D: Deserializer<'de>>(self, deserializer: D) -> Result<(), D::Error> {
            deserializer.deserialize_any(self)
        }
    }

    impl<'de> Visitor<'de> for Unique {
        type Value = ();
        fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.write_str("JSON")
        }
        fn visit_bool<E>(self, _: bool) -> Result<(), E> {
            Ok(())
        }
        fn visit_i64<E>(self, _: i64) -> Result<(), E> {
            Ok(())
        }
        fn visit_u64<E>(self, _: u64) -> Result<(), E> {
            Ok(())
        }
        fn visit_f64<E>(self, _: f64) -> Result<(), E> {
            Ok(())
        }
        fn visit_str<E>(self, _: &str) -> Result<(), E> {
            Ok(())
        }
        fn visit_unit<E>(self) -> Result<(), E> {
            Ok(())
        }
        fn visit_seq<A: SeqAccess<'de>>(self, mut items: A) -> Result<(), A::Error> {
            while items.next_element_seed(Unique)?.is_some() {}
            Ok(())
        }
        fn visit_map<A: MapAccess<'de>>(self, mut entries: A) -> Result<(), A::Error> {
            let mut seen = std::collections::BTreeSet::new();
            while let Some(key) = entries.next_key::<String>()? {
                if !seen.insert(key) {
                    return Err(serde::de::Error::custom("duplicate key"));
                }
                entries.next_value_seed(Unique)?;
            }
            Ok(())
        }
    }

    let mut deserializer = serde_json::Deserializer::from_slice(raw);
    Unique.deserialize(&mut deserializer).ok()?;
    deserializer.end().ok()
}

/// A parsed document that holds a secret (a share envelope). Wiped
/// recursively on drop as defense in depth only: serde scratch buffers,
/// allocator copies and swap stay out of reach.
pub(crate) struct SecretJson(pub Value);

impl SecretJson {
    pub fn parse(raw: &[u8]) -> Option<SecretJson> {
        parse(raw).map(SecretJson)
    }
}

impl Drop for SecretJson {
    fn drop(&mut self) {
        fn wipe(value: &mut Value) {
            match value {
                Value::String(text) => text.zeroize(),
                Value::Array(items) => items.iter_mut().for_each(wipe),
                Value::Object(fields) => fields.values_mut().for_each(wipe),
                _ => {}
            }
        }
        wipe(&mut self.0);
    }
}

// ---------------------------------------------------------------------------
// Field encodings

/// Exactly `2 * N` lowercase hex digits.
pub(crate) fn hex_bytes<const N: usize>(text: &str) -> Option<[u8; N]> {
    let lowercase = text.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'));
    let mut out = [0u8; N];
    (lowercase && text.len() == 2 * N && hex::decode_to_slice(text, &mut out).is_ok())
        .then_some(out)
}

pub(crate) fn hex32(text: &str) -> Option<[u8; 32]> {
    hex_bytes(text)
}

pub(crate) fn is_digest(text: &str) -> bool {
    text.strip_prefix("sha256:").and_then(hex32).is_some()
}

/// `onym:component:` followed by 1-64 of `[a-z0-9-]`.
pub(crate) fn is_component_id(text: &str) -> bool {
    text.strip_prefix("onym:component:").is_some_and(|id| {
        (1..=64).contains(&id.len())
            && id
                .bytes()
                .all(|b| matches!(b, b'a'..=b'z' | b'0'..=b'9' | b'-'))
    })
}

/// Standard padded base64, strict: the engine refuses missing padding and
/// non-zero trailing bits, so every byte string has one encoding.
pub(crate) fn base64(text: &str) -> Option<Vec<u8>> {
    STANDARD.decode(text).ok()
}

pub(crate) fn signature(text: &str) -> Option<[u8; 64]> {
    base64(text)?.try_into().ok()
}

pub(crate) fn sequence(value: u64) -> Option<u64> {
    (1..=MAX_SAFE_INTEGER).contains(&value).then_some(value)
}

/// Exactly `YYYY-MM-DDTHH:MM:SSZ`: UTC, whole seconds, one spelling.
pub fn timestamp(text: &str) -> Option<i64> {
    let parsed = OffsetDateTime::parse(text, &Rfc3339).ok()?;
    let canonical = parsed.offset().is_utc() && parsed.format(&Rfc3339).ok()? == text;
    canonical.then(|| parsed.unix_timestamp())
}

pub fn format_timestamp(unix_seconds: i64) -> Option<String> {
    OffsetDateTime::from_unix_timestamp(unix_seconds)
        .ok()?
        .format(&Rfc3339)
        .ok()
}

/// `P[nD][T[nH][nM][nS]]` in seconds: fixed-length units only (no years,
/// months or weeks), at least one component, at most six digits each.
pub fn duration(text: &str) -> Option<i64> {
    let body = text.strip_prefix('P')?;
    let (date, time) = match body.split_once('T') {
        Some((_, "")) => return None,
        Some((date, time)) => (date, time),
        None => (body, ""),
    };
    let mut seconds = 0;
    let mut components = 0;
    for (mut part, units) in [
        (date, &[('D', 86_400)][..]),
        (time, &[('H', 3_600), ('M', 60), ('S', 1)][..]),
    ] {
        for &(unit, scale) in units {
            if let Some((digits, rest)) = part.split_once(unit) {
                if digits.is_empty()
                    || digits.len() > 6
                    || !digits.bytes().all(|b| b.is_ascii_digit())
                {
                    return None;
                }
                seconds += digits.parse::<i64>().ok()? * scale;
                components += 1;
                part = rest;
            }
        }
        if !part.is_empty() {
            return None;
        }
    }
    (components > 0).then_some(seconds)
}

// ---------------------------------------------------------------------------
// Digests and canonical tuples

/// `authorizationKeyDigest` and `trusteeKeyId`: SHA-256 of the raw key.
pub fn key_digest(key: &[u8; 32]) -> String {
    digest(key)
}

/// Digest of the complete destination object, suite names included.
pub fn destination_keys_digest(destination: &Value) -> String {
    digest(&canonical(&json!([DESTINATION_KEYS, destination])))
}

/// What a candidate's factor key signs for one trustee slot.
pub fn factor_message(session_commitment: &str, component_id: &str, slot: &str) -> Vec<u8> {
    canonical(&json!([
        FACTOR_EVIDENCE,
        session_commitment,
        component_id,
        slot
    ]))
}

/// HPKE `info` for the recovery transfer: the Shamir profile's §6.2 tuple.
pub fn recovery_info(
    session_id: &str,
    enrollment: &EnrollmentContext,
    destination_keys_digest: &str,
    expires_at: &str,
) -> Vec<u8> {
    canonical(&json!([
        RECOVERY_INFO,
        session_id,
        enrollment.enrollment_id,
        enrollment.enrollment_sequence,
        enrollment.policy_digest,
        enrollment.artifact_id,
        enrollment.artifact_digest,
        enrollment.trustee_component_id,
        enrollment.slot,
        destination_keys_digest,
        expires_at,
    ]))
}

// ---------------------------------------------------------------------------
// Objects

/// The bindings that travel in clear next to a sealed share envelope. The
/// trustee rebuilds the HPKE `info` from them before opening and requires
/// the envelope to repeat every one of them after opening.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct EnrollmentContext {
    pub implementation_profile_id: String,
    pub enrollment_id: String,
    pub enrollment_sequence: u64,
    pub policy_digest: String,
    pub artifact_id: String,
    pub artifact_digest: String,
    pub trustee_component_id: String,
    pub slot: String,
    pub trustee_challenge: String,
    pub authorization_key_digest: String,
}

impl EnrollmentContext {
    /// Formats only; whether this trustee issued the challenge is the
    /// store's question.
    pub fn is_well_formed(&self) -> bool {
        hex32(&self.enrollment_id).is_some()
            && sequence(self.enrollment_sequence).is_some()
            && is_digest(&self.policy_digest)
            && hex32(&self.artifact_id).is_some()
            && is_digest(&self.artifact_digest)
            && is_component_id(&self.trustee_component_id)
            && hex32(&self.slot).is_some()
            && hex32(&self.trustee_challenge).is_some()
            && is_digest(&self.authorization_key_digest)
    }

    /// HPKE `info` for the enrollment transfer.
    pub fn info(&self) -> Vec<u8> {
        canonical(&json!([
            ENROLLMENT_INFO,
            self.implementation_profile_id,
            self.enrollment_id,
            self.enrollment_sequence,
            self.policy_digest,
            self.artifact_id,
            self.artifact_digest,
            self.trustee_component_id,
            self.slot,
            self.trustee_challenge,
            self.authorization_key_digest,
        ]))
    }
}

/// The Shamir profile's §4.4 share envelope with `holderAuthorization`
/// already removed. Fields borrow from one parsed tree, so the share words
/// are never copied.
#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub(crate) struct ShareEnvelope<'a> {
    pub share_envelope_version: u64,
    pub implementation_profile_id: &'a str,
    pub enrollment_id: &'a str,
    pub enrollment_sequence: u64,
    pub policy_digest: &'a str,
    pub identity_binding_commitment: &'a str,
    pub artifact_digest: &'a str,
    pub artifact_id: &'a str,
    pub recovery_mode: &'a str,
    pub trustee_component_id: &'a str,
    pub slot: &'a str,
    pub trustee_challenge: &'a str,
    pub member_index: u64,
    pub member_threshold: u64,
    pub member_count: u64,
    #[serde(borrow)]
    pub trustee_policy: TrusteePolicyFields<'a>,
    pub slip39_share: &'a str,
    pub created_at: &'a str,
    pub expires_at: &'a str,
    pub authorization_public_key: &'a str,
}

impl ShareEnvelope<'_> {
    /// True when the envelope repeats every binding of `context`.
    pub fn repeats(&self, context: &EnrollmentContext) -> bool {
        let authorization_digest = hex32(self.authorization_public_key).map(|key| key_digest(&key));
        self.implementation_profile_id == context.implementation_profile_id
            && self.enrollment_id == context.enrollment_id
            && self.enrollment_sequence == context.enrollment_sequence
            && self.policy_digest == context.policy_digest
            && self.artifact_id == context.artifact_id
            && self.artifact_digest == context.artifact_digest
            && self.trustee_component_id == context.trustee_component_id
            && self.slot == context.slot
            && self.trustee_challenge == context.trustee_challenge
            && authorization_digest.as_deref() == Some(context.authorization_key_digest.as_str())
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub(crate) struct TrusteePolicyFields<'a> {
    #[serde(borrow)]
    pub candidate_factors: Vec<&'a str>,
    pub cooldown: &'a str,
    pub session_lifetime: &'a str,
    pub maximum_attempts: u64,
    #[serde(borrow)]
    pub notifications: Vec<&'a str>,
    pub holder_veto: &'a str,
    pub lapse_policy: &'a str,
}

/// The enforceable part of an accepted trustee policy. The notice, veto and
/// lapse values are fixed by this binding, so they need no field.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TrusteePolicy {
    pub factor_key: [u8; 32],
    pub cooldown_secs: i64,
    pub session_lifetime_secs: i64,
    pub maximum_attempts: u32,
}

/// The abstract `ProtectedRecoveryArtifact` with `artifactDigest` removed.
#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub(crate) struct ProtectedArtifact<'a> {
    pub protected_artifact_version: u64,
    pub implementation_profile_id: &'a str,
    pub enrollment_id: &'a str,
    pub enrollment_sequence: u64,
    pub policy_digest: &'a str,
    pub identity_binding_commitment: &'a str,
    pub recovery_mode: &'a str,
    pub artifact_id: &'a str,
    #[serde(borrow)]
    pub protection_parameters: ProtectionParameters<'a>,
    pub ciphertext: &'a str,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ProtectionParameters<'a> {
    pub aead: &'a str,
    pub nonce: &'a str,
}

/// The abstract `RecoverySession` without `candidateEvidence` and
/// `candidateProof`: the part every trustee sees identically.
#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub(crate) struct SessionCore<'a> {
    pub session_version: u64,
    pub session_id: &'a str,
    pub enrollment_id: &'a str,
    pub enrollment_sequence: u64,
    pub policy_digest: &'a str,
    pub artifact_id: &'a str,
    pub artifact_digest: &'a str,
    #[serde(borrow)]
    pub destination: Destination<'a>,
    pub requested_at: &'a str,
    pub expires_at: &'a str,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub(crate) struct Destination<'a> {
    pub encryption_suite: &'a str,
    pub encryption_public_key: &'a str,
    pub proof_suite: &'a str,
    pub proof_public_key: &'a str,
}

/// One factor presentation, addressed to one trustee slot.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct EvidenceFields<'a> {
    pub factor: &'a str,
    pub signature: &'a str,
}

/// The abstract `TrusteeContribution` for an approval, before signing.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct Approval<'a> {
    pub contribution_version: u64,
    pub session_id: &'a str,
    pub enrollment_id: &'a str,
    pub enrollment_sequence: u64,
    pub policy_digest: &'a str,
    pub artifact_id: &'a str,
    pub artifact_digest: &'a str,
    pub component_id: &'a str,
    pub slot: &'a str,
    pub decision: &'a str,
    pub destination_keys_digest: &'a str,
    pub sealed_contribution: &'a str,
    pub decided_at: &'a str,
    pub expires_at: &'a str,
}

// ---------------------------------------------------------------------------
// Requests and receipts
//
// Every request is one canonical object with an `operation`. `enroll` is
// authorized by its single-use challenge and the envelope's own signature,
// `begin-recovery` by `candidateProof`, and every other call is a
// `SignedRequest`.

/// Declared in enrollment receipts (Shamir §5.3 `storageClass`).
pub const STORAGE_CLASS: &str = "onym:recovery-storage:sqlite-software-keys-v1";

/// `issue-challenge`: redeem an operator-issued invitation for a challenge.
#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub(crate) struct ChallengeRequest {
    pub request_version: u64,
    /// Already dispatched on; declared so unknown-field checks pass.
    #[serde(rename = "operation")]
    _operation: String,
    pub component_id: String,
    pub invitation: String,
}

/// `enroll`: a sealed envelope, the bindings that open it, and the protected
/// artifact to hold next to it. The challenge doubles as the request ID.
#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub(crate) struct EnrollRequest {
    pub request_version: u64,
    /// Already dispatched on; declared so unknown-field checks pass.
    #[serde(rename = "operation")]
    _operation: String,
    pub context: EnrollmentContext,
    pub trustee_key_id: String,
    pub sealed_envelope: String,
    pub protected_artifact: Value,
}

/// `begin-recovery`: this trustee's variant of a session. The session ID
/// doubles as the request ID.
#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub(crate) struct BeginRequest {
    pub request_version: u64,
    /// Already dispatched on; declared so unknown-field checks pass.
    #[serde(rename = "operation")]
    _operation: String,
    pub session: Value,
}

/// A request signed by an enrollment's trustee-scoped key (the holder) or a
/// session's proof key (the candidate). Envelopes and sessions signed by the
/// same keys have disjoint required fields, so none parses as another.
#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct SignedRequest {
    request_version: u64,
    operation: String,
    request_id: String,
    component_id: String,
    issued_at: String,
    #[serde(default)]
    enrollment_id: Option<String>,
    #[serde(default)]
    session_id: Option<String>,
    /// `cancel-recovery` only: `candidate` or `holder`.
    #[serde(default)]
    by: Option<String>,
}

/// A parsed `SignedRequest`, signature taken out, naming one target.
pub(crate) struct Signed {
    pub operation: String,
    pub request_id: String,
    /// The enrollment or session ID the operation acts on.
    pub target: String,
    pub by: Option<String>,
    pub issued_at: i64,
    /// The canonical bytes the signature covers.
    pub message: Vec<u8>,
    pub signature: [u8; 64],
    /// Digest of the complete request, to recognise an identical retry.
    pub digest: String,
}

impl Signed {
    /// Parse a request addressed to `component_id` that names exactly the
    /// target its operation acts on.
    pub fn parse(mut value: Value, component_id: &str) -> Option<Signed> {
        let digest = digest(&canonical(&value));
        let signature = signature(&take_string(&mut value, "signature")?)?;
        let message = canonical(&value);
        let request = SignedRequest::deserialize(&value).ok()?;
        let target = match (
            request.operation.as_str(),
            request.enrollment_id,
            request.session_id,
            &request.by,
        ) {
            (
                "read-enrollment" | "revoke-enrollment" | "close-enrollment",
                Some(id),
                None,
                None,
            ) => id,
            ("read-recovery", None, Some(id), None) => id,
            ("cancel-recovery", None, Some(id), Some(_)) => id,
            _ => return None,
        };
        let well_formed = request.request_version == 1
            && request.component_id == component_id
            && hex32(&request.request_id).is_some()
            && hex32(&target).is_some();
        Some(Signed {
            issued_at: timestamp(&request.issued_at).filter(|_| well_formed)?,
            operation: request.operation,
            request_id: request.request_id,
            target,
            by: request.by,
            message,
            signature,
            digest,
        })
    }
}

/// A signed trustee receipt (abstract §5.9, with the Shamir §5.3 fields for
/// `enroll`). Reads return the same shape with equal old and new states.
#[derive(Serialize, Default)]
#[serde(rename_all = "camelCase")]
pub(crate) struct Receipt {
    pub receipt_version: u64,
    pub operation: String,
    pub request_id: String,
    pub component_id: String,
    pub implementation_profile_id: String,
    pub enrollment_id: String,
    pub enrollment_sequence: u64,
    pub policy_digest: String,
    pub old_state: String,
    pub new_state: String,
    pub recorded_at: String,
    pub expires_at: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub session_id: Option<String>,
    /// A §15 code explaining a refused or cancelled session.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub artifact_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub artifact_digest: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub slot: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sealed_contribution_digest: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub storage_class: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cooldown_ends_at: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub remaining_attempts: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub destination_keys_digest: Option<String>,
    /// The signed `TrusteeContribution`, once released.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub contribution: Option<Value>,
    /// `read-enrollment`: every session of this sequence (holder poll).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sessions: Option<Vec<Notice>>,
}

impl Receipt {
    /// The fields every receipt about `context` carries.
    pub fn about(component_id: &str, context: &EnrollmentContext, operation: &str) -> Receipt {
        Receipt {
            receipt_version: 1,
            operation: operation.to_owned(),
            component_id: component_id.to_owned(),
            implementation_profile_id: context.implementation_profile_id.clone(),
            enrollment_id: context.enrollment_id.clone(),
            enrollment_sequence: context.enrollment_sequence,
            policy_digest: context.policy_digest.clone(),
            ..Receipt::default()
        }
    }
}

/// One session as the holder sees it when polling.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct Notice {
    pub session_id: String,
    pub state: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<&'static str>,
    pub cooldown_ends_at: String,
    pub expires_at: String,
}

/// The contract name (abstract §7.1) of a local enrollment state.
pub(crate) fn enrollment_state(
    status: EnrollmentStatus,
    expires_at: i64,
    now: i64,
) -> &'static str {
    match status {
        EnrollmentStatus::Accepted if now >= expires_at => "expired",
        EnrollmentStatus::Accepted => "active",
        other => other.name(),
    }
}

/// The contract name (abstract §7.2) of a local session state, with the
/// reason code a candidate is owed for a veto or a refusal.
pub(crate) fn session_state(
    status: SessionStatus,
    cooldown_ends_at: i64,
    expires_at: i64,
    now: i64,
) -> (&'static str, Option<&'static str>) {
    match status {
        SessionStatus::CoolingDown | SessionStatus::Released if now >= expires_at => {
            ("expired", None)
        }
        SessionStatus::CoolingDown if now < cooldown_ends_at => ("cooling_down", None),
        SessionStatus::CoolingDown | SessionStatus::Released => ("collecting", None),
        SessionStatus::Finalized => ("finalized", None),
        SessionStatus::Cancelled => ("cancelled", None),
        SessionStatus::Vetoed => ("cancelled", Some(Code::RecoveryVetoed.as_str())),
        // The only refusal recorded as a session is a failed factor.
        SessionStatus::Refused => ("refused", Some(Code::InvalidCandidateFactor.as_str())),
    }
}

/// Sign an object over its canonical bytes and embed the signature as
/// `signature`; returns the canonical bytes of the signed object.
pub(crate) fn sign_object(object: &impl Serialize, key: &SigningKey) -> Vec<u8> {
    let mut value = serde_json::to_value(object).expect("binding objects always serialize");
    let signature = crypto::sign(key, &canonical(&value));
    value["signature"] = Value::String(STANDARD.encode(signature));
    canonical(&value)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn duplicate_keys_are_refused_at_any_depth() {
        assert!(parse(br#"{"a":1,"a":2}"#).is_none());
        assert!(parse(br#"{"a":{"b":1,"b":1}}"#).is_none());
        assert!(parse(br#"{"a":[{"b":1,"b":2}]}"#).is_none());
        assert!(parse(br#"{"a":1} trailing"#).is_none());
        assert!(parse(br#"["not an object"]"#).is_none());
        assert!(parse(br#"{"a":1,"b":{"a":1}}"#).is_some());
    }

    /// Sorted output is what makes `canonical` canonical. Enabling
    /// `serde_json/preserve_order` anywhere in the graph would break it.
    #[test]
    fn keys_sort_by_utf8_bytes() {
        let value = parse(br#"{"b":1,"a":{"d":2,"C":3},"_":[3,1]}"#).unwrap();
        assert_eq!(canonical(&value), br#"{"_":[3,1],"a":{"C":3,"d":2},"b":1}"#);
    }

    #[test]
    fn encodings_have_one_spelling() {
        assert!(hex32(&"ab".repeat(32)).is_some());
        assert!(hex32(&"AB".repeat(32)).is_none());
        assert!(hex32(&"ab".repeat(31)).is_none());
        assert!(base64("AA==").is_some());
        assert!(base64("AB==").is_none(), "non-zero trailing bits");
        assert!(base64("AA").is_none(), "missing padding");
        assert!(is_component_id("onym:component:trustee-a"));
        assert!(!is_component_id("onym:component:Trustee"));
        assert!(!is_component_id("onym:component:"));
        assert_eq!(sequence(0), None);
        assert_eq!(sequence(MAX_SAFE_INTEGER + 1), None);
    }

    #[test]
    fn timestamps_are_utc_whole_seconds() {
        assert_eq!(timestamp("1970-01-01T00:01:00Z"), Some(60));
        assert_eq!(
            format_timestamp(60).as_deref(),
            Some("1970-01-01T00:01:00Z")
        );
        for rejected in [
            "1970-01-01T00:01:00.000Z",
            "1970-01-01t00:01:00z",
            "1970-01-01T01:01:00+01:00",
            "1970-01-01 00:01:00Z",
            "2026-02-30T00:00:00Z",
        ] {
            assert_eq!(timestamp(rejected), None, "{rejected}");
        }
    }

    #[test]
    fn durations_use_fixed_units_only() {
        assert_eq!(duration("P2D"), Some(172_800));
        assert_eq!(duration("PT1M30S"), Some(90));
        assert_eq!(duration("P1DT1H"), Some(90_000));
        assert_eq!(duration("PT0S"), Some(0));
        for rejected in [
            "P",
            "PT",
            "P1DT",
            "P1W",
            "P1M",
            "P1Y",
            "PT1S1M",
            "PT1.5S",
            "PT-1S",
            "P1234567D",
            "2D",
        ] {
            assert_eq!(duration(rejected), None, "{rejected}");
        }
    }
}
