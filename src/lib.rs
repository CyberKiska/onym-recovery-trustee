//! Reference trustee core for the Onym recovery-trustee seat: profile
//! `onym:recovery-implementation:shamir-trustees-slip39-v1`, wire binding
//! `draft-1` (see `wire`).
//!
//! A trustee holds one SLIP-0039 share per enrollment slot. At enrollment it
//! checks the share and the holder's signed terms; at recovery it re-seals
//! the same signed envelope to a fresh destination once the policy allows.
//! Nothing here splits, combines or reconstructs a secret, and nothing here
//! can decrypt the protected recovery artifact.
//!
//! The protocol core does no I/O and reads no clock: callers pass `now` in
//! Unix seconds. `store` adds the durable lifecycle in SQLite behind one
//! synchronous call per request.

#![forbid(unsafe_code)]

pub mod crypto;
pub mod slip39;
pub mod state;
pub mod store;
pub mod wire;

use base64::{Engine as _, engine::general_purpose::STANDARD};
use ed25519_dalek::SigningKey;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use zeroize::Zeroizing;

use crate::crypto::HpkePrivateKey;
use crate::slip39::ShareError;
use crate::wire::{Code, EnrollmentContext, SecretJson, ShareEnvelope, TrusteePolicy};

/// Operator-declared bounds, published in the manifest.
#[derive(Clone, Debug)]
pub struct Limits {
    /// Tolerated clock difference for signed timestamps, either direction.
    pub skew_secs: i64,
    pub min_cooldown_secs: i64,
    pub max_cooldown_secs: i64,
    pub max_session_lifetime_secs: i64,
    pub max_attempts: u32,
    pub max_enrollment_term_secs: i64,
    pub max_artifact_bytes: usize,
}

impl Limits {
    /// Largest request body: an `enroll` carries the artifact in base64 next
    /// to a sealed envelope of a few KiB.
    pub fn max_request_bytes(&self) -> usize {
        self.max_artifact_bytes.div_ceil(3) * 4 + 16 * 1024
    }
}

/// What an operator declares about its service in the manifest.
pub struct Service {
    /// The URL holders and candidates `POST` requests to.
    pub endpoint: String,
    pub trust_domain: String,
    pub jurisdiction: String,
    /// Where a holder raises a complaint.
    pub contact: String,
}

/// `validUntil` sits on a fixed grid of this period, 60 to 90 days ahead, so
/// manifest bytes change once a period, not on every restart, and a
/// running service never serves an expired one.
const MANIFEST_PERIOD_SECS: i64 = 30 * 86_400;

const RETENTION: &str = "The sealed share and artifact are kept until the holder revokes or \
    closes the enrollment. That removes them from the live database at once; copies in freed \
    disk blocks, snapshots or backups are not erased. A tombstone keeps the non-secret \
    bindings, and released contributions stay as ciphertext only the candidate can open. \
    Expired enrollments are not swept yet.";

/// One trustee: its component ID, keys and limits.
pub struct Trustee {
    pub component_id: String,
    pub hpke_key: HpkePrivateKey,
    pub signing_key: SigningKey,
    pub limits: Limits,
}

/// What a trustee keeps about an accepted enrollment: bindings and policy,
/// never the share. The sealed envelope is stored exactly as received.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Enrollment {
    pub context: EnrollmentContext,
    pub identity_binding_commitment: String,
    pub member_index: u8,
    pub member_threshold: u8,
    pub member_count: u8,
    pub policy: TrusteePolicy,
    pub created_at: i64,
    pub expires_at: i64,
    pub authorization_key: [u8; 32],
}

/// A recovery request whose candidate proof and destination verified.
/// Nothing in it is checked against an enrollment yet.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Session {
    pub session_id: String,
    pub enrollment_id: String,
    pub enrollment_sequence: u64,
    pub policy_digest: String,
    pub artifact_id: String,
    pub artifact_digest: String,
    pub destination_key: [u8; 32],
    pub destination_keys_digest: String,
    /// The fresh key that signed this session; it also signs the
    /// candidate's later reads and cancellation.
    pub proof_key: [u8; 32],
    /// Digest of the session without `candidateEvidence` and
    /// `candidateProof`; what factor evidence signs.
    pub session_commitment: String,
    pub requested_at: i64,
    pub expires_at: i64,
    pub evidence: Vec<Evidence>,
    /// Exact canonical bytes, so a reused `sessionId` can be compared.
    pub canonical: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Evidence {
    pub factor: String,
    pub signature: [u8; 64],
}

/// A signed `TrusteeContribution`, ready to persist before it is returned.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Contribution {
    pub canonical: Vec<u8>,
    pub sealed_digest: String,
}

impl Session {
    /// True when the session names exactly this enrollment sequence.
    pub fn binds(&self, context: &EnrollmentContext) -> bool {
        self.enrollment_id == context.enrollment_id
            && self.enrollment_sequence == context.enrollment_sequence
            && self.policy_digest == context.policy_digest
            && self.artifact_id == context.artifact_id
            && self.artifact_digest == context.artifact_digest
    }
}

impl Trustee {
    pub fn hpke_public_key(&self) -> [u8; 32] {
        crypto::hpke_public_key(&self.hpke_key)
    }

    /// `trusteeKeyId`, as published in the manifest.
    pub fn key_id(&self) -> String {
        wire::key_digest(&self.hpke_public_key())
    }

    /// `onym:key:<hex>` of the Ed25519 key that signs manifests, receipts
    /// and contributions.
    pub fn operator(&self) -> String {
        format!("onym:key:{}", hex::encode(self.signing_key.verifying_key()))
    }

    /// The signed service manifest: abstract §5.3, plus what this binding
    /// needs published (enrollment key, limits, operations) and one free
    /// offer (§12). Each unsupported operation is declared with its code.
    /// Ed25519 is deterministic, so equal inputs give equal bytes.
    pub fn manifest(&self, service: &Service, now: i64) -> Result<Vec<u8>, Code> {
        let limits = &self.limits;
        let period = now.div_euclid(MANIFEST_PERIOD_SECS);
        let valid_until = wire::format_timestamp((period + 3) * MANIFEST_PERIOD_SECS)
            .ok_or(Code::TemporarilyUnavailable)?;
        let refused: serde_json::Map<String, Value> = store::REFUSED
            .iter()
            .map(|(operation, code)| (operation.to_string(), code.as_str().into()))
            .collect();
        let manifest = json!({
            "version": 1,
            "componentId": self.component_id,
            "seat": wire::SEAT,
            "operator": self.operator(),
            "recoveryProfileId": wire::RECOVERY_PROFILE_ID,
            "implementationProfileIds": [wire::IMPLEMENTATION_PROFILE_ID],
            "bindingVersion": wire::BINDING_VERSION,
            "endpoints": [service.endpoint],
            "trustDomain": service.trust_domain,
            "jurisdiction": service.jurisdiction,
            "retention": RETENTION,
            "recoveryFactors": [wire::FACTOR_ED25519_SESSION.trim_end_matches(':')],
            "notificationChannels": [wire::NOTICE_HOLDER_POLL],
            "enrollmentKey": {
                "suite": wire::ENCRYPTION_SUITE,
                "publicKey": hex::encode(self.hpke_public_key()),
                "trusteeKeyId": self.key_id(),
            },
            "storageClass": wire::STORAGE_CLASS,
            "limits": {
                "clockSkewSeconds": limits.skew_secs,
                "minimumCooldownSeconds": limits.min_cooldown_secs,
                "maximumCooldownSeconds": limits.max_cooldown_secs,
                "maximumSessionLifetimeSeconds": limits.max_session_lifetime_secs,
                "maximumAttempts": limits.max_attempts,
                "maximumEnrollmentTermSeconds": limits.max_enrollment_term_secs,
                "maximumArtifactBytes": limits.max_artifact_bytes,
                "maximumRequestBytes": limits.max_request_bytes(),
            },
            "operations": store::OPERATIONS,
            "unsupportedOperations": refused,
            "offers": [{
                "offerId": "free-v1",
                "model": "free",
                "service": "Custody of one SLIP-0039 share per enrollment slot, released \
                    under the enrolled policy",
                "recoveryFees": "none",
                "lapse": "none",
                "export": "unavailable",
                "retention": RETENTION,
                "jurisdiction": service.jurisdiction,
                "complaints": service.contact,
                "splits": [],
                "limitations": [
                    "Unreviewed reference implementation: synthetic test secrets only.",
                    "Notices reach the holder only while an enrolled device polls.",
                    "Freshness rests on this operator's local state and clock.",
                ],
            }],
            "validUntil": valid_until,
        });
        Ok(wire::sign_object(&manifest, &self.signing_key))
    }

    /// Open one sealed share envelope and decide whether to take custody.
    /// Checks the holder's signature, every binding against `context`, the
    /// share and the trustee policy. Whether the challenge is fresh and
    /// unused is the caller's check, made in the same transaction.
    pub fn accept_enrollment(
        &self,
        context: &EnrollmentContext,
        sealed: &[u8],
        now: i64,
    ) -> Result<Enrollment, Code> {
        if context.implementation_profile_id != wire::IMPLEMENTATION_PROFILE_ID {
            return Err(Code::UnsupportedProfile);
        }
        if !context.is_well_formed() || context.trustee_component_id != self.component_id {
            return Err(Code::InvalidEnrollment);
        }
        let plaintext = crypto::open(&self.hpke_key, &context.info(), sealed)
            .map_err(|_| Code::InvalidEnrollment)?;
        let mut document = SecretJson::parse(&plaintext).ok_or(Code::InvalidEnrollment)?;
        let envelope = verified_envelope(&mut document, context)?;
        self.admit_envelope(&envelope, context, now)
    }

    /// Check the protected artifact stored next to an accepted enrollment:
    /// its digest and every header binding. The trustee cannot check the
    /// artifact's AEAD tag; only the recovering vault holds that key.
    pub fn check_artifact(&self, enrollment: &Enrollment, raw: &[u8]) -> Result<(), Code> {
        let mut value = wire::parse(raw).ok_or(Code::InvalidEnrollment)?;
        let claimed =
            wire::take_string(&mut value, "artifactDigest").ok_or(Code::InvalidEnrollment)?;
        let computed = wire::digest(&wire::canonical(&value));
        let artifact =
            wire::ProtectedArtifact::deserialize(&value).map_err(|_| Code::InvalidEnrollment)?;
        let ciphertext = wire::base64(artifact.ciphertext).ok_or(Code::InvalidEnrollment)?;
        let well_formed = artifact.protected_artifact_version == 1
            && artifact.protection_parameters.aead == wire::ARTIFACT_AEAD
            && wire::hex_bytes::<12>(artifact.protection_parameters.nonce).is_some()
            && (16..=self.limits.max_artifact_bytes).contains(&ciphertext.len());
        if !well_formed {
            return Err(Code::InvalidEnrollment);
        }
        let context = &enrollment.context;
        let bound = claimed == computed
            && computed == context.artifact_digest
            && artifact.implementation_profile_id == context.implementation_profile_id
            && artifact.enrollment_id == context.enrollment_id
            && artifact.enrollment_sequence == context.enrollment_sequence
            && artifact.policy_digest == context.policy_digest
            && artifact.identity_binding_commitment == enrollment.identity_binding_commitment
            && artifact.recovery_mode == wire::RECOVERY_MODE
            && artifact.artifact_id == context.artifact_id;
        if !bound {
            return Err(Code::ArtifactMismatch);
        }
        Ok(())
    }

    /// Verify a recovery request on its own: form, the fresh proof key's
    /// signature, and the destination. Nothing here depends on whether an
    /// enrollment exists, so the answer cannot reveal one. Bindings
    /// ([`Session::binds`]) and factors ([`Trustee::check_factor`]) come next.
    pub fn verify_session(&self, raw: &[u8]) -> Result<Session, Code> {
        use Code::InvalidRequest;
        let mut value = wire::parse(raw).ok_or(InvalidRequest)?;
        let canonical = wire::canonical(&value);
        let proof = wire::take_string(&mut value, "candidateProof").ok_or(InvalidRequest)?;
        let signed = wire::canonical(&value);
        let evidence = wire::take(&mut value, "candidateEvidence").ok_or(InvalidRequest)?;
        let session_commitment = wire::digest(&wire::canonical(&value));

        let core = wire::SessionCore::deserialize(&value).map_err(|_| InvalidRequest)?;
        let evidence = Vec::<wire::EvidenceFields>::deserialize(&evidence)
            .map_err(|_| InvalidRequest)?
            .into_iter()
            .map(|item| {
                Some(Evidence {
                    factor: item.factor.to_owned(),
                    signature: wire::signature(item.signature)?,
                })
            })
            .collect::<Option<Vec<_>>>()
            .ok_or(InvalidRequest)?;
        let requested_at = wire::timestamp(core.requested_at).ok_or(InvalidRequest)?;
        let expires_at = wire::timestamp(core.expires_at).ok_or(InvalidRequest)?;
        let well_formed = core.session_version == 1
            && wire::hex32(core.session_id).is_some()
            && wire::hex32(core.enrollment_id).is_some()
            && wire::sequence(core.enrollment_sequence).is_some()
            && wire::is_digest(core.policy_digest)
            && wire::hex32(core.artifact_id).is_some()
            && wire::is_digest(core.artifact_digest);
        if !well_formed {
            return Err(InvalidRequest);
        }

        let proof_key = wire::hex32(core.destination.proof_public_key).ok_or(InvalidRequest)?;
        let proof = wire::signature(&proof).ok_or(InvalidRequest)?;
        crypto::verify(&proof_key, &signed, &proof).map_err(|_| InvalidRequest)?;

        // A trial seal is the exact check release will make: HPKE refuses
        // low-order keys. It is cheap, and failing here beats failing after
        // the cooldown.
        let destination = &core.destination;
        let destination_key =
            wire::hex32(destination.encryption_public_key).ok_or(Code::InvalidDestination)?;
        let suites_match = destination.encryption_suite == wire::ENCRYPTION_SUITE
            && destination.proof_suite == wire::PROOF_SUITE;
        if !suites_match || crypto::seal(&destination_key, b"onym-destination-check", b"").is_err()
        {
            return Err(Code::InvalidDestination);
        }

        Ok(Session {
            session_id: core.session_id.to_owned(),
            enrollment_id: core.enrollment_id.to_owned(),
            enrollment_sequence: core.enrollment_sequence,
            policy_digest: core.policy_digest.to_owned(),
            artifact_id: core.artifact_id.to_owned(),
            artifact_digest: core.artifact_digest.to_owned(),
            destination_key,
            destination_keys_digest: wire::destination_keys_digest(&value["destination"]),
            proof_key,
            session_commitment,
            requested_at,
            expires_at,
            evidence,
            canonical,
        })
    }

    /// The candidate's evidence for this slot: exactly one presentation of
    /// the enrolled factor, signed over this session and this slot.
    pub fn check_factor(&self, enrollment: &Enrollment, session: &Session) -> Result<(), Code> {
        let [evidence] = session.evidence.as_slice() else {
            return Err(Code::InvalidCandidateFactor);
        };
        let factor = enrollment.policy.factor_key;
        let enrolled = format!("{}{}", wire::FACTOR_ED25519_SESSION, hex::encode(factor));
        let context = &enrollment.context;
        let message = wire::factor_message(
            &session.session_commitment,
            &context.trustee_component_id,
            &context.slot,
        );
        if evidence.factor != enrolled
            || crypto::verify(&factor, &message, &evidence.signature).is_err()
        {
            return Err(Code::InvalidCandidateFactor);
        }
        Ok(())
    }

    /// Build this slot's contribution: open the stored envelope with the
    /// stored bindings, confirm it is still the holder-signed envelope that
    /// was accepted, and seal its exact bytes to the session destination.
    /// Call only after the release predicate allows it, inside the
    /// transaction that persists the result.
    pub fn release(
        &self,
        enrollment: &Enrollment,
        sealed: &[u8],
        session: &Session,
        now: i64,
    ) -> Result<Contribution, Code> {
        use Code::TemporarilyUnavailable;
        let context = &enrollment.context;
        if !session.binds(context) {
            return Err(Code::InvalidRequest);
        }
        let plaintext = crypto::open(&self.hpke_key, &context.info(), sealed)
            .map_err(|_| TemporarilyUnavailable)?;
        {
            let mut document = SecretJson::parse(&plaintext).ok_or(TemporarilyUnavailable)?;
            verified_envelope(&mut document, context).map_err(|_| TemporarilyUnavailable)?;
        }

        let expires_at =
            wire::format_timestamp(session.expires_at).ok_or(TemporarilyUnavailable)?;
        let decided_at = wire::format_timestamp(now).ok_or(TemporarilyUnavailable)?;
        let info = wire::recovery_info(
            &session.session_id,
            context,
            &session.destination_keys_digest,
            &expires_at,
        );
        let resealed = crypto::seal(&session.destination_key, &info, &plaintext)
            .map_err(|_| Code::InvalidDestination)?;
        let approval = wire::Approval {
            contribution_version: 1,
            session_id: &session.session_id,
            enrollment_id: &context.enrollment_id,
            enrollment_sequence: context.enrollment_sequence,
            policy_digest: &context.policy_digest,
            artifact_id: &context.artifact_id,
            artifact_digest: &context.artifact_digest,
            component_id: &context.trustee_component_id,
            slot: &context.slot,
            decision: "approved",
            destination_keys_digest: &session.destination_keys_digest,
            sealed_contribution: &STANDARD.encode(&resealed),
            decided_at: &decided_at,
            expires_at: &expires_at,
        };
        Ok(Contribution {
            canonical: wire::sign_object(&approval, &self.signing_key),
            sealed_digest: wire::digest(&resealed),
        })
    }

    /// Acceptance-time checks on a verified envelope: profile parameters,
    /// the share, timestamps and the trustee policy.
    fn admit_envelope(
        &self,
        envelope: &ShareEnvelope<'_>,
        context: &EnrollmentContext,
        now: i64,
    ) -> Result<Enrollment, Code> {
        if envelope.share_envelope_version != 1 || envelope.recovery_mode != wire::RECOVERY_MODE {
            return Err(Code::UnsupportedProfile);
        }
        let (index, threshold, count) = (
            envelope.member_index,
            envelope.member_threshold,
            envelope.member_count,
        );
        let parameters_valid = 2 <= threshold && threshold <= count && count <= 16 && index < count;
        if !parameters_valid || !wire::is_digest(envelope.identity_binding_commitment) {
            return Err(Code::InvalidEnrollment);
        }
        let share = slip39::validate(envelope.slip39_share).map_err(|error| match error {
            ShareError::Malformed => Code::InvalidEnrollment,
            ShareError::Unsupported => Code::UnsupportedProfile,
        })?;
        if u64::from(share.member_index) != index || u64::from(share.member_threshold) != threshold
        {
            return Err(Code::InvalidEnrollment);
        }

        let created_at = wire::timestamp(envelope.created_at).ok_or(Code::InvalidEnrollment)?;
        let expires_at = wire::timestamp(envelope.expires_at).ok_or(Code::InvalidEnrollment)?;
        if created_at > now + self.limits.skew_secs {
            return Err(Code::InvalidEnrollment);
        }
        if expires_at <= now {
            return Err(Code::EnrollmentExpired);
        }
        if expires_at > now + self.limits.max_enrollment_term_secs {
            return Err(Code::InvalidEnrollment);
        }

        Ok(Enrollment {
            context: context.clone(),
            identity_binding_commitment: envelope.identity_binding_commitment.to_owned(),
            member_index: share.member_index,
            member_threshold: share.member_threshold,
            member_count: count as u8,
            policy: self.policy(&envelope.trustee_policy)?,
            created_at,
            expires_at,
            authorization_key: wire::hex32(envelope.authorization_public_key)
                .ok_or(Code::InvalidEnrollment)?,
        })
    }

    /// The trustee policy under this binding: one Ed25519 session factor,
    /// holder-poll notices, veto by the authorization key, no lapse, and
    /// timings inside the published limits.
    fn policy(&self, fields: &wire::TrusteePolicyFields<'_>) -> Result<TrusteePolicy, Code> {
        let limits = &self.limits;
        let [factor] = fields.candidate_factors.as_slice() else {
            return Err(Code::InvalidPolicy);
        };
        let factor_key = factor
            .strip_prefix(wire::FACTOR_ED25519_SESSION)
            .and_then(wire::hex32)
            .filter(crypto::is_usable_verifying_key)
            .ok_or(Code::InvalidPolicy)?;
        let cooldown = wire::duration(fields.cooldown).ok_or(Code::InvalidPolicy)?;
        let lifetime = wire::duration(fields.session_lifetime).ok_or(Code::InvalidPolicy)?;
        let valid = fields.notifications == [wire::NOTICE_HOLDER_POLL]
            && fields.holder_veto == wire::VETO_AUTHORIZATION_KEY
            && fields.lapse_policy == wire::LAPSE_NONE
            && (limits.min_cooldown_secs..=limits.max_cooldown_secs).contains(&cooldown)
            && cooldown < lifetime
            && lifetime <= limits.max_session_lifetime_secs
            && (1..=u64::from(limits.max_attempts)).contains(&fields.maximum_attempts);
        if !valid {
            return Err(Code::InvalidPolicy);
        }
        Ok(TrusteePolicy {
            factor_key,
            cooldown_secs: cooldown,
            session_lifetime_secs: lifetime,
            maximum_attempts: fields.maximum_attempts as u32,
        })
    }
}

/// Remove and verify `holderAuthorization`, then require the envelope to
/// repeat every binding of `context`. The returned fields borrow from
/// `document`, which wipes itself when dropped.
fn verified_envelope<'a>(
    document: &'a mut SecretJson,
    context: &EnrollmentContext,
) -> Result<ShareEnvelope<'a>, Code> {
    let authorization =
        wire::take_string(&mut document.0, "holderAuthorization").ok_or(Code::InvalidEnrollment)?;
    let signed = Zeroizing::new(wire::canonical(&document.0));
    let tree: &'a Value = &document.0;
    let envelope = ShareEnvelope::deserialize(tree).map_err(|_| Code::InvalidEnrollment)?;
    let key = wire::hex32(envelope.authorization_public_key).ok_or(Code::InvalidEnrollment)?;
    let signature = wire::signature(&authorization).ok_or(Code::InvalidEnrollment)?;
    crypto::verify(&key, &signed, &signature).map_err(|_| Code::InvalidEnrollment)?;
    if !envelope.repeats(context) {
        return Err(Code::InvalidEnrollment);
    }
    Ok(envelope)
}
