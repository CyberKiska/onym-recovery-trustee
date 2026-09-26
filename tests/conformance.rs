//! Conformance fixtures for the trustee core, binding `draft-1`:
//!
//! - SLIP-0039: the official Trezor vectors, annotated with the reference
//!   implementation's own decoding, and profile shares it generated;
//! - HPKE: the CFRG vector for exactly our suite;
//! - canonical JSON: Onym Discovery's cross-language fixtures;
//! - the binding itself: envelope, artifact, session and contribution in
//!   `tests/fixtures/binding/`, plus refusal cases for every binding.
//!
//! Deterministic outputs are byte-compared with the committed files. Sealed
//! values carry fresh randomness, so they are opened and checked instead.
//! Regenerate deliberately: `REGEN_FIXTURES=1 cargo test --test conformance`.

use std::collections::BTreeSet;
use std::path::PathBuf;

use base64::{Engine as _, engine::general_purpose::STANDARD};
use ed25519_dalek::SigningKey;
use hpke::{Deserializable, Kem as _, OpModeR, Serializable};
use onym_recovery_trustee::slip39::{self, Fields, Share, ShareError};
use onym_recovery_trustee::wire::{self, Code, EnrollmentContext};
use onym_recovery_trustee::{Enrollment, Limits, Trustee, crypto};
use serde_json::{Value, json};

fn fixtures() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures")
}

fn read(path: &str) -> Vec<u8> {
    std::fs::read(fixtures().join(path)).unwrap_or_else(|error| panic!("{path}: {error}"))
}

fn read_json(path: &str) -> Value {
    serde_json::from_slice(&read(path)).unwrap()
}

fn regenerating() -> bool {
    std::env::var_os("REGEN_FIXTURES").is_some()
}

// ---------------------------------------------------------------------------
// SLIP-0039

#[test]
fn official_slip39_vectors_decode_as_the_reference_does() {
    let (mut malformed, mut unsupported) = (0, 0);
    for case in read_json("slip39/official-decoded.json")["cases"]
        .as_array()
        .unwrap()
    {
        let mnemonic = case["mnemonic"].as_str().unwrap();
        let reference = &case["reference"];
        let label = format!("case {}", case["case"]);
        let words = mnemonic.split(' ').count();
        let decoded = slip39::decode(mnemonic);

        if words != 33 {
            assert_eq!(decoded, Err(ShareError::Malformed), "{label}: not 256-bit");
        } else if let Some(error) = reference["error"].as_str() {
            assert!(matches!(error, "checksum" | "padding"), "{label}: {error}");
            assert_eq!(decoded, Err(ShareError::Malformed), "{label}");
        } else {
            let number = |field: &str| reference[field].as_u64().unwrap();
            let expected = Fields {
                identifier: number("identifier") as u16,
                extendable: reference["extendable"].as_bool().unwrap(),
                iteration_exponent: number("iterationExponent") as u8,
                group_index: number("groupIndex") as u8,
                group_threshold: number("groupThreshold") as u8,
                group_count: number("groupCount") as u8,
                member_index: number("memberIndex") as u8,
                member_threshold: number("memberThreshold") as u8,
            };
            assert_eq!(decoded, Ok(expected), "{label}");
            assert_eq!(number("valueBytes"), 32, "{label}");
        }

        // No official vector fits the Onym profile: 256-bit ones use
        // exponent 2, the extendable flag, a threshold of 1 or several groups.
        match slip39::validate(mnemonic) {
            Ok(_) => panic!("{label}: an official vector fits the profile"),
            Err(ShareError::Malformed) if words == 33 => malformed += 1,
            Err(ShareError::Malformed) => {}
            Err(ShareError::Unsupported) => unsupported += 1,
        }
    }
    assert_eq!((malformed, unsupported), (2, 22), "33-word shares");
}

#[test]
fn generated_profile_shares_validate() {
    let sets = read_json("slip39/onym-generated.json");
    let sets = sets["cases"].as_array().unwrap();
    assert_eq!(sets.len(), 4, "2-of-3, 3-of-5, 2-of-16, 16-of-16");
    for set in sets {
        let threshold = set["memberThreshold"].as_u64().unwrap() as u8;
        let shares = set["shares"].as_array().unwrap();
        assert_eq!(shares.len() as u64, set["memberCount"].as_u64().unwrap());
        let mut identifiers = BTreeSet::new();
        for (index, share) in shares.iter().enumerate() {
            let mnemonic = share.as_str().unwrap();
            let expected = Share {
                member_index: index as u8,
                member_threshold: threshold,
            };
            assert_eq!(slip39::validate(mnemonic), Ok(expected));
            identifiers.insert(slip39::decode(mnemonic).unwrap().identifier);
            assert_canonical_form_only(mnemonic);
        }
        assert_eq!(identifiers.len(), 1, "one identifier per set");
    }
}

/// Only the exact canonical spelling is a share: no case folding, no
/// trimming, no other whitespace, no prefixes, no correction.
fn assert_canonical_form_only(mnemonic: &str) {
    let words: Vec<&str> = mnemonic.split(' ').collect();
    let substituted = |position: usize, word: &str| {
        let mut changed = words.clone();
        changed[position] = word;
        changed.join(" ")
    };
    let other_word = if words[10] == "academic" {
        "acid"
    } else {
        "academic"
    };
    let long = words.iter().position(|word| word.len() > 4).unwrap();
    let variants = [
        mnemonic.to_uppercase(),
        mnemonic.replacen(' ', "  ", 1),
        mnemonic.replacen(' ', "\t", 1),
        format!(" {mnemonic}"),
        format!("{mnemonic}\n"),
        substituted(long, &words[long][..4]),
        substituted(10, other_word),
        words[..32].join(" "),
    ];
    for variant in variants {
        assert_eq!(
            slip39::validate(&variant),
            Err(ShareError::Malformed),
            "{variant:?}"
        );
    }
}

// ---------------------------------------------------------------------------
// HPKE

#[test]
fn hpke_suite_matches_the_cfrg_vector() {
    let vector = read_json("hpke/cfrg-base-x25519-sha256-aes256gcm.json");
    let bytes = |value: &Value| hex::decode(value.as_str().unwrap()).unwrap();
    let field = |name: &str| bytes(&vector[name]);

    assert_eq!(vector["mode"], 0);
    assert_eq!(vector["kem_id"], <crypto::Kem as hpke::Kem>::KEM_ID);
    assert_eq!(vector["kdf_id"], <crypto::Kdf as hpke::kdf::Kdf>::KDF_ID);
    assert_eq!(
        vector["aead_id"],
        <crypto::Aead as hpke::aead::Aead>::AEAD_ID
    );

    let (private, public) = crypto::Kem::derive_keypair(&field("ikmR"));
    assert_eq!(private.to_bytes().as_slice(), field("skRm"));
    assert_eq!(public.to_bytes().as_slice(), field("pkRm"));
    let (_, ephemeral) = crypto::Kem::derive_keypair(&field("ikmE"));
    assert_eq!(ephemeral.to_bytes().as_slice(), field("enc"));

    let enc = <crypto::Kem as hpke::Kem>::EncappedKey::from_bytes(&field("enc")).unwrap();
    let mut receiver = hpke::setup_receiver::<crypto::Aead, crypto::Kdf, crypto::Kem>(
        &OpModeR::Base,
        &private,
        &enc,
        &field("info"),
    )
    .unwrap();
    let encryptions = vector["encryptions"].as_array().unwrap();
    assert_eq!(encryptions.len(), 257);
    for encryption in encryptions {
        let plaintext = receiver.open(&bytes(&encryption["ct"]), &bytes(&encryption["aad"]));
        assert_eq!(plaintext.unwrap(), bytes(&encryption["pt"]));
    }
}

// ---------------------------------------------------------------------------
// Canonical JSON

#[test]
fn discovery_canonical_fixtures_reproduce() {
    for name in [
        "canonical",
        "canonical-case",
        "canonical-escaping",
        "foundation-vectors",
    ] {
        let mut value = wire::parse(&read(&format!("canonical/{name}-input.json"))).unwrap();
        value.as_object_mut().unwrap().remove("signature");
        assert_eq!(
            wire::canonical(&value),
            read(&format!("canonical/{name}-bytes.bin")),
            "{name}"
        );
    }
    assert!(wire::parse(&read("canonical/duplicate-keys-input.json")).is_none());
}

// ---------------------------------------------------------------------------
// Binding vectors

const DAY: i64 = 86_400;
const COMPONENT: &str = "onym:component:reference-trustee";
const CREATED_AT: &str = "2026-09-23T00:00:00Z";
const EXPIRES_AT: &str = "2027-09-23T00:00:00Z";
/// When the trustee accepts the enrollment.
const ENROLLED_AT: &str = "2026-09-23T12:00:00Z";
const REQUESTED_AT: &str = "2026-10-01T00:00:00Z";
const SESSION_EXPIRES_AT: &str = "2026-10-06T00:00:00Z";
/// When the trustee releases, after a two-day cooldown.
const RELEASED_AT: &str = "2026-10-03T12:00:00Z";

/// Every key of the vectors, from a fixed seed. Test keys only.
struct Keys {
    /// The holder's trustee-scoped authorization key.
    holder: SigningKey,
    /// The candidate's pre-enrolled recovery factor.
    factor: SigningKey,
    /// The trustee's operator key, which signs contributions.
    operator: SigningKey,
    /// The candidate's fresh session-proof key.
    proof: SigningKey,
    trustee_hpke: [u8; 32],
    destination_hpke: [u8; 32],
}

fn keys() -> Keys {
    Keys {
        holder: SigningKey::from_bytes(&[0x11; 32]),
        factor: SigningKey::from_bytes(&[0x22; 32]),
        operator: SigningKey::from_bytes(&[0x33; 32]),
        proof: SigningKey::from_bytes(&[0x66; 32]),
        trustee_hpke: [0x44; 32],
        destination_hpke: [0x55; 32],
    }
}

fn at(text: &str) -> i64 {
    wire::timestamp(text).unwrap()
}

fn hex_public(key: &SigningKey) -> String {
    hex::encode(key.verifying_key().to_bytes())
}

fn trustee() -> Trustee {
    Trustee {
        component_id: COMPONENT.to_owned(),
        hpke_key: crypto::hpke_private_key(&keys().trustee_hpke).unwrap(),
        signing_key: keys().operator,
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

/// Sign `value` over its canonical bytes and embed the signature as `field`.
fn signed(mut value: Value, field: &str, key: &SigningKey) -> Vec<u8> {
    let signature = crypto::sign(key, &wire::canonical(&value));
    value[field] = json!(STANDARD.encode(signature));
    wire::canonical(&value)
}

/// Member 1 of the generated 2-of-3 set: a real, public test share.
fn share() -> String {
    let sets = read_json("slip39/onym-generated.json");
    sets["cases"][0]["shares"][1].as_str().unwrap().to_owned()
}

fn bindings() -> Value {
    json!({
        "implementationProfileId": wire::IMPLEMENTATION_PROFILE_ID,
        "enrollmentId": "e1".repeat(32),
        "enrollmentSequence": 1,
        "policyDigest": wire::digest(b"example: canonical private recovery policy"),
        "artifactId": "a1".repeat(32),
    })
}

fn identity_binding_commitment() -> String {
    wire::digest(b"example: identity binding commitment")
}

/// A protected artifact without `artifactDigest`. The ciphertext is
/// synthetic: a trustee never decrypts it, it only checks the header.
fn artifact_header() -> Value {
    let b = bindings();
    json!({
        "protectedArtifactVersion": 1,
        "implementationProfileId": b["implementationProfileId"],
        "enrollmentId": b["enrollmentId"],
        "enrollmentSequence": b["enrollmentSequence"],
        "policyDigest": b["policyDigest"],
        "identityBindingCommitment": identity_binding_commitment(),
        "recoveryMode": wire::RECOVERY_MODE,
        "artifactId": b["artifactId"],
        "protectionParameters": {"aead": wire::ARTIFACT_AEAD, "nonce": "000102030405060708090a0b"},
        "ciphertext": STANDARD.encode([0xa5u8; 48]),
    })
}

fn artifact_digest() -> String {
    wire::digest(&wire::canonical(&artifact_header()))
}

fn artifact_document() -> Vec<u8> {
    let mut artifact = artifact_header();
    artifact["artifactDigest"] = json!(artifact_digest());
    wire::canonical(&artifact)
}

/// The unsigned share envelope (Shamir profile §4.4) for this trustee.
fn envelope_value() -> Value {
    let keys = keys();
    let b = bindings();
    json!({
        "shareEnvelopeVersion": 1,
        "implementationProfileId": b["implementationProfileId"],
        "enrollmentId": b["enrollmentId"],
        "enrollmentSequence": b["enrollmentSequence"],
        "policyDigest": b["policyDigest"],
        "identityBindingCommitment": identity_binding_commitment(),
        "artifactDigest": artifact_digest(),
        "artifactId": b["artifactId"],
        "recoveryMode": wire::RECOVERY_MODE,
        "trusteeComponentId": COMPONENT,
        "slot": "51".repeat(32),
        "trusteeChallenge": "c1".repeat(32),
        "memberIndex": 1,
        "memberThreshold": 2,
        "memberCount": 3,
        "trusteePolicy": {
            "candidateFactors": [format!("{}{}", wire::FACTOR_ED25519_SESSION, hex_public(&keys.factor))],
            "cooldown": "P2D",
            "sessionLifetime": "P7D",
            "maximumAttempts": 3,
            "notifications": [wire::NOTICE_HOLDER_POLL],
            "holderVeto": wire::VETO_AUTHORIZATION_KEY,
            "lapsePolicy": wire::LAPSE_NONE,
        },
        "slip39Share": share(),
        "createdAt": CREATED_AT,
        "expiresAt": EXPIRES_AT,
        "authorizationPublicKey": hex_public(&keys.holder),
    })
}

fn context() -> EnrollmentContext {
    let envelope = envelope_value();
    let text = |field: &str| envelope[field].as_str().unwrap().to_owned();
    EnrollmentContext {
        implementation_profile_id: text("implementationProfileId"),
        enrollment_id: text("enrollmentId"),
        enrollment_sequence: envelope["enrollmentSequence"].as_u64().unwrap(),
        policy_digest: text("policyDigest"),
        artifact_id: text("artifactId"),
        artifact_digest: text("artifactDigest"),
        trustee_component_id: text("trusteeComponentId"),
        slot: text("slot"),
        trustee_challenge: text("trusteeChallenge"),
        authorization_key_digest: wire::key_digest(&keys().holder.verifying_key().to_bytes()),
    }
}

fn envelope_document() -> Vec<u8> {
    signed(envelope_value(), "holderAuthorization", &keys().holder)
}

fn trustee_public_key() -> [u8; 32] {
    crypto::hpke_public_key(&crypto::hpke_private_key(&keys().trustee_hpke).unwrap())
}

fn destination_public_key() -> [u8; 32] {
    crypto::hpke_public_key(&crypto::hpke_private_key(&keys().destination_hpke).unwrap())
}

/// The session every trustee sees identically.
fn session_core() -> Value {
    let b = bindings();
    json!({
        "sessionVersion": 1,
        "sessionId": "5e".repeat(32),
        "enrollmentId": b["enrollmentId"],
        "enrollmentSequence": b["enrollmentSequence"],
        "policyDigest": b["policyDigest"],
        "artifactId": b["artifactId"],
        "artifactDigest": artifact_digest(),
        "destination": {
            "encryptionSuite": wire::ENCRYPTION_SUITE,
            "encryptionPublicKey": hex::encode(destination_public_key()),
            "proofSuite": wire::PROOF_SUITE,
            "proofPublicKey": hex_public(&keys().proof),
        },
        "requestedAt": REQUESTED_AT,
        "expiresAt": SESSION_EXPIRES_AT,
    })
}

fn session_commitment(core: &Value) -> String {
    wire::digest(&wire::canonical(core))
}

/// Evidence for one slot: the factor key signs the commitment and the slot.
fn evidence(core: &Value, key: &SigningKey, component: &str, slot: &str) -> Value {
    let message = wire::factor_message(&session_commitment(core), component, slot);
    json!({
        "factor": format!("{}{}", wire::FACTOR_ED25519_SESSION, hex_public(key)),
        "signature": STANDARD.encode(crypto::sign(key, &message)),
    })
}

/// This trustee's variant of the session: only its own evidence.
fn session_document_with(core: Value, evidence: Value) -> Vec<u8> {
    let mut session = core;
    session["candidateEvidence"] = evidence;
    signed(session, "candidateProof", &keys().proof)
}

fn session_document() -> Vec<u8> {
    let core = session_core();
    let evidence = evidence(&core, &keys().factor, COMPONENT, &"51".repeat(32));
    session_document_with(core, json!([evidence]))
}

/// Everything deterministic, as the answers other implementations check.
fn vectors() -> Value {
    let keys = keys();
    let core = session_core();
    let destination_keys_digest = wire::destination_keys_digest(&core["destination"]);
    let context = context();
    json!({
        "bindingVersion": wire::BINDING_VERSION,
        "note": "Test keys and a public test share only. The artifact ciphertext is synthetic.",
        "seeds": {
            "holderAuthorization": hex::encode([0x11u8; 32]),
            "factor": hex::encode([0x22u8; 32]),
            "trusteeOperator": hex::encode([0x33u8; 32]),
            "trusteeHpkePrivateKey": hex::encode(keys.trustee_hpke),
            "destinationHpkePrivateKey": hex::encode(keys.destination_hpke),
            "sessionProof": hex::encode([0x66u8; 32]),
        },
        "publicKeys": {
            "holderAuthorization": hex_public(&keys.holder),
            "factor": hex_public(&keys.factor),
            "trusteeOperator": hex_public(&keys.operator),
            "trusteeHpke": hex::encode(trustee_public_key()),
            "destinationHpke": hex::encode(destination_public_key()),
            "sessionProof": hex_public(&keys.proof),
        },
        "trusteeComponentId": COMPONENT,
        "trusteeKeyId": wire::key_digest(&trustee_public_key()),
        "authorizationKeyDigest": context.authorization_key_digest,
        "artifactDigest": artifact_digest(),
        "enrollmentInfo": String::from_utf8(context.info()).unwrap(),
        "sessionCommitment": session_commitment(&core),
        "factorMessage": String::from_utf8(wire::factor_message(&session_commitment(&core), COMPONENT, &context.slot)).unwrap(),
        "destinationKeysDigest": destination_keys_digest,
        "recoveryInfo": String::from_utf8(wire::recovery_info(&"5e".repeat(32), &context, &destination_keys_digest, SESSION_EXPIRES_AT)).unwrap(),
        "times": {"enrolledAt": ENROLLED_AT, "releasedAt": RELEASED_AT},
    })
}

fn seal_envelope(envelope: &[u8], context: &EnrollmentContext) -> Vec<u8> {
    crypto::seal(&trustee_public_key(), &context.info(), envelope).unwrap()
}

fn accept(envelope: &[u8], context: &EnrollmentContext) -> Result<Enrollment, Code> {
    trustee().accept_enrollment(context, &seal_envelope(envelope, context), at(ENROLLED_AT))
}

/// Byte-compare `bytes` with a committed fixture, or rewrite it.
fn pin(path: &str, bytes: &[u8]) {
    if regenerating() {
        std::fs::write(fixtures().join(path), bytes).unwrap();
    } else {
        assert!(
            read(path) == bytes,
            "{path} differs; regenerate deliberately if intended"
        );
    }
}

#[test]
fn binding_vectors_reproduce_and_verify() {
    let trustee = trustee();
    let context = context();

    pin("binding/envelope.json", &envelope_document());
    pin("binding/protected-artifact.json", &artifact_document());
    pin("binding/session.json", &session_document());
    let mut answers = serde_json::to_vec_pretty(&vectors()).unwrap();
    answers.push(b'\n');
    pin("binding/vectors.json", &answers);

    if regenerating() {
        let sealed = seal_envelope(&envelope_document(), &context);
        let enrollment = json!({
            "context": context,
            "trusteeKeyId": trustee.key_id(),
            "sealedEnvelope": STANDARD.encode(&sealed),
        });
        pin("binding/enrollment.json", &wire::canonical(&enrollment));
        let accepted = trustee
            .accept_enrollment(&context, &sealed, at(ENROLLED_AT))
            .unwrap();
        let session = trustee.verify_session(&session_document()).unwrap();
        let contribution = trustee
            .release(&accepted, &sealed, &session, at(RELEASED_AT))
            .unwrap();
        pin("binding/contribution.json", &contribution.canonical);
    }

    // Enrollment: the committed sealed envelope opens to the committed
    // envelope under the committed context, and the trustee accepts it.
    let enrollment = read_json("binding/enrollment.json");
    assert_eq!(
        serde_json::from_value::<EnrollmentContext>(enrollment["context"].clone()).unwrap(),
        context
    );
    assert_eq!(enrollment["trusteeKeyId"], json!(trustee.key_id()));
    let sealed = STANDARD
        .decode(enrollment["sealedEnvelope"].as_str().unwrap())
        .unwrap();
    let opened = crypto::open(&trustee.hpke_key, &context.info(), &sealed).unwrap();
    assert_eq!(opened.as_slice(), read("binding/envelope.json"));
    let accepted = trustee
        .accept_enrollment(&context, &sealed, at(ENROLLED_AT))
        .unwrap();
    assert_eq!(
        (
            accepted.member_index,
            accepted.member_threshold,
            accepted.member_count
        ),
        (1, 2, 3)
    );
    assert_eq!(accepted.policy.cooldown_secs, 2 * DAY);
    assert_eq!(
        trustee.check_artifact(&accepted, &read("binding/protected-artifact.json")),
        Ok(())
    );

    // Session: verifies, binds this enrollment, and carries valid evidence.
    let session = trustee
        .verify_session(&read("binding/session.json"))
        .unwrap();
    assert!(session.binds(&context));
    assert_eq!(trustee.check_factor(&accepted, &session), Ok(()));
    assert_eq!(
        json!(session.session_commitment),
        vectors()["sessionCommitment"]
    );

    // Contribution: signed by the operator key, bound to this session, and
    // carrying exactly the holder-signed envelope.
    let mut contribution = wire::parse(&read("binding/contribution.json")).unwrap();
    let signature = contribution
        .as_object_mut()
        .unwrap()
        .remove("signature")
        .unwrap();
    let signature: [u8; 64] = STANDARD
        .decode(signature.as_str().unwrap())
        .unwrap()
        .try_into()
        .unwrap();
    let operator = keys().operator.verifying_key().to_bytes();
    assert_eq!(
        crypto::verify(&operator, &wire::canonical(&contribution), &signature),
        Ok(())
    );
    for (field, expected) in [
        ("sessionId", json!("5e".repeat(32))),
        ("enrollmentId", json!(context.enrollment_id)),
        ("enrollmentSequence", json!(1)),
        ("componentId", json!(COMPONENT)),
        ("slot", json!(context.slot)),
        ("decision", json!("approved")),
        (
            "destinationKeysDigest",
            vectors()["destinationKeysDigest"].clone(),
        ),
        ("decidedAt", json!(RELEASED_AT)),
        ("expiresAt", json!(SESSION_EXPIRES_AT)),
    ] {
        assert_eq!(contribution[field], expected, "{field}");
    }
    let sealed = STANDARD
        .decode(contribution["sealedContribution"].as_str().unwrap())
        .unwrap();
    let destination = crypto::hpke_private_key(&keys().destination_hpke).unwrap();
    let info = vectors()["recoveryInfo"]
        .as_str()
        .unwrap()
        .as_bytes()
        .to_vec();
    let released = crypto::open(&destination, &info, &sealed).unwrap();
    assert_eq!(released.as_slice(), read("binding/envelope.json"));
}

// ---------------------------------------------------------------------------
// Refusals, binding by binding

#[test]
fn every_enrollment_binding_is_enforced() {
    let envelope = envelope_document();
    assert!(accept(&envelope, &context()).is_ok());

    // A context the envelope does not repeat never opens: `info` binds it.
    type Mutation = fn(&mut EnrollmentContext);
    let mutations: [(&str, Mutation); 9] = [
        ("enrollmentId", |c| c.enrollment_id = "e2".repeat(32)),
        ("enrollmentSequence", |c| c.enrollment_sequence = 2),
        ("policyDigest", |c| {
            c.policy_digest = wire::digest(b"other policy")
        }),
        ("artifactId", |c| c.artifact_id = "a2".repeat(32)),
        ("artifactDigest", |c| {
            c.artifact_digest = wire::digest(b"other artifact")
        }),
        ("slot", |c| c.slot = "52".repeat(32)),
        ("trusteeChallenge", |c| {
            c.trustee_challenge = "c2".repeat(32)
        }),
        ("authorizationKeyDigest", |c| {
            c.authorization_key_digest = wire::digest(b"other key")
        }),
        ("trusteeComponentId", |c| {
            c.trustee_component_id = "onym:component:other".into()
        }),
    ];
    for (name, mutate) in mutations {
        let mut other = context();
        mutate(&mut other);
        // Sealed under the other context, so only the envelope comparison
        // (or the component check) can catch it.
        assert_eq!(
            accept(&envelope, &other),
            Err(Code::InvalidEnrollment),
            "{name}"
        );
        // Sealed under the right context, opened with the other one.
        let sealed = seal_envelope(&envelope, &context());
        assert_eq!(
            trustee().accept_enrollment(&other, &sealed, at(ENROLLED_AT)),
            Err(Code::InvalidEnrollment),
            "{name}"
        );
    }

    let mut other_profile = context();
    other_profile.implementation_profile_id =
        "onym:recovery-implementation:cloud-custody-v1".into();
    assert_eq!(
        accept(&envelope, &other_profile),
        Err(Code::UnsupportedProfile)
    );

    let mut truncated = seal_envelope(&envelope, &context());
    truncated.pop();
    assert_eq!(
        trustee().accept_enrollment(&context(), &truncated, at(ENROLLED_AT)),
        Err(Code::InvalidEnrollment)
    );
}

#[test]
fn envelope_contents_are_checked() {
    let context = context();
    let holder = keys().holder;
    let official = read_json("slip39/official-decoded.json");
    let extendable = official["cases"]
        .as_array()
        .unwrap()
        .iter()
        .find(|case| {
            let reference = &case["reference"];
            reference["extendable"] == json!(true)
                && reference["memberThreshold"] == json!(2)
                && reference["valueBytes"] == json!(32)
        })
        .map(|case| case["mnemonic"].clone())
        .unwrap();
    let mut corrupted: Vec<String> = share().split(' ').map(str::to_owned).collect();
    corrupted[10] = if corrupted[10] == "academic" {
        "acid"
    } else {
        "academic"
    }
    .into();
    let factor = envelope_value()["trusteePolicy"]["candidateFactors"][0].clone();
    let small_order_factor = format!("{}01{}", wire::FACTOR_ED25519_SESSION, "00".repeat(31));

    // (case, field path, replacement, expected refusal)
    let cases = [
        ("unknown field", "extra", json!(1), Code::InvalidEnrollment),
        (
            "float index",
            "memberIndex",
            json!(1.0),
            Code::InvalidEnrollment,
        ),
        (
            "index mismatch",
            "memberIndex",
            json!(2),
            Code::InvalidEnrollment,
        ),
        (
            "threshold mismatch",
            "memberThreshold",
            json!(3),
            Code::InvalidEnrollment,
        ),
        (
            "threshold above count",
            "memberCount",
            json!(1),
            Code::InvalidEnrollment,
        ),
        (
            "count above 16",
            "memberCount",
            json!(17),
            Code::InvalidEnrollment,
        ),
        (
            "corrupted share",
            "slip39Share",
            json!(corrupted.join(" ")),
            Code::InvalidEnrollment,
        ),
        (
            "extendable share",
            "slip39Share",
            extendable,
            Code::UnsupportedProfile,
        ),
        (
            "other recovery mode",
            "recoveryMode",
            json!("authority-migration"),
            Code::UnsupportedProfile,
        ),
        (
            "other envelope version",
            "shareEnvelopeVersion",
            json!(2),
            Code::UnsupportedProfile,
        ),
        (
            "created in the future",
            "createdAt",
            json!("2026-09-24T00:00:00Z"),
            Code::InvalidEnrollment,
        ),
        (
            "fractional timestamp",
            "createdAt",
            json!("2026-09-23T00:00:00.000Z"),
            Code::InvalidEnrollment,
        ),
        (
            "already expired",
            "expiresAt",
            json!("2026-09-23T06:00:00Z"),
            Code::EnrollmentExpired,
        ),
        (
            "term too long",
            "expiresAt",
            json!("2030-01-01T00:00:00Z"),
            Code::InvalidEnrollment,
        ),
        (
            "two factors",
            "trusteePolicy/candidateFactors",
            json!([factor, factor]),
            Code::InvalidPolicy,
        ),
        (
            "unknown factor type",
            "trusteePolicy/candidateFactors",
            json!(["onym:recovery-factor:sms-code-v1"]),
            Code::InvalidPolicy,
        ),
        (
            "small-order factor key",
            "trusteePolicy/candidateFactors",
            json!([small_order_factor]),
            Code::InvalidPolicy,
        ),
        (
            "cooldown below limit",
            "trusteePolicy/cooldown",
            json!("PT30S"),
            Code::InvalidPolicy,
        ),
        (
            "lifetime within cooldown",
            "trusteePolicy/sessionLifetime",
            json!("P1D"),
            Code::InvalidPolicy,
        ),
        (
            "calendar duration",
            "trusteePolicy/sessionLifetime",
            json!("P1M"),
            Code::InvalidPolicy,
        ),
        (
            "zero attempts",
            "trusteePolicy/maximumAttempts",
            json!(0),
            Code::InvalidPolicy,
        ),
        (
            "no notification",
            "trusteePolicy/notifications",
            json!([]),
            Code::InvalidPolicy,
        ),
        (
            "other veto",
            "trusteePolicy/holderVeto",
            json!("onym:recovery-veto:email-v1"),
            Code::InvalidPolicy,
        ),
    ];
    for (name, path, replacement, expected) in cases {
        let mut envelope = envelope_value();
        let mut field = &mut envelope;
        for key in path.split('/') {
            field = &mut field[key];
        }
        *field = replacement;
        let outcome = accept(&signed(envelope, "holderAuthorization", &holder), &context);
        assert_eq!(outcome.map(|_| ()), Err(expected), "{name}");
    }

    // Signed by a key other than the one the envelope names.
    let impostor = SigningKey::from_bytes(&[0x77; 32]);
    let forged = signed(envelope_value(), "holderAuthorization", &impostor);
    assert_eq!(
        accept(&forged, &context).map(|_| ()),
        Err(Code::InvalidEnrollment)
    );

    // Names and uses another key, but the context pins the holder's digest.
    let mut swapped = envelope_value();
    swapped["authorizationPublicKey"] = json!(hex_public(&impostor));
    let swapped = signed(swapped, "holderAuthorization", &impostor);
    assert_eq!(
        accept(&swapped, &context).map(|_| ()),
        Err(Code::InvalidEnrollment)
    );

    // Duplicate keys, which a last-key-wins parser would silently accept.
    let text = String::from_utf8(envelope_document()).unwrap();
    let duplicated = text.replacen(
        "{\"artifactDigest\"",
        "{\"memberIndex\":2,\"artifactDigest\"",
        1,
    );
    assert_ne!(duplicated, text);
    assert_eq!(
        accept(duplicated.as_bytes(), &context).map(|_| ()),
        Err(Code::InvalidEnrollment)
    );
}

#[test]
fn artifact_header_must_match_the_enrollment() {
    let trustee = trustee();
    let enrollment = accept(&envelope_document(), &context()).unwrap();
    assert_eq!(
        trustee.check_artifact(&enrollment, &artifact_document()),
        Ok(())
    );

    let with = |mutate: &dyn Fn(&mut Value), redigest: bool| {
        let mut artifact = artifact_header();
        mutate(&mut artifact);
        let digest = if redigest {
            wire::digest(&wire::canonical(&artifact))
        } else {
            artifact_digest()
        };
        artifact["artifactDigest"] = json!(digest);
        trustee.check_artifact(&enrollment, &wire::canonical(&artifact))
    };
    // A changed header with a stale digest, and a re-digested header the
    // envelope never signed, both mismatch.
    assert_eq!(
        with(&|a| a["artifactId"] = json!("a2".repeat(32)), false),
        Err(Code::ArtifactMismatch)
    );
    assert_eq!(
        with(&|a| a["artifactId"] = json!("a2".repeat(32)), true),
        Err(Code::ArtifactMismatch)
    );
    assert_eq!(
        with(&|a| a["enrollmentSequence"] = json!(2), true),
        Err(Code::ArtifactMismatch)
    );
    assert_eq!(
        with(&|a| a["protectionParameters"]["nonce"] = json!("00"), true),
        Err(Code::InvalidEnrollment)
    );
    assert_eq!(
        with(&|a| a["ciphertext"] = json!(""), true),
        Err(Code::InvalidEnrollment)
    );
}

#[test]
fn sessions_are_verified_before_any_enrollment_lookup() {
    let trustee = trustee();
    assert!(trustee.verify_session(&session_document()).is_ok());

    // Any change after signing breaks the candidate proof.
    let mut tampered = wire::parse(&session_document()).unwrap();
    tampered["expiresAt"] = json!("2026-10-07T00:00:00Z");
    assert_eq!(
        trustee
            .verify_session(&wire::canonical(&tampered))
            .map(|_| ()),
        Err(Code::InvalidRequest)
    );

    let with_destination = |mutate: &dyn Fn(&mut Value)| {
        let mut core = session_core();
        mutate(&mut core["destination"]);
        let evidence = evidence(&core, &keys().factor, COMPONENT, &"51".repeat(32));
        trustee
            .verify_session(&session_document_with(core, json!([evidence])))
            .map(|_| ())
    };
    assert_eq!(
        with_destination(
            &|d| d["encryptionSuite"] = json!("hpke-base-x25519-hkdf-sha256-chacha20poly1305")
        ),
        Err(Code::InvalidDestination)
    );
    assert_eq!(
        with_destination(&|d| d["encryptionPublicKey"] = json!("00".repeat(32))),
        Err(Code::InvalidDestination)
    );
    // The proof key must be the one that signed.
    assert_eq!(
        with_destination(&|d| d["proofPublicKey"] = json!(hex_public(&keys().holder))),
        Err(Code::InvalidRequest)
    );
}

#[test]
fn factor_evidence_is_bound_to_session_and_slot() {
    let trustee = trustee();
    let enrollment = accept(&envelope_document(), &context()).unwrap();
    let core = session_core();
    let slot = "51".repeat(32);
    let check = |evidence: Value| {
        let session = trustee
            .verify_session(&session_document_with(core.clone(), evidence))
            .unwrap();
        assert!(session.binds(&enrollment.context));
        trustee.check_factor(&enrollment, &session)
    };
    let ours = evidence(&core, &keys().factor, COMPONENT, &slot);
    assert_eq!(check(json!([ours])), Ok(()));

    let other_slot = evidence(&core, &keys().factor, COMPONENT, &"52".repeat(32));
    let other_trustee = evidence(&core, &keys().factor, "onym:component:other", &slot);
    let other_key = evidence(
        &core,
        &SigningKey::from_bytes(&[0x77; 32]),
        COMPONENT,
        &slot,
    );
    let mut other_session = session_core();
    other_session["sessionId"] = json!("5f".repeat(32));
    let replayed = evidence(&other_session, &keys().factor, COMPONENT, &slot);
    for (name, presented) in [
        ("another slot", json!([other_slot])),
        ("another trustee", json!([other_trustee])),
        ("an unenrolled key", json!([other_key])),
        ("another session", json!([replayed])),
        ("no evidence", json!([])),
        ("two presentations", json!([ours, ours])),
    ] {
        assert_eq!(
            check(presented),
            Err(Code::InvalidCandidateFactor),
            "{name}"
        );
    }
}

#[test]
fn release_seals_to_this_session_only() {
    let trustee = trustee();
    let context = context();
    let sealed = seal_envelope(&envelope_document(), &context);
    let enrollment = trustee
        .accept_enrollment(&context, &sealed, at(ENROLLED_AT))
        .unwrap();
    let session = trustee.verify_session(&session_document()).unwrap();

    let contribution = trustee
        .release(&enrollment, &sealed, &session, at(RELEASED_AT))
        .unwrap();
    let value = wire::parse(&contribution.canonical).unwrap();
    let sealed_contribution = STANDARD
        .decode(value["sealedContribution"].as_str().unwrap())
        .unwrap();
    assert_eq!(
        contribution.sealed_digest,
        wire::digest(&sealed_contribution)
    );

    // The destination opens it only under this session's exact `info`.
    let destination = crypto::hpke_private_key(&keys().destination_hpke).unwrap();
    let info = vectors()["recoveryInfo"]
        .as_str()
        .unwrap()
        .as_bytes()
        .to_vec();
    assert!(crypto::open(&destination, &info, &sealed_contribution).is_ok());
    let other_session = wire::recovery_info(
        &"5f".repeat(32),
        &context,
        &session.destination_keys_digest,
        SESSION_EXPIRES_AT,
    );
    assert!(crypto::open(&destination, &other_session, &sealed_contribution).is_err());

    // A sealed envelope swapped in from another enrollment does not open
    // under the stored bindings, even though anyone can seal to the key.
    let mut other = context.clone();
    other.enrollment_id = "e2".repeat(32);
    let swapped = seal_envelope(&envelope_document(), &other);
    assert_eq!(
        trustee.release(&enrollment, &swapped, &session, at(RELEASED_AT)),
        Err(Code::TemporarilyUnavailable)
    );

    // A session for another enrollment is refused outright.
    let mut unbound = session.clone();
    unbound.enrollment_id = "e2".repeat(32);
    assert_eq!(
        trustee.release(&enrollment, &sealed, &unbound, at(RELEASED_AT)),
        Err(Code::InvalidRequest)
    );
}

#[test]
fn manifests_are_signed_and_stay_valid() {
    let trustee = trustee();
    let service = onym_recovery_trustee::Service {
        endpoint: "https://trustee.example/v1/trustee".into(),
        trust_domain: "trustee.example".into(),
        jurisdiction: "none".into(),
        contact: "none".into(),
    };
    let now = at(ENROLLED_AT);
    let manifest = trustee.manifest(&service, now).unwrap();
    let mut value = wire::parse(&manifest).unwrap();
    let signature = value.as_object_mut().unwrap().remove("signature").unwrap();
    let signature: [u8; 64] = STANDARD
        .decode(signature.as_str().unwrap())
        .unwrap()
        .try_into()
        .unwrap();
    let operator = keys().operator.verifying_key().to_bytes();
    assert_eq!(
        crypto::verify(&operator, &wire::canonical(&value), &signature),
        Ok(())
    );
    assert_eq!(
        value["operator"],
        json!(format!("onym:key:{}", hex::encode(operator)))
    );
    // The offer spine Onym clients decode: an ID, a model, a service object.
    let offer = &value["offers"][0];
    assert_eq!(
        (&offer["offerId"], &offer["model"]),
        (&json!("free-v1"), &json!("free"))
    );
    assert!(offer["service"].is_object());

    // Valid 60 to 90 days ahead, on a grid: the same bytes until it moves.
    let valid_until = at(value["validUntil"].as_str().unwrap());
    assert!((now + 60 * DAY..=now + 90 * DAY).contains(&valid_until));
    let grid = valid_until - 90 * DAY;
    assert_eq!(
        trustee.manifest(&service, grid).unwrap(),
        trustee.manifest(&service, grid + 30 * DAY - 1).unwrap()
    );
    assert_ne!(
        trustee.manifest(&service, grid).unwrap(),
        trustee.manifest(&service, grid + 30 * DAY).unwrap()
    );
}
