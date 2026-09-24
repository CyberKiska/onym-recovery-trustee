#!/usr/bin/env python3
"""Holder and candidate client for the Onym recovery trustee (binding draft-1).

A demo client, not a vault: keys live in plain files and the protected
artifact is synthetic. Shares are split and combined by Trezor's reference
SLIP-0039 implementation; HPKE, Ed25519 and AES-GCM come from
pyca/cryptography. Nothing here shares code with the trustee.

  enroll          split a fresh recovery key t-of-n across trustees
  poll            show every trustee's recovery sessions (the holder's notice)
  veto            cancel a recovery session at every trustee, as the holder
  close           close the enrollment at every trustee, as the holder
  recover         begin or resume a session, wait out the cooldown, combine t shares
  share-fixtures  regenerate tests/fixtures/slip39
"""

import argparse
import base64
import hashlib
import json
import os
import re
import secrets
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from http.client import HTTPException
from pathlib import Path

from cryptography.exceptions import InvalidSignature, InvalidTag
from cryptography.hazmat.primitives import hpke
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from shamir_mnemonic import combine_mnemonics, generate_mnemonics
from shamir_mnemonic.share import Share
from shamir_mnemonic.utils import MnemonicError

FIXTURES = Path(__file__).resolve().parent.parent / "tests" / "fixtures" / "slip39"

BINDING = "draft-1"
PROFILE = "onym:recovery-implementation:shamir-trustees-slip39-v1"
RECOVERY_PROFILE = "onym:recovery-profile:trustee-v1"
RECOVERY_MODE = "secret-restoration"
ENCRYPTION_SUITE = "hpke-base-x25519-hkdf-sha256-aes-256-gcm"
FACTOR = "onym:recovery-factor:ed25519-session-v1:"
NOTICE = "onym:recovery-notice:holder-poll-v1"
VETO = "onym:recovery-veto:authorization-key-v1"
LAPSE = "onym:recovery-lapse:none-v1"
# The demo's artifact payload: a synthetic secret and the scoped keys.
PAYLOAD_SCHEMA = "onym:recovery-payload:synthetic-demo-v1"

MAX_SAFE_INTEGER = 2**53 - 1
# Far above any manifest, receipt or contribution this binding produces.
MAX_RESPONSE_BYTES = 1 << 20

# RFC 9180 Base mode, KEM 0x0020, KDF 0x0001, AEAD 0x0002; output enc || ct.
HPKE = hpke.Suite(hpke.KEM.X25519, hpke.KDF.HKDF_SHA256, hpke.AEAD.AES_256_GCM)

# The enrollment context, in `info` order (binding §4).
CONTEXT = (
    "implementationProfileId", "enrollmentId", "enrollmentSequence", "policyDigest", "artifactId",
    "artifactDigest", "trusteeComponentId", "slot", "trusteeChallenge", "authorizationKeyDigest",
)
# A contribution's bindings, in recovery `info` order (Shamir §6.2).
CONTRIBUTION = (
    "sessionId", "enrollmentId", "enrollmentSequence", "policyDigest", "artifactId", "artifactDigest",
    "componentId", "slot", "destinationKeysDigest", "expiresAt",
)
# Every field of a signed contribution (binding §6.5), and no other.
CONTRIBUTION_FIELDS = {*CONTRIBUTION, "contributionVersion", "decision", "sealedContribution", "decidedAt", "signature"}


# ---------------------------------------------------------------------------
# Encodings (binding §§2-4)


def canonical(value):
    """Discovery §3 bytes: sorted keys, no whitespace, minimal escaping."""
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def parse(raw):
    """A JSON object, refusing duplicate keys at any depth, floats and non-finite numbers."""

    def unique(pairs):
        if len({key for key, _ in pairs}) != len(pairs):
            raise ValueError("duplicate key")
        return dict(pairs)

    def refuse(constant):
        raise ValueError(f"not an integer: {constant}")

    value = json.loads(raw, object_pairs_hook=unique, parse_float=refuse, parse_constant=refuse)
    if not isinstance(value, dict):
        raise ValueError("not an object")
    return value


def digest(data):
    return "sha256:" + hashlib.sha256(data).hexdigest()


def b64(data):
    return base64.b64encode(data).decode()


def unb64(text):
    """Strict padded base64: one spelling per byte string, as in Rust."""
    data = base64.b64decode(text, validate=True)
    if b64(data) != text:
        raise ValueError("non-canonical base64")
    return data


def hex32(text):
    """Exactly 64 lowercase hex digits; `bytes.fromhex` alone accepts more."""
    if not re.fullmatch(r"[0-9a-f]{64}", text):
        raise ValueError("expected 64 lowercase hex digits")
    return bytes.fromhex(text)


def uint(value):
    """A JSON integer in 0..2^53-1; a boolean is not one."""
    if type(value) is not int or not 0 <= value <= MAX_SAFE_INTEGER:
        raise ValueError(f"not an unsigned integer: {value!r}")
    return value


def timestamp(seconds):
    return datetime.fromtimestamp(int(seconds), timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def seconds(text):
    """Exactly `YYYY-MM-DDTHH:MM:SSZ`; any other spelling is refused, as in Rust."""
    value = int(datetime.strptime(text, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc).timestamp())
    if timestamp(value) != text:
        raise ValueError(f"timestamp: {text}")
    return value


def duration(text):
    """Seconds in `P[nD][T[nH][nM][nS]]`, the subset the binding allows."""
    match = re.fullmatch(r"P(?:(\d{1,6})D)?(?:T(?:(\d{1,6})H)?(?:(\d{1,6})M)?(?:(\d{1,6})S)?)?", text)
    if not match or text in ("P", "PT") or text.endswith("T"):
        raise ValueError(f"duration: {text}")
    days, hours, minutes, secs = (int(part or 0) for part in match.groups())
    return ((days * 24 + hours) * 60 + minutes) * 60 + secs


def random_id():
    return secrets.token_hex(32)


def public_hex(key):
    return key.public_key().public_bytes_raw().hex()


def private_hex(key):
    return key.private_bytes_raw().hex()


def ed25519(private):
    return Ed25519PrivateKey.from_private_bytes(hex32(private))


def sign(value, field, key):
    """Sign `value` over its canonical bytes into `field`; returns `value`."""
    value[field] = b64(key.sign(canonical(value)))
    return value


def verify(value, field, public):
    """Check that `field` signs the rest of `value`; raises InvalidSignature."""
    rest = {key: item for key, item in value.items() if key != field}
    Ed25519PublicKey.from_public_bytes(hex32(public)).verify(unb64(value[field]), canonical(rest))


def artifact_aad(header):
    """Shamir §4.2 associated data."""
    return canonical([
        header["implementationProfileId"], header["enrollmentId"], header["enrollmentSequence"],
        header["policyDigest"], header["identityBindingCommitment"], header["recoveryMode"],
        header["artifactId"],
    ])


def identity_commitment(salt, subject, descriptor):
    """Abstract §5.5: the policy's subject commitment, salted so trustees
    cannot link enrollments by it."""
    return digest(canonical(["onym-recovery-identity-binding-v1", salt, subject, descriptor]))


def expect(value, fields, what):
    """Require each field to equal its expected value, type included."""
    mismatched = sorted(key for key, item in fields.items() if canonical(value.get(key)) != canonical(item))
    if mismatched:
        raise ValueError(f"{what}: unexpected {', '.join(mismatched)}")


# ---------------------------------------------------------------------------
# Transport


class Refused(Exception):
    """A trustee's refusal: HTTP status, stable code and the raw body."""

    def __init__(self, status, body):
        self.status, self.body = status, body
        try:
            self.code = parse(body).get("error")
        except ValueError:
            self.code = None
        super().__init__(f"{status} {self.code}")


# Every way one trustee can fail: its refusal, the network, or a response
# that does not verify. Callers keep other trustees going on any of these.
FAILURES = (Refused, OSError, HTTPException, ValueError, KeyError, TypeError, InvalidSignature, InvalidTag)


def transient(error):
    """Worth retrying later: the trustee was unreachable or said so."""
    return isinstance(error, (OSError, HTTPException)) or isinstance(error, Refused) and error.status == 503


def describe(error):
    """One line naming a failure, never echoing a request."""
    return str(error) if isinstance(error, (Refused, ValueError, OSError)) else type(error).__name__


class NoRedirect(urllib.request.HTTPRedirectHandler):
    """A redirect is refused, not followed: requests go only where pinned."""

    def redirect_request(self, *args, **kwargs):
        return None


OPENER = urllib.request.build_opener(NoRedirect)


def check_url(url):
    """https, or plain http to this machine for local demos."""
    parts = urllib.parse.urlsplit(url)
    local = parts.scheme == "http" and parts.hostname in ("127.0.0.1", "localhost")
    if not (parts.scheme == "https" or local) or parts.username or parts.query or parts.fragment:
        raise ValueError(f"not an https URL: {url}")


def send(url, body=None):
    """GET, or POST `body`; returns at most MAX_RESPONSE_BYTES of response."""
    check_url(url)
    request = urllib.request.Request(url, data=body, headers={"content-type": "application/json"})

    def read(response):
        data = response.read(MAX_RESPONSE_BYTES + 1)
        if len(data) > MAX_RESPONSE_BYTES:
            raise ValueError("response too large")
        return data

    try:
        with OPENER.open(request, timeout=30) as response:
            return read(response)
    except urllib.error.HTTPError as error:
        raise Refused(error.code, read(error)) from None


class Trustee:
    """One trustee, as its signed manifest describes it.

    The manifest's own key signs it, so the first fetch is trust on first
    use over HTTPS. Pinned copies in a map or holder file load with
    `current=False`: they may have expired, and stand as evidence of the
    keys enrolled with. `refreshed` checks what the trustee serves now."""

    def __init__(self, manifest, current=True):
        self.operator = manifest["operator"].removeprefix("onym:key:")
        verify(manifest, "signature", self.operator)
        key = manifest["enrollmentKey"]
        usable = (
            manifest["bindingVersion"] == BINDING
            and PROFILE in manifest["implementationProfileIds"]
            and key["suite"] == ENCRYPTION_SUITE
            and key["trusteeKeyId"] == digest(hex32(key["publicKey"]))
            and manifest["endpoints"][0].endswith("/v1/trustee")
            and (not current or seconds(manifest["validUntil"]) > time.time())
        )
        if not usable:
            raise ValueError(f"unusable manifest: {manifest['componentId']}")
        self.manifest = manifest
        self.component_id = manifest["componentId"]
        self.endpoint = manifest["endpoints"][0]
        check_url(self.endpoint)
        self.enrollment_key = X25519PublicKey.from_public_bytes(hex32(key["publicKey"]))
        self.key_id = key["trusteeKeyId"]

    @classmethod
    def fetch(cls, origin):
        return cls(parse(send(origin.rstrip("/") + "/manifest.json")))

    def refreshed(self):
        """The trustee's current manifest, which must keep this component,
        operator key and enrollment key. The draft defines no key rotation,
        so any change is refused rather than trusted."""
        current = Trustee.fetch(self.endpoint.removesuffix("/v1/trustee"))
        if (current.component_id, current.operator, current.key_id) != (self.component_id, self.operator, self.key_id):
            raise ValueError(f"{self.component_id}: the trustee's keys changed")
        return current

    def post(self, request):
        """Send one request; returns the raw response bytes."""
        return send(self.endpoint, canonical(request))

    def call(self, request, operation, request_id):
        """Send a request; returns its receipt, signature and echo checked."""
        receipt = parse(self.post(request))
        verify(receipt, "signature", self.operator)
        answer = {"receiptVersion": 1, "componentId": self.component_id, "operation": operation,
                  "requestId": request_id}
        expect(receipt, answer, "receipt")
        return receipt

    def signed(self, operation, key, target, by=None):
        """A request signed by `key` acting on `target`: (field, id)."""
        request = {
            "requestVersion": 1,
            "operation": operation,
            "requestId": random_id(),
            "componentId": self.component_id,
            "issuedAt": timestamp(time.time()),
            target[0]: target[1],
        }
        if by:
            request["by"] = by
        return sign(request, "signature", key)


# ---------------------------------------------------------------------------
# Checks on what a map holds


def check_policy(policy):
    """The private policy under this profile; returns t and its slots."""
    expect(policy, {"policyVersion": 1, "recoveryMode": RECOVERY_MODE, "implementationProfileId": PROFILE}, "policy")
    entries = policy["trustees"]
    rule = re.fullmatch(r"slip39-(\d+)-of-(\d+)", policy["approvalRule"])
    if not rule:
        raise ValueError("policy: approval rule")
    threshold, count = int(rule[1]), int(rule[2])
    slots = {hex32(entry["slot"]) for entry in entries}
    components = {entry["componentId"] for entry in entries}
    if not (2 <= threshold <= count <= 16 and count == len(entries) == len(slots) == len(components)):
        raise ValueError("policy: threshold, slots or trustees")
    seconds(policy["expiresAt"])
    return threshold, entries


def check_artifact(protected, policy):
    """The protected artifact's digest, and a header bound to this policy."""
    rest = {key: item for key, item in protected.items() if key != "artifactDigest"}
    if digest(canonical(rest)) != protected["artifactDigest"]:
        raise ValueError("artifact digest")
    expect(protected, {
        "protectedArtifactVersion": 1,
        "implementationProfileId": PROFILE,
        "policyDigest": digest(canonical(policy)),
        "identityBindingCommitment": policy["identityBindingCommitment"],
        "recoveryMode": RECOVERY_MODE,
    }, "artifact header")
    uint(protected["enrollmentSequence"])
    hex32(protected["enrollmentId"])
    hex32(protected["artifactId"])


def check_enrollment_receipt(receipt, protected, entry):
    """An enroll receipt naming exactly this slot's custody."""
    expect(receipt, {
        "componentId": entry["componentId"],
        "implementationProfileId": PROFILE,
        "enrollmentId": protected["enrollmentId"],
        "enrollmentSequence": protected["enrollmentSequence"],
        "policyDigest": protected["policyDigest"],
        "artifactId": protected["artifactId"],
        "artifactDigest": protected["artifactDigest"],
        "slot": entry["slot"],
        "oldState": "none",
        "newState": "active",
    }, "enrollment receipt")


# ---------------------------------------------------------------------------
# Holder: enrollment, poll, veto, closure


class Enrollment:
    """A fresh t-of-n enrollment, prepared without contacting anyone. The
    holder's keys and the factor keys exist before the first request, so a
    caller can save them first and can always close what was accepted."""

    def __init__(self, trustees, threshold, cooldown, lifetime, attempts, payload="synthetic demo secret",
                 term_days=365):
        count = len(trustees)
        if len({trustee.component_id for trustee in trustees}) != count:
            raise ValueError("a trustee appears twice")
        if not 2 <= threshold <= count <= 16:
            raise ValueError("the profile needs 2 <= threshold <= trustees <= 16")
        if len({trustee.manifest["trustDomain"] for trustee in trustees}) != count:
            print("warning: trustees share a declared trust domain; they are not independent", file=sys.stderr)

        now = int(time.time())
        ruk = os.urandom(32)
        self.threshold = threshold
        self.enrollment_id, artifact_id = random_id(), random_id()
        # A real vault commits to its identity and descriptor; these stand in.
        salt, subject, descriptor = random_id(), "onym:key:" + random_id(), digest(b"synthetic descriptor")
        identity = identity_commitment(salt, subject, descriptor)
        self.slots = [
            {"trustee": trustee, "slot": random_id(), "authorization": Ed25519PrivateKey.generate(),
             "factor": Ed25519PrivateKey.generate()}
            for trustee in trustees
        ]
        for slot in self.slots:
            slot["policy"] = {
                "candidateFactors": [FACTOR + public_hex(slot["factor"])],
                "cooldown": cooldown,
                "sessionLifetime": lifetime,
                "maximumAttempts": attempts,
                "notifications": [NOTICE],
                "holderVeto": VETO,
                "lapsePolicy": LAPSE,
            }
        # Holder-private: a trustee sees only its digest.
        self.policy = {
            "policyVersion": 1,
            "policyId": random_id(),
            "recoveryMode": RECOVERY_MODE,
            "identityBindingCommitment": identity,
            "implementationProfileId": PROFILE,
            "trustees": [
                {"componentId": slot["trustee"].component_id, "slot": slot["slot"],
                 "authorizationPublicKey": public_hex(slot["authorization"]), "trusteePolicy": slot["policy"]}
                for slot in self.slots
            ],
            "approvalRule": f"slip39-{threshold}-of-{count}",
            "createdAt": timestamp(now),
            "expiresAt": timestamp(now + term_days * 86_400),
        }

        header = {
            "protectedArtifactVersion": 1,
            "implementationProfileId": PROFILE,
            "enrollmentId": self.enrollment_id,
            "enrollmentSequence": 1,
            "policyDigest": digest(canonical(self.policy)),
            "identityBindingCommitment": identity,
            "recoveryMode": RECOVERY_MODE,
            "artifactId": artifact_id,
        }
        # Abstract §5.5. The payload carries the scoped keys, so a recovered
        # vault regains authority over the enrollment (a stand-in for
        # identity §10 seat keys).
        artifact = {
            "artifactVersion": 1,
            "artifactId": artifact_id,
            "recoveryMode": RECOVERY_MODE,
            "identitySubject": subject,
            "descriptorDigest": descriptor,
            "identityBindingSalt": salt,
            "payloadSchema": PAYLOAD_SCHEMA,
            "payload": {
                "secret": payload,
                "authorizationKeys": {
                    slot["trustee"].component_id: private_hex(slot["authorization"]) for slot in self.slots
                },
            },
            "createdAt": timestamp(now),
        }
        nonce = os.urandom(12)
        self.protected = dict(
            header,
            protectionParameters={"aead": "aes-256-gcm", "nonce": nonce.hex()},
            ciphertext=b64(AESGCM(ruk).encrypt(nonce, canonical(artifact), artifact_aad(header))),
        )
        self.protected["artifactDigest"] = digest(canonical(self.protected))
        [self.shares] = generate_mnemonics(1, [(threshold, count)], ruk, b"", extendable=False, iteration_exponent=0)

        self.holder = {
            "enrollmentId": self.enrollment_id,
            "trustees": [
                {"manifest": slot["trustee"].manifest, "authorizationKey": private_hex(slot["authorization"])}
                for slot in self.slots
            ],
        }
        self.factors = {slot["trustee"].component_id: private_hex(slot["factor"]) for slot in self.slots}

    def run(self, invitations):
        """Enroll every slot, one invitation code each, in trustee order;
        returns the recovery map once all n receipts verify."""
        if len(invitations) != len(self.slots):
            raise ValueError("one invitation per trustee")
        receipts = [self.enroll_slot(index, invitation) for index, invitation in enumerate(invitations)]
        return {
            "recoveryMapVersion": 1,
            "recoveryProfileId": RECOVERY_PROFILE,
            "implementationProfileId": PROFILE,
            "enrollmentId": self.enrollment_id,
            "enrollmentSequence": 1,
            "policy": self.policy,
            "protectedArtifact": self.protected,
            "trusteeManifests": [slot["trustee"].manifest for slot in self.slots],
            "trusteeReceipts": receipts,
        }

    def enroll_slot(self, index, invitation):
        """Redeem an invitation, then seal and deliver one signed envelope."""
        slot, protected = self.slots[index], self.protected
        trustee, authorization = slot["trustee"], slot["authorization"]
        offer = parse(trustee.post({
            "requestVersion": 1, "operation": "issue-challenge",
            "componentId": trustee.component_id, "invitation": invitation,
        }))
        expect(offer, {"componentId": trustee.component_id, "trusteeKeyId": trustee.key_id}, "challenge")
        hex32(offer["challenge"])
        context = {
            "implementationProfileId": PROFILE,
            "enrollmentId": self.enrollment_id,
            "enrollmentSequence": protected["enrollmentSequence"],
            "policyDigest": protected["policyDigest"],
            "artifactId": protected["artifactId"],
            "artifactDigest": protected["artifactDigest"],
            "trusteeComponentId": trustee.component_id,
            "slot": slot["slot"],
            "trusteeChallenge": offer["challenge"],
            "authorizationKeyDigest": digest(authorization.public_key().public_bytes_raw()),
        }
        envelope = {key: context[key] for key in CONTEXT if key != "authorizationKeyDigest"}
        envelope.update({
            "shareEnvelopeVersion": 1,
            "identityBindingCommitment": protected["identityBindingCommitment"],
            "recoveryMode": RECOVERY_MODE,
            "memberIndex": index,
            "memberThreshold": self.threshold,
            "memberCount": len(self.slots),
            "trusteePolicy": slot["policy"],
            "slip39Share": self.shares[index],
            "createdAt": self.policy["createdAt"],
            "expiresAt": self.policy["expiresAt"],
            "authorizationPublicKey": public_hex(authorization),
        })
        sign(envelope, "holderAuthorization", authorization)
        info = canonical(["onym-shamir-enrollment-v1", *(context[key] for key in CONTEXT)])
        sealed = HPKE.encrypt(canonical(envelope), trustee.enrollment_key, info)
        request = {
            "requestVersion": 1,
            "operation": "enroll",
            "context": context,
            "trusteeKeyId": trustee.key_id,
            "sealedEnvelope": b64(sealed),
            "protectedArtifact": protected,
        }
        receipt = trustee.call(request, "enroll", offer["challenge"])
        check_enrollment_receipt(receipt, protected, self.policy["trustees"][index])
        expect(receipt, {"sealedContributionDigest": digest(sealed)}, "enrollment receipt")
        return receipt


def seal_map(recovery_map):
    """Shamir §5.5: AES-256-GCM under a separate key, bound to the profile
    and a random map ID. Returns the sealed map and its key."""
    key, map_id, nonce = os.urandom(32), random_id(), os.urandom(12)
    ciphertext = AESGCM(key).encrypt(nonce, canonical(recovery_map), canonical([PROFILE, map_id]))
    return {"mapId": map_id, "nonce": nonce.hex(), "ciphertext": b64(ciphertext)}, key


def open_map(sealed, key):
    """Decrypt a map and check all of it: the policy's threshold and slots,
    the artifact bound to that policy, and exactly one authentic manifest
    and enroll receipt per slot, in policy order. Returns the map, its
    trustees (as pinned at enrollment) and t."""
    plaintext = AESGCM(key).decrypt(
        bytes.fromhex(sealed["nonce"]), unb64(sealed["ciphertext"]), canonical([PROFILE, sealed["mapId"]])
    )
    recovery_map = parse(plaintext)
    policy, protected = recovery_map["policy"], recovery_map["protectedArtifact"]
    threshold, entries = check_policy(policy)
    check_artifact(protected, policy)
    expect(recovery_map, {
        "recoveryMapVersion": 1, "recoveryProfileId": RECOVERY_PROFILE, "implementationProfileId": PROFILE,
        "enrollmentId": protected["enrollmentId"], "enrollmentSequence": protected["enrollmentSequence"],
    }, "map")
    manifests, receipts = recovery_map["trusteeManifests"], recovery_map["trusteeReceipts"]
    if not len(manifests) == len(receipts) == len(entries):
        raise ValueError("map: one manifest and one receipt per slot")
    trustees = []
    for entry, manifest, receipt in zip(entries, manifests, receipts):
        trustee = Trustee(manifest, current=False)
        if trustee.component_id != entry["componentId"]:
            raise ValueError("map: manifests out of policy order")
        verify(receipt, "signature", trustee.operator)
        expect(receipt, {"receiptVersion": 1, "operation": "enroll"}, "map receipt")
        check_enrollment_receipt(receipt, protected, entry)
        trustees.append(trustee)
    return recovery_map, trustees, threshold


class Holder:
    """The healthy device: one trustee-scoped key per trustee."""

    def __init__(self, enrollment_id, keys):
        self.enrollment_id = enrollment_id
        self.keys = keys  # [(Trustee, Ed25519PrivateKey)]

    @classmethod
    def load(cls, holder):
        keys = [(Trustee(entry["manifest"], current=False), ed25519(entry["authorizationKey"]))
                for entry in holder["trustees"]]
        return cls(holder["enrollmentId"], keys)

    def each(self, operation, target, by=None):
        """One signed request per trustee, each on its own: a failure at one
        never stops the others. Returns (component ID, receipt or error)."""
        results = []
        for trustee, key in self.keys:
            try:
                trustee = trustee.refreshed()
                request = trustee.signed(operation, key, target, by)
                results.append((trustee.component_id, trustee.call(request, operation, request["requestId"])))
            except FAILURES as error:
                results.append((trustee.component_id, error))
        return results

    def poll(self):
        return self.each("read-enrollment", ("enrollmentId", self.enrollment_id))

    def veto(self, session_id):
        return self.each("cancel-recovery", ("sessionId", session_id), by="holder")

    def close(self):
        return self.each("close-enrollment", ("enrollmentId", self.enrollment_id))


# ---------------------------------------------------------------------------
# Candidate: recovery on a fresh device


class Candidate:
    """A recovering device: fresh destination and proof keys, one session.
    `state` resumes a session saved from `state()`; signing is
    deterministic, so a resumed session resends byte-identical requests."""

    def __init__(self, recovery_map, factors, state=None):
        policy, artifact = recovery_map["policy"], recovery_map["protectedArtifact"]
        self.map, self.factors = recovery_map, factors
        self.threshold, entries = check_policy(policy)
        self.slots = {entry["componentId"]: entry for entry in entries}
        self.envelopes, self.contributions = {}, {}
        state = state or {
            "destinationKey": private_hex(X25519PrivateKey.generate()),
            "proofKey": private_hex(Ed25519PrivateKey.generate()),
            "contributions": {},
        }
        self.destination_key = X25519PrivateKey.from_private_bytes(hex32(state["destinationKey"]))
        self.proof_key = ed25519(state["proofKey"])
        self.saved = state["contributions"]
        self.destination = {
            "encryptionSuite": ENCRYPTION_SUITE,
            "encryptionPublicKey": public_hex(self.destination_key),
            "proofSuite": "ed25519",
            "proofPublicKey": public_hex(self.proof_key),
        }
        self.session = state.get("session") or self.new_session(policy)
        expect(self.session, {
            "sessionVersion": 1,
            "enrollmentId": recovery_map["enrollmentId"],
            "enrollmentSequence": recovery_map["enrollmentSequence"],
            "policyDigest": digest(canonical(policy)),
            "artifactId": artifact["artifactId"],
            "artifactDigest": artifact["artifactDigest"],
            "destination": self.destination,
        }, "session")
        self.commitment = digest(canonical(self.session))
        self.destination_keys_digest = digest(canonical(["onym-recovery-destination-keys-v1", self.destination]))

    def new_session(self, policy):
        """A session every trustee can admit: it outlasts the longest
        cooldown, stays inside the shortest lifetime with a margin for
        clock skew, and ends before the enrollment does."""
        now = int(time.time())
        terms = [entry["trusteePolicy"] for entry in policy["trustees"]]
        lifetime = min(duration(term["sessionLifetime"]) for term in terms)
        cooldown = max(duration(term["cooldown"]) for term in terms)
        margin = min(60, (lifetime - cooldown) // 2)
        expires = min(now + lifetime - margin, seconds(policy["expiresAt"]))
        if expires <= now + cooldown + margin:
            raise ValueError("the enrollment ends before a session could outlast its cooldown")
        return {
            "sessionVersion": 1,
            "sessionId": random_id(),
            "enrollmentId": self.map["enrollmentId"],
            "enrollmentSequence": self.map["enrollmentSequence"],
            "policyDigest": digest(canonical(policy)),
            "artifactId": self.map["protectedArtifact"]["artifactId"],
            "artifactDigest": self.map["protectedArtifact"]["artifactDigest"],
            "destination": self.destination,
            "requestedAt": timestamp(now),
            "expiresAt": timestamp(expires),
        }

    def state(self):
        """What a restart needs: the session, its keys and contributions."""
        return {
            "session": self.session,
            "destinationKey": private_hex(self.destination_key),
            "proofKey": private_hex(self.proof_key),
            "contributions": {**self.saved, **self.contributions},
        }

    @property
    def session_id(self):
        return self.session["sessionId"]

    def begin_request(self, trustee, factor=None):
        """This trustee's session variant, carrying only its own evidence."""
        factor = factor or ed25519(self.factors[trustee.component_id])
        message = canonical([
            "onym-recovery-factor-ed25519-session-v1", self.commitment,
            trustee.component_id, self.slots[trustee.component_id]["slot"],
        ])
        evidence = [{"factor": FACTOR + public_hex(factor), "signature": b64(factor.sign(message))}]
        variant = sign(dict(self.session, candidateEvidence=evidence), "candidateProof", self.proof_key)
        return {"requestVersion": 1, "operation": "begin-recovery", "session": variant}

    def begin(self, trustee):
        """Begin at one trustee. Returns its signed receipt: cooling down,
        or refused for the factor, which also spent an attempt."""
        receipt = trustee.call(self.begin_request(trustee), "begin-recovery", self.session_id)
        expect(receipt, {"sessionId": self.session_id, "enrollmentId": self.session["enrollmentId"],
                         "destinationKeysDigest": self.destination_keys_digest}, "session receipt")
        if receipt["newState"] not in ("cooling_down", "refused"):
            raise ValueError(f"session receipt: {receipt['newState']}")
        return receipt

    def read(self, trustee):
        """Poll one trustee; returns its receipt and, once released, the
        verified envelope it contributed."""
        request = trustee.signed("read-recovery", self.proof_key, ("sessionId", self.session_id))
        receipt = trustee.call(request, "read-recovery", request["requestId"])
        expect(receipt, {"sessionId": self.session_id}, "recovery receipt")
        contribution = receipt.get("contribution")
        return receipt, contribution and self.accept(trustee, contribution)

    def accept(self, trustee, contribution):
        """Check a contribution completely, open it with the destination key
        and verify the holder-signed envelope inside. Keeps and returns it."""
        name, entry = trustee.component_id, self.slots[trustee.component_id]
        if set(contribution) != CONTRIBUTION_FIELDS:
            raise ValueError(f"{name}: contribution fields")
        verify(contribution, "signature", trustee.operator)
        bindings = {key: self.session[key] for key in CONTRIBUTION if key in self.session}
        bindings.update(componentId=name, slot=entry["slot"], destinationKeysDigest=self.destination_keys_digest)
        expect(contribution, dict(bindings, contributionVersion=1, decision="approved"), "contribution")
        seconds(contribution["decidedAt"])
        if seconds(contribution["expiresAt"]) <= time.time():
            raise ValueError(f"{name}: contribution expired")
        info = canonical(["onym-shamir-recovery-contribution-v1", *(bindings[key] for key in CONTRIBUTION)])
        envelope = parse(HPKE.decrypt(unb64(contribution["sealedContribution"]), self.destination_key, info))
        verify(envelope, "holderAuthorization", entry["authorizationPublicKey"])
        session, policy = self.session, self.map["policy"]
        expect(envelope, {
            "shareEnvelopeVersion": 1,
            **{key: session[key] for key in ("enrollmentId", "enrollmentSequence", "policyDigest", "artifactId",
                                             "artifactDigest")},
            "implementationProfileId": PROFILE,
            "identityBindingCommitment": policy["identityBindingCommitment"],
            "recoveryMode": RECOVERY_MODE,
            "trusteeComponentId": name,
            "slot": entry["slot"],
            "trusteePolicy": entry["trusteePolicy"],
            "authorizationPublicKey": entry["authorizationPublicKey"],
            "memberThreshold": self.threshold,
            "memberCount": len(self.slots),
        }, "envelope")
        indices = {other["memberIndex"] for other_name, other in self.envelopes.items() if other_name != name}
        if uint(envelope["memberIndex"]) >= len(self.slots) or envelope["memberIndex"] in indices:
            raise ValueError(f"{name}: member index")
        self.envelopes[name], self.contributions[name] = envelope, contribution
        return envelope


def recover(candidate, trustees, interval, save=lambda: None, log=print):
    """Collect t verified shares, each trustee on its own. An unreachable
    trustee is retried every round; one that refuses or does not verify is
    dropped. Stops with t shares, or when fewer than t trustees remain or
    the session expires. Calls `save` after each new contribution."""
    live = {trustee.component_id: trustee for trustee in trustees}
    for name, contribution in candidate.saved.items():
        candidate.accept(live[name], contribution)
    current, last = set(), {}

    def note(name, line):
        """Log a trustee's line once, not on every poll of a long cooldown."""
        if last.get(name) != line:
            last[name] = line
            log(f"{name}: {line}")
    while len(candidate.envelopes) < candidate.threshold:
        for name, trustee in list(live.items()):
            if name in candidate.envelopes or len(candidate.envelopes) >= candidate.threshold:
                continue
            try:
                if name not in current:
                    live[name] = trustee = trustee.refreshed()
                    # Idempotent: a resumed or retried begin resends the same bytes.
                    receipt = candidate.begin(trustee)
                    if receipt["newState"] == "refused":
                        raise ValueError(f"refused ({receipt['reason']})")
                    current.add(name)
                    note(name, f"cooling down until {receipt['cooldownEndsAt']}")
                receipt, envelope = candidate.read(trustee)
                if envelope:
                    save()
                    note(name, "contributed")
                elif receipt["newState"] not in ("cooling_down", "collecting"):
                    raise ValueError(f"{receipt['newState']} {receipt.get('reason', '')}".strip())
            except FAILURES as error:
                if transient(error):
                    note(name, f"unavailable ({describe(error)}); retrying")
                else:
                    del live[name]
                    note(name, f"dropped ({describe(error)})")
        if len(candidate.envelopes) >= candidate.threshold:
            break
        if len(live) < candidate.threshold:
            raise ValueError(f"recovery cannot complete: {len(live)} of {candidate.threshold} trustees remain")
        if time.time() >= seconds(candidate.session["expiresAt"]):
            raise ValueError("the recovery session expired")
        time.sleep(interval)
    return [envelope["slip39Share"] for envelope in candidate.envelopes.values()][: candidate.threshold]


def restore(recovery_map, shares):
    """Combine shares into the recovery key, open the artifact, and require
    it to match the protected header, identity commitment included. Raises
    MnemonicError when the shares do not suffice."""
    protected = recovery_map["protectedArtifact"]
    check_artifact(protected, recovery_map["policy"])
    ruk = combine_mnemonics(shares)
    nonce = bytes.fromhex(protected["protectionParameters"]["nonce"])
    artifact = parse(AESGCM(ruk).decrypt(nonce, unb64(protected["ciphertext"]), artifact_aad(protected)))
    expect(artifact, {"artifactVersion": 1, "artifactId": protected["artifactId"],
                      "recoveryMode": protected["recoveryMode"], "payloadSchema": PAYLOAD_SCHEMA}, "artifact")
    commitment = identity_commitment(
        artifact["identityBindingSalt"], artifact["identitySubject"], artifact["descriptorDigest"]
    )
    if commitment != protected["identityBindingCommitment"]:
        raise ValueError("artifact: identity binding")
    return artifact


# ---------------------------------------------------------------------------
# Files and commands


def write_private(path, value, replace=False):
    """Write an owner-only file whole: a temporary file, fsync, then an
    atomic link (never overwriting) or rename (`replace`)."""
    path = Path(path)
    temporary = path.with_name(path.name + ".tmp")
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(descriptor, "wb") as file:
            file.write(value.encode() if isinstance(value, str) else canonical(value))
            file.flush()
            os.fsync(file.fileno())
        if replace:
            os.replace(temporary, path)
        else:
            os.link(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)
    directory = os.open(path.parent, os.O_RDONLY)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)


def enroll_to(out, invitations, threshold, **terms):
    """Enroll at every (trustee, invitation) and write the vault directory
    `out`, which must not exist. The holder and factor keys are written
    before any trustee is contacted; if enrollment fails, those keys close
    every slot. The map and its key are read back from disk at the end."""
    out = Path(out)
    enrollment = Enrollment([trustee for trustee, _ in invitations], threshold, **terms)
    out.mkdir(mode=0o700)
    write_private(out / "holder.json", enrollment.holder)
    write_private(out / "factors.json", enrollment.factors)
    try:
        recovery_map = enrollment.run([code for _, code in invitations])
    except FAILURES:
        print("enrollment failed; closing every slot with the saved holder keys", file=sys.stderr)
        for name, result in Holder.load(enrollment.holder).close():
            outcome = "closed" if isinstance(result, dict) else f"not closed ({describe(result)})"
            print(f"  {name}: {outcome}", file=sys.stderr)
        raise
    sealed, key = seal_map(recovery_map)
    write_private(out / "map.key", key.hex())
    write_private(out / "map.json", sealed)
    reopened, _, _ = open_map(parse((out / "map.json").read_bytes()), hex32((out / "map.key").read_text()))
    if reopened != recovery_map:
        raise ValueError("the saved map does not reopen")
    return recovery_map


def report(results, show):
    """Print one line per trustee; exit non-zero if any failed."""
    failed = 0
    for name, result in results:
        if isinstance(result, dict):
            show(name, result)
        else:
            failed += 1
            print(f"{name}: failed ({describe(result)})")
    if failed:
        sys.exit(f"{failed} of {len(results)} trustees failed; retry later")


def enroll_command(args):
    invitations = [(Trustee.fetch(origin), code) for origin, code in args.trustee]
    recovery_map = enroll_to(
        args.out, invitations, args.threshold, cooldown=args.cooldown, lifetime=args.lifetime,
        attempts=args.attempts, payload=args.payload,
    )
    print(f"enrolled {recovery_map['enrollmentId']} at {len(invitations)} trustees; "
          f"map, holder and factor keys in {args.out}/")


def poll_command(args):
    def show(name, receipt):
        print(f"{name}: {receipt['newState']}")
        for session in receipt.get("sessions", []):
            reason = f" ({session['reason']})" if "reason" in session else ""
            released = ", contribution released" if session["released"] else ""
            print(f"  {session['sessionId']} {session['state']}{reason}{released}; "
                  f"cooldown ends {session['cooldownEndsAt']}")

    report(Holder.load(parse(Path(args.holder).read_bytes())).poll(), show)


def veto_command(args):
    report(Holder.load(parse(Path(args.holder).read_bytes())).veto(args.session),
           lambda name, receipt: print(f"{name}: {receipt['oldState']} -> {receipt['newState']}"))


def close_command(args):
    report(Holder.load(parse(Path(args.holder).read_bytes())).close(),
           lambda name, receipt: print(f"{name}: {receipt['oldState']} -> {receipt['newState']}"))


def recover_command(args):
    sealed = parse(Path(args.map).read_bytes())
    recovery_map, trustees, _ = open_map(sealed, hex32(Path(args.map_key).read_text().strip()))
    factors = parse(Path(args.factors).read_bytes())
    path = Path(args.session)
    # Saved before the first request, so a restart resumes this session
    # instead of spending another attempt and restarting the cooldown.
    if path.exists():
        candidate = Candidate(recovery_map, factors, parse(path.read_bytes()))
        print(f"resuming session {candidate.session_id}")
    else:
        candidate = Candidate(recovery_map, factors)
        write_private(path, candidate.state())
    try:
        shares = recover(candidate, trustees, args.interval,
                         save=lambda: write_private(path, candidate.state(), replace=True))
    except ValueError:
        # An expired session is of no further use; anything else may resume.
        if time.time() >= seconds(candidate.session["expiresAt"]):
            path.unlink()
        raise
    artifact = restore(recovery_map, shares)
    write_private(args.out, artifact)
    path.unlink()
    print(f"recovered artifact {artifact['artifactId']}; identity binding verified; written to {args.out}")


# Reference error messages, by the class the fixture records.
ERRORS = {
    "Invalid mnemonic checksum": "checksum",
    "Invalid mnemonic padding": "padding",
    "Invalid mnemonic length": "length",
    "Group threshold cannot be greater than group count": "group-threshold",
    "Invalid mnemonic word": "word",
}

# The Onym Shamir profile: one group, 256-bit secret, no extendable flag,
# exponent zero, empty passphrase. The library defaults differ
# (extendable=True, iteration_exponent=1), so every argument is explicit.
PROFILE_SETS = [(2, 3), (3, 5), (2, 16), (16, 16)]


def decoded(mnemonic):
    """The reference decoding of one share, or the class of its error."""
    try:
        share = Share.from_mnemonic(mnemonic)
    except MnemonicError as error:
        return {"error": next(kind for text, kind in ERRORS.items() if text in str(error))}
    return {
        "identifier": share.identifier,
        "extendable": share.extendable,
        "iterationExponent": share.iteration_exponent,
        "groupIndex": share.group_index,
        "groupThreshold": share.group_threshold,
        "groupCount": share.group_count,
        "memberIndex": share.index,
        "memberThreshold": share.member_threshold,
        "valueBytes": len(share.value),
    }


def share_fixtures(_args):
    vectors = json.loads((FIXTURES / "vectors.json").read_text())
    official = [
        {"case": number, "description": description, "mnemonic": mnemonic, "reference": decoded(mnemonic)}
        for number, (description, mnemonics, _secret, _xprv) in enumerate(vectors, 1)
        for mnemonic in mnemonics
    ]
    generated = []
    for threshold, count in PROFILE_SETS:
        secret = os.urandom(32)
        [shares] = generate_mnemonics(
            1, [(threshold, count)], secret, b"", extendable=False, iteration_exponent=0
        )
        generated.append(
            {"memberThreshold": threshold, "memberCount": count, "masterSecret": secret.hex(), "shares": shares}
        )
    write_fixture("official-decoded.json", official)
    write_fixture("onym-generated.json", generated)


def write_fixture(name, cases):
    document = {"generator": "shamir-mnemonic 0.3.0 via tools/client.py share-fixtures", "cases": cases}
    (FIXTURES / name).write_text(json.dumps(document, indent=1) + "\n")


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    commands = parser.add_subparsers(required=True)

    command = commands.add_parser("enroll", help="split a fresh recovery key across trustees")
    command.add_argument("--trustee", nargs=2, action="append", required=True, metavar=("ORIGIN", "INVITATION"))
    command.add_argument("--threshold", type=int, required=True)
    command.add_argument("--cooldown", default="P2D")
    command.add_argument("--lifetime", default="P7D", help="session lifetime")
    command.add_argument("--attempts", type=int, default=3)
    command.add_argument("--payload", default="synthetic demo secret")
    command.add_argument("--out", required=True, help="new directory for the map, its key and the holder's keys")
    command.set_defaults(run=enroll_command)

    for name, run, help in (
        ("poll", poll_command, "show recovery sessions at every trustee"),
        ("veto", veto_command, "cancel a recovery session at every trustee"),
        ("close", close_command, "close the enrollment at every trustee"),
    ):
        command = commands.add_parser(name, help=help)
        command.add_argument("--holder", required=True)
        if name == "veto":
            command.add_argument("session")
        command.set_defaults(run=run)

    command = commands.add_parser("recover", help="recover on a fresh device")
    command.add_argument("--map", required=True)
    command.add_argument("--map-key", required=True)
    command.add_argument("--factors", required=True)
    command.add_argument("--session", default="recovery-session.json",
                         help="owner-only session state, kept until the recovery completes or expires")
    command.add_argument("--out", required=True, help="new file for the recovered artifact")
    command.add_argument("--interval", type=float, default=5, help="seconds between polls")
    command.set_defaults(run=recover_command)

    commands.add_parser(
        "share-fixtures", help="regenerate tests/fixtures/slip39 from the reference implementation"
    ).set_defaults(run=share_fixtures)

    args = parser.parse_args()
    try:
        args.run(args)
    except (*FAILURES, MnemonicError) as error:
        sys.exit(f"failed: {describe(error)}")


if __name__ == "__main__":
    main()
