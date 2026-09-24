#!/usr/bin/env python3
"""Holder and candidate client for the Onym recovery trustee (binding draft-1).

A demo client, not a vault: keys live in plain files and the protected
artifact is synthetic. Shares are split and combined by Trezor's reference
SLIP-0039 implementation; HPKE, Ed25519 and AES-GCM come from
pyca/cryptography. Nothing here shares code with the trustee.

  enroll          split a fresh recovery key t-of-n across trustees
  poll            show every trustee's recovery sessions (the holder's notice)
  veto            cancel a recovery session at every trustee, as the holder
  recover         begin a session, wait out the cooldown, combine t shares
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
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

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


# ---------------------------------------------------------------------------
# Encodings (binding §§2-4)


def canonical(value):
    """Discovery §3 bytes: sorted keys, no whitespace, minimal escaping."""
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def parse(raw):
    """A JSON object, refusing duplicate keys at any depth and non-finite numbers."""

    def unique(pairs):
        if len({key for key, _ in pairs}) != len(pairs):
            raise ValueError("duplicate key")
        return dict(pairs)

    def refuse(constant):
        raise ValueError(constant)

    value = json.loads(raw, object_pairs_hook=unique, parse_constant=refuse)
    if not isinstance(value, dict):
        raise ValueError("not an object")
    return value


def digest(data):
    return "sha256:" + hashlib.sha256(data).hexdigest()


def b64(data):
    return base64.b64encode(data).decode()


def unb64(text):
    return base64.b64decode(text, validate=True)


def timestamp(seconds):
    return datetime.fromtimestamp(int(seconds), timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def seconds(text):
    return int(datetime.strptime(text, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc).timestamp())


def duration(text):
    """Seconds in `P[nD][T[nH][nM][nS]]`, the subset the binding allows."""
    match = re.fullmatch(r"P(?:(\d+)D)?(?:T(?:(\d+)H)?(?:(\d+)M)?(?:(\d+)S)?)?", text)
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
    return Ed25519PrivateKey.from_private_bytes(bytes.fromhex(private))


def sign(value, field, key):
    """Sign `value` over its canonical bytes into `field`; returns `value`."""
    value[field] = b64(key.sign(canonical(value)))
    return value


def verify(value, field, public):
    """Check that `field` signs the rest of `value`; raises InvalidSignature."""
    rest = {key: item for key, item in value.items() if key != field}
    Ed25519PublicKey.from_public_bytes(bytes.fromhex(public)).verify(unb64(value[field]), canonical(rest))


def artifact_aad(header):
    """Shamir §4.2 associated data."""
    return canonical([
        header["implementationProfileId"], header["enrollmentId"], header["enrollmentSequence"],
        header["policyDigest"], header["identityBindingCommitment"], header["recoveryMode"],
        header["artifactId"],
    ])


def expect(value, fields, what):
    mismatched = sorted(key for key, item in fields.items() if value.get(key) != item)
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


def http(url, body=None):
    request = urllib.request.Request(url, data=body, headers={"content-type": "application/json"})
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            return response.read()
    except urllib.error.HTTPError as error:
        raise Refused(error.code, error.read()) from None


class Trustee:
    """One trustee, as its verified manifest describes it."""

    def __init__(self, manifest):
        self.operator = manifest["operator"].removeprefix("onym:key:")
        verify(manifest, "signature", self.operator)
        key = manifest["enrollmentKey"]
        usable = (
            manifest["bindingVersion"] == BINDING
            and PROFILE in manifest["implementationProfileIds"]
            and key["suite"] == ENCRYPTION_SUITE
            and key["trusteeKeyId"] == digest(bytes.fromhex(key["publicKey"]))
            and seconds(manifest["validUntil"]) > time.time()
        )
        if not usable:
            raise ValueError(f"unusable manifest: {manifest['componentId']}")
        self.manifest = manifest
        self.component_id = manifest["componentId"]
        self.endpoint = manifest["endpoints"][0]
        self.enrollment_key = X25519PublicKey.from_public_bytes(bytes.fromhex(key["publicKey"]))
        self.key_id = key["trusteeKeyId"]

    @classmethod
    def fetch(cls, origin):
        return cls(parse(http(origin.rstrip("/") + "/manifest.json")))

    def post(self, request):
        """Send one request; returns the raw response bytes."""
        return http(self.endpoint, canonical(request))

    def call(self, request, operation, request_id):
        """Send a request; returns its receipt, signature and echo checked."""
        receipt = parse(self.post(request))
        verify(receipt, "signature", self.operator)
        answer = {"componentId": self.component_id, "operation": operation, "requestId": request_id}
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
# Holder: enrollment, poll, veto, closure


def enroll(invitations, threshold, cooldown, lifetime, attempts, payload, term_days=365):
    """Split a fresh recovery key across `invitations`, a list of (trustee,
    invitation code), and collect every receipt. Returns the recovery map,
    the holder's key file and the independently held factor keys."""
    trustees = [trustee for trustee, _ in invitations]
    count = len(trustees)
    if len({trustee.component_id for trustee in trustees}) != count:
        raise ValueError("a trustee appears twice")
    if len({trustee.manifest["trustDomain"] for trustee in trustees}) != count:
        print("warning: trustees share a declared trust domain; they are not independent", file=sys.stderr)

    now = int(time.time())
    ruk = os.urandom(32)
    enrollment_id, artifact_id = random_id(), random_id()
    # A real vault commits to its identity descriptor (identity profile).
    identity = digest(canonical(
        ["onym-recovery-identity-binding-v1", random_id(), "demo-identity", digest(b"demo-descriptor")]
    ))
    slots = [
        {"trustee": trustee, "slot": random_id(), "authorization": Ed25519PrivateKey.generate(),
         "factor": Ed25519PrivateKey.generate()}
        for trustee in trustees
    ]
    for slot in slots:
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
    policy = {
        "policyVersion": 1,
        "policyId": random_id(),
        "recoveryMode": RECOVERY_MODE,
        "identityBindingCommitment": identity,
        "implementationProfileId": PROFILE,
        "trustees": [
            {"componentId": slot["trustee"].component_id, "slot": slot["slot"],
             "authorizationPublicKey": public_hex(slot["authorization"]), "trusteePolicy": slot["policy"]}
            for slot in slots
        ],
        "approvalRule": f"slip39-{threshold}-of-{count}",
        "createdAt": timestamp(now),
        "expiresAt": timestamp(now + term_days * 86_400),
    }

    # The artifact carries the scoped keys, so a recovered vault regains
    # authority over the enrollment (demo stand-in for identity §10 seat keys).
    header = {
        "protectedArtifactVersion": 1,
        "implementationProfileId": PROFILE,
        "enrollmentId": enrollment_id,
        "enrollmentSequence": 1,
        "policyDigest": digest(canonical(policy)),
        "identityBindingCommitment": identity,
        "recoveryMode": RECOVERY_MODE,
        "artifactId": artifact_id,
    }
    artifact = {
        "artifactVersion": 1,
        "synthetic": True,
        "payload": payload,
        "authorizationKeys": {slot["trustee"].component_id: private_hex(slot["authorization"]) for slot in slots},
    }
    nonce = os.urandom(12)
    protected = dict(
        header,
        protectionParameters={"aead": "aes-256-gcm", "nonce": nonce.hex()},
        ciphertext=b64(AESGCM(ruk).encrypt(nonce, canonical(artifact), artifact_aad(header))),
    )
    protected["artifactDigest"] = digest(canonical(protected))

    [shares] = generate_mnemonics(1, [(threshold, count)], ruk, b"", extendable=False, iteration_exponent=0)
    receipts = []
    for index, ((trustee, invitation), slot, share) in enumerate(zip(invitations, slots, shares)):
        envelope = {
            "shareEnvelopeVersion": 1,
            "identityBindingCommitment": identity,
            "recoveryMode": RECOVERY_MODE,
            "memberIndex": index,
            "memberThreshold": threshold,
            "memberCount": count,
            "trusteePolicy": slot["policy"],
            "slip39Share": share,
            "createdAt": timestamp(now),
            "expiresAt": policy["expiresAt"],
            "authorizationPublicKey": public_hex(slot["authorization"]),
        }
        receipts.append(enroll_slot(trustee, invitation, header, protected, slot, envelope))

    recovery_map = {
        "recoveryMapVersion": 1,
        "recoveryProfileId": RECOVERY_PROFILE,
        "implementationProfileId": PROFILE,
        "enrollmentId": enrollment_id,
        "enrollmentSequence": 1,
        "policy": policy,
        "protectedArtifact": protected,
        "trusteeManifests": [trustee.manifest for trustee in trustees],
        "trusteeReceipts": receipts,
    }
    holder = {
        "enrollmentId": enrollment_id,
        "trustees": [
            {"manifest": slot["trustee"].manifest, "authorizationKey": private_hex(slot["authorization"])}
            for slot in slots
        ],
    }
    factors = {slot["trustee"].component_id: private_hex(slot["factor"]) for slot in slots}
    return recovery_map, holder, factors


def enroll_slot(trustee, invitation, header, protected, slot, envelope):
    """Redeem an invitation, then seal and deliver one signed envelope."""
    offer = parse(trustee.post({
        "requestVersion": 1, "operation": "issue-challenge",
        "componentId": trustee.component_id, "invitation": invitation,
    }))
    expect(offer, {"componentId": trustee.component_id, "trusteeKeyId": trustee.key_id}, "challenge")
    authorization = slot["authorization"]
    context = {
        "implementationProfileId": PROFILE,
        "enrollmentId": header["enrollmentId"],
        "enrollmentSequence": header["enrollmentSequence"],
        "policyDigest": header["policyDigest"],
        "artifactId": header["artifactId"],
        "artifactDigest": protected["artifactDigest"],
        "trusteeComponentId": trustee.component_id,
        "slot": slot["slot"],
        "trusteeChallenge": offer["challenge"],
        "authorizationKeyDigest": digest(authorization.public_key().public_bytes_raw()),
    }
    envelope.update({key: context[key] for key in CONTEXT if key != "authorizationKeyDigest"})
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
    expect(receipt, {
        "newState": "active",
        "enrollmentId": header["enrollmentId"],
        "slot": slot["slot"],
        "artifactDigest": protected["artifactDigest"],
        "sealedContributionDigest": digest(sealed),
    }, "enrollment receipt")
    return receipt


def seal_map(recovery_map):
    """Shamir §5.5: AES-256-GCM under a separate key, bound to the profile
    and a random map ID. Returns the sealed map and its key."""
    key, map_id, nonce = os.urandom(32), random_id(), os.urandom(12)
    ciphertext = AESGCM(key).encrypt(nonce, canonical(recovery_map), canonical([PROFILE, map_id]))
    return {"mapId": map_id, "nonce": nonce.hex(), "ciphertext": b64(ciphertext)}, key


def open_map(sealed, key):
    """Decrypt a map and verify every manifest and receipt it carries."""
    plaintext = AESGCM(key).decrypt(
        bytes.fromhex(sealed["nonce"]), unb64(sealed["ciphertext"]), canonical([PROFILE, sealed["mapId"]])
    )
    recovery_map = parse(plaintext)
    trustees = [Trustee(manifest) for manifest in recovery_map["trusteeManifests"]]
    for trustee, receipt in zip(trustees, recovery_map["trusteeReceipts"], strict=True):
        verify(receipt, "signature", trustee.operator)
        expect(receipt, {"componentId": trustee.component_id, "newState": "active",
                         "enrollmentId": recovery_map["enrollmentId"]}, "map receipt")
    return recovery_map, trustees


class Holder:
    """The healthy device: one trustee-scoped key per trustee."""

    def __init__(self, enrollment_id, keys):
        self.enrollment_id = enrollment_id
        self.keys = keys  # [(Trustee, Ed25519PrivateKey)]

    @classmethod
    def load(cls, holder):
        keys = [(Trustee(entry["manifest"]), ed25519(entry["authorizationKey"])) for entry in holder["trustees"]]
        return cls(holder["enrollmentId"], keys)

    def each(self, operation, target, by=None):
        """One signed request per trustee; returns the receipts."""
        receipts = []
        for trustee, key in self.keys:
            request = trustee.signed(operation, key, target, by)
            receipts.append(trustee.call(request, operation, request["requestId"]))
        return receipts

    def poll(self):
        return self.each("read-enrollment", ("enrollmentId", self.enrollment_id))

    def veto(self, session_id):
        return self.each("cancel-recovery", ("sessionId", session_id), by="holder")

    def close(self):
        return self.each("close-enrollment", ("enrollmentId", self.enrollment_id))


# ---------------------------------------------------------------------------
# Candidate: recovery on a fresh device


class Candidate:
    """A recovering device: fresh destination and proof keys, one session."""

    def __init__(self, recovery_map, factors):
        policy, artifact = recovery_map["policy"], recovery_map["protectedArtifact"]
        self.map, self.factors = recovery_map, factors
        self.slots = {entry["componentId"]: entry for entry in policy["trustees"]}
        self.destination_key = X25519PrivateKey.generate()
        self.proof_key = Ed25519PrivateKey.generate()
        destination = {
            "encryptionSuite": ENCRYPTION_SUITE,
            "encryptionPublicKey": public_hex(self.destination_key),
            "proofSuite": "ed25519",
            "proofPublicKey": public_hex(self.proof_key),
        }
        now = int(time.time())
        lifetime = min(duration(entry["trusteePolicy"]["sessionLifetime"]) for entry in policy["trustees"])
        self.session = {
            "sessionVersion": 1,
            "sessionId": random_id(),
            "enrollmentId": recovery_map["enrollmentId"],
            "enrollmentSequence": recovery_map["enrollmentSequence"],
            "policyDigest": digest(canonical(policy)),
            "artifactId": artifact["artifactId"],
            "artifactDigest": artifact["artifactDigest"],
            "destination": destination,
            "requestedAt": timestamp(now),
            # A minute's margin keeps it inside every trustee's lifetime.
            "expiresAt": timestamp(now + lifetime - 60),
        }
        self.commitment = digest(canonical(self.session))
        self.destination_keys_digest = digest(canonical(["onym-recovery-destination-keys-v1", destination]))

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
        receipt = trustee.call(self.begin_request(trustee), "begin-recovery", self.session_id)
        expect(receipt, {"newState": "cooling_down", "sessionId": self.session_id,
                         "destinationKeysDigest": self.destination_keys_digest}, "session receipt")
        return receipt

    def read(self, trustee):
        """Poll one trustee; returns its receipt and, once released, the
        verified envelope it contributed."""
        request = trustee.signed("read-recovery", self.proof_key, ("sessionId", self.session_id))
        receipt = trustee.call(request, "read-recovery", request["requestId"])
        contribution = receipt.get("contribution")
        return receipt, contribution and self.open(trustee, contribution)

    def open(self, trustee, contribution):
        """Check a contribution's signature and bindings, open it with the
        destination key, and verify the holder's signature inside."""
        verify(contribution, "signature", trustee.operator)
        slot = self.slots[trustee.component_id]
        bindings = {key: self.session[key] for key in CONTRIBUTION if key in self.session}
        bindings.update(componentId=trustee.component_id, slot=slot["slot"],
                        destinationKeysDigest=self.destination_keys_digest)
        expect(contribution, dict(bindings, contributionVersion=1, decision="approved"), "contribution")
        info = canonical(["onym-shamir-recovery-contribution-v1", *(bindings[key] for key in CONTRIBUTION)])
        envelope = parse(HPKE.decrypt(unb64(contribution["sealedContribution"]), self.destination_key, info))
        verify(envelope, "holderAuthorization", slot["authorizationPublicKey"])
        expect(envelope, {
            "enrollmentId": self.session["enrollmentId"],
            "artifactDigest": self.session["artifactDigest"],
            "trusteeComponentId": trustee.component_id,
            "slot": slot["slot"],
        }, "envelope")
        return envelope


def restore(recovery_map, shares):
    """Combine shares into the recovery key and open the artifact. Raises
    MnemonicError when the shares do not suffice."""
    protected = dict(recovery_map["protectedArtifact"])
    if digest(canonical({k: v for k, v in protected.items() if k != "artifactDigest"})) != protected["artifactDigest"]:
        raise ValueError("artifact digest")
    ruk = combine_mnemonics(shares)
    nonce = bytes.fromhex(protected["protectionParameters"]["nonce"])
    return parse(AESGCM(ruk).decrypt(nonce, unb64(protected["ciphertext"]), artifact_aad(protected)))


# ---------------------------------------------------------------------------
# Commands


def write_private(path, value):
    """Create an owner-only file; never overwrite."""
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "wb") as file:
        file.write(value if isinstance(value, bytes) else canonical(value))


def enroll_command(args):
    invitations = [(Trustee.fetch(origin), code) for origin, code in args.trustee]
    recovery_map, holder, factors = enroll(
        invitations, args.threshold, args.cooldown, args.lifetime, args.attempts, payload=args.payload
    )
    sealed, key = seal_map(recovery_map)
    if open_map(sealed, key)[0] != recovery_map:
        raise ValueError("the map does not reopen")
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    write_private(out / "map.json", sealed)
    write_private(out / "map.key", key.hex().encode())
    write_private(out / "holder.json", holder)
    write_private(out / "factors.json", factors)
    print(f"enrolled {recovery_map['enrollmentId']} at {len(invitations)} trustees; "
          f"map, holder and factor keys in {out}/")


def poll_command(args):
    holder = Holder.load(parse(Path(args.holder).read_bytes()))
    for (trustee, _), receipt in zip(holder.keys, holder.poll()):
        print(f"{trustee.component_id}: {receipt['newState']}")
        for session in receipt.get("sessions", []):
            reason = f" ({session['reason']})" if "reason" in session else ""
            print(f"  {session['sessionId']} {session['state']}{reason} "
                  f"cooldown ends {session['cooldownEndsAt']}")


def veto_command(args):
    holder = Holder.load(parse(Path(args.holder).read_bytes()))
    for (trustee, _), receipt in zip(holder.keys, holder.veto(args.session)):
        print(f"{trustee.component_id}: {receipt['oldState']} -> {receipt['newState']}")


def recover_command(args):
    sealed = parse(Path(args.map).read_bytes())
    recovery_map, trustees = open_map(sealed, bytes.fromhex(Path(args.map_key).read_text().strip()))
    candidate = Candidate(recovery_map, parse(Path(args.factors).read_bytes()))
    for trustee in trustees:
        receipt = candidate.begin(trustee)
        print(f"{trustee.component_id}: cooling down until {receipt['cooldownEndsAt']}")
    envelopes, ended = {}, set()
    while True:
        for trustee in trustees:
            name = trustee.component_id
            if name in envelopes or name in ended:
                continue
            receipt, envelope = candidate.read(trustee)
            if envelope:
                envelopes[name] = envelope
                print(f"{name}: contributed")
            elif receipt["newState"] not in ("cooling_down", "collecting"):
                ended.add(name)
                print(f"{name}: {receipt['newState']} {receipt.get('reason', '')}")
        shares = [envelope["slip39Share"] for envelope in envelopes.values()]
        threshold = next(iter(envelopes.values()), {}).get("memberThreshold")
        if threshold and len(shares) >= threshold:
            artifact = restore(recovery_map, shares[:threshold])
            print(f"recovered artifact {recovery_map['protectedArtifact']['artifactId']}: {artifact['payload']}")
            return
        if len(envelopes) + len(ended) == len(trustees):
            sys.exit("recovery cannot complete: too few trustees contributed")
        time.sleep(args.interval)


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
    command.add_argument("--out", required=True, help="directory for the map, its key and the holder's keys")
    command.set_defaults(run=enroll_command)

    command = commands.add_parser("poll", help="show recovery sessions at every trustee")
    command.add_argument("--holder", required=True)
    command.set_defaults(run=poll_command)

    command = commands.add_parser("veto", help="cancel a recovery session at every trustee")
    command.add_argument("--holder", required=True)
    command.add_argument("session")
    command.set_defaults(run=veto_command)

    command = commands.add_parser("recover", help="recover on a fresh device")
    command.add_argument("--map", required=True)
    command.add_argument("--map-key", required=True)
    command.add_argument("--factors", required=True)
    command.add_argument("--interval", type=float, default=5, help="seconds between polls")
    command.set_defaults(run=recover_command)

    commands.add_parser(
        "share-fixtures", help="regenerate tests/fixtures/slip39 from the reference implementation"
    ).set_defaults(run=share_fixtures)

    args = parser.parse_args()
    try:
        args.run(args)
    except Refused as refusal:
        sys.exit(f"refused: {refusal}")


if __name__ == "__main__":
    main()
