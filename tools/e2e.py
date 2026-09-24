#!/usr/bin/env python3
"""End to end against three local trustee processes:

- 2-of-3 enrollment collects all three receipts and writes an encrypted map;
- the begin, holder poll, veto and refusal paths behave as specified;
- release happens only after the cooldown, and a restart keeps the deadline;
- two shares rebuild the key and open the artifact, one share does not;
- Python opens Rust's HPKE output and verifies its signatures, and the
  other way round;
- no planted secret reaches an error body or a log.

    cargo build && python3 tools/e2e.py
"""

import argparse
import os
import secrets
import subprocess
import sys
import tempfile
import time
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import client as c  # noqa: E402
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey  # noqa: E402
from shamir_mnemonic import combine_mnemonics  # noqa: E402
from shamir_mnemonic.utils import MnemonicError  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent
COOLDOWN = 3


def ok(message):
    print(f"  ok  {message}")


def raises(error, action):
    try:
        action()
    except error:
        return True
    return False


def refused(send, status, code):
    """Run `send`; require the refusal `status code`. Returns the raw body."""
    try:
        send()
    except c.Refused as refusal:
        assert (refusal.status, refusal.code) == (status, code), f"{refusal}, wanted {status} {code}"
        return refusal.body
    raise AssertionError(f"accepted, wanted {status} {code}")


class Server:
    """One trustee process with its own key file, database and log."""

    def __init__(self, binary, work, name, port):
        self.binary, self.port = binary, port
        self.log = work / f"{name}.log"
        self.env = dict(
            os.environ,
            TRUSTEE_COMPONENT_ID=f"onym:component:demo-trustee-{name}",
            TRUSTEE_PUBLIC_URL=f"http://127.0.0.1:{port}",
            TRUSTEE_BIND=f"127.0.0.1:{port}",
            TRUSTEE_KEY_FILE=str(work / f"{name}.key"),
            TRUSTEE_STORE_PATH=str(work / f"{name}.sqlite"),
            TRUSTEE_MIN_COOLDOWN="PT1S",
        )
        self.run("keygen", self.env["TRUSTEE_KEY_FILE"])
        self.process = None

    @property
    def origin(self):
        return self.env["TRUSTEE_PUBLIC_URL"]

    def run(self, *args):
        return subprocess.run([self.binary, *args], env=self.env, check=True, capture_output=True, text=True).stdout

    def invite(self):
        return self.run("invite").strip()

    def start(self):
        with open(self.log, "ab") as log:
            self.process = subprocess.Popen([self.binary, "serve"], env=self.env, stderr=log)
        for _ in range(50):
            try:
                urllib.request.urlopen(f"{self.origin}/health", timeout=1).read()
                return
            except OSError:
                time.sleep(0.1)
        raise RuntimeError(f"{self.origin} did not start")

    def stop(self):
        if self.process:
            self.process.terminate()
            self.process.wait()
            self.process = None


def check(servers):
    """The acceptance run. Returns every secret it planted or learned."""
    fixtures = ROOT / "tests/fixtures/canonical"
    for name in ("canonical", "canonical-case", "canonical-escaping", "foundation-vectors"):
        value = c.parse((fixtures / f"{name}-input.json").read_bytes())
        value.pop("signature")  # the bytes are the signing input
        assert c.canonical(value) == (fixtures / f"{name}-bytes.bin").read_bytes(), name
    assert raises(ValueError, lambda: c.parse((fixtures / "duplicate-keys-input.json").read_bytes()))
    ok("Python's stdlib JSON reproduces Discovery's canonical bytes")

    trustees = [c.Trustee.fetch(server.origin) for server in servers]
    ok("three signed manifests verify")

    canary = "canary-" + secrets.token_hex(16)
    recovery_map, holder_file, factors = c.enroll(
        [(trustee, server.invite()) for trustee, server in zip(trustees, servers)],
        threshold=2, cooldown=f"PT{COOLDOWN}S", lifetime="PT10M", attempts=5, payload=canary,
    )
    sealed_map, map_key = c.seal_map(recovery_map)
    assert c.open_map(sealed_map, map_key)[0] == recovery_map
    ok("2-of-3 enrollment: all three receipts verified; the encrypted map reopens")

    holder = c.Holder.load(holder_file)
    assert all(receipt["newState"] == "active" and not receipt["sessions"] for receipt in holder.poll())
    first, second, third = trustees

    # --- A recovery the holder vetoes -------------------------------------
    vetoed = c.Candidate(recovery_map, factors)
    request = vetoed.begin_request(first)
    receipt = first.post(request)
    assert first.post(request) == receipt, "an identical retry returns identical bytes"
    other_factor = Ed25519PrivateKey.generate()
    refused(lambda: first.post(vetoed.begin_request(first, factor=other_factor)), 409, "request_conflict")
    for trustee in (second, third):
        assert vetoed.begin(trustee)["remainingAttempts"] == 4
    ok("begin-recovery at every trustee; a retry replays its bytes, a changed body conflicts")

    for poll in holder.poll():
        [notice] = poll["sessions"]
        assert (notice["sessionId"], notice["state"]) == (vetoed.session_id, "cooling_down")
    ok("the holder's poll shows the session at every trustee")

    assert all(receipt["newState"] == "cancelled" for receipt in holder.veto(vetoed.session_id))
    time.sleep(COOLDOWN + 1)
    for trustee in trustees:
        receipt, envelope = vetoed.read(trustee)
        assert (receipt["newState"], receipt["reason"], envelope) == ("cancelled", "recovery_vetoed", None)
    ok("a veto during the cooldown blocks release after it")

    # --- Refusals ---------------------------------------------------------
    errors = []
    wrong = c.Candidate(recovery_map, factors)
    errors.append(refused(lambda: first.post(wrong.begin_request(first, factor=other_factor)),
                          400, "invalid_candidate_factor"))
    unknown = c.Candidate(dict(recovery_map, enrollmentId=c.random_id()), factors)
    errors.append(refused(lambda: first.post(unknown.begin_request(first)), 400, "invalid_request"))
    stranger = Ed25519PrivateKey.generate()
    forged = first.signed("read-enrollment", stranger, ("enrollmentId", recovery_map["enrollmentId"]))
    errors.append(refused(lambda: first.post(forged), 400, "invalid_request"))
    errors.append(refused(lambda: first.post({"requestVersion": 1, "operation": "bootstrap-recovery"}),
                          501, "bootstrap_unavailable"))
    errors.append(refused(lambda: first.post({"requestVersion": 1, "operation": "finalize-recovery"}),
                          400, "invalid_request"))
    for probe in (
        {"requestVersion": 1, "operation": canary},
        {"requestVersion": 1, "operation": "issue-challenge", "componentId": first.component_id,
         "invitation": canary},
        {"requestVersion": 1, "operation": "enroll", "context": {"slot": canary}},
        {"requestVersion": 1, "operation": "begin-recovery", "session": {"sessionId": canary}},
    ):
        errors.append(refused(lambda: first.post(probe), 400, "invalid_request"))
    limit = first.manifest["limits"]["maximumRequestBytes"]
    errors.append(refused(lambda: c.http(first.endpoint, b" " * (limit + 1)), 400, "invalid_request"))
    ok("wrong factor, unknown enrollment, forged key, unsupported operations and oversize "
       "bodies get their declared refusals")

    # --- A recovery that completes ----------------------------------------
    candidate = c.Candidate(recovery_map, factors)
    deadlines = [candidate.begin(trustee)["cooldownEndsAt"] for trustee in trustees]
    for trustee in trustees:
        receipt, envelope = candidate.read(trustee)
        assert (receipt["newState"], envelope) == ("cooling_down", None)
    servers[1].stop()
    servers[1].start()
    receipt, _ = candidate.read(second)
    assert (receipt["newState"], receipt["cooldownEndsAt"]) == ("cooling_down", deadlines[1])
    ok("nothing is released during the cooldown, and a restart keeps the deadline")

    time.sleep(max(c.seconds(deadline) for deadline in deadlines) - time.time() + 1)
    released = [candidate.read(trustee) for trustee in trustees]
    shares = [envelope["slip39Share"] for _, envelope in released]
    again, envelope = candidate.read(first)
    assert again["contribution"] == released[0][0]["contribution"] and envelope["slip39Share"] == shares[0]
    ok("after the cooldown every trustee releases; a later read resends the same contribution")

    artifact = c.restore(recovery_map, shares[:2])
    assert artifact["payload"] == canary
    assert raises(MnemonicError, lambda: c.restore(recovery_map, shares[:1]))
    ok("two shares rebuild the key and open the artifact; one share does not")
    ok("Rust opened Python's HPKE envelopes and verified its signatures; Python opened "
       "Rust's contributions and verified its receipts")

    # --- The recovered vault holds the enrollment's authority ---------------
    recovered = c.Holder(recovery_map["enrollmentId"], [
        (trustee, c.ed25519(artifact["authorizationKeys"][trustee.component_id])) for trustee in trustees
    ])
    assert all(receipt["newState"] == "closed" for receipt in recovered.close())
    errors.append(refused(lambda: candidate.read(first), 409, "enrollment_revoked"))
    ok("the recovered vault closes the enrollment; the trustees then refuse the session")

    for body in errors:
        assert canary.encode() not in body, body
    return [
        canary, map_key.hex(), combine_mnemonics(shares[:2]).hex(), *shares, *factors.values(),
        *artifact["authorizationKeys"].values(), recovery_map["enrollmentId"], candidate.session_id,
        vetoed.session_id,
    ]


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--binary", default=str(ROOT / "target/debug/onym-recovery-trustee"))
    parser.add_argument("--port", type=int, default=18181, help="first of three ports")
    args = parser.parse_args()

    with tempfile.TemporaryDirectory() as work:
        work = Path(work)
        servers = [Server(args.binary, work, name, args.port + n) for n, name in enumerate("abc")]
        try:
            for server in servers:
                server.start()
            planted = check(servers)
        finally:
            for server in servers:
                server.stop()
        logs = b"".join(server.log.read_bytes() for server in servers)
        leaked = [secret for secret in planted if secret.encode() in logs]
        assert not leaked, f"secrets in the logs: {leaked}"
        ok(f"no planted secret, share, key or identifier in error bodies or {len(logs)} bytes of logs")
    print("end to end: all checks passed")


if __name__ == "__main__":
    main()
