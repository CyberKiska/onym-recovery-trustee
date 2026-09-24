#!/usr/bin/env python3
"""End to end against three local trustee processes:

- 2-of-3 enrollment collects all three receipts and writes the vault files,
  which are read back from disk; a failed enrollment closes what it opened;
- the begin, holder poll, veto and refusal paths behave as specified;
- release happens only after the cooldown, and a restart keeps the deadline;
- recovery completes with one trustee down at begin and another down while
  polling, resuming the candidate's saved session after a restart;
- two shares rebuild the key and open the artifact, one share does not;
- expired pinned manifests still work; a trustee whose keys changed does not;
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
TERMS = {"cooldown": f"PT{COOLDOWN}S", "lifetime": "PT10M", "attempts": 5}


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


def receipts(results):
    """The receipts of a holder operation that must succeed everywhere."""
    failed = [(name, result) for name, result in results if not isinstance(result, dict)]
    assert not failed, failed
    return [receipt for _, receipt in results]


class Server:
    """One trustee process with its own key file, database and log."""

    def __init__(self, binary, work, name, port):
        self.binary, self.port, self.work = binary, port, work
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

    def operator_key(self):
        seed = Path(self.env["TRUSTEE_KEY_FILE"]).read_text().split()[1]
        return c.ed25519(seed)

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


def check(servers, work):
    """The acceptance run. Returns every secret it planted or learned."""
    fixtures = ROOT / "tests/fixtures/canonical"
    for name in ("canonical", "canonical-case", "canonical-escaping", "foundation-vectors"):
        value = c.parse((fixtures / f"{name}-input.json").read_bytes())
        value.pop("signature")  # the bytes are the signing input
        assert c.canonical(value) == (fixtures / f"{name}-bytes.bin").read_bytes(), name
    assert raises(ValueError, lambda: c.parse((fixtures / "duplicate-keys-input.json").read_bytes()))
    for spelling in ("2026-10-01T00:00:00.5Z", "2026-10-01T00:00:00+00:00", "2026-1-01T00:00:00Z"):
        assert raises(ValueError, lambda: c.seconds(spelling)), spelling
    assert raises(ValueError, lambda: c.unb64("AB==")) and raises(ValueError, lambda: c.uint(True))
    ok("Python's stdlib JSON reproduces Discovery's canonical bytes; strict encodings match Rust's")

    trustees = [c.Trustee.fetch(server.origin) for server in servers]
    first, second, third = trustees
    ok("three signed manifests verify")

    # --- Enrollment -------------------------------------------------------
    codes = [server.invite() for server in servers]
    taken = work / "taken"
    taken.mkdir()
    assert raises(FileExistsError, lambda: c.enroll_to(taken, list(zip(trustees, codes)), 2, **TERMS))
    broken = work / "broken"
    assert raises(c.Refused, lambda: c.enroll_to(broken, list(zip(trustees, codes[:2] + ["00" * 32])), 2, **TERMS))
    assert not (broken / "map.json").exists()
    closed = c.Holder.load(c.parse((broken / "holder.json").read_bytes())).poll()
    assert [result["newState"] for _, result in closed[:2]] == ["closed", "closed"], closed
    ok("an existing vault directory stops enrollment before any request; a failed one closes its slots")

    canary = "canary-" + secrets.token_hex(16)
    vault = work / "vault"
    recovery_map = c.enroll_to(vault, [(t, s.invite()) for t, s in zip(trustees, servers)], 2, payload=canary, **TERMS)
    assert oct((vault / "map.key").stat().st_mode & 0o777) == "0o600"
    recovery_map, pinned, threshold = c.open_map(
        c.parse((vault / "map.json").read_bytes()), c.hex32((vault / "map.key").read_text())
    )
    factors = c.parse((vault / "factors.json").read_bytes())
    holder = c.Holder.load(c.parse((vault / "holder.json").read_bytes()))
    assert threshold == 2 and all(r["newState"] == "active" and not r["sessions"] for r in receipts(holder.poll()))
    ok("2-of-3 enrollment: all three receipts verified; the vault files reopen from disk")

    short = dict(recovery_map, trusteeReceipts=recovery_map["trusteeReceipts"][:2])
    assert raises(ValueError, lambda: c.open_map(*c.seal_map(short)))
    ok("a map missing a receipt is refused")

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

    for poll in receipts(holder.poll()):
        [notice] = poll["sessions"]
        assert (notice["sessionId"], notice["state"], notice["released"]) == (vetoed.session_id, "cooling_down", False)
    ok("the holder's poll shows the session at every trustee")

    for receipt in receipts(holder.veto(vetoed.session_id)):
        assert (receipt["newState"], receipt["reason"]) == ("cancelled", "recovery_vetoed")
    time.sleep(COOLDOWN + 1)
    for trustee in trustees:
        receipt, envelope = vetoed.read(trustee)
        assert (receipt["newState"], receipt["reason"], envelope) == ("cancelled", "recovery_vetoed", None)
    quiet = []
    assert raises(ValueError, lambda: c.recover(vetoed, trustees, 0.1, log=quiet.append))
    ok("a veto during the cooldown blocks release after it; recovery then stops, not hangs")

    # --- Refusals ---------------------------------------------------------
    errors = []
    wrong = c.Candidate(recovery_map, factors)
    refusal = first.call(wrong.begin_request(first, factor=other_factor), "begin-recovery", wrong.session_id)
    assert (refusal["newState"], refusal["reason"]) == ("refused", "invalid_candidate_factor")
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
    errors.append(refused(lambda: c.send(first.endpoint, b" " * (limit + 1)), 400, "invalid_request"))
    ok("a wrong factor gets a signed refusal; unknown enrollment, forged key, unsupported "
       "operations and oversize bodies get their declared refusals")

    # --- A recovery that completes with one trustee down at a time ---------
    session_file = work / "session.json"
    candidate = c.Candidate(recovery_map, factors)
    c.write_private(session_file, candidate.state())
    servers[2].stop()
    deadlines = [candidate.begin(trustee)["cooldownEndsAt"] for trustee in (first, second)]
    assert raises(OSError, lambda: candidate.begin(third))
    for trustee in (first, second):
        receipt, envelope = candidate.read(trustee)
        assert (receipt["newState"], envelope) == ("cooling_down", None)
    servers[1].stop()
    servers[1].start()
    receipt, _ = candidate.read(second)
    assert (receipt["newState"], receipt["cooldownEndsAt"]) == ("cooling_down", deadlines[1])
    ok("nothing is released during the cooldown, and a restart keeps the deadline")

    # The candidate restarts from its session file; the third trustee is back,
    # the first is now down.
    servers[2].start()
    servers[0].stop()
    resumed = c.Candidate(recovery_map, factors, c.parse(session_file.read_bytes()))
    assert resumed.session_id == candidate.session_id
    log = []
    shares = c.recover(resumed, pinned, 0.5,
                       save=lambda: c.write_private(session_file, resumed.state(), replace=True), log=log.append)
    assert sorted(resumed.envelopes) == [second.component_id, third.component_id], log
    assert any(line.startswith(f"{first.component_id}: unavailable") for line in log), log
    saved = c.parse(session_file.read_bytes())["contributions"]
    assert sorted(saved) == sorted(resumed.envelopes)
    servers[0].start()
    released = {r["componentId"]: r["sessions"][-1]["released"] for r in receipts(holder.poll())}
    assert released == {first.component_id: False, second.component_id: True, third.component_id: True}
    ok("a resumed session completes with one trustee down at begin and another while polling")

    again, envelope = resumed.read(second)
    assert again["contribution"] == saved[second.component_id] and envelope["slip39Share"] in shares
    ok("a later read resends the same contribution")

    artifact = c.restore(recovery_map, shares)
    assert artifact["payload"]["secret"] == canary
    assert raises(MnemonicError, lambda: c.restore(recovery_map, shares[:1]))
    ok("two shares rebuild the key and open the artifact, identity binding checked; one share does not")
    ok("Rust opened Python's HPKE envelopes and verified its signatures; Python opened "
       "Rust's contributions and verified its receipts")

    # --- Pinned manifests: expiry and key continuity ---------------------
    expired = []
    for trustee, server in zip(pinned, servers):
        manifest = {key: value for key, value in trustee.manifest.items() if key != "signature"}
        manifest["validUntil"] = c.timestamp(time.time() - 60)
        expired.append(c.sign(manifest, "signature", server.operator_key()))
    assert raises(ValueError, lambda: c.Trustee(expired[0]))
    _, old, _ = c.open_map(*c.seal_map(dict(recovery_map, trusteeManifests=expired)))
    assert [trustee.refreshed().operator for trustee in old] == [trustee.operator for trustee in pinned]
    ok("expired manifests pinned in a map still open it; the trustees' current ones continue them")

    # --- The recovered vault holds the enrollment's authority ---------------
    keys = artifact["payload"]["authorizationKeys"]
    recovered = c.Holder(recovery_map["enrollmentId"], [(t, c.ed25519(keys[t.component_id])) for t in pinned])
    assert all(receipt["newState"] == "closed" for receipt in receipts(recovered.close()))
    errors.append(refused(lambda: resumed.read(second), 409, "enrollment_revoked"))
    ok("the recovered vault closes the enrollment; the trustees then refuse the session")

    servers[2].stop()
    Path(servers[2].env["TRUSTEE_KEY_FILE"]).unlink()
    servers[2].run("keygen", servers[2].env["TRUSTEE_KEY_FILE"])
    servers[2].start()
    assert raises(ValueError, lambda: pinned[2].refreshed())
    [(_, error)] = [result for result in recovered.poll() if result[0] == third.component_id]
    assert isinstance(error, ValueError)
    ok("a trustee serving new keys is refused, and only that trustee")

    for body in errors:
        assert canary.encode() not in body, body
    return [
        canary, (vault / "map.key").read_text(), combine_mnemonics(shares).hex(), *shares, *factors.values(),
        *keys.values(), recovery_map["enrollmentId"], candidate.session_id, vetoed.session_id,
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
            planted = check(servers, work)
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
