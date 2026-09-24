# onym-recovery-trustee

Reference trustee for the Onym recovery-trustee seat, Shamir profile
[`onym:recovery-implementation:shamir-trustees-slip39-v1`](https://github.com/onymchat/onym-system/blob/main/recovery/Recovery-Trustee-Shamir.md),
wire binding `draft-1`.

A trustee holds one SLIP-0039 share for one enrollment slot. It checks the
share and the holder's signed terms when it takes custody. At recovery, once
the enrolled policy allows it, it re-seals that same holder-signed envelope to
a fresh destination key. The destination device combines shares itself.

## What it is not

- **Not a secret-sharing implementation.** No code here splits, combines or
  reconstructs a secret. A trustee validates one share and never sees another.
- **Not able to read what it guards.** The protected recovery artifact is
  encrypted under a key only a recovering vault reconstructs. The trustee
  checks its digest and header, not its contents.
- **Not reviewed.** Nothing here has had independent cryptographic or code
  review. Do not use it with real secrets.

## Status

Done:

- **Protocol core:** SLIP-0039 single-share validation; canonical JSON and
  the binding's objects; fixed-suite HPKE and Ed25519; the pure release
  predicate.
- **Durable lifecycle in SQLite:** invitations and single-use challenges,
  custody with read-back before the receipt, recovery sessions with
  attempts and a cooldown, holder-poll notices, veto and cancellation,
  revocation and closure as tombstones, replay nonces and idempotent
  outcomes.
- **HTTP service:** a signed manifest and one request endpoint.
- **Python client:** enrollment, holder poll and veto, and recovery,
  checked end to end against three local trustees.

There is no public deployment yet. The wire binding is a draft that has not
been agreed with the Onym maintainers. Everything it decides lives in
`src/wire.rs`.

| Module | Role |
|---|---|
| `src/slip39.rs` | One share: word list, RS1024 checksum, padding, profile parameters |
| `src/wire.rs` | The binding: canonical JSON, encodings, digests, HPKE `info` tuples, objects, error codes |
| `src/crypto.rs` | HPKE Base mode, DHKEM(X25519, HKDF-SHA256), HKDF-SHA256, AES-256-GCM; Ed25519 `verify_strict`; SHA-256 |
| `src/state.rs` | Session admission and the release predicate, with time passed in |
| `src/lib.rs` | Enrollment acceptance, artifact check, session verification, factor check, release, manifest |
| `src/store.rs` | SQLite (WAL, `synchronous=FULL`): one IMMEDIATE transaction per request; receipts signed after commit and read-back |
| `src/main.rs` | `serve`, `keygen`, `invite`; the HTTP binding |
| `tools/client.py` | Holder and candidate client (pyca/cryptography, Trezor's `shamir-mnemonic`) |
| `tools/e2e.py` | The end-to-end check against three local trustees |

## Running a trustee

```sh
cargo build --release
target/release/onym-recovery-trustee keygen trustee.key   # owner-only; prints the public keys
TRUSTEE_STORE_PATH=trustee.sqlite target/release/onym-recovery-trustee invite   # one code per holder

TRUSTEE_COMPONENT_ID=onym:component:my-trustee \
TRUSTEE_PUBLIC_URL=https://trustee.example \
TRUSTEE_KEY_FILE=trustee.key \
TRUSTEE_STORE_PATH=trustee.sqlite \
target/release/onym-recovery-trustee serve
```

`onym-recovery-trustee` with no arguments lists every variable. The
service speaks plain HTTP/1 and expects a TLS proxy in front of it.

| Route | |
|---|---|
| `GET /manifest.json` | The signed manifest: keys, limits, supported and refused operations, the free offer |
| `GET /health` | `{"status":"ok"}` |
| `POST /v1/trustee` | One canonical request object; the response is a signed receipt or `{"error": code}` |

Status classes are 400 for an invalid request, 409 for a state conflict,
429 when attempts are spent, 501 for a declared-unsupported operation and
503 when the trustee cannot decide safely. The log records route, status,
code and duration, never a body, identifier or key.

## Client

```sh
pip install --require-hashes -r tools/requirements.txt
python3 tools/client.py enroll --threshold 2 --out vault \
    --trustee https://a.example CODE_A --trustee https://b.example CODE_B --trustee https://c.example CODE_C
python3 tools/client.py poll --holder vault/holder.json
python3 tools/client.py veto --holder vault/holder.json SESSION_ID
python3 tools/client.py recover --map vault/map.json --map-key vault/map.key --factors vault/factors.json
```

`enroll` writes the encrypted recovery map, its key, the holder's scoped
keys and the independently held factor keys, all owner-only. It is a demo
client, not a vault: keys sit in plain files and the artifact is synthetic.

## Tests

```sh
cargo test
cargo clippy --all-targets -- -D warnings
```

The conformance suite (`tests/conformance.rs`) checks the SLIP-0039 decoder
against the reference implementation's own decoding of every official
vector, and validates generated profile shares. It runs the CFRG HPKE vector
for this exact suite and reproduces Onym Discovery's canonical-JSON bytes. It
also pins the binding vectors in `tests/fixtures/binding/` and refuses a
tampered version of every binding. See
[`tests/fixtures/README.md`](tests/fixtures/README.md) for provenance.

The lifecycle suite (`tests/lifecycle.rs`) drives `Store::handle` end to end:

- enrollment only with an issued, unused challenge;
- identical retries returning identical bytes, even after the replay window;
- a restart during cooldown keeping the deadline;
- holder veto against release, raced on two connections;
- tombstones refusing replays, and bounded attempts.

The end-to-end check runs the client against three trustee processes: 2-of-3
enrollment, holder poll and veto, refusals, release after the cooldown
across a restart, reconstruction with two shares and not one, and a scan of
error bodies and logs for planted secrets.

```sh
cargo build
python3 tools/e2e.py
```

Regenerating fixtures is deliberate:

```sh
REGEN_FIXTURES=1 cargo test --test conformance      # binding vectors
pip install --require-hashes -r tools/requirements.txt
python3 tools/client.py share-fixtures               # SLIP-0039 fixtures
```

## Failure behaviour

- **Entropy.** It never falls back to a deterministic source. `hpke` 0.14.1
  draws the ephemeral key through an infallible RNG interface, so an OS RNG
  failure panics inside sealing. Both profiles build with `panic = "abort"`,
  so that ends the process before anything is sealed, sent or committed.
  `serve` also refuses to start if the OS RNG fails.
- **Errors.** Every error is a stable code from the recovery contract's §15
  vocabulary, plus `invalid_request` and `request_conflict`. None carries data.

## Licence

MIT. Vendored data keeps its own notices; see
[`tests/fixtures/README.md`](tests/fixtures/README.md).
