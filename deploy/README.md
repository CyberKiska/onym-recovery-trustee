# Deploying the trustee

One operator, one host: three trustees, a 2-of-3 set, behind Caddy.

- **Trustees** run as uid 10001 with a read-only root and key file, no
  capabilities, no core dumps and no published port. Each writes only its
  own data volume and refuses a database that belongs to another key.
- **Caddy** terminates TLS (Let's Encrypt), cuts off slow clients, caps
  request bodies and queues requests instead of piling them onto a trustee.
  It keeps no access log, and logs failed requests without the client's
  address, URI or headers. It runs read-only, able only to bind 80 and 443.

The three trustees declare one trust domain, so a client warns that they
are not independent. The service is unreviewed: its manifest limits it to
synthetic test secrets, and so should you.

## First start

You need a Linux host with Docker Engine and Compose, ports 80 and 443
open, and three DNS names pointing straight at it (no proxying CDN: the
ACME challenge must reach Caddy).

```sh
cd deploy
cp .env.example .env        # hostnames, trust domain, contact
docker compose build

install -d -m 700 secrets
for t in a b c; do
  docker run --rm --user "$(id -u):$(id -g)" -v "$PWD/secrets:/keys" \
    onym-recovery-trustee:local keygen /keys/trustee-$t.key
done
sudo chown 10001:10001 secrets/*.key   # readable by the service user only

docker compose up -d
docker compose logs trustee-a trustee-b trustee-c   # component, operator key, trusteeKeyId
```

`keygen` prints each trustee's operator key and `trusteeKeyId`; publish them
wherever holders can compare them with the manifests. Back up `secrets/`
offline and apart from the data volumes.

Check the running stack, spending one invitation per trustee:

```sh
python3 -m venv .venv && .venv/bin/pip install --require-hashes -r ../tools/requirements.txt
PYTHON=.venv/bin/python ./check.sh
```

To run everything on one machine instead, with Caddy's own CA on
`https://localhost:8441` to `8443`: `cp local.env .env` and the same steps.
On Docker Desktop the `chown` is not needed.

## Invitations

Enrollment needs one invitation per holder and trustee. Mint them on the
host and hand each over with its origin, `https://<host>`:

```sh
docker compose exec trustee-a onym-recovery-trustee invite P7D
```

Holders enroll with `tools/client.py` (see the top-level README).

## Operating

- **Restart or upgrade:** `docker compose up -d --build`. A trustee drains
  on SIGTERM; custody, sessions and cooldown deadlines live in its volume.
- **Keys:** never change a trustee's key or component ID under existing
  enrollments; the trustee refuses to start. There is no key rotation yet.
- **Key lost:** that trustee's custody is gone. A 2-of-3 set still
  recovers without it; holders should close and enroll again.
- **Key leaked:** stop that trustee (`docker compose stop trustee-a`) and
  tell its holders to close and enroll elsewhere; the leaked key opens every
  envelope it stored.
- **Backups:** a trustee restored from an older copy can forget a veto, a
  cancellation or spent attempts, and nothing here detects it. Restore only
  test data, and tell holders when you do.
- **Deletion:** revoke and close remove custody from the live database at
  once. Volume snapshots and backups keep what they held.
- **Logs:** per request, route, status, error code and duration; public
  keys at startup. Rotated at 3 × 10 MB.
- **Limits:** stock Caddy has no per-client rate limit. The attempt budget,
  single-use invitations and the body and connection caps bound what
  anonymous traffic can do; add a rate-limiting front end before any real
  use.
