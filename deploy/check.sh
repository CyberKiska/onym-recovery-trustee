#!/bin/sh
# Acceptance check against the running stack, with synthetic secrets:
#
# - each trustee runs as uid 10001 with a read-only key file and root;
# - a 2-of-3 enrollment over HTTPS verifies every signed manifest and receipt;
# - with trustee C down, recovery needs B; B goes down during the cooldown
#   and is recreated, as an upgrade does, and the client waits it out with
#   the same session instead of giving up;
# - recovery completes with one session and one release at A and at B;
# - a request sent to B while it was down left no client address, URI or
#   header in any log;
# - the enrollment is closed again.
#
# It spends one invitation per trustee and stops trustee C while it runs.
# Run from anywhere:
#   PYTHON=/path/to/venv/bin/python deploy/check.sh
set -eu
cd "$(dirname "$0")"
set -a
. ./.env
set +a
python=${PYTHON:-python3}
client="$python ../tools/client.py"
work=$(mktemp -d)
recovering=
# However the check ends: no client left running, the stack whole again.
trap 'set +e; [ -z "$recovering" ] || kill "$recovering" 2>/dev/null; wait
      docker compose start trustee-b trustee-c >/dev/null 2>&1; rm -rf "$work"' EXIT

# A local stack is signed by Caddy's own CA, which exists once Caddy runs.
case $TRUSTEE_A_HOST in localhost:*) export SSL_CERT_FILE="$work/root.crt" ;; esac

# Waits, at most a minute, until every named site answers over TLS.
ready() {
    for _ in $(seq 60); do
        if { [ -z "${SSL_CERT_FILE:-}" ] || docker compose cp \
                caddy:/data/caddy/pki/authorities/local/root.crt "$SSL_CERT_FILE" >/dev/null 2>&1; } &&
            $python -c 'import sys, urllib.request
for host in sys.argv[1:]:
    urllib.request.urlopen(f"https://{host}/health", timeout=5).read()' "$@" 2>/dev/null; then
            return
        fi
        sleep 1
    done
    echo "not answering over TLS: $*" >&2
    return 1
}

# Waits, at most a minute, until the recovery log has $2 lines matching $1.
logged() {
    for _ in $(seq 60); do
        [ "$(grep -c -e "$1" "$work/recover.log")" -ge "$2" ] && return
        sleep 1
    done
    cat "$work/recover.log" >&2
    return 1
}

# Checks one trustee's container, then prints `--trustee ORIGIN INVITATION`.
trustee() {
    docker compose exec -T "trustee-$1" sh -c 'test "$(id -u)" = 10001 &&
            ! touch /run/secrets/trustee-key 2>/dev/null && ! touch /probe 2>/dev/null' ||
        { echo "trustee-$1: not uid 10001 with a read-only key file and root" >&2; return 1; }
    echo "--trustee https://$2 $(docker compose exec -T "trustee-$1" onym-recovery-trustee invite PT1H)"
}

ready "$TRUSTEE_A_HOST" "$TRUSTEE_B_HOST" "$TRUSTEE_C_HOST"
a=$(trustee a "$TRUSTEE_A_HOST")
b=$(trustee b "$TRUSTEE_B_HOST")
c=$(trustee c "$TRUSTEE_C_HOST")
echo "ok  every trustee runs as uid 10001 with a read-only key file and root"

vault=$work/vault
# The shortest cooldown every trustee accepts: the floor compose gives them.
# shellcheck disable=SC2086 # the three argument groups split on purpose
$client enroll --threshold 2 --cooldown "${MIN_COOLDOWN:-PT1M}" --lifetime PT1H --out "$vault" $a $b $c
echo "ok  2-of-3 enrollment over HTTPS; manifests and receipts verified"

docker compose stop trustee-c >/dev/null 2>&1
# Unbuffered, so its log shows each step as it happens.
PYTHONUNBUFFERED=1 $client recover --map "$vault/map.json" --map-key "$vault/map.key" --factors "$vault/factors.json" \
    --session "$work/session.json" --out "$work/artifact.json" --interval 2 >"$work/recover.log" 2>&1 &
recovering=$!
logged ': cooling down until' 2

docker compose stop trustee-b >/dev/null 2>&1
canary=$($python -c 'import secrets; print("canary-" + secrets.token_hex(16))')
$python -c 'import sys, urllib.error, urllib.request
request = urllib.request.Request(sys.argv[1] + "?" + sys.argv[2], headers={"X-Canary": sys.argv[2]})
try:
    urllib.request.urlopen(request, timeout=10)
except urllib.error.HTTPError as error:
    sys.exit(error.code != 502)
sys.exit(1)' "https://$TRUSTEE_B_HOST/manifest.json" "$canary"
logged '-b: unavailable (502' 1
docker compose up -d --force-recreate --no-deps trustee-b >/dev/null 2>&1

wait "$recovering" || { recovering=; cat "$work/recover.log"; exit 1; }
recovering=
test -s "$work/artifact.json"
echo "ok  C down, B recreated mid-recovery: the client retried B's 502s instead of dropping it"
echo "ok  recovery completed: t shares, artifact opened, identity binding verified"

docker compose start trustee-c >/dev/null 2>&1
ready "$TRUSTEE_C_HOST"
$client poll --holder "$vault/holder.json" >"$work/poll.log"
if [ "$(grep -c '^  ' "$work/poll.log")" != 2 ] ||
    [ "$(grep -c '^  .*contribution released' "$work/poll.log")" != 2 ]; then
    cat "$work/poll.log" "$work/recover.log"
    exit 1
fi
echo "ok  one session and one release at A and at B, none at C: the outage cost no attempt"

enrollment=$($python -c 'import json, sys; print(json.load(open(sys.argv[1]))["enrollmentId"])' "$vault/holder.json")
docker compose logs --no-color >"$work/stack.log" 2>&1
grep -q '"status":502' "$work/stack.log" || { echo "Caddy logged no 502" >&2; exit 1; }
if grep -q -e "$canary" -e "$enrollment" -e remote_ip -e client_ip "$work/stack.log"; then
    echo "a client address, URI, header or identifier reached the logs" >&2
    exit 1
fi
echo "ok  B's 502 is logged without the client's address, URI or headers"

$client close --holder "$vault/holder.json" >/dev/null
echo "ok  enrollment closed at every trustee"
