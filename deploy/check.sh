#!/bin/sh
# Acceptance check against the running stack, with synthetic secrets:
#
# - each trustee runs as uid 10001 with a read-only key and root;
# - a 2-of-3 enrollment over HTTPS verifies every signed manifest and receipt;
# - a trustee restarted during the cooldown keeps the pending session;
# - recovery completes, and the enrollment is closed again.
#
# It spends one invitation per trustee. Run from anywhere:
#   PYTHON=/path/to/venv/bin/python deploy/check.sh
set -eu
cd "$(dirname "$0")"
set -a
. ./.env
set +a
client="${PYTHON:-python3} ../tools/client.py"
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

# A local stack is signed by Caddy's own CA.
case $TRUSTEE_A_HOST in localhost:*)
    docker compose cp caddy:/data/caddy/pki/authorities/local/root.crt "$work/root.crt" >/dev/null 2>&1
    export SSL_CERT_FILE="$work/root.crt" ;;
esac

# Checks one trustee's container, then prints `--trustee ORIGIN INVITATION`.
trustee() {
    docker compose exec -T "trustee-$1" sh -c \
        'test "$(id -u)" = 10001 && ! touch /run/secrets/trustee-key /probe 2>/dev/null' \
        || { echo "trustee-$1: not unprivileged and read-only" >&2; return 1; }
    echo "--trustee https://$2 $(docker compose exec -T "trustee-$1" onym-recovery-trustee invite PT1H)"
}
a=$(trustee a "$TRUSTEE_A_HOST")
b=$(trustee b "$TRUSTEE_B_HOST")
c=$(trustee c "$TRUSTEE_C_HOST")
echo "ok  every trustee runs as uid 10001 with a read-only key and root"

vault=$work/vault
# shellcheck disable=SC2086 # the three argument groups split on purpose
$client enroll --threshold 2 --cooldown PT20S --lifetime PT1H --out "$vault" $a $b $c
echo "ok  2-of-3 enrollment over HTTPS; manifests and receipts verified"

$client recover --map "$vault/map.json" --map-key "$vault/map.key" --factors "$vault/factors.json" \
    --session "$work/session.json" --out "$work/artifact.json" --interval 2 >"$work/recover.log" 2>&1 &
recovering=$!
sleep 4
docker compose restart trustee-b >/dev/null 2>&1
$client poll --holder "$vault/holder.json" >"$work/poll.log"
if [ "$(grep -c ' cooling_down' "$work/poll.log")" != 3 ]; then
    cat "$work/poll.log" "$work/recover.log"
    exit 1
fi
echo "ok  after a restart during the cooldown, every trustee still holds the session"

wait "$recovering" || { cat "$work/recover.log"; exit 1; }
test -s "$work/artifact.json"
echo "ok  recovery completed: t shares, artifact opened, identity binding verified"

$client close --holder "$vault/holder.json" >/dev/null
echo "ok  enrollment closed at every trustee"
