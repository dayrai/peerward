#!/bin/sh
set -eu

repository=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
cd "$repository"
set -a
# shellcheck source=/dev/null
. ./.env
set +a

control_url=${PEERWARD_ANDROID_CONTROL_URL:-http://127.0.0.1:28080}
claim_url_base=${PEERWARD_ANDROID_CLAIM_URL_BASE:-http://127.0.0.1:28080}
authorization="Authorization: Bearer $PEERWARD_DEV_BEARER"

meshes=$(curl --fail --silent --show-error -H "$authorization" "$control_url/api/v1/meshes?limit=100")
mesh_id=""
for candidate in $(printf '%s' "$meshes" | jq -r '.items[].id'); do
    authorities=$(curl --fail --silent --show-error -H "$authorization" \
        "$control_url/api/v1/meshes/$candidate/authorities?limit=100")
    if printf '%s' "$authorities" | jq -e '.items[] | select(.lifecycle == "active")' >/dev/null; then
        mesh_id=$candidate
        break
    fi
done
test -n "$mesh_id" || { echo "no Mesh has an active Authority" >&2; exit 1; }

ticket=$(curl --fail --silent --show-error \
    -H "$authorization" -H 'Content-Type: application/json' \
    --data '{"expires_in_seconds":600}' \
    "$control_url/api/v1/meshes/$mesh_id/join-tickets")
token=$(printf '%s' "$ticket" | jq -er '.token')
fingerprint=$(printf '%s' "$ticket" | jq -er '.root_fingerprint')
expires_at=$(printf '%s' "$ticket" | jq -er '.expires_at_unix')
nonce=$(openssl rand -base64 24 | tr '+/' '-_' | tr -d '=\n')
bundle=$(jq -cn \
    --arg claim_url "$claim_url_base/api/v1/join/$token/claim" \
    --arg root_fingerprint "$fingerprint" \
    --argjson expires_at "$expires_at" \
    --arg nonce "$nonce" \
    '{claim_url:$claim_url,root_fingerprint:$root_fingerprint,expires_at:$expires_at,nonce:$nonce}')
encoded=$(printf '%s' "$bundle" | base64 -w 0 | tr '+/' '-_' | tr -d '=')
printf 'peerward://join?bundle=%s\n' "$encoded"
