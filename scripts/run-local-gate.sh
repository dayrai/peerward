#!/usr/bin/env bash
set -euo pipefail

root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
gate=${1:-}
shift || true
target_arguments=$(jq -cn '$ARGS.positional' --args "$@")
case "$gate" in
  standard|privileged-network|console-e2e|android-web|wcag-visual|android-target|android-emulator|fuzz-smoke|nightly|component-load|deployment-runtime|full) ;;
  *)
    echo "usage: scripts/run-local-gate.sh LOCAL_CI_TARGET [TARGET ARGUMENTS]" >&2
    exit 64
    ;;
esac

worktree_fingerprint() {
  (
    cd "$root"
    {
      git diff --binary HEAD --
      while IFS= read -r -d '' path; do
        printf 'untracked\0%s\0' "$path"
        sha256sum --zero -- "$path"
      done < <(git ls-files --others --exclude-standard -z | LC_ALL=C sort -z)
    } | sha256sum | cut -d' ' -f1
  )
}

started_at=$(date -u +%Y-%m-%dT%H:%M:%SZ)
stamp=$(date -u +%Y%m%dT%H%M%SZ)
commit=$(git -C "$root" rev-parse HEAD)
started_fingerprint=$(worktree_fingerprint)
if [[ -z "$(git -C "$root" status --porcelain --untracked-files=normal)" ]]; then
  worktree_clean=true
else
  worktree_clean=false
fi
directory="$root/artifacts/local-gates/$commit/$stamp-$gate"
mkdir -p "$directory"
log="$directory/output.log"

set +e
"$root/scripts/local-ci.sh" "$gate" "$@" 2>&1 | tee "$log"
status=${PIPESTATUS[0]}
set -e
finished_at=$(date -u +%Y-%m-%dT%H:%M:%SZ)
finished_fingerprint=$(worktree_fingerprint)
if [[ "$finished_fingerprint" != "$started_fingerprint" ]]; then
  printf 'local verification invalidated: the version-controlled worktree changed during execution\n' \
    | tee -a "$log" >&2
  status=74
  result=invalidated
elif (( status == 0 )); then
  result=passed
else
  result=failed
fi

jq -cn \
  --arg gate "$gate" --arg status "$result" --arg commit "$commit" \
  --arg started "$started_at" --arg finished "$finished_at" \
  --arg host "$(hostname)" --arg kernel "$(uname -srmo)" \
  --arg rustc "$(rustc --version 2>/dev/null || printf unavailable)" \
  --arg cargo "$(cargo --version 2>/dev/null || printf unavailable)" \
  --arg java "$(java --version 2>&1 | head -n 1 || printf unavailable)" \
  --arg started_fingerprint "$started_fingerprint" \
  --arg finished_fingerprint "$finished_fingerprint" \
  --arg log_sha256 "$(sha256sum "$log" | cut -d' ' -f1)" \
  --argjson clean "$worktree_clean" --argjson target_arguments "$target_arguments" \
  '{schema_version:1,kind:"local_verification",gate:$gate,target_arguments:$target_arguments,status:$status,commit_sha:$commit,worktree_clean:$clean,worktree_fingerprint:{started:$started_fingerprint,finished:$finished_fingerprint},started_at:$started,finished_at:$finished,environment:{host:$host,kernel:$kernel},tool_versions:{rustc:$rustc,cargo:$cargo,java:$java},output_log:{name:"output.log",sha256:$log_sha256},release_gate_eligible:false}' \
  >"$directory/result.json"
printf 'local verification record: %s\n' "$directory/result.json"
exit "$status"
