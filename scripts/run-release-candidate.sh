#!/usr/bin/env bash
# Local release-candidate orchestration. It deliberately does not create stable release evidence.
set -uo pipefail

root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
usage() {
  cat <<'USAGE'
usage: scripts/run-release-candidate.sh [console|full]

console  Run the repository core gate, guided Console/Playwright regressions,
         and deployment-contract checks. This is the default profile.
full     Run the complete local gate, guided Console regressions, and the
         disposable Linux updater apply/rollback rehearsal.

The result is written under artifacts/release-candidate/. It is local candidate
information only (release_gate_eligible=false) and cannot close stable-release
evidence gates.
USAGE
}

profile=${1:-console}
case "$profile" in
  -h|--help) usage; exit 0 ;;
  console|full) ;;
  *) usage >&2; exit 64 ;;
esac
(( $# <= 1 )) || { usage >&2; exit 64; }

for command_name in git jq python3 sha256sum tee; do
  command -v "$command_name" >/dev/null 2>&1 || {
    echo "$command_name is required for release-candidate orchestration" >&2
    exit 69
  }
done

git -C "$root" rev-parse --show-toplevel >/dev/null 2>&1 || {
  echo "release-candidate checks require a Git worktree, not a source archive" >&2
  exit 69
}
[[ "$(git -C "$root" rev-parse --show-toplevel)" == "$root" ]] || {
  echo "repository root mismatch" >&2
  exit 69
}
if [[ -n "$(git -C "$root" status --porcelain --untracked-files=normal)" ]]; then
  echo "release-candidate checks require a clean worktree" >&2
  git -C "$root" status --short --untracked-files=normal >&2
  exit 65
fi

commit=$(git -C "$root" rev-parse HEAD)
started_at=$(date -u +%Y-%m-%dT%H:%M:%SZ)
stamp=$(date -u +%Y%m%dT%H%M%SZ)
directory="$root/artifacts/release-candidate/$commit/$stamp-$profile"
mkdir -p "$directory"
steps_file="$directory/steps.jsonl"
: >"$steps_file"
failed=0

run_step() {
  local name=$1
  shift
  local log="$directory/$name.log" step_started step_finished status code command_json
  step_started=$(date -u +%Y-%m-%dT%H:%M:%SZ)
  command_json=$(jq -cn '$ARGS.positional' --args "$@")
  printf '\n== %s ==\n' "$name" | tee "$log"
  printf 'command:' | tee -a "$log"
  printf ' %q' "$@" | tee -a "$log"
  printf '\n' | tee -a "$log"
  set +e
  "$@" 2>&1 | tee -a "$log"
  code=${PIPESTATUS[0]}
  set -e
  step_finished=$(date -u +%Y-%m-%dT%H:%M:%SZ)
  if (( code == 0 )); then
    status=passed
  else
    status=failed
    failed=1
  fi
  jq -cn \
    --arg name "$name" --arg status "$status" \
    --arg started_at "$step_started" --arg finished_at "$step_finished" \
    --arg log "$(basename "$log")" \
    --arg log_sha256 "$(sha256sum "$log" | cut -d' ' -f1)" \
    --argjson exit_code "$code" --argjson command "$command_json" \
    '{name:$name,status:$status,exit_code:$exit_code,command:$command,started_at:$started_at,finished_at:$finished_at,log:{path:$log,sha256:$log_sha256}}' \
    >>"$steps_file"
}

cd "$root"
if [[ "$profile" == console ]]; then
  run_step core scripts/verify.sh core
  run_step console_v14 env \
    "PEERWARD_EVIDENCE_SCREENSHOT_DIR=$directory/console-v14-screenshots" \
    scripts/test-console-v14.sh
  run_step deployment_contract scripts/verify.sh deployment
else
  run_step local_full_gate scripts/run-local-gate.sh full
  run_step console_v14 env \
    "PEERWARD_EVIDENCE_SCREENSHOT_DIR=$directory/console-v14-screenshots" \
    scripts/test-console-v14.sh
  run_step upgrade_rollback_rehearsal \
    scripts/test-upgrade-rollback-rehearsal.sh \
    --output "$directory/upgrade-rollback"
fi

finished_at=$(date -u +%Y-%m-%dT%H:%M:%SZ)
final_commit=$(git -C "$root" rev-parse HEAD)
final_status=$(git -C "$root" status --porcelain --untracked-files=normal)
invalidated=0
if [[ "$final_commit" != "$commit" || -n "$final_status" ]]; then
  invalidated=1
  failed=1
  printf '\nrelease-candidate check invalidated: source worktree changed during execution\n' >&2
fi
release_json=$(python3 - "$root/release.toml" <<'PY'
import json
import pathlib
import sys
import tomllib
with pathlib.Path(sys.argv[1]).open('rb') as source:
    print(json.dumps(tomllib.load(source), separators=(',', ':')))
PY
)
steps_json=$(jq -s '.' "$steps_file")
evidence_json=$(cat "$root/release/release-evidence.preview.json")

jq -n \
  --arg profile "$profile" --arg commit_sha "$commit" --arg final_commit_sha "$final_commit" \
  --arg started_at "$started_at" --arg finished_at "$finished_at" \
  --argjson release "$release_json" --argjson steps "$steps_json" \
  --argjson evidence_preview "$evidence_json" \
  --argjson passed "$(( failed == 0 ))" --argjson invalidated "$invalidated" \
  --argjson worktree_clean_at_finish "$(( ${#final_status} == 0 ))" \
  '{schema_version:1,kind:"local_release_candidate_check",profile:$profile,status:(if $invalidated==1 then "invalidated" elif $passed==1 then "passed" else "failed" end),commit_sha:$commit_sha,final_commit_sha:$final_commit_sha,worktree_clean_at_start:true,worktree_clean_at_finish:($worktree_clean_at_finish==1),started_at:$started_at,finished_at:$finished_at,release:$release,steps:$steps,release_evidence_preview:$evidence_preview,release_gate_eligible:false,stable_release_authorized:false,boundaries:["local checks do not close signed release-evidence gates","guided Console fixtures do not prove live Mesh connectivity","updater rehearsal uses synthetic role executables and does not prove full application/database cross-version compatibility","independent keyboard/focus/manual WCAG review and physical-device evidence remain separate"]}' \
  >"$directory/summary.json"

cat >"$directory/manual-checks.md" <<EOF_MANUAL
# Manual release-candidate follow-up

Candidate commit: \`$commit\`
Profile: \`$profile\`
Automated summary: \`summary.json\`

Do not mark a stable release from this file. Record independent evidence through the release-evidence process.

- [ ] Review every failed/warning log; no unexplained browser console or server error remains.
- [ ] Pure-keyboard pass: main navigation → device detail → tab navigation → close/focus return → global search.
- [ ] Independent focus and screen-reader/manual WCAG review completed; automated axe alone is not sufficient.
- [ ] Backup plus encrypted external-secret restore was rehearsed on an isolated copy.
- [ ] Rollout/rollback plan was checked against the exact Schema/Wire compatibility in \`release.toml\`.
- [ ] A complete application rollout (not only the synthetic updater role fixture) was exercised in a disposable installation.
- [ ] Required physical Android, real-network, soak, capacity, clean-room and external-security evidence is attached or explicitly remains missing for this channel.
- [ ] Artifact inventory, evidence binding and signatures are created only after the final commit and artifact set are frozen.
EOF_MANUAL

printf '\nrelease-candidate summary: %s\n' "$directory/summary.json"
printf 'manual follow-up: %s\n' "$directory/manual-checks.md"
if (( failed )); then
  exit 1
fi
