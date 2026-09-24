#!/usr/bin/env bash
set -euo pipefail

workspace="$(cd "$(dirname "$0")/.." && pwd)"
cd "$workspace"

# The complete supported product graph has one reviewed RSA exception.
cargo deny check --hide-inclusion-graph
(
    cd fuzz
    cargo deny --config ../deny-fuzz.toml check --hide-inclusion-graph advisories sources
)

# Treat every new or changed duplicate as a supply-chain review failure.
duplicate_dir="$(mktemp -d)"
trap 'rm -rf -- "$duplicate_dir"' EXIT
duplicate_headings() {
    awk 'BEGIN { first=1 } /^$/ { first=1; next } first { print $1, $2; first=0 }' \
        | sort -u
}
reviewed_duplicates() {
    sed -e '/^[[:space:]]*#/d' -e '/^[[:space:]]*$/d' "$1" | sort -u
}
cargo tree --duplicates --workspace --prefix none \
    | duplicate_headings > "$duplicate_dir/core.actual"
reviewed_duplicates scripts/allowed-core-duplicates.txt > "$duplicate_dir/core.expected"
diff -u "$duplicate_dir/core.expected" "$duplicate_dir/core.actual"
# cargo-audit sees informational maintenance/unsound findings that cargo-deny
# intentionally does not match. Require the reviewed list to be exact so a
# stale exception and a new finding both fail before applying the exceptions.
reviewed_duplicates scripts/allowed-rustsec.txt > "$duplicate_dir/rustsec.expected"
cargo audit --json > "$duplicate_dir/rustsec.json" || true
python3 - "$duplicate_dir/rustsec.json" > "$duplicate_dir/rustsec.actual" <<'PY'
import json
import sys

report = json.load(open(sys.argv[1], encoding="utf-8"))
identifiers = {item["advisory"]["id"] for item in report["vulnerabilities"]["list"]}
for findings in report["warnings"].values():
    identifiers.update(item["advisory"]["id"] for item in findings)
print("\n".join(sorted(identifiers)))
PY
diff -u "$duplicate_dir/rustsec.expected" "$duplicate_dir/rustsec.actual"
python3 - scripts/rustsec-exceptions.json "$duplicate_dir/rustsec.expected" <<'PY'
import datetime
import json
import pathlib
import sys

metadata = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
if set(metadata) != {"schema_version", "exceptions"} or metadata["schema_version"] != 1:
    raise SystemExit("RustSec exception metadata must use exact schema version 1")
expected = set(pathlib.Path(sys.argv[2]).read_text(encoding="utf-8").splitlines())
exceptions = metadata["exceptions"]
if not isinstance(exceptions, list) or not exceptions:
    raise SystemExit("RustSec exception metadata must contain a non-empty exceptions array")
ids = set()
today = datetime.date.today()
for index, item in enumerate(exceptions):
    required = {"id", "owner", "scope", "reviewed_on", "expires_on"}
    if not isinstance(item, dict) or set(item) != required:
        raise SystemExit(f"RustSec exception {index} fields differ from the strict schema")
    if item["id"] in ids:
        raise SystemExit(f"duplicate RustSec exception {item['id']}")
    ids.add(item["id"])
    if not item["owner"].strip() or not item["scope"].strip():
        raise SystemExit(f"RustSec exception {item['id']} lacks owner or constrained scope")
    reviewed = datetime.date.fromisoformat(item["reviewed_on"])
    expires = datetime.date.fromisoformat(item["expires_on"])
    if reviewed > today or (today - reviewed).days > 93:
        raise SystemExit(f"RustSec exception {item['id']} missed quarterly review")
    if expires < today or expires <= reviewed:
        raise SystemExit(f"RustSec exception {item['id']} is expired or has an invalid expiry")
if ids != expected:
    raise SystemExit(
        f"RustSec metadata IDs differ: missing={sorted(expected-ids)} extra={sorted(ids-expected)}"
    )
PY
mapfile -t reviewed_rustsec < "$duplicate_dir/rustsec.expected"
audit_ignore_args=()
for advisory in "${reviewed_rustsec[@]}"; do
    audit_ignore_args+=(--ignore "$advisory")
done
cargo audit --deny warnings "${audit_ignore_args[@]}"
cargo audit --file fuzz/Cargo.lock --deny warnings
