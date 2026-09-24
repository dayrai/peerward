#!/bin/sh
set -eu

production_limit=600
test_limit=900
failed=0

files=$(git ls-files --cached --others --exclude-standard -- \
    'crates/**/*.rs' 'apps/**/*.rs' 'apps/**/*.kt')

for file in $files; do
    [ -f "$file" ] || continue
    case "$file" in
        */target/*|*/build/*|*/generated/*)
            continue
            ;;
        */tests/*|*/src/test/*|*/src/androidTest/*|*/tests.rs|*_tests.rs|*/tests_*.rs)
            limit=$test_limit
            kind='test'
            ;;
        *)
            limit=$production_limit
            kind='production'
            ;;
    esac

    lines=$(wc -l < "$file")
    if [ "$lines" -gt "$limit" ]; then
        printf '%s source exceeds %s lines: %s (%s)\n' \
            "$kind" "$limit" "$file" "$lines" >&2
        failed=1
    fi
done

if [ "$failed" -ne 0 ]; then
    exit 1
fi

printf 'source size policy passed (production <= %s, tests <= %s)\n' \
    "$production_limit" "$test_limit"
