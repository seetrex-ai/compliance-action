#!/usr/bin/env bash
# Runs every test_intent_* / test_scenario_* function of tests/test_*.sh, each
# in its own bash process (contract in the header of tests/lib.sh).
#
#   bash tests/run_all.sh            all tests, floor enforced
#   bash tests/run_all.sh <regex>    tests whose name matches; no floor
#
# Exit 0 only if every test passed and, unfiltered, the number of discovered
# tests is at least tests/EXPECTED_TEST_COUNT.
set -uo pipefail

TESTS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LIB="$TESTS_DIR/lib.sh"
filter="${1:-}"
per_test_timeout="${TEST_TIMEOUT:-600}"

floor_file="$TESTS_DIR/EXPECTED_TEST_COUNT"
floor=""
if [ -f "$floor_file" ]; then
  floor="$(tr -d '[:space:]' < "$floor_file")"
fi
if ! [[ "$floor" =~ ^[0-9]+$ ]]; then
  printf 'FATAL: %s must hold a single integer (got [%s])\n' "$floor_file" "$floor"
  exit 1
fi

printf 'jq: %s\n' "$(jq --version 2>&1)"
printf 'bash: %s\n' "$BASH_VERSION"

have_timeout=0
if command -v timeout > /dev/null 2>&1; then
  have_timeout=1
fi

errors=0
discovered=0
ran=0
passed=0
failed=0
declare -A owner=()
failed_names=()

shopt -s nullglob
files=("$TESTS_DIR"/test_*.sh)
shopt -u nullglob

for f in "${files[@]}"; do
  base="$(basename "$f")"
  # Discover in a separate process: sourcing must define functions only.
  names_out="$(bash -c '
    set -euo pipefail
    source "$1"
    source "$2"
    compgen -A function test_intent_ || true
    compgen -A function test_scenario_ || true
  ' _ "$LIB" "$f" 2>&1)"
  disc_rc=$?
  if [ "$disc_rc" -ne 0 ]; then
    printf 'FAIL  %s: cannot be sourced (rc=%s)\n%s\n' "$base" "$disc_rc" "$names_out"
    errors=$((errors + 1))
    continue
  fi
  names=()
  while IFS= read -r name; do
    name="${name%$'\r'}"
    [ -n "$name" ] && names+=("$name")
  done <<< "$names_out"

  for name in "${names[@]}"; do
    if [ -n "${owner[$name]:-}" ]; then
      printf 'FAIL  %s: defined in both %s and %s\n' "$name" "${owner[$name]}" "$base"
      errors=$((errors + 1))
      continue
    fi
    owner[$name]="$base"
    discovered=$((discovered + 1))

    if [ -n "$filter" ] && ! [[ "$name" =~ $filter ]]; then
      continue
    fi
    ran=$((ran + 1))

    test_tmp="$(mktemp -d)"
    log="$test_tmp.log"
    runner=(bash -c '
      set -euo pipefail
      cd "$TEST_TMP"
      source "$1"
      source "$2"
      "$3"
    ' _ "$LIB" "$f" "$name")
    if [ "$have_timeout" = 1 ]; then
      runner=(timeout "$per_test_timeout" "${runner[@]}")
    fi
    TEST_TMP="$test_tmp" "${runner[@]}" > "$log" 2>&1 < /dev/null
    rc=$?

    asserts=0
    if [ -f "$test_tmp/.asserts" ]; then
      asserts="$(wc -c < "$test_tmp/.asserts")"
      asserts="${asserts//[[:space:]]/}"
    fi

    verdict=PASS
    reason=""
    if [ "$rc" -eq 124 ] && [ "$have_timeout" = 1 ]; then
      verdict=FAIL
      reason="timed out after ${per_test_timeout}s"
    elif [ "$rc" -ne 0 ]; then
      verdict=FAIL
      reason="exit $rc"
    elif [ "$asserts" -eq 0 ]; then
      verdict=FAIL
      reason="made no assertion"
    fi

    if [ "$verdict" = PASS ]; then
      passed=$((passed + 1))
      printf 'PASS  %s (%s, %s assertions)\n' "$name" "$base" "$asserts"
    else
      failed=$((failed + 1))
      failed_names+=("$name")
      printf 'FAIL  %s (%s): %s\n' "$name" "$base" "$reason"
      while IFS= read -r line; do
        printf '    | %s\n' "$line"
      done < "$log"
    fi

    if [ "${KEEP_TMP:-}" = 1 ]; then
      printf '      kept: %s\n' "$test_tmp"
    else
      rm -rf "$test_tmp" "$log"
    fi
  done
done

printf '\n%s discovered, %s ran, %s passed, %s failed, %s file/discovery errors; floor %s\n' \
  "$discovered" "$ran" "$passed" "$failed" "$errors" "$floor"

status=0
if [ "$failed" -gt 0 ]; then
  printf 'FAILED tests: %s\n' "${failed_names[*]}"
  status=1
fi
if [ "$errors" -gt 0 ]; then
  status=1
fi
if [ "$ran" -eq 0 ]; then
  printf 'No test ran.\n'
  status=1
fi
if [ -z "$filter" ]; then
  if [ "$discovered" -lt "$floor" ]; then
    printf 'Test count %s is below the floor %s (tests/EXPECTED_TEST_COUNT).\n' "$discovered" "$floor"
    status=1
  elif [ "$discovered" -gt "$floor" ]; then
    printf 'Notice: %s tests exceed the floor %s; raise tests/EXPECTED_TEST_COUNT.\n' "$discovered" "$floor"
  fi
else
  printf 'Filtered run (%s): floor not enforced.\n' "$filter"
fi

exit "$status"
