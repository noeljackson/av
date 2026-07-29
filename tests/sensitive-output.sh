#!/usr/bin/env bash

# Search sensitive artifacts without ever printing the pattern. A scanner
# error is a test failure, not evidence that the value was absent.
assert_literal_absent_from() {
  local description=$1
  local literal=$2
  shift 2

  if grep --fixed-strings --quiet -- "$literal" "$@"; then
    printf '%s\n' "$description reached logs or audit metadata" >&2
    return 1
  else
    local status=$?
    if ((status != 1)); then
      printf '%s\n' "$description scan could not inspect all artifacts" >&2
      return 1
    fi
  fi
}

assert_pattern_file_absent_from() {
  local description=$1
  local pattern_file=$2
  shift 2

  [[ -s $pattern_file ]] || {
    printf '%s\n' "$description canary was empty or unavailable" >&2
    return 1
  }
  if grep --fixed-strings --quiet --file "$pattern_file" "$@"; then
    printf '%s\n' "$description reached logs or audit metadata" >&2
    return 1
  else
    local status=$?
    if ((status != 1)); then
      printf '%s\n' "$description scan could not inspect all artifacts" >&2
      return 1
    fi
  fi
}
