#!/usr/bin/env bash
# Reject commits whose identity, trailers, or message would leak internal
# information. Used by the public repository's CI for both PRs and pushes to
# main (so the squash-merge commit that actually lands is also checked).
#
# Give the commits to check as either:
#   RANGE="<git range or rev>"   (preferred)   e.g. "abc..def" or a single sha
#   BASE_SHA=... HEAD_SHA=...                   -> checked as BASE_SHA..HEAD_SHA
set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
pattern="$(cat "$here/forbidden.txt")"
allowed='hogejun <7918106+hogejun@users.noreply.github.com>'

if [ -n "${RANGE:-}" ]; then
  revs="$RANGE"
elif [ -n "${BASE_SHA:-}" ] && [ -n "${HEAD_SHA:-}" ]; then
  revs="${BASE_SHA}..${HEAD_SHA}"
else
  echo "::error::commit-lint: provide RANGE or BASE_SHA/HEAD_SHA"; exit 2
fi

# Fail closed on an unreadable/invalid range.
if ! git rev-list "$revs" >/dev/null 2>&1; then
  echo "::error::commit-lint: cannot read commit range '$revs'"; exit 2
fi

commits="$(git rev-list "$revs")"
if [ -z "$commits" ]; then
  echo "commit-lint: no commits in range (nothing to check)"; exit 0
fi

fail=0
while IFS= read -r sha; do
  # 1) author AND committer must be exactly the one allowed noreply identity
  while IFS= read -r id; do
    if [ "$id" != "$allowed" ]; then
      echo "::error::${sha:0:12}: disallowed identity: $id"; fail=1
    fi
  done < <(git show -s --format='%an <%ae>%n%cn <%ce>' "$sha")

  body="$(git show -s --format='%B' "$sha")"
  # 2) no identity trailers at all (public policy: a single noreply identity,
  #    no co-authors — this also catches squash-merge auto-added co-authors)
  if printf '%s\n' "$body" | grep -niE '^[[:space:]]*(co-authored-by|signed-off-by):' >/dev/null; then
    echo "::error::${sha:0:12}: identity trailer (co-authored-by/signed-off-by) not allowed"; fail=1
  fi
  # 3) no forbidden terms anywhere in the message/trailers
  if printf '%s\n' "$body" | grep -niE "$pattern" >/dev/null; then
    echo "::error::${sha:0:12}: forbidden term in commit message"; fail=1
  fi
done <<< "$commits"

if [ "$fail" -ne 0 ]; then exit 1; fi
echo "commit-lint: clean ($(printf '%s\n' "$commits" | wc -l | tr -d ' ') commit(s))"
