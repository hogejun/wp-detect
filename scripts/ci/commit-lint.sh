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
# The author must always be the project's noreply identity. The committer may
# also be GitHub's web-flow identity, which GitHub sets on the commit it creates
# for a squash/merge performed through the web UI or `gh pr merge` — the standard
# way changes land here. Neither identity carries a real name or address.
allowed='hogejun <7918106+hogejun@users.noreply.github.com>'
webflow_committer='GitHub <noreply@github.com>'

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
  # 1) the author must be exactly the allowed noreply identity; the committer
  #    must be that, or GitHub's web-flow identity (squash/merge commits).
  author="$(git show -s --format='%an <%ae>' "$sha")"
  committer="$(git show -s --format='%cn <%ce>' "$sha")"
  if [ "$author" != "$allowed" ]; then
    echo "::error::${sha:0:12}: disallowed author: $author"; fail=1
  fi
  if [ "$committer" != "$allowed" ] && [ "$committer" != "$webflow_committer" ]; then
    echo "::error::${sha:0:12}: disallowed committer: $committer"; fail=1
  fi

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
