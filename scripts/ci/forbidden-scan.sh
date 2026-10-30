#!/usr/bin/env bash
# Fail if any forbidden term appears in the published tree: internal identity,
# internal repo/module/check names, internal review IDs, process markers, or
# local paths. A regression guard for the public repository.
set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
pattern="$(cat "$here/forbidden.txt")"

# Scan the whole tree from the current directory. Exclude VCS/build/venv dirs.
# The only intentional exceptions are the two data files that must contain the
# terms: forbidden.txt (the pattern source) and forbidden-samples.txt (example
# matches used by the guard tests). The scripts/workflow carry no terms.
# Fail closed: distinguish match (0), clean (1), and grep error (>=2). A bare
# `|| true` would hide read/regex failures as "clean".
set +e
matches="$(grep -rIEni "$pattern" . \
  --exclude-dir=.git --exclude-dir=.venv --exclude-dir=dist --exclude-dir=build \
  --exclude-dir=__pycache__ --exclude-dir=.pytest_cache --exclude-dir='*.egg-info' \
  --exclude='forbidden.txt' --exclude='forbidden-samples.txt')"
rc=$?
set -e

case "$rc" in
  0) echo "$matches"; echo "::error::forbidden term(s) found in the published tree (see above)"; exit 1 ;;
  1) echo "forbidden-scan: clean" ;;
  *) echo "::error::forbidden-scan failed (grep exit $rc)"; exit 2 ;;
esac
