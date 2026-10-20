#!/bin/sh
# The Vercel build (vercel.json): the static console from the real engine.
#   sh scripts/vercel-build.sh [output directory, default public]
# Picks a Python >= 3.11 (the PATH's python3 when it qualifies, else a versioned one;
# Vercel's default is 3.12) and installs the package; then scripts/static_console.py
# regenerates the snapshot on an in-memory synthetic world, validates it and assembles
# index.html + ui/ in the output directory.
# Any failure fails the build: a stale or empty snapshot is never published.
# docs/DEPLOYMENT.md, "Static console".
set -eu
OUT="${1:-public}"
PY=""
for c in python3 python3.12 python3.13 python3.14 python3.11; do  # the PATH python first (CI), then the build image versions
  if command -v "$c" >/dev/null 2>&1 && "$c" -c 'import sys; sys.exit(0 if sys.version_info >= (3, 11) else 1)' 2>/dev/null; then
    PY="$c"; break
  fi
done
[ -n "$PY" ] || { echo "vercel-build: no Python >= 3.11 on PATH" >&2; exit 1; }
echo "vercel-build: $("$PY" --version) at $(command -v "$PY")"
"$PY" -m pip install --quiet --disable-pip-version-check .
"$PY" scripts/static_console.py build --out "$OUT"
