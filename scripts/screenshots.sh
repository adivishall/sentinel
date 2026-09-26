#!/usr/bin/env bash
# Capture the README screenshots from a running console with a local headless
# Chrome / Chromium. Nothing is drawn: each image is the live console (real engine
# output over the synthetic demo dataset) at a shareable URL.
#
#   make api                      # in another terminal (serves http://localhost:8000)
#   scripts/screenshots.sh        # writes docs/img/*.png
#   scripts/screenshots.sh http://localhost:8765 /tmp/shots
#
# Set CHROME=/path/to/chrome if it is not found automatically.
set -euo pipefail
BASE=${1:-http://localhost:8000}
OUT=${2:-docs/img}
CHROME=${CHROME:-}
if [ -z "$CHROME" ]; then
  for c in "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome" \
           "/Applications/Chromium.app/Contents/MacOS/Chromium" \
           google-chrome google-chrome-stable chromium chromium-browser; do
    if [ -x "$c" ] || command -v "$c" >/dev/null 2>&1; then CHROME=$c; break; fi
  done
fi
[ -n "$CHROME" ] || { echo "no Chrome/Chromium found; set CHROME=/path/to/chrome" >&2; exit 1; }
curl -sf "$BASE/v1/system" >/dev/null || { echo "no console at $BASE (run: make api)" >&2; exit 1; }
mkdir -p "$OUT"

shot() {  # <file> <view> [height]
  local prof pid last=-1 size i
  prof=$(mktemp -d)
  rm -f "$OUT/$1"
  "$CHROME" --headless=new --disable-gpu --hide-scrollbars --no-first-run \
    --no-default-browser-check --user-data-dir="$prof" --window-size=1440,"${3:-1000}" \
    --virtual-time-budget=8000 --screenshot="$OUT/$1" "$BASE/$2" >/dev/null 2>&1 &
  pid=$!
  # Chrome sometimes keeps running after writing the file: wait for a stable file, then stop it
  for i in $(seq 1 120); do
    size=0; [ -f "$OUT/$1" ] && size=$(wc -c <"$OUT/$1" | tr -d ' ')
    if [ "$size" -gt 0 ] && [ "$size" -eq "$last" ]; then break; fi
    last=$size
    sleep 0.5
  done
  kill "$pid" 2>/dev/null || true
  wait "$pid" 2>/dev/null || true
  rm -rf "$prof"
  [ -s "$OUT/$1" ] || { echo "failed: $1" >&2; exit 1; }
  echo "$OUT/$1"
}

# 1. the flagship attack, WITHOUT vs WITH Sentinel (running it records one decision + case)
shot ai-security.png "#aisecurity/document_injection"
# 2. that case's review packet
CASE=$(curl -s "$BASE/v1/cases?limit=100" | python3 -c '
import json, sys
print(next(c["case_id"] for c in json.load(sys.stdin)["cases"] if c["title"].startswith("AI-security")))')
shot case-review.png "#investigations/$CASE"
# 3. replay: a recorded denial re-run under an older policy version
shot replay.png "#replay/example"
# 4. the highest-scoring evaluated transaction (ties: the larger amount)
TX=$(curl -s "$BASE/v1/transactions?limit=10000" | python3 -c '
import json, sys
ts = [t for t in json.load(sys.stdin)["transactions"] if t.get("decision")]
print(max(ts, key=lambda t: (t["decision"]["risk_score"], t["amount"]))["transaction_id"])')
shot transaction-risk.png "#transactions/$TX"
