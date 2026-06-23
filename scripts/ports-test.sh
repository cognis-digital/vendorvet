#!/usr/bin/env bash
# Smoke-test every language port: each must score the demo questionnaire to the
# same risk tier as the Python reference and exit 2 on high/critical.
set -u

Q="demos/07-startup-unanswered/questionnaire.json"   # high-risk fixture
EXPECT_TIER="high"
fails=0

check() {
  local name="$1" tier="$2" rc="$3"
  if [ "$tier" = "$EXPECT_TIER" ] && [ "$rc" = "2" ]; then
    echo "  ok   $name -> $tier (exit $rc)"
  else
    echo "  FAIL $name -> '$tier' (exit $rc), expected $EXPECT_TIER/2"
    fails=$((fails + 1))
  fi
}

# Capture a port's JSON to a temp file (preserving its exit code), then read tier.
TMP=$(mktemp)
run_port() {  # name, command...
  local name="$1"; shift
  "$@" >"$TMP" 2>/dev/null
  local rc=$?
  local tier
  tier=$(jq -r .tier <"$TMP" 2>/dev/null)
  check "$name" "$tier" "$rc"
}

run_port "python" python -m vendorvet --format json questionnaire "$Q"

if command -v node >/dev/null; then
  run_port "node" node ports/javascript/index.js questionnaire "$Q" --format json
else echo "  skip node (not installed)"; fi

if command -v jq >/dev/null; then
  run_port "shell" sh ports/shell/vendorvet.sh questionnaire "$Q" --format json
else echo "  skip shell (jq not installed)"; fi

if command -v go >/dev/null; then
  ( cd ports/go && go build -o /tmp/vv_go . ) && \
    run_port "go" /tmp/vv_go questionnaire "$Q" --format json
else echo "  skip go (not installed)"; fi

if command -v cargo >/dev/null; then
  ( cd ports/rust && cargo build -q --release ) && \
    run_port "rust" ports/rust/target/release/vendorvet questionnaire "$Q" --format json
else echo "  skip rust (not installed)"; fi

rm -f "$TMP"

if [ "$fails" -gt 0 ]; then echo "ports-test: $fails failure(s)"; exit 1; fi
echo "ports-test: all available ports agree"
