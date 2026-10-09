#!/bin/sh
# BEDROCK_SPEC.md 9.6: slim Bedrock's own release image, then check that the
# pruned image passes verify and `bedrock --version` prints the same string.
# Needs Docker and a Linux host with ptrace (run as root in CI).
set -eu

BEDROCK="${BEDROCK:-target/release/bedrock}"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

docker build -t bedrock-self-test .
docker save bedrock-self-test -o "$WORK/image.tar"

# The workload runs the image's entrypoint (bedrock) with --version.
"$BEDROCK" slim "$WORK/image.tar" --workload-duration 20s -o "$WORK/slim" \
    --report "$WORK/report.json" -- --version

expected="$("$BEDROCK" --version)"
# The entrypoint's output goes to stderr; the reach set is on stdout.
actual="$("$BEDROCK" trace "$WORK/slim" --workload-duration 20s -- --version 2>&1 >/dev/null | head -1)"
if [ "$actual" != "$expected" ]; then
    echo "self-test failed: pruned image printed '$actual', expected '$expected'" >&2
    exit 1
fi
echo "self-test passed: $actual"
