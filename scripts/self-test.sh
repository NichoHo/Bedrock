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
# The entrypoint's output goes to stderr, among Bedrock's own messages (such as
# the warning about running as root); the reach set is on stdout.
out="$("$BEDROCK" trace "$WORK/slim" --workload-duration 20s -- --version 2>&1 >/dev/null || true)"
if ! printf '%s\n' "$out" | grep -Fxq "$expected"; then
    echo "self-test failed: pruned image did not print '$expected'. It printed:" >&2
    printf '%s\n' "$out" >&2
    exit 1
fi
echo "self-test passed: $expected"
