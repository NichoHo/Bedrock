#!/usr/bin/env bash
# Validates SBOM files with the official tools (BEDROCK_SPEC.md Phase 1 exit
# criterion): pyspdxtools from spdx-tools for *.spdx.json, and the CycloneDX
# 1.5 JSON schema via cyclonedx-python-lib for *.cdx.json.
#
#   scripts/validate-sbom.sh out/alpine.spdx.json out/alpine.cdx.json ...
set -euo pipefail

venv=$(mktemp -d)
python3 -m venv "$venv"
"$venv/bin/pip" install --quiet spdx-tools "cyclonedx-python-lib[json-validation]"

for f in "$@"; do
  case "$f" in
    *.spdx.json)
      # Validation is on by default; exits non-zero and lists errors if invalid.
      "$venv/bin/pyspdxtools" -i "$f"
      ;;
    *.cdx.json)
      "$venv/bin/python" - "$f" <<'EOF'
import sys
from cyclonedx.schema import SchemaVersion
from cyclonedx.validation.json import JsonStrictValidator

path = sys.argv[1]
with open(path) as fh:
    error = JsonStrictValidator(SchemaVersion.V1_5).validate_str(fh.read())
if error:
    sys.exit(f"{path}: {error}")
EOF
      ;;
    *)
      echo "don't know how to validate $f (expected *.spdx.json or *.cdx.json)" >&2
      exit 2
      ;;
  esac
  echo "valid: $f"
done
