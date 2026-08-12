#!/usr/bin/env bash
#
# Publish a packaged Osprey CRX to the update server's directory and record it in releases.json.
#
# This is a convenience so you do not hand-edit JSON for every build. It copies the CRX into the updates
# directory under the conventional name osprey-<version>.crx and appends a matching entry to releases.json,
# creating that file if it does not exist. The proxy hot-reloads releases.json within about a second, so the
# build is offered as soon as a channel points at it (see docs/updates.md).
#
# Usage:
#   OSPREY_UPDATES_DIR=/var/lib/osprey/updates \
#     ./osprey-release.sh <version> <path-to-crx> ["release notes"] [--rollback-of <version>]
#
# Example:
#   ./osprey-release.sh 2.0.7 ./build/osprey.crx "Faster startup; provider timeout fix."
#
# Requirements: bash and python3

set -euo pipefail

UPDATES_DIR="${OSPREY_UPDATES_DIR:-/var/lib/osprey/updates}"

if [ "$#" -lt 2 ]; then
    echo "usage: $0 <version> <path-to-crx> [\"release notes\"] [--rollback-of <version>]" >&2
    exit 2
fi

VERSION="$1"
CRX_SRC="$2"
NOTES="${3:-}"
ROLLBACK_OF=""

# Parse an optional --rollback-of flag from the remaining arguments
shift $(( $# < 3 ? $# : 3 ))
while [ "$#" -gt 0 ]; do
    case "$1" in
        --rollback-of)
            ROLLBACK_OF="${2:-}"
            shift 2
            ;;
        *)
            echo "unknown argument: $1" >&2
            exit 2
            ;;
    esac
done

if [ ! -f "$CRX_SRC" ]; then
    echo "error: CRX not found: $CRX_SRC" >&2
    exit 1
fi

mkdir -p "$UPDATES_DIR"

CRX_NAME="osprey-${VERSION}.crx"
CRX_DEST="${UPDATES_DIR}/${CRX_NAME}"
RELEASES="${UPDATES_DIR}/releases.json"
DATE="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

cp -f "$CRX_SRC" "$CRX_DEST"
echo "copied $CRX_SRC -> $CRX_DEST"

VERSION="$VERSION" CRX_NAME="$CRX_NAME" DATE="$DATE" NOTES="$NOTES" \
ROLLBACK_OF="$ROLLBACK_OF" RELEASES="$RELEASES" python3 - <<'PY'
import json
import os

path = os.environ["RELEASES"]
version = os.environ["VERSION"]

try:
    with open(path, "r", encoding="utf-8") as fh:
        doc = json.load(fh)
except FileNotFoundError:
    doc = {}
except json.JSONDecodeError as exc:
    raise SystemExit(f"error: {path} is not valid JSON: {exc}")

if not isinstance(doc, dict):
    raise SystemExit(f"error: {path} must contain a JSON object")

releases = doc.get("releases")
if not isinstance(releases, list):
    releases = []
    doc["releases"] = releases

if any(isinstance(r, dict) and r.get("version") == version for r in releases):
    raise SystemExit(f"error: version {version} is already present in {path}")

entry = {"version": version, "crx": os.environ["CRX_NAME"], "date": os.environ["DATE"]}

notes = os.environ.get("NOTES", "").strip()
if notes:
    entry["notes"] = notes

rollback_of = os.environ.get("ROLLBACK_OF", "").strip()
if rollback_of:
    entry["rollback_of"] = rollback_of

releases.append(entry)

with open(path, "w", encoding="utf-8") as fh:
    json.dump(doc, fh, indent=2)
    fh.write("\n")

print(f"recorded version {version} in {path}")
PY

echo "done. Point a channel at version ${VERSION} in channels.json to offer it."
