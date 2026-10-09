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
NOTES=""
ROLLBACK_OF=""

# The release notes are optional: a third argument that is not a flag is the notes
shift 2
if [ "$#" -gt 0 ] && [[ "$1" != --* ]]; then
    NOTES="$1"
    shift
fi

# Parse an optional --rollback-of flag from the remaining arguments
while [ "$#" -gt 0 ]; do
    case "$1" in
        --rollback-of)
            if [ "$#" -lt 2 ]; then
                echo "error: --rollback-of needs a version" >&2
                exit 2
            fi
            ROLLBACK_OF="$2"
            shift 2
            ;;
        *)
            echo "unknown argument: $1" >&2
            exit 2
            ;;
    esac
done

# The version becomes part of a file name, so allow only characters that cannot escape the updates directory
if ! [[ "$VERSION" =~ ^[0-9A-Za-z][0-9A-Za-z._-]*$ ]] || [[ "$VERSION" == *..* ]]; then
    echo "error: invalid version: $VERSION" >&2
    exit 2
fi

if [ ! -f "$CRX_SRC" ]; then
    echo "error: CRX not found: $CRX_SRC" >&2
    exit 1
fi

mkdir -p "$UPDATES_DIR"

CRX_NAME="osprey-${VERSION}.crx"
CRX_DEST="${UPDATES_DIR}/${CRX_NAME}"
RELEASES="${UPDATES_DIR}/releases.json"
DATE="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

if [ -e "$CRX_DEST" ]; then
    echo "error: ${CRX_DEST} already exists; published builds are never overwritten" >&2
    exit 1
fi

# Shared by the pre-copy duplicate check and the final recording step
RELEASE_PY=$(cat <<'PY'
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

if os.environ.get("MODE") == "check":
    raise SystemExit(0)

entry = {"version": version, "crx": os.environ["CRX_NAME"], "date": os.environ["DATE"]}

notes = os.environ.get("NOTES", "").strip()
if notes:
    entry["notes"] = notes

rollback_of = os.environ.get("ROLLBACK_OF", "").strip()
if rollback_of:
    entry["rollback_of"] = rollback_of

releases.append(entry)

# Write a temp file in the same directory and rename it over releases.json, so the hot-reloading
# server never reads a truncated file
tmp_path = f"{path}.tmp.{os.getpid()}"
try:
    with open(tmp_path, "w", encoding="utf-8") as fh:
        json.dump(doc, fh, indent=2)
        fh.write("\n")
        fh.flush()
        os.fsync(fh.fileno())
    os.replace(tmp_path, path)
finally:
    if os.path.exists(tmp_path):
        os.remove(tmp_path)

print(f"recorded version {version} in {path}")
PY
)

# Refuse a duplicate version before touching the updates directory
MODE=check VERSION="$VERSION" RELEASES="$RELEASES" python3 -c "$RELEASE_PY"

# Copy via a temp file in the same directory so a reader never sees a partial CRX
CRX_TMP="$(mktemp "${UPDATES_DIR}/.${CRX_NAME}.XXXXXX")"
trap 'rm -f "$CRX_TMP"' EXIT
cp -f "$CRX_SRC" "$CRX_TMP"
mv -n "$CRX_TMP" "$CRX_DEST"

if [ -e "$CRX_TMP" ]; then
    echo "error: ${CRX_DEST} appeared while copying; not overwriting" >&2
    exit 1
fi

echo "copied $CRX_SRC -> $CRX_DEST"

# Remove the copied CRX again if the release cannot be recorded, so no unlisted build is left behind
if ! MODE=record VERSION="$VERSION" CRX_NAME="$CRX_NAME" DATE="$DATE" NOTES="$NOTES"     ROLLBACK_OF="$ROLLBACK_OF" RELEASES="$RELEASES" python3 -c "$RELEASE_PY"; then
    rm -f "$CRX_DEST"
    exit 1
fi

echo "done. Point a channel at version ${VERSION} in channels.json to offer it."
