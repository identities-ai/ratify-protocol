#!/usr/bin/env bash
# Regenerate sandbox-requirements.lock inside the pinned sandbox base image.
#
# Resolved in the image the profile actually runs, by digest, against that
# image's /usr/bin/python3 (CPython 3.12), so the locked wheels are ones that
# interpreter can load. --universal resolves across platforms and emits markers,
# so the lock is not silently arm64-only.
#
# Requires network. The profile itself does not: it installs from this lock.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SANDBOX_IMAGE="ghcr.io/nvidia/openshell-community/sandboxes/base@sha256:aeef1c63f00e2913ea002ccb3aaf925f338b5c5d70e63576f0d95c16a138044e"

docker run --rm --user 0 --entrypoint /bin/sh \
  -v "$HERE:/work" "$SANDBOX_IMAGE" -c '
    set -e
    export UV_PYTHON_DOWNLOADS=never
    # Relative paths, from /work, so the generated header and the "via -r" notes
    # carry no absolute or host-specific path into a committed file.
    cd /work
    uv pip compile --quiet --universal --generate-hashes \
      --python /usr/bin/python3 \
      --output-file sandbox-requirements.lock.tmp sandbox-requirements.in
    cat sandbox-requirements.lock.tmp
    rm -f sandbox-requirements.lock.tmp
  ' > "$HERE/sandbox-requirements.lock"

echo "lock sha256: $(shasum -a 256 "$HERE/sandbox-requirements.lock" | cut -d" " -f1)"
echo "pinned distributions: $(grep -c "^[a-zA-Z0-9]" "$HERE/sandbox-requirements.lock")"
