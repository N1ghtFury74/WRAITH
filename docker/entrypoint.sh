#!/bin/sh
# WRAITH container entrypoint.
#
# Ensures the writable cases root exists before handing off to the CMD (uvicorn).
# Runs as the non-root `wraith` user. For a NAMED volume this is a no-op (the dir
# is created + owned at image build); for a bind mount it makes the directory if
# the host path is empty. If the mount is present but not writable by the runtime
# user (e.g. a root-owned host bind mount), we fail loudly with a clear message
# rather than letting the app hit an opaque write error later.
set -eu

CASES_ROOT="${WRAITH_CASES_ROOT:-/data/cases}"

mkdir -p "$CASES_ROOT" 2>/dev/null || true

if [ ! -w "$CASES_ROOT" ]; then
  echo "WRAITH: cases root '$CASES_ROOT' is not writable by uid $(id -u)." >&2
  echo "WRAITH: use the named volume (default) or 'chown -R 10001:10001' the bind-mount host path." >&2
  exit 1
fi

exec "$@"
