# syntax=docker/dockerfile:1.7
#
# WRAITH — portable, offline, air-gapped-friendly image.
#
# Two stages:
#   1. ui-build  (node:20.18.1-alpine)  — build the React/Vite SPA to ui/web/dist.
#   2. runtime   (python:3.12.7-slim)   — FastAPI + Uvicorn serving the API AND the
#                                         built SPA from one origin on :8000.
#
# Design guarantees:
#   * OFFLINE AT RUNTIME — the running container makes zero outbound network calls.
#     (The *build* fetches npm + pip deps; vendor/pre-pull for a true air-gap.)
#   * DETERMINISTIC — pinned base images, `npm ci` against the committed lockfile,
#     `==`-pinned Python deps from pyproject.toml. No cache-busting.
#   * LEAST PRIVILEGE — runs as a non-root user; cases data on a VOLUME.
#   * NO SECRETS BAKED IN — none are copied; the case workspace holds encrypted-
#     at-rest material under the mounted volume only.

# ---------------------------------------------------------------------------
# Stage 1 — build the SPA (produces /ui/dist)
# ---------------------------------------------------------------------------
FROM node:20.18.1-alpine AS ui-build

WORKDIR /ui

# Install deps first (cache-friendly): copy only the manifests, then `npm ci`
# for a reproducible, lockfile-exact install.
COPY ui/web/package.json ui/web/package-lock.json ./
RUN npm ci

# Copy the rest of the UI source and build. `npm run build` == `tsc -b && vite
# build` -> ui/web/dist. `check:offline` fails the build if any non-allowlisted
# absolute URL made it into the bundle (CLAUDE.md offline non-negotiable).
COPY ui/web/ ./
RUN npm run build && npm run check:offline

# ---------------------------------------------------------------------------
# Stage 2 — runtime image
# ---------------------------------------------------------------------------
FROM python:3.12.7-slim AS runtime

# WeasyPrint (HTML->PDF dossiers) needs native libs: cairo, pango, gdk-pixbuf,
# libffi, and fonts. Installed in ONE layer with --no-install-recommends and the
# apt lists cleaned so nothing is fetched at runtime and the layer stays lean.
# NOTE: WeasyPrint itself is not yet a pinned Python dependency (the PDF dossier
# module is not wired yet) — these system libs are installed so that module works
# the moment it lands, without a base-image rebuild. See docker notes in handback.
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      libcairo2 \
      libpango-1.0-0 \
      libpangocairo-1.0-0 \
      libpangoft2-1.0-0 \
      libgdk-pixbuf-2.0-0 \
      libffi8 \
      libharfbuzz0b \
      shared-mime-info \
      fonts-dejavu-core \
      fonts-liberation \
 && rm -rf /var/lib/apt/lists/*

# Deterministic, quiet pip; no .pyc churn; unbuffered logs.
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /app

# Install the WRAITH package + its (==-pinned) runtime deps from pyproject.toml.
# Only the files pip needs to build the wheel are copied first so this layer is
# cached until deps or source change.
COPY pyproject.toml README.md ./
COPY wraith ./wraith
RUN pip install --no-cache-dir .

# Bring in the built SPA from stage 1. The app resolves the SPA dir from
# WRAITH_UI_DIST (set below) because the package is installed into site-packages,
# so the in-repo relative default would not apply.
COPY --from=ui-build /ui/dist ./ui/web/dist

# Entrypoint ensures the cases root exists and is writable before exec'ing uvicorn.
COPY docker/entrypoint.sh /usr/local/bin/wraith-entrypoint.sh
RUN chmod +x /usr/local/bin/wraith-entrypoint.sh

# Runtime config: where the SPA lives, the writable cases root (a VOLUME), port.
ENV WRAITH_UI_DIST=/app/ui/web/dist \
    WRAITH_CASES_ROOT=/data/cases \
    WRAITH_HOST=0.0.0.0 \
    WRAITH_PORT=8000

# Non-root runtime user; own /app and the cases root. chown before VOLUME so a
# freshly-created named volume inherits writable ownership from the image dir.
RUN groupadd --system wraith \
 && useradd --system --gid wraith --uid 10001 --create-home --home-dir /home/wraith wraith \
 && mkdir -p /data/cases \
 && chown -R wraith:wraith /app /data

VOLUME ["/data/cases"]

USER wraith

EXPOSE 8000

# Liveness: hit the API banner (/api/v1 -> 200 JSON). Uses stdlib urllib so no
# extra tooling (curl) is needed in the slim image.
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
  CMD python -c "import urllib.request,sys; sys.exit(0) if urllib.request.urlopen('http://127.0.0.1:8000/api/v1', timeout=4).status==200 else sys.exit(1)" || exit 1

ENTRYPOINT ["/usr/local/bin/wraith-entrypoint.sh"]

# Serve the SAME app the owner has been testing: API under /api/v1 + the SPA at /.
CMD ["uvicorn", "wraith.api.app:create_app", "--factory", "--host", "0.0.0.0", "--port", "8000"]
