# Two-stage build: compile-time build tools stay out of the final image.

FROM python:3.12-slim AS builder

WORKDIR /build

# gcc/g++ cover any requirement lacking a manylinux wheel for this platform
# (numpy/scipy ship wheels; these are included defensively).
RUN apt-get update && apt-get install -y --no-install-recommends \
        gcc g++ \
    && rm -rf /var/lib/apt/lists/*

# pyproject.toml is the single source of truth for dependencies, so the image
# installs the package rather than a parallel requirements file that could drift
# from it. The source is copied first because a PEP 517 build needs it; the cost
# is that a source edit re-resolves dependencies, which is the price of not
# maintaining two dependency lists that can disagree.
#
# No extras: `kafka` and `benchmark` are deliberately excluded so the runtime
# image carries neither librdkafka nor a gradient booster.
COPY pyproject.toml README.md ./
COPY ueba_pipeline/ ./ueba_pipeline/
RUN pip install --no-cache-dir --prefix=/install .


FROM python:3.12-slim AS runtime

# Non-root by default — this is a data-handling service (identity/behavioral
# logs), not a throwaway script.
RUN groupadd --gid 1000 ueba && \
    useradd --uid 1000 --gid ueba --shell /bin/bash --create-home ueba

COPY --from=builder /install /usr/local

WORKDIR /app
# ueba_pipeline is installed into site-packages by the builder stage; only the
# simulator needs copying, because it is deliberately not part of the package.
COPY enterprise_simulator/ ./enterprise_simulator/

# Model artifacts and ingested data are runtime state, not image content —
# mounted as volumes in docker-compose.yml / a k8s PVC in deploy/k8s, never
# baked into the image.
RUN mkdir -p /app/artifacts /app/data && chown -R ueba:ueba /app

USER ueba
ENV PYTHONUNBUFFERED=1 \
    PYTHONPATH=/app

# The console script declared in pyproject.toml.
ENTRYPOINT ["ueba"]
CMD ["--help"]
