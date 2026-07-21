# Two-stage build: compile-time build tools stay out of the final image.

FROM python:3.12-slim AS builder

WORKDIR /build

# gcc/g++ cover any requirement lacking a manylinux wheel for this platform
# (numpy/scipy ship wheels; these are included defensively).
RUN apt-get update && apt-get install -y --no-install-recommends \
        gcc g++ \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir --prefix=/install -r requirements.txt


FROM python:3.12-slim AS runtime

# Non-root by default — this is a data-handling service (identity/behavioral
# logs), not a throwaway script.
RUN groupadd --gid 1000 ueba && \
    useradd --uid 1000 --gid ueba --shell /bin/bash --create-home ueba

COPY --from=builder /install /usr/local

WORKDIR /app
COPY ueba_pipeline/ ./ueba_pipeline/
COPY enterprise_simulator/ ./enterprise_simulator/

# Model artifacts and ingested data are runtime state, not image content —
# mounted as volumes in docker-compose.yml / a k8s PVC in deploy/k8s, never
# baked into the image.
RUN mkdir -p /app/artifacts /app/data && chown -R ueba:ueba /app

USER ueba
ENV PYTHONUNBUFFERED=1 \
    PYTHONPATH=/app

ENTRYPOINT ["python3", "-m", "ueba_pipeline.cli.main"]
CMD ["--help"]
