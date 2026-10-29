FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

COPY pyproject.toml README.md LICENSE ./
COPY sentinel_net ./sentinel_net

RUN pip install --no-cache-dir . \
    && useradd --create-home --uid 10001 sentinel \
    && mkdir -p /data /alerts \
    && chown sentinel:sentinel /alerts

USER sentinel

ENTRYPOINT ["sentinelnet"]
CMD ["--help"]
