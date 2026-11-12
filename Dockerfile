# syntax=docker/dockerfile:1
FROM python:3.12-slim

LABEL org.opencontainers.image.title="ssh-honeypot" \
      org.opencontainers.image.description="Low-interaction SSH honeypot with analytics dashboard" \
      org.opencontainers.image.licenses="MIT"

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    HP_BIND_HOST=0.0.0.0 \
    HP_PORT=2222

# unprivileged user: even a full escape of the Python process lands without root
RUN useradd --create-home --uid 10001 honeypot
WORKDIR /app

COPY requirements.txt .
RUN pip install -r requirements.txt

COPY honeypot ./honeypot
RUN mkdir -p /app/data && chown honeypot:honeypot /app/data
USER honeypot

EXPOSE 2222 5000
VOLUME ["/app/data"]

# No HEALTHCHECK here on purpose: probing port 2222 would be recorded as an
# attack session every interval. The dashboard service has an HTTP healthcheck.
CMD ["python", "-m", "honeypot"]
