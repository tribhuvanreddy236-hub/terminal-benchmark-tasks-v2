# Build context is this environment/ directory (COPY paths are relative to it).
FROM python:3.13-slim-bookworm@sha256:386df64585134ba00b1d5e307acb1e72f33e9e87dbbb00aad9b8f24dbb51db72

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        asciinema=2.2.0-1 \
        ca-certificates=20230311+deb12u1 \
        curl=7.88.1-10+deb12u14 \
        tmux=3.3a-3 \
    && rm -rf /var/lib/apt/lists/*

RUN python3 -m pip install --no-cache-dir \
    pytest==8.4.1 \
    pytest-json-ctrf==0.3.5

WORKDIR /app

RUN mkdir -p /app/sandbox/work /host /app/data \
    && chmod 700 /host

COPY data/case_*.json /app/data/
COPY run.py.template /app/sandbox/run.py
