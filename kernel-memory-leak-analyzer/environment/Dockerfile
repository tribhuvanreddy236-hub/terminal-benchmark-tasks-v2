FROM rust:1.93.1-bookworm@sha256:7c4ae649a84014c467d79319bbf17ce2632ae8b8be123ac2fb2ea5be46823f31

ENV DEBIAN_FRONTEND=noninteractive
ENV CARGO_NET_RETRY=3
ENV CARGO_TERM_COLOR=never
ENV RUST_BACKTRACE=1

RUN apt-get update \
 && apt-get install -y --no-install-recommends \
        ca-certificates=20230311+deb12u1 \
        make=4.3-4.1 \
        curl=7.88.1-10+deb12u14 \
 && apt-get clean \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /app

RUN mkdir -p /app/bin /app/output /app/config /app/data /app/src

COPY Cargo.toml /app/Cargo.toml
COPY Makefile /app/Makefile
COPY src/main.rs /app/src/main.rs

COPY config/suppressions.yaml /app/config/suppressions.yaml

COPY data/leaks.ndjson /app/data/leaks.ndjson
COPY data/modules.ndjson /app/data/modules.ndjson
COPY data/kernels.json /app/data/kernels.json

COPY SCHEMA.md /app/SCHEMA.md
COPY INPUTS.md /app/INPUTS.md
