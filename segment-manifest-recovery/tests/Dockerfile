FROM public.ecr.aws/docker/library/rust:1.85-slim@sha256:9f841bbe9e7d8e37ceb96ed907265a3a0df7f44e3737d0b100e7907a679acb36

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        procps \
        python3 \
        python3-venv \
        util-linux \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.lock /tmp/requirements.lock
RUN python3 -m venv /venv \
    && /venv/bin/pip install --no-cache-dir --require-hashes --no-deps -r /tmp/requirements.lock

RUN useradd --uid 12000 --no-create-home --home-dir /nonexistent --shell /usr/sbin/nologin sandbox \
    && install -d -o sandbox -g sandbox /work \
    && mkdir -p /app

ENV PYTHONSAFEPATH=1
WORKDIR /app

COPY test.sh test_outputs.py /tests/
COPY sealed/ /tests/sealed/
RUN chmod go-rwx /tests
