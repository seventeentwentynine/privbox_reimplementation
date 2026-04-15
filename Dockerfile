FROM python:3.11-slim-bookworm

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    flex \
    bison \
    wget \
    curl \
    ca-certificates \
    openssl \
    libgmp-dev \
    libssl-dev \
    m4 \
    autoconf \
    automake \
    libtool \
    pkg-config \
    iproute2 \
    tcpdump \
  && rm -rf /var/lib/apt/lists/*

# Build and install PBC from source
RUN cd /tmp \
  && wget https://crypto.stanford.edu/pbc/files/pbc-0.5.14.tar.gz \
  && tar xzf pbc-0.5.14.tar.gz \
  && cd pbc-0.5.14 \
  && ./configure \
  && make -j"$(nproc)" \
  && make install \
  && ldconfig \
  && cd / \
  && rm -rf /tmp/pbc-0.5.14 /tmp/pbc-0.5.14.tar.gz

WORKDIR /app

COPY requirements.txt /app/requirements.txt
RUN python -m pip install --upgrade pip setuptools wheel \
  && pip install --no-cache-dir -r /app/requirements.txt

COPY src/ /app/src/
COPY scripts/ /app/scripts/
COPY tests/ /app/tests/

ENV PYTHONUNBUFFERED=1
ENV PYTHONPATH=/app/src

CMD ["python", "-c", "print('ok')"]