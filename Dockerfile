# Dockerfile
FROM ubuntu:20.04

# Prevent interactive prompts
ENV DEBIAN_FRONTEND=noninteractive

# Install system dependencies
RUN apt-get update && apt-get install -y \
    build-essential \
    flex \
    bison \
    python3 \
    python3-dev \
    python3-pip \
    libssl-dev \
    libgmp-dev \
    libmpc-dev \
    libmpfr-dev \
    wget \
    git \
    && rm -rf /var/lib/apt/lists/*

# Build-time reference for Charm source (tag/branch/commit).
ARG CHARM_REF=dev

# Install PBC library
RUN wget https://crypto.stanford.edu/pbc/files/pbc-0.5.14.tar.gz && \
    tar -xzf pbc-0.5.14.tar.gz && \
    cd pbc-0.5.14 && \
    ./configure && \
    make && \
    make install && \
    ldconfig && \
    cd .. && \
    rm -rf pbc-0.5.14*

# Install Charm-Crypto
RUN git clone --depth 1 --branch ${CHARM_REF} https://github.com/JHUISI/charm.git && \
    cd charm && \
    ./configure.sh && \
    make && \
    make install && \
    cd .. && \
    rm -rf charm

# Set library path
ENV LD_LIBRARY_PATH=/usr/local/lib:$LD_LIBRARY_PATH
ENV PYTHONPATH=/app/src

# Create app directory
WORKDIR /app

# Copy requirements first (for better caching)
COPY requirements.txt .
RUN pip3 install --no-cache-dir -r requirements.txt

# Copy application code
COPY . .

# Run the application
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]