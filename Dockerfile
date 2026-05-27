# BTCRecover Docker Image
# Build with: docker build -t btcrecover .
# For full requirements: docker build --build-arg REQUIREMENTS=full -t btcrecover:full .

FROM python:3.12-slim-bookworm AS base

# Install build dependencies and runtime requirements
RUN apt-get update && apt-get install -y --no-install-recommends \
    git \
    build-essential \
    libffi-dev \
    autoconf \
    automake \
    libtool \
    pkg-config \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

# Enable RIPEMD160 in OpenSSL (legacy provider)
# This is required for full performance - without it, BTCRecover falls back to
# a pure Python implementation that is ~3x slower
RUN OPENSSL_CNF=$(openssl version -d | cut -d'"' -f2)/openssl.cnf && \
    if [ -f "$OPENSSL_CNF" ]; then \
        sed -i 's/^\[openssl_init\]/[openssl_init]\nproviders = provider_sect\n\n[provider_sect]\ndefault = default_sect\nlegacy = legacy_sect\n\n[default_sect]\nactivate = 1\n\n[legacy_sect]\nactivate = 1\n/' "$OPENSSL_CNF" 2>/dev/null || \
        echo -e "\n[openssl_init]\nproviders = provider_sect\n\n[provider_sect]\ndefault = default_sect\nlegacy = legacy_sect\n\n[default_sect]\nactivate = 1\n\n[legacy_sect]\nactivate = 1" >> "$OPENSSL_CNF"; \
    fi

WORKDIR /btcrecover

# Copy requirements first for better layer caching
COPY requirements.txt requirements-full.txt ./

# Build argument to select requirements: "basic" or "full"
ARG REQUIREMENTS=basic

# Install Python dependencies based on build arg
# Using --no-cache-dir to reduce image size
RUN if [ "$REQUIREMENTS" = "full" ]; then \
        pip install --no-cache-dir -r requirements-full.txt; \
    else \
        pip install --no-cache-dir -r requirements.txt; \
    fi

# Copy the rest of the application
COPY . .

# Verify RIPEMD160 is working
RUN python check_ripemd160.py

# Default command shows help
CMD ["python", "btcrecover.py", "--help"]
