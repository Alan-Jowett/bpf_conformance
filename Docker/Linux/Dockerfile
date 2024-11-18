# Copyright (c) Microsoft Corporation
# SPDX-License-Identifier: MIT

FROM ubuntu:24.04@sha256:278628f08d4979fb9af9ead44277dbc9c92c2465922310916ad0c46ec9999295

# Install dependencies
RUN apt-get update && apt-get install -y \
    libboost-program-options-dev \
    libbpf-dev

# Clean up APT when done.
RUN apt-get clean && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY . .

LABEL org.opencontainers.image.source=https://github.com/Alan-Jowett/bpf_conformance
LABEL org.opencontainers.image.description="BPF Conformance container image"
LABEL org.opencontainers.image.licenses=MIT