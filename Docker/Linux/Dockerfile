# Copyright (c) Microsoft Corporation
# SPDX-License-Identifier: MIT

FROM ubuntu:24.04@sha256:cd1dba651b3080c3686ecf4e3c4220f026b521fb76978881737d24f200828b2b

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