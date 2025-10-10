# Copyright (c) Microsoft Corporation
# SPDX-License-Identifier: MIT

FROM ubuntu:24.04@sha256:59a458b76b4e8896031cd559576eac7d6cb53a69b38ba819fb26518536368d86

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