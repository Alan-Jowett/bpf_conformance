# Copyright (c) Microsoft Corporation
# SPDX-License-Identifier: MIT

FROM ubuntu:24.04@sha256:440dcf6a5640b2ae5c77724e68787a906afb8ddee98bf86db94eea8528c2c076

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