# SPDX-FileCopyrightText: murk contributors
# SPDX-License-Identifier: MIT OR Apache-2.0

# VHS recorder image for CI: upstream vhs plus the git and direnv binaries the
# demo tapes call. Built in each vhs-record matrix job with a shared GitHub
# Actions layer cache, so only the first run after an upstream change pays for
# the apt install.
FROM ghcr.io/charmbracelet/vhs:v0.11.0@sha256:9d5fc3dc0c160b0fb1d2212baff07e6bdf3fa9438c504a3237484567302fcf93
RUN apt-get update --allow-releaseinfo-change \
    && apt-get install -y --no-install-recommends git direnv \
    && rm -rf /var/lib/apt/lists/*
