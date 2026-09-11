# Toolchain container for building and flashing the Tier 0 Zephyr/MCUboot
# reference product. Pinned to Ubuntu 24.04 because that is this repo's CI
# and reference host (see docs/agents/issue-tracker.md issue #21).
FROM docker.io/library/ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive \
    LANG=C.UTF-8

# Host packages from the Zephyr "Getting Started" guide, plus the extras this
# repo's baseline needs (libusb for esptool/west flash, ccache to speed up
# rebuilds). golang-go builds the ./course dispatcher's Go helpers and the OTA
# service.
RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential \
        ca-certificates \
        ccache \
        cmake \
        curl \
        device-tree-compiler \
        dfu-util \
        file \
        gcc-multilib \
        git \
        gperf \
        libmagic1 \
        libsdl2-dev \
        libusb-1.0-0-dev \
        make \
        ninja-build \
        python3 \
        python3-dev \
        python3-pip \
        python3-venv \
        udev \
        unzip \
        wget \
        xz-utils \
    && rm -rf /var/lib/apt/lists/*

# Go, for the ./course dispatcher's helpers and the OTA service.
ARG GO_VERSION=1.23.4
RUN ARCH=$(dpkg --print-architecture) \
    && curl -fsSL "https://go.dev/dl/go${GO_VERSION}.linux-${ARCH}.tar.gz" -o /tmp/go.tar.gz \
    && tar -C /usr/local -xzf /tmp/go.tar.gz \
    && rm /tmp/go.tar.gz
ENV PATH="/usr/local/go/bin:${PATH}"

# `plugdev` matches the group most distros use for USB serial adapters; add
# the default remote user so it can open /dev/ttyACM* without running the
# container as root.
RUN groupadd -f plugdev

# The Zephyr workspace (west init/update, SDK, build output) lives on a
# separate named volume mounted at $ZEPHYR_WORKSPACE, not in this image or
# the repo checkout, so it survives image rebuilds. See .devcontainer/post-create.sh.
ENV ZEPHYR_WORKSPACE=/opt/zephyr-workspace
RUN mkdir -p "${ZEPHYR_WORKSPACE}"

WORKDIR /workspaces
