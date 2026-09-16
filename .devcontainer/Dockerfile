# Toolchain container for building and flashing the Zephyr/MCUboot reference
# product. Pinned to Ubuntu 24.04 because that is this repo's CI and reference
# host (see docs/agents/issue-tracker.md issue #21).
#
# Nobody needs to build this. CI publishes it to
# ghcr.io/tkemlogic/learning-cyber-security-devcontainer on every change to this
# file, and both devcontainer.json files name the published image. Changing
# anything here means the published image is rebuilt when the change reaches
# main; until then, build locally as .devcontainer/README.md describes.
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
        git \
        gperf \
        libmagic1 \
        libsdl2-dev \
        libusb-1.0-0-dev \
        make \
        ninja-build \
        python3 \
        python3-dev \
        tcpdump \
        python3-pip \
        python3-venv \
        udev \
        unzip \
        wget \
        xz-utils \
    && rm -rf /var/lib/apt/lists/*

# gcc-multilib is the one package in Zephyr's list that does not exist outside
# x86. It provides 32-bit x86 support libraries, there is no arm64 candidate,
# and asking for it there fails the whole apt-get with "has no installation
# candidate". Zephyr's own getting-started guide says to skip the multilib
# packages on other architectures.
#
# Nothing in this course needs it for the ESP32-C6, which is RISC-V and builds
# with the Zephyr SDK toolchain rather than the host compiler. It is kept on
# amd64 so that image stays exactly what it was, rather than dropped from both.
RUN if [ "$(dpkg --print-architecture)" = "amd64" ]; then \
        apt-get update \
        && apt-get install -y --no-install-recommends gcc-multilib \
        && rm -rf /var/lib/apt/lists/*; \
    fi

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
