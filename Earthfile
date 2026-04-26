VERSION 0.8

# Reproducible Linux builds for the thread_db wrapper crate.
# Switch arch with: earthly +check --BS_PLATFORM=linux/amd64
ARG --global BS_PLATFORM=linux/arm64

common:
    FROM --platform=$BS_PLATFORM rust:1.89-bookworm
    ENV CARGO_TERM_COLOR=always
    ENV DEBIAN_FRONTEND=noninteractive
    RUN apt-get update && \
        apt-get install -y --no-install-recommends \
            build-essential \
            pkg-config \
            libc6-dbg \
            ca-certificates && \
        rm -rf /var/lib/apt/lists/*
    WORKDIR /td

source:
    FROM +common
    COPY Cargo.toml build.rs ./
    COPY --dir src tests ./

# Fast feedback: cargo check on the active platform.
check:
    FROM +source
    RUN cargo check --all-targets

# Lints (informational; the upstream repo predates several lints we'd
# otherwise fail on, so this target is `cargo clippy` without
# `-D warnings`).
clippy:
    FROM +source
    RUN rustup component add clippy
    RUN cargo clippy --all-targets

# Full test suite. Tests fork+ptrace, so SYS_PTRACE is required.
test:
    FROM +source
    RUN --privileged cargo test -- --test-threads=1

# Build the matrix entry-point used from CI: check + clippy + test on
# the requested BS_PLATFORM. Run twice — once for arm64, once for amd64
# — to validate both arches.
all:
    BUILD +check
    BUILD +clippy
    BUILD +test
