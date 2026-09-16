# The V2 guest toolchain: rust + the pinned SP1 toolchain (cargo-prove).
# Built on demand by `jobkit build` (tagged provework/sp1-toolchain:v2);
# subsequent builds reuse the image, and per-build dependency caches
# live in host-mounted directories, not in this image.
FROM rust:1
RUN apt-get update \
    && apt-get install -y -qq protobuf-compiler curl \
    && rm -rf /var/lib/apt/lists/*
# Pin the SP1 toolchain: guest ELFs must build against the same
# sp1-zkvm version the verifier and judge pin (6.8.0).
RUN curl -sSfL https://sp1.succinct.xyz | bash
RUN /root/.sp1/bin/sp1up -v 6.8.0
ENV PATH="/root/.sp1/bin:${PATH}"
