FROM rust:1-slim AS builder

WORKDIR /app

# Install compilation dependencies for bollard (openssl)
RUN apt-get update && apt-get install -y \
    pkg-config \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

# Copy manifests first for dependency caching
COPY Cargo.toml Cargo.lock* ./
RUN mkdir src && echo "fn main() {}" > src/main.rs
RUN cargo build --release --locked && rm -rf src

# Copy actual source
COPY src ./src
RUN touch src/main.rs && cargo build --release --locked

# Final stage: minimal runtime image
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /app/target/release/moat /usr/local/bin/moat

ENTRYPOINT ["moat"]
