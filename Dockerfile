# =============================================================================
# Stage 1: Build
# =============================================================================
FROM rust:1-slim AS builder

WORKDIR /app

# Copy source
COPY Cargo.toml Cargo.lock ./
COPY src ./src

# Build the release binary
RUN cargo build --release --manifest-path Cargo.toml

# =============================================================================
# Stage 2: Runtime
# =============================================================================
FROM debian:bookworm-slim

# Install CA certificates for HTTPS (used by reqwest for registry lookups)
RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user for security
RUN useradd --create-home --shell /bin/false moat
WORKDIR /home/moat

# Copy binary from builder stage
COPY --from=builder /app/target/release/moat /usr/local/bin/moat

# Switch to non-root user
USER moat

ENTRYPOINT ["/usr/local/bin/moat"]
