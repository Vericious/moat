# moat — Homelab Docker Security Scanner

A container security scanner for homelab Docker environments. Scans running containers for common misconfigurations and security risks, reporting findings grouped by severity.

## Checks

| Check | Severity | Description |
|-------|----------|-------------|
| `PrivilegedCheck` | Critical / High | Flags privileged containers and dangerous capabilities (`SYS_ADMIN`, `NET_ADMIN`, `SYS_PTRACE`, `DAC_OVERRIDE`) |
| `SocketMountCheck` | Critical | Detects Docker socket mounts inside containers |
| `RootUserCheck` | High | Flags containers running as root |
| `HostMountsCheck` | High | Detects sensitive host path mounts (`/etc`, `/root`, `/proc`, etc.) |
| `EnvSecretsCheck` | High | Finds environment variables that look like secrets (`PASSWORD`, `TOKEN`, `API_KEY`, etc.) |
| `ResourceLimitsCheck` | Medium | Flags containers with no memory or CPU limits |
| `ExposedPortsCheck` | Medium / Low | Reports ports exposed to `0.0.0.0` vs localhost |
| `HostNetworkCheck` | High | Detects containers using host network mode |
| `HealthCheckCheck` | Medium | Flags containers without a defined health check |
| `ImageFreshnessCheck` | Low | Warns when containers use the `latest` tag |

## Usage

```bash
# Scan with default terminal output
moat scan

# Scan with JSON output
moat scan --format json

# Scan with markdown output
moat scan --format markdown

# Use a different Docker socket
moat scan --socket /path/to/docker.sock

# Verbose output
moat scan --verbose

# Exclude specific check categories from results (case-insensitive)
moat scan --exclude-category privileged --exclude-category rootuser

# Show version
moat version
```

### Docker

```bash
# Build
docker build -t moat .

# Run against the local Docker socket
docker run --rm -v /var/run/docker.sock:/var/run/docker.sock moat scan

# Run with JSON output
docker run --rm -v /var/run/docker.sock:/var/run/docker.sock moat scan --format json
```

### Installation

```bash
# From source
cargo install --path .
moat --help
```

## Output

Findings are grouped by severity:

```
━━━ CRITICAL ━━━
  [nginx] Container 'nginx' is running in privileged mode
    → Remove privileged mode from the container security configuration

━━━ HIGH ━━━
  [web] Container 'web' is running as root user
    → Set USER directive in Dockerfile or use --user flag to run as non-root
```

Exit code is non-zero if any Critical or High findings are present.

## Configuration

No configuration file required. All checks are enabled by default. Use `--exclude-category` to filter out specific checks from the scan results.

## Architecture

- `src/checks/` — Individual security check implementations
- `src/container.rs` — `ContainerInfo` abstraction over bollard Docker API
- `src/finding.rs` — `Finding` and `Severity` types
- `src/scanner.rs` — Docker container enumeration
- `src/report/` — Output formatters (terminal, JSON, markdown)

## License

MIT
