# 🏰 Moat

**Homelab security posture scanner — know what's exposed before someone else does.**

Moat scans your running Docker containers and tells you what's misconfigured, exposed, or vulnerable. Plain English findings with actionable fixes. No security jargon.

## Quick Start

```bash
# Run with Docker (easiest)
docker run --rm -v /var/run/docker.sock:/var/run/docker.sock:ro ghcr.io/vericious/moat scan

# Or install the binary
cargo install moat

# Or download a release
curl -L https://github.com/Vericious/moat/releases/latest/download/moat-linux-amd64 -o moat
chmod +x moat
./moat scan
```

## What It Checks

| Check | Severity | What It Finds |
|-------|----------|---------------|
| Privileged mode | 🔴 Critical | Containers with `--privileged` or dangerous capabilities |
| Docker socket | 🔴 Critical | Containers with `/var/run/docker.sock` mounted read-write |
| Root user | 🟡 Medium | Containers running as UID 0 |
| Socket (read-only) | 🟠 High | Docker socket mounted read-only |
| Sensitive mounts | 🟠 High | Host paths like `/etc`, `/root`, `/home` mounted |
| Exposed ports | 🟠 High | Ports bound to 0.0.0.0 (all interfaces) |
| No resource limits | 🟡 Medium | Containers without memory/CPU limits |
| Env var secrets | 🟠 High | Passwords/API keys in environment variables |
| Image freshness | 🟡 Medium | Images significantly behind latest |
| No health check | 🟢 Info | Containers without HEALTHCHECK defined |
| Host networking | 🟠 High | Containers using `--network=host` |

## Usage

```bash
moat scan                        # Scan all running containers
moat scan --container portainer  # Scan specific container
moat scan --severity high        # Only show high+ findings
moat scan --format json          # JSON output
moat scan --format markdown      # Markdown report
moat scan --output report.md     # Write to file
```

## Output Formats

**Terminal** (default) — color-coded, grouped by container:
```
── portainer ──
  🔴 CRITICAL Docker socket mounted in container (read-write)
    Container 'portainer' has the Docker socket mounted...
    Fix: Mount the socket as read-only...

Scanned 12 container(s): 1 critical, 3 high, 5 medium, 2 info finding(s)
```

**JSON** — for scripting and automation

**Markdown** — for saving reports or sharing

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | No critical or high findings |
| 1 | High severity findings present |
| 2 | Critical severity findings present |
| 3 | Scan error |

## Docker Compose

```yaml
services:
  moat:
    image: ghcr.io/vericious/moat:latest
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock:ro
    command: scan --format json
```

## A Note on Docker Socket Access

Yes, it's ironic — a security scanner that needs Docker socket access. Moat mounts it **read-only** and only reads container metadata (it never creates, stops, or modifies containers). If you want to be extra careful, use [docker-socket-proxy](https://github.com/Tecnativa/docker-socket-proxy) and only expose the `containers` and `images` API endpoints.

## Building from Source

```bash
git clone https://github.com/Vericious/moat.git
cd moat
cargo build --release
./target/release/moat scan
```

## License

MIT
