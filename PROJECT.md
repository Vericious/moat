# Moat — Homelab Security Posture Scanner

**Language:** Rust
**License:** MIT
**Deploy:** Single binary + Docker image
**Status:** Planning

---

## What Is Moat?

A self-hosted security scanner for homelabs. Deploy it alongside your Docker stack. It scans your environment and tells you what's exposed, misconfigured, or vulnerable — in plain language with actionable fixes.

**For:** People running 5-30 Docker containers on a home server or VPS. Technical enough to run Docker, not security professionals. They want to know "am I doing something stupid?" without hiring a pentester.

**Think:** Uptime Kuma's simplicity, applied to security instead of uptime.

---

## MVP Scope (Month 1)

### Core: Docker Security Scanner

Moat connects to the Docker socket and analyzes every running container.

**Checks (each produces a finding with severity + plain-English fix):**

1. **Privileged containers** — flag any container running with `--privileged` or dangerous capabilities (SYS_ADMIN, NET_ADMIN, etc.)
2. **Root user** — flag containers running as root (UID 0) when they don't need to
3. **Docker socket mount** — flag containers with `/var/run/docker.sock` mounted (effectively root on host)
4. **Sensitive host mounts** — flag volumes mounting `/etc`, `/root`, `/home`, `/var/run` or other dangerous host paths
5. **Exposed ports** — flag containers binding ports to 0.0.0.0 (all interfaces) vs 127.0.0.1 (local only), especially for databases (3306, 5432, 6379, 27017), admin panels, and management ports
6. **No resource limits** — flag containers without memory/CPU limits set (DoS risk)
7. **Environment variable secrets** — detect likely secrets/passwords/API keys in container env vars (pattern matching on key names: PASSWORD, SECRET, API_KEY, TOKEN, etc.)
8. **Image freshness** — flag containers running images that are significantly behind the latest available tag
9. **No health check** — flag containers without a health check defined
10. **Network mode host** — flag containers using `--network=host`

### Output Formats

- **Terminal (default):** Color-coded findings grouped by container. Traffic light severity: 🔴 Critical, 🟡 Warning, 🟢 Info. Each finding includes a one-line explanation + suggested fix.
- **JSON:** Machine-readable output for scripting/automation
- **Markdown:** Human-readable report suitable for saving or sharing

### CLI Interface

```
moat scan                    # Scan all running containers
moat scan --container NAME   # Scan specific container
moat scan --severity high    # Only show high+ findings  
moat scan --format json      # JSON output
moat scan --format markdown  # Markdown report
moat scan --output report.md # Write to file
moat version                 # Version info
moat help                    # Help
```

### Exit Codes

- 0: No critical or high findings
- 1: High severity findings present
- 2: Critical severity findings present
- 3: Scan error (can't connect to Docker, etc.)

### Docker Deployment

```yaml
# docker-compose.yml
services:
  moat:
    image: ghcr.io/[org]/moat:latest
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock:ro
    command: scan --format json
```

Can run as a one-shot scan or on a cron schedule.

---

## Month 1 Goals & Objectives

### G1: Working Scanner (Week 1-2)

| # | Objective | Measurable Outcome | Done? |
|---|-----------|-------------------|-------|
| 1.1 | Connect to Docker socket and enumerate containers | `moat scan` lists all running containers with name, image, status | ☐ |
| 1.2 | Implement check: privileged mode detection | Correctly identifies `--privileged` and dangerous capabilities on test containers | ☐ |
| 1.3 | Implement check: root user detection | Correctly flags containers running as UID 0 | ☐ |
| 1.4 | Implement check: docker.sock mount detection | Correctly flags socket mount in any volume bind | ☐ |
| 1.5 | Implement check: sensitive host path mounts | Correctly flags /etc, /root, /home, /var/run mounts | ☐ |
| 1.6 | Implement check: exposed ports on 0.0.0.0 | Correctly flags all-interface bindings, especially for known-dangerous ports | ☐ |
| 1.7 | Implement check: missing resource limits | Correctly flags containers without memory/CPU limits | ☐ |
| 1.8 | Implement check: env var secret detection | Pattern-matches PASSWORD, SECRET, API_KEY, TOKEN etc. in env vars | ☐ |
| 1.9 | Implement check: image freshness | Compares running image digest against latest tag from registry | ☐ |
| 1.10 | Implement check: no health check | Flags containers without HEALTHCHECK defined | ☐ |
| 1.11 | Implement check: host network mode | Flags `--network=host` containers | ☐ |

### G2: Output & Reporting (Week 2-3)

| # | Objective | Measurable Outcome | Done? |
|---|-----------|-------------------|-------|
| 2.1 | Terminal output with color-coded severity | Findings grouped by container, colored 🔴🟡🟢, with plain-English descriptions | ☐ |
| 2.2 | JSON output format | Valid JSON array of findings with container, check, severity, message, fix fields | ☐ |
| 2.3 | Markdown output format | Clean markdown report suitable for saving/sharing | ☐ |
| 2.4 | Exit code reflects worst severity | Returns 0/1/2/3 based on findings | ☐ |
| 2.5 | Summary line | "Scanned X containers: Y critical, Z high, W medium findings" | ☐ |

### G3: Quality & Ship (Week 3-4)

| # | Objective | Measurable Outcome | Done? |
|---|-----------|-------------------|-------|
| 3.1 | Integration tests with real Docker | Test suite spins up known-bad containers, runs moat, verifies correct findings | ☐ |
| 3.2 | Unit tests for each check | Each check function has ≥3 test cases (positive, negative, edge case) | ☐ |
| 3.3 | CI pipeline | GitHub Actions: build, test, clippy, fmt on every push | ☐ |
| 3.4 | Docker image published | `ghcr.io/[org]/moat:latest` builds and pushes automatically | ☐ |
| 3.5 | README with install instructions | Binary download, cargo install, docker run — all three paths documented | ☐ |
| 3.6 | Cross-compilation | Linux amd64 + arm64 binaries (covers x86 servers + Raspberry Pi) | ☐ |
| 3.7 | Tested on real homelab stack | Run against a realistic stack (Jellyfin, *arr, Traefik, Portainer, etc.) and verify useful output | ☐ |

### G4: Month 1 Ship Criteria

**MVP is shippable when ALL of these are true:**
- [ ] All 11 checks implemented and tested
- [ ] All 3 output formats working
- [ ] CI green with ≥80% test coverage on check logic
- [ ] Docker image builds for amd64 + arm64
- [ ] README is complete and honest (what it does, what it doesn't)
- [ ] Run against a real stack produces genuinely useful findings (not just noise)
- [ ] Published on GitHub with MIT license

---

## Future (Month 2-3 candidates — not committed)

These are ideas for after MVP ships. Priority TBD based on user feedback.

**Network layer:**
- SSL/TLS certificate expiry checking
- External port scan (what's actually reachable from outside)
- Reverse proxy config analysis (Traefik, Caddy, nginx)
- DNS rebinding detection

**Configuration layer:**
- docker-compose.yml static analysis (find secrets, misconfigs before deploy)
- .env file scanning
- Known default credential checking against running services

**UX improvements:**
- Web dashboard (traffic light per container, click to drill down)
- Scheduled scans with notifications (ntfy, Discord, Telegram, email)
- Baseline/diff mode (only show new findings since last scan)
- Ignore rules (suppress known-acceptable findings)

**Community:**
- Plugin system for custom checks
- Community-contributed check packs (e.g., "*arr stack hardening")

---

## Technical Notes

**Rust crates (likely):**
- `bollard` — Docker API client
- `clap` — CLI argument parsing
- `serde` / `serde_json` — serialization
- `colored` or `owo-colors` — terminal colors
- `tokio` — async runtime (Docker API is async)
- `reqwest` — HTTP client (for registry API calls)

**Architecture:**
- Each check is a standalone function: `fn check_privileged(container: &ContainerInfo) -> Vec<Finding>`
- Checks are registered in a list, scanner runs all of them
- Finding struct: `{ container, check_id, severity, title, message, fix }`
- Reporter trait with Terminal/JSON/Markdown implementations

**Docker socket access:**
- Mount `/var/run/docker.sock:/var/run/docker.sock:ro` (read-only)
- This gives read access to container metadata — no write access needed
- Document the security implications of this in README (it's ironic but necessary)
