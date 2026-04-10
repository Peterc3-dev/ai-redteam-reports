# CIN Internal Security Scan -- 2026-04-10

**Scope:** ThinkCentre M70q (100.123.55.83) -- read-only audit
**Auditor:** Automated (Claude Code)
**Classification:** Defensive / hardening review

---

## CRITICAL

### [C1] Letta API fully open on 0.0.0.0:8283 -- no authentication

Letta (v0.16.7) is bound to `0.0.0.0:8283` with zero authentication. Any host on the network (including every Tailscale peer) can hit the full API:

- `GET /v1/health` -- returns 200, version info
- `GET /v1/agents` -- returns full agent list (1 agent found)
- All CRUD endpoints presumed open (create/delete agents, read memory, send messages)

An attacker on the Tailnet (or any network if a firewall is absent) can read agent memory, inject messages, or delete agents.

**Remediation:** Bind Letta to `127.0.0.1` or add an auth proxy. If Tailscale-only access is intended, use Tailscale ACLs or `--host 127.0.0.1` with a Tailscale funnel/serve for controlled access.

### [C2] Redis bound to 0.0.0.0:6379 -- no auth visible

Redis is listening on all interfaces with no apparent authentication. This is a well-known attack vector (data exfil, RCE via module loading).

**Remediation:** Bind to `127.0.0.1` in redis.conf, or set a `requirepass`, or both.

---

## HIGH

### [H1] DVGA (Damn Vulnerable GraphQL Application) exposed on 0.0.0.0:5013

An intentionally vulnerable application is running and listening on all interfaces. While this is a lab tool, it is reachable from any Tailscale peer and potentially from the LAN.

**Remediation:** Bind to `127.0.0.1` or firewall to Tailscale-only if used for red-team exercises.

### [H2] GitLab CE exposed on 0.0.0.0 (ports 8922, 8929, 8443)

GitLab SSH (8922), HTTP (8929), and HTTPS (8443) are all bound to all interfaces. If this is intended for Tailnet-only use, the bindings are too broad.

**Remediation:** Bind Docker port mappings to `127.0.0.1:` prefix or use Tailscale serve.

### [H3] No .gitignore in gh-reply-agent project

The `/home/raz/projects/gh-reply-agent/` directory has no `.gitignore`. The `.tg_token` file (containing the Telegram bot token) is currently untracked only because the directory is not a git repo. If `git init` is ever run, the token file would be staged by default.

**Remediation:** Add a `.gitignore` with `.tg_token`, `.env`, `*.key`, `state.json`.

### [H4] CLAUDE.md exposes full infrastructure map

`/home/raz/CLAUDE.md` contains:
- 4 Tailscale IPs (100.123.55.83, 100.77.212.27, 100.88.127.42, 100.85.219.119)
- SSH ports and connection strings for all nodes
- Device hostnames, OS versions, hardware specs
- GitHub account name and repository list
- Installed offensive tooling list (subfinder, nuclei, ffuf, etc.)

If this file leaks (e.g., via a committed repo, LLM context injection, or screen share), an attacker has a complete network map.

**Remediation:** Consider splitting sensitive connection details into a separate file excluded from version control and LLM context. Keep CLAUDE.md to roles/conventions only.

---

## MEDIUM

### [M1] SSH: PermitRootLogin not explicitly disabled

`sshd_config` has `#PermitRootLogin prohibit-password` (commented out). The default for OpenSSH is `prohibit-password`, which allows key-based root login. Explicit `PermitRootLogin no` is safer.

- Password auth: **disabled** (good -- `PasswordAuthentication no`)
- KbdInteractiveAuthentication: **disabled** (good -- via drop-in)
- PAM: enabled (fine with password auth off)

**Remediation:** Add `PermitRootLogin no` to sshd_config or a drop-in.

### [M2] Multiple services on 0.0.0.0 with unclear purpose

Additional wildcard-bound listeners:
| Port  | Notes |
|-------|-------|
| 5355  | LLMNR (systemd-resolved) |
| 8888  | Unknown -- investigate |
| 4317  | OpenTelemetry gRPC |
| 4318  | OpenTelemetry HTTP |
| 12470 | Node.js process |
| 11470 | Node.js process |
| 1716  | KDE Connect |
| 22000 | Syncthing |

**Remediation:** Audit each service. Bind to `127.0.0.1` or Tailscale IP where possible.

### [M3] Telegram bot token loaded from plaintext file

`/home/raz/projects/gh-reply-agent/.tg_token` stores the bot token in plaintext. File permissions are correct (`600`), but there is no encryption at rest.

**Remediation:** Consider using a secrets manager, systemd credentials, or at minimum ensure the file is in `.gitignore` (see H3).

---

## LOW / INFORMATIONAL

### [L1] No .env files or credential files found in ~/projects

`find` across `~/projects` returned no `.env`, `.key`, or `credentials*` files. This is good hygiene.

### [L2] agent.py reads token from file, not hardcoded

The token in `agent.py` is loaded via `Path(".tg_token").read_text()` -- not embedded in source. No partial token strings (AAG pattern) found in source code. Good practice.

### [L3] PostgreSQL (pgvector) correctly bound to 127.0.0.1:5433

The Letta database container is properly restricted to localhost. Good.

### [L4] Syncthing GUI bound to 127.0.0.1:8384

Syncthing admin interface is localhost-only. Good. However, the sync protocol (22000) is on all interfaces (expected for sync functionality).

---

## Summary

| Severity | Count | Key Issue |
|----------|-------|-----------|
| CRITICAL | 2     | Letta API + Redis unauthenticated on 0.0.0.0 |
| HIGH     | 4     | DVGA/GitLab exposed, no gitignore, CLAUDE.md info leak |
| MEDIUM   | 3     | Root login, wildcard services, plaintext token |
| LOW/INFO | 4     | Positive findings (no .env leaks, DB locked down) |

**Top 3 actions:**
1. Bind Letta to 127.0.0.1 or add authentication
2. Bind Redis to 127.0.0.1 and set requirepass
3. Add .gitignore to gh-reply-agent (and audit other projects)
