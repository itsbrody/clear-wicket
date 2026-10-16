# Clear Wicket

[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)
[![Go](https://img.shields.io/badge/Go-1.25-00ADD8.svg)](https://go.dev)

A lightweight, passwordless TOTP forward-auth gateway for Traefik.

Clear Wicket puts a pure TOTP layer (RFC 6238) in front of any service — as a standalone second factor or as the sole access control, without its own password system.

## Why?

Every established forward-auth solution (Authelia, Authentik, tinyauth, traefik-forward-auth, oauth2-proxy) requires its own first factor. Clear Wicket doesn't. One TOTP code, one cookie, done.

No SMTP configuration. No email recovery (by design — email recovery degrades TOTP security to mailbox security). No external runtime dependencies.

## Quick Start

```yaml
# docker-compose.yml
services:
  clear-wicket:
    image: ghcr.io/itsbrody/clear-wicket:latest
    environment:
      COOKIE_DOMAIN: .example.com
      AUTH_HOST: auth.example.com
    volumes:
      - wicket-data:/data
    labels:
      - traefik.enable=true
      - traefik.http.routers.wicket.rule=Host(`auth.example.com`)
      - traefik.http.routers.wicket.tls=true
      - traefik.http.services.wicket.loadbalancer.server.port=4181
      # Define the forwardAuth middleware
      - traefik.http.middlewares.wicket-auth.forwardauth.address=http://clear-wicket:4181/auth
      - traefik.http.middlewares.wicket-auth.forwardauth.authResponseHeaders=Remote-User

  protected-app:
    image: traefik/whoami
    labels:
      - traefik.enable=true
      - traefik.http.routers.app.rule=Host(`app.example.com`)
      - traefik.http.routers.app.tls=true
      - traefik.http.routers.app.middlewares=wicket-auth

volumes:
  wicket-data:
```

1. Start the stack. Open `https://auth.example.com/setup`.
2. Scan the QR code with your authenticator app, enter a code to confirm.
3. Save the backup codes.
4. Access `https://app.example.com` — you'll be redirected to the login page. Enter your TOTP code and you're in.

## Configuration

All configuration is via environment variables.

| Variable | Required | Default | Description |
|---|---|---|---|
| `COOKIE_DOMAIN` | yes | — | Domain for the session cookie. Use `.example.com` for SSO across subdomains |
| `AUTH_HOST` | yes | — | Hostname where Clear Wicket serves its login UI |
| `SESSION_TTL` | no | `24h` | Session duration (Go duration format: `12h`, `30m`, etc.) |
| `DATA_DIR` | no | `./data` | Directory for persistent state |
| `TOTP_SKEW` | no | `1` | Time window tolerance (±N windows for clock drift) |
| `TOTP_SECRET` | no | — | Pre-provision a TOTP secret (base32). Skips web setup |
| `COOKIE_SECRET` | no | auto | HMAC signing key (hex). Auto-generated and persisted if not set |
| `INSECURE_COOKIE` | no | `false` | Set `true` for local dev (disables `Secure` flag on cookies) |
| `LISTEN_ADDR` | no | `:4181` | Listen address |

## Deployment Variants

The Quick Start above shows a single app behind a single Clear Wicket container. The following variants show how to scale that to multiple apps. Pick one variant and put everything into a single `docker-compose.yml` alongside Traefik and your apps. The snippets below only show the parts that change (Traefik labels, volumes, and TLS config still apply as above).

Complete, ready-to-use Compose files: [`examples/docker-compose.shared.yml`](examples/docker-compose.shared.yml) (Variant A) and [`examples/docker-compose.isolated.yml`](examples/docker-compose.isolated.yml) (Variant B).

### Variant A — Shared SSO

One Clear Wicket container, one TOTP secret, one login for all apps.

You run a single `clear-wicket` container with a wildcard cookie domain (`.example.com`). All apps point their Traefik middleware at that one container. One TOTP code unlocks every app under `*.example.com` — same authenticator entry, same session cookie.

```yaml
services:
  clear-wicket:
    image: ghcr.io/itsbrody/clear-wicket:latest
    environment:
      COOKIE_DOMAIN: .example.com         # wildcard: cookie valid for all subdomains
      AUTH_HOST: auth.example.com
    volumes:
      - wicket-data:/data                 # one volume = one TOTP secret

  app1:
    labels:
      - traefik.http.routers.app1.middlewares=wicket-auth  # ─┐ both apps use
                                                               # │ the same middleware
  app2:                                                        # │ → same container
    labels:                                                    # │ → same TOTP secret
      - traefik.http.routers.app2.middlewares=wicket-auth  # ─┘
```

### Variant B — Per-App Isolation

One Clear Wicket container per app, each with its own TOTP secret.

You run a separate `clear-wicket` container for each app you want to protect. Each container has its own data volume (= its own TOTP secret and backup codes), its own cookie domain, and its own auth hostname. In your authenticator app, each shows up as a separate entry. Logging in to one app does not grant access to another.

```yaml
services:
  # Container 1: Clear Wicket instance for app1
  wicket-app1:
    image: ghcr.io/itsbrody/clear-wicket:latest
    environment:
      COOKIE_DOMAIN: app1.example.com     # scoped to app1 only
      AUTH_HOST: auth-app1.example.com
    volumes:
      - wicket-app1-data:/data            # own volume = own TOTP secret

  # Container 2: Clear Wicket instance for app2
  wicket-app2:
    image: ghcr.io/itsbrody/clear-wicket:latest
    environment:
      COOKIE_DOMAIN: app2.example.com     # scoped to app2 only
      AUTH_HOST: auth-app2.example.com
    volumes:
      - wicket-app2-data:/data            # own volume = own TOTP secret

  app1:
    labels:
      - traefik.http.routers.app1.middlewares=wicket-app1-auth  # → wicket-app1 container

  app2:
    labels:
      - traefik.http.routers.app2.middlewares=wicket-app2-auth  # → wicket-app2 container
```

At <15 MB per container, running one per app is negligible overhead.

### Do Not Mix Variants

If a Traefik router has both a wildcard instance (`.example.com`) and a dedicated instance (`app1.example.com`) as forwardAuth middleware, the user must pass both TOTP checks sequentially — or Traefik silently uses only the last middleware (depending on version and config). Either way, the result is unintended. Pick one variant per router.

### Platform-Specific Guides

- [Deploying on Coolify](docs/coolify.md)

## Security Model

### What Clear Wicket does

- **TOTP validation** per RFC 6238 with configurable clock drift tolerance
- **Replay protection** — an accepted code cannot be reused in the same time window
- **Rate limiting** — exponential backoff after 5 failed TOTP attempts (3 for backup codes)
- **Backup codes** — 10 one-time codes generated at setup, stored as argon2id hashes
- **Signed session cookies** — HMAC-SHA256, HttpOnly, Secure, SameSite=Lax
- **Server-side session tracking** — logout actually invalidates the session
- **CSRF protection** on all POST endpoints
- **Open redirect protection** — redirect targets validated against `COOKIE_DOMAIN`
- **Constant-time comparisons** for codes and signatures

### What Clear Wicket does not do

- **No password management** — it's a pure TOTP gate, not an identity provider
- **No email recovery** — by design. Email-based recovery degrades the factor's security to mailbox security. Recovery path: backup codes or admin reset.
- **No user database** — V1 supports a single user. Multi-user support is architecturally prepared but not yet implemented.
- **No external requests** at runtime — no telemetry, no update checks, no cloud dependencies

### Recovery

- **Self-service:** Use a backup code. After each backup code login, the remaining count is displayed. When the last code is used, you're prompted to regenerate.
- **Admin reset:** Run `clear-wicket reset` (or delete the state files in `DATA_DIR`). This clears all state and re-opens the setup flow.
- **Backup code regeneration:** After logging in with TOTP, visit the backup code regeneration endpoint. All old codes are invalidated.

## CLI

```bash
# Start the server
clear-wicket

# Reset all state (re-opens setup flow)
clear-wicket reset

# Health check (for use by your orchestrator)
clear-wicket healthcheck
```

## Building from Source

```bash
go build -o clear-wicket ./cmd/clear-wicket
```

## Docker

```bash
docker build -t clear-wicket .
```

Image: `FROM scratch`, non-root (UID 65534), read-only rootfs compatible. Target size: < 15 MB.

Mount a volume to `/data` for persistent state.

## Comparison

| | Clear Wicket | Authelia | Authentik | Keycloak | tinyauth | Onetime |
|---|---|---|---|---|---|---|
| Passwordless (TOTP only) | yes | no | no | no | no | yes |
| Backup codes | yes (V1) | no (Issue #1319) | yes | yes | no | no |
| Email recovery | no (by design) | yes | configurable | yes | no | no |
| Admin reset | CLI / state file | CLI | Admin UI | Admin Console | Config file | State file |
| SMTP required | no | yes | for email flows | for reset flows | no | no |
| Traefik native | yes | yes | yes | via adapter | yes | no (Nginx) |

## Troubleshooting

| Problem | Ursache / Lösung |
|---|---|
| Setup-Seite erscheint nicht | Setup wurde bereits abgeschlossen (`setup_complete` existiert). Zum Zurücksetzen: `clear-wicket reset` oder die Dateien in `DATA_DIR` löschen. |
| TOTP-Code wird abgelehnt | Uhrzeit des Geräts prüfen (TOTP ist zeitbasiert). Bei persistenter Abweichung: `TOTP_SKEW` erhöhen (Standard: `1`). |
| Cookie greift nicht über Subdomains | `COOKIE_DOMAIN` muss mit einem Punkt beginnen (`.example.com`), damit der Cookie für alle Subdomains gilt. |
| Daten nach Container-Neustart weg | `/data` muss auf ein persistentes Volume gemountet sein (`volumes: - wicket-data:/data`). |
| Alle Backup-Codes aufgebraucht | Mit TOTP einloggen, dann unter `/backup-codes/regenerate` neue Codes generieren. Falls kein TOTP-Zugang mehr besteht: `clear-wicket reset`. |

## License

Apache-2.0 — see [LICENSE](LICENSE).

Copyright Clear Consulting LLC (Wolfgang Brodowski).

<p align="center">
  <a href="https://klare-beratung.de/blog/ein-totp-code-ein-cookie-fertig-warum-ich-clear-wicket-gebaut-habe?utm_source=github&utm_medium=readme&utm_campaign=clear-wicket">Hintergrund im Blog</a>
</p>

<p align="center">
  Erstellt im Juli 2026 · Clear Consulting LLC · <a href="https://klare-beratung.de/?utm_source=github&utm_medium=readme&utm_campaign=clear-wicket">klare-beratung.de</a>
</p>
