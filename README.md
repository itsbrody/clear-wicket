# Clear Wicket

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

### Variant A — Shared (Authelia-like)

One Clear Wicket instance with `COOKIE_DOMAIN=.example.com`. A single TOTP secret protects all apps under `*.example.com`. One login grants access everywhere.

```yaml
services:
  clear-wicket:
    environment:
      COOKIE_DOMAIN: .example.com
      AUTH_HOST: auth.example.com

  app1:
    labels:
      - traefik.http.routers.app1.middlewares=wicket-auth

  app2:
    labels:
      - traefik.http.routers.app2.middlewares=wicket-auth
```

### Variant B — Per-App Isolation

Each app gets its own Clear Wicket instance with its own TOTP secret and a per-app `COOKIE_DOMAIN`. Login to one app does not grant access to another.

```yaml
services:
  wicket-app1:
    environment:
      COOKIE_DOMAIN: app1.example.com
      AUTH_HOST: auth-app1.example.com
    volumes:
      - wicket-app1-data:/data

  wicket-app2:
    environment:
      COOKIE_DOMAIN: app2.example.com
      AUTH_HOST: auth-app2.example.com
    volumes:
      - wicket-app2-data:/data

  app1:
    labels:
      - traefik.http.routers.app1.middlewares=wicket-app1-auth

  app2:
    labels:
      - traefik.http.routers.app2.middlewares=wicket-app2-auth
```

### Do Not Mix Variants

If a Traefik router has both a wildcard instance (`.example.com`) and a dedicated instance (`app1.example.com`) as forwardAuth middleware, the user must pass both TOTP checks sequentially — or Traefik silently uses only the last middleware (depending on version and config). Either way, the result is unintended. Pick one variant per router.

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

# Health check (used by Docker HEALTHCHECK)
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

## License

Apache-2.0 — see [LICENSE](LICENSE).

Copyright Clear Consulting LLC (Wolfgang Brodowski).
