# Deploying Clear Wicket on Coolify

Coolify brings its own Traefik instance and manages containers, networks, and TLS automatically. This changes how Clear Wicket is deployed compared to a standalone Docker Compose setup.

> The example Compose files in `examples/` include their own Traefik service and are designed for standalone use. Do not use them directly in Coolify — follow the steps below instead.

## Step 1 — Create Clear Wicket as a Coolify Resource

- **Build Pack:** Dockerfile (not Docker Compose)
- **Git Repository:** your Clear Wicket repo
- **Domain:** your auth hostname, e.g. `https://auth.example.com`

### Port

Coolify defaults to port 3000. Clear Wicket listens on **4181**. Change the exposed port in Coolify's service settings, otherwise Traefik will proxy to the wrong port and return **502 Bad Gateway**.

### Container Name

Set a **fixed container name** (e.g. `wicket-totp`) under the Container settings. Coolify generates random container names by default — if the name changes on redeploy, the forwardAuth middleware address breaks and protected apps return 502.

### Environment Variables

| Variable | Value |
|---|---|
| `COOKIE_DOMAIN` | `.example.com` (with leading dot for wildcard SSO) |
| `AUTH_HOST` | `auth.example.com` |
| `DATA_DIR` | `/data` |

To embed protected apps in another site (for example as an external page in Nextcloud), also set `FRAME_ANCESTORS`, e.g. `https://cloud.example.com`. Set it on the Clear Wicket resource, not on the protected app. Clear Wicket sets the framing headers on all of its responses, including the redirect and the login page. Without the variable, framing stays denied. A wrong value stops the container at startup; the reason is in the container log. See [Embedding in other sites](../README.md#embedding-in-other-sites) for the allowed values and the same-site requirement.

### Volume

Add a persistent volume in Coolify's Storage settings:

| Source Path | Destination Path |
|---|---|
| `/data/coolify/services/totp` | `/data` |

Create the directory on the host with the correct ownership **before the first deploy**:

```bash
mkdir -p /data/coolify/services/totp
chown -R 65534:65534 /data/coolify/services/totp
```

Clear Wicket runs as UID 65534 (non-root). Coolify creates bind mounts owned by root — without `chown`, the container cannot write its state files and will crash with `permission denied`.

### Health Check (optional)

The Dockerfile includes a commented-out health check. To enable it, uncomment the `HEALTHCHECK` line in the Dockerfile and adjust the interval to your needs.

If Coolify's built-in Healthcheck settings do not take effect (observed in Coolify v4.1.2), you can add the health check directly to the generated Compose file on the host after deployment:

```yaml
healthcheck:
  test: ["CMD", "/clear-wicket", "healthcheck"]
  interval: 5m
  timeout: 3s
```

Then apply with `docker compose up -d <service-name>`. Note that Coolify regenerates the Compose file on each deploy, so this change must be reapplied after redeployment.

## Step 2 — Add Traefik Labels to Clear Wicket

In Coolify's label editor for the Clear Wicket resource, add the forwardAuth middleware definition. Use the fixed container name from Step 1:

```
traefik.http.middlewares.wicket-auth.forwardauth.address=http://wicket-totp:4181/auth
traefik.http.middlewares.wicket-auth.forwardauth.authResponseHeaders=Remote-User
```

Deploy Clear Wicket and verify it starts healthy. Open `https://auth.example.com` — you should see the TOTP setup page.

## Step 3 — Complete TOTP Setup

Open `https://auth.example.com/setup`, scan the QR code with your authenticator app, confirm with a code, and save the backup codes. This is a one-time admin task.

## Step 4 — Protect an App

In Coolify's label editor for the app you want to protect, find the HTTPS router's `middlewares` line and append `wicket-auth`:

```
# Before
traefik.http.routers.https-0-<app-id>.middlewares=gzip

# After
traefik.http.routers.https-0-<app-id>.middlewares=gzip,wicket-auth
```

If the app already uses BasicAuth or other middlewares, append `wicket-auth` at the end — the user will complete existing auth first, then TOTP:

```
traefik.http.routers.https-0-<app-id>.middlewares=gzip,http-basic-auth-<app-id>,wicket-auth
```

Deploy the app. On the next visit, you'll be prompted for TOTP after any existing authentication.

### Network

Both the Clear Wicket container and the protected app must be on the **same Docker network** (typically `coolify`). Coolify usually handles this automatically. Verify with:

```bash
docker inspect <container-name> --format '{{range $k,$v := .NetworkSettings.Networks}}{{$k}} {{end}}'
```

## Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| 502 Bad Gateway on auth domain | Loadbalancer port set to 3000 | Change to 4181 in Coolify port settings |
| `permission denied` in container logs | Volume owned by root, container runs as UID 65534 | `chown -R 65534:65534 <volume-path>` on host |
| 502 after redeploy | Container name changed | Set a fixed container name in Coolify |
| forwardAuth not reachable | Containers on different networks | Ensure both are on the `coolify` network |
