# Simple Vault

A minimal self-hosted secrets manager. Single-file Node.js app with AES-256-GCM
encryption, fronted by Caddy for automatic HTTPS.

Designed for small teams or personal use — not a replacement for HashiCorp Vault
or Bitwarden. Think "password-protected encrypted blob store you can `curl`."

## Features

- **AES-256-GCM** encryption with **PBKDF2** key derivation (100k iterations, SHA-512)
- Password-based master key — the password itself is never stored, only a
  `vault-ok` canary encrypted with it, used to verify unlock attempts
- 30-minute session tokens, auto-extended on activity
- In-memory rate limiting: 5 `/init` + `/unlock` attempts per IP per 15 min
- Optional IP allowlist (works correctly behind Cloudflare via `CF-Connecting-IP`)
- Fully Dockerized; Caddy handles Let's Encrypt certificates automatically
- Small surface area: ~220 lines of Node.js, no client, no database

## Architecture

```
Client ──HTTPS──► Caddy (443/tcp) ──HTTP──► Node/Express (3100/tcp) ──► /data volume
                   │                                                      │
                   └── Let's Encrypt (auto-renew)                         └── one .enc file per secret
                                                                              (AES-256-GCM envelopes)
```

Caddy and the vault each run in their own Docker container, sharing a private
Compose network. Only Caddy publishes ports to the host (80/443).

## Requirements

- Any Linux VPS with a public IP
- A domain name you control, with an A record pointing to the server
- Docker Engine 20.10+ and Docker Compose v2 (both installed by the one-liner below)
- Open ports 80 and 443 on the server's firewall and cloud security group
- Port 22 for SSH (obviously)

## Quick start

### 1. Install Docker

```bash
curl -fsSL https://get.docker.com | sh
systemctl enable --now docker
```

### 2. Clone the repo

```bash
cd /opt     # or ~/ — wherever you like
git clone https://github.com/wcasa77/simple-vault
cd simple-vault
```

### 3. Point DNS

Create an A record (e.g. `vault.example.com`) → your server's public IP.
Verify it resolves before going further:

```bash
dig +short vault.example.com
# should print your server's public IP
```

### 4. Configure

```bash
cp .env.example .env
nano .env
```

```ini
# Required — Caddy will request a Let's Encrypt cert for this domain.
VAULT_DOMAIN=vault.example.com

# Optional — comma-separated list of client IPs allowed to reach the API.
# Empty = accept any IP. Rate limiting still applies either way.
ALLOWED_IPS=203.0.113.7,198.51.100.22
```

### 5. Start

```bash
docker compose up -d
docker compose logs -f caddy
```

Wait for `certificate obtained successfully` in the Caddy logs. Ctrl+C once
you've seen it.

### 6. Verify

```bash
curl https://vault.example.com/health
# {"status":"ok","initialized":false}
```

### 7. Initialize

**Pick a long random master password and save it in a password manager
before running this. There is no recovery.**

```bash
curl -X POST https://vault.example.com/init \
  -H 'Content-Type: application/json' \
  -d '{"password":"YOUR-LONG-RANDOM-MASTER-PASSWORD"}'
# {"message":"Vault initialized"}
```

## Using the API

### Bash / Linux / macOS

```bash
# Unlock → session token
TOKEN=$(curl -s -X POST https://vault.example.com/unlock \
  -H 'Content-Type: application/json' \
  -d '{"password":"YOUR-MASTER-PASSWORD"}' | jq -r .token)

# Store
curl -X POST https://vault.example.com/secrets/db-password \
  -H "x-vault-token: $TOKEN" -H 'Content-Type: application/json' \
  -d '{"value":"correct-horse-battery-staple"}'

# Read
curl https://vault.example.com/secrets/db-password -H "x-vault-token: $TOKEN"

# List names
curl https://vault.example.com/secrets -H "x-vault-token: $TOKEN"

# Delete
curl -X DELETE https://vault.example.com/secrets/db-password -H "x-vault-token: $TOKEN"

# Lock immediately (invalidate token)
curl -X POST https://vault.example.com/lock -H "x-vault-token: $TOKEN"
```

### Windows PowerShell

PowerShell's double-quoted strings expand `$variables` — use **single quotes**
for the password so nothing gets silently mangled.

```powershell
$pw = 'YOUR-MASTER-PASSWORD'    # single quotes — do NOT use double

$token = (Invoke-RestMethod -Method Post -Uri https://vault.example.com/unlock `
  -ContentType 'application/json' `
  -Body (@{password=$pw} | ConvertTo-Json)).token

$h = @{"x-vault-token"=$token}

# Store
Invoke-RestMethod -Method Post -Uri https://vault.example.com/secrets/db-password `
  -Headers $h -ContentType 'application/json' `
  -Body (@{value='correct-horse-battery-staple'} | ConvertTo-Json)

# Read
(Invoke-RestMethod -Uri https://vault.example.com/secrets/db-password -Headers $h).value
```

> **Heads-up:** in Windows PowerShell 5.x, `curl` is an alias for
> `Invoke-WebRequest` and tries to parse HTML. Use `curl.exe` to force the real
> curl binary, or just use `Invoke-RestMethod` as above.

## Secret names

Restricted to `a-z A-Z 0-9 . _ -`. Use hierarchical names with dots or dashes
to keep things organised, e.g. `prod.db-password`, `stripe.api-key`,
`github.deploy-key`.

## Behind Cloudflare

If you proxy the domain through Cloudflare (orange cloud):

1. **SSL mode** — set to **Full (strict)** in the Cloudflare dashboard
   (SSL/TLS → Overview). Caddy has a valid public cert; strict is correct.
2. **Real client IPs** — already handled. Caddy rewrites `X-Forwarded-For`
   from Cloudflare's `CF-Connecting-IP` header, so `ALLOWED_IPS` sees the
   real end-user IP instead of a CF edge IP.
3. **Origin lockdown** — strongly recommended. Restrict ports 80/443 on the
   server firewall to Cloudflare's IP ranges only, so attackers can't bypass
   CF by hitting your origin directly. The `setup-hardening.sh` script
   automates this (see below).

## Hardening

Once things are working, run:

```bash
sudo ./scripts/setup-hardening.sh
```

Cross-distro — supports **ufw**, **firewalld**, and raw **iptables**. It will:

1. **Detect your firewall** and show your existing rules.
   - **Keep** mode (default): adds Cloudflare-only allows for 80/443 without
     touching anything else.
   - **Reset** mode: flushes and rebuilds from scratch (SSH + CF-only 80/443).
     Asks twice before doing this.
   - **Skip** mode: leaves the firewall alone entirely.
2. Install a **daily backup cron** (`/etc/cron.d/vault-backup`) that tarballs
   the encrypted volume and prunes old backups.
3. Install a **weekly CF IP refresh cron** to pick up any new ranges.

Non-interactive usage (for CI / provisioning scripts):

```bash
sudo YES=1 ./scripts/setup-hardening.sh
```

Overrides:

```bash
sudo BACKUP_DIR=/mnt/storage/vault \
     BACKUP_RETENTION_DAYS=30 \
     VAULT_VOLUME=my-custom_vault-data \
     ./scripts/setup-hardening.sh
```

## Backups

The Docker volume `simple-vault_vault-data` is the only thing that matters.
Every file inside is already AES-256-GCM encrypted, so **the tarballs are safe
to store in any off-site location** (S3, B2, rclone to Dropbox, whatever) —
plaintext secrets never leave the vault process's memory.

Manual backup:

```bash
docker run --rm \
  -v simple-vault_vault-data:/data:ro \
  -v "$PWD":/backup alpine \
  tar czf /backup/vault-$(date +%F).tar.gz -C / data
```

Restore onto a new server:

```bash
# Bring up the stack so the volume exists (stack will be uninitialized)
docker compose up -d
docker compose down

# Wipe and replace the volume
docker volume rm simple-vault_vault-data
docker volume create simple-vault_vault-data
docker run --rm \
  -v simple-vault_vault-data:/data \
  -v "$PWD":/backup alpine \
  tar xzf /backup/vault-YYYY-MM-DD.tar.gz -C /

docker compose up -d
```

Your master password still unlocks the restored vault — the password derives
the decryption key via PBKDF2 with the same salts stored in the tarball.

## API reference

| Method | Path              | Auth | Body              | Notes                                 |
| ------ | ----------------- | ---- | ----------------- | ------------------------------------- |
| GET    | `/health`         | no   | —                 | Readiness / init status               |
| POST   | `/init`           | no\* | `{ "password" }`  | One-shot; 5 / 15 min rate limit       |
| POST   | `/unlock`         | no\* | `{ "password" }`  | Returns 30-min token; rate limited    |
| POST   | `/lock`           | no   | —                 | Invalidates the session token         |
| GET    | `/secrets`        | yes  | —                 | List names                            |
| POST   | `/secrets/:name`  | yes  | `{ "value" }`     | Create / overwrite                    |
| GET    | `/secrets/:name`  | yes  | —                 | Read                                  |
| DELETE | `/secrets/:name`  | yes  | —                 | Delete                                |

\* Rate-limited per IP. Authed routes require `x-vault-token: <token>`.

Password minimum length at `/init` is 8 characters — you should use at least 20.

## Configuration reference

| Variable                | Default      | Description                                           |
| ----------------------- | ------------ | ----------------------------------------------------- |
| `VAULT_DOMAIN`          | *(required)* | Domain for Caddy TLS (Let's Encrypt)                  |
| `ALLOWED_IPS`           | *(empty)*    | Comma-separated client IPs allowed (empty = any)      |
| `VAULT_DATA`            | `/data`      | Data directory inside the container                   |
| `PORT`                  | `3100`       | Internal listen port (not exposed to host)            |

## Troubleshooting

<details>
<summary><b><code>{"error":"IP not allowed"}</code> even though I added my IP</b></summary>

- `docker compose restart` does NOT reload env vars. Use
  `docker compose up -d --force-recreate vault` after editing `.env`.
- Verify the vault sees what you expect:
  `docker compose exec vault printenv ALLOWED_IPS`
- The IP must be your **public egress IP**, not a local network address.
  Run `curl ifconfig.me` on the *client* to see what the server will see.
- If you curl from the server *to itself*, the source IP becomes the Docker
  bridge gateway, not your public IP — test from a different machine.
- If behind Cloudflare, you need the `CF-Connecting-IP` header forwarding
  that's already in `Caddyfile`. Make sure your Caddyfile is up to date.
</details>

<details>
<summary><b>Let's Encrypt cert request fails</b></summary>

- DNS must resolve to your server *before* `docker compose up -d`. Check with
  `dig +short yourdomain.com`.
- Port 80 must be reachable from the internet (Let's Encrypt HTTP-01 challenge).
- If you proxy through Cloudflare, temporarily disable the orange cloud during
  the first cert acquisition, then re-enable. Or use DNS-01 challenge (not
  covered here).
</details>

<details>
<summary><b><code>{"error":"Wrong password"}</code> on unlock</b></summary>

- PowerShell: use **single quotes** around the password (`$pw = 'abc$123'`).
  Double-quoted strings expand `$variables` silently.
- cmd.exe: watch out for `^`, `%`, `"`, `!`, `&` in passwords — they're
  shell-special.
- If you've exhausted rate limit (5/15min), either wait or recycle the vault
  container: `docker compose restart vault` clears the in-memory counter.
- Truly forgot the password? No recovery. Wipe and start over:
  `docker compose down && docker volume rm simple-vault_vault-data && docker compose up -d`.
</details>

<details>
<summary><b>Environment change in <code>.env</code> isn't taking effect</b></summary>

`docker compose restart` reuses the existing container config. Force a
recreate:

```bash
docker compose up -d --force-recreate <service>
```

For `.env` changes that affect both services, omit the service name.
</details>

## Security notes & caveats

- **Hobby-grade.** Uses PBKDF2, not Argon2id. Single-node, no replication,
  no audit log, no secret rotation, no granular ACLs — one password unlocks
  everything.
- **Memory-only sessions.** Restarting the vault container invalidates every
  active token. This is a feature, not a bug — it cleanly closes sessions on
  host reboot.
- **No out-of-the-box key rotation.** To rotate the master password you'd
  need to script read-all-with-old-password → re-encrypt-with-new. Not
  currently included.
- **Rate limit counter is in-memory.** A restart resets it. That's fine for
  most threat models but means a determined attacker who can force restarts
  has unlimited tries.
- **For production workloads**, use
  [HashiCorp Vault](https://www.vaultproject.io/),
  [Bitwarden Secrets Manager](https://bitwarden.com/products/secrets-manager/),
  or [Infisical](https://infisical.com/) instead.

## Repo layout

```
.
├── Caddyfile                      Caddy reverse-proxy config + CF header handling
├── docker-compose.yml             Two-container stack (vault + caddy)
├── Dockerfile                     node:20-alpine build for the vault
├── .env.example                   Template for VAULT_DOMAIN + ALLOWED_IPS
├── package.json                   Single dependency: express
├── server.js                      The entire vault — ~220 lines
└── scripts/
    └── setup-hardening.sh         Firewall + backup + CF-refresh automation
```

## Contributing

Issues and PRs welcome. The entire app is one file — if you can make it
smaller, that's probably an improvement. Please keep:

- No external dependencies beyond Express and Node stdlib
- Zero-config defaults that work end-to-end
- Single-binary deploy story (Docker image stays tiny)

## License

Unlicensed unless noted — add a `LICENSE` file before relying on this for
anything important.
