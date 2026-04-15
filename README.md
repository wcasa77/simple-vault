# Simple Vault

A minimal self-hosted secrets manager. Single-file Node.js app with AES-256-GCM
encryption, fronted by Caddy for automatic HTTPS.

Designed for small teams or personal use — not a replacement for HashiCorp Vault
or Bitwarden. Think "password-protected encrypted blob store you can `curl`."

## Features

- **Web UI** at `/ui/` — signup wizard, login, dashboard, per-secret detail
  view, settings page, and a one-click **AI prompt helper** that builds a
  paste-ready block for Claude / ChatGPT / Cursor etc.
- **2FA (TOTP)** — optional time-based codes on top of the master password.
  Set up during signup or later from Settings. Works with any standard
  authenticator app (Google Authenticator, Authy, 1Password, etc.).
- **One-time share links** — generate a URL (with TTL and view-count limit)
  that anyone can open without a vault login. Stored in memory only, gone
  on restart.
- **Per-secret notes** — attach free-form context to each secret (target
  hostname, username, usage hints). The notes are encrypted alongside the
  value and are what the AI-prompt helper pastes as instructions to the LLM.
- **AES-256-GCM** encryption with **PBKDF2** key derivation (100k iterations, SHA-512)
- Password-based master key — the password itself is never stored, only a
  `vault-ok` canary encrypted with it, used to verify unlock attempts
- 30-minute session tokens, auto-extended on activity
- In-memory rate limiting: 5 `/init` + `/unlock` attempts per IP per 15 min
- Optional IP allowlist (works correctly behind Cloudflare via `CF-Connecting-IP`)
- Fully Dockerized; Caddy handles Let's Encrypt certificates automatically
- Small surface area: single Node.js file + a dependency-free static UI,
  no database

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

Two equivalent ways:

**Option A — Web UI (recommended for humans).** Open
`https://vault.example.com/` in a browser and follow the signup wizard.
It walks you through:

1. Setting the master password.
2. *(optional)* Scanning a QR code to enable TOTP-based 2FA.
3. Dropping straight into the dashboard where you can add, view, share,
   and copy-to-AI-chat your secrets.

**Option B — curl (for scripts / headless setup).**

```bash
curl -X POST https://vault.example.com/init \
  -H 'Content-Type: application/json' \
  -d '{"password":"YOUR-LONG-RANDOM-MASTER-PASSWORD"}'
# {"message":"Vault initialized"}
```

Either way, the vault is ready after this step. 2FA set via the UI can
be disabled again from Settings; you can always fall back to API-only
access if you prefer.

## Web UI

The web UI lives at `https://vault.example.com/ui/` (the root `/` redirects
there). It's a single static page served by the vault container — no build
step, no external CDN. Everything you can do via the API you can do here,
plus:

- **Dashboard with search** across all secret names.
- **Per-secret detail view** with show/hide on the value, editable notes,
  a delete button, and a **"Copy AI prompt"** button.
- **Share modal**: pick a TTL (1 h – 7 d) and max views (1 – 100), then
  copy the generated URL. The recipient opens it in a browser and gets a
  dark-themed page with the value, the notes, and a copy button. Once the
  views run out (or the expiry passes, or the vault restarts) the link is
  gone.
- **Generate SSH keypair** button on the new-secret form: the vault
  creates an ed25519 keypair server-side (pure Node, OpenSSH format), pre-
  fills the Value field with the base64-encoded private key, prepends the
  public key to Notes along with the SSH-key template, and shows the
  public key in a copy-ready panel with a one-liner to append it to
  `~/.ssh/authorized_keys`. The vault never persists the keypair — it only
  lives in your browser until you hit Save.
- **Settings → 2FA** to enable or disable TOTP, and a **current session
  token** display with a copy button so you can paste it straight into a
  shell or an AI agent.

### AI prompt helper

Open any secret → pick one of the two **Copy AI prompt** buttons → paste
into your AI chat.

**Safe mode (default, recommended for SSH keys and anything sensitive).**
The prompt gives the AI the vault URL, a short-lived session token, the
*name* and *notes* of the secret, and Bash + PowerShell recipes — but
**not the value**. The agent fetches the value itself via `curl` inside a
subprocess and pipes it straight into `ssh` / `base64 -d` / `psql` /
whatever, so the plaintext never appears in the chat text (and therefore
never hits the AI provider's logs or training data).

```
I'm using Simple Vault (a self-hosted secrets manager) with a shell-capable AI
(Claude Code / Cursor / Aider / etc.). I am giving you a short-lived session TOKEN
so you can fetch the secret yourself — the VALUE is intentionally NOT in this chat,
so it doesn't land in the AI provider's logs.

=== Vault Connection ===
URL:         https://vault.example.com
Session token (30-min TTL, auto-extends on activity):
  <SESSION_TOKEN>

=== What I want you to do ===
Use the secret named: ssh.staging.id_ed25519
Notes:
  SSH private key (base64-encoded)
  Host: 203.0.113.10
  User: administrator
  Port: 22

=== Security rules — please follow strictly ===
- DO NOT print, echo, cat, or log the secret value anywhere in your replies.
- Fetch it INSIDE a command pipeline so the value stays in subprocess
  stdin/stdout and never ends up in the chat text.
...

=== Recipes ===
# Bash — SSH private key stored base64-encoded
TOKEN='<TOKEN>'; URL='https://vault.example.com'; NAME='ssh.staging.id_ed25519'
curl -s "$URL/secrets/$NAME" -H "x-vault-token: $TOKEN" \
  | jq -r .value | base64 -d > /tmp/svkey && chmod 600 /tmp/svkey
ssh -i /tmp/svkey -o IdentitiesOnly=yes <USER>@<HOST>   # USER/HOST from Notes
shred -u /tmp/svkey 2>/dev/null || rm -f /tmp/svkey

# PowerShell — SSH private key stored base64-encoded
$h = @{"x-vault-token"='<TOKEN>'}
$v = (Invoke-RestMethod -Uri 'https://vault.example.com/secrets/ssh.staging.id_ed25519' -Headers $h).value
$key = Join-Path $env:TEMP 'svkey'
[IO.File]::WriteAllBytes($key, [Convert]::FromBase64String($v))
icacls $key /inheritance:r /grant:r "$($env:USERNAME):R" | Out-Null
ssh -i $key -o IdentitiesOnly=yes <USER>@<HOST>
Remove-Item $key -Force
...
```

That's enough for an agent to go straight to `ssh administrator@203.0.113.10`
on the first try — no "try ubuntu, try root, try redis" guessing loop — as
long as you've filled in the **Notes** field. The detail view shows a
warning when notes are empty and offers one-click templates (**SSH key**,
**SSH pw**, **DB**, **API token**, **Cert**) that drop a structured
skeleton into the textarea for you to edit.

**Inline value mode.** A second button, `with value`, includes the raw
value in the prompt. It's quicker for non-sensitive material (a throwaway
demo API key, config snippets) but the value lands in the AI provider's
chat history. The UI pops a confirmation dialog before copying.

> TL;DR: always paste the **safe** variant for SSH keys, certs, database
> passwords, long-lived API tokens. Save the **inline** variant for
> genuinely low-stakes values where convenience matters.

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

## Storing file contents (SSH keys, certificates, PEM files)

The `value` field must be a JSON **string**. Plain text (passwords, API keys,
single-line tokens) works directly. For **anything with newlines, binary bytes,
or shell-special characters** — SSH private keys, TLS certs, `.pfx` bundles,
GPG keys, service-account JSONs — wrap the bytes in base64 first.

Why: some clients (notably Windows PowerShell's `ConvertTo-Json` with
multi-line strings) silently serialise the value as an object, which the
server will reject. Base64 is a single-line ASCII string — no ambiguity, no
encoding drift, byte-exact round-trip.

### Bash / Linux / macOS / WSL

```bash
# Store
B64=$(base64 -w0 ~/.ssh/id_ed25519)
curl -X POST https://vault.example.com/secrets/ssh.myhost.id_ed25519 \
  -H "x-vault-token: $TOKEN" -H 'Content-Type: application/json' \
  -d "{\"value\":\"$B64\"}"

# Restore
curl -s https://vault.example.com/secrets/ssh.myhost.id_ed25519 \
  -H "x-vault-token: $TOKEN" \
  | jq -r .value | base64 -d > ~/.ssh/id_ed25519
chmod 600 ~/.ssh/id_ed25519
ssh-keygen -lf ~/.ssh/id_ed25519       # fingerprint sanity check
```

### Windows PowerShell

```powershell
# Store
$b64 = [Convert]::ToBase64String([System.IO.File]::ReadAllBytes("$HOME\.ssh\id_ed25519"))
Invoke-RestMethod -Method Post -Uri https://vault.example.com/secrets/ssh.myhost.id_ed25519 `
  -Headers $h -ContentType 'application/json' `
  -Body (@{value=$b64} | ConvertTo-Json)

# Restore
$b64 = (Invoke-RestMethod -Uri https://vault.example.com/secrets/ssh.myhost.id_ed25519 -Headers $h).value
[System.IO.File]::WriteAllBytes("$HOME\.ssh\id_ed25519", [Convert]::FromBase64String($b64))
icacls $HOME\.ssh\id_ed25519 /inheritance:r /grant:r "${env:USERNAME}:(R,W)" | Out-Null
ssh-keygen -lf $HOME\.ssh\id_ed25519   # fingerprint sanity check
```

### Verifying byte-exact round-trip

After storing, fetch and decode, then compare to the original. If the
fingerprints match, the round-trip is byte-perfect:

```bash
ssh-keygen -lf ~/.ssh/id_ed25519                            # original
curl -s https://vault.example.com/secrets/ssh.myhost.id_ed25519 \
  -H "x-vault-token: $TOKEN" | jq -r .value | base64 -d \
  | ssh-keygen -lf /dev/stdin                               # from vault
```

## Using with AI agents, CI jobs, and scripts

Core idea: **API keys live in the vault, and short-lived processes fetch them
at runtime.** No plaintext `.env` files on laptops, no keys pasted into AI
chat windows, no secrets committed by accident.

Three integration levels — pick whichever matches your threat model.

### Level 1 — Paste a session token into the agent

Simplest. You unlock the vault, paste the token into your AI chat (Claude
Code, Cursor, Aider, plain ChatGPT with shell tools, etc.), and the agent
uses it via `curl` for the session.

```
You:   My vault token is a66abe62...
You:   Fetch the github-pat secret and clone repo X
Agent: [runs curl with the token, uses the value in subsequent commands]
```

**Tradeoffs:**
- The token lives in the chat's history for its 30-minute TTL (auto-extends
  on activity). If you export/share that chat while the token is still valid,
  that's a compromise.
- The agent has access to **every** secret for the session, not just the one
  you asked about.
- Always `/lock` when done.

Fine for a one-shot task in a chat you won't share. Don't use for routine work.

### Level 2 — Shell wrapper functions (recommended)

Secrets are fetched *inside a subprocess* and never appear in the chat.
One password prompt per 30-min session covers any number of fetches.

**Bash** — add to `~/.bashrc`:

```bash
vault_unlock() {
  read -rsp "Vault password: " pw; echo
  export VAULT_TOKEN=$(curl -s -X POST https://vault.example.com/unlock \
    -H 'Content-Type: application/json' \
    -d "{\"password\":\"$pw\"}" | jq -r .token)
  unset pw
  [ -n "$VAULT_TOKEN" ] && [ "$VAULT_TOKEN" != "null" ] \
    && echo "Unlocked" || { echo "Failed"; unset VAULT_TOKEN; }
}

vault_get() {
  curl -s "https://vault.example.com/secrets/$1" \
    -H "x-vault-token: $VAULT_TOKEN" | jq -r .value
}

# Run a command with a secret injected as an env var.
# Example: vault_run github-pat gh issue list
#   -> GITHUB_PAT=<fetched> gh issue list
vault_run() {
  local name=$1; shift
  local var
  var=$(echo "$name" | tr 'a-z.-' 'A-Z__')
  env "$var=$(vault_get "$name")" "$@"
}

vault_lock() {
  curl -s -X POST https://vault.example.com/lock \
    -H "x-vault-token: $VAULT_TOKEN" >/dev/null
  unset VAULT_TOKEN
}
```

Usage:
```bash
vault_unlock                        # one prompt
claude                              # or cursor / aider / your AI CLI
# ...then inside the agent's shell:
vault_run github-pat bash -c 'git clone https://$GITHUB_PAT@github.com/user/repo'
# Token stays in the parent shell; secret value exists only inside that bash -c
```

**PowerShell** — add to `$PROFILE`:

```powershell
function Vault-Unlock {
    $pw = Read-Host "Vault password" -AsSecureString
    $plain = [System.Net.NetworkCredential]::new('', $pw).Password
    $global:VAULT_TOKEN = (Invoke-RestMethod -Method Post `
        -Uri https://vault.example.com/unlock `
        -ContentType 'application/json' `
        -Body (@{password=$plain} | ConvertTo-Json)).token
    $plain = $null
    if ($global:VAULT_TOKEN) { "Unlocked" } else { "Failed" }
}

function Vault-Get ($name) {
    (Invoke-RestMethod -Uri "https://vault.example.com/secrets/$name" `
        -Headers @{"x-vault-token"=$global:VAULT_TOKEN}).value
}

function Vault-Lock {
    Invoke-RestMethod -Method Post -Uri https://vault.example.com/lock `
        -Headers @{"x-vault-token"=$global:VAULT_TOKEN} | Out-Null
    $global:VAULT_TOKEN = $null
}
```

Usage:
```powershell
Vault-Unlock
$env:ANTHROPIC_API_KEY = Vault-Get 'anthropic.api-key'
claude                              # launches with the key in its env
Vault-Lock                          # when done
```

### Level 3 — MCP server (tightest, per-secret approval)

For MCP-compatible hosts (Claude Code, Cursor, etc.), wrap the vault as an
MCP server so each secret read becomes an explicit tool call the user
approves in the UI. Sketch:

```js
// vault-mcp.js — register in ~/.claude.json under "mcpServers"
// Expects env: VAULT_URL, VAULT_TOKEN (from Level 2's vault_unlock)
// Implements tools: vault.list, vault.get <name>
// See https://modelcontextprotocol.io/ for the full stdio protocol.
```

Tradeoffs vs. Level 2:
- **Pro:** every fetch surfaces as an approval prompt with a visible audit log
- **Con:** ~50 LoC of Node + MCP registration; still needs a token from
  Level 2's `vault_unlock` to authenticate to the vault

An out-of-the-box MCP server isn't bundled with this repo yet — PRs welcome.

### Common anti-patterns

| Don't | Why |
|-------|-----|
| Paste secret **values** into the AI chat | Ends up in context window, logs, exports |
| Store the master password *in the vault* | Circular; doesn't protect anything |
| Write `$VAULT_TOKEN` to disk | Persists past session TTL; defeats the 30-min design |
| Use one vault across unrelated projects | Blast radius of a single leak is "everything" |
| Let the agent call `/init` | Idempotent = no; re-init on an initialised vault fails, but if the volume's empty the agent could initialise it with a password only the agent knows |

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

| Method | Path                      | Auth | Body                                                        | Notes                                                    |
| ------ | ------------------------- | ---- | ----------------------------------------------------------- | -------------------------------------------------------- |
| GET    | `/health`                 | no   | —                                                           | Readiness, init status, `totp` flag, vault name          |
| POST   | `/init`                   | no\* | `{ "password" }`                                            | One-shot; 5 / 15 min rate limit                          |
| POST   | `/unlock`                 | no\* | `{ "password", "totp"? }`                                   | Returns 30-min token; `totp` required if 2FA enabled     |
| POST   | `/lock`                   | no   | —                                                           | Invalidates the session token                            |
| GET    | `/info`                   | yes  | —                                                           | Vault URL / name / description (for AI-prompt helper)    |
| GET    | `/secrets`                | yes  | —                                                           | List names                                               |
| POST   | `/secrets/:name`          | yes  | `{ "value", "notes"? }`                                     | Create / overwrite; `notes` is optional free-form text   |
| GET    | `/secrets/:name`          | yes  | —                                                           | Read; returns `{ name, value, notes }`                   |
| DELETE | `/secrets/:name`          | yes  | —                                                           | Delete                                                   |
| POST   | `/secrets/:name/share`    | yes  | `{ "ttl_seconds"?, "max_views"?, "include_notes"? }`        | Create one-time share link (in-memory, non-persistent)   |
| GET    | `/shared/:token`          | no   | —                                                           | Retrieve share; HTML by default, JSON on `Accept: application/json`. Consumes one view. |
| POST   | `/2fa/setup`              | yes  | `{ "label"? }`                                              | Generate pending TOTP secret; returns base32 + QR data-URL |
| POST   | `/2fa/confirm`            | yes  | `{ "totp" }`                                                | Activate 2FA after scanning the QR                       |
| POST   | `/2fa/disable`            | yes  | `{ "totp" }`                                                | Disable 2FA (requires a valid current code)              |
| POST   | `/keygen`                 | yes  | `{ "type"?, "comment"? }`                                   | Generate ed25519 SSH keypair server-side. Returns public line + OpenSSH PEM + base64. **Stateless** — vault does NOT persist the output. |
| GET    | `/ui/`                    | no   | —                                                           | Static web UI (SPA)                                      |

\* Rate-limited per IP. Authed routes require `x-vault-token: <token>`.

Password minimum length at `/init` is 8 characters — you should use at least 20.

### Share-link options

`POST /secrets/:name/share` body fields, all optional:

| Field             | Default | Max      | Meaning                                                |
| ----------------- | ------- | -------- | ------------------------------------------------------ |
| `ttl_seconds`     | 86400   | 604800   | How long the share stays valid (1 day default, 7 d max) |
| `max_views`       | 1       | 100      | How many times the URL can be opened before it expires  |
| `include_notes`   | `true`  | —        | If `false`, the notes field is omitted from the share   |

Shares are stored **in memory only**. A vault container restart invalidates
every active share.

## Configuration reference

| Variable                | Default         | Description                                                          |
| ----------------------- | --------------- | -------------------------------------------------------------------- |
| `VAULT_DOMAIN`          | *(required)*    | Domain for Caddy TLS (Let's Encrypt)                                 |
| `ALLOWED_IPS`           | *(empty)*       | Comma-separated client IPs allowed (empty = any)                     |
| `VAULT_NAME`            | `Simple Vault`  | Display name in the web UI and TOTP authenticator app                |
| `VAULT_DESCRIPTION`     | *(empty)*       | Free-form text pasted into the AI-prompt helper as `Environment: …`  |
| `VAULT_DATA`            | `/data`         | Data directory inside the container                                  |
| `PORT`                  | `3100`          | Internal listen port (not exposed to host)                           |

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
- **2FA is optional but recommended.** When enabled, the TOTP secret is
  encrypted with the master password (same envelope scheme as the `vault-ok`
  canary) and stored in `vault.json`. A wrong password means TOTP never
  decrypts, so 2FA cannot be bypassed by tampering with the meta file.
- **Memory-only sessions and shares.** Restarting the vault container
  invalidates every active token *and every outstanding share link*. This
  is a feature, not a bug — it cleanly closes all remote access on host
  reboot.
- **Share links contain plaintext in server memory** until they expire,
  are consumed, or the process exits. That's a deliberate trade-off for
  the "open in any browser, no login needed" UX — if you need
  end-to-end-only sharing, fall back to passing the value out of band and
  skip the share feature.
- **No out-of-the-box master-password rotation.** To rotate, script
  read-all-with-old-password → re-encrypt-with-new → swap the `verify` and
  `totp` envelopes. Not currently included.
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
├── .env.example                   Template for VAULT_DOMAIN / ALLOWED_IPS / VAULT_NAME / VAULT_DESCRIPTION
├── package.json                   Dependencies: express + qrcode
├── server.js                      The entire vault API + TOTP + shares (single file)
├── public/                        Zero-build static web UI
│   ├── index.html
│   ├── styles.css
│   └── app.js
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
