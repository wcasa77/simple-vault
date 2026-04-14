#!/usr/bin/env bash
# setup-hardening.sh — one-shot hardening for a simple-vault deployment.
#
# What this does (all idempotent — safe to re-run):
#   1. Restricts ports 80/443 in ufw to Cloudflare's published IP ranges,
#      so attackers can't bypass Cloudflare to hit the origin directly.
#   2. Installs a daily cron that backs up the encrypted vault volume
#      and prunes backups older than 14 days.
#   3. Installs a weekly cron that re-syncs Cloudflare's IP list in case
#      CF adds new ranges.
#
# Usage (run from the repo root on the server):
#   sudo ./scripts/setup-hardening.sh
#
# Environment overrides:
#   VAULT_VOLUME            (default: <cwd-basename>_vault-data)
#   BACKUP_DIR              (default: /var/backups/vault)
#   BACKUP_RETENTION_DAYS   (default: 14)

set -euo pipefail

if [[ $EUID -ne 0 ]]; then
  echo "must run as root (sudo $0)" >&2
  exit 1
fi

command -v docker >/dev/null || { echo "docker not installed" >&2; exit 1; }

VAULT_VOLUME="${VAULT_VOLUME:-$(basename "$(pwd)")_vault-data}"
BACKUP_DIR="${BACKUP_DIR:-/var/backups/vault}"
BACKUP_RETENTION_DAYS="${BACKUP_RETENTION_DAYS:-14}"

if ! docker volume inspect "$VAULT_VOLUME" >/dev/null 2>&1; then
  echo "docker volume '$VAULT_VOLUME' not found." >&2
  echo "Start the stack first: docker compose up -d" >&2
  echo "Or override with:     VAULT_VOLUME=<name> sudo $0" >&2
  exit 1
fi

echo "==> volume:     $VAULT_VOLUME"
echo "==> backup dir: $BACKUP_DIR"
echo "==> retention:  $BACKUP_RETENTION_DAYS days"
echo

# -------------------------------------------------------------------
# 1. Firewall: ufw allowing SSH + Cloudflare-only on 80/443
# -------------------------------------------------------------------
echo "==> [1/3] Firewall"

if ! command -v ufw >/dev/null; then
  echo "  installing ufw..."
  apt-get update -qq
  apt-get install -y -qq ufw
fi

# Allow SSH first so we don't lock ourselves out on enable.
ufw allow OpenSSH >/dev/null

# Strip any existing 'allow from anywhere' rules on 80/443 so we don't
# leave the origin wide-open. Each delete is safe to fail.
for rule in 'allow 80/tcp' 'allow 443/tcp' 'allow 80' 'allow 443' 'allow http' 'allow https'; do
  ufw delete $rule 2>/dev/null || true
done

echo "  fetching Cloudflare IP ranges..."
CF_V4=$(curl -fsSL https://www.cloudflare.com/ips-v4)
CF_V6=$(curl -fsSL https://www.cloudflare.com/ips-v6)
CF_COUNT=$(echo "$CF_V4 $CF_V6" | wc -w)
echo "  adding $CF_COUNT CF ranges (80 + 443)..."
for ip in $CF_V4 $CF_V6; do
  ufw allow from "$ip" to any port 80 proto tcp >/dev/null
  ufw allow from "$ip" to any port 443 proto tcp >/dev/null
done

ufw --force enable >/dev/null
echo "  ufw enabled"
echo

# -------------------------------------------------------------------
# 2. Daily backup cron
# -------------------------------------------------------------------
echo "==> [2/3] Daily backup cron"

mkdir -p "$BACKUP_DIR"

cat > /etc/cron.daily/vault-backup <<EOF
#!/bin/sh
# Daily backup of the simple-vault encrypted volume.
# Files inside are already AES-256-GCM encrypted, so the tarball is
# safe to store off-site without leaking plaintext secrets.
set -e
docker run --rm \\
  -v $VAULT_VOLUME:/data:ro \\
  -v $BACKUP_DIR:/backup alpine \\
  tar czf /backup/vault-\$(date +%F).tar.gz -C / data
find $BACKUP_DIR -name 'vault-*.tar.gz' -mtime +$BACKUP_RETENTION_DAYS -delete
EOF
chmod +x /etc/cron.daily/vault-backup

echo "  running once to verify..."
/etc/cron.daily/vault-backup
echo "  backup produced:"
ls -lh "$BACKUP_DIR" | tail -n +2 | sed 's/^/    /'
echo

# -------------------------------------------------------------------
# 3. Weekly Cloudflare IP refresh cron
# -------------------------------------------------------------------
echo "==> [3/3] Weekly CF IP refresh cron"

cat > /etc/cron.weekly/vault-cf-refresh <<'EOF'
#!/bin/bash
# Pick up any new Cloudflare IP ranges.
# Stale ranges remain allowed (CF rarely removes ranges); re-run
# setup-hardening.sh manually if you want a clean rebuild.
set -e
CF_V4=$(curl -fsSL https://www.cloudflare.com/ips-v4) || exit 0
CF_V6=$(curl -fsSL https://www.cloudflare.com/ips-v6) || exit 0
for ip in $CF_V4 $CF_V6; do
  ufw allow from "$ip" to any port 80 proto tcp >/dev/null 2>&1 || true
  ufw allow from "$ip" to any port 443 proto tcp >/dev/null 2>&1 || true
done
EOF
chmod +x /etc/cron.weekly/vault-cf-refresh
echo "  installed /etc/cron.weekly/vault-cf-refresh"
echo

# -------------------------------------------------------------------
# Summary
# -------------------------------------------------------------------
echo "==> Done."
echo
ufw status | head -8
echo
echo "Next steps:"
echo "  * Copy backups off-box periodically (scp / rclone / aws s3 sync)"
echo "  * Set Cloudflare SSL mode to 'Full (strict)' in the CF dashboard"
echo "  * Verify origin is locked down: from a non-CF IP,"
echo "      curl --max-time 5 https://<server-ip>/   # should hang or fail"
