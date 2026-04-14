#!/usr/bin/env bash
# setup-hardening.sh — one-shot hardening for a simple-vault deployment.
#
# Cross-distro: supports ufw (Debian/Ubuntu), firewalld (RHEL family),
# and raw iptables (fallback). Installs cron jobs in /etc/cron.d which
# works on any system running cron / cronie.
#
# What it does:
#   1. Restricts ports 80/443 to Cloudflare's published IP ranges so
#      attackers can't bypass CF to hit the origin directly.
#   2. Schedules a daily backup of the encrypted vault volume, keeping
#      the last $BACKUP_RETENTION_DAYS tarballs.
#   3. Schedules a weekly refresh of CF's IP list.
#
# Interactive by default — asks before touching your firewall rules.
# For automation, set YES=1 in the environment to auto-confirm everything.
#
# Usage:
#   sudo ./scripts/setup-hardening.sh
#   sudo YES=1 ./scripts/setup-hardening.sh        # non-interactive
#   sudo VAULT_VOLUME=my_vault-data ./scripts/setup-hardening.sh
#
# Environment:
#   VAULT_VOLUME             docker volume to back up
#                            (default: <cwd-basename>_vault-data)
#   BACKUP_DIR               where to write tarballs
#                            (default: /var/backups/vault)
#   BACKUP_RETENTION_DAYS    prune tarballs older than this
#                            (default: 14)
#   YES=1                    skip all confirmation prompts
#
# This script is idempotent — re-running it is safe.

set -euo pipefail

# ------------------------------------------------------------------
# Config
# ------------------------------------------------------------------
VAULT_VOLUME="${VAULT_VOLUME:-$(basename "$(pwd)")_vault-data}"
BACKUP_DIR="${BACKUP_DIR:-/var/backups/vault}"
BACKUP_RETENTION_DAYS="${BACKUP_RETENTION_DAYS:-14}"
CF_IPV4_URL="https://www.cloudflare.com/ips-v4"
CF_IPV6_URL="https://www.cloudflare.com/ips-v6"
AUTO_YES="${YES:-0}"

# ------------------------------------------------------------------
# Helpers
# ------------------------------------------------------------------
if [[ -t 1 ]]; then
  bold()   { printf '\033[1m%s\033[0m\n' "$*"; }
  red()    { printf '\033[31m%s\033[0m\n' "$*"; }
  green()  { printf '\033[32m%s\033[0m\n' "$*"; }
  yellow() { printf '\033[33m%s\033[0m\n' "$*"; }
else
  bold() { echo "$*"; }; red() { echo "$*"; }; green() { echo "$*"; }; yellow() { echo "$*"; }
fi

die() { red "ERROR: $*" >&2; exit 1; }

confirm() {
  local prompt="$1" default="${2:-N}" hint="[y/N]" yn
  [[ "$default" = "Y" ]] && hint="[Y/n]"
  if [[ "$AUTO_YES" = "1" ]]; then
    echo "$prompt $hint  (auto-yes)"
    return 0
  fi
  read -rp "$prompt $hint " yn
  yn="${yn:-$default}"
  [[ "$yn" =~ ^[Yy] ]]
}

pkg_install() {
  local pkg="$1"
  if   command -v apt-get >/dev/null; then apt-get update -qq && apt-get install -y -qq "$pkg"
  elif command -v dnf     >/dev/null; then dnf install -y "$pkg"
  elif command -v yum     >/dev/null; then yum install -y "$pkg"
  elif command -v zypper  >/dev/null; then zypper install -y "$pkg"
  elif command -v pacman  >/dev/null; then pacman -Sy --noconfirm "$pkg"
  elif command -v apk     >/dev/null; then apk add --no-cache "$pkg"
  else return 1
  fi
}

# ------------------------------------------------------------------
# Preflight
# ------------------------------------------------------------------
[[ $EUID -eq 0 ]] || die "must run as root (sudo $0)"
command -v docker >/dev/null || die "docker is required"
command -v curl   >/dev/null || die "curl is required"

if ! docker volume inspect "$VAULT_VOLUME" >/dev/null 2>&1; then
  die "docker volume '$VAULT_VOLUME' not found.
  Start the stack first:     docker compose up -d
  Or override the volume:    VAULT_VOLUME=<name> sudo $0"
fi

bold "simple-vault hardening"
cat <<EOF
  volume:      $VAULT_VOLUME
  backup dir:  $BACKUP_DIR
  retention:   $BACKUP_RETENTION_DAYS days
  mode:        $( [[ "$AUTO_YES" = "1" ]] && echo "non-interactive (YES=1)" || echo "interactive" )

EOF

# ==================================================================
# 1. Firewall
# ==================================================================
bold "[1/3] Firewall"

# Detect available backend
FW=""
if   command -v ufw          >/dev/null; then FW="ufw"
elif command -v firewall-cmd >/dev/null; then FW="firewalld"
elif command -v iptables     >/dev/null; then FW="iptables"
fi

if [[ -z "$FW" ]]; then
  yellow "No firewall detected (ufw, firewalld, or iptables)."
  if confirm "Install ufw now?" Y; then
    pkg_install ufw || die "package manager not recognised — install ufw manually"
    FW="ufw"
  else
    yellow "Skipping firewall step. Configure manually later."
    FW="skip"
  fi
fi

echo "  backend: $FW"

if [[ "$FW" != "skip" ]]; then
  echo
  echo "  --- current rules ---"
  case "$FW" in
    ufw)       ufw status numbered 2>/dev/null || echo "  (ufw inactive)" ;;
    firewalld) firewall-cmd --list-all 2>/dev/null || echo "  (firewalld not running)" ;;
    iptables)  iptables -L INPUT -n --line-numbers ;;
  esac | sed 's/^/  /'
  echo "  ----------------------"
  echo

  echo "  Two ways to apply the CF allowlist:"
  echo "    (K) KEEP existing rules, add CF-only 80/443 on top   [safe, recommended]"
  echo "    (R) RESET all rules, rebuild from scratch (SSH + CF) [destructive]"
  echo "    (S) SKIP — leave firewall alone"
  echo

  CHOICE=""
  if [[ "$AUTO_YES" = "1" ]]; then
    CHOICE="K"
    echo "  auto-yes: choosing K"
  else
    while [[ ! "$CHOICE" =~ ^[KkRrSs]$ ]]; do
      read -rp "  Choice [K/R/S] (default K): " CHOICE
      CHOICE="${CHOICE:-K}"
    done
  fi

  case "${CHOICE^^}" in
    S) yellow "  skipping firewall changes"; FW_MODE="skip" ;;
    K) FW_MODE="keep" ;;
    R)
      red "  RESET will FLUSH ALL EXISTING FIREWALL RULES."
      if confirm "  Are you absolutely sure?" N; then FW_MODE="reset"
      else yellow "  aborting reset, falling back to keep mode"; FW_MODE="keep"
      fi ;;
  esac

  if [[ "$FW_MODE" != "skip" ]]; then
    echo "  fetching Cloudflare IP ranges..."
    CF_V4=$(curl -fsSL "$CF_IPV4_URL") || die "failed to fetch $CF_IPV4_URL"
    CF_V6=$(curl -fsSL "$CF_IPV6_URL") || die "failed to fetch $CF_IPV6_URL"
    CF_COUNT=$(echo "$CF_V4 $CF_V6" | wc -w)
    echo "  got $CF_COUNT CF ranges"

    case "$FW" in
      # ------- ufw -----------------------------------------------
      ufw)
        if [[ "$FW_MODE" = "reset" ]]; then
          ufw --force reset >/dev/null
          ufw default deny incoming  >/dev/null
          ufw default allow outgoing >/dev/null
          ufw allow OpenSSH >/dev/null
        else
          # Make sure SSH stays allowed; strip any open 80/443
          ufw allow OpenSSH >/dev/null
          for rule in 'allow 80/tcp' 'allow 443/tcp' 'allow 80' 'allow 443' \
                      'allow http' 'allow https'; do
            ufw delete $rule 2>/dev/null || true
          done
        fi
        for ip in $CF_V4 $CF_V6; do
          ufw allow from "$ip" to any port 80  proto tcp >/dev/null
          ufw allow from "$ip" to any port 443 proto tcp >/dev/null
        done
        ufw --force enable >/dev/null
        ;;

      # ------- firewalld -----------------------------------------
      firewalld)
        if [[ "$FW_MODE" = "reset" ]]; then
          # Clear rules in the default (public) zone
          firewall-cmd --permanent --zone=public --set-target=default >/dev/null || true
          for svc in http https; do
            firewall-cmd --permanent --zone=public --remove-service=$svc 2>/dev/null || true
          done
          # Re-assert SSH
          firewall-cmd --permanent --zone=public --add-service=ssh >/dev/null || true
        else
          firewall-cmd --permanent --zone=public --remove-service=http  2>/dev/null || true
          firewall-cmd --permanent --zone=public --remove-service=https 2>/dev/null || true
        fi
        for ip in $CF_V4; do
          firewall-cmd --permanent --zone=public \
            --add-rich-rule="rule family=ipv4 source address=\"$ip\" port port=80  protocol=tcp accept" \
            >/dev/null 2>&1 || true
          firewall-cmd --permanent --zone=public \
            --add-rich-rule="rule family=ipv4 source address=\"$ip\" port port=443 protocol=tcp accept" \
            >/dev/null 2>&1 || true
        done
        for ip in $CF_V6; do
          firewall-cmd --permanent --zone=public \
            --add-rich-rule="rule family=ipv6 source address=\"$ip\" port port=80  protocol=tcp accept" \
            >/dev/null 2>&1 || true
          firewall-cmd --permanent --zone=public \
            --add-rich-rule="rule family=ipv6 source address=\"$ip\" port port=443 protocol=tcp accept" \
            >/dev/null 2>&1 || true
        done
        firewall-cmd --reload >/dev/null
        ;;

      # ------- iptables (bare) -----------------------------------
      iptables)
        if [[ "$FW_MODE" = "reset" ]]; then
          iptables -F INPUT
          iptables -P INPUT DROP
          iptables -A INPUT -i lo -j ACCEPT
          iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
          iptables -A INPUT -p tcp --dport 22 -j ACCEPT
          if command -v ip6tables >/dev/null; then
            ip6tables -F INPUT
            ip6tables -P INPUT DROP
            ip6tables -A INPUT -i lo -j ACCEPT
            ip6tables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
            ip6tables -A INPUT -p tcp --dport 22 -j ACCEPT
          fi
        else
          # Drop any wide-open accept on 80/443
          while iptables -C INPUT -p tcp --dport 80  -j ACCEPT 2>/dev/null; do
            iptables -D INPUT -p tcp --dport 80  -j ACCEPT; done
          while iptables -C INPUT -p tcp --dport 443 -j ACCEPT 2>/dev/null; do
            iptables -D INPUT -p tcp --dport 443 -j ACCEPT; done
        fi
        for ip in $CF_V4; do
          iptables -C INPUT -s "$ip" -p tcp --dport 80  -j ACCEPT 2>/dev/null \
            || iptables -A INPUT -s "$ip" -p tcp --dport 80  -j ACCEPT
          iptables -C INPUT -s "$ip" -p tcp --dport 443 -j ACCEPT 2>/dev/null \
            || iptables -A INPUT -s "$ip" -p tcp --dport 443 -j ACCEPT
        done
        if command -v ip6tables >/dev/null; then
          for ip in $CF_V6; do
            ip6tables -C INPUT -s "$ip" -p tcp --dport 80  -j ACCEPT 2>/dev/null \
              || ip6tables -A INPUT -s "$ip" -p tcp --dport 80  -j ACCEPT
            ip6tables -C INPUT -s "$ip" -p tcp --dport 443 -j ACCEPT 2>/dev/null \
              || ip6tables -A INPUT -s "$ip" -p tcp --dport 443 -j ACCEPT
          done
        fi
        # Persist if we know how
        if command -v netfilter-persistent >/dev/null; then
          netfilter-persistent save >/dev/null
        elif [[ -d /etc/iptables ]]; then
          iptables-save  > /etc/iptables/rules.v4
          command -v ip6tables-save >/dev/null && ip6tables-save > /etc/iptables/rules.v6
        else
          yellow "  WARNING: iptables rules are in memory only."
          yellow "           Install iptables-persistent (or equivalent) or they'll"
          yellow "           disappear on reboot."
        fi
        ;;
    esac
    green "  firewall updated ($FW_MODE mode, $CF_COUNT CF ranges)"
  fi
fi
echo

# ==================================================================
# 2. Daily backup cron
# ==================================================================
bold "[2/3] Daily backup cron"

mkdir -p "$BACKUP_DIR"

CRON_BACKUP=/etc/cron.d/vault-backup
cat > "$CRON_BACKUP" <<EOF
# simple-vault: daily encrypted volume backup
# Runs 03:30 local time. Tarballs are AES-256-GCM encrypted by the app,
# so they're safe for off-site storage.
SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

30 3 * * * root docker run --rm -v $VAULT_VOLUME:/data:ro -v $BACKUP_DIR:/backup alpine tar czf /backup/vault-\$(date +\%F).tar.gz -C / data && find $BACKUP_DIR -name 'vault-*.tar.gz' -mtime +$BACKUP_RETENTION_DAYS -delete
EOF
chmod 644 "$CRON_BACKUP"
echo "  installed $CRON_BACKUP (runs 03:30 daily)"

if confirm "  Run one backup now to verify?" Y; then
  docker run --rm \
    -v "$VAULT_VOLUME":/data:ro \
    -v "$BACKUP_DIR":/backup alpine \
    tar czf "/backup/vault-$(date +%F).tar.gz" -C / data
  echo "  $(ls -lh "$BACKUP_DIR" | tail -1)"
  green "  OK"
fi
echo

# ==================================================================
# 3. Weekly CF IP refresh
# ==================================================================
bold "[3/3] Weekly Cloudflare IP refresh"

CRON_REFRESH=/etc/cron.d/vault-cf-refresh

if [[ "$FW" = "skip" ]] || [[ "${FW_MODE:-skip}" = "skip" ]]; then
  yellow "  skipping (firewall step was skipped)"
  # Clean up any stale refresh cron from a previous run
  rm -f "$CRON_REFRESH"
else
  # Compose the refresh command for the chosen backend.
  # All backends: fetch CF list, re-add allow rules (idempotent).
  case "$FW" in
    ufw)
      CMD='for ip in $(curl -fsSL '"$CF_IPV4_URL"') $(curl -fsSL '"$CF_IPV6_URL"'); do ufw allow from "$ip" to any port 80 proto tcp >/dev/null 2>&1 || true; ufw allow from "$ip" to any port 443 proto tcp >/dev/null 2>&1 || true; done' ;;
    firewalld)
      CMD='for ip in $(curl -fsSL '"$CF_IPV4_URL"'); do firewall-cmd --permanent --zone=public --add-rich-rule="rule family=ipv4 source address=\"$ip\" port port=80 protocol=tcp accept" >/dev/null 2>&1 || true; firewall-cmd --permanent --zone=public --add-rich-rule="rule family=ipv4 source address=\"$ip\" port port=443 protocol=tcp accept" >/dev/null 2>&1 || true; done; for ip in $(curl -fsSL '"$CF_IPV6_URL"'); do firewall-cmd --permanent --zone=public --add-rich-rule="rule family=ipv6 source address=\"$ip\" port port=80 protocol=tcp accept" >/dev/null 2>&1 || true; firewall-cmd --permanent --zone=public --add-rich-rule="rule family=ipv6 source address=\"$ip\" port port=443 protocol=tcp accept" >/dev/null 2>&1 || true; done; firewall-cmd --reload >/dev/null' ;;
    iptables)
      CMD='for ip in $(curl -fsSL '"$CF_IPV4_URL"'); do iptables -C INPUT -s "$ip" -p tcp --dport 80 -j ACCEPT 2>/dev/null || iptables -A INPUT -s "$ip" -p tcp --dport 80 -j ACCEPT; iptables -C INPUT -s "$ip" -p tcp --dport 443 -j ACCEPT 2>/dev/null || iptables -A INPUT -s "$ip" -p tcp --dport 443 -j ACCEPT; done' ;;
  esac

  cat > "$CRON_REFRESH" <<EOF
# simple-vault: weekly Cloudflare IP range refresh
# Runs Sun 04:17. Only ADDS new ranges; re-run setup-hardening.sh for
# a clean rebuild if CF drops ranges.
SHELL=/bin/bash
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

17 4 * * 0 root bash -c '$CMD'
EOF
  chmod 644 "$CRON_REFRESH"
  echo "  installed $CRON_REFRESH (runs Sun 04:17)"
fi
echo

# ==================================================================
# Summary
# ==================================================================
green "Done."
echo
cat <<EOF
Summary
  firewall       : $FW  ${FW_MODE:+($FW_MODE mode)}
  backup dir     : $BACKUP_DIR  (retention: ${BACKUP_RETENTION_DAYS}d)
  daily cron     : /etc/cron.d/vault-backup
  weekly cron    : $( [[ -f "$CRON_REFRESH" ]] && echo "$CRON_REFRESH" || echo "(skipped)" )

Recommended manual steps
  1. Cloudflare dashboard → SSL/TLS → Overview → set to 'Full (strict)'
  2. Mirror $BACKUP_DIR to an off-box location (scp / rclone / s3 sync)
  3. Verify origin is locked: from a non-CF host,
       curl --max-time 5 https://<server-public-ip>/    # should hang

Re-running this script is safe (idempotent).
EOF
