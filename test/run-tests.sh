#!/usr/bin/env bash
# End-to-end test suite for Simple Vault v2 (DEK + agents).
# Spins up the server against a scratch data dir and exercises every flow,
# including migration of a legacy (v1 password-encrypted) vault.
set -uo pipefail

cd "$(dirname "$0")/.."
DATA="$(mktemp -d)"
PORT=3199
BASE="http://127.0.0.1:$PORT"
PASS='test-master-password'

cleanup() { kill "$SERVER_PID" 2>/dev/null; rm -rf "$DATA"; }
trap cleanup EXIT

FAILS=0
check() { # check <desc> <expected> <actual>
  if [ "$2" = "$3" ]; then echo "  ok: $1"; else echo "  FAIL: $1 (expected '$2', got '$3')"; FAILS=$((FAILS+1)); fi
}

# ---------- Seed a LEGACY v1 vault (password-encrypted secrets, old formats) ----------
node - "$DATA" "$PASS" <<'EOF'
const crypto = require('crypto'), fs = require('fs'), path = require('path');
const [dir, pass] = process.argv.slice(2);
function enc(text, password) {
  const salt = crypto.randomBytes(32), iv = crypto.randomBytes(16);
  const key = crypto.pbkdf2Sync(password, salt, 100000, 32, 'sha512');
  const c = crypto.createCipheriv('aes-256-gcm', key, iv);
  let e = c.update(text, 'utf8', 'hex'); e += c.final('hex');
  return { salt: salt.toString('hex'), iv: iv.toString('hex'), tag: c.getAuthTag().toString('hex'), data: e };
}
fs.mkdirSync(path.join(dir, 'secrets'), { recursive: true });
// legacy meta: just the canary, no DEK
fs.writeFileSync(path.join(dir, 'vault.json'), JSON.stringify({ verify: enc('vault-ok', pass) }));
// v1a: bare envelope
fs.writeFileSync(path.join(dir, 'secrets', 'legacy-bare.enc'), JSON.stringify(enc('bare-value', pass)));
// v1b: {value, notes}
fs.writeFileSync(path.join(dir, 'secrets', 'legacy-noted.enc'),
  JSON.stringify({ value: enc('noted-value', pass), notes: enc('the notes', pass) }));
EOF

VAULT_DATA="$DATA" PORT=$PORT node server.js >/dev/null 2>&1 &
SERVER_PID=$!
for i in $(seq 1 50); do curl -sf "$BASE/health" >/dev/null && break; sleep 0.1; done

j() { jq -r "$1"; }

echo "== Phase 1: legacy migration =="
H=$(curl -s "$BASE/health")
check "health initialized" "true" "$(echo "$H" | j .initialized)"

R=$(curl -s -X POST "$BASE/unlock" -H 'Content-Type: application/json' -d "{\"password\":\"$PASS\"}")
TOKEN=$(echo "$R" | j .token)
check "unlock migrates 2 legacy secrets" "2" "$(echo "$R" | j .migrated)"
check "token issued" "64" "${#TOKEN}"

check "vault.json has dek_wrapped" "true" "$(jq 'has("dek_wrapped")' "$DATA/vault.json")"
check "secret file is v2" "2" "$(jq .v "$DATA/secrets/legacy-bare.enc")"
check "v2 file has no password salt on value" "false" "$(jq '.value | has("salt")' "$DATA/secrets/legacy-noted.enc")"

R=$(curl -s "$BASE/secrets/legacy-bare" -H "x-vault-token: $TOKEN")
check "migrated bare value readable" "bare-value" "$(echo "$R" | j .value)"
R=$(curl -s "$BASE/secrets/legacy-noted" -H "x-vault-token: $TOKEN")
check "migrated noted value readable" "noted-value" "$(echo "$R" | j .value)"
check "migrated notes readable" "the notes" "$(echo "$R" | j .notes)"

# Second unlock: no re-migration
R=$(curl -s -X POST "$BASE/unlock" -H 'Content-Type: application/json' -d "{\"password\":\"$PASS\"}")
check "second unlock migrates 0" "0" "$(echo "$R" | j .migrated)"

R=$(curl -s -X POST "$BASE/unlock" -H 'Content-Type: application/json' -d '{"password":"wrong-password"}')
check "wrong password rejected" "Wrong password" "$(echo "$R" | j .error)"

echo "== Secrets CRUD (master) =="
curl -s -X POST "$BASE/secrets/strapi.v3-db" -H "x-vault-token: $TOKEN" -H 'Content-Type: application/json' \
  -d '{"value":"db-pass-123","notes":"postgres on db-web-01"}' >/dev/null
curl -s -X POST "$BASE/secrets/strapi.v3-admin" -H "x-vault-token: $TOKEN" -H 'Content-Type: application/json' \
  -d '{"value":"admin-pass"}' >/dev/null
curl -s -X POST "$BASE/secrets/other-secret" -H "x-vault-token: $TOKEN" -H 'Content-Type: application/json' \
  -d '{"value":"unrelated"}' >/dev/null
R=$(curl -s "$BASE/secrets" -H "x-vault-token: $TOKEN")
check "master lists all 5" "5" "$(echo "$R" | jq length)"

echo "== Phase 2: agents =="
R=$(curl -s -X POST "$BASE/agents" -H "x-vault-token: $TOKEN" -H 'Content-Type: application/json' \
  -d '{"name":"hermes","policy":[{"pattern":"strapi.*","perms":["read"]}],"prompt_notes":"Strapi bot"}')
AKEY=$(echo "$R" | j .key)
AID=$(echo "$R" | j .id)
check "agent created, key prefix" "svk_" "${AKEY:0:4}"
check "matched_secrets count" "2" "$(echo "$R" | jq '.matched_secrets | length')"
check "key not stored in meta" "null" "$(jq '.agents[].key // null' "$DATA/vault.json" | head -1)"

# Agent list scoping
R=$(curl -s "$BASE/secrets" -H "x-vault-key: $AKEY")
check "agent sees only its 2 secrets" "2" "$(echo "$R" | jq length)"
check "agent list content" '["strapi.v3-admin","strapi.v3-db"]' "$(echo "$R" | jq -c .)"

# Agent read allowed / denied
R=$(curl -s "$BASE/secrets/strapi.v3-db" -H "x-vault-key: $AKEY")
check "agent read in-scope" "db-pass-123" "$(echo "$R" | j .value)"
R=$(curl -s -o /dev/null -w "%{http_code}" "$BASE/secrets/other-secret" -H "x-vault-key: $AKEY")
check "agent read out-of-scope -> 403" "403" "$R"

# Agent write denied (read-only policy)
R=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$BASE/secrets/strapi.v3-db" -H "x-vault-key: $AKEY" \
  -H 'Content-Type: application/json' -d '{"value":"overwrite"}')
check "agent write denied -> 403" "403" "$R"

# Agent cannot manage agents / audit / share / keygen
for EP in "GET /agents" "GET /audit" "POST /keygen"; do
  M=${EP% *}; P=${EP#* }
  R=$(curl -s -o /dev/null -w "%{http_code}" -X "$M" "$BASE$P" -H "x-vault-key: $AKEY")
  check "agent blocked from $P -> 403" "403" "$R"
done
R=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$BASE/secrets/strapi.v3-db/share" -H "x-vault-key: $AKEY")
check "agent blocked from share -> 403" "403" "$R"

# Read-write agent
R=$(curl -s -X POST "$BASE/agents" -H "x-vault-token: $TOKEN" -H 'Content-Type: application/json' \
  -d '{"name":"writer","policy":[{"pattern":"other-*","perms":["read","write"]}]}')
WKEY=$(echo "$R" | j .key)
WID=$(echo "$R" | j .id)
R=$(curl -s -X POST "$BASE/secrets/other-secret" -H "x-vault-key: $WKEY" \
  -H 'Content-Type: application/json' -d '{"value":"updated-by-agent"}')
check "rw agent write in-scope" "Saved" "$(echo "$R" | j .message)"
R=$(curl -s "$BASE/secrets/other-secret" -H "x-vault-key: $WKEY")
check "rw agent read back" "updated-by-agent" "$(echo "$R" | j .value)"
R=$(curl -s -o /dev/null -w "%{http_code}" -X DELETE "$BASE/secrets/other-secret" -H "x-vault-key: $WKEY")
check "rw agent delete denied (no delete perm)" "403" "$R"

# Duplicate name rejected
R=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$BASE/agents" -H "x-vault-token: $TOKEN" \
  -H 'Content-Type: application/json' -d '{"name":"hermes","policy":[{"pattern":"*","perms":["read"]}]}')
check "duplicate agent name -> 409" "409" "$R"

# Invalid policy rejected
R=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$BASE/agents" -H "x-vault-token: $TOKEN" \
  -H 'Content-Type: application/json' -d '{"name":"bad","policy":[{"pattern":"x","perms":["admin"]}]}')
check "invalid perm -> 400" "400" "$R"

echo "== Phase 4: rotate / disable / expiry / wrap / audit =="
R=$(curl -s -X POST "$BASE/agents/$AID/rotate" -H "x-vault-token: $TOKEN")
NEWKEY=$(echo "$R" | j .key)
R=$(curl -s -o /dev/null -w "%{http_code}" "$BASE/secrets/strapi.v3-db" -H "x-vault-key: $AKEY")
check "old key dead after rotate -> 401" "401" "$R"
R=$(curl -s "$BASE/secrets/strapi.v3-db" -H "x-vault-key: $NEWKEY")
check "new key works after rotate" "db-pass-123" "$(echo "$R" | j .value)"

# Disable
curl -s -X PATCH "$BASE/agents/$AID" -H "x-vault-token: $TOKEN" -H 'Content-Type: application/json' -d '{"disabled":true}' >/dev/null
R=$(curl -s -o /dev/null -w "%{http_code}" "$BASE/secrets/strapi.v3-db" -H "x-vault-key: $NEWKEY")
check "disabled agent -> 403" "403" "$R"
curl -s -X PATCH "$BASE/agents/$AID" -H "x-vault-token: $TOKEN" -H 'Content-Type: application/json' -d '{"disabled":false}' >/dev/null

# Wrap flow via agent key
R=$(curl -s "$BASE/secrets/strapi.v3-db?wrap=true" -H "x-vault-key: $NEWKEY")
UURL=$(echo "$R" | j .unwrap_url)
check "wrap returns no raw value" "null" "$(echo "$R" | jq .value)"
V=$(curl -s "$UURL")
check "unwrap returns raw value" "db-pass-123" "$V"
R=$(curl -s -o /dev/null -w "%{http_code}" "$UURL")
check "unwrap is one-time -> 404" "404" "$R"

# Revoke
R=$(curl -s -X DELETE "$BASE/agents/$WID" -H "x-vault-token: $TOKEN")
check "revoke ok" "Agent revoked" "$(echo "$R" | j .message)"
R=$(curl -s -o /dev/null -w "%{http_code}" "$BASE/secrets/other-secret" -H "x-vault-key: $WKEY")
check "revoked key dead -> 401" "401" "$R"

# Audit
R=$(curl -s "$BASE/audit?limit=500" -H "x-vault-token: $TOKEN")
check "audit has agent reads" "true" "$(echo "$R" | jq '[.[] | select(.actor=="agent:hermes" and .action=="read")] | length > 0')"
check "audit has denied write" "true" "$(echo "$R" | jq '[.[] | select(.action=="write" and .ok==false)] | length > 0')"
check "audit has agent_create" "true" "$(echo "$R" | jq '[.[] | select(.action=="agent_create")] | length > 0')"

echo "== Restart persistence =="
kill "$SERVER_PID"; wait "$SERVER_PID" 2>/dev/null
VAULT_DATA="$DATA" PORT=$PORT node server.js >/dev/null 2>&1 &
SERVER_PID=$!
for i in $(seq 1 50); do curl -sf "$BASE/health" >/dev/null && break; sleep 0.1; done
R=$(curl -s "$BASE/secrets/strapi.v3-db" -H "x-vault-key: $NEWKEY")
check "agent key survives restart" "db-pass-123" "$(echo "$R" | j .value)"
R=$(curl -s -X POST "$BASE/unlock" -H 'Content-Type: application/json' -d "{\"password\":\"$PASS\"}")
check "master unlock survives restart" "0" "$(echo "$R" | j .migrated)"

echo
if [ "$FAILS" -eq 0 ]; then echo "ALL TESTS PASSED"; else echo "$FAILS TEST(S) FAILED"; exit 1; fi
