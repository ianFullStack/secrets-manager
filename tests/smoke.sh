#!/usr/bin/env bash
# Smoke test against a throwaway vault in a temp directory. Never touches a real vault:
# HOME, SECRETS_DIR and SECRETS_AGENT_DIR all point into the temp dir.
#   bash tests/smoke.sh
set -u
REPO="$(cd "$(dirname "$0")/.." && pwd)"
TMP="$(mktemp -d)"
export HOME="$TMP" USERPROFILE="$TMP" SECRETS_DIR="$TMP" SECRETS_AGENT_DIR="$TMP/.agent"
export SECRETS_CATEGORIES="$REPO/secrets-categories.json"
export SECRETS_MASTER_PASSWORD="correct horse battery staple"
export SECRETS_MANAGER_QUIET=1
VAULT="$TMP/secrets.env.enc"

pass=0; fail=0
ok()   { echo "  ok   $1"; pass=$((pass + 1)); }
bad()  { echo "  FAIL $1"; fail=$((fail + 1)); }
check() { if eval "$2"; then ok "$1"; else bad "$1"; fi; }

cleanup() {
    if command -v bun >/dev/null 2>&1 && [ -f "$TMP/.agent/info.json" ]; then
        bun "$REPO/secrets-agent.ts" stop >/dev/null 2>&1
    fi
    rm -rf "$TMP"
}
trap cleanup EXIT

source "$REPO/secrets-manager.sh"

echo "vault: create, add, load"
add-secret OPENAI_API_KEY "sk-test-123" >/dev/null
check "add-secret creates a vault" '[ -f "$VAULT" ]'
add-secret DATABASE_URL "postgres://u:p@h/db?x=1&y='q'" >/dev/null
add-secret JWT_SECRET 'has spaces and "quotes"' >/dev/null
check "vault uses 600k PBKDF2 iterations" \
    'SM_PASS="$SECRETS_MASTER_PASSWORD" openssl enc -d -aes-256-cbc -pbkdf2 -iter 600000 -in "$VAULT" -pass env:SM_PASS >/dev/null 2>&1'
( unset OPENAI_API_KEY DATABASE_URL JWT_SECRET
  load-secrets-secure >/dev/null
  [ "$OPENAI_API_KEY" = "sk-test-123" ] && [ "$DATABASE_URL" = "postgres://u:p@h/db?x=1&y='q'" ] \
    && [ "$JWT_SECRET" = 'has spaces and "quotes"' ] ) && ok "load-secrets-secure round-trips values" || bad "load-secrets-secure round-trips values"

echo "vault: update, remove, wrong password"
add-secret OPENAI_API_KEY "sk-test-456" >/dev/null
( load-secrets-secure >/dev/null; [ "$OPENAI_API_KEY" = "sk-test-456" ] ) && ok "add-secret overwrites" || bad "add-secret overwrites"
remove-secret JWT_SECRET >/dev/null
( unset JWT_SECRET; load-secrets-secure >/dev/null; [ -z "${JWT_SECRET:-}" ] ) && ok "remove-secret removes" || bad "remove-secret removes"
before=$(cksum < "$VAULT")
SECRETS_MASTER_PASSWORD="wrong" add-secret X 1 >/dev/null 2>&1
check "wrong password is rejected and vault is unchanged" '[ "$(cksum < "$VAULT")" = "$before" ]'
check "invalid key name is rejected" '! add-secret "BAD;KEY" 1 >/dev/null 2>&1'

echo "vault: legacy (10k iteration) vault"
printf 'LEGACY_KEY=old\n' | SM_PASS="$SECRETS_MASTER_PASSWORD" openssl enc -aes-256-cbc -salt -pbkdf2 -out "$VAULT" -pass env:SM_PASS 2>/dev/null
( load-secrets-secure >/dev/null; [ "$LEGACY_KEY" = "old" ] ) && ok "legacy vault decrypts" || bad "legacy vault decrypts"
add-secret NEW_KEY new >/dev/null
check "re-encryption upgrades legacy vault to 600k" \
    'SM_PASS="$SECRETS_MASTER_PASSWORD" openssl enc -d -aes-256-cbc -pbkdf2 -iter 600000 -in "$VAULT" -pass env:SM_PASS 2>/dev/null | grep -q "^LEGACY_KEY=old$"'

if command -v bun >/dev/null 2>&1; then
    echo "agent: start, list, guard, stop"
    secrets-agent start >/dev/null 2>&1
    check "agent starts (unattended password)" 'bun "$REPO/secrets-agent.ts" status >/dev/null 2>&1'
    check "list shows names" 'bun "$REPO/secrets-agent.ts" list | grep -q "LEGACY_KEY"'
    check "list never shows values" '! bun "$REPO/secrets-agent.ts" list | grep -q "=old"'
    check "dump refuses without the wrapper" '! bun "$REPO/secrets-agent.ts" dump >/dev/null 2>&1'
    bun "$REPO/secrets-agent.ts" stop >/dev/null 2>&1
    sleep 1
    check "agent stops" '! bun "$REPO/secrets-agent.ts" status >/dev/null 2>&1'
else
    echo "agent: skipped (bun not installed)"
fi

echo ""
echo "$pass passed, $fail failed"
[ "$fail" -eq 0 ]
