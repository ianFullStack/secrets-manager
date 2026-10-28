#!/usr/bin/env bash
# Start a long-running process (server, bot, worker) with secrets from the vault.
# The values go from the vault into this shell's environment and are inherited by the
# exec'd process. No plaintext file is ever written.
set -euo pipefail
cd "$(dirname "$0")"

# Adjust to wherever you cloned secrets-manager.
source "${SECRETS_MANAGER:-$HOME/secrets-manager/secrets-manager.sh}"

# Either decrypt directly (popup every start)...
load-secrets-secure
# ...or use the agent (one popup per session):
# load-secrets-from-agent --bulk

exec bun run start
