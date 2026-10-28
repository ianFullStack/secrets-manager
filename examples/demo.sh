#!/usr/bin/env bash
# Demo: what a command run by an AI agent looks like when it uses secrets by reference.
# Run after loading secrets, in the same shell invocation:
#   source secrets-manager.sh && load-secrets-secure && bash examples/demo.sh
# The agent writes $DATABASE_URL and $OPENAI_API_KEY; it never sees the values.

echo "=== Database ==="
if [ -n "${DATABASE_URL:-}" ]; then echo "DATABASE_URL is set (value not shown)"; else echo "DATABASE_URL is not set"; fi

echo "=== API call ==="
if [ -n "${OPENAI_API_KEY:-}" ]; then
  # The key is expanded by the shell inside this process only.
  curl -s -o /dev/null -w "OpenAI /v1/models -> HTTP %{http_code}\n" \
    -H "Authorization: Bearer $OPENAI_API_KEY" https://api.openai.com/v1/models
else
  echo "OPENAI_API_KEY is not set"
fi
