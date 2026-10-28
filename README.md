# secrets-manager

An encrypted `.env` vault built so an AI coding agent (Claude Code, Cursor, Copilot agents and similar) can **use** your API keys and passwords without the values ever entering its context window, the chat transcript, shell history, or a plaintext file on disk.

It is a single Bash file plus an optional Bun daemon. The only dependencies are `openssl` and, for the agent, `bun`.

## The problem

Coding agents increasingly need credentials: calling an API, deploying, querying a database, sending a test email. The usual ways of handing them over all leak:

| Approach | Where the secret ends up |
|---|---|
| Paste the key into chat | The transcript, provider logs, and every later turn of the conversation |
| Let the agent read `.env` | The model's context window, alongside every other key in the file |
| `echo $KEY` to "check it is set" | Same as above |
| A plaintext `.env` on disk | Backups, sync folders, accidental commits, any process that scans the disk |

The goal here is narrower and more practical than a full secrets platform: the agent writes `$OPENAI_API_KEY` in a command, the shell expands it inside that one process, and the value never travels back to the model.

## How it works

```
                       password popup (GUI, masked)
                                  |
secrets.env.enc --openssl--> plaintext in a shell variable --export--> env vars --exec/child--> your command
 (AES-256-CBC,                (memory only)                                         uses $KEY
  PBKDF2-SHA256)
```

1. **Encrypted at rest.** The vault is a normal `KEY=VALUE` file encrypted with `openssl enc -aes-256-cbc -pbkdf2 -iter 600000` (PBKDF2-HMAC-SHA256, random salt). Older vaults written with openssl's previous default of 10,000 iterations still open and are upgraded on the next write.
2. **The password never touches the terminal.** It is collected by a native masked dialog: Windows Forms through PowerShell, AppleScript on macOS, `zenity`/`kdialog` on Linux, and a silent `read -s` as the fallback. An agent driving the shell sees only "Requesting password...". The password reaches openssl through an environment variable rather than argv, so it does not appear in process listings.
3. **Decrypted to memory, not disk.** `load-secrets-secure` pipes openssl's output into a shell variable and exports each line. For a long-running service, `load-secrets-secure && exec your-server` hands the environment to the child process with no file in between.
4. **Values in, names out.** New secrets are entered through a GUI form (`add-secret-gui`: name, value, confirm value), so the value is never typed into a command line the agent can see. The agent can list key **names** (`secrets-agent list`) but has no command that prints values.
5. **Each agent tool call is a fresh shell.** In Claude Code, every Bash call is a new process. A command such as `load-secrets-secure && curl -H "Authorization: Bearer $KEY" ...` loads the secret, uses it, and exits. The next call starts with an empty environment, so a later prompt-injected `env | grep KEY` finds nothing.

### The secrets agent (optional)

Typing the master password for every command gets old fast. `secrets-agent.ts` works like `ssh-agent`:

- One password popup starts a small daemon that keeps the decrypted vault **in memory only**.
- It listens on `127.0.0.1` on a random port. Every request must carry a random 256-bit token from `~/.secrets-agent/info.json` (mode 600).
- **Category scoping.** Keys are grouped by glob patterns in `secrets-categories.json` (`ai`, `dev`, `payments`, ...). The first request for a key in a category that is not yet unlocked opens a new password popup. If you only unlocked `ai` keys this session and something tries to load a `payments` key, a human has to approve it.
- **Bulk unlock.** `load-secrets-from-agent --bulk` unlocks the `bulk_categories` with one popup, which is what a service start script wants.
- **Idle TTL.** After 8 hours without use (configurable), the process exits and the secrets are gone.
- The master password is not kept. The agent stores a salted scrypt hash of it to verify later category popups.
- The commands that print values (`get`, `dump`) refuse to run unless invoked by the Bash wrapper, which captures their output with `$(...)` and `eval`s it. Run directly, they would print values into the agent's context.
- `extra_files` merges more vaults at start (for example, a per-project vault), so the loaded set does not depend on the directory the agent was started from.

## Quick start

Requirements: Bash (Git Bash on Windows works), OpenSSL 1.1.1 or newer, and [Bun](https://bun.sh) if you want the agent.

```bash
git clone https://github.com/ianFullStack/secrets-manager.git ~/secrets-manager
source ~/secrets-manager/secrets-manager.sh

# Add a secret. The first run creates the vault and asks you to choose a password (twice),
# then a form asks for the name, value and confirmation.
add-secret-gui
# (Or import an existing file: cp .env ~/secrets.env && lock-secrets)

# Use secrets in a command (one popup, memory only)
load-secrets-secure && curl -s -H "Authorization: Bearer $OPENAI_API_KEY" https://api.openai.com/v1/models

# Or start the agent once and load without popups for the rest of the session
secrets-agent start
load-secrets-from-agent --bulk
```

The vault lives in `$SECRETS_DIR` (default `$HOME`), so commands work from any directory. Set `SECRETS_DIR` to keep a vault per project. Copy `secrets-categories.json` next to the vault to customize categories.

Run the test suite (it uses a throwaway vault in a temp directory):

```bash
bash tests/smoke.sh
```

## Commands

| Command | What it does |
|---|---|
| `load-secrets-secure` | Password popup, decrypt to env vars in the current shell. Nothing is written to disk. |
| `secrets-agent start` / `stop` / `status` | Start the daemon (one popup), stop it, or show idle time and unlocked categories. |
| `secrets-agent list [PREFIX]` | List key names and their categories. Never values. Safe for an AI agent to run. |
| `load-secrets-from-agent` | Load keys from categories already unlocked this session. Starts the agent if needed. |
| `load-secrets-from-agent --bulk` | One popup unlocks `bulk_categories` and loads them. |
| `add-secret-gui` | GUI form: name, value, confirm value. Creates the vault on first use. The value is never visible in the terminal. |
| `add-secret KEY VALUE` | Scriptable version. The value is visible in shell history and the process list. |
| `remove-secret KEY` | Remove a key. |
| `rekey-secrets` | Change the vault password (also upgrades a legacy vault). |
| `unlock-secrets` / `lock-secrets` | Manual flow: decrypt to a plaintext `secrets.env` (mode 600) and re-encrypt it, shredding the plaintext. |
| `show-secrets-help` | Command list and current vault/agent status. |

Every command that edits the vault decrypts to memory, changes it, and re-encrypts to a temp file that is renamed over the old vault, so a failed write cannot truncate it.

### Environment variables

| Variable | Default | Purpose |
|---|---|---|
| `SECRETS_DIR` | `$HOME` | Folder containing `secrets.env.enc` |
| `SECRETS_CATEGORIES` | `$SECRETS_DIR/secrets-categories.json` | Agent category config (built-in defaults if missing) |
| `SECRETS_AGENT_DIR` | `~/.secrets-agent` | Agent port/token/pid/log files |
| `SECRETS_AGENT_TTL_MS` | `28800000` (8 h) | Agent idle timeout |
| `SECRETS_MASTER_PASSWORD` | unset | Non-interactive password for scheduled jobs (see limitations) |

## Using it with an AI coding agent

Add rules like these to the agent's project memory (`CLAUDE.md`, `.cursorrules`, `AGENTS.md`):

```markdown
## Secrets
Secrets are in an encrypted vault managed by ~/secrets-manager/secrets-manager.sh.
- Never read secrets.env, .env files, or run `secrets-agent.ts get|dump` directly.
- Never echo or print a secret. Reference it as $NAME inside the command that needs it.
- Each Bash call is a fresh shell, so chain everything in one call:
  source ~/secrets-manager/secrets-manager.sh && load-secrets-from-agent && <command using $NAME>
- To see which keys exist: secrets-agent list   (names only)
- To check a key is set: [ -n "$NAME" ] && echo set || echo missing
- When the user wants to add a secret, run add-secret-gui and tell them a popup will appear.
  Never ask them to paste a value into the chat.
- Long-running services: load-secrets-from-agent --bulk && exec <command>
```

`examples/start-secure.sh` shows the `load ... && exec` pattern for a service, and `examples/demo.sh` shows a command that uses secrets by reference.

## Threat model and limitations

This tool reduces accidental exposure. It is not a sandbox, and it is honest about the following.

**What it protects against**
- Secret values entering an AI agent's context, the chat transcript, or the provider's logs during normal use.
- Plaintext `.env` files sitting on disk, in backups, in sync folders, or in a commit.
- The master password appearing in the terminal, shell history, or process arguments.
- Scope creep within a session: keys outside the categories you unlocked need another human approval.

**What it does not protect against**
- **A non-cooperative agent.** The agent sees names, not values, only as long as it follows the rules. Any process holding the environment can print it: an agent that runs `load-secrets-from-agent && env` will see the values. The design makes leakage something that has to be done on purpose and narrows the window to a single command; it cannot make it impossible. Review commands before approving them, or use your agent's permission settings to block `env`, `printenv` and `echo $...`.
- **Child processes.** Environment variables are inherited by every child of the shell and, on Linux, readable by the same user through `/proc/<pid>/environ`. Load only what a command needs.
- **Same-user malware.** Anything running as you can read the agent's token file, query the agent, attach a debugger to it, or capture the password dialog. On Windows, `chmod 600` does not change ACLs; the token file is protected only by the default permissions of your profile folder.
- **Swap and crash dumps.** Decrypted values in memory can be paged to disk. Use full-disk encryption (BitLocker, FileVault, LUKS).
- **Weak master passwords.** PBKDF2 at 600,000 iterations slows offline guessing but does not stop it. A stolen `secrets.env.enc` is only as strong as its password. Use a long passphrase.
- **No integrity protection beyond padding.** `openssl enc` uses AES-CBC without a MAC, so a tampered vault is detected only by failing to decrypt or failing the KEY=VALUE format check. If you need authenticated encryption, wrap the vault with `age` or `gpg` instead.
- **`SECRETS_MASTER_PASSWORD`.** Convenient for scheduled jobs, but it puts the password in an environment variable. Load it from an OS-protected store (Windows DPAPI, macOS Keychain, libsecret) at job start, never from a plain file.
- **`add-secret KEY VALUE`** puts the value in shell history and briefly in the process list. Use `add-secret-gui` for anything sensitive.

## Files

| File | Purpose |
|---|---|
| `secrets-manager.sh` | Bash functions: vault operations, password popups, agent wrapper |
| `secrets-agent.ts` | Bun daemon: in-memory vault, token auth, categories, idle TTL |
| `secrets-categories.json` | Example category config (copy next to your vault) |
| `secrets.env.template` | Example key names for a new vault |
| `examples/` | `start-secure.sh` (service start) and `demo.sh` (use by reference) |
| `tests/smoke.sh` | End-to-end test against a temporary vault |

## License

MIT. See [LICENSE](LICENSE).
