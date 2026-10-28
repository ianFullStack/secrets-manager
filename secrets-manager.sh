#!/usr/bin/env bash
# secrets-manager.sh - an encrypted .env vault that humans and AI coding agents can share
# without the secret values ever entering the agent's context, chat history or disk.
#
# Usage:   source /path/to/secrets-manager.sh   then   show-secrets-help
#
# Vault location (override with SECRETS_DIR, default $HOME):
#   $SECRETS_DIR/secrets.env.enc   encrypted vault: AES-256-CBC, key from PBKDF2-SHA256
#   $SECRETS_DIR/secrets.env       plaintext; exists only during the manual unlock/lock flow
#
# Environment:
#   SECRETS_DIR              directory holding the vault (default: $HOME)
#   SECRETS_AGENT_SCRIPT     path to secrets-agent.ts (default: next to this file)
#   SECRETS_AGENT_DIR        agent runtime dir for port/token/pid/log (default: $HOME/.secrets-agent)
#   SECRETS_MASTER_PASSWORD  non-interactive password for unattended jobs. Load it from an
#                            OS-protected store (DPAPI, Keychain, libsecret), never a plain file.

SECRETS_MANAGER_HOME="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# New encryptions use 600,000 PBKDF2 iterations (OWASP 2023 guidance for PBKDF2-HMAC-SHA256).
# Vaults written with openssl's old default (-pbkdf2 without -iter = 10,000) still decrypt and
# are upgraded automatically the next time the vault is re-encrypted.
SECRETS_KDF_ITER=600000
SECRETS_LEGACY_ITER=10000

# Colors for output
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

# Resolve vault paths at call time, so SECRETS_DIR can be changed after sourcing.
_sm-paths() {
    local dir="${SECRETS_DIR:-$HOME}"
    SECRETS_FILE="$dir/secrets.env"
    ENCRYPTED_FILE="$dir/secrets.env.enc"
    AGENT_SCRIPT="${SECRETS_AGENT_SCRIPT:-$SECRETS_MANAGER_HOME/secrets-agent.ts}"
    AGENT_DIR="${SECRETS_AGENT_DIR:-$HOME/.secrets-agent}"
}
_sm-paths

_sm-valid-key() {
    [[ "$1" =~ ^[A-Za-z_][A-Za-z0-9_]*$ ]]
}

# True when every line is blank, a comment, or KEY=VALUE. A wrong password or wrong
# iteration count occasionally passes openssl's padding check and yields random bytes;
# this check stops that garbage from being loaded or, worse, re-encrypted over the vault.
_sm-is-env-text() {
    ! printf '%s\n' "$1" | LC_ALL=C grep -qvE '^[[:space:]]*(#.*)?$|^[[:space:]]*[A-Za-z_][A-Za-z0-9_]*='
}

# _sm-decrypt FILE PASSWORD -> plaintext on stdout. Plaintext stays in memory (a pipe).
# The password reaches openssl through an environment variable, not argv, so it does not
# show up in process listings.
_sm-decrypt() {
    local file="$1" pass="$2" out iter
    for iter in "$SECRETS_KDF_ITER" "$SECRETS_LEGACY_ITER"; do
        { out=$(SM_PASS="$pass" openssl enc -d -aes-256-cbc -pbkdf2 -iter "$iter" \
                  -in "$file" -pass env:SM_PASS 2>/dev/null); } 2>/dev/null || continue
        if _sm-is-env-text "$out"; then
            printf '%s\n' "$out"
            return 0
        fi
    done
    return 1
}

# _sm-encrypt PASSWORD OUTFILE < plaintext. Writes to a temp file and renames it, so a
# failed encryption never truncates the existing vault.
_sm-encrypt() {
    local pass="$1" out="$2"
    local tmp="$out.tmp.$$"
    if SM_PASS="$pass" openssl enc -aes-256-cbc -salt -pbkdf2 -iter "$SECRETS_KDF_ITER" \
           -out "$tmp" -pass env:SM_PASS 2>/dev/null; then
        mv -f "$tmp" "$out"
    else
        rm -f "$tmp"
        return 1
    fi
}

# Get password via GUI popup, cross-platform (never visible in terminal or AI context).
# Detection order: Windows (PowerShell) > macOS (osascript) > Linux (zenity/kdialog) > terminal (read -s)
# Usage: _get-secrets-password ["Prompt text"]
_get-secrets-password() {
    if [ -n "$SECRETS_MASTER_PASSWORD" ]; then
        printf '%s\n' "$SECRETS_MASTER_PASSWORD"
        return 0
    fi
    local prompt="${1:-Enter secrets password:}"
    local pw os
    os="$(uname -s 2>/dev/null || echo unknown)"

    case "$os" in
        # Windows under Git Bash, MSYS, Cygwin. The prompt is passed through an env var
        # so it cannot break out of the PowerShell script.
        MINGW*|MSYS*|CYGWIN*|Windows_NT)
            pw=$(SM_PROMPT="$prompt" powershell -NoProfile -Command '
                Add-Type -AssemblyName System.Windows.Forms
                $form = New-Object System.Windows.Forms.Form
                $form.Text = "Secrets Password"
                $form.Size = New-Object System.Drawing.Size(350,150)
                $form.StartPosition = "CenterScreen"
                $form.TopMost = $true
                $label = New-Object System.Windows.Forms.Label
                $label.Text = $env:SM_PROMPT
                $label.Location = New-Object System.Drawing.Point(10,15)
                $label.Size = New-Object System.Drawing.Size(310,20)
                $form.Controls.Add($label)
                $box = New-Object System.Windows.Forms.TextBox
                $box.UseSystemPasswordChar = $true
                $box.Location = New-Object System.Drawing.Point(10,40)
                $box.Size = New-Object System.Drawing.Size(310,20)
                $form.Controls.Add($box)
                $btn = New-Object System.Windows.Forms.Button
                $btn.Text = "OK"
                $btn.Location = New-Object System.Drawing.Point(130,70)
                $btn.DialogResult = [System.Windows.Forms.DialogResult]::OK
                $form.AcceptButton = $btn
                $form.Controls.Add($btn)
                $form.Add_Shown({ $box.Focus() })
                $result = $form.ShowDialog()
                if ($result -eq [System.Windows.Forms.DialogResult]::OK) {
                    Write-Output $box.Text
                }
                $form.Dispose()
            ' 2>/dev/null)
            pw="${pw%$'\r'}"
            ;;

        # macOS: AppleScript, prompt passed as an argument
        Darwin)
            pw=$(osascript - "$prompt" 2>/dev/null <<'APPLESCRIPT'
on run argv
    tell application "System Events"
        activate
        set p to text returned of (display dialog (item 1 of argv) default answer "" with title "Secrets Password" with hidden answer)
    end tell
    return p
end run
APPLESCRIPT
)
            ;;

        # Linux: zenity, then kdialog, then a silent terminal read
        Linux)
            if command -v zenity >/dev/null 2>&1; then
                pw=$(zenity --password --title="Secrets Password" 2>/dev/null)
            elif command -v kdialog >/dev/null 2>&1; then
                pw=$(kdialog --title "Secrets Password" --password "$prompt" 2>/dev/null)
            elif [ -t 0 ]; then
                echo -n "$prompt " >&2
                read -rs pw
                echo "" >&2
            else
                echo "Error: no GUI dialog available (install zenity or kdialog) and no interactive terminal." >&2
                return 1
            fi
            ;;

        *)
            if [ -t 0 ]; then
                echo -n "$prompt " >&2
                read -rs pw
                echo "" >&2
            else
                echo "Error: unsupported OS '$os' and no interactive terminal." >&2
                return 1
            fi
            ;;
    esac

    printf '%s\n' "$pw"
}

# Ask for a NEW password twice (typo protection when creating or re-keying a vault).
_sm-new-password() {
    local p1 p2
    p1=$(_get-secrets-password "Choose a secrets password:") || return 1
    [ -z "$p1" ] && return 1
    p2=$(_get-secrets-password "Confirm the secrets password:") || return 1
    if [ "$p1" != "$p2" ]; then
        echo -e "${RED}Passwords do not match.${NC}" >&2
        return 1
    fi
    printf '%s\n' "$p1"
}

# Export KEY=VALUE lines from $1 into the current shell. Sets _SM_COUNT.
_sm-export-lines() {
    local line key value
    _SM_COUNT=0
    while IFS= read -r line; do
        line="${line%$'\r'}"
        [[ "$line" =~ ^[[:space:]]*# ]] && continue
        [[ -z "${line//[[:space:]]/}" ]] && continue
        key="${line%%=*}"
        key="${key#"${key%%[![:space:]]*}"}"   # trim leading whitespace
        value="${line#*=}"
        _sm-valid-key "$key" || continue
        # Remove one pair of surrounding quotes, if present
        if [[ "$value" == \"*\" && ${#value} -ge 2 ]] || [[ "$value" == \'*\' && ${#value} -ge 2 ]]; then
            value="${value:1:${#value}-2}"
        fi
        export "$key=$value"
        _SM_COUNT=$((_SM_COUNT + 1))
    # Process substitution, not a here-string: older Bash writes here-strings to a temp file.
    done < <(printf '%s\n' "$1")
}

# Upsert KEY=VALUE into plaintext $1, print the result.
_sm-upsert() {
    local text="$1" key="$2" value="$3" updated
    updated=$(printf '%s\n' "$text" | grep -v "^${key}=")
    local custom_hdr="# Custom secrets (added via add-secret/add-secret-gui)"
    if ! printf '%s\n' "$updated" | grep -qF "$custom_hdr"; then
        updated="${updated}"$'\n\n'"${custom_hdr}"
    fi
    printf '%s\n%s=%s\n' "$updated" "$key" "$value"
}

# ---------------------------------------------------------------------------
# Manual flow: plaintext file on disk between unlock and lock
# ---------------------------------------------------------------------------

unlock-secrets() {
    _sm-paths
    if [ -f "$SECRETS_FILE" ]; then
        echo -e "${YELLOW}Warning: $SECRETS_FILE already exists and is unlocked.${NC}"
        read -r -p "Re-decrypt and overwrite it? (y/N): " confirm
        [[ "$confirm" =~ ^[Yy]$ ]] || { echo "Aborted."; return 1; }
    fi
    if [ ! -f "$ENCRYPTED_FILE" ]; then
        echo -e "${RED}Error: $ENCRYPTED_FILE not found.${NC}"
        echo "Create one with lock-secrets (from a plaintext secrets.env) or add-secret-gui."
        return 1
    fi

    local password decrypted
    password=$(_get-secrets-password) || return 1
    [ -z "$password" ] && { echo -e "${RED}No password provided.${NC}"; return 1; }

    if decrypted=$(_sm-decrypt "$ENCRYPTED_FILE" "$password"); then
        ( umask 077; printf '%s\n' "$decrypted" > "$SECRETS_FILE" )
        echo -e "${GREEN}Secrets unlocked: $SECRETS_FILE${NC}"
        echo -e "${YELLOW}Plaintext is on disk. Run lock-secrets when you are done.${NC}"
    else
        echo -e "${RED}Failed to decrypt. Wrong password or corrupted file.${NC}"
        return 1
    fi
}

lock-secrets() {
    _sm-paths
    if [ ! -f "$SECRETS_FILE" ]; then
        echo -e "${RED}Error: $SECRETS_FILE not found. Nothing to lock.${NC}"
        return 1
    fi
    if ! _sm-is-env-text "$(cat "$SECRETS_FILE")"; then
        echo -e "${RED}Error: $SECRETS_FILE has lines that are not KEY=VALUE, comments or blank.${NC}"
        return 1
    fi
    if [ -f "$ENCRYPTED_FILE" ]; then
        echo -e "${YELLOW}$ENCRYPTED_FILE already exists.${NC}"
        read -r -p "Overwrite it with the contents of $SECRETS_FILE? (y/N): " confirm
        [[ "$confirm" =~ ^[Yy]$ ]] || { echo "Aborted. Your secrets remain unlocked."; return 1; }
    fi

    local password
    password=$(_sm-new-password) || { echo -e "${RED}No password set. Aborted.${NC}"; return 1; }

    if _sm-encrypt "$password" "$ENCRYPTED_FILE" < "$SECRETS_FILE"; then
        shred -u "$SECRETS_FILE" 2>/dev/null || rm -f "$SECRETS_FILE"
        echo -e "${GREEN}Secrets encrypted to $ENCRYPTED_FILE; plaintext deleted.${NC}"
    else
        echo -e "${RED}Failed to encrypt.${NC}"
        return 1
    fi
}

toggle-secrets() {
    _sm-paths
    if [ -f "$SECRETS_FILE" ]; then lock-secrets; else unlock-secrets; fi
}

# Load an already-unlocked plaintext file into env vars.
load-secrets() {
    _sm-paths
    if [ ! -f "$SECRETS_FILE" ]; then
        echo -e "${RED}Error: $SECRETS_FILE not found. Use load-secrets-secure instead.${NC}"
        return 1
    fi
    _sm-export-lines "$(cat "$SECRETS_FILE")"
    echo -e "${GREEN}Loaded $_SM_COUNT secrets into the environment.${NC}"
}

# ---------------------------------------------------------------------------
# Memory-only flow (recommended)
# ---------------------------------------------------------------------------

# Decrypt into env vars of the current shell. Plaintext never touches disk.
load-secrets-secure() {
    _sm-paths
    if [ ! -f "$ENCRYPTED_FILE" ]; then
        echo -e "${RED}Error: $ENCRYPTED_FILE not found (set SECRETS_DIR?).${NC}"
        return 1
    fi

    echo "Requesting password..."
    local password decrypted
    password=$(_get-secrets-password) || return 1
    [ -z "$password" ] && { echo -e "${RED}No password provided.${NC}"; return 1; }

    if ! decrypted=$(_sm-decrypt "$ENCRYPTED_FILE" "$password"); then
        echo -e "${RED}Failed to decrypt. Wrong password?${NC}"
        return 1
    fi
    _sm-export-lines "$decrypted"
    echo -e "${GREEN}Loaded $_SM_COUNT secrets into the environment (never written to disk).${NC}"
}

# For a long-running process, load then exec so the child inherits the env vars:
#
#   source secrets-manager.sh && load-secrets-secure && exec <your command>
#
# See examples/start-secure.sh.

# Add or update a secret. Decrypts to memory, updates, re-encrypts.
# Note: VALUE is visible in shell history and the process list. Prefer add-secret-gui.
# Usage: add-secret KEY VALUE
add-secret() {
    _sm-paths
    if [ $# -ne 2 ]; then
        echo -e "${RED}Usage: add-secret KEY VALUE${NC}"
        return 1
    fi
    local key="$1" value="$2"
    _sm-valid-key "$key" || { echo -e "${RED}Invalid key name '$key' (use A-Z, 0-9, _).${NC}"; return 1; }
    [[ "$value" == *$'\n'* ]] && { echo -e "${RED}Values cannot contain newlines.${NC}"; return 1; }

    local password decrypted=""
    if [ ! -f "$ENCRYPTED_FILE" ]; then
        echo "No vault yet; creating $ENCRYPTED_FILE."
        password=$(_sm-new-password) || { echo -e "${RED}No password set.${NC}"; return 1; }
    else
        password=$(_get-secrets-password) || return 1
        [ -z "$password" ] && { echo -e "${RED}No password provided.${NC}"; return 1; }
        if ! decrypted=$(_sm-decrypt "$ENCRYPTED_FILE" "$password"); then
            echo -e "${RED}Failed to decrypt. Wrong password?${NC}"
            return 1
        fi
    fi

    if _sm-upsert "$decrypted" "$key" "$value" | _sm-encrypt "$password" "$ENCRYPTED_FILE"; then
        echo -e "${GREEN}Secret '$key' added/updated and re-encrypted.${NC}"
    else
        echo -e "${RED}Failed to re-encrypt.${NC}"
        return 1
    fi
}

# GUI form for a new secret: name + value + confirm value.
# Prints "KEY=VALUE" if the user confirms with matching values, nothing on cancel/mismatch.
_get-new-secret-input() {
    local result os
    os="$(uname -s 2>/dev/null || echo unknown)"

    case "$os" in
        MINGW*|MSYS*|CYGWIN*|Windows_NT)
            result=$(powershell -NoProfile -Command '
                Add-Type -AssemblyName System.Windows.Forms
                Add-Type -AssemblyName System.Drawing

                while ($true) {
                    $form = New-Object System.Windows.Forms.Form
                    $form.Text = "Add New Secret"
                    $form.Size = New-Object System.Drawing.Size(380,260)
                    $form.StartPosition = "CenterScreen"
                    $form.TopMost = $true
                    $form.FormBorderStyle = "FixedDialog"
                    $form.MaximizeBox = $false
                    $form.MinimizeBox = $false

                    $lblName = New-Object System.Windows.Forms.Label
                    $lblName.Text = "Secret Name (e.g. MY_API_KEY):"
                    $lblName.Location = New-Object System.Drawing.Point(15,15)
                    $lblName.Size = New-Object System.Drawing.Size(340,18)
                    $form.Controls.Add($lblName)

                    $boxName = New-Object System.Windows.Forms.TextBox
                    $boxName.Location = New-Object System.Drawing.Point(15,35)
                    $boxName.Size = New-Object System.Drawing.Size(340,22)
                    $boxName.CharacterCasing = "Upper"
                    $form.Controls.Add($boxName)

                    $lblVal = New-Object System.Windows.Forms.Label
                    $lblVal.Text = "Secret Value:"
                    $lblVal.Location = New-Object System.Drawing.Point(15,68)
                    $lblVal.Size = New-Object System.Drawing.Size(340,18)
                    $form.Controls.Add($lblVal)

                    $boxVal = New-Object System.Windows.Forms.TextBox
                    $boxVal.UseSystemPasswordChar = $true
                    $boxVal.Location = New-Object System.Drawing.Point(15,88)
                    $boxVal.Size = New-Object System.Drawing.Size(340,22)
                    $form.Controls.Add($boxVal)

                    $lblConf = New-Object System.Windows.Forms.Label
                    $lblConf.Text = "Confirm Value:"
                    $lblConf.Location = New-Object System.Drawing.Point(15,121)
                    $lblConf.Size = New-Object System.Drawing.Size(340,18)
                    $form.Controls.Add($lblConf)

                    $boxConf = New-Object System.Windows.Forms.TextBox
                    $boxConf.UseSystemPasswordChar = $true
                    $boxConf.Location = New-Object System.Drawing.Point(15,141)
                    $boxConf.Size = New-Object System.Drawing.Size(340,22)
                    $form.Controls.Add($boxConf)

                    $btnOk = New-Object System.Windows.Forms.Button
                    $btnOk.Text = "Save"
                    $btnOk.Location = New-Object System.Drawing.Point(180,180)
                    $btnOk.Size = New-Object System.Drawing.Size(80,28)
                    $btnOk.DialogResult = [System.Windows.Forms.DialogResult]::OK
                    $form.AcceptButton = $btnOk
                    $form.Controls.Add($btnOk)

                    $btnCancel = New-Object System.Windows.Forms.Button
                    $btnCancel.Text = "Cancel"
                    $btnCancel.Location = New-Object System.Drawing.Point(275,180)
                    $btnCancel.Size = New-Object System.Drawing.Size(80,28)
                    $btnCancel.DialogResult = [System.Windows.Forms.DialogResult]::Cancel
                    $form.CancelButton = $btnCancel
                    $form.Controls.Add($btnCancel)

                    $form.Add_Shown({ $boxName.Focus() })
                    $r = $form.ShowDialog()

                    if ($r -ne [System.Windows.Forms.DialogResult]::OK) {
                        $form.Dispose()
                        return
                    }

                    $name = $boxName.Text.Trim()
                    $v1 = $boxVal.Text
                    $v2 = $boxConf.Text
                    $form.Dispose()

                    if ([string]::IsNullOrEmpty($name)) {
                        [System.Windows.Forms.MessageBox]::Show("Secret name cannot be empty.", "Error", "OK", "Error") | Out-Null
                        continue
                    }
                    if ($name -notmatch "^[A-Za-z_][A-Za-z0-9_]*$") {
                        [System.Windows.Forms.MessageBox]::Show("Secret name must start with a letter or underscore and contain only letters, numbers, and underscores.", "Error", "OK", "Error") | Out-Null
                        continue
                    }
                    if ($v1 -ne $v2) {
                        [System.Windows.Forms.MessageBox]::Show("Values do not match. Please try again.", "Error", "OK", "Error") | Out-Null
                        continue
                    }
                    if ([string]::IsNullOrEmpty($v1)) {
                        [System.Windows.Forms.MessageBox]::Show("Secret value cannot be empty.", "Error", "OK", "Error") | Out-Null
                        continue
                    }

                    Write-Output "$name=$v1"
                    return
                }
            ' 2>/dev/null)
            result="${result%$'\r'}"
            ;;

        Darwin)
            local name v1 v2
            name=$(osascript -e 'tell application "System Events"
                activate
                set theName to text returned of (display dialog "Secret Name (e.g. MY_API_KEY):" default answer "" with title "Add New Secret")
            end tell' 2>/dev/null)
            [ -z "$name" ] && return
            _sm-valid-key "$name" || { echo "Error: invalid secret name." >&2; return 1; }
            v1=$(osascript -e "tell application \"System Events\"
                activate
                set theVal to text returned of (display dialog \"Enter value for $name:\" default answer \"\" with title \"Add New Secret\" with hidden answer)
            end tell" 2>/dev/null)
            [ -z "$v1" ] && return
            v2=$(osascript -e "tell application \"System Events\"
                activate
                set theVal to text returned of (display dialog \"Confirm value for $name:\" default answer \"\" with title \"Add New Secret\" with hidden answer)
            end tell" 2>/dev/null)
            if [ "$v1" != "$v2" ]; then
                osascript -e 'display dialog "Values do not match." with title "Error" buttons {"OK"}' >/dev/null 2>&1
                return
            fi
            result="$name=$v1"
            ;;

        Linux)
            if command -v zenity >/dev/null 2>&1; then
                local form_out name v1 v2
                form_out=$(zenity --forms --title="Add New Secret" \
                    --text="Enter secret details" \
                    --add-entry="Secret Name (e.g. MY_API_KEY)" \
                    --add-password="Value" \
                    --add-password="Confirm Value" \
                    --separator=$'\x1f' 2>/dev/null)
                [ -z "$form_out" ] && return
                # Unit separator: cannot be typed into the form, so values may contain any text.
                IFS=$'\x1f' read -r name v1 v2 < <(printf '%s\n' "$form_out")
                if [ -z "$name" ]; then
                    zenity --error --text="Secret name cannot be empty." 2>/dev/null
                    return
                fi
                if [ "$v1" != "$v2" ]; then
                    zenity --error --text="Values do not match." 2>/dev/null
                    return
                fi
                result="$name=$v1"
            else
                echo "Error: zenity not installed (e.g. sudo apt install zenity)." >&2
                return 1
            fi
            ;;

        *)
            echo "Error: unsupported OS '$os' for GUI input. Use add-secret KEY VALUE." >&2
            return 1
            ;;
    esac

    printf '%s\n' "$result"
}

# Add a secret through GUI popups only: master password, then name / value / confirm.
# The value never appears in shell history, terminal output or an AI agent's context.
add-secret-gui() {
    _sm-paths
    local password decrypted=""
    if [ ! -f "$ENCRYPTED_FILE" ]; then
        echo "No vault at $ENCRYPTED_FILE yet; creating one."
        password=$(_sm-new-password) || { echo -e "${RED}No password set.${NC}"; return 1; }
    else
        echo "Requesting master password..."
        password=$(_get-secrets-password) || return 1
        [ -z "$password" ] && { echo -e "${RED}No password provided.${NC}"; return 1; }

        # Verify the password first, so the form does not open on a bad password
        if ! decrypted=$(_sm-decrypt "$ENCRYPTED_FILE" "$password"); then
            echo -e "${RED}Failed to decrypt. Wrong password?${NC}"
            return 1
        fi
    fi

    echo "Opening secret entry form..."
    local entry
    entry=$(_get-new-secret-input)
    if [ -z "$entry" ]; then
        echo -e "${YELLOW}Cancelled. No secret added.${NC}"
        return 1
    fi

    local key="${entry%%=*}"
    local value="${entry#*=}"
    if ! _sm-valid-key "$key" || [ -z "$value" ]; then
        echo -e "${RED}Invalid entry from form.${NC}"
        return 1
    fi

    if printf '%s\n' "$decrypted" | grep -q "^${key}="; then
        echo -e "${YELLOW}Note: '$key' already exists and will be overwritten.${NC}"
    fi

    if _sm-upsert "$decrypted" "$key" "$value" | _sm-encrypt "$password" "$ENCRYPTED_FILE"; then
        echo -e "${GREEN}Secret '$key' added/updated and re-encrypted.${NC}"
    else
        echo -e "${RED}Failed to re-encrypt.${NC}"
        return 1
    fi
}

# Remove a secret by key name.  Usage: remove-secret KEY
remove-secret() {
    _sm-paths
    if [ $# -ne 1 ]; then
        echo -e "${RED}Usage: remove-secret KEY${NC}"
        return 1
    fi
    local key="$1"
    _sm-valid-key "$key" || { echo -e "${RED}Invalid key name '$key'.${NC}"; return 1; }
    if [ ! -f "$ENCRYPTED_FILE" ]; then
        echo -e "${RED}Error: $ENCRYPTED_FILE not found.${NC}"
        return 1
    fi

    echo "Requesting password..."
    local password decrypted
    password=$(_get-secrets-password) || return 1
    [ -z "$password" ] && { echo -e "${RED}No password provided.${NC}"; return 1; }

    if ! decrypted=$(_sm-decrypt "$ENCRYPTED_FILE" "$password"); then
        echo -e "${RED}Failed to decrypt. Wrong password?${NC}"
        return 1
    fi
    if ! printf '%s\n' "$decrypted" | grep -q "^${key}="; then
        echo -e "${YELLOW}Key '$key' not found in secrets.${NC}"
        return 1
    fi

    if printf '%s\n' "$decrypted" | grep -v "^${key}=" | _sm-encrypt "$password" "$ENCRYPTED_FILE"; then
        echo -e "${GREEN}Secret '$key' removed and re-encrypted.${NC}"
    else
        echo -e "${RED}Failed to re-encrypt.${NC}"
        return 1
    fi
}

# Change the vault password (and upgrade a legacy vault to the current KDF settings).
rekey-secrets() {
    _sm-paths
    [ -f "$ENCRYPTED_FILE" ] || { echo -e "${RED}Error: $ENCRYPTED_FILE not found.${NC}"; return 1; }
    local old new decrypted
    old=$(_get-secrets-password "Current secrets password:") || return 1
    if ! decrypted=$(_sm-decrypt "$ENCRYPTED_FILE" "$old"); then
        echo -e "${RED}Failed to decrypt. Wrong password?${NC}"
        return 1
    fi
    new=$(SECRETS_MASTER_PASSWORD="" _sm-new-password) || { echo -e "${RED}Aborted.${NC}"; return 1; }
    if printf '%s\n' "$decrypted" | _sm-encrypt "$new" "$ENCRYPTED_FILE"; then
        echo -e "${GREEN}Vault re-encrypted with the new password.${NC}"
    else
        echo -e "${RED}Failed to re-encrypt.${NC}"
        return 1
    fi
}

# ---------------------------------------------------------------------------
# Secrets agent: one popup per session, category-scoped (see secrets-agent.ts)
# ---------------------------------------------------------------------------

_sm-agent() {
    SECRETS_DIR="${SECRETS_DIR:-$HOME}" SECRETS_AGENT_DIR="$AGENT_DIR" bun "$AGENT_SCRIPT" "$@"
}

# Wrapper: secrets-agent <start|stop|status|list [PREFIX]>
secrets-agent() {
    _sm-paths
    if [ ! -f "$AGENT_SCRIPT" ]; then
        echo -e "${RED}Error: $AGENT_SCRIPT not found.${NC}"
        return 1
    fi
    if ! command -v bun >/dev/null 2>&1; then
        echo -e "${RED}Error: bun runtime not found. Install from https://bun.sh${NC}"
        return 1
    fi

    local subcmd="${1:-status}"

    if [ "$subcmd" = "start" ]; then
        if _sm-agent status >/dev/null 2>&1; then
            echo -e "${GREEN}Agent already running.${NC}"
            _sm-agent status
            return 0
        fi

        # Spawn the daemon in the background; its output goes to a log file.
        local log_file="$AGENT_DIR/agent.log"
        mkdir -p "$AGENT_DIR" 2>/dev/null
        chmod 700 "$AGENT_DIR" 2>/dev/null
        nohup env SECRETS_DIR="${SECRETS_DIR:-$HOME}" SECRETS_AGENT_DIR="$AGENT_DIR" \
            bun "$AGENT_SCRIPT" start > "$log_file" 2>&1 &
        disown 2>/dev/null

        # Wait for the password popup to be answered (up to 90 s). info.json is written
        # only after a successful decrypt, so its presence means the password was right.
        local info_file="$AGENT_DIR/info.json"
        echo "Waiting for password entry (a popup should be visible)..."
        local waited=0
        while [ $waited -lt 90 ]; do
            if [ -f "$info_file" ] && _sm-agent status >/dev/null 2>&1; then
                echo -e "${GREEN}Secrets agent started.${NC}"
                _sm-agent status
                return 0
            fi
            sleep 1
            waited=$((waited + 1))
        done

        echo -e "${RED}Timed out waiting for the agent (90 s). Check $log_file${NC}"
        return 1
    fi

    _sm-agent "$@"
}

# Load secrets via the agent (auto-starts it). Values go straight from the agent into
# env vars through $(...) + eval and are never printed.
#   load-secrets-from-agent          keys in categories already unlocked this session
#   load-secrets-from-agent --bulk   one popup unlocks bulk_categories and loads them
load-secrets-from-agent() {
    _sm-paths
    if [ ! -f "$AGENT_SCRIPT" ] || ! command -v bun >/dev/null 2>&1; then
        echo -e "${YELLOW}Agent unavailable; falling back to load-secrets-secure.${NC}"
        load-secrets-secure
        return $?
    fi

    if ! _sm-agent status >/dev/null 2>&1; then
        echo "Agent not running; starting it (password popup)..."
        secrets-agent start || return 1
    fi

    local mode="dump"
    if [ "${1:-}" = "--bulk" ] || [ "${1:-}" = "--all" ]; then
        mode="dump-all"
    fi

    # SECRETS_AGENT_INTERNAL=1 tells the agent CLI that its stdout is being captured.
    local export_lines
    export_lines=$(SECRETS_AGENT_INTERNAL=1 _sm-agent "$mode" 2>/dev/null)
    if [ -z "$export_lines" ]; then
        echo -e "${YELLOW}No keys returned from agent (no categories unlocked yet?).${NC}"
        echo "Try: load-secrets-from-agent --bulk"
        return 1
    fi

    eval "$export_lines"
    local count
    count=$(printf '%s\n' "$export_lines" | grep -c '^export ')
    echo -e "${GREEN}Loaded $count secrets from agent.${NC}"
}

show-secrets-help() {
    _sm-paths
    echo "Secrets Manager commands"
    echo ""
    echo "Agent (one popup per session, category-scoped):"
    echo "  secrets-agent start              Start the agent (master password popup)"
    echo "  secrets-agent status             Running state, idle time, unlocked categories"
    echo "  secrets-agent list [PREFIX]      Key names and categories (never values)"
    echo "  secrets-agent stop               Stop the agent (forces re-auth on next use)"
    echo "  load-secrets-from-agent          Load unlocked keys into env vars"
    echo "  load-secrets-from-agent --bulk   One popup, load bulk_categories"
    echo ""
    echo "Direct (no agent, popup every time):"
    echo "  load-secrets-secure              Decrypt to env vars in memory only"
    echo ""
    echo "Manage the vault:"
    echo "  add-secret-gui                   GUI form: name + value + confirm value"
    echo "  add-secret KEY VALUE             CLI version (value visible in shell history)"
    echo "  remove-secret KEY                Remove a secret"
    echo "  rekey-secrets                    Change the password / upgrade KDF settings"
    echo "  unlock-secrets / lock-secrets    Manual flow via a plaintext file"
    echo "  toggle-secrets                   Lock if unlocked, unlock if locked"
    echo ""
    echo "Vault: $ENCRYPTED_FILE"
    if [ -f "$SECRETS_FILE" ]; then
        echo -e "  ${YELLOW}UNLOCKED${NC} - $SECRETS_FILE exists (plaintext on disk)"
    else
        echo -e "  ${GREEN}LOCKED${NC}"
    fi
    if [ -f "$AGENT_SCRIPT" ] && command -v bun >/dev/null 2>&1; then
        if _sm-agent status >/dev/null 2>&1; then
            echo -e "  ${GREEN}AGENT RUNNING${NC}"
        else
            echo -e "  ${YELLOW}Agent not running${NC} (run: secrets-agent start)"
        fi
    fi
}

if [ -z "${SECRETS_MANAGER_QUIET:-}" ]; then
    echo -e "${GREEN}Secrets Manager loaded.${NC} Run show-secrets-help for commands."
fi
