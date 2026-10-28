#!/usr/bin/env bun
/**
 * Secrets Agent: like ssh-agent, but for an encrypted .env vault.
 *
 * Holds decrypted secrets in memory after one master-password entry, so later
 * commands across separate shell invocations (for example, each Bash tool call
 * an AI coding agent makes) do not re-prompt. Enforces category scoping: the
 * first request for a key in a new category triggers a fresh password popup.
 *
 * Architecture:
 *   - HTTP on 127.0.0.1, random port (same code path on Windows, macOS, Linux)
 *   - Every request carries a random 256-bit token read from info.json (mode 600)
 *   - Decrypted secrets live in process memory only: never on disk, never logged
 *   - The master password is kept only as a salted scrypt hash, for re-auth checks
 *   - Idle timeout: the process exits and the secrets are gone
 *
 * Commands:
 *   bun secrets-agent.ts start          pop up master password, run the daemon
 *   bun secrets-agent.ts status         running state, idle time, unlocked categories
 *   bun secrets-agent.ts list [PREFIX]  key names + categories (never values)
 *   bun secrets-agent.ts stop           shut down the daemon
 *   get / dump / dump-all               internal; print export lines for the bash wrapper
 *
 * Environment:
 *   SECRETS_DIR              vault directory (default: home). Vault = $SECRETS_DIR/secrets.env.enc
 *   SECRETS_CATEGORIES       categories file (default: $SECRETS_DIR/secrets-categories.json)
 *   SECRETS_AGENT_DIR        runtime dir for info.json / pid (default: ~/.secrets-agent)
 *   SECRETS_AGENT_TTL_MS     idle timeout in ms (default: 8 hours)
 *   SECRETS_MASTER_PASSWORD  optional non-interactive password for `start` (unattended hosts)
 *
 * Caveats (same as any user-space credential store):
 *   - Process memory is readable by a debugger or same-user malware
 *   - Memory pages can be swapped to disk; use full-disk encryption
 *   - Anyone who can read info.json (same user) can query the agent
 */

import { spawnSync } from 'child_process';
import { existsSync, readFileSync, writeFileSync, unlinkSync, chmodSync, mkdirSync } from 'fs';
import { homedir, platform } from 'os';
import { join, resolve } from 'path';
import { randomBytes, scryptSync, timingSafeEqual } from 'crypto';

// ─── Paths ──────────────────────────────────────────────────────────────

const SECRETS_DIR = process.env.SECRETS_DIR || homedir();
const AGENT_DIR = process.env.SECRETS_AGENT_DIR || join(homedir(), '.secrets-agent');
const INFO_FILE = join(AGENT_DIR, 'info.json');   // port + token, mode 600
const PID_FILE = join(AGENT_DIR, 'pid');
const CATEGORIES_FILE = process.env.SECRETS_CATEGORIES || join(SECRETS_DIR, 'secrets-categories.json');

function expandPath(p: string): string {
  if (p === '~' || p.startsWith('~/') || p.startsWith('~\\')) return join(homedir(), p.slice(1));
  return resolve(SECRETS_DIR, p);
}

function findEncryptedFile(): string {
  const file = join(SECRETS_DIR, 'secrets.env.enc');
  if (!existsSync(file)) {
    console.error(`Error: ${file} not found (set SECRETS_DIR to the folder holding your vault).`);
    process.exit(1);
  }
  return file;
}

// ─── Categories ─────────────────────────────────────────────────────────

interface CategoriesConfig {
  categories: Record<string, string[]>;  // name -> glob patterns (* wildcard, case-insensitive)
  default_category: string;
  bulk_categories?: string[];            // unlocked together by `load-secrets-from-agent --bulk`
  extra_files?: string[];                // more vaults merged at start; first file wins on duplicates
}

const DEFAULT_CATEGORIES: CategoriesConfig = {
  categories: {
    ai:       ['OPENAI_*', 'ANTHROPIC_*', 'GEMINI_*', 'MISTRAL_*'],
    payments: ['STRIPE_*', 'PAYPAL_*'],
    dev:      ['GITHUB_*', 'NPM_TOKEN', 'DATABASE_URL', 'REDIS_URL'],
    cloud:    ['AWS_*', 'AZURE_*', 'GCP_*', 'CLOUDFLARE_*'],
    email:    ['SMTP_*', 'SENDGRID_*', 'RESEND_*'],
    keys:     ['*PRIVATE_KEY*', '*_SECRET_KEY', '*MNEMONIC*'],
  },
  default_category: 'other',
  bulk_categories: ['ai', 'dev'],
};

function loadCategories(): CategoriesConfig {
  if (existsSync(CATEGORIES_FILE)) {
    try {
      return JSON.parse(readFileSync(CATEGORIES_FILE, 'utf-8'));
    } catch {
      console.error(`Warning: failed to parse ${CATEGORIES_FILE}, using defaults`);
    }
  }
  return DEFAULT_CATEGORIES;
}

function categorize(key: string, config: CategoriesConfig): string {
  for (const [cat, patterns] of Object.entries(config.categories)) {
    for (const pat of patterns) {
      const escaped = pat.replace(/[.+?^${}()|[\]\\]/g, '\\$&').replace(/\*/g, '.*');
      if (new RegExp('^' + escaped + '$', 'i').test(key)) return cat;
    }
  }
  return config.default_category;
}

// ─── Password popup (cross-platform) ────────────────────────────────────

function getPasswordViaPopup(prompt: string = 'Enter secrets password:'): string {
  const os = platform();
  let pw = '';
  try {
    if (os === 'win32') {
      // The prompt is passed through an environment variable, not spliced into the script.
      const ps = `
Add-Type -AssemblyName System.Windows.Forms
$f = New-Object System.Windows.Forms.Form
$f.Text = 'Secrets Agent'
$f.Size = New-Object System.Drawing.Size(380,150)
$f.StartPosition = 'CenterScreen'
$f.TopMost = $true
$f.FormBorderStyle = 'FixedDialog'
$l = New-Object System.Windows.Forms.Label
$l.Text = $env:SM_PROMPT
$l.Location = New-Object System.Drawing.Point(15,15)
$l.Size = New-Object System.Drawing.Size(340,18)
$f.Controls.Add($l)
$b = New-Object System.Windows.Forms.TextBox
$b.UseSystemPasswordChar = $true
$b.Location = New-Object System.Drawing.Point(15,38)
$b.Size = New-Object System.Drawing.Size(340,22)
$f.Controls.Add($b)
$ok = New-Object System.Windows.Forms.Button
$ok.Text = 'OK'
$ok.Location = New-Object System.Drawing.Point(280,72)
$ok.DialogResult = [System.Windows.Forms.DialogResult]::OK
$f.AcceptButton = $ok
$f.Controls.Add($ok)
$f.Add_Shown({ $b.Focus() })
if ($f.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) { Write-Output $b.Text }
$f.Dispose()
`;
      const r = spawnSync('powershell', ['-NoProfile', '-Command', ps], {
        encoding: 'utf-8', env: { ...process.env, SM_PROMPT: prompt },
      });
      pw = (r.stdout || '').replace(/\r?\n$/, '');
    } else if (os === 'darwin') {
      const r = spawnSync('osascript', [
        '-e', 'on run argv',
        '-e', 'tell application "System Events"',
        '-e', 'activate',
        '-e', 'set p to text returned of (display dialog (item 1 of argv) default answer "" with title "Secrets Agent" with hidden answer)',
        '-e', 'end tell',
        '-e', 'return p',
        '-e', 'end run',
        prompt,
      ], { encoding: 'utf-8' });
      pw = (r.stdout || '').replace(/\r?\n$/, '');
    } else {
      let r = spawnSync('zenity', ['--password', '--title=Secrets Agent'], { encoding: 'utf-8' });
      if (r.status === 0) {
        pw = (r.stdout || '').replace(/\r?\n$/, '');
      } else {
        r = spawnSync('kdialog', ['--title', 'Secrets Agent', '--password', prompt], { encoding: 'utf-8' });
        pw = (r.stdout || '').replace(/\r?\n$/, '');
      }
    }
  } catch (e) {
    console.error('Password popup failed:', e);
  }
  return pw;
}

// ─── Decryption ─────────────────────────────────────────────────────────

// New vaults use 600,000 PBKDF2 iterations; vaults from openssl's old default (10,000) still open.
const KDF_ITERATIONS = [600000, 10000];
const KEY_RE = /^[A-Za-z_][A-Za-z0-9_]*$/;
const LINE_RE = /^\s*(#.*)?$|^\s*[A-Za-z_][A-Za-z0-9_]*=/;

function parseEnv(text: string): Map<string, string> | null {
  const map = new Map<string, string>();
  for (const raw of text.split(/\r?\n/)) {
    // Reject anything that is not KEY=VALUE / comment / blank. A wrong key occasionally
    // passes openssl's padding check and yields random bytes; this catches it.
    if (!LINE_RE.test(raw)) return null;
    const trimmed = raw.trim();
    if (!trimmed || trimmed.startsWith('#')) continue;
    const eq = trimmed.indexOf('=');
    const k = trimmed.slice(0, eq).trim();
    if (!KEY_RE.test(k)) continue;
    let v = trimmed.slice(eq + 1);
    if (v.length >= 2 && ((v.startsWith('"') && v.endsWith('"')) || (v.startsWith("'") && v.endsWith("'")))) {
      v = v.slice(1, -1);
    }
    map.set(k, v);
  }
  return map;
}

function decryptSecrets(encryptedFile: string, password: string): Map<string, string> | null {
  for (const iter of KDF_ITERATIONS) {
    // Password via env var, not argv, so it does not appear in process listings.
    const r = spawnSync('openssl', [
      'enc', '-aes-256-cbc', '-d', '-pbkdf2', '-iter', String(iter),
      '-in', encryptedFile, '-pass', 'env:SM_PASS',
    ], { encoding: 'utf-8', env: { ...process.env, SM_PASS: password } });
    if (r.status !== 0) continue;
    const map = parseEnv(r.stdout || '');
    if (map) return map;
  }
  return null;
}

// ─── Password verification (no plaintext password kept in state) ────────

function makeVerifier(password: string): (candidate: string) => boolean {
  const salt = randomBytes(16);
  const hash = scryptSync(password, salt, 32);
  return (candidate: string) => !!candidate && timingSafeEqual(scryptSync(candidate, salt, 32), hash);
}

// ─── Daemon state ───────────────────────────────────────────────────────

interface AgentState {
  secrets: Map<string, string>;
  verifyPassword: (candidate: string) => boolean;
  unlockedCategories: Set<string>;
  config: CategoriesConfig;
  lastAccess: number;
  authToken: string;
}

const IDLE_TTL_MS = parseInt(process.env.SECRETS_AGENT_TTL_MS || String(8 * 60 * 60 * 1000), 10);

function exportLine(k: string, v: string): string {
  return `export ${k}='${v.replace(/'/g, `'"'"'`)}'`;
}

function tokenMatches(given: unknown, expected: string): boolean {
  if (typeof given !== 'string' || given.length !== expected.length) return false;
  return timingSafeEqual(Buffer.from(given), Buffer.from(expected));
}

// ─── Server ─────────────────────────────────────────────────────────────

function startDaemon(state: AgentState, port: number): void {
  if (!existsSync(AGENT_DIR)) mkdirSync(AGENT_DIR, { recursive: true, mode: 0o700 });
  writeFileSync(INFO_FILE, JSON.stringify({ port, token: state.authToken }), { mode: 0o600 });
  try { chmodSync(INFO_FILE, 0o600); } catch {}
  writeFileSync(PID_FILE, String(process.pid), { mode: 0o600 });

  Bun.serve({
    port,
    hostname: '127.0.0.1',
    async fetch(req) {
      let body: any = {};
      try { body = await req.json(); } catch {}

      if (!tokenMatches(body.token, state.authToken)) {
        return Response.json({ error: 'invalid token' }, { status: 401 });
      }

      state.lastAccess = Date.now();
      const url = new URL(req.url);

      switch (url.pathname) {
        case '/status':
          return Response.json({
            running: true,
            pid: process.pid,
            idleMs: Date.now() - state.lastAccess,
            ttlMs: IDLE_TTL_MS,
            unlockedCategories: Array.from(state.unlockedCategories),
            keyCount: state.secrets.size,
          });

        case '/list-names': {
          // Key names + categories only, never values. Safe to show to an AI agent.
          const filter: string = body.prefix || '';
          const items: { key: string; category: string }[] = [];
          for (const k of state.secrets.keys()) {
            if (filter && !k.toLowerCase().startsWith(filter.toLowerCase())) continue;
            items.push({ key: k, category: categorize(k, state.config) });
          }
          return Response.json({ count: items.length, items });
        }

        case '/get': {
          const key: string = body.key;
          if (!key || !state.secrets.has(key)) {
            return Response.json({ error: 'key not found' }, { status: 404 });
          }
          const cat = categorize(key, state.config);
          if (!state.unlockedCategories.has(cat)) {
            const pw = getPasswordViaPopup(`New category "${cat}" - enter password to authorize:`);
            if (!state.verifyPassword(pw)) {
              return Response.json({ error: `category "${cat}" not authorized` }, { status: 403 });
            }
            state.unlockedCategories.add(cat);
          }
          return Response.json({ key, value: state.secrets.get(key), category: cat });
        }

        case '/unlock-category': {
          const cat: string = body.category;
          if (state.unlockedCategories.has(cat)) {
            return Response.json({ ok: true, alreadyUnlocked: true });
          }
          const pw = getPasswordViaPopup(`Unlock category "${cat}" - enter password:`);
          if (!state.verifyPassword(pw)) {
            return Response.json({ error: 'wrong password' }, { status: 403 });
          }
          state.unlockedCategories.add(cat);
          return Response.json({ ok: true });
        }

        case '/dump': {
          // Export lines for keys in categories already unlocked this session.
          const lines: string[] = [];
          for (const [k, v] of state.secrets) {
            if (state.unlockedCategories.has(categorize(k, state.config))) lines.push(exportLine(k, v));
          }
          return new Response(lines.join('\n') + '\n', { headers: { 'Content-Type': 'text/plain' } });
        }

        case '/dump-all': {
          // Bulk mode: one popup unlocks every bulk category (all categories if none are
          // configured), then returns the keys in those categories. Keys outside
          // bulk_categories still need their own unlock.
          const all = [...Object.keys(state.config.categories), state.config.default_category];
          const bulk = state.config.bulk_categories?.length ? state.config.bulk_categories : all;
          if (bulk.some(c => !state.unlockedCategories.has(c))) {
            const pw = getPasswordViaPopup('Bulk-load secrets - enter password:');
            if (!state.verifyPassword(pw)) {
              return Response.json({ error: 'wrong password' }, { status: 403 });
            }
            for (const c of bulk) state.unlockedCategories.add(c);
          }
          const lines: string[] = [];
          for (const [k, v] of state.secrets) {
            const cat = categorize(k, state.config);
            if (bulk.includes(cat) || state.unlockedCategories.has(cat)) lines.push(exportLine(k, v));
          }
          return new Response(lines.join('\n') + '\n', { headers: { 'Content-Type': 'text/plain' } });
        }

        case '/stop':
          setTimeout(() => { cleanup(); process.exit(0); }, 100);
          return Response.json({ ok: true, stopping: true });

        default:
          return new Response('not found', { status: 404 });
      }
    },
  });

  console.log(`Secrets agent started: PID ${process.pid}, listening on 127.0.0.1:${port}`);
  console.log(`Idle timeout: ${Math.round(IDLE_TTL_MS / 60000)} min`);

  setInterval(() => {
    if (Date.now() - state.lastAccess > IDLE_TTL_MS) {
      console.log('Idle timeout reached, exiting');
      cleanup();
      process.exit(0);
    }
  }, 60 * 1000);

  for (const sig of ['SIGINT', 'SIGTERM']) {
    process.on(sig as any, () => { cleanup(); process.exit(0); });
  }
}

function cleanup() {
  try { unlinkSync(INFO_FILE); } catch {}
  try { unlinkSync(PID_FILE); } catch {}
}

// ─── Client helpers ─────────────────────────────────────────────────────

async function callAgent(path: string, body: object = {}): Promise<any> {
  if (!existsSync(INFO_FILE)) return { error: 'agent not running' };
  let info: { port: number; token: string };
  try { info = JSON.parse(readFileSync(INFO_FILE, 'utf-8')); } catch { return { error: 'bad info file' }; }
  try {
    const res = await fetch(`http://127.0.0.1:${info.port}${path}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ ...body, token: info.token }),
    });
    // Read the body once, then try JSON (avoids "body already consumed").
    const text = await res.text();
    try { return JSON.parse(text); } catch { return text; }
  } catch (e: any) {
    return { error: `agent unreachable: ${e.message}` };
  }
}

async function isAgentRunning(): Promise<boolean> {
  if (!existsSync(INFO_FILE)) return false;
  const r = await callAgent('/status');
  return !!r && r.running === true;
}

// ─── CLI ────────────────────────────────────────────────────────────────

async function main() {
  const cmd = process.argv[2];

  if (cmd === 'start') {
    if (await isAgentRunning()) {
      console.log('Agent already running.');
      return;
    }
    const encryptedFile = findEncryptedFile();
    const config = loadCategories();

    // Re-ask on a wrong password instead of exiting; an empty entry (Cancel) aborts.
    const MAX_ATTEMPTS = 5;
    let password = '';
    let secrets: Map<string, string> | null = null;
    const unattended = process.env.SECRETS_MASTER_PASSWORD;
    if (unattended) {
      password = unattended;
      secrets = decryptSecrets(encryptedFile, password);
      if (!secrets) { console.error('SECRETS_MASTER_PASSWORD did not decrypt the vault.'); process.exit(1); }
    } else {
      for (let attempt = 1; attempt <= MAX_ATTEMPTS; attempt++) {
        const prompt = attempt === 1
          ? 'Enter secrets password:'
          : `Wrong password - try again (${attempt}/${MAX_ATTEMPTS}):`;
        password = getPasswordViaPopup(prompt);
        if (!password) { console.error('Password entry cancelled.'); process.exit(1); }
        secrets = decryptSecrets(encryptedFile, password);
        if (secrets) break;
        console.error(`Failed to decrypt: wrong password (attempt ${attempt}/${MAX_ATTEMPTS}).`);
      }
    }
    if (!secrets) { console.error(`Giving up after ${MAX_ATTEMPTS} failed password attempts.`); process.exit(1); }
    if (secrets.size === 0) { console.error('Decryption succeeded but no secrets found.'); process.exit(1); }

    // Extra vaults: merge every listed vault so the loaded set does not depend on the
    // directory the agent was started from. Keys already loaded win. Each vault is tried
    // with the master password first, then gets its own popup.
    for (const raw of config.extra_files ?? []) {
      const file = expandPath(raw);
      if (!existsSync(file) || resolve(file).toLowerCase() === resolve(encryptedFile).toLowerCase()) continue;
      let extra = decryptSecrets(file, password);
      if (!extra) {
        const pw = getPasswordViaPopup(`Password for ${file}:`);
        extra = pw ? decryptSecrets(file, pw) : null;
      }
      if (!extra) { console.error(`Could not open ${file}; continuing without it.`); continue; }
      let added = 0;
      for (const [k, v] of extra) if (!secrets.has(k)) { secrets.set(k, v); added++; }
      console.log(`Merged ${added} key(s) from ${file}.`);
    }

    const port = 30000 + Math.floor(Math.random() * 30000);
    const state: AgentState = {
      secrets,
      verifyPassword: makeVerifier(password),
      unlockedCategories: new Set(),
      config,
      lastAccess: Date.now(),
      authToken: randomBytes(32).toString('hex'),
    };
    password = '';
    startDaemon(state, port);
    return;
  }

  if (cmd === 'status') {
    const r = await callAgent('/status');
    if (!r || r.error) { console.log('Agent not running.'); process.exit(1); }
    console.log(`Running: PID ${r.pid}`);
    console.log(`Idle: ${Math.round(r.idleMs / 1000)}s / TTL ${Math.round(r.ttlMs / 1000)}s`);
    console.log(`Keys loaded: ${r.keyCount}`);
    console.log(`Unlocked categories: ${r.unlockedCategories.length ? r.unlockedCategories.join(', ') : '(none yet)'}`);
    return;
  }

  if (cmd === 'stop') {
    const r = await callAgent('/stop');
    if (!r || r.error) { console.log('Agent was not running.'); return; }
    console.log('Agent stopped.');
    return;
  }

  if (cmd === 'list' || cmd === 'list-names') {
    const prefix = process.argv[3] || '';
    const r = await callAgent('/list-names', { prefix });
    if (!r || r.error) { console.error('Error:', r?.error); process.exit(1); }
    if (r.count === 0) {
      console.log(prefix ? `No keys matching "${prefix}*"` : 'No keys loaded.');
      return;
    }
    console.log(prefix ? `Keys matching "${prefix}*":` : 'All loaded keys:');
    const padding = Math.max(...r.items.map((i: any) => i.key.length));
    for (const item of r.items) console.log(`  ${item.key.padEnd(padding)}   [${item.category}]`);
    console.log(`\nTotal: ${r.count} key${r.count === 1 ? '' : 's'}`);
    return;
  }

  // Internal commands used by the bash wrapper. They print secret VALUES to stdout,
  // meant to be captured by $(...) and eval'd. Run directly, they would print values to
  // the terminal or an AI agent's context, so they refuse unless SECRETS_AGENT_INTERNAL=1
  // (set by the wrapper) or --i-understand-this-leaks is passed.
  if (cmd === 'get' || cmd === 'dump' || cmd === 'dump-all') {
    const guarded = process.env.SECRETS_AGENT_INTERNAL === '1' ||
                    process.argv.includes('--i-understand-this-leaks');
    if (!guarded) {
      console.error(`Refusing to run "${cmd}" directly: its output contains secret values.`);
      console.error('Use the bash wrapper instead:');
      console.error('  source secrets-manager.sh && load-secrets-from-agent');
      process.exit(2);
    }

    if (cmd === 'get') {
      const key = process.argv[3];
      if (!key) { console.error('Usage: secrets-agent get KEY'); process.exit(1); }
      const r = await callAgent('/get', { key });
      if (!r || r.error) { console.error('Error:', r?.error); process.exit(1); }
      console.log(exportLine(r.key, r.value));
      return;
    }

    const r = await callAgent(cmd === 'dump-all' ? '/dump-all' : '/dump');
    if (typeof r === 'object' && r?.error) { console.error('Error:', r.error); process.exit(1); }
    process.stdout.write(typeof r === 'string' ? r : '');
    return;
  }

  console.log(`Usage: bun secrets-agent.ts <command>

Commands:
  start             Start the agent (master password popup)
  status            Show running state, idle time, unlocked categories
  list [PREFIX]     List key names and categories (never values)
  stop              Stop the agent (forces re-auth on next use)

To load secrets into a shell, use the bash wrapper. Never call get/dump directly:
they print secret values to stdout.

  source secrets-manager.sh && load-secrets-from-agent          # category-scoped
  source secrets-manager.sh && load-secrets-from-agent --bulk   # one popup, bulk categories

Environment:
  SECRETS_DIR            Vault directory (default: home)
  SECRETS_AGENT_TTL_MS   Idle timeout in ms (default 28800000 = 8 hours)`);
}

main().catch(e => { console.error(e); process.exit(1); });
