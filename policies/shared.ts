/**
 * FailproofAI/jev-policies — the regex floor's shared detectors.
 *
 * Imported only by `./regex.ts`. Everything here is copied from
 * `src/hooks/builtin-policies.ts` in the failproofai repo, verbatim except where
 * a comment says otherwise, so that a conformance run can diff the two halves
 * without first having to decide whether a difference was intentional.
 *
 * Four detectors are DELIBERATELY narrower than the builtin's. Each carries a
 * `REWRITE` comment naming what stops being caught deterministically and which
 * semantic check now carries that remainder; every one of them belongs to a
 * policy this pack marks `reviewable`, so the remainder has somewhere to go.
 * `DECISIONS.md` lists all four in one place.
 *
 * Everything the `alwaysOn` self-protection guard needed
 * (`classifySelfInvocation`, `destroysFailproofaiState`, the glob compiler, the
 * brace expander, ~900 lines) is absent on purpose: `block-failproofai-commands`
 * ships compiled into the CLI, `pack-manifest.ts` refuses any pack that declares
 * `alwaysOn`, and this pack does not contain that policy.
 */
import { execFileSync, execSync } from "node:child_process";
import { statSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";
import type { PolicyContext } from "failproofai";

// ── Context accessors ────────────────────────────────────────────────────────

export function getCommand(ctx: PolicyContext): string {
  return (ctx.toolInput?.command as string) ?? "";
}

export function getFilePath(ctx: PolicyContext): string {
  return (ctx.toolInput?.file_path as string) ?? "";
}

/**
 * Parse a command string into argv tokens for safe pattern matching.
 * Splits on whitespace and strips simple single/double quotes.
 * Does not handle all shell syntax — sufficient for prefix-match allowlists.
 */
export function parseArgvTokens(cmd: string): string[] {
  return cmd.trim().split(/\s+/).map((t) => t.replace(/^['"]|['"]$/g, ""));
}

// Shell operators that always act as command separators when whitespace-delimited.
const SHELL_OPERATORS = new Set(["&&", "||", "|", ";"]);

// Shell metacharacters that are unsafe when embedded inside a token. Any command
// whose argv contains one of these in a token is rejected before allowlist matching.
// Note: | is intentionally excluded here because "foo|bar" is a valid grep/sed
// argument value; the standalone-operator check already handles bare "|" tokens.
const SHELL_METACHAR_RE = /[;&<>`$()\\]/;

/**
 * Check if a command matches an allow pattern using token-by-token comparison.
 * The "*" token is a wildcard. Extra command tokens beyond the pattern are allowed,
 * UNLESS any token is a standalone shell operator (&&, ||, |, ;) OR contains an
 * embedded shell metacharacter — both cases are rejected to prevent bypass via
 * appended sub-commands or glued operators (e.g. "nginx;" or "nginx;evil").
 */
export function matchesAllowedPattern(cmd: string, pattern: string): boolean {
  const cmdTokens = parseArgvTokens(cmd);
  const patTokens = parseArgvTokens(pattern);
  if (cmdTokens.length < patTokens.length) return false;
  if (cmdTokens.some((tok) => SHELL_OPERATORS.has(tok))) return false;
  if (cmdTokens.some((tok) => SHELL_METACHAR_RE.test(tok))) return false;
  return patTokens.every((tok, i) => tok === "*" || tok === cmdTokens[i]);
}

// ── Agent-home / agent-settings path recognition ─────────────────────────────

/**
 * Whether `resolved` lives under an agent CLI's home directory
 * (~/.claude/, ~/.codex/, ~/.copilot/, ~/.cursor/, ~/.pi/, ~/.gemini/, or any
 * of OpenCode's three home-side dirs). Used to whitelist agent self-reads of
 * their own config and transcripts.
 */
export function isAgentInternalPath(resolved: string): boolean {
  const normResolved = resolved.replaceAll("\\", "/");
  for (const dir of [".claude", ".codex", ".copilot", ".cursor", ".opencode", ".pi", ".gemini"]) {
    const root = join(homedir(), dir).replaceAll("\\", "/");
    if (normResolved === root || normResolved.startsWith(root + "/")) return true;
  }
  for (const sub of [join(".config", "opencode"), join(".local", "share", "opencode")]) {
    const root = join(homedir(), sub).replaceAll("\\", "/");
    if (normResolved === root || normResolved.startsWith(root + "/")) return true;
  }
  return false;
}

/**
 * Whether `resolved` is a settings/hooks file for an agent CLI. These must NEVER
 * be edited by the agent itself — that would let it disable its own protections.
 */
export function isAgentSettingsFile(resolved: string): boolean {
  if (/[\\/]\.claude[\\/]settings(?:\.[^/\\]+)?\.json$/.test(resolved)) return true;
  if (/[\\/]\.codex[\\/]hooks\.json$/.test(resolved)) return true;
  if (/[\\/]\.copilot[\\/]hooks[\\/][^/\\]+\.json$/.test(resolved)) return true;
  if (/[\\/]\.github[\\/]hooks[\\/][^/\\]+\.json$/.test(resolved)) return true;
  if (/[\\/]\.cursor[\\/]hooks\.json$/.test(resolved)) return true;
  if (/[\\/]\.opencode[\\/]opencode\.jsonc?$/.test(resolved)) return true;
  if (/[\\/]\.opencode[\\/]plugins[\\/][^/\\]+\.(?:mjs|js|ts)$/.test(resolved)) return true;
  if (/[\\/]\.config[\\/]opencode[\\/]opencode\.jsonc?$/.test(resolved)) return true;
  if (/[\\/]\.config[\\/]opencode[\\/]config\.json$/.test(resolved)) return true;
  if (/[\\/]\.config[\\/]opencode[\\/]plugins[\\/][^/\\]+\.(?:mjs|js|ts)$/.test(resolved)) return true;
  if (/[\\/]\.pi[\\/](?:agent[\\/])?settings\.json$/.test(resolved)) return true;
  if (/[\\/]\.pi[\\/](?:agent[\\/])?extensions[\\/]/.test(resolved)) return true;
  if (/[\\/]\.gemini[\\/]settings\.json$/.test(resolved)) return true;
  if (/[\\/]\.gemini[\\/]config[\\/]hooks\.json$/.test(resolved)) return true;
  return false;
}

// ── sanitize-* patterns (PostToolUse) ────────────────────────────────────────

export const JWT_RE = /eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/;

/**
 * Ordered most-specific first, which is load-bearing: a generic
 * `sk-[A-Za-z0-9]{20,}` placed before `sk-ant-…` would label an Anthropic key as
 * an OpenAI one.
 */
export const API_KEY_PATTERNS: Array<[RegExp, string]> = [
  [/sk-ant-[A-Za-z0-9\-_]{20,}/, "Anthropic API key"],
  [/sk-proj-[A-Za-z0-9\-_]{20,}/, "OpenAI project API key"],
  [/sk-[A-Za-z0-9]{20,}/, "OpenAI API key"],
  [/ghp_[A-Za-z0-9]{36}/, "GitHub personal access token"],
  [/github_pat_[A-Za-z0-9_]{82}/, "GitHub fine-grained token"],
  [/AKIA[A-Z0-9]{16}/, "AWS access key ID"],
  [/sk_live_[A-Za-z0-9]{24,}/, "Stripe live secret key"],
  [/sk_test_[A-Za-z0-9]{24,}/, "Stripe test secret key"],
  [/AIza[0-9A-Za-z\-_]{35}/, "Google API key"],
];

export const CONNECTION_STRING_RE =
  /(?:postgresql|postgres|mysql|mongodb(?:\+srv)?|redis|amqps?|smtps?):\/\/[^@\s]+@/;
export const PRIVATE_KEY_RE = /-----BEGIN (?:[A-Z]+ )?PRIVATE KEY-----/;
export const BEARER_TOKEN_RE = /Authorization:\s*Bearer\s+[A-Za-z0-9\-._~+/]{20,}/i;

// ── SQL ──────────────────────────────────────────────────────────────────────

export const SQL_TOOL_RE = /\b(?:psql|mysql|sqlite3|pgcli|clickhouse-client)\b/;
export const DESTRUCTIVE_SQL_RE = /\b(?:DROP\s+(?:TABLE|DATABASE|SCHEMA)|TRUNCATE\b)/i;
export const DELETE_NO_WHERE_RE = /\bDELETE\s+FROM\b/i;
export const SQL_WHERE_RE = /\bWHERE\b/i;
export const SCHEMA_ALTER_RE =
  /\bALTER\s+TABLE\b[\s\S]*\b(?:DROP\s+COLUMN|ADD\s+COLUMN|RENAME\s+(?:COLUMN|TO)|MODIFY\s+COLUMN)\b/i;

// ── Package publishing / installing ──────────────────────────────────────────

export const PUBLISH_CMD_RE =
  /(?:npm\s+publish|bun\s+publish|pnpm\s+publish|yarn\s+npm\s+publish|twine\s+upload|poetry\s+publish|cargo\s+publish|gem\s+push)\b/;

export const NPM_GLOBAL_RE = /\bnpm\s+(?:install|i)\b(?=.*(?:\s-g\b|--global\b))/;
export const YARN_GLOBAL_RE = /\byarn\s+global\s+add\b/;
export const PNPM_GLOBAL_RE = /\bpnpm\s+(?:add|install|i)\b(?=.*(?:\s-g\b|--global\b))/;
export const BUN_GLOBAL_RE = /\bbun\s+(?:install|add)\b(?=.*(?:\s-g\b|--global\b))/;
export const CARGO_INSTALL_RE = /\bcargo\s+install\b/;
export const PIP_SYSTEM_RE = /\bpip(?:3)?\s+install\b(?=.*(?:--user\b|--break-system-packages\b))/;

/** preferPackageManager — maps manager name → detection patterns. */
export const PKG_MANAGER_DETECTORS: Record<string, RegExp[]> = {
  pip: [/\bpip\b/, /\bpip3\b/, /\bpython3?\s+-m\s+pip\b/],
  npm: [/\bnpm\b/, /\bnpx\b/],
  yarn: [/\byarn\b/],
  pnpm: [/\bpnpm\b/, /\bpnpx\b/],
  bun: [/\bbun\b/, /\bbunx\b/],
  uv: [/\buv\b/],
  poetry: [/\bpoetry\b/],
  pipenv: [/\bpipenv\b/],
  conda: [/\bconda\b/],
  cargo: [/\bcargo\b/],
};

/** Split a compound shell command into independent segments. */
export const SEGMENT_SPLIT_RE = /\s*(?:&&|\|\||\||;)\s*/;

// ── Background processes ─────────────────────────────────────────────────────

export const NOHUP_RE = /\bnohup\s+\S/;
export const SCREEN_DETACH_RE = /\bscreen\s+-[A-Za-z]*d[A-Za-z]*\b/;
export const TMUX_DETACH_RE = /\btmux\s+(?:new-session|new)\b[^|&;]*-d\b/;
export const DISOWN_RE = /\bdisown\b/;
export const BACKGROUND_AMPERSAND_RE = /(?<![&|])\s?&\s*(?:$|#|;)/;

// ── protect-env-vars ────────────────────────────────────────────────────────

/** `env` / `printenv`, which print every variable. Unchanged from the builtin. */
export const ENV_PRINTENV_RE = /(?:^|\s|;|&&|\|\|)(?:env|printenv)(?:\s|$|;|&&|\|)/;

/**
 * REWRITE 1 of 4 — `protect-env-vars`, the `export` branch.
 *
 * The builtin used `EXPORT_RE = /(?:^|\s|;|&&|\|\|)export\s+\w+/`, which denies
 * `export NODE_ENV=test` and `export PATH=$PATH:/opt/bin`. An assignment PRINTS
 * NOTHING: nothing about it puts a value into the transcript, which is the harm
 * this policy's own description names ("Prevent commands that read environment
 * variables"). So only the DUMP forms are matched — `export` with no operand and
 * `export -p`, both of which list every exported variable with its value.
 *
 * Gives up: nothing measurable. An assignment cannot expose a value, and
 * `env-secrets-dump` is asked on the same call either way.
 */
export const EXPORT_DUMP_RE = /(?:^|\s|;|&&|\|\|)export(?:\s+-p\b|\s*(?:$|;|&&|\|))/;

/** An `echo` / `printf` in a position where it is the command being run. */
export const ECHO_CMD_RE = /(?:^|[\s;&|(])(?:echo|printf)\s/;

/** `$VAR` / `${VAR}` references, wherever they sit. */
export const SHELL_VAR_REF_RE = /\$\{?([A-Za-z_][A-Za-z0-9_]*)\}?/g;
/** PowerShell `$env:VAR`. */
export const PS_ENV_VAR_REF_RE = /\$env:([A-Za-z_][A-Za-z0-9_]*)/gi;
/** cmd.exe `%VAR%`. */
export const CMD_ENV_VAR_REF_RE = /%([A-Za-z_][A-Za-z0-9_]*)%/g;

/**
 * Underscore-delimited words that name credential material.
 *
 * A word SET rather than a substring pattern, because the substrings collide with
 * ordinary names in exactly the direction that produces false blocks: `AUTH`
 * matches `GIT_AUTHOR_NAME`, `PASS` matches `BYPASS_CACHE`, `KEY` matches
 * `KEYMAP`. Splitting the name on `_`/`-` first and requiring a whole part to be
 * one of these keeps `GIT_AUTHOR_NAME` out and lets `AWS_SECRET_ACCESS_KEY` in.
 */
const SECRET_VAR_WORDS = new Set([
  "KEY", "KEYS", "APIKEY", "PRIVATEKEY", "SECRET", "SECRETS", "TOKEN", "TOKENS",
  "PASSWORD", "PASSWORDS", "PASSWD", "CREDENTIAL", "CREDENTIALS", "CREDS",
  "AUTH", "BEARER", "COOKIE", "COOKIES", "SESSION", "DSN", "PAT", "SALT",
  "SIGNATURE", "PASSPHRASE", "PRIVATE",
]);

/** True when a variable name plausibly holds a credential. */
export function looksLikeSecretVar(name: string): boolean {
  return name
    .toUpperCase()
    .split(/[_-]+/)
    .some((part) => SECRET_VAR_WORDS.has(part));
}

function firstSecretName(cmd: string, ...res: RegExp[]): string | null {
  for (const re of res) {
    for (const match of cmd.matchAll(re)) {
      const name = match[1];
      if (name && looksLikeSecretVar(name)) return name;
    }
  }
  return null;
}

/**
 * A credential-shaped variable in a command that PRINTS it.
 *
 * REWRITE 1 of 4 (continued) — `protect-env-vars`, the `echo` branch.
 *
 * The builtin used `ECHO_ENV_RE = /echo\s+.*\$\{?[A-Za-z_]/`: ANY variable
 * reference after an `echo`. On a `defaultEnabled: true` policy that denies
 * `echo "building $VERSION"`, `echo $PWD`, `echo "done: $name"` — three shapes
 * that appear in ordinary work constantly and expose nothing. This narrows the
 * branch to a variable whose NAME names credential material, and folds in the
 * builtin's separate `echo %VAR%` (cmd.exe) pattern, which had the same problem.
 *
 * The echo/printf context is REQUIRED for these two spellings and is the reason
 * they are split from the PowerShell one below: a bare `$VAR` is how every shell
 * script refers to anything, so a `$SECRET` inside `curl -H "…$TOKEN…"` is not a
 * print and this branch deliberately does not reach it.
 *
 * Gives up: `echo $DATABASE_URL`, `echo $MY_THING` — a variable that holds a
 * secret under a name that does not say so is no longer a deterministic deny.
 * `env-secrets-dump` is asked on every shell call and its probe covers exactly
 * that case ("echo of a variable whose name suggests a key, token, password or
 * secret"), but only on a machine where Jev is configured. This is the one
 * rewrite that trades real floor coverage for the false-positive rate, and it is
 * the trade the policy's noise makes worth naming.
 */
export function secretEchoedVar(cmd: string): string | null {
  if (!ECHO_CMD_RE.test(cmd)) return null;
  return firstSecretName(cmd, SHELL_VAR_REF_RE, CMD_ENV_VAR_REF_RE);
}

/**
 * A credential-shaped PowerShell `$env:NAME`, wherever it sits.
 *
 * Kept position-independent, unlike the two above, because the builtin's
 * `PS_ENV_VAR_RE = /\$env:[A-Za-z_]/i` was position-independent and `$env:` is
 * unambiguous: it IS an environment read, in a way a bare `$VAR` is not. Only the
 * name test is added, so `$env:PATH` stops being denied and `$env:OPENAI_API_KEY`
 * still is — including in `Write-Host $env:SECRET`, which an echo-only rule would
 * have missed.
 */
export function secretPsEnvVar(cmd: string): string | null {
  return firstSecretName(cmd, PS_ENV_VAR_REF_RE);
}

/** PowerShell: `Get-ChildItem Env:` / `dir env:` / `gci env:` / `ls env:` — a full dump. */
export const PS_CHILDITEM_ENV_RE = /(?:Get-ChildItem|dir|gci|ls)\s+Env:/i;
/** .NET: `[Environment]::GetEnvironmentVariable(s)`. */
export const DOTNET_GETENV_RE = /\[Environment\]::GetEnvironment/i;

// ── block-env-files ─────────────────────────────────────────────────────────

/** A `file_path` naming a dotenv file. Unchanged from the builtin. */
export const ENV_FILE_PATH_RE = /(?:^|[\\/])\.env(?:\.|$)/;

/**
 * REWRITE 2 of 4 — `block-env-files`, the Bash branch.
 *
 * The builtin used `ENV_CMD_RE = /\.env(?:\b|\s|$|\.)/` over the whole command
 * string, which matches the substring `.env` anywhere at all. The consequences,
 * on a `defaultEnabled: true` policy:
 *
 *   grep -rn "process.env" src/          → denied
 *   node -e 'console.log(process.env.CI)'→ denied
 *   rg 'import.meta.env' app/            → denied
 *
 * None of those reads a file. Meanwhile the policy's OTHER branch
 * (`ENV_FILE_PATH_RE`, over `file_path`) only ever matched `.env` as the start of
 * a basename — so the two branches of one policy disagreed by an order of
 * magnitude about what an env file is.
 *
 * This makes the Bash branch agree with the file branch: `.env` has to begin a
 * path SEGMENT, either at the start of a word or straight after a `/`.
 *
 * Gives up: a non-dotfile env file named inside a command — `cat config/app.env`,
 * `source prod.env`. Those were never matched by the `file_path` branch either,
 * so no tool loses coverage it had; the asymmetry is what goes away.
 * `secret-exposure` (this policy's reviewer, asked on every shell/read/write
 * call) is what catches them once Jev is configured.
 */
export const ENV_FILE_TOKEN_RE =
  /(?:^|[\s"'=:;|&(<>])(?:[^\s"'=;|&<>]*[\\/])?\.env(?:\.[A-Za-z0-9_.-]+)?(?=$|[\s"'=:;|&)<>,])/;

// ── block-sudo ──────────────────────────────────────────────────────────────

export const PS_ELEVATION_RE = /Start-Process\s+.*-Verb\s+RunAs/i;
export const RUNAS_RE = /(?:^|;|&&|\|\|)\s*runas\s/i;

/**
 * Tokens that stand in front of the real binary without being it: package
 * runners, interpreters, and the `exec`-alikes. Compared by basename, so
 * `/usr/bin/env` and `env` behave identically.
 */
const COMMAND_PREFIX_TOKENS = new Set([
  "npx", "bunx", "pnpx", "npm", "pnpm", "yarn", "dlx", "exec", "run", "eval",
  "node", "bun", "deno", "env", "command", "builtin", "nohup", "setsid",
  "time", "timeout", "nice", "stdbuf", "xargs", "sudo", "doas",
  "sh", "bash", "zsh", "dash", "ksh", "fish", "ash",
]);

/** An `FOO=bar` prefix assignment, which a shell consumes before the command. */
const ENV_ASSIGNMENT_RE = /^[A-Za-z_][A-Za-z0-9_]*=/;

/**
 * A bare operand belonging to the runner in front of it — `timeout 30 …`,
 * `nice -n 5 …`. Safe to skip unconditionally: no binary is named `30` or `5m`.
 */
const RUNNER_OPERAND_RE = /^\d+[a-z]*$/i;

/** `-c` and friends: the flags whose ARGUMENT is a command, not data. */
const EVAL_FLAG_RE = /^-{1,2}c$/;

/**
 * Split a command into per-segment TOKEN LISTS the way a shell reads it.
 *
 * Segmentation happens on the RAW string and skips separators inside quotes,
 * which is the whole point: stripping quoting FIRST turns `\|` — a literal pipe
 * in a grep alternation — into a real separator, so `grep "a\|sudo b"` parses as
 * a command called `sudo` and gets denied. Each token is unquoted individually
 * afterwards, which still defeats `\sudo` and `"sudo"` without ever letting quote
 * removal change where the boundaries are.
 */
export function quoteAwareSegments(command: string): Array<string[]> {
  const segments: Array<string[]> = [];
  let tokens: string[] = [];
  let token = "";
  let quote: '"' | "'" | null = null;
  const endToken = () => {
    if (token) tokens.push(token);
    token = "";
  };
  const endSegment = () => {
    endToken();
    if (tokens.length) segments.push(tokens);
    tokens = [];
  };
  for (let i = 0; i < command.length; i++) {
    const c = command[i];
    if (quote) {
      if (c === "\\" && quote === '"' && i + 1 < command.length) {
        token += command[++i];
        continue;
      }
      if (c === quote) {
        quote = null;
        continue;
      }
      token += c;
      continue;
    }
    if (c === "\\" && i + 1 < command.length) {
      token += command[++i];
      continue;
    }
    if (c === '"' || c === "'") {
      quote = c;
      continue;
    }
    if (/\s/.test(c)) {
      endToken();
      continue;
    }
    if (/[;&|\n\r(){}`]/.test(c)) {
      endSegment();
      continue;
    }
    token += c;
  }
  endSegment();
  return segments;
}

/**
 * True when a command runs an elevation binary IN COMMAND POSITION.
 *
 * Anchored structurally rather than by token: a token-anchored `\bsudo\b` left
 * `/usr/bin/sudo rm -rf /` ALLOWED — a direct invocation, one absolute path away
 * from root on a `defaultEnabled` guard. Every form the shell resolves before it
 * settles on the binary (prefix assignments, redirections, runners and their
 * flags) is walked off first, and the comparison is on the BASENAME.
 *
 * A quoted argument is re-examined ONLY when the command that owns it is a shell
 * runner invoked with an eval flag (`bash -c "sudo …"`): `bash -c "sudo x"` and
 * `grep "a|sudo x"` are identical from the outside, and the only thing separating
 * an execution from a search string is whether the receiving binary evaluates it.
 */
export function namesElevation(command: string, depth = 0): boolean {
  for (const tokens of quoteAwareSegments(command)) {
    let i = 0;
    while (i < tokens.length) {
      const token = tokens[i];
      const base = token.slice(token.lastIndexOf("/") + 1);
      // Tested BEFORE the skip list: `sudo`/`doas` are themselves prefix tokens,
      // so the walk would otherwise step straight over what it is looking for.
      if (base === "sudo" || base === "doas") return true;
      const isSkippable =
        ENV_ASSIGNMENT_RE.test(token) ||
        token.startsWith("-") ||
        token.startsWith(">") ||
        token.startsWith("<") ||
        RUNNER_OPERAND_RE.test(token) ||
        COMMAND_PREFIX_TOKENS.has(base);
      if (!isSkippable) break;
      if (EVAL_FLAG_RE.test(token) && depth < 3 && i + 1 < tokens.length) {
        if (namesElevation(tokens[i + 1], depth + 1)) return true;
      }
      i++;
    }
  }
  return false;
}

// ── block-curl-pipe-sh ──────────────────────────────────────────────────────

export const CURL_PIPE_SH_RE = /(?:curl|wget)\s.*\|\s*(?:sh|bash|zsh|dash|ksh|csh|tcsh|fish|ash)\b/;
export const PS_WEB_PIPE_RE =
  /(?:Invoke-WebRequest|iwr|Invoke-RestMethod|irm)\s+.*\|\s*(?:Invoke-Expression|iex)/i;

// ── git push: shared argument extraction ────────────────────────────────────

export function extractGitPushArgs(cmd: string): string[] {
  return cmd
    .split(/&&|\|\||[|;\n]/)
    .map((s) => s.trim())
    .filter((s) => /^git\s+push\s/.test(s))
    .map((s) => s.replace(/^git\s+push\s+/, ""));
}

/**
 * REWRITE 3 of 4 — `block-push-master`.
 *
 * The builtin built one alternation out of `protectedBranches` and tested it with
 * `\b…\b` against the whole argument string, so every branch whose NAME CONTAINS
 * a protected word was denied:
 *
 *   git push origin feature/main-menu   → denied (`/` and `-` are non-word chars)
 *   git push origin main-v2             → denied
 *   git push origin hotfix/master-fix   → denied
 *
 * `push-to-protected-branch` names that exact class in its own false criteria ("a
 * feature branch whose name merely contains a word like main"), which is how we
 * know it is the wrong kind of miss. But that check is `mode: "instruct"`, so it
 * cannot be this policy's reviewer without demoting it — the policy stays HARD
 * (see its entry in `regex.ts`). That makes this rewrite the whole fix rather
 * than half of one: the floor itself is narrowed to the ref a push actually lands
 * on. Reduce each operand to its destination ref and require an EXACT match.
 *
 * Gives up: a push whose remote operand is displaced by an unusual flag form
 * (`git push --repo=origin main` leaves one bare operand, which git reads as the
 * remote, so it is skipped). `git push --mirror origin` and a bare `git push` on
 * a protected branch were misses before this change and remain misses. Being hard
 * does not make those invisible to the semantic tier: `push-to-protected-branch`
 * is still asked on the call, still reads `facts.current_git_branch`, and its own
 * instruct still joins the most-severe merge. What `hard` withholds is only the
 * power to CLEAR this policy's deny, never the check's own verdict.
 */
export function pushTargetRef(token: string): string | null {
  if (!token || token.startsWith("-")) return null;
  // A force refspec (`+HEAD:main`) and a delete refspec (`:main`) both carry the
  // destination after the colon; `refs/heads/` is the long spelling of a branch.
  let ref = token.replace(/^\+/, "");
  const colon = ref.lastIndexOf(":");
  if (colon !== -1) ref = ref.slice(colon + 1);
  ref = ref.replace(/^refs\/heads\//, "");
  return ref === "" ? null : ref;
}

// ── block-force-push ────────────────────────────────────────────────────────

const SHORT_FLAG_BUNDLE_RE = /^-[a-zA-Z]*f[a-zA-Z]*$/;
const SAFE_FORCE_PREFIXES = ["--force-with-lease", "--force-if-includes"] as const;

export function isForcePushFlag(token: string): boolean {
  if (token === "--force") return true;
  if (SAFE_FORCE_PREFIXES.some((prefix) => token.startsWith(prefix))) return false;
  if (token.startsWith("--force")) return true;
  return SHORT_FLAG_BUNDLE_RE.test(token);
}

// ── block-secrets-write ─────────────────────────────────────────────────────

const SECRET_FILE_EXT_RE = /\.(?:pem|key)$/;
/** Extensions that make a path source or prose rather than a credential store. */
const SOURCE_OR_DOC_EXT_RE =
  /\.(?:ts|tsx|js|jsx|mjs|cjs|py|go|rs|rb|java|kt|kts|cs|php|swift|sh|bash|zsh|md|mdx|rst|txt|snap|tpl|hbs|ejs|html|css|scss)$/i;

/**
 * REWRITE 4 of 4 — `block-secrets-write`.
 *
 * The builtin tested three patterns against the whole `file_path`, two of them
 * unanchored substrings: `/id_rsa/` and `/credentials/`. So writing
 * `src/auth/credentials.ts`, `docs/credentials.md`, `lib/id_rsa_parser.ts` or
 * anything at all under a directory called `credentials/` was denied as "writing
 * a secret key file".
 *
 * Narrowed to the BASENAME, and to a basename that is the credential file rather
 * than merely a name containing the word: `*.pem` / `*.key` unchanged (already
 * anchored at the end), `id_rsa` exactly, and a `credentials` stem whose
 * extension is not source or prose.
 *
 * Gives up: `~/.ssh/id_rsa.old`, `~/.ssh/id_rsa_backup`, a credentials file whose
 * name only contains the word (`prod-credentials.tar`), and anything under a
 * directory called `credentials/`. `secret-exposure` — this policy's reviewer,
 * asked on every `write` call — covers all four, and its own false criteria
 * ("documentation about credentials", "a test fixture") is what the builtin was
 * denying instead.
 */
export function writesSecretFile(filePath: string): boolean {
  if (SECRET_FILE_EXT_RE.test(filePath)) return true;
  const base = filePath.replace(/^.*[\\/]/, "");
  if (base === "id_rsa") return true;
  if (base.toLowerCase() === ".credentials") return true;
  const stem = base.replace(/\.[^.]+$/, "");
  if (stem.toLowerCase() === "credentials") return !SOURCE_OR_DOC_EXT_RE.test(base);
  return false;
}

// ── block-work-on-main / warn-git-* ─────────────────────────────────────────

export const GIT_COMMIT_MERGE_RE = /git\s+(commit|merge|rebase|cherry-pick)\b/;
export const GIT_AMEND_RE = /\bgit\s+commit\b.*--amend\b/;
export const GIT_STASH_DROP_RE = /\bgit\s+stash\s+(?:drop|clear)\b/;
export const GIT_ADD_ALL_RE = /\bgit\s+add\s+(?:-A\b|--all\b|\.(?:\s|$|;|&&|\|\|))/;

// ── block-rm-rf: deletion-target resolution ─────────────────────────────────

/**
 * Leading shell forms that resolve to a home directory: `~`, `~user`, `$HOME`,
 * `${HOME}`. The lookahead keeps `$HOMEBREW_PREFIX` (a variable this policy
 * cannot resolve) from being mistaken for `$HOME`.
 */
const HOME_PREFIX_RE = /^(?:~[A-Za-z0-9_.-]*|\$HOME|\$\{HOME\})(?=$|\/)/;

/** `rm`, `/bin/rm`, `/usr/bin/rm`, … — the command word of a delete. */
const RM_CMD_RE = /^(?:\/\S*\/)?rm$/;
const FIND_CMD_RE = /^(?:\/\S*\/)?find$/;
const FIND_EXEC_RE = /^-(?:exec|execdir|ok|okdir)$/;
/** find's global options, which precede its path operands (`find -L / -delete`). */
const FIND_GLOBAL_OPT_RE = /^-(?:[HLP]|D|O\d*)$/;
/** First token of find's expression — everything before it is a path operand. */
const FIND_EXPR_START_RE = /^(?:-|\\?[(!])/;

/**
 * Roots that exist to hold throwaway data. A delete of the root itself is still
 * catastrophic (`rm -rf /tmp` wipes every process's scratch space); a delete of
 * something *inside* one is ordinary work.
 */
const SCRATCH_ROOTS = ["/tmp", "/var/tmp"];

/**
 * How many path segments below a root (`/` or a home directory) a delete has to
 * reach before it stops being catastrophic.
 */
const CATASTROPHIC_DEPTH = 2;

/** Expand the leading `~` / `$HOME` / `${HOME}` of a path to the real home directory. */
export function expandHomePrefix(path: string): string {
  const m = path.match(/^(?:~|\$HOME|\$\{HOME\})(?=$|\/)/);
  return m ? homedir() + path.slice(m[0].length) : path;
}

/** Drop a trailing `/*` glob and any trailing slashes: `/tmp/foo/*` → `/tmp/foo`. */
export function stripTrailingGlob(path: string): string {
  return path.replace(/\/\*$/, "").replace(/\/+$/, "");
}

/**
 * Would deleting this target be catastrophic?
 *
 * Fails safe: a token whose head is an expansion this policy cannot evaluate —
 * command substitution or any variable other than `$HOME` — could expand to `/`,
 * so it counts as catastrophic. Relative targets are not flagged.
 */
export function isCatastrophicTarget(token: string): boolean {
  const raw = token.replace(/^['"]|['"]$/g, "");
  if (raw === "") return false;

  const homePrefix = raw.match(HOME_PREFIX_RE);
  if (!homePrefix && /^[$`]/.test(raw)) return true;

  const belowRoot = homePrefix ? raw.slice(homePrefix[0].length) : raw.startsWith("/") ? raw : null;
  if (belowRoot === null) return false;

  const segments = stripTrailingGlob(belowRoot).split("/").filter(Boolean);
  if (!homePrefix && SCRATCH_ROOTS.some((r) => `/${segments.join("/")}`.startsWith(`${r}/`))) return false;
  return segments.length <= CATASTROPHIC_DEPTH;
}

/**
 * The paths a single command segment would recursively delete, or `null` when the
 * segment is not a recursive delete at all. Understands `rm` with both `-r` and
 * `-f`, and `find` paired with `-delete` or an `-exec rm`.
 */
export function recursiveDeletionTargets(seg: string): string[] | null {
  const tokens = parseArgvTokens(seg);

  const findIdx = tokens.findIndex((t) => FIND_CMD_RE.test(t));
  if (findIdx >= 0) {
    const expr = tokens.slice(findIdx + 1);
    const execIdx = expr.findIndex((t) => FIND_EXEC_RE.test(t));
    const deletes = expr.includes("-delete") || (execIdx >= 0 && RM_CMD_RE.test(expr[execIdx + 1] ?? ""));
    if (deletes) {
      let start = 0;
      while (start < expr.length && FIND_GLOBAL_OPT_RE.test(expr[start])) {
        start += expr[start] === "-D" ? 2 : 1;
      }
      const rest = expr.slice(start);
      const end = rest.findIndex((t) => FIND_EXPR_START_RE.test(t));
      return end < 0 ? rest : rest.slice(0, end);
    }
  }

  const rmIdx = tokens.findIndex((t) => RM_CMD_RE.test(t));
  if (rmIdx >= 0) {
    const args = tokens.slice(rmIdx + 1);
    const shortFlags = args.filter((t) => /^-[^-]/.test(t)).join("");
    const longFlags = args.filter((t) => /^--/.test(t));
    const recursive = /r/i.test(shortFlags) || longFlags.some((f) => /^--recursive$/i.test(f));
    const force = /f/.test(shortFlags) || longFlags.some((f) => /^--force$/i.test(f));
    if (recursive && force) return args.filter((t) => !t.startsWith("-"));
  }

  return null;
}

/** Split a command into the segments the shell would run as separate commands. */
export function shellSegments(cmd: string): string[] {
  return cmd.split(/&&|\|\||[|;\n]/).map((s) => s.trim()).filter((s) => s !== "");
}

/**
 * Check whether all recursive-delete targets in a command are under an
 * allowlisted path. Splits on shell operators first so `/tmp` in an unrelated
 * sub-command does not trigger a false allow, and uses path-boundary comparison
 * so `/tmp` does not cover `/tmp2`.
 */
export function deletionTargetIsAllowed(cmd: string, allowPaths: string[]): boolean {
  if (allowPaths.length === 0) return false;
  const normalizedAllowPaths = allowPaths.map((p) => stripTrailingGlob(expandHomePrefix(p)) || "/");
  let sawRecursiveDelete = false;
  for (const seg of shellSegments(cmd)) {
    const targets = recursiveDeletionTargets(seg);
    if (targets === null) continue;
    sawRecursiveDelete = true;
    for (const target of targets) {
      const normalized = stripTrailingGlob(expandHomePrefix(target)) || "/";
      const covered = normalizedAllowPaths.some((np) => normalized === np || normalized.startsWith(np + "/"));
      if (!covered) {
        // Fallback: quoted paths containing spaces, which parseArgvTokens splits.
        const segCovered = allowPaths.some((p) => {
          const escaped = p.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
          return new RegExp(`${escaped}(?:[/"'\\s/*]|$)`).test(seg);
        });
        if (!segCovered) return false;
      }
    }
  }
  return sawRecursiveDelete;
}

// ── block-read-outside-cwd ──────────────────────────────────────────────────

/** Read-like commands that access file system contents. */
export const READ_LIKE_CMDS =
  /(?:^|;|&&|\|\||\|)\s*(?:ls|find|cat|head|tail|less|more|wc|file|stat|tree|du)\s/;

/**
 * Extract absolute paths from a Bash command string.
 *
 * Quoted strings are scanned only in the first pipeline segment and only when the
 * content has no glob or regex metacharacters, which catches `cat "/etc/passwd"`
 * while avoiding false positives from grep patterns in later stages. Runs of
 * slashes with nothing else (`//`, `///`) are dropped: those are a line-comment
 * marker, not a directory.
 */
export function extractAbsolutePaths(command: string): string[] {
  const paths: string[] = [];
  const pathRe =
    /(?<![a-zA-Z0-9_.\-~\\*?:=/])(?:~\/[^\s;|&"'()\[\]{}]*|~(?=\s|$|[;|&"'()\[\]{}])|\/[^\s;|&"'()\[\]{}]*)/g;

  function addPaths(s: string): void {
    pathRe.lastIndex = 0;
    let m: RegExpExecArray | null;
    while ((m = pathRe.exec(s)) !== null) {
      let p = m[0];
      if (/^\/{2,}$/.test(p)) continue; // a `//` comment marker, not the root
      if (p === "~") p = homedir();
      else if (p.startsWith("~/")) p = join(homedir(), p.slice(2));
      paths.push(p);
    }
  }

  let firstBarePipe = command.length;
  let inDouble = false, inSingle = false;
  for (let i = 0; i < command.length; i++) {
    const c = command[i];
    if (c === '"' && !inSingle) inDouble = !inDouble;
    else if (c === "'" && !inDouble) inSingle = !inSingle;
    else if (c === "|" && !inDouble && !inSingle) { firstBarePipe = i; break; }
  }

  const firstSegment = command.slice(0, firstBarePipe);
  const quotedRe = /"([^"]*)"|'([^']*)'/g;
  let qm: RegExpExecArray | null;
  while ((qm = quotedRe.exec(firstSegment)) !== null) {
    const content = qm[1] ?? qm[2] ?? "";
    if (/[*?\[\]^$+()\\]/.test(content)) continue;
    addPaths(content);
  }

  const stripped = command
    .replace(/"[^"]*"/g, (m) => " ".repeat(m.length))
    .replace(/'[^']*'/g, (m) => " ".repeat(m.length));
  addPaths(stripped);

  return paths;
}

// ── Infra CLIs ──────────────────────────────────────────────────────────────

// Each regex matches the CLI name only when it appears as the first token of a
// command segment (start-of-string or after ; && || |). The trailing \s prevents
// false matches on names like "kubectlx" or "awsctl".
export const KUBECTL_RE = /(?:^|[;\n]|&&|\|\|?|&)\s*kubectl(?:\s|$)/;
export const TERRAFORM_RE = /(?:^|[;\n]|&&|\|\|?|&)\s*(?:terraform|tofu)(?:\s|$)/;
export const AWS_CLI_RE = /(?:^|[;\n]|&&|\|\|?|&)\s*aws(?:\s|$)/;
export const GCLOUD_RE = /(?:^|[;\n]|&&|\|\|?|&)\s*gcloud(?:\s|$)/;
export const AZ_CLI_RE = /(?:^|[;\n]|&&|\|\|?|&)\s*az(?:\s|$)/;
export const HELM_RE = /(?:^|[;\n]|&&|\|\|?|&)\s*helm(?:\s|$)/;
export const GH_PIPELINE_RE =
  /(?:^|[;\n]|&&|\|\|?|&)\s*gh\s+(?:workflow\s+(?:run|enable|disable)|run\s+(?:rerun|cancel)|pr\s+merge|release\s+(?:create|delete)|cache\s+delete|secret\s+(?:set|delete))\b/;

// ── git / gh state readers (Stop-event policies) ────────────────────────────

// Caches the current branch per cwd, gated on .git/HEAD's mtime rather than
// reused unconditionally: the daemon's warm worker keeps this Map alive across
// many calls and many projects' cwds, and reusing a branch name forever would
// silently deny or allow a Stop based on a branch checked out an hour ago.
// Bounded at 500 entries.
const gitBranchCache = new Map<string, { branch: string; headMtimeMs: number }>();
const GIT_BRANCH_CACHE_MAX_ENTRIES = 500;

function statGitHeadMtimeMs(cwd: string): number | null {
  try {
    return statSync(join(cwd, ".git", "HEAD")).mtimeMs;
  } catch {
    return null;
  }
}

export function getCurrentBranch(cwd: string): string | null {
  try {
    const headMtimeMs = statGitHeadMtimeMs(cwd);
    const cached = gitBranchCache.get(cwd);
    if (cached && headMtimeMs !== null && cached.headMtimeMs === headMtimeMs) {
      return cached.branch || null;
    }
    const branch = execSync("git rev-parse --abbrev-ref HEAD", {
      cwd,
      encoding: "utf8", stdio: ["pipe", "pipe", "pipe"],
      timeout: 3000,
    }).trim();
    if (headMtimeMs !== null) {
      if (gitBranchCache.size >= GIT_BRANCH_CACHE_MAX_ENTRIES) gitBranchCache.clear();
      gitBranchCache.set(cwd, { branch, headMtimeMs });
    }
    return branch || null;
  } catch {
    return null;
  }
}

export function getHeadSha(cwd: string): string | null {
  try {
    const sha = execSync("git rev-parse HEAD", {
      cwd,
      encoding: "utf8", stdio: ["pipe", "pipe", "pipe"],
      timeout: 3000,
    }).trim();
    return sha || null;
  } catch {
    return null;
  }
}

export interface CiCheck {
  name: string;
  status: string;
  conclusion: string;
}

/** Fetch third-party check runs (non-GitHub-Actions) for a commit via the Checks API. */
export function getThirdPartyCheckRuns(cwd: string, sha: string): CiCheck[] {
  try {
    const json = execFileSync(
      "gh",
      [
        "api",
        `repos/{owner}/{repo}/commits/${sha}/check-runs`,
        "--jq",
        '.check_runs | map(select(.app.slug != "github-actions")) | map({name: .name, status: .status, conclusion: (.conclusion // "")})',
      ],
      {
        cwd,
        encoding: "utf8", stdio: ["pipe", "pipe", "pipe"],
        timeout: 15000,
      },
    ).trim();

    if (!json || json === "[]") return [];
    return JSON.parse(json) as CiCheck[];
  } catch {
    return [];
  }
}

/** Fetch commit statuses (legacy Status API) and normalize to CiCheck format. */
export function getCommitStatuses(cwd: string, sha: string): CiCheck[] {
  try {
    const json = execFileSync(
      "gh",
      [
        "api",
        `repos/{owner}/{repo}/commits/${sha}/statuses`,
        "--jq",
        'map({name: .context, state: .state}) | unique_by(.name)',
      ],
      {
        cwd,
        encoding: "utf8", stdio: ["pipe", "pipe", "pipe"],
        timeout: 15000,
      },
    ).trim();

    if (!json || json === "[]") return [];
    const statuses = JSON.parse(json) as Array<{ name: string; state: string }>;
    return statuses.map((s) => ({
      name: s.name,
      status: s.state === "pending" ? "in_progress" : "completed",
      conclusion: s.state === "pending" ? "" : s.state === "success" ? "success" : "failure",
    }));
  } catch {
    return [];
  }
}

/**
 * Claude Code plan mode is research-and-plan-only — the agent makes no commits,
 * pushes or PRs by design. The Stop-workflow gates all assume the agent produced
 * code changes, so in plan mode they would demand actions plan mode forbids.
 */
export function isPlanMode(ctx: PolicyContext): boolean {
  return ctx.session?.permissionMode === "plan";
}

/** Maximum size of the per-session tool-call sidecar before we stop updating it. */
export const TOOL_CALL_TRACKER_MAX_BYTES = 65_536; // 64 KB
