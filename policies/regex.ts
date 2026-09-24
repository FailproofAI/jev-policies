/**
 * FailproofAI/jev-policies — the regex floor.
 *
 * All 38 publishable policies, registered through the same public API a
 * third-party pack uses. Importing this module IS the registration; there is
 * nothing to call afterwards.
 *
 * ## What this file is and is not
 *
 * It is the deterministic FLOOR. Every `fn` here decides from the tool call's
 * text alone, with no model in the loop, and that is what a machine with no Jev
 * key — or a machine whose Jev call timed out, ran out of credits or came back
 * unparseable — still gets. `combine.ts` guarantees the two-tier result is never
 * less severe than this floor unless a clear fired.
 *
 * It is NOT the whole pack. `../policies/semantic.ts` carries the 16 Jev checks,
 * and 19 of the 38 policies below name one or more of them in `reviewedBy`.
 *
 * ## Order is load-bearing
 *
 * Policy evaluation short-circuits on the first deny, so registration order
 * decides which policy NAME reaches the agent, the activity log and the audit
 * report. This file is in the exact order of the builtin catalog
 * (`src/hooks/policy-catalog.ts`), minus `block-failproofai-commands`. Do not
 * sort or regroup it. First appearance of each `category` also orders the
 * sections in the TUI picker and the dashboard.
 *
 * ## `block-failproofai-commands` is absent, deliberately
 *
 * It is the `alwaysOn` self-protection guard, it ships compiled into the CLI, and
 * `pack-manifest.ts` REFUSES any pack that declares `alwaysOn`. A pack containing
 * it would be rejected by failproofai's own loader — correctly. It is the one
 * catalog entry with no counterpart here, which is why this file has 38 policies
 * and the catalog has 39.
 *
 * ## `authority` / `reviewedBy`
 *
 * Every entry states its authority explicitly, even though absent already means
 * `hard`: whether Jev may clear a verdict is a decision made per policy, not a
 * default to inherit. `reviewedBy` is a CONJUNCTION — every name must have been
 * ASKED for this call and none may have answered `deny` — so naming a check makes
 * a policy harder to clear, never easier, and naming one that is never asked for
 * the shapes this policy matches makes the block permanent. Each pairing below
 * carries the one-line reason it is live; `DECISIONS.md` carries the table, the
 * pairings that were refused, and the measurements.
 *
 * ## Four `fn`s are narrower than the builtin's
 *
 * `protect-env-vars`, `block-env-files`, `block-push-master` and
 * `block-secrets-write`. Each is marked REWRITTEN below and each names, in
 * `./shared.ts`, exactly what stops being caught deterministically and which
 * semantic check carries that remainder. Every other `fn` is a faithful copy.
 */
import { customPolicies as failproofaiPolicies, allow, deny, instruct } from "failproofai";
import type { PolicyAuthority, PolicyContext, PolicyResult } from "failproofai";
import { execFileSync, execSync } from "node:child_process";
import { readFile, writeFile } from "node:fs/promises";
import { resolve } from "node:path";
import {
  API_KEY_PATTERNS,
  AWS_CLI_RE,
  AZ_CLI_RE,
  BACKGROUND_AMPERSAND_RE,
  BEARER_TOKEN_RE,
  BUN_GLOBAL_RE,
  CARGO_INSTALL_RE,
  CONNECTION_STRING_RE,
  CURL_PIPE_SH_RE,
  DELETE_NO_WHERE_RE,
  DESTRUCTIVE_SQL_RE,
  DISOWN_RE,
  DOTNET_GETENV_RE,
  ENV_FILE_PATH_RE,
  ENV_FILE_TOKEN_RE,
  ENV_PRINTENV_RE,
  EXPORT_DUMP_RE,
  GCLOUD_RE,
  GH_PIPELINE_RE,
  GIT_ADD_ALL_RE,
  GIT_AMEND_RE,
  GIT_COMMIT_MERGE_RE,
  GIT_STASH_DROP_RE,
  HELM_RE,
  JWT_RE,
  KUBECTL_RE,
  NOHUP_RE,
  NPM_GLOBAL_RE,
  PIP_SYSTEM_RE,
  PKG_MANAGER_DETECTORS,
  PNPM_GLOBAL_RE,
  PRIVATE_KEY_RE,
  PS_CHILDITEM_ENV_RE,
  PS_ELEVATION_RE,
  PS_WEB_PIPE_RE,
  PUBLISH_CMD_RE,
  READ_LIKE_CMDS,
  RUNAS_RE,
  SCHEMA_ALTER_RE,
  SCREEN_DETACH_RE,
  SEGMENT_SPLIT_RE,
  SQL_TOOL_RE,
  SQL_WHERE_RE,
  TERRAFORM_RE,
  TMUX_DETACH_RE,
  TOOL_CALL_TRACKER_MAX_BYTES,
  YARN_GLOBAL_RE,
  type CiCheck,
  deletionTargetIsAllowed,
  extractAbsolutePaths,
  extractGitPushArgs,
  getCommand,
  getCommitStatuses,
  getCurrentBranch,
  getFilePath,
  getHeadSha,
  getThirdPartyCheckRuns,
  isAgentInternalPath,
  isAgentSettingsFile,
  isCatastrophicTarget,
  isForcePushFlag,
  isPlanMode,
  matchesAllowedPattern,
  namesElevation,
  parseArgvTokens,
  pushTargetRef,
  recursiveDeletionTargets,
  secretEchoedVar,
  secretPsEnvVar,
  shellSegments,
  writesSecretFile,
} from "./shared";

/**
 * The shape `customPolicies.add` accepts from a PACK.
 *
 * The published `CustomHook` type describes the narrower thing a user's own
 * policy file registers — `match.events` only, and no `category`,
 * `defaultEnabled` or `params`. A pack entry carries all of them: `category` and
 * `defaultEnabled` because `failproofai publish` reads them off the registration
 * to build the manifest (omit them and every policy files under "General" with
 * none on by default), `match.toolNames` because `parsePackPolicy` validates and
 * honours it, and `params` because a pack's manifest is where a policy's params
 * SCHEMA is declared — `registerPolicy` reads it from there by name, and a policy
 * with no schema receives `ctx.params` as `{}`, which discards the user's own
 * configured values as well as the defaults.
 *
 * Widened once, here, rather than with a cast at each of 38 call sites.
 */
interface PackPolicyParam {
  type: "string" | "string[]" | "number" | "boolean" | "pattern[]";
  description: string;
  default: unknown;
}

interface PackPolicy {
  name: string;
  description: string;
  category: string;
  defaultEnabled: boolean;
  match: { events?: string[]; toolNames?: string[] };
  fn: (ctx: PolicyContext) => PolicyResult | Promise<PolicyResult>;
  params?: Record<string, PackPolicyParam>;
  authority?: PolicyAuthority;
  reviewedBy?: string[];
}

const customPolicies = failproofaiPolicies as unknown as { add(policy: PackPolicy): void };

// ─────────────────────────────────────────────────────────────────────────────
// Sanitize — PostToolUse output scrubbing.
//
// All five are HARD, and not as a judgement about how serious a leaked key is:
// they run on PostToolUse, and Jev is only ever asked on PreToolUse and
// PermissionRequest. There is no Jev answer in existence for one of these calls,
// so `reviewedBy` could name nothing that was ever asked and any `reviewable`
// declaration would resolve to a permanent block by a different route. The same
// is true of the five `require-*-before-stop` policies at the end of this file.
// ─────────────────────────────────────────────────────────────────────────────

customPolicies.add({
  name: "sanitize-jwt",
  description: "Stop Claude from reading JWTs in tool responses",
  category: "Sanitize",
  defaultEnabled: true,
  match: { events: ["PostToolUse"] },
  authority: "hard",
  fn: (ctx) => {
    const output = JSON.stringify(ctx.payload);
    if (JWT_RE.test(output)) {
      return {
        decision: "deny",
        reason: "JWT token detected in tool output",
        message: "[REDACTED: JWT token removed by failproofai]",
      };
    }
    return allow();
  },
});

customPolicies.add({
  name: "sanitize-api-keys",
  description:
    "Stop Claude from reading API keys (OpenAI, Anthropic, GitHub, AWS, Stripe, Google) in tool responses",
  category: "Sanitize",
  defaultEnabled: true,
  match: { events: ["PostToolUse"] },
  authority: "hard",
  params: {
    additionalPatterns: {
      type: "pattern[]",
      description: "Additional API key patterns to scrub, each with { regex, label }",
      default: [],
    },
  },
  fn: (ctx) => {
    const output = JSON.stringify(ctx.payload);
    for (const [pattern, label] of API_KEY_PATTERNS) {
      if (pattern.test(output)) {
        return {
          decision: "deny",
          reason: `${label} detected in tool output`,
          message: `[REDACTED: ${label} removed by failproofai]`,
        };
      }
    }

    const additional = (ctx.params?.additionalPatterns ?? []) as Array<{ regex: string; label: string }>;
    for (const { regex, label } of additional) {
      try {
        if (new RegExp(regex).test(output)) {
          return {
            decision: "deny",
            reason: `${label} detected in tool output`,
            message: `[REDACTED: ${label} removed by failproofai]`,
          };
        }
      } catch {
        // The builtin calls `hookLogWarn` here. A pack cannot: it is not on the
        // public API, and the one channel a pack does have — stderr — is read by
        // some CLIs as the deny text itself, so writing to it from an ALLOW path
        // would show the user a block that never happened. An unparseable
        // user-supplied pattern is skipped, which is what the builtin does for
        // enforcement purposes too. The only behavioural difference between this
        // pack and the builtin that is not a deliberate narrowing.
      }
    }

    return allow();
  },
});

customPolicies.add({
  name: "sanitize-connection-strings",
  description:
    "Stop Claude from reading database connection strings with embedded credentials in tool responses",
  category: "Sanitize",
  defaultEnabled: true,
  match: { events: ["PostToolUse"] },
  authority: "hard",
  fn: (ctx) => {
    const output = JSON.stringify(ctx.payload);
    if (CONNECTION_STRING_RE.test(output)) {
      return {
        decision: "deny",
        reason: "Database connection string with credentials detected in tool output",
        message: "[REDACTED: connection string removed by failproofai]",
      };
    }
    return allow();
  },
});

customPolicies.add({
  name: "sanitize-private-key-content",
  description: "Stop Claude from reading PEM private key content in tool responses",
  category: "Sanitize",
  defaultEnabled: true,
  match: { events: ["PostToolUse"] },
  authority: "hard",
  fn: (ctx) => {
    const output = JSON.stringify(ctx.payload);
    if (PRIVATE_KEY_RE.test(output)) {
      return {
        decision: "deny",
        reason: "Private key content detected in tool output",
        message: "[REDACTED: private key content removed by failproofai]",
      };
    }
    return allow();
  },
});

customPolicies.add({
  name: "sanitize-bearer-tokens",
  description: "Stop Claude from reading Authorization Bearer tokens in tool responses",
  category: "Sanitize",
  defaultEnabled: true,
  match: { events: ["PostToolUse"] },
  authority: "hard",
  fn: (ctx) => {
    const output = JSON.stringify(ctx.payload);
    if (BEARER_TOKEN_RE.test(output)) {
      return {
        decision: "deny",
        reason: "Bearer token detected in tool output",
        message: "[REDACTED: Bearer token removed by failproofai]",
      };
    }
    return allow();
  },
});

// ─────────────────────────────────────────────────────────────────────────────
// Environment
// ─────────────────────────────────────────────────────────────────────────────

customPolicies.add({
  name: "protect-env-vars",
  description: "Prevent commands that read environment variables",
  category: "Environment",
  defaultEnabled: true,
  match: { events: ["PreToolUse"], toolNames: ["Bash"] },
  // Both checks are asked on EVERY shell call — `env-secrets-dump` and
  // `secret-exposure` each declare `appliesTo: ["shell", …]` and neither has a
  // precondition — and this policy only ever fires on Bash, so the conjunction is
  // live for every input it matches. `env-secrets-dump` is the same concern
  // ("prints environment variable VALUES that may be secret") and clears the
  // ordinary-variable case.
  //
  // `secret-exposure` is the builtin's own second name, kept verbatim. It is NOT
  // what makes this a review — that is the refined test: even a conjunction naming
  // only `env-secrets-dump` would be honest here, because `secret-exposure` is
  // asked on the same call whether or not it is named and can deny on its own
  // through the most-severe merge. Naming it as well only makes the clear stricter,
  // and since it is what shipped and what was measured, it stays as it is.
  authority: "reviewable",
  reviewedBy: ["env-secrets-dump", "secret-exposure"],
  // REWRITTEN: the `echo`, `export` and `$env:` branches. See `secretEchoedVar`,
  // `secretPsEnvVar` and `EXPORT_DUMP_RE` in ./shared.ts for what each gives up.
  fn: (ctx) => {
    if (ctx.toolName !== "Bash") return allow();
    const cmd = getCommand(ctx);
    if (ENV_PRINTENV_RE.test(cmd)) {
      return deny("Command reads environment variables");
    }
    if (EXPORT_DUMP_RE.test(cmd)) {
      return deny("Command prints every exported environment variable");
    }
    // PowerShell: Get-ChildItem Env: / dir env: / gci env: / ls env: — a full dump.
    if (PS_CHILDITEM_ENV_RE.test(cmd)) {
      return deny("Command reads environment variables via PowerShell");
    }
    // .NET: [Environment]::GetEnvironmentVariable(s)
    if (DOTNET_GETENV_RE.test(cmd)) {
      return deny("Command reads environment variable via .NET");
    }
    // PowerShell `$env:NAME` — position-independent, like the builtin's pattern.
    const psName = secretPsEnvVar(cmd);
    if (psName) return deny(`Command reads environment variable $env:${psName} via PowerShell`);
    // `echo` / `printf` of a credential-shaped `$VAR` or `%VAR%`.
    const name = secretEchoedVar(cmd);
    if (name) return deny(`Command echoes environment variable $${name}`);
    return allow();
  },
});

customPolicies.add({
  name: "block-env-files",
  description: "Block reading/writing .env files",
  category: "Environment",
  defaultEnabled: true,
  match: { events: ["PreToolUse"] },
  // `secret-exposure` applies to shell, read AND write, has no precondition, and
  // this policy's only two branches are a `file_path` (read/write tools) and a
  // Bash command — so it is asked for every input. On an MCP tool, which this
  // policy also matches because it declares no `toolNames`, `selectPolicies` asks
  // every check regardless of class, so the pairing is live there too. Its false
  // criteria names this policy's largest false-positive class outright: "an
  // .env.example template, a test fixture, documentation about credentials".
  authority: "reviewable",
  reviewedBy: ["secret-exposure"],
  // REWRITTEN: the Bash branch. See `ENV_FILE_TOKEN_RE` in ./shared.ts.
  fn: (ctx) => {
    const cmd = getCommand(ctx);
    const filePath = getFilePath(ctx);

    if (filePath && ENV_FILE_PATH_RE.test(filePath)) {
      return deny("Access to .env file blocked");
    }
    if (ctx.toolName === "Bash" && ENV_FILE_TOKEN_RE.test(cmd)) {
      return deny("Command references .env file");
    }
    return allow();
  },
});

customPolicies.add({
  name: "block-read-outside-cwd",
  description: "Block file reads outside the session working directory",
  category: "Environment",
  defaultEnabled: false,
  match: { events: ["PreToolUse"], toolNames: ["Read", "Glob", "Grep", "Bash"] },
  // `read-outside-workspace` applies to shell AND read, covering all four tools
  // this policy matches, and its precondition was widened specifically for this
  // pairing: it fires on any path relation outside the project INCLUDING
  // `system`, and separately on any path outside the live cwd. Before that
  // widening it asked only about the two home relations while this policy denied
  // any path outside the project, which left 106 of its 154 denials on the
  // 1,332-case corpus with no paired question at all — unclearable by
  // construction, because the paths were mostly /tmp/claude-* and classify as
  // `system`. That is the exact bug this pack must not reintroduce anywhere else.
  //
  // Instruct-only, and correctly so — this is the row that shows why the test is
  // "is anything left that can deny" and not "can this conjunction keep the
  // block". `read-outside-workspace` is `mode: "instruct"`, so once it is asked
  // this policy's deny is always cleared. Nothing is left unenforced by that,
  // because clearing a regex verdict does not stop the semantic tier answering:
  // `secret-exposure`, `credential-exfiltration` and `agent-config-tampering` are
  // all asked on the same call, all `mode: "deny"`, and all still deny ON THEIR
  // OWN through the most-severe merge. A read of `~/.aws/credentials` outside the
  // project is still blocked — by the check that understands it, instead of by a
  // path comparison. So Jev REPLACES the regex judgment on the noisiest policy in
  // the set rather than surrendering it.
  //
  // An earlier revision of this pack added `secret-exposure` to the conjunction
  // "so the pairing could keep a block". Reverted: it is unnecessary under the
  // refined test, and it is not free. #833's headline numbers (false blocks
  // 32% → 7.4%, attacks 123 of 234) were measured with this pairing exactly as it
  // stands, so removing clears here — which is all a second name can do — moves a
  // measured result in the one place the PR makes a numeric claim. That needs a
  // corpus replay, not a judgement call.
  authority: "reviewable",
  reviewedBy: ["read-outside-workspace"],
  params: {
    allowPaths: {
      type: "string[]",
      description: "Absolute paths outside cwd that are allowed to be read",
      default: [],
    },
  },
  fn: (ctx) => {
    // Prefer $CLAUDE_PROJECT_DIR (stable project root) over ctx.session.cwd,
    // which tracks the live shell CWD and drifts when the agent `cd`s into a subdir.
    const cwd = process.env.CLAUDE_PROJECT_DIR || ctx.session?.cwd;
    if (!cwd) return allow(); // Can't enforce without cwd

    const allowPaths = (ctx.params?.allowPaths ?? []) as string[];

    if (ctx.toolName === "Bash") {
      const cmd = getCommand(ctx);
      if (!READ_LIKE_CMDS.test(cmd)) return allow();

      const paths = extractAbsolutePaths(cmd);
      const cwdWithSep = cwd.endsWith("/") ? cwd : cwd + "/";
      for (const p of paths) {
        const resolved = resolve(cwd, p);
        if (isAgentSettingsFile(resolved)) {
          return deny(`Reading agent settings file blocked: ${resolved}`);
        }
        if (isAgentInternalPath(resolved)) continue; // Whitelist ~/.claude/ et al.
        if (resolved === "/dev/null") continue; // Harmless special file
        if (resolved !== cwd && !resolved.startsWith(cwdWithSep)) {
          if (allowPaths.some((ap) => resolved === ap || resolved.startsWith(ap.endsWith("/") ? ap : ap + "/"))) continue;
          return deny(`Bash read outside project directory blocked: ${resolved}`);
        }
      }
      return allow();
    }

    const filePath = getFilePath(ctx);
    const searchPath = (ctx.toolInput?.path as string) ?? "";

    const target = filePath || searchPath;
    if (!target) return allow();

    const resolved = resolve(cwd, target);

    if (isAgentSettingsFile(resolved)) {
      return deny(`Reading agent settings file blocked: ${resolved}`);
    }
    if (isAgentInternalPath(resolved)) return allow();
    if (resolved === "/dev/null") return allow();

    const cwdWithSep = cwd.endsWith("/") ? cwd : cwd + "/";
    if (resolved !== cwd && !resolved.startsWith(cwdWithSep)) {
      if (allowPaths.some((ap) => resolved === ap || resolved.startsWith(ap.endsWith("/") ? ap : ap + "/"))) return allow();
      return deny(`Access outside project directory blocked: ${resolved}`);
    }
    return allow();
  },
});

// ─────────────────────────────────────────────────────────────────────────────
// Dangerous Commands
// ─────────────────────────────────────────────────────────────────────────────

customPolicies.add({
  name: "block-sudo",
  description: "Block sudo commands",
  category: "Dangerous Commands",
  defaultEnabled: true,
  // PermissionRequest is Codex's escalation-approval event; fire the same sudo
  // guard there so Codex sandbox bypasses are blocked too. Jev is asked on both
  // PreToolUse and PermissionRequest, so the pairing below covers both events.
  match: { events: ["PreToolUse", "PermissionRequest"], toolNames: ["Bash"] },
  // `privilege-escalation` is the purpose-built twin: `appliesTo: ["shell"]`, no
  // precondition (so asked on every Bash call), `mode: "deny"` (so a genuine
  // escalation it recognises comes back `deny` and the block STANDS — pairing with
  // an `instruct`-mode check would have downgraded this policy to a warning), and
  // a probe that enumerates sudo, doas, su, pkexec and run0 "including when the
  // binary is written as an absolute path or reached through a variable or
  // wrapper" — a superset of what `namesElevation` can see. What a clear buys is
  // the two cases the string matcher cannot judge: the user asked for this exact
  // command, and the word appears where no elevation happens.
  authority: "reviewable",
  reviewedBy: ["privilege-escalation"],
  params: {
    allowPatterns: {
      type: "string[]",
      description:
        "Sudo command patterns to allow, matched token-by-token (e.g. 'sudo systemctl status')",
      default: [],
    },
  },
  fn: (ctx) => {
    if (ctx.toolName !== "Bash") return allow();
    const cmd = getCommand(ctx).trimStart();
    if (namesElevation(cmd)) {
      const allowPatterns = (ctx.params?.allowPatterns ?? []) as string[];
      if (allowPatterns.some((p) => matchesAllowedPattern(cmd, p))) return allow();
      return deny("sudo commands are blocked");
    }
    if (PS_ELEVATION_RE.test(cmd)) {
      return deny("Elevated process launch is blocked");
    }
    if (RUNAS_RE.test(cmd)) {
      return deny("runas elevation is blocked");
    }
    return allow();
  },
});

customPolicies.add({
  name: "block-curl-pipe-sh",
  description: "Block piping downloads to shell",
  category: "Dangerous Commands",
  defaultEnabled: true,
  match: { events: ["PreToolUse"], toolNames: ["Bash"] },
  // `remote-code-execution`: shell class, no precondition, `mode: "deny"`, and a
  // probe whose examples are this policy's own pattern. Two things only the
  // semantic side can decide, both of which this policy gets wrong today:
  // `CURL_PIPE_SH_RE` matches the substring anywhere, so `grep -rn "curl x | sh"
  // README.md` and a commit message quoting an install line are both denied — the
  // probe's false criteria names that outright ("merely searches for or quotes
  // such a command (for example grep over a README)") — and the check carries an
  // `official_installer` exemption for `bun.sh`, `sh.rustup.rs`, `get.docker.com`
  // and friends, which is the single most common legitimate instance.
  authority: "reviewable",
  reviewedBy: ["remote-code-execution"],
  fn: (ctx) => {
    if (ctx.toolName !== "Bash") return allow();
    const cmd = getCommand(ctx);
    if (CURL_PIPE_SH_RE.test(cmd)) {
      return deny("Piping downloads to shell is blocked");
    }
    if (PS_WEB_PIPE_RE.test(cmd)) {
      return deny("Piping downloads to Invoke-Expression is blocked");
    }
    return allow();
  },
});

customPolicies.add({
  name: "block-rm-rf",
  description: "Prevent catastrophic deletions",
  category: "Dangerous Commands",
  defaultEnabled: false,
  match: { events: ["PreToolUse"], toolNames: ["Bash"] },
  // `destructive-deletion`: shell+write, no precondition, `mode: "deny"`, two
  // probes. The second one — `irreplaceable` — is the judgement this policy
  // approximates with a path-depth count, and its false criteria is the
  // approximation's error term verbatim: "build output, dist/, caches,
  // node_modules, virtualenvs, coverage reports, temp files". `isCatastrophicTarget`
  // denies `rm -rf ~/.cache` (one segment below home), `rm -rf ~/.npm` and every
  // `rm -rf $VAR` whose head it cannot resolve; all three are cleared by a check
  // that can see what the target actually holds. `rm -rf /` keeps both probes true
  // and stays denied.
  authority: "reviewable",
  reviewedBy: ["destructive-deletion"],
  params: {
    allowPaths: {
      type: "string[]",
      description: "Paths that are allowed to be recursively deleted",
      default: [],
    },
  },
  fn: (ctx) => {
    if (ctx.toolName !== "Bash") return allow();
    const cmd = getCommand(ctx);

    const hasCatastrophicTarget = shellSegments(cmd).some((seg) => {
      const targets = recursiveDeletionTargets(seg);
      return targets !== null && targets.some(isCatastrophicTarget);
    });
    if (hasCatastrophicTarget) {
      const allowPaths = (ctx.params?.allowPaths ?? []) as string[];
      if (deletionTargetIsAllowed(cmd, allowPaths)) return allow();
      return deny("Catastrophic deletion blocked");
    }

    // PowerShell: Remove-Item -Recurse -Force on root/drive
    if (/Remove-Item\s+.*-Recurse.*-Force.*(?:[A-Z]:\\(?:\s|$)|\\\*)/i.test(cmd)) {
      return deny("Catastrophic deletion blocked");
    }
    // cmd: rd /s /q or rmdir /s /q on drive root
    if (/(?:rd|rmdir)\s+\/s\s+\/q\s+[A-Z]:\\/i.test(cmd)) {
      return deny("Catastrophic deletion blocked");
    }
    return allow();
  },
});

// `block-failproofai-commands` belongs here in catalog order. It is `alwaysOn`
// and a pack may not declare that, so it is absent — see the header.

// ─────────────────────────────────────────────────────────────────────────────
// Infra Commands
//
// All six CLI guards share one reviewer and one reason, so it is written once.
//
// `production-infra-change` is `appliesTo: ["shell"]`, has no precondition, and is
// `mode: "deny"`. Its first probe enumerates every one of these binaries by name
// ("kubectl, helm, terraform, tofu, pulumi, aws, gcloud, az, doctl, flyctl,
// vercel, wrangler, railway, and so on — however the binary is spelled or
// pathed"), and its false criteria is precisely the split these six regexes cannot
// make: "It only reads or plans: get, list, describe, logs, status, plan, diff,
// validate, whoami, or --dry-run." Every one of these policies denies the whole
// CLI, read-only subcommands included, unless the user hand-writes an
// `allowPatterns` entry. Its second probe adds the other half — `not_local`, which
// clears kind, minikube, k3d, docker-desktop and any context, workspace or profile
// whose name says dev, test, staging, sandbox or local — and answers "unknown
// environment" as production, so nothing is cleared by ambiguity.
//
// The residual: a `terraform apply` against real production that the user
// genuinely asked for is cleared by the user-override path. That is the semantic
// tier's own design (`userCanOverride: true` on this check) and it needs the scope
// probe, the target-naming check and a clean injection answer to fire.
// ─────────────────────────────────────────────────────────────────────────────

function blockInfraCli(ctx: PolicyContext, re: RegExp, denyMsg: string): PolicyResult {
  if (ctx.toolName !== "Bash") return allow();
  const cmd = getCommand(ctx);
  if (!re.test(cmd)) return allow();
  const allowPatterns = (ctx.params?.allowPatterns ?? []) as string[];
  if (allowPatterns.some((p) => matchesAllowedPattern(cmd, p))) return allow();
  return deny(denyMsg);
}

const INFRA_REVIEWED_BY = ["production-infra-change"];

customPolicies.add({
  name: "block-kubectl",
  description: "Block kubectl commands (Kubernetes cluster mutations)",
  category: "Infra Commands",
  defaultEnabled: false,
  match: { events: ["PreToolUse"], toolNames: ["Bash"] },
  authority: "reviewable",
  reviewedBy: INFRA_REVIEWED_BY,
  params: {
    allowPatterns: {
      type: "string[]",
      description:
        "kubectl command patterns to allow, matched token-by-token (e.g. 'kubectl get *', 'kubectl describe *')",
      default: [],
    },
  },
  fn: (ctx) => blockInfraCli(ctx, KUBECTL_RE, "kubectl commands are blocked"),
});

customPolicies.add({
  name: "block-terraform",
  description: "Block terraform and tofu (OpenTofu) commands",
  category: "Infra Commands",
  defaultEnabled: false,
  match: { events: ["PreToolUse"], toolNames: ["Bash"] },
  authority: "reviewable",
  reviewedBy: INFRA_REVIEWED_BY,
  params: {
    allowPatterns: {
      type: "string[]",
      description: "terraform/tofu command patterns to allow (e.g. 'terraform plan', 'terraform validate')",
      default: [],
    },
  },
  fn: (ctx) => blockInfraCli(ctx, TERRAFORM_RE, "terraform/tofu commands are blocked"),
});

customPolicies.add({
  name: "block-aws-cli",
  description: "Block aws CLI commands",
  category: "Infra Commands",
  defaultEnabled: false,
  match: { events: ["PreToolUse"], toolNames: ["Bash"] },
  authority: "reviewable",
  reviewedBy: INFRA_REVIEWED_BY,
  params: {
    allowPatterns: {
      type: "string[]",
      description: "aws CLI command patterns to allow (e.g. 'aws s3 ls *', 'aws sts get-caller-identity')",
      default: [],
    },
  },
  fn: (ctx) => blockInfraCli(ctx, AWS_CLI_RE, "aws CLI commands are blocked"),
});

customPolicies.add({
  name: "block-gcloud",
  description: "Block gcloud (Google Cloud) CLI commands",
  category: "Infra Commands",
  defaultEnabled: false,
  match: { events: ["PreToolUse"], toolNames: ["Bash"] },
  authority: "reviewable",
  reviewedBy: INFRA_REVIEWED_BY,
  params: {
    allowPatterns: {
      type: "string[]",
      description: "gcloud command patterns to allow (e.g. 'gcloud auth list', 'gcloud config list')",
      default: [],
    },
  },
  fn: (ctx) => blockInfraCli(ctx, GCLOUD_RE, "gcloud commands are blocked"),
});

customPolicies.add({
  name: "block-az-cli",
  description: "Block az (Azure) CLI commands",
  category: "Infra Commands",
  defaultEnabled: false,
  match: { events: ["PreToolUse"], toolNames: ["Bash"] },
  authority: "reviewable",
  reviewedBy: INFRA_REVIEWED_BY,
  params: {
    allowPatterns: {
      type: "string[]",
      description: "az CLI command patterns to allow (e.g. 'az account show', 'az group list')",
      default: [],
    },
  },
  fn: (ctx) => blockInfraCli(ctx, AZ_CLI_RE, "az (Azure) CLI commands are blocked"),
});

customPolicies.add({
  name: "block-helm",
  description: "Block helm commands",
  category: "Infra Commands",
  defaultEnabled: false,
  match: { events: ["PreToolUse"], toolNames: ["Bash"] },
  authority: "reviewable",
  reviewedBy: INFRA_REVIEWED_BY,
  params: {
    allowPatterns: {
      type: "string[]",
      description: "helm command patterns to allow (e.g. 'helm list', 'helm status *')",
      default: [],
    },
  },
  fn: (ctx) => blockInfraCli(ctx, HELM_RE, "helm commands are blocked"),
});

customPolicies.add({
  name: "block-gh-pipeline",
  description:
    "Block gh CLI pipeline-trigger subcommands (workflow run, run rerun/cancel, pr merge, release create/delete, cache delete, secret set/delete)",
  category: "Infra Commands",
  defaultEnabled: false,
  match: { events: ["PreToolUse"], toolNames: ["Bash"] },
  // HARD, and the only Infra policy that is. The check whose probe names these
  // actions — `external-destructive-action`: "merging or closing pull requests;
  // changing permissions, access or billing" — is `appliesTo: ["other"]`, and this
  // policy only ever fires on Bash, which classifies as `shell`. `selectPolicies`
  // would never ask it, so naming it would make the block PERMANENT. And the
  // check that IS asked on a shell call, `production-infra-change`, answers `none`
  // for `gh pr merge`, `gh workflow run`, `gh release create`, `gh cache delete`
  // and `gh run rerun` — none of them mutates cloud or cluster state — and a
  // `none` answer CLEARS. So that pairing would not review this policy; it would
  // switch it off for five of its six shapes while leaving `gh secret set` as the
  // only one still blocked.
  authority: "hard",
  params: {
    allowPatterns: {
      type: "string[]",
      description:
        "gh pipeline command patterns to allow (e.g. specific scripted invocations); read-only gh subcommands like 'gh pr view' and 'gh run list' are not matched by this policy",
      default: [],
    },
  },
  fn: (ctx) => blockInfraCli(ctx, GH_PIPELINE_RE, "gh pipeline-trigger commands are blocked"),
});

customPolicies.add({
  name: "block-secrets-write",
  description: "Block writing secret key files",
  category: "Dangerous Commands",
  defaultEnabled: false,
  // DIVERGES from the builtin, which matches `["Write"]` only. That left a hole
  // in the one policy whose entire job is these files: `Edit` on
  // `~/.ssh/id_rsa` or `~/.aws/credentials` passed the whole regex tier, because
  // nothing else covers it either (`block-read-outside-cwd` is
  // `["Read", "Glob", "Grep", "Bash"]`, and `block-env-files` only matches a
  // `.env` path). The policy's name and description both say "writing", so the
  // gap was invisible from the outside. `Edit` carries the same canonical
  // `file_path` key on every CLI, so the path detection is used unchanged.
  //
  // `NotebookEdit` is deliberately not added: `writesSecretFile` matches
  // `*.pem`, `*.key`, `id_rsa` and a `credentials` stem, and no `.ipynb` is any
  // of those, so it would widen the match without changing one verdict. `Bash`
  // is not added either — a shell write needs a command detector this policy has
  // never had, and inventing one here would be a new policy wearing this one's
  // name.
  match: { events: ["PreToolUse"], toolNames: ["Write", "Edit"] },
  // `secret-exposure` includes the `write` class and has no precondition, so it is
  // asked on every call this policy matches. `mode: "deny"`, so an actual private
  // key still comes back `deny` and the block stands. What it clears is the
  // substring problem: the builtin tested `/credentials/` and `/id_rsa/`
  // unanchored against the whole path, and the check's false criteria — "source
  // code that reads process.env, a variable name, an .env.example template, a test
  // fixture, documentation about credentials" — is a list of the things that
  // matched. Half of that class is now excluded deterministically too (see
  // `writesSecretFile`).
  //
  // Not routed around: `credential-exfiltration`, the non-overridable check, is
  // about secrets LEAVING the machine and is `appliesTo: ["shell", "network"]`.
  // Writing a local file is neither, so naming it here would have been a dead
  // name, and clearing this policy cannot suppress it — every applicable semantic
  // check is still asked independently and its own deny still joins the
  // most-severe merge.
  authority: "reviewable",
  reviewedBy: ["secret-exposure"],
  params: {
    additionalPatterns: {
      type: "string[]",
      description: "Additional filename patterns (substrings) to block",
      default: [],
    },
  },
  // REWRITTEN: basename-anchored. See `writesSecretFile` in ./shared.ts.
  fn: (ctx) => {
    if (ctx.toolName !== "Write" && ctx.toolName !== "Edit") return allow();
    const filePath = getFilePath(ctx);
    if (writesSecretFile(filePath)) {
      return deny("Writing secret key files is blocked");
    }
    const additionalPatterns = (ctx.params?.additionalPatterns ?? []) as string[];
    for (const pattern of additionalPatterns) {
      if (filePath.includes(pattern)) {
        return deny(`Writing blocked file pattern: ${pattern}`);
      }
    }
    return allow();
  },
});

// ─────────────────────────────────────────────────────────────────────────────
// Git
// ─────────────────────────────────────────────────────────────────────────────

customPolicies.add({
  name: "block-push-master",
  description: "Block pushing to main/master",
  category: "Git",
  defaultEnabled: true,
  match: { events: ["PreToolUse"], toolNames: ["Bash"] },
  // HARD — and the reason is worth more written down than the pairing would have
  // been worth shipping.
  //
  // The obvious candidate, `push-to-protected-branch`, IS asked on every Bash
  // call (shell class, no precondition). But it is `mode: "instruct"`, and an
  // instruct-mode check can never return `deny` (`decide.ts`: `p.mode === "deny"
  // && evidence >= thresholds.deny ? "deny" : "instruct"`), while `instruct`
  // counts as a clear. So once it is asked, this policy's deny is always cleared.
  //
  // Instruct-only is not itself the defect — `block-read-outside-cwd` is
  // instruct-only and correct. The defect is what is left afterwards: ask which
  // deny-mode check could still stop `git push origin main` on its own, and the
  // answer is none. `git-history-rewrite` is deny-mode and is asked, but it fires
  // on a force-push or a remote-branch delete, not on an ordinary push that only
  // adds commits. Nothing else in the 16 mentions protected branches at all. So a
  // clear here leaves the call unenforced by both tiers, converting a
  // `defaultEnabled: true` block into nothing on every machine with a Jev key.
  //
  // Blocking a push to main is not a false positive; it is the policy working,
  // and it is one of the most visible guarantees the product makes. This pack
  // exists to cut false blocks on NOISY policies, not to lower severity on a
  // correct one, and a severity change nobody asked for is not a pack's to make.
  // The noise this policy DID have was a matcher bug, not a severity problem, and
  // it is fixed deterministically below — see `pushTargetRef`, which is what makes
  // staying hard affordable.
  authority: "hard",
  params: {
    protectedBranches: {
      type: "string[]",
      description: "Branch names to protect from direct pushes",
      default: ["main", "master"],
    },
  },
  // REWRITTEN: exact ref match instead of `\bmain\b` over the argument string.
  // See `pushTargetRef` in ./shared.ts.
  fn: (ctx) => {
    if (ctx.toolName !== "Bash") return allow();
    const protectedBranches = (ctx.params?.protectedBranches ?? ["main", "master"]) as string[];
    if (protectedBranches.length === 0) return allow();
    const protectedSet = new Set(protectedBranches);
    for (const args of extractGitPushArgs(getCommand(ctx))) {
      // The first bare operand is the remote (`git push origin main`); a lone bare
      // operand is a remote too (`git push origin`), which is why refspecs are
      // only read from the second onward.
      const operands = parseArgvTokens(args).filter((t) => t !== "" && !t.startsWith("-"));
      for (const token of operands.slice(1)) {
        const ref = pushTargetRef(token);
        if (ref !== null && protectedSet.has(ref)) {
          return deny(`Pushing to ${protectedBranches.join("/")} is blocked`);
        }
      }
    }
    return allow();
  },
});

customPolicies.add({
  name: "block-force-push",
  description: "Prevent force-pushing to any branch",
  category: "Git",
  defaultEnabled: false,
  match: { events: ["PreToolUse"], toolNames: ["Bash"] },
  // `git-history-rewrite`: shell class, no precondition, `mode: "deny"`, and its
  // probe is a superset of this matcher — it counts `--force-with-lease` (which
  // `isForcePushFlag` deliberately treats as safe), a `+refspec`, and deleting a
  // remote branch, and it says outright that `git -C dir` / `git -c key=val` and
  // an absolute path to the binary do not change what the command does. So a real
  // force-push comes back `deny` and the block stands.
  //
  // What a clear buys is the one case this policy cannot distinguish and that
  // `SCOPE_PROBE`'s own doc comment cites: the user asked to force-push their own
  // branch. Rebasing your own PR branch and pushing it is ordinary work, and the
  // override needs the human's words to name the target, the scope answer to hold,
  // and the injection answer to be clean.
  authority: "reviewable",
  reviewedBy: ["git-history-rewrite"],
  fn: (ctx) => {
    if (ctx.toolName !== "Bash") return allow();
    for (const segment of extractGitPushArgs(getCommand(ctx))) {
      let sawEndOfOptions = false;
      for (const token of segment.split(/\s+/)) {
        if (token === "--") {
          sawEndOfOptions = true;
          continue;
        }
        if (sawEndOfOptions) continue;
        if (isForcePushFlag(token)) {
          return deny("Force-pushing is blocked");
        }
      }
    }
    return allow();
  },
});

customPolicies.add({
  name: "block-work-on-main",
  description: "Block git commits and merges on main/master branch",
  category: "Git",
  defaultEnabled: false,
  match: { events: ["PreToolUse"], toolNames: ["Bash"] },
  // HARD. The builtin shipped this as reviewable by `commit-on-protected-branch`
  // and has since landed the same change with the same reasoning, so the two
  // agree; the argument is kept here because it is the clearest case of it.
  //
  // That check is the right concern stated as behaviour, and it is asked wherever
  // this policy can fire with the default params (its precondition covers main,
  // master, production, prod, release and trunk — a strict superset of
  // `["main", "master"]`). But it is `mode: "instruct"`, so once it is asked this
  // policy's deny is always cleared — and no deny-mode check in the 16 can stop a
  // `git commit` on main on its own. Nothing is left. So the mark reads
  // "reviewable" while the policy is in fact SWITCHED OFF wherever Jev is
  // configured, and a user who deliberately opted into it — it is
  // `defaultEnabled: false`, so enabling it is an act — gets nothing for it.
  // `hard` is the honest state.
  //
  // The contrast that makes this a defect rather than a design is
  // `block-read-outside-cwd`, which is also instruct-only and is correct: three
  // deny-mode checks are asked on that same call and still deny on their own, so
  // Jev REPLACES the regex judgment there. Here there is nothing to replace it
  // with, which is why the test is "is anything left that can deny" rather than
  // "can this conjunction keep the block".
  //
  // What this costs, stated rather than hidden: `GIT_COMMIT_MERGE_RE` matches
  // `git commit|merge|rebase|cherry-pick` as a SUBSTRING, so on a protected branch
  // it denies `gh pr create --body "git commit"` and `grep -rn "git rebase" docs/`
  // with nothing left to clear them. The exposure is bounded — the policy is
  // `defaultEnabled: false`, so it is opt-in — and the fix is the same shape as
  // `pushTargetRef`: require `git` in command position. That is a matcher change
  // with its own false-positive surface, so it belongs in the builtin where its
  // tests live, not in a pack. Recorded in DECISIONS.md as the one coverage
  // regression this pack accepts relative to the builtin.
  authority: "hard",
  params: {
    protectedBranches: {
      type: "string[]",
      description: "Branch names where commits/merges are blocked",
      default: ["main", "master"],
    },
  },
  fn: (ctx) => {
    if (ctx.toolName !== "Bash") return allow();
    const cmd = getCommand(ctx);
    const match = cmd.match(GIT_COMMIT_MERGE_RE);
    if (!match) return allow();

    const cwd = ctx.session?.cwd;
    if (!cwd) return allow();

    const branch = getCurrentBranch(cwd);
    if (!branch) return allow();

    const protectedBranches = (ctx.params?.protectedBranches ?? ["main", "master"]) as string[];
    if (protectedBranches.includes(branch)) {
      return deny(`Git ${match[1]} on ${branch} is blocked. Create a feature branch first.`);
    }
    return allow();
  },
});

customPolicies.add({
  name: "warn-git-amend",
  description: "Warns before amending git commits, which rewrites history",
  category: "Git",
  defaultEnabled: false,
  match: { events: ["PreToolUse"], toolNames: ["Bash"] },
  // Amending an UNPUSHED commit is ordinary; the harm is rewriting history others
  // may have pulled, and no string can tell the two apart. `git-history-rewrite`
  // is asked on every Bash call and answers on the whole command, which is what
  // makes this work in both directions: a bare `git commit --amend` leaves
  // `rewrites_remote` false, so the check answers `none` and the warning is
  // cleared — the intended outcome, not a blanket clear — while
  // `git commit --amend && git push -f` keeps it true, comes back `deny`, and the
  // call is blocked harder than this policy's own instruct would have been.
  authority: "reviewable",
  reviewedBy: ["git-history-rewrite"],
  fn: (ctx) => {
    if (ctx.toolName !== "Bash") return allow();
    const cmd = getCommand(ctx);
    if (GIT_AMEND_RE.test(cmd)) {
      return instruct(
        "STOP: This command amends the last commit, which rewrites git history. If this commit has already been pushed to a shared branch, this will cause divergence for other contributors. Confirm with the user before executing.",
      );
    }
    return allow();
  },
});

customPolicies.add({
  name: "warn-git-stash-drop",
  description: "Warns before permanently deleting stashed changes",
  category: "Git",
  defaultEnabled: false,
  match: { events: ["PreToolUse"], toolNames: ["Bash"] },
  // HARD. The nearest check, `destructive-deletion`, IS asked on every Bash call —
  // so this is not the dead-pairing failure, it is the opposite one. Its first
  // probe is written about the filesystem: "permanently deletes, wipes, truncates
  // or overwrites existing files, directories or disks". A `git stash drop`
  // touches no file and leaves the working tree alone, so `destroys` answers
  // false, evidence is the min over probes, the outcome is `none` — and `none`
  // CLEARS. Naming it would not review this policy; it would silence it on every
  // input it matches. Nothing else in the 16 mentions discarding uncommitted work.
  authority: "hard",
  fn: (ctx) => {
    if (ctx.toolName !== "Bash") return allow();
    const cmd = getCommand(ctx);
    if (GIT_STASH_DROP_RE.test(cmd)) {
      return instruct(
        "STOP: This command permanently deletes stashed changes (git stash drop/clear). Stash entries cannot be recovered after deletion. Confirm with the user before executing.",
      );
    }
    return allow();
  },
});

customPolicies.add({
  name: "warn-all-files-staged",
  description: "Warns before staging all working tree files with git add -A / . / --all",
  category: "Git",
  defaultEnabled: false,
  match: { events: ["PreToolUse"], toolNames: ["Bash"] },
  // HARD. The concern is what a wide stage PICKS UP — a generated file, a key, a
  // local override — which is a property of the working tree, and no probe in the
  // 16 reads the working tree. `secret-exposure` is asked on the call and answers
  // `none` for `git add -A` (it stages; it reads and prints nothing), and `none`
  // clears, so pairing with it would switch this policy off rather than narrow it.
  authority: "hard",
  fn: (ctx) => {
    if (ctx.toolName !== "Bash") return allow();
    const cmd = getCommand(ctx);
    if (GIT_ADD_ALL_RE.test(cmd)) {
      return instruct(
        "STOP: This command stages all files in the working tree (git add -A / --all / .). This may inadvertently include build artifacts, generated files, or sensitive files not covered by .gitignore. Confirm with the user before executing.",
      );
    }
    return allow();
  },
});

// ─────────────────────────────────────────────────────────────────────────────
// Database
// ─────────────────────────────────────────────────────────────────────────────

customPolicies.add({
  name: "warn-destructive-sql",
  description:
    "Warn before executing destructive SQL (DROP/TRUNCATE/DELETE without WHERE) via database clients",
  category: "Database",
  defaultEnabled: false,
  match: { events: ["PreToolUse"], toolNames: ["Bash"] },
  // `database-destruction`: shell class, no precondition, `mode: "deny"`, two
  // probes. The first is this policy restated as behaviour and adds what the regex
  // gets wrong — it counts an always-true predicate (`WHERE 1=1`, `WHERE id > 0`)
  // as narrowing nothing, where `SQL_WHERE_RE` accepts any `WHERE` at all. The
  // second, `real_database`, is the judgement this policy cannot make: it clears a
  // sqlite `:memory:` or a `test_` database and treats "cannot be told" as real.
  authority: "reviewable",
  reviewedBy: ["database-destruction"],
  fn: (ctx) => {
    if (ctx.toolName !== "Bash") return allow();
    const cmd = getCommand(ctx);
    if (!SQL_TOOL_RE.test(cmd)) return allow();

    if (DESTRUCTIVE_SQL_RE.test(cmd)) {
      return instruct(
        "STOP: This command contains destructive SQL (DROP/TRUNCATE/DELETE). Confirm with the user before executing.",
      );
    }

    if (DELETE_NO_WHERE_RE.test(cmd) && !SQL_WHERE_RE.test(cmd)) {
      return instruct(
        "STOP: This command contains destructive SQL (DROP/TRUNCATE/DELETE). Confirm with the user before executing.",
      );
    }

    return allow();
  },
});

customPolicies.add({
  name: "warn-schema-alteration",
  description: "Warns before SQL schema changes (ALTER TABLE with column or rename operations)",
  category: "Database",
  defaultEnabled: false,
  match: { events: ["PreToolUse"], toolNames: ["Bash"] },
  // HARD. `database-destruction` is asked on the call, but it asks about ROWS AND
  // TABLES being removed, and this policy's harm is different: an `ALTER TABLE`
  // takes a lock and breaks readers. `ADD COLUMN` and `RENAME COLUMN` destroy no
  // data, so the check answers `none` on exactly the two statements this policy
  // exists to surface — and `none` clears. Only `DROP COLUMN` would survive
  // review, so the pairing would remove most of the policy's coverage rather than
  // narrow it.
  authority: "hard",
  fn: (ctx) => {
    if (ctx.toolName !== "Bash") return allow();
    const cmd = getCommand(ctx);
    if (!SQL_TOOL_RE.test(cmd)) return allow();
    if (SCHEMA_ALTER_RE.test(cmd)) {
      return instruct(
        "STOP: This command contains a schema-altering SQL statement (ALTER TABLE with column or rename operation). Schema changes on production databases are irreversible or disruptive. Confirm with the user before executing.",
      );
    }
    return allow();
  },
});

// ─────────────────────────────────────────────────────────────────────────────
// Packages & System
// ─────────────────────────────────────────────────────────────────────────────

customPolicies.add({
  name: "warn-package-publish",
  description:
    "Warn before publishing packages to public registries (npm, PyPI, crates.io, RubyGems, etc.)",
  category: "Packages & System",
  defaultEnabled: false,
  match: { events: ["PreToolUse"], toolNames: ["Bash"] },
  // HARD, refused in both directions. The check whose probe names this —
  // `external-destructive-action`, "performs an irreversible or externally visible
  // action" — is `appliesTo: ["other"]`, and a `npm publish` is a Bash call, so it
  // is never asked: naming it makes the block permanent. The two checks that ARE
  // asked on a shell call and might look adjacent both answer `none`:
  // `production-infra-change` (a registry is not infrastructure) and
  // `system-modification` (publishing installs nothing), and `none` clears. There
  // is no pairing that reviews this policy rather than switching it off.
  authority: "hard",
  fn: (ctx) => {
    if (ctx.toolName !== "Bash") return allow();
    const cmd = getCommand(ctx);
    if (PUBLISH_CMD_RE.test(cmd)) {
      return instruct(
        "STOP: This command publishes a package to a public registry. Confirm with the user that this is intentional.",
      );
    }
    return allow();
  },
});

customPolicies.add({
  name: "warn-global-package-install",
  description: "Warns before installing packages globally (npm -g, cargo install, etc.)",
  category: "Packages & System",
  defaultEnabled: false,
  match: { events: ["PreToolUse"], toolNames: ["Bash"] },
  // The same concern: changing the machine outside the project.
  // `system-modification` is shell class with no precondition, its probe names
  // `npm install -g` and `pip install` outside a virtualenv explicitly.
  //
  // Instruct-only, like `block-read-outside-cwd`, but honest for a different
  // reason — and this row is the one place the refined test has to be read
  // carefully. Nothing deny-mode covers "installs software system-wide", so
  // "is anything left that can deny" answers NO here, exactly as it does for
  // `block-work-on-main`. What saves it is that this policy never denied: its own
  // verdict is `instruct`. There is no block to surrender, and a clear on
  // `instruct` means the check FIRED and warned, so the warning joins the
  // most-severe merge in Jev's words instead of a regex's. Severity in, severity
  // out. Its false criteria ("installs project dependencies locally") is what
  // clears the `PIP_SYSTEM_RE` case where `--user` is passed inside an active
  // venv.
  authority: "reviewable",
  reviewedBy: ["system-modification"],
  fn: (ctx) => {
    if (ctx.toolName !== "Bash") return allow();
    const cmd = getCommand(ctx);
    const isGlobal =
      NPM_GLOBAL_RE.test(cmd) ||
      YARN_GLOBAL_RE.test(cmd) ||
      PNPM_GLOBAL_RE.test(cmd) ||
      BUN_GLOBAL_RE.test(cmd) ||
      CARGO_INSTALL_RE.test(cmd) ||
      // Bare 'pip install' respects the active venv when one is present;
      // only flag explicit system-level flags (--user, --break-system-packages).
      PIP_SYSTEM_RE.test(cmd);
    if (isGlobal) {
      return instruct(
        "STOP: This command installs a package globally, which modifies the system-wide environment outside the project. This can conflict with other projects or system tools. Confirm with the user before executing.",
      );
    }
    return allow();
  },
});

customPolicies.add({
  name: "prefer-package-manager",
  description:
    "Blocks non-preferred package managers and tells Claude to use an allowed one (e.g., uv instead of pip)",
  category: "Packages & System",
  defaultEnabled: false,
  match: { events: ["PreToolUse"], toolNames: ["Bash"] },
  // HARD. This is a team convention, not a safety judgement, and there is nothing
  // for Jev to be right about: `pip install flask` inside a venv is the exact
  // command this policy blocks and the exact command `system-modification`'s false
  // criteria calls out as fine. That check is asked on every Bash call and would
  // answer `none` for essentially every input here, so the pairing would clear
  // 100% of the policy's denies. A convention with no semantic counterpart is the
  // clearest case in the pack for staying hard.
  authority: "hard",
  params: {
    allowed: {
      type: "string[]",
      description:
        "Allowed package manager names (e.g. ['uv', 'bun']). Any detected manager not in this list is blocked.",
      default: [],
    },
    blocked: {
      type: "string[]",
      description: "Additional manager names to block beyond the built-in list (e.g. ['pdm', 'pipx']).",
      default: [],
    },
  },
  fn: (ctx) => {
    if (ctx.toolName !== "Bash") return allow();
    const cmd = getCommand(ctx);
    if (!cmd) return allow();

    const allowed = (ctx.params?.allowed ?? []) as string[];
    if (allowed.length === 0) return allow();

    const allowedSet = new Set(allowed.map((a) => a.toLowerCase()));
    const blocked = (ctx.params?.blocked ?? []) as string[];
    const allowedList = allowed.join(", ");

    // Evaluate each shell segment independently so that
    // "uv --version && pip install flask" correctly denies the pip segment.
    const segments = cmd.split(SEGMENT_SPLIT_RE);

    for (const segment of segments) {
      const trimmed = segment.trim();
      if (!trimmed) continue;

      let segmentAllowed = false;
      for (const manager of allowedSet) {
        const patterns = PKG_MANAGER_DETECTORS[manager];
        if (!patterns) continue;
        for (const pattern of patterns) {
          if (pattern.test(trimmed)) { segmentAllowed = true; break; }
        }
        if (segmentAllowed) break;
      }
      if (segmentAllowed) continue;

      for (const [manager, patterns] of Object.entries(PKG_MANAGER_DETECTORS)) {
        if (allowedSet.has(manager)) continue;
        for (const pattern of patterns) {
          if (pattern.test(trimmed)) {
            return deny(
              `"${manager}" is not an allowed package manager. ` +
                `Allowed package managers for this project: ${allowedList}. ` +
                `Rewrite this command using an allowed package manager.`,
            );
          }
        }
      }

      for (const name of blocked) {
        const lower = name.toLowerCase();
        if (allowedSet.has(lower)) continue;
        const re = new RegExp(`\\b${lower.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}\\b`);
        if (re.test(trimmed)) {
          return deny(
            `"${lower}" is not an allowed package manager. ` +
              `Allowed package managers for this project: ${allowedList}. ` +
              `Rewrite this command using an allowed package manager.`,
          );
        }
      }
    }

    return allow();
  },
});

customPolicies.add({
  name: "warn-large-file-write",
  description: "Warn before writing files larger than 1MB (configurable via thresholdKb param)",
  category: "Packages & System",
  defaultEnabled: false,
  match: { events: ["PreToolUse"], toolNames: ["Write"] },
  // HARD. This is a number compared against a number, and the semantic tier's own
  // authoring rule forbids exactly that: "Never ask Jev to count, compare numbers
  // or resolve a path." All three checks asked on a `write` call
  // (`destructive-deletion`, `secret-exposure`, `agent-config-tampering`) are
  // silent about size and would answer `none` for a large ordinary file, so every
  // available pairing clears every oversized write.
  authority: "hard",
  params: {
    thresholdKb: {
      type: "number",
      description: "File size threshold in KB above which a warning is issued",
      default: 1024,
    },
  },
  fn: (ctx) => {
    if (ctx.toolName !== "Write") return allow();
    const content = ctx.toolInput?.content as string | undefined;
    if (typeof content !== "string") return allow();
    const thresholdKb = (ctx.params?.thresholdKb ?? 1024) as number;
    const thresholdBytes = thresholdKb * 1024;
    if (content.length > thresholdBytes) {
      return instruct(
        `STOP: You are writing a file larger than ${thresholdKb}KB (${Math.round(content.length / 1024)}KB). This is unusually large. Confirm this is intentional before proceeding.`,
      );
    }
    return allow();
  },
});

customPolicies.add({
  name: "warn-background-process",
  description: "Warns before starting detached or background processes",
  category: "Packages & System",
  defaultEnabled: false,
  match: { events: ["PreToolUse"], toolNames: ["Bash"] },
  // HARD. Nothing in the 16 asks about process lifetime. `system-modification` is
  // the only adjacent one — it covers `systemctl enable`, crontab and shell
  // startup files — and a `nohup ... &` changes no machine configuration, so it
  // answers `none` and would clear every input. The harm here (a process that
  // outlives the session and nobody reaps) is a property of what happens AFTER the
  // call, which is not something a question about the call can reach.
  authority: "hard",
  fn: (ctx) => {
    if (ctx.toolName !== "Bash") return allow();
    const cmd = getCommand(ctx);
    const isBackground =
      NOHUP_RE.test(cmd) ||
      SCREEN_DETACH_RE.test(cmd) ||
      TMUX_DETACH_RE.test(cmd) ||
      DISOWN_RE.test(cmd) ||
      BACKGROUND_AMPERSAND_RE.test(cmd);
    if (isBackground) {
      return instruct(
        "STOP: This command starts a background or detached process (nohup, screen -d, tmux -d, or trailing &). Background processes persist after Claude's session and may be difficult to track or stop. Confirm with the user before executing.",
      );
    }
    return allow();
  },
});

// ─────────────────────────────────────────────────────────────────────────────
// AI Behavior
// ─────────────────────────────────────────────────────────────────────────────

customPolicies.add({
  name: "warn-repeated-tool-calls",
  description: "Warn when the same tool is called 3+ times with identical parameters",
  category: "AI Behavior",
  defaultEnabled: false,
  match: { events: ["PreToolUse"] },
  // HARD, and wrong in both directions at once. No probe in the 16 asks about
  // repetition — this policy's whole input is a COUNT held in a sidecar file, and
  // the semantic authoring rules forbid asking Jev to count. And because it
  // declares no `toolNames` it fires on every tool, including the known-inert ones
  // where a stuck loop is most common (`Task`, `TodoWrite`, `Skill`):
  // `selectPolicies` returns an EMPTY set for `toolIsKnown && toolClass ===
  // "other"`, so nothing at all is asked there and any `reviewedBy` would be dead
  // by construction on exactly those calls while blanket-clearing the rest.
  authority: "hard",
  fn: async (ctx) => {
    const THRESHOLD = 3;
    const transcriptPath = ctx.session?.transcriptPath;
    if (!transcriptPath || !ctx.toolName || !ctx.toolInput) return allow();

    // Sidecar file tracks { fingerprint: count } — O(1) per call vs O(transcript).
    const trackerPath = `${transcriptPath}.tool-calls.json`;
    const fingerprint = JSON.stringify({ tool: ctx.toolName, input: ctx.toolInput });

    let counts: Record<string, number> = {};
    try {
      const raw = await readFile(trackerPath, "utf8");
      counts = JSON.parse(raw) as Record<string, number>;
    } catch { /* first call or unreadable — start fresh */ }

    const prevCount = counts[fingerprint] ?? 0;
    if (prevCount >= THRESHOLD) {
      return instruct(
        `STOP: You have already called ${ctx.toolName} ${prevCount} times with identical parameters. This is wasteful and unproductive. Do NOT repeat this call — use a different approach or ask the user for clarification.`,
      );
    }

    counts[fingerprint] = prevCount + 1;
    try {
      const serialized = JSON.stringify(counts);
      if (serialized.length <= TOOL_CALL_TRACKER_MAX_BYTES) {
        await writeFile(trackerPath, serialized, "utf8");
      }
    } catch { /* non-fatal */ }

    return allow();
  },
});

// ─────────────────────────────────────────────────────────────────────────────
// Workflow — Stop-event session-completion gates.
//
// All five are HARD for the same structural reason the `sanitize-*` five are:
// they fire on `Stop`, and Jev is only ever asked on PreToolUse and
// PermissionRequest. No question about one of these calls is ever put to Jev, so
// no name in `reviewedBy` could satisfy the "was it asked" gate and `reviewable`
// would resolve to a block nothing can lift — the same end state as `hard`,
// reached by a route that reads as if review were possible. Declaring it honestly
// is the point.
// ─────────────────────────────────────────────────────────────────────────────

customPolicies.add({
  name: "require-commit-before-stop",
  description: "Require all changes to be committed before Claude stops",
  category: "Workflow",
  defaultEnabled: false,
  match: { events: ["Stop"] },
  authority: "hard",
  fn: (ctx) => {
    if (isPlanMode(ctx)) return allow("Plan mode — no changes made, skipping commit check.");
    const cwd = ctx.session?.cwd;
    if (!cwd) return allow("No working directory available, skipping commit check.");

    try {
      const status = execSync("git status --porcelain", {
        cwd,
        encoding: "utf8", stdio: ["pipe", "pipe", "pipe"],
        timeout: 5000,
      }).trim();

      if (status.length > 0) {
        return deny("You have uncommitted changes in the working directory. Commit all changes now.");
      }
      return allow("All changes are committed.");
    } catch {
      return allow("Not a git repository, skipping commit check.");
    }
  },
});

customPolicies.add({
  name: "require-push-before-stop",
  description: "Require all commits to be pushed to remote before Claude stops",
  category: "Workflow",
  defaultEnabled: false,
  match: { events: ["Stop"] },
  authority: "hard",
  params: {
    remote: {
      type: "string",
      description: "Remote name to push to (default: origin)",
      default: "origin",
    },
    baseBranch: {
      type: "string",
      description: "Base branch to compare against (default: main)",
      default: "main",
    },
  },
  fn: (ctx) => {
    if (isPlanMode(ctx)) return allow("Plan mode — no changes made, skipping push check.");
    const cwd = ctx.session?.cwd;
    if (!cwd) return allow("No working directory available, skipping push check.");

    try {
      const remotes = execSync("git remote", {
        cwd,
        encoding: "utf8", stdio: ["pipe", "pipe", "pipe"],
        timeout: 3000,
      }).trim();

      if (!remotes) return allow("No git remote configured, skipping push check.");

      const remote = (ctx.params?.remote as string) ?? "origin";

      const branch = getCurrentBranch(cwd);
      if (!branch || branch === "HEAD") return allow("Detached HEAD, skipping push check.");

      const baseBranch = (ctx.params?.baseBranch as string) ?? "main";

      if (branch === baseBranch) {
        return allow(`On base branch "${baseBranch}", skipping push check.`);
      }

      try {
        const ahead = execFileSync(
          "git",
          ["log", `${remote}/${baseBranch}..HEAD`, "--oneline"],
          { cwd, encoding: "utf8", stdio: ["pipe", "pipe", "pipe"], timeout: 5000 },
        ).trim();

        if (!ahead) {
          // No commits ahead — branch is fully merged (regular merge / fast-forward)
          return allow(`No commits ahead of ${remote}/${baseBranch}, skipping push check.`);
        }

        // Commits exist but might be from a squash-merged PR. Check the actual
        // file diff — if the trees are identical, the work is already in base.
        const diff = execFileSync(
          "git",
          ["diff", "--stat", `${remote}/${baseBranch}`, "HEAD"],
          { cwd, encoding: "utf8", stdio: ["pipe", "pipe", "pipe"], timeout: 5000 },
        ).trim();

        if (!diff) {
          return allow(`No file changes compared to ${remote}/${baseBranch}, skipping push check.`);
        }
      } catch {
        // remote/{baseBranch} ref missing — fall through to existing push checks
      }

      let hasTracking = false;
      try {
        execFileSync("git", ["rev-parse", "--verify", `${remote}/${branch}`], {
          cwd,
          encoding: "utf8", stdio: ["pipe", "pipe", "pipe"],
          timeout: 3000,
        });
        hasTracking = true;
      } catch {
        // Remote tracking branch does not exist
      }

      if (!hasTracking) {
        return deny(
          `Branch "${branch}" has not been pushed to remote "${remote}". ` +
          `Run now: git push -u ${remote} ${branch}`,
        );
      }

      const unpushed = execFileSync("git", ["log", `${remote}/${branch}..HEAD`, "--oneline"], {
        cwd,
        encoding: "utf8", stdio: ["pipe", "pipe", "pipe"],
        timeout: 5000,
      }).trim();

      if (unpushed.length > 0) {
        const commitCount = unpushed.split("\n").length;
        return deny(
          `You have ${commitCount} unpushed commit${commitCount > 1 ? "s" : ""} on branch "${branch}". ` +
          `Run now: git push`,
        );
      }

      return allow(`All commits pushed to "${remote}".`);
    } catch {
      return allow("Could not check push status, skipping.");
    }
  },
});

customPolicies.add({
  name: "require-pr-before-stop",
  description: "Require a pull request to exist for the current branch before Claude stops",
  category: "Workflow",
  defaultEnabled: false,
  match: { events: ["Stop"] },
  authority: "hard",
  params: {
    baseBranch: {
      type: "string",
      description: "Base branch to compare against (default: main)",
      default: "main",
    },
  },
  fn: (ctx) => {
    if (isPlanMode(ctx)) return allow("Plan mode — no changes made, skipping PR check.");
    const cwd = ctx.session?.cwd;
    if (!cwd) return allow("No working directory available, skipping PR check.");

    try {
      try {
        execSync("gh --version", { cwd, encoding: "utf8", stdio: ["pipe", "pipe", "pipe"], timeout: 3000 });
      } catch {
        return allow("GitHub CLI (gh) not installed, skipping PR check.");
      }

      const branch = getCurrentBranch(cwd);
      if (!branch || branch === "HEAD") return allow("Detached HEAD, skipping PR check.");

      const baseBranch = (ctx.params?.baseBranch as string) ?? "main";

      if (branch === baseBranch) {
        return allow(`On base branch "${baseBranch}", skipping PR check.`);
      }

      try {
        const ahead = execFileSync(
          "git",
          ["log", `origin/${baseBranch}..HEAD`, "--oneline"],
          { cwd, encoding: "utf8", stdio: ["pipe", "pipe", "pipe"], timeout: 5000 },
        ).trim();

        if (!ahead) {
          return allow(`No commits ahead of origin/${baseBranch}, skipping PR check.`);
        }

        const diff = execFileSync(
          "git",
          ["diff", "--stat", `origin/${baseBranch}`, "HEAD"],
          { cwd, encoding: "utf8", stdio: ["pipe", "pipe", "pipe"], timeout: 5000 },
        ).trim();

        if (!diff) {
          return allow(`No file changes compared to origin/${baseBranch}, skipping PR check.`);
        }
      } catch {
        // origin/{baseBranch} ref missing or git error — fall through to gh pr view
      }

      let prJson: string;
      try {
        prJson = execSync("gh pr view --json number,url,state", {
          cwd,
          encoding: "utf8", stdio: ["pipe", "pipe", "pipe"],
          timeout: 15000,
        }).trim();
      } catch {
        // gh pr view exits non-zero when no PR exists
        return deny(`No pull request found for branch "${branch}". Run now: gh pr create`);
      }

      const pr = JSON.parse(prJson) as { number: number; url: string; state: string };

      if (pr.state === "OPEN") {
        return allow(`PR #${pr.number} exists: ${pr.url}`);
      }

      // Trust GitHub's authoritative state. Local-ref reconciliation can never
      // converge after squash-merge or rebase-merge, or when base is auto-modified
      // post-merge. The PR being MERGED is itself the proof that the work shipped.
      if (pr.state === "MERGED") {
        return allow(
          `PR #${pr.number} was merged: ${pr.url}. ` +
          `Switch off this branch (e.g. 'git checkout ${baseBranch} && git pull') before stopping again.`,
        );
      }

      // Reaches here only for CLOSED-without-merge — PR was rejected.
      return deny(`Pull request for branch "${branch}" is ${pr.state.toLowerCase()}. Run now: gh pr create`);
    } catch {
      return allow("Could not check PR status, skipping.");
    }
  },
});

customPolicies.add({
  name: "require-no-conflicts-before-stop",
  description: "Require the current branch to merge cleanly with the base branch before Claude stops",
  category: "Workflow",
  defaultEnabled: false,
  match: { events: ["Stop"] },
  authority: "hard",
  params: {
    baseBranch: {
      type: "string",
      description: "Base branch to check for conflicts against (default: main)",
      default: "main",
    },
  },
  fn: (ctx) => {
    if (isPlanMode(ctx)) return allow("Plan mode — no changes made, skipping conflict check.");
    const cwd = ctx.session?.cwd;
    if (!cwd) return allow("No working directory available, skipping conflict check.");

    const branch = getCurrentBranch(cwd);
    if (!branch || branch === "HEAD") return allow("Detached HEAD, skipping conflict check.");

    const baseBranch = (ctx.params?.baseBranch as string) ?? "main";
    if (branch === baseBranch) {
      return allow(`On base branch "${baseBranch}", skipping conflict check.`);
    }

    // Precheck: only enforce when an OPEN PR exists on GitHub. Without a
    // confirmable merge target there is nothing to enforce.
    try {
      execSync("gh --version", { cwd, encoding: "utf8", stdio: ["pipe", "pipe", "pipe"], timeout: 3000 });
    } catch {
      return allow("gh CLI not installed, skipping conflict check.");
    }

    let prJson: string;
    try {
      prJson = execSync("gh pr view --json mergeable,number,url,state", {
        cwd, encoding: "utf8", stdio: ["pipe", "pipe", "pipe"], timeout: 15000,
      }).trim();
    } catch {
      return allow("No pull request found for branch, skipping conflict check.");
    }

    let pr: { mergeable: string; number: number; url: string; state: string };
    try {
      pr = JSON.parse(prJson);
    } catch {
      return allow("Could not parse gh pr view output, skipping conflict check.");
    }

    // GitHub stops computing mergeability for non-OPEN PRs (returns UNKNOWN forever).
    if (pr.state !== "OPEN") {
      return allow(`PR #${pr.number} is ${pr.state.toLowerCase()}; skipping conflict check.`);
    }

    // Layer 1: local git merge-tree
    try {
      execFileSync("git", ["rev-parse", "--verify", `origin/${baseBranch}`], {
        cwd, encoding: "utf8", stdio: ["pipe", "pipe", "pipe"], timeout: 3000,
      });

      const ahead = execFileSync(
        "git", ["log", `origin/${baseBranch}..HEAD`, "--oneline"],
        { cwd, encoding: "utf8", stdio: ["pipe", "pipe", "pipe"], timeout: 5000 },
      ).trim();

      if (ahead) {
        execFileSync(
          "git",
          ["merge-tree", "--write-tree", "--name-only", `origin/${baseBranch}`, "HEAD"],
          { cwd, encoding: "utf8", stdio: ["pipe", "pipe", "pipe"], timeout: 10000 },
        );
      }
      // !ahead or merge-tree exit 0 → fall through to Layer 2
    } catch (err) {
      const e = err as { status?: number; stdout?: string | Buffer };
      if (e.status === 1) {
        // git merge-tree exit 1 = conflicts. stdout: <tree>\n<file>\n<file>\n\n<messages>
        const out = (typeof e.stdout === "string" ? e.stdout : e.stdout?.toString("utf8") ?? "").trim();
        const lines = out.split("\n");
        const files: string[] = [];
        for (let i = 1; i < lines.length; i++) {
          const line = lines[i];
          if (line === "") break;
          files.push(line);
        }
        const fileList = files.length ? files.join(", ") : "one or more files";
        return deny(
          `Branch "${branch}" has merge conflicts with ${baseBranch} in: ${fileList}. ` +
          `Rebase or merge origin/${baseBranch} now and resolve the conflicts.`,
        );
      }
      // any other failure (e.g. missing origin/<base>, log failure) → fall through
    }

    // Layer 2: GitHub PR mergeability (reuses pr from precheck)
    if (pr.mergeable === "CONFLICTING") {
      return deny(
        `PR #${pr.number} has merge conflicts per GitHub (${pr.url}). ` +
        `Rebase or merge origin/${baseBranch} now and resolve the conflicts.`,
      );
    }
    if (pr.mergeable === "UNKNOWN") {
      return deny(
        `GitHub is still computing mergeability for PR #${pr.number} (${pr.url}). ` +
        `Wait ~10 seconds, then re-check with \`gh pr view --json mergeable\` before attempting to stop again.`,
      );
    }
    return allow(`PR #${pr.number} merges cleanly per GitHub.`);
  },
});

customPolicies.add({
  name: "require-ci-green-before-stop",
  description:
    "Require CI checks to pass on the current HEAD commit before Claude stops (ignores stale runs on prior commits)",
  category: "Workflow",
  defaultEnabled: false,
  match: { events: ["Stop"] },
  authority: "hard",
  fn: (ctx) => {
    if (isPlanMode(ctx)) return allow("Plan mode — no changes made, skipping CI check.");
    const cwd = ctx.session?.cwd;
    if (!cwd) return allow("No working directory available, skipping CI check.");

    try {
      try {
        execSync("gh --version", { cwd, encoding: "utf8", stdio: ["pipe", "pipe", "pipe"], timeout: 3000 });
      } catch {
        return allow("GitHub CLI (gh) not installed, skipping CI check.");
      }

      const branch = getCurrentBranch(cwd);
      if (!branch || branch === "HEAD") return allow("Detached HEAD, skipping CI check.");

      // Resolve HEAD up front — the workflow-runs filter below uses it to ignore
      // runs targeting prior commits on the same branch.
      const sha = getHeadSha(cwd);

      // 1. GitHub Actions workflow runs (filtered to current HEAD, deduped by name)
      let workflowRuns: CiCheck[] = [];
      try {
        // --limit 20: a busy branch can push the latest run for some workflow out
        // of a top-5 window after the SHA filter.
        const runsJson = execFileSync(
          "gh",
          ["run", "list", "--branch", branch, "--limit", "20", "--json", "status,conclusion,name,headSha"],
          { cwd, encoding: "utf8", stdio: ["pipe", "pipe", "pipe"], timeout: 15000 },
        ).trim();

        if (runsJson && runsJson !== "[]") {
          const allWorkflowRuns = JSON.parse(runsJson) as Array<CiCheck & { headSha?: string }>;
          const headRuns = sha
            ? allWorkflowRuns.filter((r) => r.headSha === sha)
            : allWorkflowRuns;
          // Dedupe by workflow name, keeping the first occurrence (newest-first).
          // Handles "Re-run all jobs", which creates a fresh run record with the
          // same name + headSha.
          const seen = new Set<string>();
          workflowRuns = headRuns.filter((r) => {
            if (seen.has(r.name)) return false;
            seen.add(r.name);
            return true;
          });
        }
      } catch {
        // fail-open for workflow runs; continue to check third-party checks
      }

      // 2. Third-party check runs (CodeRabbit, SonarCloud, Codecov, etc.)
      let thirdPartyChecks: CiCheck[] = [];
      let commitStatuses: CiCheck[] = [];
      if (sha) {
        thirdPartyChecks = getThirdPartyCheckRuns(cwd, sha);
        commitStatuses = getCommitStatuses(cwd, sha);
      }

      // 3. Merge all checks
      const allChecks = [...workflowRuns, ...thirdPartyChecks, ...commitStatuses];

      if (allChecks.length === 0) return allow(`No CI runs found for branch "${branch}".`);

      const failing = allChecks.filter(
        (r) =>
          r.status === "completed" &&
          r.conclusion !== "success" &&
          r.conclusion !== "skipped" &&
          r.conclusion !== "cancelled" &&
          r.conclusion !== "neutral",
      );
      if (failing.length > 0) {
        const names = failing.map((r) => `"${r.name}"`).join(", ");
        return deny(`CI checks are failing on branch "${branch}": ${names}. Fix the failing checks now.`);
      }

      const pending = allChecks.filter(
        (r) => r.status === "in_progress" || r.status === "queued" || r.status === "waiting",
      );
      if (pending.length > 0) {
        const names = pending.map((r) => `"${r.name}"`).join(", ");
        return deny(
          `CI checks are still running on branch "${branch}": ${names}. Wait for all checks to complete, then verify they pass.`,
        );
      }

      return allow(`All CI checks passed on branch "${branch}".`);
    } catch {
      return allow("Could not check CI status, skipping.");
    }
  },
});
