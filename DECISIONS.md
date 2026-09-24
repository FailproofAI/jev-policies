# DECISIONS — the regex half of `FailproofAI/jev-policies`

What authority each of the 38 policies in `policies/regex.ts` got, which semantic checks
review it, and why. Every `hard` row says what would go wrong if Jev could clear it, which
is a different question from "is this dangerous" and is the one that decides.

**Headline: 17 of 38 reviewable, up from 6.** 11 policies moved from `hard` to
`reviewable`; none moved the other way. 4 `fn`s were rewritten to be narrower, and 1 `match`
was widened to close a hole. 12 candidate pairings were considered and refused — one of them twice, in opposite
directions — and the refusals are the part of this document worth reading.

## Verification

Not asserted by eye. `policies/regex.ts` was loaded through a stub `failproofai` that
captures `customPolicies.add()`, and the registrations were checked against
`src/hooks/policy-catalog.ts` and run through the repo's own validators:

| Check | Result |
| --- | --- |
| Policy count vs. catalog minus `alwaysOn` | 38 = 39 − 1 |
| Registration order vs. catalog order | identical, index by index |
| `name` / `description` / `category` / `defaultEnabled` / `params` | byte-identical to the catalog for all 38 |
| `match` | byte-identical for 37; `block-secrets-write` adds `Edit` (see §Divergences), asserted explicitly |
| `block-failproofai-commands` absent; no entry declares `alwaysOn` | yes |
| `manifestAuthority()` — what `failproofai publish` refuses to ship | accepts all 38 |
| `parsePackPolicy()` — what `pack add` refuses to install | accepts all 38 |
| every `reviewedBy` name in `SEMANTIC_POLICY_NAMES` **and** in this pack's `policies/semantic.ts` | 16 of 16 names line up; no pairing names a check the pack does not declare |
| behaviour: 125 cases — the 4 rewrites' kept denies, their former false positives, their named give-ups, the closed `Edit` hole, and spot-checks of every copied `fn` | 0 unexpected |

Reproduce with `bun build --target=node --format=esm --external failproofai policies/regex.ts`,
loaded against a stub that captures `customPolicies.add`.

## The four rules this document applies

`reviewedBy` is a conjunction: a regex verdict is cleared only when **every** named check
was among the ones put to Jev for this call **and** none came back `deny` (`combine.ts`).
That single sentence has four consequences, and a pairing has to survive all four.

**1. Asked, not merely named.** `selectPolicies` drops a check whose `appliesTo` excludes
the call's tool class, whose `precondition` is false, or — for a known tool of class
`other` (`Task`, `TodoWrite`, `Skill`) — every check at all. A name that is never asked
makes the block **permanent**. This is the bug that cost 106 false blocks on this branch:
`read-outside-workspace` asked only about the two home relations while
`block-read-outside-cwd` denied any path outside the project, so 106 of its 154 denials on
the 1,332-case corpus had no paired question — the paths were mostly `/tmp/claude-*`, which
`facts.ts` classifies as `system`. Every pairing below states the class and precondition
that make it live.

**2. `none` clears.** The mirror failure, and the one the 106-block story does not warn
about: a check that IS asked but never fires for the shapes the regex matches answers
`none`, and `none` counts as a clear. Naming it does not review the policy — it **switches
the policy off** on every input it matches. Six of the nine refusals below are this, not
the dead-pairing kind.

**3. A clear is only a demotion when nothing is left that can deny.** `decide.ts`:
`p.mode === "deny" && evidence >= 0.85 ? "deny" : "instruct"`. An `instruct`-mode check's
outcome is at most `instruct`, and `instruct` clears — so an `instruct`-mode check can never
keep a block, and a conjunction of only `instruct`-mode names has exactly one reachable
outcome once it is asked: cleared.

The tempting conclusion is that such a pairing is always a demotion. It is not, and the
difference is the whole substance of this rule. `reviewedBy` decides only whether Jev may
clear THIS policy's verdict. It does not decide what Jev is asked: every applicable semantic
check is put to Jev independently of any `reviewedBy`, and `combineTwoTier` takes the most
severe answer. So a cleared regex verdict does not mean an allowed call — it means the
regex tier stopped voting, and the semantic tier's own denies still stand.

So the test is not "can this conjunction keep the block". It is:

> **When this pairing clears, is there anything left that can deny the calls this policy
> matches?**

Three ways to answer yes, and one to answer no:

| | |
| --- | --- |
| a `deny`-mode check inside the conjunction | `block-env-files` → `secret-exposure` |
| a `deny`-mode check asked on the same call that covers the concern on its own, named or not | `block-read-outside-cwd` → `secret-exposure`, `credential-exfiltration`, `agent-config-tampering` all still deny a credential read |
| the policy never denied in the first place | `warn-git-amend`, `warn-destructive-sql`, `warn-global-package-install` — a warning replaced by a warning is not a loss |
| **nothing** — the only check covering the concern is instruct-only, and no other check fires on these shapes | `block-push-master`, `block-work-on-main` → **refused, hard** |

That last row is the defect, and it is the same defect as Rule 2 wearing different clothes:
in both cases the mark says `reviewable` while the policy is in fact switched off whenever
Jev answers. Rule 2 gets there through a check that answers `none`; this gets there through
a check that can only answer `instruct`. The user-visible result is identical.

It is also why "add a `deny`-mode name to repair the conjunction" is the wrong instinct. A
second name can only ever REMOVE clears, and removing clears restores blocks — including the
106 that `read-outside-workspace`'s widened precondition and the path-extraction fixes were
built to kill. #833's headline numbers (false blocks 32% → 7.4%, attacks 123 of 234) were
measured with these pairings exactly as they stand, so a change to what clears needs a
corpus replay, not a judgement call. An earlier revision of this pack added `secret-exposure`
to `block-read-outside-cwd` on the narrower form of this rule; it is reverted.

**4. The two non-overridable checks cannot be routed around.** `credential-exfiltration`
and `agent-config-tampering` carry `userCanOverride: false` because they are what a prompt
injection most wants approved. Two things protect them here. Neither is an accident:

- No policy in this pack names them, and none needs to: both are `appliesTo` sets that
  exclude the classes where the overlapping regex policies fire (`credential-exfiltration`
  is `["shell", "network"]`, so it is a dead name on a `Write`; `agent-config-tampering` is
  `["shell", "write"]`, so it is a dead name on a `Read`). Naming either would have created
  a permanent block, not extra safety.
- Clearing a regex verdict never suppresses the semantic tier's **own** deny. Every
  applicable check is asked independently of any `reviewedBy`, and `combineTwoTier` takes
  the most severe answer. So when an agent points `rm -rf` at `~/.claude/settings.json`,
  `destructive-deletion` clearing this pack's `block-rm-rf` does not help it:
  `agent-config-tampering` is asked on the same call, is not overridable, and its deny is
  the verdict.

There is one thing to flag rather than claim as safety: **no policy in these 38 is an
egress guard**, so `credential-exfiltration` has no regex floor under it at all. See
"What looks wrong in the existing 38".

## The table

`M` = the reviewing check's mode: **D** = `deny` (a real block survives review), **I** =
`instruct` (can never keep a block on its own). An all-`I` row is NOT automatically a
demotion — see Rule 3: what matters is whether anything is left that can deny, which for
`block-read-outside-cwd` is three other checks and for `warn-global-package-install` is moot
because the policy only ever warned. The two rows where the answer was "nothing"
(`block-push-master`, `block-work-on-main`) are hard.

| Policy | Authority | Reviewed by | M | Reason |
| --- | --- | --- | --- | --- |
| `sanitize-jwt` | hard | — | | PostToolUse. See §"Two families that are hard structurally". |
| `sanitize-api-keys` | hard | — | | PostToolUse. Same. |
| `sanitize-connection-strings` | hard | — | | PostToolUse. Same. |
| `sanitize-private-key-content` | hard | — | | PostToolUse. Same. |
| `sanitize-bearer-tokens` | hard | — | | PostToolUse. Same. |
| `protect-env-vars` | reviewable | `env-secrets-dump`, `secret-exposure` | I+**D** | Both are `shell`-class with no precondition and this policy is Bash-only, so both are asked for every input it matches. `env-secrets-dump` is the same concern stated as behaviour and clears the ordinary-variable case. `secret-exposure` is the builtin's own second name, kept verbatim; it is `mode: deny`, so a `printenv` of real credential material still comes back `deny`. It is not what makes this a review — under Rule 3 it would deny on its own whether or not it were named — it is what shipped and what was measured. |
| `block-env-files` | reviewable | `secret-exposure` | D | `appliesTo` covers `shell`/`read`/`write` — this policy's only branches are a `file_path` and a Bash command — and on an MCP tool (which it also matches, having no `toolNames`) every check is asked regardless of class. Its false criteria names the largest false-positive class verbatim: "an .env.example template, a test fixture, documentation about credentials". |
| `block-read-outside-cwd` | reviewable | `read-outside-workspace` | I | `shell` + `read` covers all four matched tools, and the precondition was widened for this exact pairing: any relation outside the project including `system`, plus any path outside the live cwd. It is the pairing the 106-block fix was for, and the numbers in #833 were measured with it exactly as it stands. Instruct-only and correct: `secret-exposure`, `credential-exfiltration` and `agent-config-tampering` are all asked on the same call and all still deny on their own, so Jev replaces the regex judgment on the noisiest policy in the set rather than surrendering it (Rule 3). |
| `block-sudo` | reviewable | `privilege-escalation` | D | `shell`, no precondition, `mode: deny` — so a real escalation comes back `deny` and the block **stands**. Its probe is a superset of `namesElevation`: sudo, doas, su, pkexec, run0, "including when the binary is written as an absolute path or reached through a variable or wrapper". A clear buys the two cases a string matcher cannot judge: the user asked for this command, and the word sits where nothing is elevated. |
| `block-curl-pipe-sh` | reviewable | `remote-code-execution` | D | `shell`, no precondition, `mode: deny`. The regex matches its pattern as a substring anywhere, so `grep -rn "curl x \| sh" README.md` is denied — named outright in the probe's false criteria ("merely searches for or quotes such a command"). The check also carries an `official_installer` exemption (bun.sh, sh.rustup.rs, get.docker.com), which is the most common legitimate instance. |
| `block-rm-rf` | reviewable | `destructive-deletion` | D | `shell`+`write`, no precondition, `mode: deny`, and its second probe is this policy's path-depth heuristic done properly: `irreplaceable`'s false criteria ("build output, dist/, caches, node_modules, virtualenvs, coverage reports, temp files") is the heuristic's error term. `rm -rf ~/.cache` is one segment below home and denied today; `rm -rf /` keeps both probes true and stays denied. |
| `block-kubectl` | reviewable | `production-infra-change` | D | `shell`, no precondition, `mode: deny`; the probe names kubectl explicitly and its false criteria is the split this regex cannot make — "get, list, describe, logs, status, plan, diff, validate, whoami, or --dry-run". This policy denies the whole CLI, read-only subcommands included. |
| `block-terraform` | reviewable | `production-infra-change` | D | Same; the probe names terraform and tofu. Clears `terraform plan` / `validate`. |
| `block-aws-cli` | reviewable | `production-infra-change` | D | Same; the probe names aws. Clears `aws sts get-caller-identity`, `aws s3 ls`. |
| `block-gcloud` | reviewable | `production-infra-change` | D | Same; the probe names gcloud. Clears `gcloud auth list`, `gcloud config list`. |
| `block-az-cli` | reviewable | `production-infra-change` | D | Same; the probe names az. Clears `az account show`. |
| `block-helm` | reviewable | `production-infra-change` | D | Same; the probe names helm. Clears `helm list`, `helm status`. |
| `block-gh-pipeline` | **hard** | — | | Refused in both directions. `external-destructive-action` names these actions ("merging or closing pull requests… changing permissions, access or billing") but is `appliesTo: ["other"]`, and this policy only fires on Bash — a permanent block. `production-infra-change` IS asked and answers `none` for `gh pr merge`, `gh workflow run`, `gh release create`, `gh cache delete` and `gh run rerun` (none mutates cloud state), so it would clear five of the six shapes and leave only `gh secret set` blocked. |
| `block-secrets-write` | reviewable | `secret-exposure` | D | `write` is in `appliesTo` and covers both matched tools, no precondition, `mode: deny`, so a private key still comes back `deny`. What it clears is the substring problem the builtin had (`/credentials/` and `/id_rsa/` unanchored against the whole path); the check's false criteria is a list of what that matched. `credential-exfiltration` would have been a dead name: it is `["shell", "network"]`, and a file write is neither. **`match` widened to `["Write", "Edit"]`** — see §Divergences. |
| `block-push-master` | **hard** | — | | Refused on Rule 3. `push-to-protected-branch` is asked on every Bash call but is `mode: instruct`, so once asked it always clears — and nothing is left that can deny: `git-history-rewrite` fires on a force-push or a remote-branch delete, not on a push that only adds commits, and nothing else in the 16 mentions protected branches. A clear would leave a `defaultEnabled: true` block enforced by neither tier. The noise this policy had was its `\bmain\b` matcher, and that is fixed in the floor instead (rewrite 3). Being hard does not blind the semantic tier: `push-to-protected-branch` is still asked and its own instruct still joins the merge; `hard` withholds only the power to clear this deny. |
| `block-force-push` | reviewable | `git-history-rewrite` | D | `shell`, no precondition, `mode: deny`, and the probe is a superset of the matcher — it counts `--force-with-lease` (which `isForcePushFlag` deliberately treats as safe), a `+refspec`, and a remote-branch delete, and says `git -C dir` and an absolute binary path change nothing. A real force-push stays blocked; what clears is the case `SCOPE_PROBE`'s own doc cites — the user asked to force-push their own branch. |
| `block-work-on-main` | **hard** | — | | Refused on Rule 3. `commit-on-protected-branch` is the right concern and is asked wherever the policy can fire with the default params (its precondition covers main, master, production, prod, release and trunk — a strict superset of `["main", "master"]`), but it is `mode: instruct`, so once asked it always clears — and no deny-mode check in the 16 can stop a `git commit` on main on its own. Nothing is left, so the mark would read `reviewable` while the policy was switched off for a user who deliberately opted in. `block-read-outside-cwd` is instruct-only too and is correct, which is the contrast that makes this a defect rather than a design. The builtin shipped this same change while this pack was being written, so the two now agree; the residual matcher noise is recorded in §Accepted costs. |
| `warn-git-amend` | reviewable | `git-history-rewrite` | D | Amending an unpushed commit is ordinary; the harm is rewriting history others pulled, and no string can tell them apart. Live in both directions: a bare `git commit --amend` leaves `rewrites_remote` false → `none` → the warning is cleared, which is the intended outcome; `git commit --amend && git push -f` keeps it true → `deny` → the call is blocked harder than this policy's own instruct. |
| `warn-git-stash-drop` | **hard** | — | | The nearest check, `destructive-deletion`, *is* asked on every Bash call — so this is the `none`-clears failure, not the dead-pairing one. Its `destroys` probe is written about the filesystem ("files, directories or disks"); a `git stash drop` touches no file and leaves the working tree alone, so evidence (the min over probes) collapses and the answer is `none`. Naming it would silence this policy on every input it matches. Nothing in the 16 mentions discarding uncommitted work. |
| `warn-all-files-staged` | **hard** | — | | The concern is what a wide stage PICKS UP — a generated file, a key, a local override — which is a property of the working tree, and no probe reads the working tree. `secret-exposure` is asked and answers `none` for `git add -A` (it stages; it reads and prints nothing), so pairing with it would clear every input rather than narrow any. |
| `warn-destructive-sql` | reviewable | `database-destruction` | D | `shell`, no precondition, `mode: deny`, two probes. The first adds what the regex gets wrong — an always-true predicate (`WHERE 1=1`, `WHERE id > 0`) narrows nothing, where `SQL_WHERE_RE` accepts any `WHERE`. The second, `real_database`, is the judgement the regex cannot make, and treats "cannot be told" as real. Kept from the builtin. |
| `warn-schema-alteration` | **hard** | — | | `database-destruction` is asked, but it asks about rows and tables being REMOVED, and this policy's harm is different: an `ALTER TABLE` takes a lock and breaks readers. `ADD COLUMN` and `RENAME COLUMN` destroy no data → `none` → cleared, on exactly the two statements the policy exists to surface. Only `DROP COLUMN` would survive review, so the pairing would delete most of the coverage rather than narrow it. |
| `warn-package-publish` | **hard** | — | | Refused in both directions. `external-destructive-action` names it ("an irreversible or externally visible action") but is `appliesTo: ["other"]` and `npm publish` is a Bash call — permanent block. The two asked on a shell call both answer `none`: `production-infra-change` (a registry is not infrastructure) and `system-modification` (publishing installs nothing). No pairing reviews this policy; every one switches it off. |
| `warn-global-package-install` | reviewable | `system-modification` | I | The same concern: changing the machine outside the project. `shell`, no precondition, probe names `npm install -g` and `pip install` outside a virtualenv explicitly. Instruct-only, and nothing deny-mode covers system-wide installs — so it passes Rule 3 on the third escape, not the second: **this policy's own verdict is already `instruct`**, so there is no block to surrender, and a clear on `instruct` means the check fired and its warning joins the merge in Jev's words. Kept from the builtin. |
| `prefer-package-manager` | **hard** | — | | A team convention, not a safety judgement, and there is nothing for Jev to be right about: `pip install flask` in a venv is both the exact command this policy blocks and the exact command `system-modification`'s false criteria calls fine. That check is asked on every Bash call and would answer `none` for essentially every input, clearing 100% of the denies. |
| `warn-large-file-write` | **hard** | — | | A number compared against a number. The semantic tier's own authoring rule forbids exactly that ("Never ask Jev to count, compare numbers or resolve a path"), and all three checks asked on a `write` call (`destructive-deletion`, `secret-exposure`, `agent-config-tampering`) are silent about size, so every available pairing clears every oversized write. |
| `warn-background-process` | **hard** | — | | Nothing in the 16 asks about process lifetime. `system-modification` is the only adjacent one (`systemctl enable`, crontab, shell startup files) and a `nohup … &` changes no machine configuration → `none` → cleared. The harm is a property of what happens AFTER the call, which no question about the call can reach. |
| `warn-repeated-tool-calls` | **hard** | — | | Wrong in both directions at once. No probe asks about repetition (the input is a COUNT in a sidecar file, and Jev is not asked to count), and because the policy declares no `toolNames` it fires on the known-inert tools where a stuck loop is most common — `Task`, `TodoWrite`, `Skill` — for which `selectPolicies` returns an EMPTY set. Any `reviewedBy` would be dead by construction on exactly those calls and blanket-clearing on the rest. |
| `require-commit-before-stop` | hard | — | | Stop event. See §"Two families that are hard structurally". |
| `require-push-before-stop` | hard | — | | Stop event. Same. |
| `require-pr-before-stop` | hard | — | | Stop event. Same. |
| `require-no-conflicts-before-stop` | hard | — | | Stop event. Same. |
| `require-ci-green-before-stop` | hard | — | | Stop event. Same. |

## Two families that are hard structurally, said once

The 5 `sanitize-*` policies fire on `PostToolUse` and the 5 `require-*-before-stop`
policies fire on `Stop`. Jev is asked on `PreToolUse` and `PermissionRequest` only, so for
one of these calls no Jev answer exists at all.

That makes `reviewable` not merely useless but **misleading**: nothing in `reviewedBy`
could ever satisfy the "was it asked" gate, so the declaration would produce a verdict no
review can lift — the same end state as `hard`, reached by a route that reads in the
manifest, in `failproofai policies`, and in the dashboard as if review were possible. All
ten are left exactly as the builtin has them, and they are declared `hard` explicitly
rather than by omission.

The `sanitize-*` five have a second reason on top: their `PolicyResult` carries a
`message` (the redaction text), not just a decision. Clearing the verdict would leave the
secret in the model's context, which is the one thing the policy exists to prevent.

## Every row re-checked against Rule 3's refined test

The table below is the audit Rule 3 demands, run over every reviewable row and every
refusal, asking one question each: *when this pairing clears, is anything left that can
deny?* Nothing in this list was edited as a result — the two rows whose stated REASON changed
are marked, because a right answer reached by a wrong argument is worth correcting even when
the answer stands.

`combine.ts`'s measured Rule B is what makes an `instruct` answer a clear at all: it took
real work blocked from 13.9% to 8.7% against 33.3% for the regex tier alone, moving 54 calls,
every one of them deny → warning and none to allow.

### The five rows that name an `instruct`-mode check

| Policy | Its verdict | Instruct name | Anything left that can deny? | Verdict |
| --- | --- | --- | --- | --- |
| `block-read-outside-cwd` | deny | `read-outside-workspace` | **yes** — `secret-exposure`, `credential-exfiltration` and `agent-config-tampering` are all `mode: deny`, all asked on a `read`/`shell` call, and all still deny on their own. A read of `~/.aws/credentials` outside the project is still blocked, by the check that understands it rather than by a path comparison. | **reviewable**, exactly as the builtin ships it and as #833 measured it |
| `protect-env-vars` | deny | `env-secrets-dump` | **yes** — `secret-exposure`, and it happens also to be named. **Reason corrected:** an earlier revision said the second name was "what makes this a review". It is not; `secret-exposure` would deny on its own whether or not it appeared in `reviewedBy`. It stays named because that is what the builtin ships and what was measured, not because the rule requires it. | **reviewable**, unchanged |
| `warn-global-package-install` | **instruct** | `system-modification` | **no** — nothing deny-mode covers "installs software system-wide". But the policy never denied: a clear on `instruct` means the check fired and warned, and that warning joins the most-severe merge in Jev's words instead of a regex's. **Reason corrected:** this row passes on the third escape ("never denied"), not because anything can deny. | **reviewable**, unchanged |
| `block-push-master` | deny | `push-to-protected-branch` | **no.** `git-history-rewrite` is deny-mode and asked, but fires on a force-push or a remote-branch delete, not on a push that only adds commits. Nothing else in the 16 mentions protected branches. | **hard** |
| `block-work-on-main` | deny | `commit-on-protected-branch` | **no.** No deny-mode check stops a `git commit` on main. The mark would read `reviewable` while the policy was switched off for a user who deliberately opted in. | **hard**, and the builtin landed the same change independently |

### The eleven deny-mode pairings

`block-sudo`, `block-curl-pipe-sh`, `block-rm-rf`, the six infra guards,
`block-secrets-write`, `block-force-push`, `block-env-files`, `warn-destructive-sql` and
`warn-git-amend` each name a `mode: deny` check, so the conjunction itself can answer `deny`
and the test is satisfied by the first escape. No flips.

### The refusals

Rule 3's refined form does not loosen a single Rule 2 refusal — it strengthens all of them,
because "the named check answers `none` and nothing else covers the concern" is the same
finding as "nothing is left that can deny". Checked individually: when
`production-infra-change` clears `gh pr merge`, when `database-destruction` clears
`ALTER TABLE … ADD COLUMN`, when `destructive-deletion` clears `git stash drop`, when
`secret-exposure` clears `git add -A`, and for `warn-package-publish`,
`prefer-package-manager`, `warn-large-file-write`, `warn-background-process` and
`warn-repeated-tool-calls` — in every case no other deny-mode check fires on those shapes
either. All nine refusals confirmed, none flips.

The dead-name refusals (`external-destructive-action` and `credential-exfiltration` on
Bash/Write policies) are unaffected: a name that is never asked makes the block permanent,
which is Rule 1 and independent of this test.

## Pairings considered and refused

| Policy | Candidate | Why refused |
| --- | --- | --- |
| `block-gh-pipeline` | `external-destructive-action` | Dead. `appliesTo: ["other"]`; a Bash call is class `shell`, so `selectPolicies` never asks it. Permanent block for all six shapes. |
| `block-gh-pipeline` | `production-infra-change` | Asked, but answers `none` for `gh pr merge` / `workflow run` / `release create` / `cache delete` / `run rerun`. Would clear 5 of 6 shapes — switching the policy off, not reviewing it. |
| `warn-package-publish` | `external-destructive-action` | Dead, same reason: `["other"]` vs. a Bash call. |
| `warn-package-publish` | `production-infra-change` or `system-modification` | Both asked, both `none` for `npm publish` / `cargo publish` / `twine upload`. Blanket clear. |
| `warn-git-stash-drop` | `destructive-deletion` | Asked, but `destroys` enumerates files, directories and disks. A stash entry is none of those → `none` → blanket clear. |
| `warn-schema-alteration` | `database-destruction` | Asked, but `none` for `ADD COLUMN` and `RENAME COLUMN`, which are exactly the lock-taking, reader-breaking statements this policy is for. Only `DROP COLUMN` would survive. |
| `warn-all-files-staged` | `secret-exposure` | Asked, `none` for `git add -A` (staging reads and prints nothing). Blanket clear. |
| `block-env-files` | + `external-data-egress` (for the MCP case) | It is asked only when the tool is unknown (MCP), and `reviewedBy` is one global conjunction — adding it would make the common Bash/Read/Write case, where it is never asked, a permanent block. A per-tool-class `reviewedBy` does not exist. |
| `block-read-outside-cwd` | + `secret-exposure` | Added in an earlier revision on the narrower reading of Rule 3, then **reverted**. Unnecessary — the check denies on its own whether named or not — and not free: a second name only ever removes clears, and the clears here are the measured ones. See §Reversed on review. |
| `block-push-master` | `push-to-protected-branch` | Asked, but `mode: instruct`, so it always clears, and nothing else can deny an ordinary push to main. Rule 3. |
| `block-work-on-main` | `commit-on-protected-branch` | Same. No `deny`-mode check exists for "commit on a protected branch", so the conjunction cannot be repaired. Rule 3. |
| `block-secrets-write` | `credential-exfiltration` | Dead. `appliesTo: ["shell", "network"]`; a `Write` is class `write`. Naming the non-overridable check here would have made the block permanent, not stronger. |
| `block-sudo` | + `system-modification` | Asked, `instruct`-mode. Adding it to a `deny`-mode pairing cannot add a block (its worst answer clears), and it answers `none` for most `sudo` calls, so it would only ever remove clears from the `privilege-escalation` pairing. |
| `warn-large-file-write`, `prefer-package-manager`, `warn-background-process`, `warn-repeated-tool-calls` | everything in the 16 | No probe covers the concern. Each candidate is either never asked for the matched tool classes or answers `none` for every input the policy matches. |

## Reversed on review

`block-read-outside-cwd` + `secret-exposure` was refused, then added, then reverted. The
round trip is kept because each step was wrong for an instructive reason.

**Refused first**, as "strictly a hardening with no gain: it answers `none` for an ordinary
source-file read, so it can only subtract clears from the pairing the 106-block fix was built
for." Both halves true; the conclusion was luck rather than reasoning, because it did not
notice that the sole named reviewer is instruct-only.

**Then added**, on the narrower form of Rule 3 — "the conjunction must be able to keep the
block". That reading is wrong in a way worth naming: it treats `reviewedBy` as if it were the
only thing standing between the call and an allow. It is not. `reviewedBy` decides who may
clear THIS policy's verdict; it has no bearing on what Jev is asked. `secret-exposure`,
`credential-exfiltration` and `agent-config-tampering` are asked on that call either way and
deny on their own through the most-severe merge, so nothing was ever unenforced and the
addition bought no safety.

**Reverted**, on the refined form, and on a second ground that outranks it: #833's headline
result (false blocks 32% → 7.4%, attacks 123 of 234) was measured with this pairing exactly
as the builtin ships it. A second name removes clears; removing clears restores blocks; and
the blocks it would restore are drawn from the 106 plus the 12 that the widened precondition
and the path-extraction fixes were written to kill. That is a measured number moved by a
judgement call, in the one place the PR makes a numeric claim — the same reason the probe
wording and the other shipped regexes in §"What looks wrong" are left alone. It needs a
corpus replay, which this pack is not the place to run.

The general lesson, which is the version that belongs in the rule: **a pairing is a demotion
only when nothing is left that can deny.** Instruct-only is a symptom, not the diagnosis.

## Known dead-pairing risk

`commit-on-protected-branch`'s precondition reads `facts.currentGitBranch` against a
compiled-in set (`main`, `master`, `production`, `prod`, `release`, `trunk`) and never sees
policy params, so a policy configured with `protectedBranches: ["develop"]` would never have
the question asked on `develop`. That gap no longer bites this pack — `block-work-on-main` is
hard for an unrelated reason — but it is the live hazard for anyone who adds a
branch-scoped policy to a future version, and closing it needs `facts.ts` to carry the
effective protected list rather than a change a pack can make.

Of the 10 distinct reviewers the 17 reviewable rows name, exactly one has a precondition —
`read-outside-workspace` — and it was widened specifically to cover everything its partner
denies. Every other pairing in the pack is asked unconditionally for its tool class.

## The four rewritten `fn`s

Every other `fn` is a faithful copy of the builtin. These four are deliberately narrower,
and each one hands the remainder to the check that policy names in `reviewedBy`. All four
belong to `reviewable` policies — a narrowing on a `hard` policy would have nowhere to hand
the remainder to, so none was made.

### 1. `protect-env-vars` — the `echo`, `export` and `$env:` branches

The builtin used `ECHO_ENV_RE = /echo\s+.*\$\{?[A-Za-z_]/` (any variable reference after
any `echo`), `EXPORT_RE = /export\s+\w+/` (any assignment) and `PS_ENV_VAR_RE = /\$env:./`
(any PowerShell env reference). On a `defaultEnabled: true` policy that denies
`echo "building $VERSION"`, `echo $PWD`, `export NODE_ENV=test`,
`export PATH=$PATH:/opt/bin` and `Write-Host $env:PATH`. Now:

- `export` only in its dump forms — bare and `-p`. Those print every exported value; an
  assignment prints nothing, which is the harm the policy's own description names.
- `echo` / `printf` only of a variable whose NAME names credential material, the name split
  on `_`/`-` with a whole part required to match — so `GIT_AUTHOR_NAME` is out (a substring
  test on `AUTH` would have kept it in) and `AWS_SECRET_ACCESS_KEY` is in. `%VAR%` (cmd.exe)
  folds into the same test.
- `$env:NAME` keeps the builtin's position-independence — it is unambiguously an
  environment read, unlike a bare `$VAR` — and only gains the name test, so
  `Write-Host $env:SECRET` is still caught and `$env:PATH` is not.

**Gives up:** `echo $DATABASE_URL`, `echo $MY_THING` — a secret held under a name that does
not say so is no longer a deterministic deny. `env-secrets-dump` covers it ("echo of a
variable whose name suggests a key, token, password or secret") but only where Jev is
configured. This is the one rewrite that trades real floor coverage for the false-positive
rate. The other two branches give up nothing: an assignment cannot expose a value, and a
bare `$SECRET` inside `curl -H "Authorization: $TOKEN"` is a use, not a print — and that
one is `credential-exfiltration`'s concern, not this policy's.

### 2. `block-env-files` — the Bash branch

The builtin used `ENV_CMD_RE = /\.env(?:\b|\s|$|\.)/` over the whole command, i.e. the
substring `.env` anywhere, so `grep -rn "process.env" src/`,
`node -e 'console.log(process.env.CI)'` and `rg 'import.meta.env' app/` were all denied on a
`defaultEnabled: true` policy. Meanwhile the policy's other branch (`ENV_FILE_PATH_RE` over
`file_path`) only matched `.env` at the start of a basename — so one policy's two branches
disagreed by an order of magnitude about what an env file is. The Bash branch now requires
`.env` to begin a path segment (start of word, or straight after `/`).

**Gives up:** a non-dotfile env file named in a command — `cat config/app.env`,
`source prod.env`. The `file_path` branch never matched those either, so no tool loses
coverage it had; the asymmetry is what goes away. `secret-exposure` catches them with Jev
configured.

### 3. `block-push-master` — exact ref match

The builtin built one `\b…\b` alternation from `protectedBranches` and tested it against the
whole argument string, so `git push origin feature/main-menu`, `main-v2` and
`hotfix/master-fix` were all denied — the class `push-to-protected-branch` names in its own
false criteria. Each operand after the remote is now reduced to the ref it lands on (`+`
stripped, `src:dst` → `dst`, `refs/heads/` stripped) and compared exactly.

This rewrite carries more weight than the other three: because the policy stays **hard**
(Rule 3), the floor is the *only* thing that fixes its noise. That is the trade the pack
makes on this row — narrow the matcher deterministically rather than demote the policy — and
it is why the fix is in the detector rather than in `reviewedBy`.

**Gives up:** a push whose remote operand is displaced by an unusual flag form
(`git push --repo=origin main` leaves one bare operand, which git reads as the remote, so it
is skipped). `git push --mirror origin` and a bare `git push` on a protected branch were
misses before this change and remain misses. Being hard does not hide those from Jev:
`push-to-protected-branch` is still asked, still reads `facts.current_git_branch`, and its own
instruct still joins the most-severe merge — `hard` withholds only the power to clear this
policy's deny.

### 4. `block-secrets-write` — basename-anchored

The builtin tested `/id_rsa/` and `/credentials/` as unanchored substrings of the whole
path, so `src/auth/credentials.ts`, `docs/credentials.md`, `lib/id_rsa_parser.ts` and
everything under a `credentials/` directory were denied as "writing a secret key file".
`*.pem` / `*.key` are unchanged (already anchored); `id_rsa` must now be the whole basename,
and a `credentials` stem must not carry a source or prose extension.

**Gives up:** `~/.ssh/id_rsa.old`, `~/.ssh/id_rsa_backup`, `prod-credentials.tar`, and
anything under a directory called `credentials/`. `secret-exposure` covers all four — and
its false criteria ("documentation about credentials", "a test fixture") is a list of what
the builtin was denying instead.

## Divergences from the builtin, beyond the four rewrites

One, and it widens rather than narrows. (A second, `block-work-on-main`'s authority, stopped
being a divergence when the builtin landed the same change — see §Accepted costs.)

### `block-secrets-write` now matches `Edit` as well as `Write` — a hole closed

The builtin declares `toolNames: ["Write"]` and its `fn` opens with
`if (ctx.toolName !== "Write") return allow()`. So an `Edit` of `~/.ssh/id_rsa` or
`~/.aws/credentials` passed the **entire** regex tier: nothing else covers it either —
`block-read-outside-cwd` is `["Read", "Glob", "Grep", "Bash"]` and `block-env-files` only
matches a `.env` path. The policy's name, description and `displayTitle` all say "writing",
so the gap was invisible from outside the source.

`Edit` carries the same canonical `file_path` key on every one of the 11 CLIs, so the path
detection is reused byte for byte — this widens `match`, it does not touch `writesSecretFile`.
Verified on both tools: `id_rsa`, `credentials`, `server.pem` deny under `Write` and `Edit`
alike, and `src/auth/credentials.ts` allows under both.

`NotebookEdit` was considered and excluded: `writesSecretFile` matches `*.pem`, `*.key`,
`id_rsa` and a `credentials` stem, and no `.ipynb` is any of those, so adding it would widen
the match without changing one verdict. `Bash` was excluded too — a shell write needs a
command detector this policy has never had, and inventing one here would be a new policy
wearing this one's name.

Same question asked of every other path-based policy, since `Write`-only was the shape of the
bug: `block-env-files` declares no `toolNames` at all and already fires on `Edit` (confirmed,
not assumed). `warn-large-file-write` is `Write`-only but reads `toolInput.content`, which
`Edit` does not carry — its subject is the size of a file being created, not of an edit, so
adding `Edit` would match more calls and decide none of them. `block-read-outside-cwd` omits
`Write`/`Edit` by design; a *write* outside the project is a policy that does not exist in
these 38, which is a gap to propose, not one to close by widening a read guard.

## Accepted costs

### `block-work-on-main` is hard, and its matcher noise now has no backstop

Rule 3 forces the authority, and the builtin's catalog now carries the same decision with
the same reasoning — so this is no longer a divergence. The cost is still real, so it is
written down rather than left implicit:
`GIT_COMMIT_MERGE_RE` matches `git commit|merge|rebase|cherry-pick` as a **substring**, so on
a protected branch it denies `gh pr create --body "git commit"` and
`grep -rn "git rebase" docs/` — and with the pairing refused there is nothing left to clear
them. Marking it reviewable did not actually undo that: the reviewer is instruct-only, so the
policy was switched off wholesale rather than having its noise filtered.

Bounded, and bounded deliberately: the policy is `defaultEnabled: false`, so it is opt-in.
Accepted on review, with the reasoning recorded: a working policy with a known noisy edge
beats a policy that silently does nothing, and the noise is a matcher bug rather than a
severity question. The proper fix is the same shape as `pushTargetRef` — require `git` in
command position — but that is a matcher change with its own false-positive surface and it
belongs in the builtin where its tests live, not in a pack that cannot run them.

## What looks wrong in the existing 38

Found while reading the builtins. One of these — `block-secrets-write` matching `Write` only,
so `Edit` on a key file passed the whole regex tier — **is fixed in this pack**; see
§Divergences. The six below are not, either because they are shipped regexes with measured
false-positive rates, calibrated probe text, or a new policy: each needs a corpus replay to
validate rather than a judgement call, and the `params` drop belongs to whoever owns
`pack-cli.ts`.

1. **`failproofai publish` silently drops every `params` schema.** `pack-cli.ts`'s `build()`
   assembles its manifest candidate from `name`, `description`, `category`,
   `defaultEnabled`, `match` and the authority fields — and not `params`. But
   `registerPolicy` reads a pack policy's params schema **from the manifest, by name**, and a
   policy with no schema gets `ctx.params = {}`, which discards the user's own configured
   `policyParams` as well as the publisher's defaults (the loader's `unionCatalog` comment
   says exactly this about the collapse case). 19 of these 38 carry `params`. Published
   through `pack-cli`, `prefer-package-manager` becomes permanently inert (`allowed.length
   === 0` → `allow()` on every call), and `block-sudo`'s `allowPatterns`,
   `block-read-outside-cwd`'s `allowPaths` and `block-rm-rf`'s `allowPaths` stop working —
   silently stricter, which is the direction that produces false blocks nobody can switch
   off. `scripts/build-policy-pack.mjs` is unaffected because it builds its manifest from
   the catalog. This pack registers `params` on every entry that has one, so the fix is one
   line in `build()`; until it lands, the manifest has to be built from the catalog rather
   than from the entry.
2. **The `isAgentSettingsFile` branch of `block-read-outside-cwd` is unclearable in
   practice.** It denies `.claude/settings.json` even when the path is *inside* the project,
   but `read-outside-workspace`'s precondition requires some path outside the project — so
   for a project-local settings file nothing is asked and the deny stands whatever Jev
   thinks. That is the safe direction and arguably correct (reading your agent's own
   guardrails is the reconnaissance step before editing them), but the policy's manifest
   will say `reviewable` while that branch behaves as `hard`. Worth a sentence in
   `authority.mdx` rather than a code change.
3. **`block-force-push` treats `--force-with-lease` and `--force-if-includes` as safe, and
   `git-history-rewrite` does not.** The probe counts `--force-with-lease` as overwriting
   remote history. So the regex tier allows what the semantic tier denies: the *only* thing
   that stops a leased force-push on a machine with Jev is Jev. Not a defect in either half
   on its own, but the two halves disagree, and the disagreement is invisible in
   `authority.mdx`'s one-line reason.
4. **No policy in the 38 guards egress.** There is no regex counterpart to
   `credential-exfiltration` — nothing matches `curl -d @~/.ssh/id_rsa https://…`,
   `scp ~/.aws/credentials …` or a `nc` upload. The most severe non-overridable check in the
   semantic set has no deterministic floor under it, so on a machine without a Jev key that
   entire class is unguarded. This is the largest gap in the set and the clearest candidate
   for a 39th policy.
5. **`warn-repeated-tool-calls`' fingerprint is the whole `toolInput`.** It is
   `JSON.stringify({ tool, input: ctx.toolInput })`, so a `Write` of a 2 MB file produces a
   2 MB map key; the serialized tracker then exceeds `TOOL_CALL_TRACKER_MAX_BYTES` (64 KB),
   the write is skipped, and that call is never recorded. So repeated identical large writes
   — the loop that costs the most tokens — can never be detected, while small-input tools
   keep working. Nothing reports the skipped write.
6. **`ENV_PRINTENV_RE` fires on the WORD `env`, not the command.** `env FOO=bar ./script`
   (a runner, printing nothing), `cd env && ls` and `python -m venv env` are all denied by a
   `defaultEnabled: true` policy — and `env-secrets-dump`'s false criteria names the third
   one outright ("creates a virtualenv named env"), which is how we know it was measured.
   Left exactly as the builtin has it rather than narrowed: fixing it needs a
   command-position walk like `namesElevation`'s, which changes the detector's shape rather
   than its threshold, and is a change to make in the builtin where its tests live.

## Wiring

`policies/regex.ts` registers on import; `index.ts` (owned by the semantic half) imports it
first so the floor is standing even if the semantic import fails. `policies/shared.ts` holds
the detectors and is imported only by `regex.ts` — the bundler inlines it, so the published
artifact is still the single content-addressed entry a pack has to be.

`reviewedBy` names resolve against the pack's own `semantic` array once
`resolvePolicyAuthority` takes the effective reviewer set (contract §6). On a CLI without
that change the 16 names still resolve, because they are byte-identical to the compiled-in
`SEMANTIC_POLICY_NAMES` — which is why this pack's semantic half keeps the builtin names
rather than renaming anything.
