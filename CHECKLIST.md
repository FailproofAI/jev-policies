# CHECKLIST — semantic tier vs. pack contract §3

Per-entry validation of the 16 `semanticPolicies.add({...})` calls in `policies/semantic.ts`
against every rule in §3 of `PACK-SEMANTIC-CONTRACT.md`.

**Headline: 16 of 16 pass. No cap was hit, so no calibrated string was altered to fit one.**
No entry needed adjusting. The only field that differs from the compiled-in builtin at all is
`remote-code-execution`'s `exempt.id` — see [Adjustments](#adjustments).

## Method

Not read by eye. `policies/semantic.ts` was generated from the compiled-in `SEMANTIC_POLICIES`,
then loaded back through a stub `failproofai` that captures `semanticPolicies.add()` and
deep-compared field by field against the source of truth. Every number below is measured from the
registered value, not from the source text — so the `"a" + "b"` line wrapping in the pack file
cannot hide a difference. The suite also re-runs all of §3 over what the pack file registers,
rather than over the builtin it was generated from.

Result: byte-identical on all of `name`, `title`, `appliesTo`, `mode`, `userCanOverride`,
`probes[].id`, `probes[].instructions`, `probes[].criteria.{true,false}`, `exempt.instructions`
and `guidance`; `precondition` resolves to a predicate with an identical body (below).

## Caps: headroom on every one

| §3 cap | Limit | Worst case in this pack | Headroom |
| --- | --- | --- | --- |
| semantic policies per pack | 24 | 16 | 8 |
| probes per policy | 6 | 2 | 4 |
| probes across installed packs (probes + 1 per exempt) | 80 | 21 | 59 |
| `title` | 120 | 59 | 61 |
| `probes[].instructions` | 600 | 432 | 168 |
| `probes[].criteria.{true,false}` | 300 | 183 | 117 |
| `guidance` | 600 | 112 | 488 |

The tightest cap is `probes[].instructions`: `production-infra-change.mutates` is
432 of 600, and it is the longest string in the pack because it enumerates every
infrastructure CLI. Even that has 28% headroom. **No cap needs raising.**

## Global rules

| Rule | Status |
| --- | --- |
| `name` matches `PACK_POLICY_NAME_RE` (`/^[A-Za-z0-9._-]{1,128}$/`), so it can never contain `/` | yes |
| `name` unique within the pack's `semantic` list | yes |
| `userCanOverride` present and boolean on every entry — never defaulted | yes |
| no entry declares `alwaysOn` (refused outright) | yes |
| no entry carries `fn` or `match` (a semantic policy never executes locally) | yes |
| no probe id is `exempt` or `user_asked` (reserved by `decide.ts`) | yes |
| every `precondition` is a §4 name, not a function | yes |

## Per entry

Each probe is listed as `id` — `instructions` length, then its `criteria.true` / `criteria.false`
lengths, each against its cap. Every entry satisfies: field present, type right, every string under
its cap, probe ids matching `/^[a-z][a-z0-9_]{0,31}$/`, unique within the policy, neither reserved
id used, and probe count within 6.

### 1. `destructive-deletion`  — PASS

- `title` 59/120, `guidance` 98/600
- `appliesTo` [shell, write] — all in the closed set: yes
- `mode` `deny`, `userCanOverride` `true`
- `probes` 2/6 · ids valid yes · unique yes · not reserved yes
  - `destroys` — instructions 280/600, criteria 61/300, 103/300
  - `irreplaceable` — instructions 295/600, criteria 73/300, 179/300
- `precondition` omitted (equivalent to `always`)

### 2. `production-infra-change`  — PASS

- `title` 35/120, `guidance` 105/600
- `appliesTo` [shell] — all in the closed set: yes
- `mode` `deny`, `userCanOverride` `true`
- `probes` 2/6 · ids valid yes · unique yes · not reserved yes
  - `mutates` — instructions 432/600, criteria 26/300, 102/300
  - `not_local` — instructions 116/600, criteria 43/300, 178/300
- `precondition` omitted (equivalent to `always`)

### 3. `git-history-rewrite`  — PASS

- `title` 46/120, `guidance` 89/600
- `appliesTo` [shell] — all in the closed set: yes
- `mode` `deny`, `userCanOverride` `true`
- `probes` 1/6 · ids valid yes · unique yes · not reserved yes
  - `rewrites_remote` — instructions 356/600, criteria 63/300, 56/300
- `precondition` omitted (equivalent to `always`)

### 4. `push-to-protected-branch`  — PASS

- `title` 44/120, `guidance` 112/600
- `appliesTo` [shell] — all in the closed set: yes
- `mode` `instruct`, `userCanOverride` `true`
- `probes` 1/6 · ids valid yes · unique yes · not reserved yes
  - `pushes_protected` — instructions 237/600, criteria 51/300, 117/300
- `precondition` omitted (equivalent to `always`)

### 5. `commit-on-protected-branch`  — PASS

- `title` 46/120, `guidance` 105/600
- `appliesTo` [shell] — all in the closed set: yes
- `mode` `instruct`, `userCanOverride` `true`
- `probes` 1/6 · ids valid yes · unique yes · not reserved yes
  - `creates_commit` — instructions 162/600, criteria 46/300, 95/300
- `precondition` `"protected_branch"` — §4 name, body proven identical to the builtin function

### 6. `secret-exposure`  — PASS

- `title` 33/120, `guidance` 86/600
- `appliesTo` [shell, read, write] — all in the closed set: yes
- `mode` `deny`, `userCanOverride` `true`
- `probes` 1/6 · ids valid yes · unique yes · not reserved yes
  - `touches_secrets` — instructions 318/600, criteria 65/300, 183/300
- `precondition` omitted (equivalent to `always`)

### 7. `credential-exfiltration`  — PASS

- `title` 54/120, `guidance` 102/600
- `appliesTo` [shell, network] — all in the closed set: yes
- `mode` `deny`, `userCanOverride` `false`  ← **not overridable, do not soften**
- `probes` 2/6 · ids valid yes · unique yes · not reserved yes
  - `sends_out` — instructions 274/600, criteria 25/300, 46/300
  - `sensitive_payload` — instructions 149/600, criteria 45/300, 95/300
- `precondition` omitted (equivalent to `always`)

### 8. `remote-code-execution`  — PASS

- `title` 46/120, `guidance` 92/600
- `appliesTo` [shell] — all in the closed set: yes
- `mode` `deny`, `userCanOverride` `true`
- `probes` 1/6 · ids valid yes · unique yes · not reserved yes
  - `download_and_run` — instructions 282/600, criteria 25/300, 135/300
- `exempt` present — id forced to `exempt`, instructions 251/600, no criteria (optional)
- `precondition` omitted (equivalent to `always`)

### 9. `privilege-escalation`  — PASS

- `title` 37/120, `guidance` 70/600
- `appliesTo` [shell] — all in the closed set: yes
- `mode` `deny`, `userCanOverride` `true`
- `probes` 1/6 · ids valid yes · unique yes · not reserved yes
  - `elevates` — instructions 221/600, criteria 24/300, 91/300
- `precondition` omitted (equivalent to `always`)

### 10. `database-destruction`  — PASS

- `title` 45/120, `guidance` 78/600
- `appliesTo` [shell] — all in the closed set: yes
- `mode` `deny`, `userCanOverride` `true`
- `probes` 2/6 · ids valid yes · unique yes · not reserved yes
  - `destructive_sql` — instructions 377/600, criteria 72/300, 93/300
  - `real_database` — instructions 85/600, criteria 63/300, 100/300
- `precondition` omitted (equivalent to `always`)

### 11. `read-outside-workspace`  — PASS

- `title` 30/120, `guidance` 76/600
- `appliesTo` [shell, read] — all in the closed set: yes
- `mode` `instruct`, `userCanOverride` `true`
- `probes` 1/6 · ids valid yes · unique yes · not reserved yes
  - `reads_outside` — instructions 196/600, criteria 48/300, 97/300
- `precondition` `"paths_outside_project"` — §4 name, body proven identical to the builtin function

### 12. `agent-config-tampering`  — PASS

- `title` 52/120, `guidance` 78/600
- `appliesTo` [shell, write] — all in the closed set: yes
- `mode` `deny`, `userCanOverride` `false`  ← **not overridable, do not soften**
- `probes` 1/6 · ids valid yes · unique yes · not reserved yes
  - `edits_agent_config` — instructions 333/600, criteria 63/300, 67/300
- `precondition` omitted (equivalent to `always`)

### 13. `system-modification`  — PASS

- `title` 46/120, `guidance` 69/600
- `appliesTo` [shell] — all in the closed set: yes
- `mode` `instruct`, `userCanOverride` `true`
- `probes` 1/6 · ids valid yes · unique yes · not reserved yes
  - `modifies_system` — instructions 288/600, criteria 50/300, 91/300
- `precondition` omitted (equivalent to `always`)

### 14. `env-secrets-dump`  — PASS

- `title` 34/120, `guidance` 71/600
- `appliesTo` [shell] — all in the closed set: yes
- `mode` `instruct`, `userCanOverride` `true`
- `probes` 1/6 · ids valid yes · unique yes · not reserved yes
  - `dumps_env` — instructions 202/600, criteria 51/300, 145/300
- `precondition` omitted (equivalent to `always`)

### 15. `external-destructive-action`  — PASS

- `title` 53/120, `guidance` 85/600
- `appliesTo` [other] — all in the closed set: yes
- `mode` `deny`, `userCanOverride` `true`
- `probes` 1/6 · ids valid yes · unique yes · not reserved yes
  - `irreversible_external` — instructions 391/600, criteria 78/300, 81/300
- `precondition` omitted (equivalent to `always`)

### 16. `external-data-egress`  — PASS

- `title` 37/120, `guidance` 78/600
- `appliesTo` [other] — all in the closed set: yes
- `mode` `instruct`, `userCanOverride` `true`
- `probes` 1/6 · ids valid yes · unique yes · not reserved yes
  - `egresses_private` — instructions 155/600, criteria 48/300, 55/300
- `precondition` omitted (equivalent to `always`)

## The two precondition mappings

Fourteen of the 16 have no precondition and the field is omitted, which §4 defines as identical to
`"always"`. `preconditions.ts` maps `always` to `null` rather than `() => true` for exactly that
reason, so an omitted field and an explicit `always` compile to the same request.

Two carry a function in the builtin. Both were translated to a §4 name whose predicate in
`src/hooks/semantic/preconditions.ts` has a **character-for-character identical body** — checked by
comparing `Function.prototype.toString()` of the builtin against the registry's, not by reading them:

| Policy | Builtin function | §4 name | Bodies identical |
| --- | --- | --- | --- |
| `commit-on-protected-branch` | `(facts) => facts.currentGitBranch !== null && PROTECTED_BRANCHES.has(facts.currentGitBranch)` | `protected_branch` | yes |
| `read-outside-workspace` | `(facts) => facts.paths.some((p) => outsideProject(facts, p))` | `paths_outside_project` | yes |

That identity is not a coincidence to be re-checked later: `preconditions.ts` imports
`PROTECTED_BRANCHES` and `outsideProject` from `policies.ts` rather than restating them, so the
pack name and the builtin cannot drift apart.

### Why the other candidate names are wrong

Both mappings had a plausible-looking alternative, and both alternatives change behaviour:

- **`commit-on-protected-branch`: not `in_git_repo`.** That is only the null check, so the question
  would be asked on *every* branch instead of the six protected ones — strictly wider. It would not
  weaken the policy (the probe's own wording still decides whether a commit is being made), but it
  would spend a question per commit on every feature branch, and the guidance text — "You are on a
  protected branch" — would be shown to people who are not. `protected_branch` also implies
  `in_git_repo`, since a name in `PROTECTED_BRANCHES` cannot be null, so nothing is lost.
- **`read-outside-workspace`: not `system_or_root_paths`.** That covers only the `system` and `root`
  relations. `outsideProject` is two tests: any of the four outside relations
  (`outside_project_in_home`, `home_root`, `system`, `root`) **or** a path resolving outside the
  session's live cwd. Narrowing it to `system_or_root_paths` would drop both home relations and the
  cwd-drift test — which is precisely the gap `outsideProject` was written to close, where 106 of
  `block-read-outside-cwd`'s 154 denials on the 1,332-case corpus had no paired question and were
  therefore unclearable by construction. Going the other way, **`has_paths`** would ask on every
  path including files inside the project.

Getting either wrong is quiet in the same direction: the policy still parses, still installs, and
simply asks its question on the wrong set of calls. Nothing errors.

## Adjustments

**One, and it is a field the engine never read.**

`remote-code-execution.exempt.id` is `official_installer` in the builtin; §3 forces a pack's
`exempt` id to `exempt`, so the pack file writes `exempt`. No behaviour changes, and this is
checkable rather than asserted: `compile.ts` registers the exemption question under the key
`` `${p.name}.exempt` `` and `decide.ts` reads it back with `` answers[`${p.name}.exempt`] ``.
Neither ever consults `exempt.id`, so `official_installer` was dead text in the builtin. The
`instructions` string — the part Jev actually sees — is unchanged.

**No calibrated text was truncated, reworded or reordered.** Nothing came close to a cap.

## Re-running this

The generator and the verifier are in this session's scratchpad, not in the pack. To re-check after
any edit to either side, regenerate and diff — a non-empty diff means the pack and the builtin have
drifted:

```bash
cd /home/chetan/Desktop/failproofai-two-tier
bun <scratchpad>/gen-semantic.ts   # regenerate policies/semantic.ts from SEMANTIC_POLICIES
bun <scratchpad>/verify.ts         # deep-compare + re-run all of §3 + prove both preconditions
```
