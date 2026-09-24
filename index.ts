/**
 * FailproofAI/jev-policies — pack entry.
 *
 * The sixteen Jev checks, and nothing else.
 *
 * ── What this pack is, and is not ──
 * These are not policies. Nothing switches one on or off, `--policy` cannot name
 * one, and they appear in no `failproofai policies` listing. Each is a set of
 * typed yes/no questions put to Jev about a tool call, answered with a
 * probability, and a check fires only when EVERY one of its probes clears its
 * threshold.
 *
 * They do two things. Ten of them are the REVIEWERS named by the regex policies
 * in FailproofAI/policies: when such a policy denies and the check it names
 * answers "no concern", the deny is cleared — which is how a pattern that
 * matches `.env.example` as readily as `.env` stops being a false block. The
 * other six review nothing, because no pattern could: they only ever ADD a deny
 * or a warning of their own.
 *
 * ── What it needs ──
 * A configured Jev endpoint. With no `~/.failproofai/jev.json` this pack
 * contributes nothing at all — not a weaker version of itself, nothing: the
 * evaluator's modules are never even loaded. Install FailproofAI/policies for
 * the deterministic floor, which stands on its own.
 *
 * Declaring any semantic entry REPLACES the checks the CLI ships with, so this
 * file is the whole semantic tier on a machine that installs it rather than an
 * addition to it.
 *
 *   failproofai policies add FailproofAI/policies       # the floor
 *   failproofai policies add FailproofAI/jev-policies   # the judgement
 *
 * ── Publishing ──
 * Discovery looks for a top-level file that imports `failproofai` and registers
 * something. This file only re-exports its sibling, so name it explicitly:
 *
 *   failproofai publish index.ts --min-cli-version 1.0.7-beta.0
 */
import "./policies/semantic";
