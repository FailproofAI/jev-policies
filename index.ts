/**
 * FailproofAI/jev-policies — pack entry.
 *
 * Importing this one file registers the whole pack: the regex floor and the
 * semantic (Jev) tier. Both halves are side-effect imports, because each module
 * registers at module scope — `customPolicies.add(...)` / `semanticPolicies.add(...)`
 * run as the file is evaluated, and there is nothing to name afterwards.
 *
 * Order is deliberate. Regex first, so that on a machine where the semantic
 * import throws, or where Jev is not configured and the semantic tier is never
 * consulted, the floor is already standing. The semantic half only ever CLEARS a
 * reviewable regex verdict — losing it leaves the block in place (noisier, never
 * weaker), which is the same direction the loader drops a bad entry in.
 *
 * ── Publishing ──
 * `failproofai publish` discovers a top-level file that both imports
 * `failproofai` and calls `customPolicies.add`. THIS file does neither: it only
 * re-exports two siblings, and discovery is non-recursive so `policies/` is not
 * scanned. Name it explicitly:
 *
 *   failproofai publish index.ts --min-cli-version 1.0.7-beta.0
 *
 * The bundler inlines whatever the entry imports, so both halves land in the one
 * artifact a pack has to be. Bundling needs `bun` on PATH.
 */

// The regex floor. Owned by the other half of this pack; if your checkout does
// not have `policies/regex.ts` yet, that file is still being written — this
// import is correct and will resolve once it lands.
import "./policies/regex";

// The semantic (Jev) tier: 16 policies. Declaring even one `semantic` entry
// REPLACES the compiled-in `SEMANTIC_POLICIES` wholesale, so this file is the
// whole semantic tier rather than an addition to it.
import "./policies/semantic";
