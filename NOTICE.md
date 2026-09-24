# Where the 38 went

Up to `0.1.0` this pack carried both halves: 38 regex policies and the 16 Jev
checks. From `0.2.0` it carries **only the 16**.

The 38 now ship as `FailproofAI/policies` v2, generated from the CLI's own
policy catalog. That is a real improvement rather than a reshuffle: the
`authority` marks that decide which policies Jev may clear now live beside the
policies themselves, so a machine with no pack installed gets the same
reviewability as one with the pack, and there is no hand-written second copy of
38 policy implementations free to drift from the first.

## If you installed 0.1.0

Take both:

    failproofai policies add FailproofAI/policies
    failproofai policies add FailproofAI/jev-policies

Upgrading this pack alone would leave you with the 16 checks and no
deterministic floor beneath them. That configuration is legitimate — it is
Jev-only mode, and it is what installing a pack called `jev-policies` on its own
asks for — but it is almost certainly not what you want: on the labelled corpus
the regex tier alone catches 37 attacks Jev misses.

## Why two packs rather than one

They are needed at different times. The 38 work with no Jev configured at all
and are the floor. The 16 do nothing without it. Shipping them together meant a
user could not take the floor without also taking a dependency on an endpoint
and a key they may not have.
