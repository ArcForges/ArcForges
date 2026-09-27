# Execution primitives

The owner explicitly creates task or chat-turn identity, then separate command,
invocation, run, step and attempt identities. New IDs are canonical Contracts UUIDs;
recovery reads the stored same identity. A duplicate delivery retains all identities.
An authorized retry preserves command/invocation/run/step and changes only attempt.
Unknown effects require explicit owner reconciliation authorization; memory-only
primitives never claim exactly-once effects or provide durable receipts.

`CanonicalCommandHash.Compute` accepts already owner-validated semantic fields and
server-derived realm/workspace/actor. It binds profile, operation and revision kind
and value; transport IDs and credential fields are refused. Semantic JSON sorts
unique ASCII property names ordinally, preserves array order and text scalars,
distinguishes absent/null/empty, and admits int32 numbers only. Wider integers and
exact decimals use their validated canonical string projection from Contracts.
This routine is not an arbitrary scientific-content hash or an authorization check.
Owner-specific normalization happens before this boundary, never globally here.

Failures and cancellation use the distinct `Errors.Outcome<T>` variants and preserve
effect certainty. Application.Abstractions supplies explicit clock, cancellation and
lifecycle ports. Durable transaction/receipt/crash acceptance remains PLT.01.
