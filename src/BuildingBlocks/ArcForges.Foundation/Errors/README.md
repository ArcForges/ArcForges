# Foundation error primitives (FND.05)

`Errors/ReasonCodes.cs` is the implementation source for the 44 initial stable codes in the canonical operation catalogue at Design `722e85641c8afb765dafcab5bc0e84d5a22d5a3c`, section 3.2 and its category projection. `Errors/generate_registry.py` projects those definitions into `eng/policy/reason-codes.json`. Do not edit the generated policy manually or remove/change an already published code. New producer codes require prior Design registration and append-only review.

```text
python src/BuildingBlocks/ArcForges.Foundation/Errors/generate_registry.py
python src/BuildingBlocks/ArcForges.Foundation/Errors/generate_registry.py --check
```

`ArcForges.Foundation.Errors.Outcome<T>` is an immutable success/failure/cancelled algebra over the published Contracts enums. A cancelled outcome has an explicit effect certainty, has no typed failure, and preserves cancellation through `Map`. A reference type prevents an uninitialized default value from silently representing a successful operation. Transport/protocol exceptions are not fabricated as domain outcomes.

`TypedFailure.Create` admits registered codes only. Its `ArcError`, correlation, details and retry-advice adapters clone mutable protobuf values at both boundaries. Message keys are canonical registry keys, never provider messages. The registry's retry mode is a required prerequisite, not unconditional permission: missing evidence yields `Never`; timed capacity retry requires the server instant, and reconciliation requires an explicit owner operation. Unknown effects never become same-command/timed automatic retries. Conditional quota/provider remedies conservatively default to no automatic retry until an owning operation supplies its authorised recovery behavior.

`TypedFailure.FromWire` supports future readers: an unknown code remains a failure with `error.generic`, no retry authority and preserved correlation/effect certainty. Unknown or absent effect enum values become `Unknown`; malformed retry advice becomes `Never`. An unknown reader code cannot be emitted through `ToWire` as an unregistered producer code. Readers must not use a message key or a raw reason string as markup or authority.

The offline `Tests/OutcomeTests.cs` matrix covers all registry entries, completeness, immutable wire adapters, registered last-credential/AST/simulator-invalid-input refusal metadata before effects, unknown future code/enum fallback, retry recovery prerequisites, and cancellation across mapping. These are storage-free primitive tests; they do not claim real credential deletion, parser execution, simulator effects, browser/Cloud integration or durable owner receipts. Owner tasks enforce those real state transitions.
