# Principals and actor-chain provenance (PLT.36)

This nonpackable mechanism constructs a complete, immutable actor chain at an
entry point and carries it explicitly. Identity evidence does not authenticate a
caller or authorize an operation. Agent profiles are configuration, never human
principals. Delegated execution retains the human owner and each intervening actor.

Offline queue and serialization tests cover lossless propagation and malformed
input refusal. They do not prove live process authentication, persisted queues,
product integration, or the later PLT.38 enforcement decision pipeline.

## Instruction provenance (PLT.42)

Instruction-bearing text enters this building block through `InstructionInput.Capture` with
one of six explicit origins: model output, extension output, retrieved content, imported
document, deep link, or catalog metadata. Each input owns an immutable string and carries a
bounded source reference plus a SHA-256 binding over the origin, reference, and content. The
binding detects accidental snapshot corruption; it is not a signature and does not authenticate
the asserted source.

`InstructionSnapshot` is a bounded, strict process-boundary representation. It rejects unknown,
duplicate, missing, unsupported, and content-mismatched fields. Decoding preserves the same
untrusted status. `ActorOperation<T>` can carry or forward marked content and the actor chain,
but it is only a carrier: neither provenance nor the chain authorizes execution. An enforcement
point must still run the separate decision and authorization pipeline before acting.

## Supporting registrations (ADP.07)

The owned artifact is `src/BuildingBlocks/ArcForges.Security/**` including its
nested offline test project. Before supporting edits, claim epoch 1 binds:

- `DesktopPlatform.slnx` and `.github/workflows/package-validation.yml`: append
  Security test registration using the shared solution/CI append protocol.
- `eng/policy/licence-boundary.json`, `eng/policy/runtime-ownership.json`, and
  `eng/policy/reconciliation/active-projects.json`: register the exact owned
  project and its offline tests using the shared project-inventory protocol.
- `eng/provenance/files.json`: append first-party source/test paths and remove
  the replaced scaffold path using the provenance registration protocol.
- `eng/policy/dependency-policy.json` and
  `eng/policy/dependency-reviews/plt-36-r1.json`: bind regenerated owned locks and
  the already admitted Foundation/xunit closure via an immutable successor
  receipt. No dependency version, framework, or publication admission changes.
