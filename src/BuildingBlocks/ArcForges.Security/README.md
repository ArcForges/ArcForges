# Principals and actor-chain provenance (PLT.36)

This nonpackable mechanism constructs a complete, immutable actor chain at an
entry point and carries it explicitly. Identity evidence does not authenticate a
caller or authorize an operation. Agent profiles are configuration, never human
principals. Delegated execution retains the human owner and each intervening actor.

Offline queue and serialization tests cover lossless propagation and malformed
input refusal. They do not prove live process authentication, persisted queues,
product integration, or the later PLT.38 enforcement decision pipeline.

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
