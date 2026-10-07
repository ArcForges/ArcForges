<!-- SPDX-License-Identifier: AGPL-3.0-only -->
# Native installation credential custody

The first-party native host supplies its real realm, closed product, platform and persistent installation ID to `InstallationCredentialScope`. It makes an explicit isolation decision when creating `InstallationCredentialBroker`. This purpose is available before account authentication and does not invent a Device, User or Session. The existing authenticated connector `SecretBroker` and its grants remain unchanged.

`GetPlatformSupport` reports `Unsupported` for absent macOS/Linux adapters. Current Windows composition uses the actual existing Credential Manager adapter and declares `SameUserShared`. `RequireOsEnforcedPerApplication` refuses on this adapter. The broker's target namespace and current-user mutex do not prevent hostile sibling code from addressing the same Windows user's credential store.

`InitializeNewInstallationAsync` is an explicit initial-installation operation: it reads protected state first and reuses a valid existing tuple. `OpenExistingAsync` requires immutable expected public-key metadata and never generates a replacement when state is missing, corrupt or mismatched. Version 1 is stable; login does not rotate it. There is no public private-key export or arbitrary signing port.

The bounded versioned record binds the exact purpose/realm/product/platform/installation/current-principal digest, canonical 91-byte P256 DER-SPKI, stable positive version and canonical internal PKCS8. Private key/record/readback buffers are owned and cleared; imported crypto handles are disposed. Each operation checks the captured actual Windows user before addressing the backing store.

The backing store has no CAS. A current-user, per-installation `Global` named mutex serializes cooperating processes across logon sessions. A synchronous worker owns acquisition through release on one thread and rereads actual state after abandonment. There is no foreign/network await under the mutex. Admission is bounded to 32 operations per broker; queue and mutex wait share the configured cancellation/deadline budget (default 10 seconds, maximum 30 seconds). Entered synchronous OS calls cannot be forcibly canceled: they finish with readback reconciliation, and disposal joins them rather than reporting fictitious termination.

Every attempted write is followed by exact readback, including when the adapter throws. A confirmed exact write is a real effect; canceled callers receive `Happened`. Missing, failed or mismatched readback remains `Unknown`, preserves the original unresolved public tuple, and never retries a write or deletes/replaces another record. A later explicit read reconciles actual stored state. Before-write cancellation and admission refusals have no effect. All concurrent disposers join the same drain.

## Current component observations

Pinned SDK 10.0.400 locked Release with repository AOT/trim/analyzer guards compiled cleanly. Fourteen ordinary components passed for canonical P256 and independent signature verification, immutable metadata, stable restart, missing/corrupt/wrong expected-key refusal, scope/principal fences, uncertain-write reconciliation, post-commit synchronization failure preserving its actual effect, concurrent initialization, bounded admission, deadline/cancellation, abandoned mutex and joined disposal. Fault-injecting backing adapters simulate only unavailable dependency failures; they do not establish OS storage or deployment.

Three separate explicit local Windows diagnostics passed against actual Credential Manager: restart with the same protected key; parent plus two owned processes initializing one stable key; and real owned-process termination while holding the named mutex followed by unchanged-key reconciliation. Only unique test-owned targets were deleted during cleanup. These observations do not prove different-user isolation, signed/installed product behavior, other OS custody or remote login acceptance.

## Independent custody publication and remaining signer integration

The complete custody core is delivered independently through PLT.65 in the existing Secrets package. Its source/API review, applicable current CI, normal package publication and delivery ledger are required before a product consumes that artifact. The existing fourteen component, separate three Windows and Native AOT observations establish the stated local behavior; they do not replace those delivery gates.

PLT.64 retains the five closed typed signers. They must consume the actual published CON.34 `InstallationPossession` helpers and generated flow/callback/session fields, plus CON.40's original native refresh-context carriage. That signer integration remains in progress. Exact published-helper vectors, wrong operation/key/version/context tests, independent review, applicable current CI and normal publication remain required. The custody core exposes public identity metadata and stable expected-key opening; it provides no private-key export or arbitrary signing interface. Full native account/login/session and all-platform installed acceptance retain their original owners.
