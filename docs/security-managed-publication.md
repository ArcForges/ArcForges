<!-- SPDX-License-Identifier: AGPL-3.0-only -->
# Managed security and content-helper publication

PLT.59 admits seven existing implementations into the normal, lockstep NuGet publisher:
`ArcForges.Security`, `ArcForges.Security.Secrets`, `ArcForges.Security.Audit`,
`ArcForges.Security.LocalRpcBoundary`, `ArcForges.Security.CapabilityEnforcement`,
`ArcForges.ContentSandbox.Contracts` and `ArcForges.ContentSandbox.Broker`.
These are managed packages. The content-helper executable, native parsers and RID packages
are separate producers and are not bundled or certified by this admission.

The normal package catalogue checks the actual generated dependency set before producing
an exact-version nuspec. Owned packages use the same candidate version; external Contracts
Foundation, PublicApi, LocalRpc.Platform, LocalRpc.Sandbox and Sdk peers use the verified
`1.0.0-ci.324.1` publication from Contracts commit
`330e46bd158bfbb7cdc94c7006565c87e27b1cc6`. Only the affected production selectors and
consumer locks change. The earlier `113.1` fixtures and `270.1` realtime probe remain pinned.
No range relaxation or NU1608 suppression admits an incompatible product closure.

The security packages retain current actor, permission, approval, lease and owner gates.
Instruction provenance and an actor-chain snapshot carry evidence; neither grants authority.
The durable audit adapters preserve exact producer facts, cancellation and terminal outcomes.
Consumers supply real authority, owner operations, persistence and lifecycle dependencies;
there is no default successful authorization or execution adapter.

ContentSandbox.Contracts is the bounded parent/helper protocol. Broker owns parent-side
registration, launch, input and output lifetimes, supervision and cancellation. A managed
package is not proof that a particular parser or OS isolation profile is available. An
unavailable isolation profile refuses the launch. NAT.22/NAT.25 own native RID, executable
identity and release trust; PLT.46 owns complete product and OS acceptance.

Validation binds the complete actual locked dependency closure, licences, source inputs and
immutable predecessor receipts. Component tests run the existing implementations; actual
generated NuGet dependencies and legal assets are checked before admission. PR and normal
main CI must pass at the independently reviewed source. Only the normal NuGet publisher's
receipt proves publication. APP.02/APP.03 compose the published packages into the product,
including its shared AI assistant, and retain their own authorization and acceptance checks.

Local verification on the accepted NAT.15/GOV.23 source parent used the pinned .NET
10.0.400 SDK: complete evaluated restore and Release build passed with zero warnings or
errors. Actual component suites passed 928 security, 34 secrets, 53 durable audit,
79 capability and 161 content-helper cases. Two secret-store and thirteen helper OS tests
were explicitly skipped; these results do not establish OS isolation or product acceptance.
The actual generated dependencies and managed/legal assets passed for all 22 managed
entries in the 24-package catalogue. Diagnostic packages used a local component version
and are not source-bound publication candidates. The exact-head canonical pipeline must
still produce, verify and publish the final source-bound cohort.
