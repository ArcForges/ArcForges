# FND.07 published Foundation acceptance

This is an explicitly local consumer of the immutable published
`ArcForges.Foundation` and `ArcForges.Application.Abstractions` candidate
`1.0.0-ci.29.1`, with Contracts `1.0.0-ci.113.1`. It has no project references,
copied generated contracts, source-package substitutions, solution registration,
or hosted consumer execution. Package locks bind the complete restored closure.

`Program.cs` produces actual protobuf bytes using the published C# packages.
`roundtrip.ts` checks their independent expected values through the published TS
projection and returns protobuf bytes. C# verifies the returned values and
additional TS-origin vectors. The TS consumer also reads the independently
authored, published Contracts fixture package. The fixture files and temporary
exchange are test data, not real customer operations.

Coverage includes UUID network ordering; signed/unsigned values beyond JS safe
integers; exact decimal coefficient/scale and rational values; opaque cursors;
absent versus explicit zero time components; ProtoJSON integer/base64 exceptions;
inert unknown fields and enum values; all 44 registered reason codes; unknown
reader codes; duplicate command identity with distinct retry attempts; and
refusal of automatic retries for unknown effects. The consumer implements the
published `IExecutionContext` port. It proves no durable exactly-once effect,
product integration, live RPC, authentication, provider or device behavior.

## Explicit local use

Use the existing repository-selected SDK and a Node runtime that supports native
TypeScript stripping. Restore only when this exact consumer closure is needed:

```text
dotnet restore eng/acceptance/foundation/Foundation.Acceptance.csproj --locked-mode
npm ci --prefix eng/acceptance/foundation --ignore-scripts --no-audit --no-fund
python C:/MyFile/Projects/Plan/tools/delivery.py build-slot run --worker <worker> --task FND.07 -- python eng/acceptance/foundation/run.py --local
```

The runner fails closed in CI, builds only this consumer, never restores, and
uses a temporary directory for the exchange. Do not add it to a CI workflow or
default repository build. A locally installed compatible SDK can be selected
without modifying `global.json` by adding
`--sdk-dll "C:/Program Files/dotnet/sdk/10.0.401/dotnet.dll"` to the runner;
restore with that same SDK using `dotnet <sdk-dll> restore ... --locked-mode`.
This does not replace the pinned `10.0.400` producer CI authority.

See [receipt.json](receipt.json) for actual executed inputs and limitations.
Kotlin inherits generated compilation evidence from CON.91; no Kotlin runtime
conformance is claimed. The original publication remains the candidate authority;
this acceptance does not require a tag, replacement version or republishing.
