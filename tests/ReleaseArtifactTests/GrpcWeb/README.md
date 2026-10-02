# SPDX-License-Identifier: AGPL-3.0-only

# Generated gRPC-Web Native AOT probe (PRF.05)

`GrpcWebAotProbe` is a non-packable test executable. It drives the generated `HelloService` client of the published
`ArcForges.Contracts.PublicApi` candidate `1.0.0-ci.216.1` through `Grpc.Net.Client` and the binary gRPC-Web handler of
`Grpc.Net.Client.Web` 2.84.0, as a Native AOT image. It is not a product host and not a release package.

## What it checks

Against an ingress (`--live`): the health identity of the deployed revision, a unary success (request shape, response
media type, worker revision header, terminal status in the trailer frame), exact text values (a surrogate pair,
surrounding whitespace, precomposed and decomposed forms, controls, and the 256 UTF-16 unit boundary measured in UTF-16
units), scoped errors (`INVALID_ARGUMENT`, `RESOURCE_EXHAUSTED`, carried as HTTP 200 with a status frame), a
cancellation made while the request is in flight and the same channel serving the next call, an expired deadline and the
emitted `grpc-timeout` header, an unknown method (`UNIMPLEMENTED` from HTTP 404) and an unreachable target
(`UNAVAILABLE`). In process, without any wire: exact 64-bit extremes and a decimal string through the generated
Foundation messages (`codec.*`).

The Hello service only carries strings, so 64-bit integers and decimals are never sent over a wire to an ingress by this
probe. Scope, permission, session expiry and native UI cases do not exist on the anonymous Hello service and are not
checked.

## Self-test (no network)

`--self-test` runs the option guards, the verifier against an in-process stand-in for the ingress, and the verifier
against eleven deliberate misbehaviors of that stand-in, each of which must be caught by a named check. It is a test of
the probe itself. Its result says nothing about any real ingress.

## Opt-in runs (local only, never CI)

CI only restores with the lock file and publishes the executable (job `grpc-web-aot` in
`.github/workflows/package-validation.yml`); it never executes it and never contacts an endpoint. `--live` refuses to run
when `CI` or `GITHUB_ACTIONS` is `true`, requires a Native AOT process, accepts only an `https` base address (`http` only
for loopback) without credentials, query or fragment, and sends no credential of any kind.

```powershell
dotnet publish tests/ReleaseArtifactTests/GrpcWeb/GrpcWebAotProbe.csproj -c Release -r win-x64 -o artifacts/prf-05/win-x64
artifacts/prf-05/win-x64/GrpcWebAotProbe.exe --self-test
artifacts/prf-05/win-x64/GrpcWebAotProbe.exe --live https://arcforges.com/api --evidence artifacts/prf-05/live-evidence.json
```

`--expect-revision <40 hex>` makes a stale deployment fail. The evidence file holds the origin and path, check outcomes
and runtime identity, never a header other than the worker revision, a body or a credential.

`https://arcforges.com/api` is the production Hello ingress of the Cloud repository (docs/development.md there). The
`env.proof` ingress of PRF.07 does not exist, and nothing in this probe addresses it. Run `--live` only while holding the
Plan lease `RES-cloud-deployment`.

## Findings that shaped the probe

`Grpc.Net.Client` sends `/<service>/<method>` and discards any path of the channel address, so the ingress path base
`/api` is applied by a delegating handler (`PathBaseHandler`). A JIT run of this build output reports dynamic code as
unsupported (the project sets `PublishAot`), so the Native AOT identity is taken from the feature switch plus zero
JIT-compiled methods.
