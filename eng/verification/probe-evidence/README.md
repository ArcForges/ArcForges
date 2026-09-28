# PRF.09 — Avalonia TableView Native AOT probe

<!-- SPDX-License-Identifier: AGPL-3.0-only -->

This is the first-candidate probe required by PRF.09 / WP-06.06. It constructs the actual
`Avalonia.Controls.TableView` with two typed compiled-binding columns and a real row, then
publishes that host as a trimmed, self-contained Windows x64 Native AOT executable. No warning
suppression or reflection-based binding is used.

| Input | Exact identity |
|---|---|
| Source revision | `0af8d140896cea353706a49a56c9952f4b5bbd3d` |
| SDK | .NET SDK `10.0.400` from the repository `global.json` |
| Target | `net10.0`, `win-x64`, `PublishAot=true`, full trimming |
| Candidate package | `Avalonia` `12.1.3`; NuGet package SHA-256 `DFFB6605B02E144866CB23765EB5AF7255379EBB7EDE75CF11066F3248D83734` |
| Lock/source binding | `packages.lock.json` and NuGet's `.nupkg.metadata` both record content hash `l0VGyGn1OwqFrhmIhIHivvrQP0DtBD4Vn2F1vLYgGA2X2qHg0DMVRAln/6xOTLBUYoTopiVAujN0jtH8MpVSeA==` from `https://api.nuget.org/v3/index.json`; the separate SHA-256 above binds the exact cached signed `.nupkg` bytes |
| Publish output | `prf-09-publish.log` (captured publish stdout/stderr, unedited) |

The locked restore command was:

```text
C:\Users\J7Rdm\.dotnet\dotnet.exe restore eng/verification/probe-evidence/Prf09.TableViewProbe.csproj --locked-mode --verbosity minimal
```

The exact publish command was:

```text
C:\Users\J7Rdm\.dotnet\dotnet.exe publish eng/verification/probe-evidence/Prf09.TableViewProbe.csproj --no-restore -c Release -r win-x64 --verbosity normal
```

The retained log shows the SDK invoking ILC and the native linker, followed by `Build succeeded`,
`0 Warning(s)`, and `0 Error(s)`. The output executable was produced at
`artifacts/bin/dotnet/windows/Prf09.TableViewProbe/Release/net10.0/win-x64/publish/Prf09.TableViewProbe.exe`;
its SHA-256 was `B13B6401CA36A1E93F1A3C800B8CDE1062B0DB871934FAC7495DEE5349264D26`.

This is publish-only evidence for the candidate control in a probe host. The binary was not run;
no GUI/runtime behavior, production shell integration, or product adoption is claimed. A separate
Windows `aot-probe` job in `package-validation.yml` repeats locked restore and compile-only publish
for PR and main package-validation runs; it does not run or upload the executable or create a
product package. PRF.09 schedules VG-03 for WP-10, and any shipped-shell use still needs its own
real consuming-application proof and the repository's recorded licence/admission decision.
