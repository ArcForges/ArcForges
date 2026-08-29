# AGENTS.md

Guidance for AI coding agents (and humans) working in the ArcForges repository. Read this before making
changes. It is the primary agent instruction file; `CLAUDE.md` defers to it.

ArcForges is one open-source C# product family for AI work, knowledge, instruments, and media, shipped as a
single buildable monorepo. Every planned product and boundary already has a real project; product behavior
lands through small, reviewable steps. Do not treat a scaffolded project as finished behavior, and do not
claim work is done without evidence (see [Ground rules](#ground-rules)).

## Products

| Product | ProductId | Host / runtime |
|---|---|---|
| **ArcChat** | `arcchat` | Avalonia desktop (Native AOT); AI chat, tasks, approvals, local Hub, MCP tools |
| **ArcNotes** | `arcnotes` | Avalonia desktop (Native AOT); documents, knowledge, edgeless, database, slides |
| **ArcScope** | `arcscope` | Avalonia desktop (Native AOT); acquisition, decode, visualize, analyze, report |
| **ArcSlate** | `arcslate` | Avalonia desktop (Native AOT) + owned native C ABIs; NLE timeline, media, render, export |
| **ArcForges Cloud** | `arcforges-cloud` | ASP.NET Core JIT modular monolith; identity, sync, durable agent, storage, policy |
| **ArcChat Mobile** | `arcchat-mobile` | .NET MAUI; Android delivered (Mono AOT), iOS architecture present but build-deferred |
| **ArcForges Web** | `arcforges-web` | Standalone Blazor WebAssembly; marketing site, account portal, ArcChat web companion |

There is exactly **one** Mobile app (`ArcChat.Mobile`) and **one** Web app (`ArcForges.Web.App`); every other
mobile/web project is an internal library or test. Desktop RIDs are `win-x64`, `win-arm64`, `osx-x64`,
`osx-arm64`, `linux-x64` (`linux-arm64` is later). Mobile/Web are ArcChat companions, not editors for the
professional desktop products.

## Frozen architecture invariants — never violate these

These are decided, not open questions. A change that needs any of the following is an architecture error, not
a "temporary compatibility" shim. If real code genuinely conflicts with an invariant, stop and raise it rather
than working around it.

- **Language/runtime is pinned.** Managed code is C# 14 / .NET 10 (SDK pinned in `global.json`); native code is
  strict C++20 with C17-compatible public ABI headers. No `preview`/`latest` language versions, no C++23.
- **Desktops are pure-native Avalonia/Skia.** No WebView / WebView2 / CEF / Chromium / Electron / WKWebView /
  HybridWebView / BlazorWebView, no DOM or JavaScript engine, no localhost/loopback UI, no HTML-as-UI. External
  links open only in the system browser through the single external-URI launcher. HTML is a controlled
  import/export data format, never a renderer.
- **Untrusted content parsing is sandboxed.** HTML / PDF / OOXML / compressed-image parsing of untrusted input
  runs only inside `ArcForges.ContentSandbox`: on-demand, parent-bound, no network, no UI, no persistent state,
  exiting with its parent. It is not a web/Office service.
- **Web is standalone Blazor WASM only.** No React, TypeScript, TypeSpec, Node, or JS package managers; no
  Blazor Server circuit; no agent running in the browser. Minimal audited JS interop only where no managed
  wrapper exists. `RunAOTCompilation=false`.
- **Single agent.** No BackgroundAgents, handoff, Agent Team / Team Mode, or multi-agent / external-agent
  delegation — in the product and in how the code is implemented.
- **Agent authority lives in Cloud.** Durable `Task`/`Run`/`Step`/`Attempt`, the model loop, and the harness run
  in `ArcForges.Cloud.Host` (JIT), using `Microsoft.Agents.AI` + `Microsoft.Extensions.AI` as a thin adapter.
  There is no native `AgentHost`/daemon/service/Worker; authorized stdio MCP servers are on-demand tool child
  processes only.
- **Cloud never touches the local machine directly.** No Cloud connection to localhost / Named Pipe / UDS /
  stdio. Cloud creates a durable `ToolRequest`; ArcChat Desktop pulls, re-authorizes, executes, and idempotently
  returns a `ToolResult`. SignalR is optional wakeup/delta only; native clients may fall back to bounded HTTP
  polling on the same authority surface.
- **Same-machine product↔product IPC is StreamJsonRpc + UTF-8 JSON over Named Pipe/UDS**, first-party only.
  Cloud, browser, and mobile never use it.
- **Wire contracts are JSON with System.Text.Json source generation.** No MessagePack / Fory / binary control
  protocol. C# DTOs and endpoint metadata are the source of truth; OpenAPI 3.1 + JSON Schema 2020-12 are
  generated with a CI compatibility diff. Public HTTP uses Refit generated clients. Large data moves via files /
  chunked upload / object storage / `ResourceRef`, never Base64 in JSON.
- **No CRDT and no multi-user editing.** No Yjs / state vector / awareness / shared cursors / real-time
  co-editing, and no org/team membership, Team Workspace, or invites. `WorkspaceId` is the single-user data,
  device, billing, sync, and permission boundary. Multi-device sync uses stable IDs, explicit revisions,
  ETag/baseRevision, outbox/inbox, change feed, tombstones, and explicit conflict records — never silent
  last-write-wins.
- **No local models.** No Ollama / local Whisper / local embeddings / on-device provider loop. Remote agents use
  Managed AI or Cloud BYOK with KMS/HSM envelope encryption (no "key never leaves the device" claim, no reveal
  API).
- **Persistence is explicit SQL.** SQLite via `Microsoft.Data.Sqlite`, PostgreSQL via `Npgsql`, both with
  hand-written SQL. No SqlSugar / Dapper / EF default stack. Migrations follow Expand/Migrate/Contract; app
  replicas do not run DDL.
- **Native interop goes through owned narrow C ABIs.** Prefer a mature, license-compatible C# binding; a plain
  stable C API may be `[LibraryImport]`ed directly; a C++ library without a mature binding must be wrapped by an
  ArcForges-owned narrow C ABI — never cross a C++ ABI. Media (FFmpeg/miniaudio) lives only behind the owned
  `ArcMediaNative` C ABI; never import `libav*`/miniaudio directly or expose `AV*` types. The six owned shims are
  fixed: `arcmedia-ffmpeg-abi`, `arcslate-otio-abi`, `arcslate-color-abi`, `arcslate-image-abi`,
  `arcscope-mdf-abi`, `arcgraphics-metal-abi`. C# calls them via source-generated `[LibraryImport]` + `SafeHandle`.
- **Native dependencies use the pinned classic vcpkg checkout.** No in-repo vcpkg manifest, custom triplets,
  registry lock, or repository-local installed tree. CMake consumes vcpkg through `VCPKG_ROOT`; `win.slnx`
  consumes a one-time `vcpkg integrate install`. The pinned commit and install specs are documented in
  [deploy/README.md](deploy/README.md).
- **The whole family is AGPL-3.0-only.** Every copied / ported / rewritten / replaced source needs source
  path + commit + license + target + verification oracle + NOTICE entry. Third-party attribution lives in
  [NOTICE.md](NOTICE.md).

## Repository layout

- `src/ArcChat`, `src/ArcNotes`, `src/ArcScope`, `src/ArcSlate` — the four desktop products. Each has
  `Domain` / `Application` / `Infrastructure` / `Presentation`, product-specific libraries, and
  `Tests.Unit` / `Tests.Integration` / `Tests.Ui`.
- `src/Cloud` — `ArcForges.Cloud.Host` plus `ArcForges.Cloud.Modules.*` (Identity, Agent, Sync, Chat, Notes,
  Scope, Slate, Billing, Policy, …), Migrations, Infrastructure, and Realtime.
- `src/Contracts` — `ArcForges.Contracts.*` (Foundation owns stable serialized IDs; LocalRpc, PublicApi,
  Realtime, Agent, Sync, Serialization).
- `src/BuildingBlocks` — shared `ArcForges.*` (Foundation, Persistence.Sqlite/Postgres, Security, Observability,
  Desktop.Experience/Graphics/Preview/RichContent/Text, NativeInterop, Testing).
- `src/DesktopHelpers/ArcForges.ContentSandbox`, `src/Mobile/ArcChat.Mobile*`, `src/Web/ArcForges.Web.*`,
  `src/Extensions`, `src/SDK`.
- `native/` — the six owned C ABI shims, built by both CMake and independent Windows `.vcxproj` projects.
- `contracts/`, `tests/`, `docs/`, `eng/`, `benchmarks/`, `deploy/` — contract goldens, cross-cutting test
  projects, documentation, declarative build inputs, benchmarks, and deployment notes.

## Conventions

- Add `SPDX-License-Identifier: AGPL-3.0-only` to new **source and configuration** files (`.cs`, `.cpp`, `.h`,
  `.props`, `.targets`, `.vcxproj`, `CMakeLists.txt`, …) within the first lines; this is enforced by
  `RepositoryPolicyTests`. Markdown docs (including this file) do not carry an SPDX header.
- All package versions live in `Directory.Packages.props`; never write an inline `PackageReference` version.
  Commit every generated `packages*.lock.json` and restore locked. Preview/prerelease packages are rejected
  (one audited transitive is allowlisted).
- C# style follows `.editorconfig`: file-scoped namespaces (error), 4-space indent, `_camelCase` private fields,
  `nullable` and `ImplicitUsings` enabled, deterministic builds, `AnalysisLevel=latest-all`, and
  warnings-as-errors. Config/markup files use 2-space indent; all text files are UTF-8, LF, final-newline, no
  trailing whitespace.
- Do **not** commit tracked `.ps1`/`.sh` helper scripts — this is enforced. Keep `eng/build` declarative
  (`.props`/`.targets`) and put executable verification in test projects or CI workflows.
- Managed tests run on the Microsoft.Testing.Platform runner (pinned in `global.json`) with xUnit v3 and
  `[Trait("Category", …)]` taxonomy (`Unit`, `Integration`, `Contract`, `Ui`, `Architecture`, `Browser`).
  `ArchitectureTests`/`RepositoryPolicyTests` assert the repository structure and policy; keep them green.
- Native code is strict C++20 (no `c++23`/`c++latest`/`c++2b`) and clang-formatted (`.clang-format`, enforced by
  the pre-commit hook).
- Wire/schema/native-ABI breaking changes require version + compatibility + mixed-version tests. Never put
  secrets, PII, prompts, chat, or tool arguments into logs, fixtures, snapshots, or exceptions.

## Ground rules

- **Work in a Git worktree.** Branch from the current reviewed base and keep one focused branch/PR per change;
  worktrees live under `.worktree/` (gitignored). Preserve existing user changes; never run destructive
  `reset`/`checkout`. Touch only the scope your change owns; record cross-cutting problems instead of expanding
  the diff.
- **Single, serial execution.** The implementation plan is a numbered sequence (00→31) advanced by one main
  context; do not parallelize it across delegated/background agents. Finish and verify a step before the next.
- **Evidence over assertion.** "Builds", "AOT verified", "tests pass", "performance met", and "deployed" are only
  true with the actual command, input, output, and artifact. Planning checkboxes (`[ ]`) are future gates, not
  completed work. If code and plan disagree, stop, record file/commit/impact, fix the documentation, then
  continue.

## Build and verify

Prerequisites: .NET SDK `10.0.400`, CMake 4.3+, a C++20 compiler, the `maui-android` and `wasm-tools` workloads,
and a standard vcpkg installation (see [deploy/README.md](deploy/README.md)).

Managed loop:

```bash
dotnet restore ArcForges.slnx --locked-mode
dotnet format ArcForges.slnx --verify-no-changes --no-restore
dotnet build ArcForges.slnx -c Release --no-restore
dotnet test --solution ArcForges.slnx -c Release --no-build
```

Native (repeat for the `shim-static` profile). Presets are Ninja everywhere and named for the RID, so
configure, build and test share one name. On Windows, initialise MSVC with `vcvars64.bat` first and then
**restore `VCPKG_ROOT`**, which vcvars64 overwrites with the Visual Studio bundled vcpkg:

```bash
cmake --preset win-x64-runtime-shared
cmake --build --preset win-x64-runtime-shared
ctest --preset win-x64-runtime-shared
```

The compiler runs through `sccache` on Windows and Linux; `sccache --show-stats` shows hits and misses.

Repository hooks: `pre-commit run --all-files`. `win.slnx` is built by a Windows-only `pre-push` hook
(`pre-commit run --hook-stage pre-push win-slnx-release-x64`) and never by CI. The PR gate additionally runs
the full managed test taxonomy, the Windows CMake native path, app/browser smoke tests, one Android package,
dependency review, and secret scanning; fill in
[.github/PULL_REQUEST_TEMPLATE.md](.github/PULL_REQUEST_TEMPLATE.md).

## References

- [README.md](README.md) — product family, build, and architecture overview.
- [CONTRIBUTING.md](CONTRIBUTING.md) and [docs/dev-conventions.md](docs/dev-conventions.md) — contribution flow
  and conventions.
- [docs/deviations.md](docs/deviations.md) — accepted departures from the plan and their rationale.
- [deploy/README.md](deploy/README.md) — vcpkg checkout, native install specs, and packaging.
- [docs/](docs/) — scope, coverage, execution ledgers, compliance, and the traceability matrix that reflect the
  numbered implementation plan the frozen invariants above come from.
