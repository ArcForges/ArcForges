# ArcForges.ContentSandbox

The first-party Native AOT content helper host (WP-11.09, PLT.45). A product never parses hostile PDF or image bytes in its own process:
it launches this helper in a restricted operating-system profile through `ArcForges.ContentSandbox.Broker` and talks to it over the
generated `ContentSandboxService` contract. This project is non-packable; package admission is PLT.46.

## What it is

- **Entry (`Host/HelperEntry`).** Reads one launch frame from its inherited standard input (never argv, environment or a file), wraps exactly
  the resources the frame lists, brings the operating-system profile into force, verifies it by attempting what it must deny, and only then runs
  the host. A malformed frame (exit 64), an inventory that is not the closed set (65) or a profile that cannot be enforced and verified (70)
  ends the process before any parser exists. A helper never falls back to full trust.
- **Host (`Host/ContentSandboxHost`).** Serves the sandbox contract to the parent on the supplied service stream and proves the one-use launch
  secret to the parent on the supplied control stream (the generated LocalBootstrap challenge, confirm and renew from `ArcForges.LocalRpc`),
  keeps its registration lease, and leaves the process when the parent is lost, the session lease passes or the session is closed. Renewal and
  cancellation are declared reserved control methods, so they pass a full data lane. It listens on no network endpoint.
- **Service (`Host/ContentSandboxServiceImpl`).** Holds exactly one invocation-scoped session whose identity, input and budget the launch fixed.
  It chooses parsers only from the composition named by the launch (the production helper composes `ProductionParserProfile`: the PDF parser over the native `arc_pdf_*` library; no image parser is composed yet), fills only the slot grants the parent made, seals exactly the bytes written, and checks every
  result with the same shape rules the parent applies again. A parser that fails, overruns its deadline or is cancelled ends the invocation.
- **Profiles.** Windows: the parent creates the process in an AppContainer and Job Object; the helper checks it cannot reach the parent process
  or the user profile. Linux (`Native/LinuxEnforcement`): the helper applies no_new_privs, resource limits, Landlock and a seccomp
  filter to itself and checks them. Seccomp is synchronised to every thread (TSYNC). Landlock restricts only the calling thread unless its own
  TSYNC flag is given, so the helper passes that flag, refuses to run if the kernel rejects it (a kernel without multithread Landlock, which
  is recent), and its self-check observes the denial from the applying thread, from several thread-pool threads and from a new thread. Parent loss is detected by the helper polling its parent id (no parent-death signal: the kernel ties it to the spawning thread, which may retire while the parent lives) and the supervising parent kills the helper on every path. A wedged helper whose parent was killed is not ended by the kernel. No offline test observes the Landlock TSYNC flag or the shrink seal (a mutant that drops either survives offline); both need a Linux kernel. Not covered on Linux: tgkill to another same-user process (the runtime needs it), no PID/user/mount namespaces, and
  the profile has never run on a Linux kernel here. macOS: no launcher exists; `macos/ArcForges.ContentSandbox.entitlements` is the declarative input of the
  profile that a signed sandboxed bundle and an XPC descriptor handoff would need, and a launch there is refused.
- **Fixture (`Fixture/`).** TEST ONLY: the same host with one deliberately hostile first-party test composition (the registered
  `SUB-hostile-test-parser`). It parses no real format. Its script attacks the boundary (reads a product file, connects to a real listener,
  sends datagrams, opens other processes, spawns, maps the read-only input writable) or crashes, hangs, exhausts memory or overruns its
  output. It is never packaged or composed into a release.

## Tests

`Tests/` (`ArcForges.ContentSandbox.Tests`) runs offline in CI: the launch frame, the record mapping, the budget, paging of PDF text, the parent
and the real helper host end to end over in-memory streams (grant, seal, private copy and digest on the copy, acknowledgement, cancellation through
the control slot while the data lane is full, deadlines), a helper that lies, the pure parts of the Linux profile (a classic-BPF interpreter runs
the seccomp program), and the macOS refusal. **The in-process helper is not operating-system containment.**

The OS checks are explicit local opt-in, skipped by default and in hosted CI. On Windows, once:

```powershell
dotnet publish src/DesktopHelpers/ArcForges.ContentSandbox/Fixture/ArcForges.ContentSandbox.HostileFixture.csproj -c Release -r win-x64
$env:ARCFORGES_CONTENTSANDBOX_OS = '1'
$env:ARCFORGES_CONTENTSANDBOX_FIXTURE = '<the publish directory>'
dotnet test --project src/DesktopHelpers/ArcForges.ContentSandbox/Tests/ArcForges.ContentSandbox.Tests.csproj -c Release
```

Publishing needs the Visual Studio C++ tools on the path of the shell; on a machine where `findvcvarsall.bat` cannot find `vswhere.exe`, put
`%ProgramFiles(x86)%\Microsoft Visual Studio\Installer` on `PATH` for that shell. The results are evidence for that machine, that Windows build and that fixture only.

## What is not proven

See the Plan ledger record of PLT.45. In short: the Linux profile and launcher are compiled in hosted CI and unit-tested only; they have not been run
on Linux. macOS has no launcher. Windows signature (Authenticode) verification of the helper is not implemented: the launcher pins the
SHA-256 of the installed helper from the signed inventory.

## Production composition (NAT.14)

`ProductionParserProfile` (`arcforges-parsers-v1`) is the one composition the production helper contains. Its PDF parser
(`Host/NativePdfParser`) adapts the sandbox parser interface to the native `arc_pdf_*` library through `ArcForges.Native.Pdf`:
it passes the launch budget on, assembles page text from bounded native chunks, validates every geometry, box and size it takes
from the native side, and turns every native or loader failure into one parser failure. `Prepare` runs before the operating-system
profile is applied (a restricted process cannot load a library afterwards) and ends the helper when the library cannot be loaded or
has no PDF backend linked (`backend=none`); the helper exits with the internal-failure code and writes one diagnostic line. The hostile
test composition is never registered in production; the fixture stays a test-only regression executable.

**What is not proven.** `native/arcpdf-abi` links no PDF parser yet, so a production helper built from this tree refuses every PDF
(the library reports `backend=none`). No real PDF was parsed, no operating-system isolation check was re-run against a real parser,
the ACL a Windows AppContainer needs on the directory that holds the native libraries is unobserved, and Linux and macOS have no
native library path (`NativeLoader` is win-x64 only). The offline tests drive the adapter with a scripted native document and the
engine with a scripted backend; they prove the containment and limit code, not PDFium. Real-parser composition and acceptance are
tracked as NAT.15.
