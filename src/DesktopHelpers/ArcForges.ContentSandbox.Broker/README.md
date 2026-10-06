# ArcForges.ContentSandbox.Broker

The parent side of the content helper (WP-11.09, PLT.45): restricted launch, the closed resource inventory, registration, the session, brokered
buffers and supervision. PLT.59 admits this implemented managed package to normal
lockstep publication. Native/helper runtime and release trust remain separate
producers; PLT.46 retains complete product and OS acceptance.

```csharp
await using var launcher = new ContentSandboxLauncher(new ContentSandboxLaunchOptions
{
    HelperPath = installedHelper,        // the signed helper of this installation
    HelperSha256 = pinnedDigest,         // from the installed signed inventory
    ParserProfile = "…",                 // chosen by the helper build, never a path
    RuntimeRoot = ownerOnlyDirectory,
});
var launched = await launcher.LaunchAsync(inputBytes);   // typed failure when no restricted profile can run
await using var invocation = launched.Value!;
var image = await invocation.OpenImageAsync(0, 0, 1);
using var tile = (await invocation.ReadImageTileAsync(image.Value, 0, 0, 256, 256)).Value!;   // bytes verified on a private copy
```

- **No fallback.** A platform without a verified profile (macOS here, an unknown OS, a failed AppContainer or self-check) fails with
  `security.isolation_unavailable`, starts nothing, and never parses in process.
- **Windows (`Windows/`).** The helper is opened with writers refused and its SHA-256 compared with the pin; an AppContainer identity is leased from
  a pool of eight (a lock file per identity, released by the OS if the owner ends); the process is created suspended with a handle list naming
  exactly its closed inventory (two private pipes whose child ends are opened overlapped and never bound to a completion port here, a read-only
  duplicate of the input section, up to three output sections, standard input for the launch frame and standard output for diagnostics), a minimal
  environment and mitigation policies; its token is read back and must be that AppContainer with no capability before the thread resumes; a
  non-breakaway Job Object (kill on close, one process, a memory limit, no user-interface access) is attached first. Parent death closes the job and ends the helper. Renaming or deleting the helper file is refused while its handle is held. Every leased identity is now deleted and recreated fresh, with complete package-storage removal verified before reuse. Canonical per-user/profile locks remain authoritative across caller directories. The component and actual Windows hostile-fixture privacy checks cover this storage boundary; full parser/product acceptance remains separately owned.
- **Linux (`Linux/`).** Descriptors are created close-on-exec and placed at fixed numbers by a spawn plan; the helper restricts itself. Output slots are memfds sealed against shrinking and growing (a hostile helper cannot truncate one under the parent's copy); every parent descriptor above the inventory is closed by the plan. The helper file is hashed through a handle that blocks writers, but on Linux a rename in the install directory is not blocked: the install directory must be unwritable for the user. Not run on Linux.
- **Supervision.** One generated call at a time; a transport failure, a deadline or a misbehaving result ends the invocation and returns
  `resource.parser_failed` or `resource.integrity_failed`. Cancellation uses the reserved control slot; the session lease is renewed every 10 s.
- **Native bindings** (`Native/`): the exact libc and Windows calls above, each unique in the repository and listed in the closed native-binding map of the architecture tests.

## Isolation and lifetime repair (PLT.60)

Every Windows helper holds one of eight AppContainer identities through a canonical per-user/profile lock, independent of caller lock-directory overrides. A caller-specific lock is additional coordination only. Profiles are removed before creation and after confirmed child termination; the actual SID-owned storage path must disappear. A successful Userenv deletion alone is insufficient, and remaining storage refuses reuse. The implementation never recursively deletes a computed profile path.

Teardown has one shared completion for concurrent disposals. It terminates and closes the kill-on-close Job Object, attempts every stream/mapping cleanup despite diagnostic failure, and waits on the retained kernel process handle. An unconfirmed exit returns a bounded failure and quarantines that identity with an owned continuation until actual exit; it never releases a live helper's slot. Diagnostics cannot skip the remaining cleanup. Component fault injections do not certify OS containment.

The Linux seccomp program now allows tgkill only when both words of the first argument equal the helper's own positive PID with a zero high word. Runtime thread suspension remains possible. The BPF interpreter covers foreign/zero/high-word PIDs on x64 and arm64; this is filter logic evidence, not an observed Linux kernel enforcement run. Existing architecture, x32, clone and denied-call rules remain in force.

The canonical slot lock also stores a bounded canonical lifetime record. Pending state is flushed before process creation, Job assignment is atomic through JOB_LIST, and actual PID/creation time plus verified AppContainer SID are flushed before the suspended child resumes. Recovery checks the original actual process instance and token; prior-live, pending, malformed or unverifiable records quarantine that slot without killing a previous PID. Reopening a named Job as empty cannot prove an original child exited. An unknown pending crash cut remains quarantined until an authorized operator can establish absence; this is an explicit fail-closed availability limit of the bounded pool. Existing all-platform/product acceptance remains separate.
