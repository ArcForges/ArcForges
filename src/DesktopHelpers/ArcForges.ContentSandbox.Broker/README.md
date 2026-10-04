# ArcForges.ContentSandbox.Broker

The parent side of the content helper (WP-11.09, PLT.45): restricted launch, the closed resource inventory, registration, the session, brokered
buffers and supervision. Non-packable until PLT.46.

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
  non-breakaway Job Object (kill on close, one process, a memory limit, no user-interface access) is attached first. Parent death closes the job and ends the helper. Renaming or deleting the helper file is refused while its handle is held. Not proven: the pooled AppContainer identities are reused one after another and keep their per-container storage between invocations, so data a hostile parser leaves there could be seen by a later invocation on the same identity; no test covers it and nothing cleans the container on release.
- **Linux (`Linux/`).** Descriptors are created close-on-exec and placed at fixed numbers by a spawn plan; the helper restricts itself. Output slots are memfds sealed against shrinking and growing (a hostile helper cannot truncate one under the parent's copy); every parent descriptor above the inventory is closed by the plan. The helper file is hashed through a handle that blocks writers, but on Linux a rename in the install directory is not blocked: the install directory must be unwritable for the user. Not run on Linux.
- **Supervision.** One generated call at a time; a transport failure, a deadline or a misbehaving result ends the invocation and returns
  `resource.parser_failed` or `resource.integrity_failed`. Cancellation uses the reserved control slot; the session lease is renewed every 10 s.
- **Native bindings** (`Native/`): the exact libc and Windows calls above, each unique in the repository and listed in the closed native-binding map of the architecture tests.
