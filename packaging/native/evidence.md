<!-- SPDX-License-Identifier: AGPL-3.0-only -->
# Native package evidence

Generate the aggregate SPDX document in the prepared package stage before computing the stage digests and signing.

```text
python packaging/native/sbom.py --stage <stage> --rid <win-x64|linux-x64>
```

The inventory uses the published native executables, their restored application lock graphs for the chosen RID, and the exact SDK Native AOT runtime pack present in the restored package cache. It distinguishes runtime graph inputs from build dependencies. The graphs cannot identify individual managed symbols retained by Native AOT. Staged NuGet license expressions are reported as declarations. Unattributed components retain `NOASSERTION`.

The staged official MXC document remains byte-identical to its pinned SPDX release. The aggregate references that document and identifies the selected native files, their hashes and the pinned manifest. The upstream document describes the complete upstream x64 release. The aggregate lists only the per-RID native members shipped in the stage.

## Native performance capture

Run this on the actual native release venue. Use the authenticated extraction of the exact signed archive and the independently published native Bench and TestLoad executables. Keep the installer's authentication receipt next to the performance report to retain the archive and signing identity. On Windows, use a new extraction directly under the installing user's local temporary directory so the native trust checks can verify the installation path. The fixture launches a distinct offline Node under its own temporary data root and endpoint. On Linux the socket is in an independent private temporary directory, and the real systemd user manager keeps its existing runtime directory.

```text
python packaging/native/measure.py --install <verified-install> --bench <native-arcforges-bench> --testload <native-arcforges-testload> --output <new-report.json>
```

The report binds the measured binaries to their SHA-256 digests and records the first CLI process observation and repeated samples, Node readiness, Node and Run supervisor idle counters, terminal output bytes and gaps, a separately executed TestLoad reference, and observed Stop to verified empty. The first CLI run does not imply an empty OS cache. Terminal throughput is a measured end-to-end window. The report identifies Linux per-process private commit and any paired resource overhead, stalled-consumer or sampler cadence observations that are unavailable. This command sets no new performance gate. A failure keeps the synthetic fixture for diagnosis and requests a graceful stop at its own endpoint.
