# ArcForges.Persistence.Resources

A domain-free, single-writer append store for raw capture bytes. It owns no
relational tables, product schema, decoder, acquisition scheduler or device.
This project is nonpackable; PLT.08 owns package/integration acceptance.

`AppendStore.Create` creates new evidence exclusively. `AppendChunk`,
`MapSegment` and `RecordGap` append and flush to stable storage before returning.
A failed write faults that writer permanently. `Seal` appends the explicit end
marker and forbids subsequent writes. Existing captures cannot be reopened for
writing through this API. Atomic create-new exclusion applies on every platform.
Windows additionally enforces deny-write file sharing; Unix callers must protect
capture paths against unrelated filesystem writers. Checksums detect changed
frames but do not make the file an access-control boundary.

`ManagedResourceStore` keeps immutable content-addressed objects under SHA-256
locations, with opaque `BlobId` mappings and a durable referrer table. The
reference count is derived from that table. It flushes object bytes before
publishing the identity mapping, and publishes references only after the mapping
is durable. Reads return bytes only after checking the mapped length and full
digest. Collection removes unreferenced identity mappings before sweeping
unreachable object files, so an interrupted collection can leave reclaimable
orphans but cannot delete a still-referenced object. A store root has one
process owner at a time; reads within that owner may run concurrently.

Every frame has a 64-byte little-endian header: `AFAPPEND`, version 1, kind,
reserved zero bytes, monotonically increasing sequence, bounded payload length,
and SHA-256 over its 32 metadata bytes and payload. Payloads are at most 4 MiB;
a capture has at most one million frames including its seal. Segment manifests
map independent nonempty GUID identities to up to 1024 ordered physical chunk
slices. Range reads return at most 4 MiB and verify each touched chunk in full.
Timestamps in gap records use the caller's monotonic acquisition units; overflow,
drop and back-pressure causes and intervals are explicit. Decoder output belongs
in a derived store, never this raw capture store.

`CaptureSnapshot.Open` scans without modifying capture bytes. Missing seals,
truncation, damaged checksums, trailing data or invalid manifests produce a
verified prefix and `CaptureLoss`, with unknown effect/count/time kept unknown.
The separately checksummed `.loss` receipt binds the full capture digest, length,
verified boundary and cause. It is flushed to a unique pending file and moved
without overwrite; interrupted pending receipts remain evidence. A conflicting
or damaged final receipt is refused. Recovery never silently resumes or reseals
the capture. The SHA-256 checksums detect corruption, not malicious authenticity.

Offline tests cover every byte truncation (including 231 distinct persisted-loss recoveries), checksum/header/bound violations,
segment mappings, bounded range reads, explicit gaps, writer exclusion and
receipt integrity. Explicit local diagnostics additionally kill an actual
`AppendStore` child after a committed segment and during the next chunk's payload
write. Enable `ARCFORGES_APPEND_KILL_DIAGNOSTICS=1` only for that local run; these
two process diagnostics are skipped in hosted/default tests. The test-only
intercepted FileStream creates a deterministic midwrite boundary, while the
production append/flush path writes all acknowledged preceding frames.

Observed local .NET SDK 10.0.401 compatibility build: zero warnings/errors; all
13 tests passed including both real writer process interruptions. The expanded default
suite then passed 12 tests with both local process diagnostics explicitly skipped. The committed
SDK 10.0.400 and retained CI remain authoritative. No native/device, installed
consumer or power-loss hardware guarantee is claimed.
