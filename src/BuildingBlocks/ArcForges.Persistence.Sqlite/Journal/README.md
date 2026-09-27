# Transactional journal

`SqliteJournal` is an internal participant in the store's commit unit. It never
opens a connection or commits a transaction. The store owns durable SQLite
configuration, commit/flush, command receipts, body/origin, revisions and outbox,
and acknowledges only after that transaction commits. A journal exception must
abort the owner's commit unit.

The journal owns its two tables and aggregate replay index. Its store-bound
sequence is separate from transport delivery positions and per-aggregate local
edit positions. The durable high watermark survives prefix truncation. Entries
include aggregate identity, typed previous/next versions, command identity and
operation version, one payload or durable reference, actor, correlation,
causation and nanosecond commit time. SHA256 covers a versioned, length-prefixed
binary encoding of the complete record. Input and returned byte arrays are
defensively copied. The owning store admits durable references atomically with
the referenced data; a reference is never a license to acknowledge staged bytes.

Reads use the owner's pinned read transaction. Paging refuses foreign-store
cursors, missing sequences, a missing committed tail, malformed typed values and
checksum changes. After truncation the caller must explicitly supply a verified
snapshot position; a missing cursor never silently skips the removed prefix.

The snapshot policy signals pressure by entry count, encoded size or elapsed
time. Count and size caps refuse additional appends with `JournalCapacityException`
before changing the log, allowing the owner to map its registered storage-pressure
outcome. Truncation requires an independently verified snapshot binding to the
exact store, sequence and entry checksum. With no snapshot verifier it refuses.
The snapshot producer and corruption-recovery workflow belong to PLT.03. Tests
name their snapshot-verifier fixture and do not claim that a real snapshot exists.
The owner's SQLite read transaction preserves an existing reader while a writer
prepares prefix deletion; deletion and the retained snapshot watermark commit
together. No journal method independently enables WAL or relaxes durability.

Targeted tests use isolated local SQLite files and in-process interruption before
and after commit. They cover atomic body/journal recovery, complete replay,
defensive ownership, corruption refusal, concurrent read/truncate, watermark
preservation, snapshot refusal and bounded capacity. They do not simulate a real
OS crash, power loss, network volume, removable device or installed product.
