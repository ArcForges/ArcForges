# ArcForges.Persistence.Resources

The large append store is a domain-free, single-writer mechanism for raw capture
bytes. It is independent of the SQLite working store. Product schemas, device
decoders, acquisition scheduling and canonical transaction ownership stay with
their owners.

PLT.06 implementation plan:

1. Add a bounded, versioned binary append format with checksum-protected frame
   metadata and payloads, monotonically numbered frames and an explicit seal.
   Flush each accepted frame to stable storage before acknowledging it.
2. Keep domain segment identifiers separate from physical chunk identifiers.
   Persist segment-to-chunk slice manifests and explicit overflow/drop/pressure
   gap records. Reads verify complete touched chunks while returning only the
   requested bounded range.
3. Recover the verified prefix without modifying damaged capture evidence.
   Persist a separately checksummed recovery-loss record. A missing seal is
   never a successful complete capture; unknown lost counts/time bounds remain
   unknown. Recovered captures are read-only and require a new stream to resume.
4. Exercise truncation at every frame byte and committed boundary, checksum and
   header damage, malformed bounds, explicit gaps, sealing, concurrent writers,
   segment manifests and bounded reads using isolated offline file fixtures.
5. Admit only this implemented managed package, reuse the delivered Foundation
   primitives and existing test toolchain, and bind source/dependency/provenance
   inventories. Retain all existing CI and obtain independent exact-head review.

The planned format is a local persistence implementation, not a wire contract,
portable archive, domain schema or cryptographic authenticity proof. Native
device/process tests and installed-consumer acceptance are separate tasks.
