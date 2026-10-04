# ArcForges.Assistant.Abstractions

Storage-free typed host ports and explicit identity-scoped assistant composition for the desktop products.

`AssistantHost.Create` accepts immutable options plus an explicit service bundle and returns the one
`IAssistantSession` of that composition. Product IDs are a closed set (`arcscope`, `companion`); installations,
process instances (with an epoch) and profile store partitions are separate typed identities. The installation
directory is derived beneath an absolute, platform-owned root from the product ID and installation ID, and a
profile directory is resolved only for a partition of that same installation, so a caller cannot select a sibling
product's, installation's or profile's directory.

The context, action, resource, navigation, lifecycle and platform-service ports are supplied by the owning
product. `AssistantHostServices` refuses any port, sub-port, session factory or store scope that belongs to a
different product, installation, instance or epoch; `Create` refuses services built for another identity or
profile partition, refuses a session whose identity, options, services or profile differ from the composition,
and creates exactly one session per service bundle (windows of one application reuse it; disposal does not allow
a second session). A failed creation is not committed and can be retried; a successful one seals action
registration.

Action registration uses a bounded runtime-only descriptor projection and a specific generic request/result
delegate, with a per-composition operation and capability allowlist; the owning product binds it to its
generated, admitted descriptor. The projection is not a wire model. A registration token is honoured only by the
registry that issued it and only for its own host identity, an unavailable action is refused with a visible
reason before its handler runs, and cancellation before the handler is reported as cancelled with no effect.
Registrations cannot be reflected into a universal invocation surface.

Resource references retain the generated Foundation `ResourceVersionRef`; construction validates a supported
product owner, an owner-namespaced kind, a typed revision and a SHA-256 content hash, and copies on entry and
exit. This package adds no wire schema and does not expose file paths, bytes, database handles, tokens or
unmanaged pointers to UI code. Resource owners continue to recheck authority for reads, previews and exports.
A frozen context can only be built within an item and byte budget (bounded by the shared 64 MiB ceiling, with
overflow-safe accounting), only from the owning product's resources and never changes afterwards. No
whole-document upload is implicit.

This package defines contracts and composition boundaries only. It does not implement assistant UI,
persistence, Cloud behavior, cross-product discovery or WP15/WP17 services. Its tests use a clearly test-only
host double to exercise the port signatures; no real product host is composed here (APP.08 owns the minimal real
sample). The only direct package dependencies are `ArcForges.Foundation` and
`ArcForges.Application.Abstractions`; `ArcForges.Capabilities` is a design precedent, not a dependency.
