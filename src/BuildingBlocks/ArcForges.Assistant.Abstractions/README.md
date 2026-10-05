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

`AssistantLifecycle` is the reusable product-host lifecycle for one composition: it is the `IHostLifecycle` the host
supplies in `AssistantHostServices`, launches the one session (`LaunchAsync`) and separates three lifetimes. Views
(`OpenView`, one per window) own a draft and a view-scoped cancellation token; closing one saves its draft and cancels
only its own scope, leaving the session, other views, local work and Cloud work alone. The session and services live for
the application and are released once, last, by `DisposeAsync`. Canonical data is never touched here. Launch and save never
consult Cloud (an optional `IAssistantRemoteLink` is read for information only and a throwing link counts as
unavailable). Drafts are made durable through the host's `IAssistantDraftStore` port (revisioned, atomic, one profile
partition); after a crash every durable draft is returned by the next launch at its last durable revision and each can be
resumed by exactly one view. Shutdown saves unsaved drafts and asks local work to checkpoint; whatever cannot be made
durable is a stated refusal, Cloud-only work never blocks quitting and is never cancelled here. The package defines no
store: the draft store, the Cloud link and the canonical data are supplied by the host.

This package defines contracts and composition boundaries only. It does not implement assistant UI,
persistence, Cloud behavior, cross-product discovery or WP15/WP17 services. Its tests use a clearly test-only
host double to exercise the port signatures; no real product host is composed here (APP.08 owns the minimal real
sample). The only direct package dependencies are `ArcForges.Foundation` and
`ArcForges.Application.Abstractions`; `ArcForges.Capabilities` is a design precedent, not a dependency.
