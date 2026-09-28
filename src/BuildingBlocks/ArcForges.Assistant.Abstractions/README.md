# ArcForges.Assistant.Abstractions

Storage-free typed host ports and explicit identity-scoped assistant composition for the desktop products.

`AssistantHost.Create` accepts immutable options plus an explicit service bundle. Product IDs are a closed set (`arcscope`, `companion`); installations, process instances and profile store partitions are separate typed identities. The installation data root is derived beneath the platform-owned base root and the product ID, and callers cannot select a sibling product's directory. One service bundle creates one assistant session; windows within that application reuse it.

The context, action, resource, navigation, lifecycle and platform-service ports are supplied by the owning product. Each port is bound to one live application identity. Store scopes are bound to one product/installation/profile partition. Action registration uses a bounded runtime-only descriptor projection and a specific generic request/result delegate, with a per-composition operation/capability allowlist; the owning product binds it to its generated, admitted descriptor. This projection is not a wire model. Registrations cannot be reflected into a universal invocation surface or used through a different registry.

Resource references retain the generated Foundation `ResourceVersionRef`; this package adds no wire schema and does not expose file paths, bytes, database handles, tokens or unmanaged pointers to UI code. Resource owners continue to recheck authority for reads, previews and exports. Context snapshots are immutable and bounded by the shared 64 MiB ceiling. No whole-document upload is implicit.

This package defines contracts and composition boundaries only. It does not implement assistant UI, persistence, Cloud behavior, cross-product discovery or WP15/WP17 services. The only direct package dependencies are `ArcForges.Foundation` and `ArcForges.Application.Abstractions`; `ArcForges.Capabilities` is a design precedent, not a dependency.
