# ArcForges.Contributions

PLT.18 provides explicit, per-application registration for statically declared first-party contributions. A registry is bound to one `ApplicationComposition<T>` and the installation identity of that composition. It validates the product-owned contribution namespace and declared tool schemas, stores metadata through an owner-provided durable state port, and creates only strongly typed owner handlers. Registration does not grant invocation permission.

`IContributionRegistrationStore` is the application-owned persistence seam. A production adapter must partition records by the exact product installation and atomically treat an identical record as idempotent while refusing a conflicting record with the same key. The offline tests exercise the seam through the existing PLT.01 `IStore`; SQLite is not a dependency of this package.

This package currently does not admit extension-child contributions. No generated extension-contract package is pinned by DesktopPlatform, and no admitted child-host/grant boundary is connected here. The child-registration entry point therefore refuses explicitly with `ChildUnavailable`; this is not evidence of extension handshake, grant, transport or child invocation behavior. It also does not copy Contracts' `Contribution` wire message into a local DTO. First-party contribution metadata in this package is a local registration descriptor; public/generated wire-contract integration remains deferred to an authorized contract edge.

The package performs no process discovery, reflection, global registration, cross-product lookup or implicit fallback. It does not own product capability schemas or product databases.
