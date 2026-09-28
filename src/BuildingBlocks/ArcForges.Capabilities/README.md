# Application identity and composition

PLT.17 implements the in-process identity boundary from WP09.00. `AppIdentity` has the closed product values `arcscope` and `companion`; Companion remains one identity across Android and Web. `InstallationIdentity` combines product, device and the published strong installation ID. `InstanceIdentity` adds the published strong instance ID and an explicitly supplied delivery epoch (the full uint64 range, including zero).

Each `ApplicationComposition.Start<TOwner>` creates a fresh instance and calls the owning application's explicit typed factory. The host supplies independently scoped sessions, history and capability state inside that owner. Typed handler registrations belong to one composition and cannot be dispatched through another. Missing targets fail validation, foreign product/device/installation or handler bindings fail authorization, and old instance/epoch or stopped compositions fail as gone before entering the handler. All refusals use existing Foundation error metadata with no effects and no automatic retry.

| Lifecycle | Installation | Instance and epoch | Result |
|---|---|---|---|
| Two products on one device | Separate product/install scope | Independent composition | No shared registry or fallback |
| Companion on different platforms | Same product, distinct installation | Independent composition | Platform never becomes ProductId |
| Concurrent instances | May retain one installation | Different InstanceId | Targets stay with the chosen instance |
| Restart | Retained by host | Fresh InstanceId and newly registered epoch | Old captured targets refuse |
| Stop | Remains intact | Future admission fenced | Already admitted effects are not called undone |
| Reinstall | New InstallationId | New instance | Prior installation targets refuse |

This trusted in-process composition mechanism is not a security sandbox for arbitrary host code. The host must not deliberately share stores between owner factories. Authentication, current grants, durable epoch allocation, concrete product stores, named contribution validation, remote wire target adaptation and device registration remain their respective owners' work. Public protobuf remains owned by Contracts; `ToApplicationScope` returns a fresh generated Foundation value. No transport, process enumeration, static mutable product registry, shared desktop service or launch behavior is added.

The nested offline tests demonstrate isolation with typed fixture owners. They do not claim Android/Web execution, product persistence, live device registration or installed-consumer evidence.

## Typed context contributions and invocation snapshots

`ContextProvider<TMessage>` is scoped to one captured `InstanceIdentity` and accepts generated protobuf message types supplied by its caller. Snapshot freezing records each message's exact descriptor and private serialized bytes; consumer reads deserialize a new copy, so neither later live-context changes nor mutations of a returned object can alter an in-flight snapshot. Provider ownership mismatches fail before provider code runs.

The default budget is 50 messages and 65,536 serialized protobuf bytes. Explicit budgets may narrow those limits but cannot exceed the current 200-message/262,144-byte context ceilings. Exceeding either bound raises a typed refusal; no entries are truncated. This is a generic in-process seam, not a copied context wire DTO and not a claim of integration with `ArcForges.Contracts.PublicApi` records.

## Resource and artifact access

`ResourceResolutionRegistry<TAccess>` is created for one `AppIdentity` inside
that application's composition and accepts the published Foundation references.
It keeps only explicit resource-kind registrations for that owner, so it cannot
become a cross-product routing catalog. `ResourceRef` follows the
floating path and asks its owner for the current version; `ResourceVersionRef`
follows a separate pinned path and must carry a valid cloud or native revision.
The two paths never fall back to each other. Each access receives an owned
contract copy, invokes the owner's current permission check, and only then calls
that same owner's resolver. A denied check returns `perm.resource_denied` before
content resolution; an owner/kind with no admitted handler returns
`resource.unavailable`. The display-only hint is stripped before either owner
callback, so it cannot become an alternate resolution key.

`ArtifactHandlerRegistry<TAccess>` is likewise bound to one application and
accepts only explicit registrations keyed by that owner's artifact kind. A
compatible explicit preference wins;
otherwise handlers sort by descending priority and ordinal ID. Permission is
re-checked for each action, and denial never falls through to another handler.
The catalog does not discover or launch products. Supported actions are the
closed `Open`, `Preview`, `Import`, `Convert`, and `Edit` values.

| Resolution case | Expected boundary | Offline evidence |
|---|---|---|
| Registered owner and kind | Permission is checked before the owner resolves | `FloatingResolutionUsesTheRegisteredOwnerAndRechecksPermissionOnEveryAccess` |
| Owner or kind absent | Refuses as `resource.unavailable`; no discovery or fallback | `MissingOwnerRegistrationAndMissingKindReturnUnavailableWithoutDiscovery` |
| Owner denies access | Refuses as `perm.resource_denied` before resolution | `PermissionDenialNeverFallsThroughToResourceResolution` |
| Pinned version | Authorizes and resolves only the explicit cloud/native revision | `PinnedResolutionPreservesTheExactRevisionAndNeverFallsBackToFloating` |
| Physical location prohibition | Published references have no path, pointer, access handle, credential or raw content-payload fields | `PublishedReferencesHaveNoPhysicalLocationOrAccessHandleFields` |

Artifact tests additionally prove per-kind registration, deterministic handler
selection, per-action permission re-checking, and that a denial cannot fall
through to a lower-priority handler.
