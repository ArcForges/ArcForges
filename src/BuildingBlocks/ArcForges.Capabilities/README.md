# Application identity and composition

PLT.17 implements the in-process identity boundary from WP09.00. `AppIdentity` has the closed product values `arcscope` and `companion`; Companion remains one identity across Android and Web. `InstallationIdentity` combines product, device and the published strong installation ID. `InstanceIdentity` adds the published strong instance ID and an explicitly supplied delivery epoch (the full uint64 range, including zero).

Each `ApplicationComposition<TOwner>.Start` creates a fresh instance and calls the owning application's explicit typed factory. The host supplies independently scoped sessions, history and capability state inside that owner. Typed handler registrations belong to one composition and cannot be dispatched through another. Missing targets fail validation, foreign product/device/installation or handler bindings fail authorization, and old instance/epoch or stopped compositions fail as gone before entering the handler. All refusals use existing Foundation error metadata with no effects and no automatic retry.

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
