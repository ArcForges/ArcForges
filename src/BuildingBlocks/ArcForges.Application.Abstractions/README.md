# ArcForges.Application.Abstractions

Storage-free per-application execution and lifecycle ports. `IExecutionContext`
provides immutable command/attempt identity, the explicit clock and cancellation.
`IApplicationLifecycle` exposes shutdown and typed stop results. Cancellation is
distinct from failure and never implies that a dispatched mutation had no effect.

Applications supply these ports in their own composition roots; this package owns
no database, session, global application registry or durable receipt adapter.
Durable single-effect evidence belongs to PLT.01 and later owner integration.
