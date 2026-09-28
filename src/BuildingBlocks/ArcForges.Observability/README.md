# ArcForges.Observability

This non-packable DesktopPlatform library is the shared emission surface for metrics, traces, and
typed structured events. Install an `ObservabilityContext` with `ObservabilityScope.Push` around an
operation, then emit events with `SignalEmitter`. The context always requires the application ID,
FND instance ID, build-policy build ID, and environment. Optional dimensions are attached only when
provided; `FromApplicationAssembly` reads the actual `ArcForges.BuildId` assembly stamp and refuses
unstamped assemblies.

Each emission creates an OpenTelemetry-compatible `ActivitySource` span when a listener is present,
increments a `Meter` counter, records duration when available, and writes one typed `StructuredSignal`
through a host-provided sink. The same dimensions go to
traces and structured events. Metric labels are deliberately restricted to application, build,
environment, and service identity: actor, workspace, command, run, attempt, resource, and correlation
identifiers remain trace/log dimensions so they do not create high-cardinality metric series.

Resource references passed through this surface must already be redacted. Event fields are typed
scalars, not preformatted sentences; fields that describe secret material, credentials, tokens, raw
content, or request payloads are rejected. Hosts own export configuration and data retention.

This project is not currently an admitted package. See the [repository README](../../../README.md)
for ownership and publication policy.
