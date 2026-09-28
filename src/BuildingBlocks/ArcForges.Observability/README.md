# ArcForges.Observability

This non-packable DesktopPlatform library is the shared emission surface for metrics, traces, and
typed structured events. Install an `ObservabilityContext` with `ObservabilityScope.Push` around an
operation, then emit events with `SignalEmitter`. The context always requires the application ID,
FND instance ID, build-policy build ID, and environment. Optional dimensions are attached only when
provided; `FromApplicationAssembly` reads the actual `ArcForges.BuildId` assembly stamp and refuses
unstamped assemblies.

Each emission creates an OpenTelemetry-compatible `ActivitySource` span when a listener is present,
increments a `Meter` counter, records duration when available, and writes one typed `StructuredSignal`
through a host-provided sink. The same dimensions go to traces and structured events. Each emitter is
bound on first use to one application/build/instance/environment identity; those required identities
are attached to its Meter instrumentation scope, not to measurement point labels. Point labels contain
only the optional bounded service name. Actor, workspace, command, run, attempt, resource, and
correlation identifiers remain trace/log dimensions so they do not create high-cardinality metric series.

The emitter has no caller-supplied event-property bag: it accepts only the closed ambient dimension
schema, so adding an event cannot smuggle arbitrary prompt, path, request, or secret text into logs or
trace tags. String dimensions are bounded identifier tokens; actor and resource references must be
lowercase SHA-256 references, never raw identifiers. Hosts own export configuration and data retention.

This project is not currently an admitted package. See the [repository README](../../../README.md)
for ownership and publication policy.
