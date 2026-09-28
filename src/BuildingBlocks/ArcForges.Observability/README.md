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
are attached to its Meter instrumentation scope, not to measurement point labels. Measurement points have
no labels. Actor, workspace, command, run, attempt, resource, and correlation identifiers remain trace/log
dimensions so they do not create high-cardinality metric series.

The emitter has no caller-supplied event-property bag or free-form event-name overload: event names and
operational dimensions use finite enums, and reason codes use the product's registered `ReasonCode` values.
`SignalApplicationDimension` is only a telemetry vocabulary, not the product identity authority; application
composition maps its already-trusted product identity to one of the closed values. Build identity is read from
the actual assembly stamp and checked against the build-policy format. Actor and resource references must be
fixed-size lowercase SHA-256 references, never raw identifiers; invalid or secret/path-shaped values are
refused before emission. Hosts own export configuration and data retention.

This project is not currently an admitted package. See the [repository README](../../../README.md)
for ownership and publication policy.
