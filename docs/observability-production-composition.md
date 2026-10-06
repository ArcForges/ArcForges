# Production desktop observability composition

PLT.58 implements the shared production exporter and host. `DesktopObservabilityHost.Open` opens the existing bounded
local diagnostic store and durable consent record, attaches `TracePolicy` to the host's explicitly selected activity
sources, supplies `SignalEmitter`, collects the finite reviewed instrument vocabulary, and runs the real
`OtlpHttpExporter`. Products reference the published `ArcForges.Observability` and `ArcForges.Observability.Desktop`
packages at one exact version. No sibling-source reference or extra OpenTelemetry package is required.

```csharp
await using DesktopObservabilityHost observability = DesktopObservabilityHost.Open(
    new DesktopDiagnosticsOptions { Directory = diagnosticDirectory, Identity = applicationIdentity },
    new TracePolicyOptions(deploymentTraceRatio, deploymentSlowSpanThreshold),
    new OtlpExporterOptions { Collector = approvedCollector, Credentials = collectorCredentials },
    source => source.Name == SignalEmitter.SourceName || source.Name == ownedActivitySourceName);
```

The product presents `Diagnostics.Consent` to its actual human consent flow, uses the unchanged report preview/approval
and verbose-session APIs, emits through `Signals`, and awaits host shutdown after stopping its producers. Grant never
occurs automatically. Local diagnostics remain available without telemetry consent. APP.03 owns the actual product
composition and shared assistant UI; this mechanism does not create an alternative assistant or claim product acceptance.

The HTTPS collector is explicit, without URL credentials, query or fragment. `/v1/traces`, `/v1/logs`, and `/v1/metrics`
are appended to its base path. The production adapter owns its `SocketsHttpHandler`: redirects and cookies are disabled,
ordinary certificate/hostname validation remains active, and only one upload runs at a time. Optional
`IOtlpCollectorCredentials` is the host's secret-owner adapter. Each attempt acquires a fresh, bounded bearer credential,
adds it only to the transport authorization header, and destroys its owned character buffer afterwards. No authorization
header, collector URI, backend error message, prompt, exception message, raw URL, path or arbitrary label enters telemetry.
The immutable transport header string is subject to normal .NET garbage collection; the implementation does not claim
an impossible guarantee of scrubbing strings held inside `HttpClient`.

Serialization is AOT-safe `Utf8JsonWriter`, following the [OTLP/HTTP JSON encoding specification](https://opentelemetry.io/docs/specs/otlp/).
Trace/span identifiers are hexadecimal, enums numeric and 64-bit timestamps/integer values decimal strings. Unsigned
revision values use lossless decimal `AnyValue.stringValue` because OTLP has signed `int64` only. Span events are limited
to 64 with a dropped-event count; record byte limits still apply. Structured event bodies contain finite reviewed event
names, never user messages. The metric listener accepts only the exact shared instrument names/types and current host
identity. Point attributes pass `MetricLabelPolicy`, so only finite `service.name` values survive. Synchronous counters
are delta sums; duration measurements are delta histograms with count/sum/min/max and one infinity bucket. Observable
counters establish a fresh baseline after each grant/revocation epoch; earlier consent-free activity is not uploaded.

The queue accounts for in-flight records as well as pending records. Admission is nonblocking, serialized and bounded by
record count, retained payload bytes and individual record bytes. Overflow is counted locally and drops the new record.
Serialization has at most one bounded temporary record buffer; telemetry is never spooled to disk. A single worker sends
one record per request. Attempts, request deadlines, exponential jitter/backoff, Retry-After and response byte/depth limits
are bounded. Only OTLP-defined `429`, `502`, `503`, `504`, connection failures and request timeouts retry. Redirects,
authorization failures, malformed or partial success and other statuses are terminal. Ambiguous network delivery may be
duplicated; this is not an exactly-once service. Collector response text is never included in diagnostics.

Withdrawal advances a process epoch and immediately purges pending uploads and the diagnostic trace buffer before any
consent persistence I/O. It cancels the current upload. Live consent and epoch checks fence queue admission, credential
acquisition, transport hand-off, trace start/end and retries, so a rapid revoke/re-grant cannot resurrect earlier records
or spans crossing withdrawal. A cancelled secret lookup that ignores its token is bounded to one outstanding lookup;
its eventual credential is disposed and never reused. Uploads already received by the remote collector cannot be recalled.
Existing local diagnostic retention and user-approved report behavior remain separate from automatic telemetry.

`TracePolicy.Attach` captures a write-once consent epoch at actual activity start. Hosts using their own listener wire
`ActivityStarted = policy.OnSpanStarted` and `ActivityStopped = policy.OnSpanEnded`; the revocable policy refuses an
unmarked span, and calling the start callback again cannot relabel an old span. Immutable `CollectionEpoch` provenance
travels with scrubbed spans and structured events, and metric admission supplies its captured epoch. The exporter checks
that original epoch at admission, covering revocation between a producer's consent check and its sink hand-off.
This provenance is not a telemetry attribute and never enters the OTLP payload. Sink callbacks remain outside policy locks.
The production exporter refuses unmarked direct spans or structured events; it never invents a current epoch at send time.
Direct event-sink adapters implement `ITelemetryEpochSource` by delegating to the exporter's collection snapshot. Direct
span delivery uses the start-stamped `TracePolicy` path. The historical `ConsentGatedTelemetry.Export(Activity)` primitive
still supports custom send-time-gated transports, but its unmarked span is deliberately refused by this production exporter.

`CollectorReadiness` reports the last actual delivery outcome, recovers after success and becomes Unknown after configured
freshness expires. It never calls lack of observations healthy. The host's `Readiness` uses a real read/write/flush/delete-on-close
probe in the diagnostic directory; existing files are untouched. `DependencyHealthMonitor` also composes product-owned
SQLite, secret, RPC or other `IRequiredDependencyProbe` adapters, executes bounded parallel checks, propagates caller
cancellation, and fails unavailable/unknown/invalid/errors closed. Repeated probes never accumulate more than one hung
call per dependency. Such supplied adapters must own their actual dependency checks; the monitor does not fabricate them.
Collector availability need not be a product-start prerequisite: the product decides its required dependency set.

Ordinary tests exercise the actual serializer, exporter, queue, consent persistence, trace policy, metric listener,
diagnostic store, monitor and filesystem adapter. Only the unavailable collector HTTP endpoint and external dependency
adapters are faked. These tests do not prove collector deployment, real product GUI operation or OS parser isolation.
After immutable package publication, APP.03 owns published-package host composition and product lifecycle acceptance;
the collector deployment owner supplies an approved endpoint and authorization for a live opt-in delivery check.
