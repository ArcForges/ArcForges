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

## Redaction by construction (WP-12.02)

Redaction is a property of the types, with a scrubbing processor behind them as a second line of defence
(observability architecture RD-01 to RD-08). `eng/policy/telemetry-policy.json` records the reviewed vocabulary, and
tests keep it identical to what this library enforces.

- **No logging representation.** The emission surface has no text, object, exception or property-bag parameter, so a
  secret reference, token, prompt, note or path has nothing to be passed through. The only public members that accept
  such input are the named boundaries in `PublicSurfaceTests`, each of which validates, maps or discards it. A type that
  holds secret or user content is declared with `[SensitiveContent]`; the reference structural audit in this project's
  tests (`SensitiveTypeAudit`) fails any such type that is a record, is unsealed, implements a formatting interface,
  exposes text, bytes, spans, streams or `object`, converts to such a type, or overrides `ToString` with anything but
  `Name:[redacted]`. It is a reference audit, not a proof: it examines one type's own declared members (including
  explicit interface implementations) and treats arrays, spans, memory, sequences, `Task<>`, `ValueTask<>`, `Lazy<>`,
  `Func<>`, `IEnumerable` carriers, `StringBuilder`, `TextReader` and `TextWriter` of text or bytes as text. It does
  not follow members transitively into other types, inspect inherited members (a base type other than `object` is
  itself a finding), or recognise carriers it does not list. The audit uses reflection, which production AOT code may
  not, so it lives in the tests; an owner of a content type runs the same check over its own assembly.
- **Scrubbing processor.** `RedactionProcessor` removes every field that is not in the reviewed export vocabulary, is a
  known-sensitive header or field name (authorization, cookie, API key, token, prompt, note, path, raw URL, exception
  text, and so on), or has a value that is not exactly the reviewed shape of its field. `SignalEmitter` runs every
  dimension through it, and `RedactionProcessor.Scrub(Activity)` copies a finished foreign span into an export-safe
  `ScrubbedSpan` that drops the status description, links, baggage and any non-reviewed tag or event field. A host
  exporter exports the `ScrubbedSpan`, never the live `Activity`. Span events recorded with `Activity.AddException`
  cannot be removed from the live activity, which is why exporters copy through the processor.
- **URLs.** `RouteTemplateSet` records a request target as a registered route template plus opaque identifiers.
  Scheme, host, user information, query and fragment are discarded unread, a slot accepts only a canonical UUID, and a
  target that matches no template is recorded as `{unmatched}`, never as text. Identifiers are trace and log fields,
  never metric labels. An exporter accepts an `http.route` value only if a `RouteTemplateSet` registered it.
- **Exceptions.** `ExceptionReasonMapper` and `ObservabilityContext.WithFailure` map an exception to a registered
  `ReasonCode` by its runtime type alone. The message, data and stack are never read, and an unknown type is
  `internal.unexpected`. A cancellation is recorded as cancelled with no reason code.

This project is not currently an admitted package. See the [repository README](../../../README.md)
for ownership and publication policy.
