# ArcForges.Observability.Desktop

Desktop diagnostics and consent (PLT.52, WP-12.05; observability architecture section 9). This non-packable DesktopPlatform
library is the headless model behind the diagnostic report, consent and verbose-session surfaces. It has no UI: the shell
presents `TelemetryConsent`, `VerboseSessionState`, `DiagnosticReportPreview` and the typed failures (registered reason
codes) that this library returns. `eng/packaging/packages.json` is not changed here; package admission belongs to PLT.53.

`DesktopDiagnostics.Open` takes a host-owned local directory and the application identity. It holds three kinds of state
there: a rotating diagnostic log, the consent record and, after a crash, a pending crash record.

## The three tiers

| Tier | What it does | Uploads |
|---|---|---|
| Minimal, always on (`DiagnosticTier.LocalMinimal`) | `LocalSink` keeps typed events at Information and above in a bounded, rotating local log. `ReadRecent` is the local diagnostic view. | Never. It does not read consent. |
| User-approved report (`UserApprovedReport`) | `CreateReport` generates a report. `Preview()` returns the exact text; `Approve()` is refused until it was previewed; `SendAsync` hands those bytes to a host uploader once. | Only after approval, per report. |
| Verbose session (`VerboseSession`) | `Verbose.Start(duration)` (positive, at most 4 hours; 30 minutes by default) makes the local log keep Debug and Trace detail. `Verbose.State` carries the remaining time for the shell indicator. | Never. The session only widens local retention; detail below Information is not handed to the telemetry transport even while consent is granted. |

A verbose session ends by itself: whether it is active is computed from the monotonic clock on every read, so it cannot
outlive its period or be extended by a wall-clock change, and a `TimeProvider` timer (armed again if it fires a moment before the
monotonic clock agrees) raises `Changed(Expired)` so a shell can hide the indicator without polling. Diagnostics are not telemetry consent (QI-24): no tier reads or changes consent.

## Consent and revocation

`TelemetryConsent` is Absent until the user grants it. The record is read fail-closed: a missing, unreadable, unknown or
malformed record is Absent. `Grant()` is durable first; a grant that cannot be stored throws and changes nothing. `Revoke()`
stops collection first: the state changes to Revoked in one atomic exchange before anything else happens (a `Grant()` that
began earlier cannot overwrite it), no send that has not started can start, and a synchronous send to the host transport that was
already running has handed its signal over when `Revoke()` returns; only then is the revocation stored (if it cannot be, the
stored record is removed, since no record also means no consent). Revocation also voids every approved report that has not
been sent. The guarantee is at the hand-off to the host: `Revoke()` does not call the transport, an upload that an approved
report already started is not awaited or cancelled (no upload starts after `Revoke()` returns), and the host must drop what it
queued. The consent record is unauthenticated: a malformed record is Absent, but any process of the same user can write a
well-formed `granted` record, which is honoured at the next start. Any code in the process can call `Grant()`.

`TelemetryConsent` implements `ArcForges.Observability.ITelemetryConsent`, the live consent state that the Observability
`TracePolicy` (PLT.50) reads on every span. That interface has no change notification, and the trace policy asks the host to
call `PurgeBuffer` when consent is revoked; a host does that from `TelemetryConsent.Changed` when `IsGranted` is false. This
wiring is documented here and not exercised by this project's tests. The Observability assembly also has a static class named
`TelemetryConsent` (`NotRequired`, for Cloud hosts); a file that imports both namespaces must qualify one of the two names.

`CreateTelemetry(transport)` returns the only path by which telemetry leaves this library: a `ConsentGatedTelemetry` sink
for a `SignalEmitter`, with `Export(Activity)` for the host's span exporter (spans are copied through the Observability
scrubbing processor first). Events are always kept locally; the host's `IClientTelemetryTransport` is called only while
consent is granted (events at Information and above only) and should enqueue and return, because a revocation waits for sends in progress, and so does the first synchronous part of an uploader. This library queues
nothing, so a host that queues telemetry must drop its queue when `TelemetryConsent.Changed` reports that consent is no
longer granted. Metrics export is host-owned and must consult `TelemetryConsent.IsGranted` the same way.

## Reports and crashes

The report text carries the application identity, consent state, the reason code of a recorded crash and, only when
`IncludeLogEntries` is set, the newest reviewed log entries. Its format has no field for a memory dump, file path,
document content or secret, and says so in an `includes` block. Stored log lines are re-checked on every read with the
Observability scrubbing processor and a dotted-identifier rule for event names, so an altered log cannot put an unreviewed
field into the local view or a report; lines that are not valid entries are skipped and counted. A report carries at most
256 KiB of log entries: the oldest are left out and counted in `omittedEntries`. Reading the log for a view or report does not
hold the lock that event writes take, so a segment being removed or written during the read can cost entries from that view.

`DesktopDiagnostics` holds no uploader. `RecordCrash(exception)` stores the registered reason code of the exception type
(never its message, data or stack) and a support reference, and sends nothing; a failure to store it is swallowed, a null
argument throws. At the next start `TryGetPendingCrashReport()`
returns a draft that follows the same preview, approve and send flow. "Shown in full" is enforced as an order and an identity:
`Approve()` is refused before `Preview()` was called, and the bytes sent are exactly the previewed text. The library cannot know
that a user interface displayed the text or that a person rather than code called `Approve()`; `DismissPendingCrashReport()` discards it. A failed
or cancelled upload is a typed outcome with unknown effect and is not retried by this library.

The rotation budget (segment size, segment count and age, defaults 512 KiB, 8 and 14 days) and the report approval period
(15 minutes) are implementation defaults, not values fixed by the design. The age budget is met per log segment.

## What is not covered here

No UI, no real telemetry exporter or backend, no platform crash capture hook (the host calls `RecordCrash` from its own
unhandled-exception handler), no encryption of the local log and no cross-process locking of the directory (one process
owns it). The tests are offline and local, using temporary directories and a manual time provider; they do not show behavior
of a product host. `InternalsVisibleTo` exposes this assembly's internals to its test assembly only; PLT.53 re-confirms that when it
decides what is published.
