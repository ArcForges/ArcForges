// SPDX-License-Identifier: AGPL-3.0-only
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;

namespace ArcForges.Observability.Desktop;

/// <summary>
/// The only place client telemetry can leave this library, supplied by the host. It is reached only through
/// <see cref="ConsentGatedTelemetry"/>, while consent is granted. An implementation should enqueue and return:
/// it is called while a revocation waits for in-flight sends, so a send that blocks delays that revocation.
/// </summary>
public interface IClientTelemetryTransport
{
    /// <summary>Hands one typed structured event to the host's exporter.</summary>
    void Send(StructuredSignal signal);

    /// <summary>Hands one span, already reduced to its reviewed fields, to the host's exporter.</summary>
    void Send(ScrubbedSpan span);
}

/// <summary>
/// The consent gate in front of client telemetry (observability architecture DG-01, DG-08, TV-08). Install it as the
/// <see cref="IStructuredEventSink"/> of a <see cref="SignalEmitter"/> and call <see cref="Export"/> from the host's
/// span exporter. Every event is kept in the local diagnostic store whatever the consent is, because diagnostics are not
/// consent; it is handed to the transport only while consent is granted. With consent absent or revoked the transport is
/// never called, and a revocation takes effect for the very next signal, whatever thread it comes from.
/// </summary>
public sealed class ConsentGatedTelemetry : IStructuredEventSink
{
    private readonly TelemetryConsent _consent;
    private readonly LocalDiagnosticStore _local;
    private readonly IClientTelemetryTransport _transport;

    internal ConsentGatedTelemetry(TelemetryConsent consent, LocalDiagnosticStore local, IClientTelemetryTransport transport)
    {
        _consent = consent;
        _local = local;
        _transport = transport;
    }

    /// <summary>
    /// Keeps the event locally and, only while consent is granted, sends it. Detail below Information (Debug and Trace,
    /// which only a verbose session keeps) stays on this device even with consent: client telemetry is minimal (DG-01).
    /// </summary>
    public void Write(StructuredSignal signal)
    {
        ArgumentNullException.ThrowIfNull(signal);
        _local.Write(signal);
        if (signal.Level < SignalLevel.Information)
        {
            return;
        }

        SendIfGranted(() => _transport.Send(signal));
    }

    /// <summary>
    /// Copies a finished span through the scrubbing processor and, only while consent is granted, sends the copy. The live
    /// <see cref="Activity"/> never reaches the transport.
    /// </summary>
    public void Export(Activity activity)
    {
        ArgumentNullException.ThrowIfNull(activity);
        if (!_consent.IsGranted)
        {
            return;
        }

        ScrubbedSpan span = RedactionProcessor.Scrub(activity);
        SendIfGranted(() => _transport.Send(span));
    }

    [SuppressMessage("Design", "CA1031:Do not catch general exception types", Justification = "A broken client transport must not fail the operation being observed; the signal is lost and is never retried after consent changed.")]
    private void SendIfGranted(Action send)
    {
        lock (_consent.SendGate)
        {
            if (!_consent.IsGranted)
            {
                return;
            }

            try
            {
                send();
            }
            catch (Exception)
            {
                // Lost, not retried: a retry could run after a revocation.
            }
        }
    }
}
