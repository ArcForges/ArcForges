// SPDX-License-Identifier: AGPL-3.0-only
using System.Buffers;
using System.Globalization;
using System.Diagnostics.CodeAnalysis;
using System.Text.Json;
using ArcForges.Foundation;

namespace ArcForges.Observability.Desktop;

/// <summary>
/// The revocable consent to send client telemetry (observability architecture DG-01, DG-08). The default is
/// <see cref="TelemetryConsentState.Absent"/>, which sends nothing. Consent is held in a small local record that is
/// read fail-closed: a missing, unreadable, unknown or malformed record is Absent. Diagnostics are not consent (QI-24):
/// the local diagnostic store, a verbose session and a user-approved report never read this state.
/// It is the <see cref="ITelemetryConsent"/> that the Observability trace policy reads live on every span. Note that the
/// Observability assembly also has a static class named <c>TelemetryConsent</c> (for hosts that need no consent); a file that imports
/// both namespaces must qualify one of them.
/// </summary>
public sealed class TelemetryConsent : IRevocableTelemetryConsent
{
    internal const string FileName = "telemetry-consent.json";
    private const int RecordVersion = 1;

    private readonly object _stateGate = new();
    private readonly string _path;
    private readonly IClock _clock;
    private int _state;
    private long _revocations;
    private Instant? _changedAt;

    internal TelemetryConsent(string directory, IClock clock)
    {
        _path = Path.Combine(directory, FileName);
        _clock = clock;
        (TelemetryConsentState state, Instant? changedAt) = Load(_path);
        _state = (int)state;
        _changedAt = changedAt;
    }

    /// <summary>The current consent. Read on every send, so a revocation is visible to the very next signal.</summary>
    public TelemetryConsentState State => (TelemetryConsentState)Volatile.Read(ref _state);

    /// <summary>True only while the user's consent stands.</summary>
    public bool IsGranted => State == TelemetryConsentState.Granted;
    public long CollectionEpoch => Revocations;

    /// <summary>When the state last changed, or null if the user has never changed it.</summary>
    public Instant? ChangedAt
    {
        get
        {
            lock (_stateGate)
            {
                return _changedAt;
            }
        }
    }

    /// <summary>Raised after the state changed. A host drops any telemetry it has queued when consent is no longer granted.</summary>
    public event EventHandler? Changed;

    // Production queue/trace purge occurs before durable I/O, so a slow or failing disk cannot delay withdrawal.
    internal event Action? Revoking;

    /// <summary>The gate under which every client send runs; revocation waits on it so no send is in flight afterwards.</summary>
    internal object SendGate { get; } = new();

    /// <summary>How many times consent was revoked in this process; an approval taken before a revocation is void.</summary>
    internal long Revocations => Interlocked.Read(ref _revocations);

    /// <summary>Runs inside <see cref="Grant"/> after the grant was stored and before it takes effect; tests use it to interleave a revocation.</summary>
    internal Action? BeforeGrantCommit { get; set; }

    /// <summary>
    /// Records the user's explicit grant. The grant is made durable first; if it cannot be stored the exception
    /// propagates and the state stays as it was, so a grant that would not survive a restart is never claimed. A grant
    /// that a concurrent <see cref="Revoke"/> overtakes has no effect: the state change is one atomic exchange from the
    /// state the grant started from, so a revocation can never be overwritten by a grant that began earlier.
    /// </summary>
    public void Grant()
    {
        lock (_stateGate)
        {
            TelemetryConsentState previous = State;
            if (previous == TelemetryConsentState.Granted)
            {
                return;
            }

            Instant now = _clock.GetCurrentInstant();
            Persist(TelemetryConsentState.Granted, now);
            BeforeGrantCommit?.Invoke();
            if (Interlocked.CompareExchange(ref _state, (int)TelemetryConsentState.Granted, (int)previous) != (int)previous)
            {
                // Revoke already set the state; it stores the revocation once this lock is released.
                return;
            }

            _changedAt = now;
        }

        Changed?.Invoke(this, EventArgs.Empty);
    }

    /// <summary>
    /// Revokes consent. Collection stops first and locally: the state becomes Revoked in one atomic exchange before
    /// anything else happens, so no send that has not begun can begin, and a synchronous send to the host transport that is
    /// already inside the send gate has handed its signal over when this method returns. Only then is the revocation made
    /// durable. If it cannot be stored, the stored record is removed (an absent record is also no consent); if that fails
    /// too the exception propagates, but this process stays revoked. The guarantee is at the hand-off to the host: a host
    /// that queued telemetry must drop its queue when <see cref="Changed"/> reports the revocation, and an upload that an
    /// approved report already started is not cancelled.
    /// </summary>
    public void Revoke()
    {
        if (Interlocked.Exchange(ref _state, (int)TelemetryConsentState.Revoked) == (int)TelemetryConsentState.Revoked)
        {
            return;
        }

        Interlocked.Increment(ref _revocations);
        NotifyRevoking();
        lock (SendGate)
        {
            // Draining barrier only: any send holding this gate has completed, and none starts while it is Revoked.
        }

        Instant now = _clock.GetCurrentInstant();
        try
        {
            lock (_stateGate)
            {
                _changedAt = now;
                try
                {
                    Persist(TelemetryConsentState.Revoked, now);
                }
                catch (Exception error) when (error is IOException or UnauthorizedAccessException)
                {
                    File.Delete(_path);
                }
            }
        }
        finally
        {
            Changed?.Invoke(this, EventArgs.Empty);
        }
    }

    private void Persist(TelemetryConsentState state, Instant at)
    {
        var buffer = new ArrayBufferWriter<byte>();
        using (var writer = new Utf8JsonWriter(buffer))
        {
            writer.WriteStartObject();
            writer.WriteNumber("schema", RecordVersion);
            writer.WriteString("state", state == TelemetryConsentState.Granted ? "granted" : "revoked");
            writer.WriteString("changedAt", at.ToDateTimeOffset().ToString("O", CultureInfo.InvariantCulture));
            writer.WriteEndObject();
        }

        string temporary = _path + ".tmp";
        File.WriteAllBytes(temporary, buffer.WrittenSpan.ToArray());
        File.Move(temporary, _path, overwrite: true);
    }

    [SuppressMessage("Design", "CA1031:Do not catch general exception types", Justification = "An internal purge/cancellation callback must never prevent durable revocation or another owner's purge; live state and the revocation epoch are already fenced.")]
    private void NotifyRevoking()
    {
        foreach (Action callback in Revoking?.GetInvocationList().Cast<Action>() ?? [])
        {
            try { callback(); }
            catch (Exception) { }
        }
    }

    private static (TelemetryConsentState State, Instant? ChangedAt) Load(string path)
    {
        try
        {
            if (!File.Exists(path))
            {
                return (TelemetryConsentState.Absent, null);
            }

            using JsonDocument document = JsonDocument.Parse(File.ReadAllBytes(path), new JsonDocumentOptions { MaxDepth = 2 });
            JsonElement root = document.RootElement;
            if (root.ValueKind != JsonValueKind.Object
                || !root.TryGetProperty("schema", out JsonElement schema) || !schema.TryGetInt32(out int version) || version != RecordVersion
                || !root.TryGetProperty("state", out JsonElement state) || state.ValueKind != JsonValueKind.String
                || !root.TryGetProperty("changedAt", out JsonElement changed) || changed.ValueKind != JsonValueKind.String
                || !DateTimeOffset.TryParse(changed.GetString(), CultureInfo.InvariantCulture, DateTimeStyles.RoundtripKind, out DateTimeOffset at))
            {
                return (TelemetryConsentState.Absent, null);
            }

            Instant instant = Instant.FromDateTimeOffset(at);
            return state.GetString() switch
            {
                "granted" => (TelemetryConsentState.Granted, instant),
                "revoked" => (TelemetryConsentState.Revoked, instant),
                _ => (TelemetryConsentState.Absent, null),
            };
        }
        catch (Exception error) when (error is IOException or UnauthorizedAccessException or JsonException or ArgumentException or InvalidOperationException)
        {
            // An unreadable record is never consent.
            return (TelemetryConsentState.Absent, null);
        }
    }

    internal static string Describe(TelemetryConsentState state) => state switch
    {
        TelemetryConsentState.Granted => "granted",
        TelemetryConsentState.Revoked => "revoked",
        _ => "absent",
    };
}
