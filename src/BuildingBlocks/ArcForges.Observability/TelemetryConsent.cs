// SPDX-License-Identifier: AGPL-3.0-only
namespace ArcForges.Observability;

/// <summary>
/// The live telemetry consent state a client host owns (observability architecture DG-01, DG-08). It is read on every
/// decision, never cached, so revocation takes effect on the next signal. The diagnostics and consent flow that grants
/// and revokes consent is PLT.52's; this library only consumes the answer.
/// </summary>
public interface ITelemetryConsent
{
    /// <summary>True only while the user has granted consent to collect telemetry on this device.</summary>
    bool IsGranted { get; }
}

/// <summary>Consent states for hosts whose telemetry does not depend on a user's choice.</summary>
public static class TelemetryConsent
{
    /// <summary>
    /// For a host that is not a desktop client, such as a Cloud service (observability architecture OA-07). A desktop
    /// client never passes this; it passes the consent state its user controls.
    /// </summary>
    public static ITelemetryConsent NotRequired { get; } = new Always();

    private sealed class Always : ITelemetryConsent
    {
        public bool IsGranted => true;
    }
}
