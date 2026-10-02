// SPDX-License-Identifier: AGPL-3.0-only
namespace ArcForges.Observability.Desktop;

/// <summary>
/// The three explicit desktop diagnostic tiers (observability architecture DG-05). A tier decides what is kept on
/// this device; none of them uploads anything. Uploading needs telemetry consent (signals) or a per-report approval.
/// </summary>
public enum DiagnosticTier
{
    /// <summary>The minimal, always-on local tier: events at Information or above, kept in the local store.</summary>
    LocalMinimal = 0,

    /// <summary>A report the user asked for or approved: generated, shown in full, and sent only after approval.</summary>
    UserApprovedReport = 1,

    /// <summary>A time-bounded verbose session the user started: local only, self-disabling and visible while active.</summary>
    VerboseSession = 2,
}

/// <summary>Whether this installation may send client telemetry. Absent is the default and means no.</summary>
public enum TelemetryConsentState
{
    /// <summary>The user has never granted consent. Nothing leaves the device.</summary>
    Absent = 0,

    /// <summary>The user granted consent and has not revoked it.</summary>
    Granted = 1,

    /// <summary>The user granted consent and then revoked it. Nothing leaves the device.</summary>
    Revoked = 2,
}

/// <summary>Why a report exists: the user asked for it, or the previous run recorded a crash.</summary>
public enum DiagnosticReportOrigin
{
    UserRequested = 0,
    PreviousCrash = 1,
}
