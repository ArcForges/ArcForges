// SPDX-License-Identifier: AGPL-3.0-only
using System.Diagnostics.CodeAnalysis;
using System.Text;
using ArcForges.Contracts.Foundation.V1;
using ArcForges.Foundation;
using ArcForges.Foundation.Errors;

namespace ArcForges.Observability.Desktop;

/// <summary>What a report holds, chosen by the user. Nothing is included unless the user asked for it.</summary>
public sealed record DiagnosticReportOptions
{
    /// <summary>The most log entries a report may carry (upper bound 1000).</summary>
    public const int DefaultMaximumLogEntries = 200;

    /// <summary>
    /// Whether the reviewed local log entries are part of the report. Off by default: each sensitive category of a
    /// diagnostic bundle is a separate explicit opt-in (distribution requirements RP-04).
    /// </summary>
    public bool IncludeLogEntries { get; init; }

    /// <summary>The most recent log entries to include when <see cref="IncludeLogEntries"/> is set.</summary>
    public int MaximumLogEntries { get; init; } = DefaultMaximumLogEntries;
}

/// <summary>The exact text a report consists of, as it must be shown to the user in full before approval.</summary>
public sealed class DiagnosticReportPreview
{
    internal DiagnosticReportPreview(string supportReference, string text, string digest)
    {
        SupportReference = supportReference;
        Text = text;
        Digest = digest;
    }

    /// <summary>The identifier the user can quote in a support case without attaching anything.</summary>
    public string SupportReference { get; }

    /// <summary>The complete report. These exact UTF-8 bytes are what an approved report sends; nothing else is added.</summary>
    public string Text { get; }

    /// <summary>The lowercase SHA-256 of the UTF-8 bytes of <see cref="Text"/>.</summary>
    public string Digest { get; }
}

/// <summary>The exact bytes an approved report hands to the uploader.</summary>
/// <param name="SupportReference">The support reference of the report.</param>
/// <param name="Digest">The SHA-256 of <paramref name="Content"/>, equal to the digest the user saw.</param>
/// <param name="Content">The previewed text as UTF-8.</param>
public sealed record DiagnosticReportUpload(string SupportReference, string Digest, ReadOnlyMemory<byte> Content);

/// <summary>Confirmation that the uploader accepted an approved report.</summary>
/// <param name="SupportReference">The support reference of the report.</param>
/// <param name="Digest">The digest of the content that was handed over.</param>
public sealed record DiagnosticReportReceipt(string SupportReference, string Digest);

/// <summary>
/// The host's report upload, given to <see cref="ApprovedDiagnosticReport.SendAsync"/> only. This library never holds
/// an uploader, so nothing can be uploaded except a report the user previewed and approved.
/// </summary>
public interface IDiagnosticReportUploader
{
    ValueTask UploadAsync(DiagnosticReportUpload upload, CancellationToken cancellationToken);
}

/// <summary>
/// A generated report that has not been approved. The flow is fixed: generate, show it in full (<see cref="Preview"/>),
/// the user approves (<see cref="Approve"/>), then it is sent. Generating a report sends nothing.
/// </summary>
public sealed class DiagnosticReportDraft
{
    private readonly DesktopDiagnostics _owner;
    private readonly string _text;
    private readonly string _digest;
    private readonly object _gate = new();
    private bool _shown;
    private bool _approved;

    internal DiagnosticReportDraft(DesktopDiagnostics owner, string supportReference, DiagnosticReportOrigin origin, string text, string digest)
    {
        _owner = owner;
        SupportReference = supportReference;
        Origin = origin;
        _text = text;
        _digest = digest;
    }

    public string SupportReference { get; }

    public DiagnosticReportOrigin Origin { get; }

    /// <summary>True once <see cref="Preview"/> has been called, that is, once the report has been handed over for display.</summary>
    public bool HasBeenShown
    {
        get
        {
            lock (_gate)
            {
                return _shown;
            }
        }
    }

    /// <summary>Returns the complete report for display. Approval is possible only after this call.</summary>
    public DiagnosticReportPreview Preview()
    {
        lock (_gate)
        {
            _shown = true;
        }

        return new DiagnosticReportPreview(SupportReference, _text, _digest);
    }

    /// <summary>
    /// Records the user's approval of exactly the text that <see cref="Preview"/> returned. It is refused until the report
    /// has been shown, and a report can be approved once.
    /// </summary>
    public ApprovedDiagnosticReport Approve()
    {
        lock (_gate)
        {
            if (!_shown)
            {
                throw new InvalidOperationException("A diagnostic report must be shown in full before it can be approved.");
            }

            if (_approved)
            {
                throw new InvalidOperationException("This diagnostic report was already approved.");
            }

            _approved = true;
        }

        return _owner.Approve(SupportReference, Origin, _text, _digest);
    }
}

/// <summary>
/// A report the user approved. It can be sent once, within a short period, and only while the consent state at the time
/// of approval has not been revoked since; the report is then handed to the uploader unchanged.
/// </summary>
public sealed class ApprovedDiagnosticReport
{
    private readonly DesktopDiagnostics _owner;
    private readonly DiagnosticReportOrigin _origin;
    private readonly byte[] _content;
    private readonly long _revocationsAtApproval;
    private readonly MonotonicTimestamp _approvedAt;
    private readonly object _gate = new();
    private bool _consumed;

    internal ApprovedDiagnosticReport(DesktopDiagnostics owner, string supportReference, string digest, DiagnosticReportOrigin origin,
        string text, long revocationsAtApproval, MonotonicTimestamp approvedAt)
    {
        _owner = owner;
        SupportReference = supportReference;
        Digest = digest;
        _origin = origin;
        _content = new UTF8Encoding(encoderShouldEmitUTF8Identifier: false).GetBytes(text);
        _revocationsAtApproval = revocationsAtApproval;
        _approvedAt = approvedAt;
    }

    public string SupportReference { get; }

    public string Digest { get; }

    /// <summary>
    /// Hands the approved report to <paramref name="uploader"/> once. It fails without calling the uploader when the
    /// approval was already used, has expired, or was withdrawn by a revocation of consent. A failure of the uploader is
    /// reported as an unknown effect, because the report may or may not have arrived; it is not sent again by this call.
    /// </summary>
    [SuppressMessage("Design", "CA1031:Do not catch general exception types", Justification = "An uploader failure of any kind is reported as a typed dependency failure with unknown effect.")]
    public async ValueTask<Outcome<DiagnosticReportReceipt>> SendAsync(IDiagnosticReportUploader uploader, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(uploader);
        ValueTask upload = default;
        Exception? startFailure = null;
        DiagnosticEventKind? refusalEvent = null;
        TypedFailure? refusal;
        lock (_owner.SendGate)
        {
            lock (_gate)
            {
                if (_consumed)
                {
                    refusal = TypedFailure.Create("state.invalid_transition");
                }
                else
                {
                    _consumed = true;
                    refusal = _owner.VerifyApproval(_revocationsAtApproval, _approvedAt, out refusalEvent);
                }
            }

            if (refusal is null)
            {
                // Started inside the gate that a revocation drains, so no upload begins once Revoke has returned.
                try
                {
                    upload = uploader.UploadAsync(new DiagnosticReportUpload(SupportReference, Digest, _content), cancellationToken);
                }
                catch (Exception error)
                {
                    startFailure = error;
                }
            }
        }

        if (refusal is not null)
        {
            _owner.RecordReportRefusal(refusalEvent, SupportReference);
            return Outcome.Failure<DiagnosticReportReceipt>(refusal);
        }

        if (startFailure is not null)
        {
            return UploadFailed(startFailure, cancellationToken);
        }

        try
        {
            await upload.ConfigureAwait(false);
        }
        catch (Exception error)
        {
            return UploadFailed(error, cancellationToken);
        }

        _owner.RecordReportSent(SupportReference, _origin);
        return Outcome.Success(new DiagnosticReportReceipt(SupportReference, Digest));
    }

    private static Outcome<DiagnosticReportReceipt> UploadFailed(Exception error, CancellationToken cancellationToken) =>
        error is OperationCanceledException && cancellationToken.IsCancellationRequested
            ? Outcome.Cancelled<DiagnosticReportReceipt>(EffectCertainty.Unknown)
            : Outcome.Failure<DiagnosticReportReceipt>(TypedFailure.Create("dependency.unavailable"));
}
