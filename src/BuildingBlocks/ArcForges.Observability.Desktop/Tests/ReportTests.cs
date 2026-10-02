// SPDX-License-Identifier: AGPL-3.0-only
using System.Diagnostics.CodeAnalysis;
using System.Reflection;
using System.Security.Cryptography;
using System.Text;
using ArcForges.Contracts.Foundation.V1;
using ArcForges.Foundation.Errors;
using Xunit;

namespace ArcForges.Observability.Desktop.Tests;

[SuppressMessage("Trimming", "IL2026", Justification = "Test-only reflection over this repository's own assembly; tests are never trimmed.")]
[SuppressMessage("Trimming", "IL2075", Justification = "Test-only reflection over this repository's own assembly; tests are never trimmed.")]
public sealed class ReportTests
{
    private const string Marker = "MARKER-REPORT-LEAK";

    [Fact]
    public async Task AReportIsGeneratedShownInFullAndSentOnlyAfterApproval()
    {
        using var directory = new TestDirectory();
        using DesktopDiagnostics diagnostics = Fixtures.Open(directory.Path);
        diagnostics.Consent.Grant();
        Fixtures.Emit(diagnostics.LocalSink, SignalEventName.OperationCompleted, SignalLevel.Information, count: 2);
        var uploader = new RecordingUploader();

        DiagnosticReportDraft draft = diagnostics.CreateReport(new DiagnosticReportOptions { IncludeLogEntries = true });
        Assert.Equal(DiagnosticReportOrigin.UserRequested, draft.Origin);
        Assert.False(draft.HasBeenShown);
        Assert.Matches("^ARC-[0-9A-Z]{4}-[0-9A-Z]{4}-[0-9A-Z]{4}$", draft.SupportReference);
        Assert.Throws<InvalidOperationException>(draft.Approve);
        Assert.Empty(uploader.Uploads);

        DiagnosticReportPreview preview = draft.Preview();
        Assert.True(draft.HasBeenShown);
        Assert.Contains(draft.SupportReference, preview.Text, StringComparison.Ordinal);
        Assert.Contains("operation.completed", preview.Text, StringComparison.Ordinal);
        byte[] shown = Encoding.UTF8.GetBytes(preview.Text);
        Assert.Equal(Convert.ToHexStringLower(SHA256.HashData(shown)), preview.Digest);

        ApprovedDiagnosticReport approved = draft.Approve();
        Assert.Throws<InvalidOperationException>(draft.Approve);
        Assert.Empty(uploader.Uploads);

        Outcome<DiagnosticReportReceipt> sent = await approved.SendAsync(uploader, TestContext.Current.CancellationToken).ConfigureAwait(true);
        Assert.True(sent.TryGetValue(out DiagnosticReportReceipt? receipt));
        Assert.Equal(preview.Digest, receipt!.Digest);
        DiagnosticReportUpload upload = Assert.Single(uploader.Uploads);
        Assert.Equal(shown, upload.Content.ToArray());
        Assert.Equal(preview.Digest, upload.Digest);

        // One approval, one send.
        Outcome<DiagnosticReportReceipt> again = await approved.SendAsync(uploader, TestContext.Current.CancellationToken).ConfigureAwait(true);
        Assert.Equal("state.invalid_transition", Fixtures.FailureCode(again));
        Assert.Single(uploader.Uploads);
        Assert.Contains(diagnostics.ReadRecent(100), entry => entry.Name == "diagnostics.report.sent");
    }

    [Fact]
    public async Task AnApprovalExpiresAndARevocationWithdrawsItWithoutTheUploaderBeingCalled()
    {
        using var directory = new TestDirectory();
        var time = new ManualTimeProvider();
        using DesktopDiagnostics diagnostics = Fixtures.Open(directory.Path, time);
        var uploader = new RecordingUploader();

        DiagnosticReportDraft stale = diagnostics.CreateReport();
        stale.Preview();
        ApprovedDiagnosticReport staleApproval = stale.Approve();
        time.Advance(TimeSpan.FromMinutes(16));
        Outcome<DiagnosticReportReceipt> expired = await staleApproval.SendAsync(uploader, TestContext.Current.CancellationToken).ConfigureAwait(true);
        Assert.Equal("perm.approval_expired", Fixtures.FailureCode(expired));

        diagnostics.Consent.Grant();
        DiagnosticReportDraft revoked = diagnostics.CreateReport();
        revoked.Preview();
        ApprovedDiagnosticReport revokedApproval = revoked.Approve();
        diagnostics.Consent.Revoke();
        Outcome<DiagnosticReportReceipt> withdrawn = await revokedApproval.SendAsync(uploader, TestContext.Current.CancellationToken).ConfigureAwait(true);
        Assert.Equal("perm.approval_required", Fixtures.FailureCode(withdrawn));

        Assert.Empty(uploader.Uploads);
        Assert.Equal(2, diagnostics.ReadRecent(100).Count(entry => entry.Name == "diagnostics.report.cancelled"));
    }

    [Fact]
    public async Task AnUploaderFailureIsAnUnknownEffectAndIsNeverRetried()
    {
        using var directory = new TestDirectory();
        using DesktopDiagnostics diagnostics = Fixtures.Open(directory.Path);

        var failing = new RecordingUploader { Failure = new IOException("MARKER-UPLOAD-DETAIL") };
        DiagnosticReportDraft draft = diagnostics.CreateReport();
        draft.Preview();
        Outcome<DiagnosticReportReceipt> failed = await draft.Approve().SendAsync(failing, TestContext.Current.CancellationToken).ConfigureAwait(true);
        Assert.True(failed.TryGetFailure(out TypedFailure? failure));
        Assert.Equal("dependency.unavailable", failure!.Code);
        Assert.Equal(EffectCertainty.Unknown, failure.Effect);
        Assert.Single(failing.Uploads);

        using var cancel = new CancellationTokenSource();
        var cancelling = new RecordingUploader { Failure = new OperationCanceledException(cancel.Token) };
        await cancel.CancelAsync().ConfigureAwait(true);
        DiagnosticReportDraft second = diagnostics.CreateReport();
        second.Preview();
        Outcome<DiagnosticReportReceipt> cancelled = await second.Approve().SendAsync(cancelling, cancel.Token).ConfigureAwait(true);
        Assert.Equal(OutcomeKind.Cancelled, cancelled.Kind);
        Assert.Equal(EffectCertainty.Unknown, cancelled.CancellationEffect);
    }

    [Fact]
    public async Task ACrashIsKeptLocallyNeverUploadedAutomaticallyAndSentOnlyAfterApproval()
    {
        using var directory = new TestDirectory();
        var transport = new RecordingTransport();
        var uploader = new RecordingUploader();
        string reference;

        using (DesktopDiagnostics crashing = Fixtures.Open(directory.Path))
        {
            crashing.Consent.Grant();
            _ = crashing.CreateTelemetry(transport);
            crashing.RecordCrash(new InvalidOperationException(Marker + " message with C:\\Users\\someone\\secret.txt"));

            Assert.Equal(0, transport.Total);
            Assert.Empty(uploader.Uploads);
            Assert.True(crashing.HasPendingCrashReport);
            Assert.DoesNotContain(Marker, await File.ReadAllTextAsync(Path.Combine(directory.Path, "pending-crash.json"), TestContext.Current.CancellationToken).ConfigureAwait(true), StringComparison.Ordinal);
            LocalDiagnosticEntry entry = Assert.Single(crashing.ReadRecent(100), candidate => candidate.Name == "diagnostics.crash.recorded");
            Assert.Equal("state.invalid_transition", entry.Fields["reason.code"]);
            reference = (string)entry.Fields["support.reference"]!;
        }

        // The next start finds the crash. Even with telemetry consent granted nothing is sent until the user approves.
        using DesktopDiagnostics restarted = Fixtures.Open(directory.Path);
        Assert.True(restarted.HasPendingCrashReport);
        DiagnosticReportDraft? draft = restarted.TryGetPendingCrashReport();
        Assert.NotNull(draft);
        Assert.Equal(DiagnosticReportOrigin.PreviousCrash, draft!.Origin);
        Assert.Equal(reference, draft.SupportReference);
        Assert.Empty(uploader.Uploads);

        DiagnosticReportPreview preview = draft.Preview();
        Assert.Contains("\"reason.code\": \"state.invalid_transition\"", preview.Text, StringComparison.Ordinal);
        Assert.DoesNotContain(Marker, preview.Text, StringComparison.Ordinal);
        Assert.Contains("\"memoryDump\": false", preview.Text, StringComparison.Ordinal);

        Outcome<DiagnosticReportReceipt> sent = await draft.Approve().SendAsync(uploader, TestContext.Current.CancellationToken).ConfigureAwait(true);
        Assert.Equal(OutcomeKind.Success, sent.Kind);
        Assert.Single(uploader.Uploads);
        Assert.False(restarted.HasPendingCrashReport);
        Assert.Null(restarted.TryGetPendingCrashReport());
    }

    [Fact]
    public void ADismissedCrashReportIsDiscardedWithoutAnythingBeingSent()
    {
        using var directory = new TestDirectory();
        using DesktopDiagnostics diagnostics = Fixtures.Open(directory.Path);
        diagnostics.RecordCrash(new TimeoutException(Marker));
        Assert.True(diagnostics.HasPendingCrashReport);

        diagnostics.DismissPendingCrashReport();

        Assert.False(diagnostics.HasPendingCrashReport);
        Assert.Null(diagnostics.TryGetPendingCrashReport());
        Assert.Equal("dependency.timeout", Assert.Single(diagnostics.ReadRecent(100), entry => entry.Name == "diagnostics.crash.recorded").Fields["reason.code"]);
    }

    [Fact]
    public void ALogIsInAReportOnlyWhenOptedInAndNoDumpPathOrContentHasAnyField()
    {
        using var directory = new TestDirectory();
        using DesktopDiagnostics diagnostics = Fixtures.Open(directory.Path);
        Fixtures.Emit(diagnostics.LocalSink, SignalEventName.OperationCompleted, SignalLevel.Information);

        string basic = diagnostics.CreateReport().Preview().Text;
        Assert.DoesNotContain("operation.completed", basic, StringComparison.Ordinal);
        Assert.DoesNotContain("\"logEntries\": [", basic, StringComparison.Ordinal);
        Assert.Contains("\"logEntries\": 0", basic, StringComparison.Ordinal);
        foreach (string excluded in new[] { "memoryDump", "filePaths", "documentContent", "secrets" })
        {
            Assert.Contains($"\"{excluded}\": false", basic, StringComparison.Ordinal);
        }

        string opted = diagnostics.CreateReport(new DiagnosticReportOptions { IncludeLogEntries = true, MaximumLogEntries = 10 }).Preview().Text;
        Assert.Contains("operation.completed", opted, StringComparison.Ordinal);

        // Structurally: nothing in the public surface can carry a dump, a file, a path, a stream or an attachment.
        foreach (Type type in typeof(DesktopDiagnostics).Assembly.GetExportedTypes())
        {
            foreach (MemberInfo member in type.GetMembers(BindingFlags.Public | BindingFlags.Instance | BindingFlags.Static | BindingFlags.DeclaredOnly))
            {
                foreach (string forbidden in new[] { "Dump", "Attachment", "Attach", "FilePath", "Stream" })
                {
                    Assert.DoesNotContain(forbidden, member.Name, StringComparison.OrdinalIgnoreCase);
                }
            }
        }

        Assert.Throws<ArgumentOutOfRangeException>(() => diagnostics.CreateReport(new DiagnosticReportOptions { IncludeLogEntries = true, MaximumLogEntries = 1001 }));
    }

    [Fact]
    public void MarkersPlantedInTheStoredLogNeverReachAReportOrTheLocalView()
    {
        using var directory = new TestDirectory();
        string[] lines =
        [
            "{\"v\":1,\"t\":\"2026-10-02T08:00:00.0000000Z\",\"n\":\"C:\\\\Users\\\\" + Marker + "\\\\x\",\"l\":\"Information\",\"tier\":\"LocalMinimal\",\"f\":{\"Authorization\":\"Bearer " + Marker + "\",\"task.id\":\"" + Marker + "\",\"reason.code\":\"" + Marker + "\",\"prompt\":\"" + Marker + "\",\"support.reference\":\"" + Marker + "\"}}",
            "{\"v\":1,\"t\":\"2026-10-02T08:00:01.0000000Z\",\"n\":\"ok.name\",\"l\":\"Information\",\"tier\":\"LocalMinimal\",\"f\":{\"service.name\":\"Storage\",\"" + Marker + "\":\"x\",\"duration.ms\":12.5}}",
            "this is not json " + Marker,
            "{\"v\":1,\"t\":\"2026-10-02T08:00:02.0000000Z\",\"n\":\"ok.name\",\"l\":\"" + Marker + "\",\"tier\":\"LocalMinimal\",\"f\":{}}",
        ];
        File.WriteAllText(Path.Combine(directory.Path, "diagnostics-00000001.jsonl"), string.Join('\n', lines) + "\n");
        using DesktopDiagnostics diagnostics = Fixtures.Open(directory.Path);

        IReadOnlyList<LocalDiagnosticEntry> view = diagnostics.ReadRecent(100);
        Assert.Equal(2, view.Count);
        Assert.Equal("redacted", view[0].Name);
        Assert.Empty(view[0].Fields);
        Assert.Equal("ok.name", view[1].Name);
        Assert.Equal(["duration.ms", "service.name"], view[1].Fields.Keys.Order(StringComparer.Ordinal).ToArray());
        Assert.Equal(12.5, view[1].Fields["duration.ms"]);

        string report = diagnostics.CreateReport(new DiagnosticReportOptions { IncludeLogEntries = true }).Preview().Text;
        Assert.DoesNotContain(Marker, report, StringComparison.Ordinal);
        Assert.Contains("\"skippedEntries\": 2", report, StringComparison.Ordinal);
    }
}
