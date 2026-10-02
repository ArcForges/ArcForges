// SPDX-License-Identifier: AGPL-3.0-only
using System.Buffers;
using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace ArcForges.Observability.Desktop;

/// <summary>A crash the previous run recorded, kept locally until the user sends or dismisses its report.</summary>
internal sealed record CrashMarker(string ReasonCode, DateTimeOffset RecordedAt, string SupportReference);

/// <summary>
/// Builds the text of a diagnostic report. The format has no field that could hold a memory dump, a file path,
/// document content or a secret: it carries identity, consent state, the reason code of a recorded crash and, only when
/// the user opted in, reviewed local log entries. The text is what the user is shown and what is sent, byte for byte.
/// </summary>
internal static class DiagnosticReportWriter
{
    internal const int FormatVersion = 1;

    internal static (string Text, string Digest) Build(ObservabilityContext identity, TelemetryConsentState consent,
        DiagnosticReportOrigin origin, string supportReference, DateTimeOffset generatedAt, CrashMarker? crash,
        IReadOnlyList<LocalDiagnosticEntry>? entries, int skipped)
    {
        var buffer = new ArrayBufferWriter<byte>();
        using (var writer = new Utf8JsonWriter(buffer, new JsonWriterOptions { Indented = true, NewLine = "\n" }))
        {
            writer.WriteStartObject();
            writer.WriteNumber("schema", FormatVersion);
            writer.WriteString("kind", "arcforges.diagnostic-report");
            writer.WriteString("supportReference", supportReference);
            writer.WriteString("origin", origin == DiagnosticReportOrigin.PreviousCrash ? "previousCrash" : "userRequested");
            writer.WriteString("generatedAt", generatedAt.ToUniversalTime().ToString("O", CultureInfo.InvariantCulture));

            writer.WriteStartObject("identity");
            writer.WriteString("application.id", identity.ApplicationId);
            writer.WriteString("build.id", identity.BuildId);
            writer.WriteString("deployment.environment", identity.Environment.ToString());
            writer.WriteString("instance.id", identity.InstanceId.Value.ToString("N", CultureInfo.InvariantCulture));
            writer.WriteEndObject();

            writer.WriteString("telemetryConsent", TelemetryConsent.Describe(consent));

            if (crash is not null)
            {
                writer.WriteStartObject("crash");
                writer.WriteString("reason.code", crash.ReasonCode);
                writer.WriteString("recordedAt", crash.RecordedAt.ToUniversalTime().ToString("O", CultureInfo.InvariantCulture));
                writer.WriteEndObject();
            }

            writer.WriteStartObject("includes");
            writer.WriteNumber("logEntries", entries?.Count ?? 0);
            writer.WriteBoolean("memoryDump", false);
            writer.WriteBoolean("filePaths", false);
            writer.WriteBoolean("documentContent", false);
            writer.WriteBoolean("secrets", false);
            writer.WriteEndObject();

            if (entries is not null)
            {
                writer.WriteNumber("skippedEntries", skipped);
                writer.WriteStartArray("logEntries");
                foreach (LocalDiagnosticEntry entry in entries)
                {
                    DiagnosticEntryFormat.WriteEntry(writer, entry.OccurredAt, entry.Name, entry.Level, entry.Tier, entry.Fields);
                }

                writer.WriteEndArray();
            }

            writer.WriteEndObject();
        }

        string text = Encoding.UTF8.GetString(buffer.WrittenSpan);
        return (text, Convert.ToHexStringLower(SHA256.HashData(buffer.WrittenSpan)));
    }
}
