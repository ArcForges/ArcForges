// SPDX-License-Identifier: AGPL-3.0-only
using System.Globalization;
using System.Text.Json;
using System.Text.Json.Nodes;
using ArcForges.Contracts.Foundation.V1;
using ArcForges.Node.Store;

namespace ArcForges.Node.Core.Sandboxes;

internal sealed partial class SandboxManager
{
    private static string DataReceiptBody(StoredTransfer row, ArcError? error = null)
    {
        var result = JsonNode.Parse(ResultBody(row.Manifest.Revision, null, error?.Category ?? ErrorCategory.Unspecified,
            error?.Code, error?.Details.State.Reason))!.AsObject();
        result["transfer"] = new JsonObject
        {
            ["state"] = (int)row.State,
            ["verifiedOffset"] = row.VerifiedOffset,
            ["sha256"] = row.ExpectedSha256,
            ["closedAt"] = row.ClosedAt?.ToString("O", CultureInfo.InvariantCulture),
        };
        return result.ToJsonString();
    }

    private static StoredTransfer ReadDataReceiptObservation(StoredTransfer latest, string body)
    {
        using var document = JsonDocument.Parse(body);
        var receipt = document.RootElement;
        if (!receipt.TryGetProperty("transfer", out var observation))
        {
            return latest;
        }

        var closure = observation.GetProperty("closedAt");
        return latest with
        {
            Manifest = latest.Manifest with { Revision = receipt.GetProperty("revision").GetInt64() },
            State = (StoredTransferState)observation.GetProperty("state").GetInt32(),
            VerifiedOffset = observation.GetProperty("verifiedOffset").GetInt64(),
            ExpectedSha256 = observation.GetProperty("sha256").GetString() ?? string.Empty,
            ClosedAt = closure.ValueKind == JsonValueKind.Null ? null
                : DateTimeOffset.Parse(closure.GetString()!, CultureInfo.InvariantCulture, DateTimeStyles.RoundtripKind),
        };
    }
}
