// SPDX-License-Identifier: AGPL-3.0-only
using System.Text.Json;

namespace ArcForges.Node.Store;

internal sealed partial class DurableCommandStore
{
    private const string InterruptedCenterControl = """{"code":"outcome_unknown","reason":"center_control_interrupted"}""";

    /// <summary>Retains interrupted control effects before this owner starts serving new Center controls.</summary>
    internal void RecoverInterruptedCenterControls()
    {
        lock (_gate)
        {
            ObjectDisposedException.ThrowIf(_disposed, this);
            if (MaintenanceRequired) throw new DurableStoreMaintenanceException();

            var interrupted = _store.Read(reader =>
            {
                using var select = reader.CreateCommand("""
                    SELECT command_id FROM command_receipt
                    WHERE owner_id=$owner AND owner_epoch=$epoch AND state='ACCEPTED' AND method IN (
                        'CenterControlService.BeginConnect','CenterControlService.CancelConnect',
                        'CenterControlService.Disconnect','CenterControlService.SignOut')
                    ORDER BY admission_sequence LIMIT $limit;
                    """);
                StoreReader.Bind(select, [("$owner", _owner), ("$epoch", _fence.Epoch), ("$limit", _capacity.MaximumReceipts)]);
                using var rows = select.ExecuteReader();
                var commands = new List<byte[]>();
                while (rows.Read())
                {
                    commands.Add(Convert.FromHexString(rows.GetString(0)));
                }

                return commands;
            });

            foreach (var command in interrupted)
            {
                _ = SetResult(command, "UNKNOWN", 3, InterruptedCenterControl);
            }
        }
    }

    /// <summary>Reads the latest durable revocation observation or completed reset for this owner epoch.</summary>
    internal string LatestCenterRemoteRevocation()
    {
        lock (_gate)
        {
            ObjectDisposedException.ThrowIf(_disposed, this);
            if (MaintenanceRequired) throw new DurableStoreMaintenanceException();

            return _store.Read(reader =>
            {
                using var select = reader.CreateCommand("""
                    SELECT method,state,response_json FROM command_receipt
                    WHERE owner_id=$owner AND owner_epoch=$epoch AND (
                        (method='CenterControlService.BeginConnect' AND state='SUCCEEDED' AND effect_certainty=2)
                        OR (method='CenterControlService.SignOut' AND
                            (state IN ('ACCEPTED','UNKNOWN') OR (state='SUCCEEDED' AND effect_certainty=2))))
                    ORDER BY admission_sequence DESC LIMIT 1;
                    """);
                StoreReader.Bind(select, [("$owner", _owner), ("$epoch", _fence.Epoch)]);
                using var rows = select.ExecuteReader();
                if (!rows.Read() || rows.GetString(0) == "CenterControlService.BeginConnect")
                    return "not_requested";
                if (rows.GetString(1) != "SUCCEEDED" || rows.IsDBNull(2))
                    return "unknown";

                using var document = JsonDocument.Parse(rows.GetString(2));
                return document.RootElement.ValueKind == JsonValueKind.Object
                    && document.RootElement.TryGetProperty("centerRemoteRevocation", out var value)
                    && value.ValueKind == JsonValueKind.String
                    && value.GetString() is { } status && status is "unknown" or "confirmed" or "not_requested"
                    ? status : "unknown";
            });
        }
    }
}
