// SPDX-License-Identifier: AGPL-3.0-only
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
}
