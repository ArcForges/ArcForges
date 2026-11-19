// SPDX-License-Identifier: AGPL-3.0-only
using System.Text;

namespace ArcForges.Node.Store;

internal sealed partial class DurableCommandStore
{
    /// <summary>Settles observed TTL expiry outside any caller command, retaining it across clock rollback and restore.</summary>
    internal int ObserveGrantExpirations(DateTimeOffset now)
    {
        lock (_gate)
        {
            ObjectDisposedException.ThrowIf(_disposed, this);
            if (MaintenanceRequired)
            {
                throw new DurableStoreMaintenanceException();
            }

            var due = _store.Read(reader => RemoteGrantRecords.DueExpirations(reader, _owner, now));
            if (due.Count == 0)
            {
                return 0;
            }

            using var observation = new MemoryStream();
            using (var writer = new BinaryWriter(observation, Encoding.UTF8, leaveOpen: true))
            {
                writer.Write(now.UtcTicks);
                writer.Write(due.Count);
                foreach (var grant in due)
                {
                    writer.Write(grant.GrantId);
                    writer.Write(grant.EnrollmentId);
                    writer.Write(grant.Revision);
                }
            }

            Advance("observe_grant_expiry", "automatic", observation.ToArray(), transaction =>
            {
                foreach (var grant in due)
                {
                    RemoteGrantRecords.ObserveExpiration(transaction, _owner, grant, now);
                }
            });
            return due.Count;
        }
    }
}
