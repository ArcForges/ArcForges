// SPDX-License-Identifier: AGPL-3.0-only
using ArcForges.Node.Store;

namespace ArcForges.Node.Core.Sandboxes;

internal sealed partial class SandboxManager
{
    internal void VerifyExistingAuthority()
    {
        lock (OwnershipGate)
        {
            if (DurableCommandStore.HasExistingAuthority(_store, OwnerId))
            {
                _ = Receipts;
            }
            else if (_store.Read(reader => RunRecords.ListNonterminal(reader, OwnerId).Count != 0))
            {
                throw new DurableStoreMaintenanceException();
            }
        }
    }
}
