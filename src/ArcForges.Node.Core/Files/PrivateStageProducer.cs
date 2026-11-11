// SPDX-License-Identifier: AGPL-3.0-only
using ArcForges.Node.Core.Platform;
using ArcForges.Node.Store;

namespace ArcForges.Node.Core.Files;

/// <summary>Creates and binds a still-empty named stage in one Node writer transaction.</summary>
internal static class PrivateStageProducer
{
    /// <summary>
    /// The reservation must already be FULL committed. No routed read can take an identity snapshot between creation
    /// and binding because both use the Node writer. This method returns only after the identity is FULL committed;
    /// the caller owns the returned guard and may then use <see cref="PrivateStageRegistry.WriteBoundStage"/>.
    /// On a failed callback or commit this method closes its created guard. A caller abandoning this task must still
    /// observe it and dispose any successful result; cancellation does not interrupt a running native operation.
    /// </summary>
    internal static async Task<WorkspaceEmptyNamedStage> CreateBoundAsync(CommandProcessor processor, ReadOnlyMemory<byte> commandId,
        int slot, WorkspacePath workspaceRoot, WorkspacePath stageDirectory, string name, CancellationToken cancellationToken,
        Action? afterCreateForTests = null, Action? afterBindForTests = null)
    {
        ArgumentNullException.ThrowIfNull(processor);
        ArgumentNullException.ThrowIfNull(workspaceRoot);
        ArgumentNullException.ThrowIfNull(stageDirectory);
        StoreIds.Validate(commandId.Span, nameof(commandId));
        var stableId = commandId.ToArray();
        WorkspaceEmptyNamedStage? created = null;
        try
        {
            return await processor.ExecuteAsync(command =>
            {
                cancellationToken.ThrowIfCancellationRequested();
                created = stageDirectory.CreateEmptyPrivateNamedStage(name, cancellationToken);
                afterCreateForTests?.Invoke();
                PrivateStageRegistry.BindEmptyForProtection(command.Transaction, stableId, slot, workspaceRoot,
                    stageDirectory, name, created.Guard, cancellationToken);
                afterBindForTests?.Invoke();
                return created;
            }, CommitDurability.Full).ConfigureAwait(false);
        }
        catch
        {
            created?.Dispose();
            throw;
        }
    }
}
