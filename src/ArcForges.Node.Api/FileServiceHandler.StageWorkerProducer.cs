// SPDX-License-Identifier: AGPL-3.0-only
using System.Diagnostics;
using System.Security.Cryptography;
using ArcForges.Node.Core.Files;
using ArcForges.Node.Core.Platform;
using ArcForges.Node.Store;

namespace ArcForges.Node.Api;

internal sealed partial class FileServiceHandler
{
    /// <summary>Writes no stage body in the Node process. FULL metadata acknowledgements gate the actual owned worker.</summary>
    private async Task<WorkspaceEmptyNamedStage> ProduceApprovalObjectAsync(Caller caller, ApprovalProducerLease lease,
        int slot, ReadOnlyMemory<byte> body, long started, TimeSpan limit, CancellationToken token)
    {
        var reservation = lease.Production ?? throw new InvalidOperationException("The FULL producer reservation is unavailable.");
        var root = lease.Use!.Root;
        var directory = lease.StageDirectory!;
        var name = slot == 1 ? lease.OriginalName! : lease.IntendedName!;
        Task BeforeEachEffect() => node.Processor.ExecuteAsync(command =>
        {
            CheckStageApprovalAuthority(command.Transaction, caller, started, limit, token);
            RequireOriginalProducerDeadline(reservation, token);
            CheckApprovalProducerNames(lease);
            return true;
        }, CommitDurability.Full);

        Task CommitEmpty(Microsoft.Win32.SafeHandles.SafeFileHandle file, Action nativeVerifier) =>
            node.Processor.ExecuteAsync(command =>
            {
                CheckStageApprovalAuthority(command.Transaction, caller, started, limit, token);
                RequireOriginalProducerDeadline(reservation, token);
                CheckApprovalProducerNames(lease);
                PrivateStageRegistry.BindWorkerEmptyForProtection(command.Transaction, reservation, slot, root, directory,
                    name, file, nativeVerifier, token, transactionPrivateName: OperatingSystem.IsWindows());
                return true;
            }, CommitDurability.Full);

        WorkspaceEmptyNamedStage? produced = null;
        try
        {
            if (OperatingSystem.IsLinux())
            {
                var worker = await LinuxFileEffectController.StartAsync(node.Settings.TestMode, token).ConfigureAwait(false);
                try
                {
                    var sealedWorker = worker.SealedWorker;
                    var binding = await node.Processor.ExecuteAsync(command =>
                    {
                        CheckStageApprovalAuthority(command.Transaction, caller, started, limit, token);
                        RequireOriginalProducerDeadline(reservation, token);
                        CheckApprovalProducerNames(lease);
                        return FileStageProduction.RecordLinuxChild(command.Transaction, reservation, slot, sealedWorker);
                    }, CommitDurability.Full).ConfigureAwait(false);
                    produced = await worker.ExecutePrivateStageAsync(binding, root, directory, body, CommitEmpty, BeforeEachEffect, token)
                        .ConfigureAwait(false);
                }
                finally { worker.Shutdown(afterExit: null); }
            }
            else if (OperatingSystem.IsWindows())
            {
                var worker = await WindowsStageWorkerController.StartAsync(node.Settings.TestMode, token).ConfigureAwait(false);
                try
                {
                    var sealedWorker = worker.SealedWorker;
                    var binding = await node.Processor.ExecuteAsync(command =>
                    {
                        CheckStageApprovalAuthority(command.Transaction, caller, started, limit, token);
                        RequireOriginalProducerDeadline(reservation, token);
                        CheckApprovalProducerNames(lease);
                        return FileStageProduction.RecordWindowsChild(command.Transaction, reservation, slot, sealedWorker);
                    }, CommitDurability.Full).ConfigureAwait(false);
                    produced = await worker.ExecuteNamedAsync(binding, root, directory, body, CommitEmpty, BeforeEachEffect, token)
                        .ConfigureAwait(false);
                }
                finally { worker.Shutdown(afterExit: null); }
            }
            else throw new PlatformNotSupportedException();

            await node.Processor.ExecuteAsync(command =>
            {
                CheckStageApprovalAuthority(command.Transaction, caller, started, limit, token);
                RequireOriginalProducerDeadline(reservation, token);
                CheckApprovalProducerNames(lease);
                produced.Guard.CheckIntact();
                using var actual = produced.Guard.ReadForMutation(token);
                var hash = SHA256.HashData(body.Span);
                if (actual.Bytes.Length != body.Length || !CryptographicOperations.FixedTimeEquals(actual.Sha256.Span, hash))
                    throw new WorkspacePathException("file_identity_changed");
                FileStageProduction.CompleteNamedObject(command.Transaction, reservation, slot, produced.Identity, body.Length, hash);
                produced.Guard.CheckIntact();
                return true;
            }, CommitDurability.Full).ConfigureAwait(false);
            var result = produced;
            produced = null;
            return result;
        }
        finally { produced?.Dispose(); }
    }

    private static void RequireOriginalProducerDeadline(FileStageProductionReservation reservation, CancellationToken token)
    {
        token.ThrowIfCancellationRequested();
        var now = OperatingSystem.IsLinux() ? LinuxFatalDeadline.MonotonicNanoseconds() : Stopwatch.GetTimestamp();
        if (now >= reservation.DeadlineTicks) throw new OperationCanceledException(token);
    }

    private static void CheckApprovalProducerNames(ApprovalProducerLease lease)
    {
        var root = lease.Use!.Root;
        using var checkedRoot = WorkspacePath.OpenRoot(root.RootPath, root.RootIdentity);
        var parentName = lease.ParentRelativePath!;
        var parent = root.OpenDirectory(parentName);
        var actual = WorkspacePath.Identity(parent);
        if (lease.ParentIdentity is not { } expected || !expected.SameObject(actual) || !actual.IsDirectory || actual.Links == 0)
            throw new WorkspacePathException("directory_identity_changed");
    }
}
