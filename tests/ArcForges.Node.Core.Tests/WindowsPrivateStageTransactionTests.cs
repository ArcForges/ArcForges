// SPDX-License-Identifier: AGPL-3.0-only
using System.Diagnostics;
using System.Runtime.Versioning;
using System.Security.Cryptography;
using ArcForges.Node.Core.Files;
using ArcForges.Node.Core.Platform;

namespace ArcForges.Node.Core.Tests;

/// <summary>Real kernel transaction and empty-file primitives; no producer journal, approval or lifecycle acceptance.</summary>
[Trait("env", "windows-real")]
public sealed class WindowsPrivateStageTransactionTests
{
    [Fact(Timeout = 30_000)]
    [SupportedOSPlatform("windows")]
    public void EmptyStageCommitsExactIdentityThenRequiresOrdinaryExclusiveReopen()
    {
        if (!OperatingSystem.IsWindows()) { Assert.Skip("Windows native private transaction."); return; }
        using var fixture = new OwnedDirectory();
        using var root = WorkspacePath.OpenRoot(fixture.Path);
        var binding = Binding(root, TimeSpan.FromSeconds(8));
        RegisteredWorkspaces.RootIdentity recorded;
        using (var transaction = WindowsPrivateStageTransaction.Arm(binding.Deadline, binding.ExpiryMicroseconds))
        using (var file = WorkspacePath.CreateWindowsTransactionalEmptyStage(root.RootHandle, binding, transaction))
        {
            recorded = RegisteredWorkspaces.RootIdentity.Encode(WorkspacePath.Identity(file), directory: false);
            Assert.Equal(0, RandomAccess.GetLength(file));
            Assert.ThrowsAny<IOException>(() => File.OpenHandle(Path.Combine(fixture.Path, binding.Name),
                FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete));
            WorkspacePath.CheckWindowsTransactionalStage(file, root.RootHandle, binding, transaction);
            transaction.Commit();
            transaction.ConfirmCommitted();
            // A committed transacted HANDLE is not an ordinary read/write guard; its exclusive share stays held.
            Assert.Throws<WorkspacePathException>(() => root.ReopenWindowsPrivateNamedStage(
                recorded, binding.Name, 0, SHA256.HashData([]), TestContext.Current.CancellationToken));
        }
        using var reopened = root.ReopenWindowsPrivateNamedStage(recorded, binding.Name, 0, SHA256.HashData([]),
            TestContext.Current.CancellationToken);
        Assert.True(reopened.MatchesExpectedContent(SHA256.HashData([]), 0, TestContext.Current.CancellationToken));
    }

    [Fact(Timeout = 30_000)]
    [SupportedOSPlatform("windows")]
    public async Task NativeTimeoutAbortsHeldEmptyObjectAndRejectsAWriteWithoutUserCodeChecks()
    {
        if (!OperatingSystem.IsWindows()) { Assert.Skip("Windows native private transaction."); return; }
        using var fixture = new OwnedDirectory();
        using var root = WorkspacePath.OpenRoot(fixture.Path);
        var binding = Binding(root, TimeSpan.FromSeconds(2));
        using var transaction = WindowsPrivateStageTransaction.Arm(binding.Deadline, binding.ExpiryMicroseconds);
        using var file = WorkspacePath.CreateWindowsTransactionalEmptyStage(root.RootHandle, binding, transaction);
        await Task.Delay(TimeSpan.FromMilliseconds(transaction.TimeoutMilliseconds + 300),
            TestContext.Current.CancellationToken);
        Assert.ThrowsAny<IOException>(() => RandomAccess.Write(file, "must-not-write"u8, 0));
        Assert.ThrowsAny<IOException>(() => transaction.Commit());
        Assert.False(File.Exists(Path.Combine(fixture.Path, binding.Name)));
    }

    [Fact(Timeout = 30_000)]
    [SupportedOSPlatform("windows")]
    public void ExistingNameIsNotReplacedAndWrongParentIdentityIsRejected()
    {
        if (!OperatingSystem.IsWindows()) { Assert.Skip("Windows native relative private creation."); return; }
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        using var fixture = new OwnedDirectory();
        using var otherFixture = new OwnedDirectory();
        using var root = WorkspacePath.OpenRoot(fixture.Path);
        using var other = WorkspacePath.OpenRoot(otherFixture.Path);
        var binding = Binding(root, TimeSpan.FromSeconds(8));
        var path = Path.Combine(fixture.Path, binding.Name);
        File.WriteAllBytes(path, "existing-fixture"u8.ToArray());
        using var transaction = WindowsPrivateStageTransaction.Arm(binding.Deadline, binding.ExpiryMicroseconds);
        Assert.Throws<WorkspacePathException>(() =>
            WorkspacePath.CreateWindowsTransactionalEmptyStage(root.RootHandle, binding, transaction));
        Assert.Throws<WorkspacePathException>(() =>
            WorkspacePath.CreateWindowsTransactionalEmptyStage(other.RootHandle, binding, transaction));
        Assert.Equal("existing-fixture"u8.ToArray(), File.ReadAllBytes(path));
        Assert.Empty(Directory.EnumerateFileSystemEntries(otherFixture.Path));
    }

    [SupportedOSPlatform("windows")]
    private static WindowsPrivateStageBinding Binding(WorkspacePath root, TimeSpan duration)
    {
        using var process = Process.GetCurrentProcess();
        var command = Guid.NewGuid().ToByteArray();
        var identity = RegisteredWorkspaces.RootIdentity.Encode(root.RootIdentity, directory: true).Bytes;
        return new WindowsPrivateStageBinding(command, RandomNumberGenerator.GetBytes(16), RandomNumberGenerator.GetBytes(16),
            SHA256.HashData("fixture-request"u8), SHA256.HashData("fixture-caller"u8), Guid.NewGuid().ToByteArray(),
            Guid.NewGuid().ToByteArray(), 2, identity, identity, ".arcforges-stage-" + Convert.ToHexStringLower(command) + "-2",
            0, SHA256.HashData([]), checked(Stopwatch.GetTimestamp() + (long)(duration.TotalSeconds * Stopwatch.Frequency)),
            checked((DateTime.UtcNow.Ticks - DateTime.UnixEpoch.Ticks) / 10 + (long)(duration.TotalMilliseconds * 1000)),
            new WindowsOwnedStageIdentity(BootIdentity.Read(), Environment.ProcessId,
                WindowsOwnedStageProcess.CreationTimeOf(process.SafeHandle)));
    }

    private sealed class OwnedDirectory : IDisposable
    {
        private readonly DirectoryInfo _directory = Directory.CreateTempSubdirectory("arcforges-windows-stage-transaction-");
        internal string Path => _directory.FullName;
        public void Dispose() => _directory.Delete(recursive: true);
    }
}
