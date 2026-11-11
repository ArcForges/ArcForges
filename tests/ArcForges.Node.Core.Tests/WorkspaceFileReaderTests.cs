// SPDX-License-Identifier: AGPL-3.0-only
using System.Security.Cryptography;
using ArcForges.Node.Core.Files;
using ArcForges.Node.Core.Platform;

namespace ArcForges.Node.Core.Tests;

/// <summary>Real native range reads; these are component tests, not registered-root RPC or center acceptance.</summary>
[Trait("feature", "workspace-read")]
public sealed class WorkspaceFileReaderTests
{
    [Fact(Timeout = 30_000)]
    public void OversizedRequestReturnsBoundedBytesAndAnExactContinuation()
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        using var fixture = new OwnedDirectory();
        var bytes = Enumerable.Range(0, 100_003).Select(i => (byte)(i % 251)).ToArray();
        File.WriteAllBytes(Path.Combine(fixture.Path, "payload.bin"), bytes);
        using var root = WorkspacePath.OpenRoot(fixture.Path);
        var first = WorkspaceFileReader.Read(root, "payload.bin", 0, ulong.MaxValue, TestContext.Current.CancellationToken);
        Assert.Equal(65_536, first.Bytes.Length);
        Assert.Equal(65_536UL, first.NextOffset);
        Assert.Equal((ulong)bytes.Length, first.FileSize);
        Assert.False(first.Eof);
        Assert.Equal(bytes[..65_536], first.Bytes.ToArray());
        Assert.Equal(SHA256.HashData(bytes[..65_536]), first.Sha256.ToArray());
        var second = WorkspaceFileReader.Read(root, "payload.bin", first.NextOffset, ulong.MaxValue, TestContext.Current.CancellationToken);
        Assert.True(second.Eof);
        Assert.Equal((ulong)bytes.Length, second.NextOffset);
        Assert.Equal(bytes[65_536..], second.Bytes.ToArray());
        Assert.Equal(SHA256.HashData(bytes[65_536..]), second.Sha256.ToArray());
    }

    [Theory]
    [InlineData(4UL)]
    [InlineData(5UL)]
    [InlineData(ulong.MaxValue)]
    public void AtOrBeyondEofKeepsTheRequestedOffsetWithoutOverflow(ulong offset)
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        using var fixture = new OwnedDirectory();
        File.WriteAllBytes(Path.Combine(fixture.Path, "four.bin"), [1, 2, 3, 4]);
        using var root = WorkspacePath.OpenRoot(fixture.Path);
        var value = WorkspaceFileReader.Read(root, "four.bin", offset, 1, TestContext.Current.CancellationToken);
        Assert.Empty(value.Bytes.ToArray());
        Assert.Equal(offset, value.Offset);
        Assert.Equal(offset, value.NextOffset);
        Assert.Equal(4UL, value.FileSize);
        Assert.True(value.Eof);
        Assert.Equal(SHA256.HashData(ReadOnlySpan<byte>.Empty), value.Sha256.ToArray());
    }

    [Fact(Timeout = 30_000)]
    public void OffsetsCountRawBytesIncludingInsideUtf8Scalars()
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        using var fixture = new OwnedDirectory();
        File.WriteAllBytes(Path.Combine(fixture.Path, "utf8.bin"), "A😀Z"u8.ToArray());
        using var root = WorkspacePath.OpenRoot(fixture.Path);
        var value = WorkspaceFileReader.Read(root, "utf8.bin", 2, 2, TestContext.Current.CancellationToken);
        Assert.Equal(new byte[] { 0x9f, 0x98 }, value.Bytes.ToArray());
        Assert.Equal(4UL, value.NextOffset);
        Assert.Equal(6UL, value.FileSize);
        Assert.False(value.Eof);
        Assert.Equal(SHA256.HashData(new byte[] { 0x9f, 0x98 }), value.Sha256.ToArray());
    }

    [Fact(Timeout = 30_000)]
    public void EmptyFilesHaveAnExplicitEmptyDigest()
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        using var fixture = new OwnedDirectory();
        File.WriteAllBytes(Path.Combine(fixture.Path, "empty.bin"), []);
        using var root = WorkspacePath.OpenRoot(fixture.Path);
        var value = WorkspaceFileReader.Read(root, "empty.bin", 0, 64, TestContext.Current.CancellationToken);
        Assert.True(value.Eof);
        Assert.Equal(0UL, value.FileSize);
        Assert.Equal(0UL, value.NextOffset);
        Assert.Empty(value.Bytes.ToArray());
        Assert.Equal(Convert.FromHexString("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"), value.Sha256.ToArray());
    }

    [Fact(Timeout = 30_000)]
    public void InvalidLengthAndCancellationDoNotOpenTheRequestedFile()
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        using var fixture = new OwnedDirectory();
        using var root = WorkspacePath.OpenRoot(fixture.Path);
        Assert.Throws<ArgumentOutOfRangeException>(() => WorkspaceFileReader.Read(root, "missing.bin", 0, 0, TestContext.Current.CancellationToken));
        using var cancelled = new CancellationTokenSource();
        cancelled.Cancel();
        Assert.Throws<OperationCanceledException>(() => WorkspaceFileReader.Read(root, "missing.bin", 0, 1, cancelled.Token));
    }

    [Fact(Timeout = 30_000)]
    public void CancellationAtEofRefusesWithoutInventingAContentDigest()
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        using var fixture = new OwnedDirectory();
        File.WriteAllBytes(Path.Combine(fixture.Path, "four.bin"), [1, 2, 3, 4]);
        using var root = WorkspacePath.OpenRoot(fixture.Path);
        using var cancelled = new CancellationTokenSource();
        var failure = Assert.Throws<WorkspaceReadException>(() => WorkspaceFileReader.Read(root, "four.bin", 4, 1, phase =>
        {
            if (phase == WorkspaceReadCheckpoint.AfterInitialSize)
            {
                cancelled.Cancel();
            }
        }, cancelled.Token));
        Assert.Equal("file_read_cancelled", failure.Reason);
        Assert.Equal(0, failure.ObservedBytes);
        Assert.Null(failure.ObservedSha256);
    }

    [Fact(Timeout = 30_000)]
    public void CancellationAfterPartialNativeReadsPreservesOnlyObservedByteDigest()
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        using var fixture = new OwnedDirectory();
        var bytes = Enumerable.Range(0, 65_536).Select(i => (byte)(i % 251)).ToArray();
        File.WriteAllBytes(Path.Combine(fixture.Path, "payload.bin"), bytes);
        using var root = WorkspacePath.OpenRoot(fixture.Path);
        using var cancelled = new CancellationTokenSource();
        var failure = Assert.Throws<WorkspaceReadException>(() => WorkspaceFileReader.Read(root, "payload.bin", 0, (ulong)bytes.Length, phase =>
        {
            if (phase == WorkspaceReadCheckpoint.AfterBytesRead)
            {
                cancelled.Cancel();
            }
        }, cancelled.Token));
        Assert.Equal("file_read_cancelled", failure.Reason);
        Assert.InRange(failure.ObservedBytes, 1, bytes.Length - 1);
        Assert.NotNull(failure.ObservedSha256);
        Assert.Equal(SHA256.HashData(bytes.AsSpan(0, failure.ObservedBytes)), failure.ObservedSha256.Value.ToArray());
    }

    [Fact(Timeout = 30_000)]
    [Trait("env", "linux-real")]
    public void GrowthAfterTheInitialEofCheckIsNotAZeroProgressContinuation()
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        Assert.SkipUnless(OperatingSystem.IsLinux(), "Linux competing writer on an open file");
        using var fixture = new OwnedDirectory();
        var path = Path.Combine(fixture.Path, "four.bin");
        File.WriteAllBytes(path, [1, 2, 3, 4]);
        using var root = WorkspacePath.OpenRoot(fixture.Path);
        var failure = Assert.Throws<WorkspaceReadException>(() => WorkspaceFileReader.Read(root, "four.bin", 4, 1, phase =>
        {
            if (phase == WorkspaceReadCheckpoint.AfterInitialSize)
            {
                using var writer = new FileStream(path, FileMode.Append, FileAccess.Write, FileShare.ReadWrite);
                writer.WriteByte(5);
            }
        }, TestContext.Current.CancellationToken));
        Assert.Equal("file_changed_while_reading", failure.Reason);
        Assert.Equal(0, failure.ObservedBytes);
        Assert.Null(failure.ObservedSha256);
        Assert.Equal(new byte[] { 1, 2, 3, 4, 5 }, File.ReadAllBytes(path));
    }

    [Fact(Timeout = 30_000)]
    [Trait("env", "linux-real")]
    public void HardLinkAddedAfterInitialEofCheckFailsTheFinalIdentityCheck()
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        Assert.SkipUnless(OperatingSystem.IsLinux(), "Linux competing hard-link change");
        using var fixture = new OwnedDirectory();
        var path = Path.Combine(fixture.Path, "four.bin");
        var alias = Path.Combine(fixture.Path, "alias.bin");
        File.WriteAllBytes(path, [1, 2, 3, 4]);
        using var root = WorkspacePath.OpenRoot(fixture.Path);
        var failure = Assert.Throws<WorkspaceReadException>(() => WorkspaceFileReader.Read(root, "four.bin", 4, 1, phase =>
        {
            if (phase == WorkspaceReadCheckpoint.AfterInitialSize)
            {
                using var process = System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo("ln", [path, alias])
                {
                    RedirectStandardError = true,
                    CreateNoWindow = true,
                })!;
                var error = process.StandardError.ReadToEnd();
                Assert.True(process.WaitForExit(10_000) && process.ExitCode == 0, "hard-link setup: " + error);
            }
        }, TestContext.Current.CancellationToken));
        Assert.Equal("file_changed_while_reading", failure.Reason);
        Assert.Equal(0, failure.ObservedBytes);
        Assert.Null(failure.ObservedSha256);
        Assert.Equal(new byte[] { 1, 2, 3, 4 }, File.ReadAllBytes(alias));
    }

    [Fact(Timeout = 30_000)]
    [Trait("env", "linux-real")]
    public void ReplacingTheNameAfterTheActualReadIsNotReportedAsAStableRead()
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        Assert.SkipUnless(OperatingSystem.IsLinux(), "Linux namespace substitution during the held read");
        using var fixture = new OwnedDirectory();
        var path = Path.Combine(fixture.Path, "file.bin");
        var moved = Path.Combine(fixture.Path, "old.bin");
        byte[] original = [1, 2, 3, 4];
        File.WriteAllBytes(path, original);
        using var root = WorkspacePath.OpenRoot(fixture.Path);
        var failure = Assert.Throws<WorkspaceReadException>(() => WorkspaceFileReader.Read(root, "file.bin", 0, 4, phase =>
        {
            if (phase == WorkspaceReadCheckpoint.AfterBytesRead)
            {
                File.Move(path, moved);
                File.WriteAllBytes(path, [5, 6, 7, 8]);
            }
        }, TestContext.Current.CancellationToken));
        Assert.Equal("file_changed_while_reading", failure.Reason);
        Assert.Equal(4, failure.ObservedBytes);
        Assert.Equal(SHA256.HashData(original), failure.ObservedSha256!.Value.ToArray());
        Assert.Equal(original, File.ReadAllBytes(moved));
        Assert.Equal(new byte[] { 5, 6, 7, 8 }, File.ReadAllBytes(path));
    }

    [Fact(Timeout = 30_000)]
    [Trait("env", "linux-real")]
    public void SameLengthObservedContentChangeDuringReadIsNotReportedAsStable()
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        Assert.SkipUnless(OperatingSystem.IsLinux(), "Linux competing write while the read handle is open");
        using var fixture = new OwnedDirectory();
        var path = Path.Combine(fixture.Path, "file.bin");
        var original = new byte[32_768];
        File.WriteAllBytes(path, original);

        // A real earlier mtime makes this write observable even when both writes occur within one filesystem clock tick.
        File.SetLastWriteTimeUtc(path, File.GetLastWriteTimeUtc(path).AddDays(-1));
        using var root = WorkspacePath.OpenRoot(fixture.Path);
        using var observed = root.OpenRead("file.bin");
        var before = WorkspacePath.FileStamp(observed);
        WorkspaceFileStamp? after = null;
        var changed = false;
        var failure = Assert.Throws<WorkspaceReadException>(() => WorkspaceFileReader.Read(root, "file.bin", 0, 32_768, phase =>
        {
            if (!changed && phase == WorkspaceReadCheckpoint.AfterBytesRead)
            {
                using var writer = new FileStream(path, FileMode.Open, FileAccess.Write, FileShare.ReadWrite);
                writer.WriteByte(42);
                writer.Flush(flushToDisk: true);
                after = WorkspacePath.FileStamp(observed);
                changed = true;
            }
        }, TestContext.Current.CancellationToken));
        Assert.True(changed);
        Assert.NotNull(after);
        Assert.NotEqual((before.Modification, before.ModificationNanoseconds), (after.Value.Modification, after.Value.ModificationNanoseconds));
        Assert.Equal("file_changed_while_reading", failure.Reason);
        Assert.Equal(32_768, failure.ObservedBytes);
        Assert.Equal(SHA256.HashData(original), failure.ObservedSha256!.Value.ToArray());
        Assert.Equal(32_768, new FileInfo(path).Length);
        Assert.Equal(42, File.ReadAllBytes(path)[0]);
    }

    [Fact(Timeout = 30_000)]
    [Trait("env", "linux-real")]
    public void ConcurrentSameLengthWritePreservesActualReadBytesOrReturnsAnObservedConflict()
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        Assert.SkipUnless(OperatingSystem.IsLinux(), "Linux competing write while the read handle is open");
        using var fixture = new OwnedDirectory();
        var path = Path.Combine(fixture.Path, "file.bin");
        File.WriteAllBytes(path, new byte[32_768]);
        using var root = WorkspacePath.OpenRoot(fixture.Path);
        using var observed = root.OpenRead("file.bin");
        var before = WorkspacePath.FileStamp(observed);
        WorkspaceFileStamp? after = null;
        var changed = false;
        WorkspaceRead? result = null;
        WorkspaceReadException? failure = null;
        try
        {
            result = WorkspaceFileReader.Read(root, "file.bin", 0, 32_768, phase =>
            {
                if (!changed && phase == WorkspaceReadCheckpoint.AfterBytesRead)
                {
                    using var writer = new FileStream(path, FileMode.Open, FileAccess.Write, FileShare.ReadWrite);
                    writer.WriteByte(17);
                    writer.Position = 16_384;
                    writer.WriteByte(42);
                    writer.Flush(flushToDisk: true);
                    after = WorkspacePath.FileStamp(observed);
                    changed = true;
                }
            }, TestContext.Current.CancellationToken);
        }
        catch (WorkspaceReadException exception)
        {
            failure = exception;
        }

        Assert.True(changed);
        Assert.NotNull(after);
        var expectedRead = new byte[32_768];
        expectedRead[16_384] = 42;
        var final = File.ReadAllBytes(path);
        Assert.Equal(32_768, final.Length);
        Assert.Equal(17, final[0]);
        Assert.Equal(42, final[16_384]);
        Assert.NotEqual(expectedRead, final);

        var stampChanged = before != after.Value;
        TestContext.Current.TestOutputHelper?.WriteLine($"Actual held metadata changed: {stampChanged}; reader refused: {failure is not null}");
        if (stampChanged)
        {
            Assert.NotNull(failure);
        }

        if (failure is not null)
        {
            Assert.Equal("file_changed_while_reading", failure.Reason);
            Assert.Equal(32_768, failure.ObservedBytes);
            Assert.Equal(SHA256.HashData(expectedRead), failure.ObservedSha256!.Value.ToArray());
        }
        else
        {
            Assert.NotNull(result);
            Assert.Equal(before, after.Value);
            Assert.Equal(expectedRead, result.Bytes.ToArray());
            Assert.Equal(SHA256.HashData(expectedRead), result.Sha256.ToArray());
            Assert.Equal(32_768UL, result.NextOffset);
            Assert.True(result.Eof);
        }
    }

    [Fact(Timeout = 30_000)]
    [Trait("env", "windows-real")]
    public void SuccessfulReadReleasesItsDataHandleBeforeTheWorkspaceIsDisposed()
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        Assert.SkipUnless(OperatingSystem.IsWindows(), "Windows exclusive sharing checks actual data-handle lifetime");
        using var fixture = new OwnedDirectory();
        var path = Path.Combine(fixture.Path, "file.bin");
        File.WriteAllBytes(path, [1, 2, 3, 4]);
        using var root = WorkspacePath.OpenRoot(fixture.Path);
        _ = WorkspaceFileReader.Read(root, "file.bin", 0, 4, TestContext.Current.CancellationToken);
        using var exclusive = new FileStream(path, FileMode.Open, FileAccess.ReadWrite, FileShare.None);
        Assert.Equal(4, exclusive.Length);
    }

    private sealed class OwnedDirectory : IDisposable
    {
        private readonly DirectoryInfo _directory = Directory.CreateTempSubdirectory("arcforges-workspace-read-");
        public string Path => _directory.FullName;
        public void Dispose() => _directory.Delete(recursive: true);
    }
}
