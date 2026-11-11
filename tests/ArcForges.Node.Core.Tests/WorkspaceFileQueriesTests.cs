// SPDX-License-Identifier: AGPL-3.0-only
using System.Buffers.Binary;
using System.Diagnostics;
using System.Security.Cryptography;
using System.Text;
using ArcForges.Node.Core.Files;
using ArcForges.Node.Core.Platform;
using Google.Protobuf;
using N = ArcForges.Contracts.Node.V1;

namespace ArcForges.Node.Core.Tests;

/// <summary>Actual native filesystem scans and independently recomputed byte transcripts; no center/RPC acceptance claim.</summary>
[Trait("feature", "workspace-file-queries")]
public sealed class WorkspaceFileQueriesTests
{
    [Fact(Timeout = 30_000)]
    public void LiteralSearchReportsUtf8ByteOffsetsAndTheExactObservedTranscript()
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        using var fixture = new OwnedDirectory();
        var bytes = "α😀z😀"u8.ToArray();
        File.WriteAllBytes(Path.Combine(fixture.Path, "u.txt"), bytes);
        using var root = WorkspacePath.OpenRoot(fixture.Path);
        using var query = new WorkspaceFileQueries();
        var result = query.Search(root, "u.txt", "😀", N.FileSearchMode.Literal,
            cancellationToken: TestContext.Current.CancellationToken);
        Assert.Collection(result.Value.Matches,
            first => { Assert.Equal(2UL, first.ByteOffset); Assert.Equal(4U, first.ByteLength); },
            second => { Assert.Equal(7UL, second.ByteOffset); Assert.Equal(4U, second.ByteLength); });
        Assert.Equal(11UL, result.Value.ScannedBytes);
        Assert.False(result.Value.Truncated);
        Assert.Equal(SingleFrame("u.txt", bytes), result.Value.ScanDigest.ToByteArray());
        Assert.Equal(53UL, result.Value.ScanTranscriptBytes);
        Assert.Equal(1U, result.Value.ScanFileCount);
        Assert.Equal(result.Value.ScanDigest, Assert.Single(result.Audit.Observations).Sha256);
    }

    [Fact(Timeout = 30_000)]
    public void EmptySearchHasTheMandatoryDomainDigestAndZeroActualBytes()
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        using var fixture = new OwnedDirectory();
        using var root = WorkspacePath.OpenRoot(fixture.Path);
        using var query = new WorkspaceFileQueries();
        var result = query.Search(root, "", "absent", N.FileSearchMode.Literal,
            cancellationToken: TestContext.Current.CancellationToken);
        Assert.Empty(result.Value.Matches);
        Assert.Equal(0UL, result.Value.ScannedBytes);
        Assert.Equal(25UL, result.Value.ScanTranscriptBytes);
        Assert.Equal(Convert.FromHexString("3f0e0a01dc6c80ced277ce0283faa0a621a0be218e30d1759a19b07a49e7614c"), result.Value.ScanDigest.ToByteArray());
        Assert.Equal(0U, Assert.Single(result.Audit.Observations).ItemCount);
    }

    [Fact(Timeout = 30_000)]
    public void RegexThatBisectsASupplementaryScalarRefusesWithTheActualScanDigest()
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        using var fixture = new OwnedDirectory();
        var bytes = "😀"u8.ToArray();
        File.WriteAllBytes(Path.Combine(fixture.Path, "scalar.txt"), bytes);
        using var root = WorkspacePath.OpenRoot(fixture.Path);
        using var query = new WorkspaceFileQueries();
        var error = Assert.Throws<WorkspaceQueryException>(() => query.Search(root, "scalar.txt", ".", N.FileSearchMode.Regex,
            cancellationToken: TestContext.Current.CancellationToken));
        Assert.Equal("regex_scalar_boundary", error.Reason);
        var observation = Assert.Single(Assert.IsType<N.FileAuditMetadata>(error.Audit).Observations);
        Assert.Equal(4UL, observation.SizeBytes);
        Assert.Equal(SingleFrame("scalar.txt", bytes), observation.Sha256.ToByteArray());
        Assert.DoesNotContain("😀", error.ToString(), StringComparison.Ordinal);
    }

    [Fact(Timeout = 30_000)]
    public void ZeroLengthRegexAdvancesByAWholeScalar()
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        using var fixture = new OwnedDirectory();
        File.WriteAllBytes(Path.Combine(fixture.Path, "scalar.txt"), "😀"u8.ToArray());
        using var root = WorkspacePath.OpenRoot(fixture.Path);
        using var query = new WorkspaceFileQueries();
        var result = query.Search(root, "scalar.txt", "a*", N.FileSearchMode.Regex,
            cancellationToken: TestContext.Current.CancellationToken);
        Assert.Collection(result.Value.Matches,
            first => { Assert.Equal(0UL, first.ByteOffset); Assert.Equal(0U, first.ByteLength); },
            second => { Assert.Equal(4UL, second.ByteOffset); Assert.Equal(0U, second.ByteLength); });
        Assert.False(result.Value.Truncated);
    }

    [Fact(Timeout = 30_000)]
    public void AByteLimitRetainsOnlyTheCompleteUtf8PrefixButHashesEveryReadByte()
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        using var fixture = new OwnedDirectory();
        var bytes = "A€B"u8.ToArray();
        File.WriteAllBytes(Path.Combine(fixture.Path, "cut.txt"), bytes);
        using var root = WorkspacePath.OpenRoot(fixture.Path);
        using var query = new WorkspaceFileQueries();
        var result = query.Search(root, "cut.txt", "A", N.FileSearchMode.Literal, maximumBytes: 3,
            cancellationToken: TestContext.Current.CancellationToken);
        Assert.Single(result.Value.Matches);
        Assert.Equal(3UL, result.Value.ScannedBytes);
        Assert.Equal(0U, result.Value.SkippedFiles);
        Assert.True(result.Value.Truncated);
        Assert.Equal("scan_bytes", result.Value.TruncationReason);
        Assert.Equal(SingleFrame("cut.txt", bytes.AsSpan(0, 3)), result.Value.ScanDigest.ToByteArray());
        Assert.DoesNotContain(result.Value.Problems, problem => problem.Reason == "invalid_utf8");
    }

    [Fact(Timeout = 30_000)]
    public void BinaryAndMalformedPrefixesAreCountedAndHashedWithoutReplacement()
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        using var fixture = new OwnedDirectory();
        byte[] invalid = [0x61, 0xff, 0x62];
        byte[] binary = [0, 1, 2];
        File.WriteAllBytes(Path.Combine(fixture.Path, "a-invalid.txt"), invalid);
        File.WriteAllBytes(Path.Combine(fixture.Path, "b-binary.txt"), binary);
        using var root = WorkspacePath.OpenRoot(fixture.Path);
        using var query = new WorkspaceFileQueries();
        var result = query.Search(root, "", "a", N.FileSearchMode.Literal,
            cancellationToken: TestContext.Current.CancellationToken);
        Assert.Empty(result.Value.Matches);
        Assert.Equal(6UL, result.Value.ScannedBytes);
        Assert.Equal(2U, result.Value.SkippedFiles);
        Assert.True(result.Value.Truncated);
        Assert.Contains(result.Value.Problems, problem => problem.Reason == "invalid_utf8");
        Assert.Contains(result.Value.Problems, problem => problem.Reason == "binary_file");
        using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        hash.AppendData("ArcForges search-scan v1\0"u8);
        Frame(hash, "a-invalid.txt", invalid);
        Frame(hash, "b-binary.txt", binary);
        Assert.Equal(hash.GetHashAndReset(), result.Value.ScanDigest.ToByteArray());
    }

    [Fact(Timeout = 30_000)]
    public void PerFileAndMatchBoundsDoNotInventUnreadByteObservations()
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        using var fixture = new OwnedDirectory();
        var large = new byte[WorkspaceFileQueries.MaximumFileBytes + 9];
        Array.Fill(large, (byte)'a');
        File.WriteAllBytes(Path.Combine(fixture.Path, "large.txt"), large);
        using var root = WorkspacePath.OpenRoot(fixture.Path);
        using var query = new WorkspaceFileQueries();
        var result = query.Search(root, "large.txt", "missing", N.FileSearchMode.Literal,
            cancellationToken: TestContext.Current.CancellationToken);
        Assert.Equal((ulong)WorkspaceFileQueries.MaximumFileBytes, result.Value.ScannedBytes);
        Assert.True(result.Value.Truncated);
        Assert.Equal(SingleFrame("large.txt", large.AsSpan(0, WorkspaceFileQueries.MaximumFileBytes)), result.Value.ScanDigest.ToByteArray());
        var limited = query.Search(root, "large.txt", "a", N.FileSearchMode.Literal, maximumMatches: 3,
            cancellationToken: TestContext.Current.CancellationToken);
        Assert.Equal(3, limited.Value.Matches.Count);
        Assert.Equal((ulong)WorkspaceFileQueries.MaximumFileBytes, limited.Value.ScannedBytes);
    }

    [Fact(Timeout = 30_000)]
    public void CancellationAfterRealReadsPreservesThePrefixObservation()
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        using var fixture = new OwnedDirectory();
        var bytes = "observed-private-bytes"u8.ToArray();
        File.WriteAllBytes(Path.Combine(fixture.Path, "cancel.txt"), bytes);
        using var root = WorkspacePath.OpenRoot(fixture.Path);
        using var query = new WorkspaceFileQueries();
        using var cancelled = new CancellationTokenSource();
        var error = Assert.Throws<WorkspaceQueryException>(() => query.Search(root, "cancel.txt", "private", N.FileSearchMode.Literal,
            100, WorkspaceFileQueries.MaximumScanBytes, _ => cancelled.Cancel(), cancelled.Token));
        Assert.Equal("query_cancelled", error.Reason);
        var audit = Assert.Single(Assert.IsType<N.FileAuditMetadata>(error.Audit).Observations);
        Assert.Equal((ulong)bytes.Length, audit.SizeBytes);
        Assert.Equal(SingleFrame("cancel.txt", bytes), audit.Sha256.ToByteArray());
        Assert.DoesNotContain("observed-private-bytes", error.ToString(), StringComparison.Ordinal);
    }

    [Fact(Timeout = 30_000)]
    [Trait("env", "linux-real")]
    public void ARealCompetingWriterCannotTurnChangedBytesIntoSuccessfulMatches()
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        Assert.SkipUnless(OperatingSystem.IsLinux(), "Linux permits a competing writer while a data reader is open");
        using var fixture = new OwnedDirectory();
        var path = Path.Combine(fixture.Path, "changing.txt");
        var original = "match-me"u8.ToArray();
        File.WriteAllBytes(path, original);
        using var root = WorkspacePath.OpenRoot(fixture.Path);
        using var query = new WorkspaceFileQueries();
        var result = query.Search(root, "changing.txt", "match", N.FileSearchMode.Literal,
            100, WorkspaceFileQueries.MaximumScanBytes, _ => File.WriteAllText(path, "replacement-data"), TestContext.Current.CancellationToken);
        Assert.Empty(result.Value.Matches);
        Assert.Equal(1U, result.Value.SkippedFiles);
        Assert.Contains(result.Value.Problems, problem => problem.Reason == "file_changed");
        Assert.Equal(SingleFrame("changing.txt", original), result.Value.ScanDigest.ToByteArray());
    }

    [Fact(Timeout = 30_000)]
    [Trait("env", "linux-real")]
    public void FinalLinksHardLinksAndFifosAreInspectedWithoutFollowingOrBlocking()
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        Assert.SkipUnless(OperatingSystem.IsLinux(), "Linux native link and FIFO setup");
        using var fixture = new OwnedDirectory();
        var outside = Path.Combine(fixture.Base, "outside.txt");
        File.WriteAllText(outside, "outside-marker");
        File.CreateSymbolicLink(Path.Combine(fixture.Path, "link.txt"), outside);
        var fifo = Path.Combine(fixture.Path, "pipe");
        Run("mkfifo", fifo);
        var original = Path.Combine(fixture.Path, "hard.txt");
        File.WriteAllText(original, "hard-link-marker");
        Run("ln", original, Path.Combine(fixture.Path, "hard-alias.txt"));
        using var root = WorkspacePath.OpenRoot(fixture.Path);
        using var query = new WorkspaceFileQueries();
        Assert.Equal(WorkspaceEntryType.Link, root.InspectEntry("link.txt").Kind);
        Assert.Equal(WorkspaceEntryType.Other, root.InspectEntry("pipe").Kind);
        var result = query.Search(root, "", "marker", N.FileSearchMode.Literal,
            cancellationToken: TestContext.Current.CancellationToken);
        Assert.Empty(result.Value.Matches);
        Assert.Equal(0UL, result.Value.ScannedBytes);
        Assert.Equal(4U, result.Value.SkippedFiles);
        Assert.Equal("outside-marker", File.ReadAllText(outside));
    }

    [Fact(Timeout = 30_000)]
    public void SerializedResultIsBoundedIncludingSignedAuditAndNoContentSnippet()
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        using var fixture = new OwnedDirectory();
        var relative = string.Join('/', Enumerable.Range(0, 8).Select(i => new string((char)('a' + i), 240)));
        var directory = Path.Combine(fixture.Path, relative.Replace('/', Path.DirectorySeparatorChar));
        Directory.CreateDirectory(directory);
        var text = string.Join(' ', Enumerable.Repeat("PRIVATE-BODY", 100));
        var path = relative + "/matches.txt";
        File.WriteAllText(Path.Combine(directory, "matches.txt"), text);
        using var root = WorkspacePath.OpenRoot(fixture.Path);
        using var query = new WorkspaceFileQueries();
        var result = query.Search(root, path, "PRIVATE", N.FileSearchMode.Literal,
            cancellationToken: TestContext.Current.CancellationToken);
        var response = new N.FileServiceSearchFilesResponse { Value = result.Value, Audit = result.Audit };
        Assert.InRange(result.Value.Matches.Count, 1, 99);
        Assert.True(result.Value.Truncated);
        Assert.InRange(response.CalculateSize(), 1, WorkspaceFileQueries.MaximumResponseBytes);
        Assert.DoesNotContain("PRIVATE-BODY", response.ToString(), StringComparison.Ordinal);
    }

    [Fact(Timeout = 30_000)]
    public void UnsupportedPatternsAndInvalidInputsHaveNoFileObservation()
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        using var fixture = new OwnedDirectory();
        using var root = WorkspacePath.OpenRoot(fixture.Path);
        using var query = new WorkspaceFileQueries();
        var error = Assert.Throws<WorkspaceQueryException>(() => query.Search(root, "missing", "(a)\\1", N.FileSearchMode.Regex,
            cancellationToken: TestContext.Current.CancellationToken));
        Assert.Equal("pattern_unsupported", error.Reason);
        Assert.Null(error.Audit);
        Assert.Throws<WorkspacePathException>(() => query.Search(root, "../outside", "x", N.FileSearchMode.Literal,
            cancellationToken: TestContext.Current.CancellationToken));
        Assert.Throws<WorkspaceQueryException>(() => query.Search(root, "", "x", N.FileSearchMode.Literal, maximumBytes: 0,
            cancellationToken: TestContext.Current.CancellationToken));
    }


    [Fact(Timeout = 30_000)]
    public void SearchMatchesThePublishedIndependentUnicodeTranscriptVector()
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        using var fixture = new OwnedDirectory();
        File.WriteAllBytes(Path.Combine(fixture.Path, "a.txt"), "Hi\n"u8.ToArray());
        Directory.CreateDirectory(Path.Combine(fixture.Path, "src"));
        File.WriteAllBytes(Path.Combine(fixture.Path, "src", "💡.txt"), "X😀Y"u8.ToArray());
        using var root = WorkspacePath.OpenRoot(fixture.Path);
        using var query = new WorkspaceFileQueries();
        var result = query.Search(root, "", "absent", N.FileSearchMode.Literal,
            cancellationToken: TestContext.Current.CancellationToken);
        Assert.Equal(9UL, result.Value.ScannedBytes);
        Assert.Equal(75UL, result.Value.ScanTranscriptBytes);
        Assert.Equal(Convert.FromHexString("28ec2d1189959004112bf8b746d6c12ceceb4ac4d859c82ededd334b16f49aa5"), result.Value.ScanDigest.ToByteArray());
    }

    [Fact(Timeout = 30_000)]
    public void DirectoryMetadataMatchesThePublishedIndependentVector()
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        using var fixture = new OwnedDirectory();
        File.WriteAllBytes(Path.Combine(fixture.Path, "a.txt"), "abc"u8.ToArray());
        Directory.CreateDirectory(Path.Combine(fixture.Path, "src"));
        using var root = WorkspacePath.OpenRoot(fixture.Path);
        using var query = new WorkspaceFileQueries();
        var workspace = Guid.NewGuid().ToByteArray();
        var caller = SHA256.HashData("caller-a"u8);
        var result = query.ListDirectory(root, workspace, caller, "", cancellationToken: TestContext.Current.CancellationToken);
        Assert.Collection(result.Value.Entries,
            file => { Assert.Equal("a.txt", file.Name); Assert.Equal(N.FileEntryKind.File, file.Kind); Assert.True(file.HasSizeBytes); Assert.Equal(3UL, file.SizeBytes); },
            directory => { Assert.Equal("src", directory.Name); Assert.Equal(N.FileEntryKind.Directory, directory.Kind); Assert.False(directory.HasSizeBytes); });
        Assert.Equal(62UL, result.Value.MetadataBytes);
        Assert.Equal(Convert.FromHexString("68124664fb154c01edef877676ffc2f8dab06fbf9dc48cc939024ddbfac95bbb"), result.Value.MetadataDigest.ToByteArray());
        Assert.Equal(result.Value.MetadataDigest, Assert.Single(result.Audit.Observations).Sha256);
        Assert.False(result.Value.HasNextCursor);
    }

    [Fact(Timeout = 30_000)]
    public void DirectoryPagesAreStableBoundedAndCannotBeReusedByAnotherCallerOrWorkspace()
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        using var fixture = new OwnedDirectory();
        foreach (var name in new[] { "a", "b", "c" })
        {
            File.WriteAllText(Path.Combine(fixture.Path, name), name);
        }

        using var root = WorkspacePath.OpenRoot(fixture.Path);
        using var query = new WorkspaceFileQueries();
        var workspace = Guid.NewGuid().ToByteArray();
        var caller = SHA256.HashData("caller-a"u8);
        var first = query.ListDirectory(root, workspace, caller, "", 1, cancellationToken: TestContext.Current.CancellationToken);
        Assert.Equal("a", Assert.Single(first.Value.Entries).Name);
        var token = first.Value.NextCursor;
        Assert.NotEmpty(token);
        var other = SHA256.HashData("caller-b"u8);
        Assert.Equal("invalid_cursor", Assert.Throws<WorkspaceQueryException>(() => query.ListDirectory(root, workspace, other, "", 1, token,
            TestContext.Current.CancellationToken)).Reason);
        var otherWorkspace = Guid.NewGuid().ToByteArray();
        Assert.Equal("invalid_cursor", Assert.Throws<WorkspaceQueryException>(() => query.ListDirectory(root, otherWorkspace, caller, "", 1, token,
            TestContext.Current.CancellationToken)).Reason);
        var tampered = (token[0] == 'A' ? "B" : "A") + token[1..];
        Assert.Equal("invalid_cursor", Assert.Throws<WorkspaceQueryException>(() => query.ListDirectory(root, workspace, caller, "", 1, tampered,
            TestContext.Current.CancellationToken)).Reason);
        var second = query.ListDirectory(root, workspace, caller, "", 1, token, TestContext.Current.CancellationToken);
        Assert.Equal("b", Assert.Single(second.Value.Entries).Name);
        var last = query.ListDirectory(root, workspace, caller, "", 1, second.Value.NextCursor, TestContext.Current.CancellationToken);
        Assert.Equal("c", Assert.Single(last.Value.Entries).Name);
        Assert.False(last.Value.HasNextCursor);
        Assert.Equal(3U, last.Value.SnapshotEntries);
        Assert.InRange(new N.FileServiceListDirectoryResponse { Value = second.Value, Audit = second.Audit }.CalculateSize(), 1, 131_072);
        using var restarted = new WorkspaceFileQueries();
        Assert.Equal("invalid_cursor", Assert.Throws<WorkspaceQueryException>(() => restarted.ListDirectory(root, workspace, caller, "", 1, token,
            TestContext.Current.CancellationToken)).Reason);
    }

    [Fact(Timeout = 30_000)]
    public void AChangedDirectoryOrChildMetadataInvalidatesTheCursor()
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        using var fixture = new OwnedDirectory();
        File.WriteAllText(Path.Combine(fixture.Path, "a"), "a");
        File.WriteAllText(Path.Combine(fixture.Path, "b"), "b");
        using var root = WorkspacePath.OpenRoot(fixture.Path);
        using var query = new WorkspaceFileQueries();
        var workspace = Guid.NewGuid().ToByteArray();
        var caller = SHA256.HashData("caller"u8);
        var token = query.ListDirectory(root, workspace, caller, "", 1, cancellationToken: TestContext.Current.CancellationToken).Value.NextCursor;
        File.WriteAllText(Path.Combine(fixture.Path, "b"), "different size");
        Assert.Equal("invalid_cursor", Assert.Throws<WorkspaceQueryException>(() => query.ListDirectory(root, workspace, caller, "", 1, token,
            TestContext.Current.CancellationToken)).Reason);
        token = query.ListDirectory(root, workspace, caller, "", 1, cancellationToken: TestContext.Current.CancellationToken).Value.NextCursor;
        File.WriteAllText(Path.Combine(fixture.Path, "new-entry"), "new");
        Assert.Equal("invalid_cursor", Assert.Throws<WorkspaceQueryException>(() => query.ListDirectory(root, workspace, caller, "", 1, token,
            TestContext.Current.CancellationToken)).Reason);
    }

    [Fact(Timeout = 30_000)]
    public void MonotonicExpiryAndTheActualSnapshotCountBoundRejectOldCursors()
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        using var fixture = new OwnedDirectory();
        File.WriteAllText(Path.Combine(fixture.Path, "a"), "a");
        File.WriteAllText(Path.Combine(fixture.Path, "b"), "b");
        using var root = WorkspacePath.OpenRoot(fixture.Path);
        var clock = new ManualMonotonicClock();
        using var query = new WorkspaceFileQueries(clock);
        var workspace = Guid.NewGuid().ToByteArray();
        var caller = SHA256.HashData("caller"u8);
        var token = query.ListDirectory(root, workspace, caller, "", 1, cancellationToken: TestContext.Current.CancellationToken).Value.NextCursor;
        clock.Advance(TimeSpan.FromSeconds(61));
        Assert.Equal("invalid_cursor", Assert.Throws<WorkspaceQueryException>(() => query.ListDirectory(root, workspace, caller, "", 1, token,
            TestContext.Current.CancellationToken)).Reason);
        Assert.Equal(0, query.SnapshotUsage.Count);
        string? oldest = null;
        for (var index = 0; index < 65; index++)
        {
            clock.Advance(TimeSpan.FromMilliseconds(1));
            var page = query.ListDirectory(root, workspace, caller, "", 1, cancellationToken: TestContext.Current.CancellationToken);
            oldest ??= page.Value.NextCursor;
        }

        Assert.Equal(64, query.SnapshotUsage.Count);
        Assert.InRange(query.SnapshotUsage.Bytes, 1, WorkspaceFileQueries.MaximumSnapshotBytes);
        Assert.Equal("invalid_cursor", Assert.Throws<WorkspaceQueryException>(() => query.ListDirectory(root, workspace, caller, "", 1, oldest,
            TestContext.Current.CancellationToken)).Reason);
    }

    private sealed class ManualMonotonicClock : TimeProvider
    {
        private long _ticks;
        public override long TimestampFrequency => TimeSpan.TicksPerSecond;
        public override long GetTimestamp() => _ticks;
        internal void Advance(TimeSpan elapsed) => _ticks += elapsed.Ticks;
    }


    private static byte[] SingleFrame(string path, ReadOnlySpan<byte> bytes)
    {
        using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        hash.AppendData("ArcForges search-scan v1\0"u8);
        if (bytes.Length != 0)
        {
            Frame(hash, path, bytes);
        }

        return hash.GetHashAndReset();
    }

    private static void Frame(IncrementalHash hash, string path, ReadOnlySpan<byte> bytes)
    {
        var encoded = Encoding.UTF8.GetBytes(path);
        Span<byte> frame = stackalloc byte[8];
        BinaryPrimitives.WriteUInt32BigEndian(frame, checked((uint)encoded.Length));
        hash.AppendData(frame[..4]);
        hash.AppendData(encoded);
        BinaryPrimitives.WriteUInt64BigEndian(frame, checked((ulong)bytes.Length));
        hash.AppendData(frame);
        hash.AppendData(bytes);
    }

    private static void Run(string executable, params string[] arguments)
    {
        using var process = Process.Start(new ProcessStartInfo(executable, arguments) { RedirectStandardError = true, CreateNoWindow = true })!;
        var error = process.StandardError.ReadToEnd();
        Assert.True(process.WaitForExit(10_000) && process.ExitCode == 0, "owned fixture setup: " + error);
    }

    private sealed class OwnedDirectory : IDisposable
    {
        private readonly DirectoryInfo _directory = Directory.CreateTempSubdirectory("arcforges-file-query-");
        internal OwnedDirectory() => Directory.CreateDirectory(Path);
        internal string Base => _directory.FullName;
        internal string Path => System.IO.Path.Combine(Base, "root");
        public void Dispose() => _directory.Delete(recursive: true);
    }
}
