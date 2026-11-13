// SPDX-License-Identifier: AGPL-3.0-only
using System.Security.Cryptography;
using System.Text;
using ArcForges.Node.Core.Files;
using ArcForges.Node.Core.Platform;

namespace ArcForges.Node.Core.Tests;

/// <summary>Real held-file reads and exact edit planning; none of these tests performs a target write.</summary>
public sealed class WorkspaceFileEditTests
{
    [Fact(Timeout = 30_000)]
    public void GuardedReadAndExactUtf8ReplacementPreserveBytesAndDoNotNormalize()
    {
        using var fixture = new OwnedDirectory();
        var original = Encoding.UTF8.GetBytes("aéaé-aaaa-e\u0301-é");
        File.WriteAllBytes(fixture.File, original);
        ReadOnlyMemory<byte> heldMemory;
        using (var root = WorkspacePath.OpenRoot(fixture.Path))
        using (var guard = root.OpenExistingWriteGuard("target"))
        {
            using var held = guard.ReadForMutation(TestContext.Current.CancellationToken);
            heldMemory = held.Bytes;
            Assert.Equal(original, held.Bytes.ToArray());
            Assert.Equal(SHA256.HashData(original), held.Sha256.ToArray());
            using var edited = WorkspaceFileEdit.Plan(held.Bytes.Span, held.Sha256.Span, "é", "中", 3, TestContext.Current.CancellationToken);
            Assert.Equal("a中a中-aaaa-e\u0301-中", Encoding.UTF8.GetString(edited.Bytes.Span));
            Assert.Equal(3, edited.Replacements);
            Assert.Equal(SHA256.HashData(edited.Bytes.Span), edited.Sha256.ToArray());
        }

        Assert.True(heldMemory.Span.IndexOfAnyExcept((byte)0) < 0);
        Assert.Equal(original, File.ReadAllBytes(fixture.File));
    }

    [Fact(Timeout = 30_000)]
    public void OverlappingCandidatesAreCountedOnlyAsNonOverlappingOccurrences()
    {
        using var fixture = new OwnedDirectory();
        File.WriteAllText(fixture.File, "aaaaa");
        using (var root = WorkspacePath.OpenRoot(fixture.Path))
        using (var guard = root.OpenExistingWriteGuard("target"))
        using (var held = guard.ReadForMutation(TestContext.Current.CancellationToken))
        using (var edited = WorkspaceFileEdit.Plan(held.Bytes.Span, held.Sha256.Span, "aa", "X", 2, TestContext.Current.CancellationToken))
        {
            Assert.Equal("XXa", Encoding.UTF8.GetString(edited.Bytes.Span));
            Assert.Equal(2, edited.Replacements);
        }
        Assert.Equal("aaaaa", File.ReadAllText(fixture.File));
    }

    [Fact(Timeout = 30_000)]
    public void StaleHashWrongCountAndInvalidUtf8RefuseBeforeAnyWrite()
    {
        using var fixture = new OwnedDirectory();
        var original = Encoding.UTF8.GetBytes("a--a");
        File.WriteAllBytes(fixture.File, original);
        using (var root = WorkspacePath.OpenRoot(fixture.Path))
        using (var guard = root.OpenExistingWriteGuard("target"))
        using (var held = guard.ReadForMutation(TestContext.Current.CancellationToken))
        {
            var stale = Assert.Throws<WorkspaceFileEditException>(() => WorkspaceFileEdit.Plan(held.Bytes.Span, new byte[32], "a", "b", 2,
                TestContext.Current.CancellationToken));
            Assert.Equal("hash_mismatch", stale.Reason);
            var count = Assert.Throws<WorkspaceFileEditException>(() => WorkspaceFileEdit.Plan(held.Bytes.Span, held.Sha256.Span, "a", "b", 1,
                TestContext.Current.CancellationToken));
            Assert.Equal("occurrence_mismatch", count.Reason);
            byte[] invalid = [0xc0, 0xaf];
            var utf8 = Assert.Throws<WorkspaceFileEditException>(() => WorkspaceFileEdit.Plan(invalid, SHA256.HashData(invalid), "a", "b", 1,
                TestContext.Current.CancellationToken));
            Assert.Equal("invalid_utf8", utf8.Reason);
        }
        Assert.Equal(original, File.ReadAllBytes(fixture.File));
    }

    [Fact(Timeout = 30_000)]
    public void TextAndResultLimitsUseActualUtf8BytesAndRefuseBeforeWriting()
    {
        var original = new byte[WorkspaceFileEdit.MaximumFileBytes];
        original.AsSpan().Fill((byte)'a');
        original[^1] = (byte)'x';
        var hash = SHA256.HashData(original);
        var text = Assert.Throws<WorkspaceFileEditException>(() => WorkspaceFileEdit.Plan(original, hash, "x",
            new string('z', WorkspaceFileEdit.MaximumTextBytes + 1), 1, TestContext.Current.CancellationToken));
        Assert.Equal("file_edit_text_bytes", text.Reason);
        var output = Assert.Throws<WorkspaceFileEditException>(() => WorkspaceFileEdit.Plan(original, hash, "x",
            new string('z', WorkspaceFileEdit.MaximumTextBytes), 1, TestContext.Current.CancellationToken));
        Assert.Equal("file_edit_result_bytes", output.Reason);
        Assert.Equal((byte)'x', original[^1]);
    }

    [Fact(Timeout = 30_000)]
    public void GuardRefusesAnOversizeExistingFileWithoutReadingOrChangingIt()
    {
        using var fixture = new OwnedDirectory();
        var original = new byte[WorkspaceFileEdit.MaximumFileBytes + 1];
        original[0] = 0x42;
        original[^1] = 0x43;
        File.WriteAllBytes(fixture.File, original);
        using (var root = WorkspacePath.OpenRoot(fixture.Path))
        using (var guard = root.OpenExistingWriteGuard("target"))
        {
            Assert.Equal("file_too_large", Assert.Throws<WorkspacePathException>(() =>
                guard.ReadForMutation(TestContext.Current.CancellationToken)).Reason);
        }
        Assert.Equal(original, File.ReadAllBytes(fixture.File));
    }

    private sealed class OwnedDirectory : IDisposable
    {
        private readonly DirectoryInfo _root = Directory.CreateTempSubdirectory("arcforges-edit-plan-");
        internal string Path => _root.FullName;
        internal string File => System.IO.Path.Combine(Path, "target");
        public void Dispose() => _root.Delete(recursive: true);
    }
}
