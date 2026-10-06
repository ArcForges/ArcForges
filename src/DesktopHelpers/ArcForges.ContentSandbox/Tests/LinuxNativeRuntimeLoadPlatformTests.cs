// SPDX-License-Identifier: AGPL-3.0-only
using System.Runtime.Versioning;
using ArcForges.ContentSandbox.Host;
using Xunit;

namespace ArcForges.ContentSandbox.Tests;

/// <summary>Actual Linux descriptor and memfd behavior; these ordinary component checks do not certify helper isolation.</summary>
public sealed class LinuxNativeRuntimeLoadPlatformTests
{
    [Fact]
    [SupportedOSPlatform("linux")]
    public void PinnedDirectoryAndSealedBytesSurviveInstalledPathReplacement()
    {
        if (!OperatingSystem.IsLinux()) { Assert.Skip("Actual Linux kernel component is required."); return; }
        using var files = new Fixture();
        var original = Enumerable.Range(0, 70000).Select(index => (byte)(index % 251)).ToArray();
        File.WriteAllBytes(Path.Combine(files.Root, "member.so"), original);
        using var platform = new LinuxNativeRuntimeLoadPlatform(files.Root);
        var renamed = files.Root + "-retained";
        Directory.Move(files.Root, renamed);
        files.AdditionalRoot = renamed;
        Directory.CreateDirectory(files.Root);
        File.WriteAllBytes(Path.Combine(files.Root, "member.so"), "foreign replacement"u8.ToArray());
        using var lease = platform.OpenSnapshot(files.Root, "member.so", TestContext.Current.CancellationToken);
        var actual = new byte[original.Length];
        lease.Bytes.ReadExactly(actual);
        Assert.Equal(original, actual);
        File.WriteAllBytes(Path.Combine(renamed, "member.so"), "changed original after sealing"u8.ToArray());
        lease.Bytes.Position = 0;
        lease.Bytes.ReadExactly(actual);
        Assert.Equal(original, actual);
        using var mutable = new FileStream(lease.LoaderPath, FileMode.Open, FileAccess.Write, FileShare.ReadWrite, bufferSize: 1);
        Assert.IsAssignableFrom<UnauthorizedAccessException>(Record.Exception(() => mutable.WriteByte(1)));
        var shrinkError = Record.Exception(() => mutable.SetLength(1));
        Assert.True(shrinkError is IOException or UnauthorizedAccessException);
    }

    [Fact]
    [SupportedOSPlatform("linux")]
    public void LinkedMembersAncestorAliasesAndOutOfBoundFilesRefuse()
    {
        if (!OperatingSystem.IsLinux()) { Assert.Skip("Actual Linux kernel component is required."); return; }
        using var files = new Fixture();
        var member = Path.Combine(files.Root, "member.so");
        File.WriteAllBytes(member, "actual bytes"u8.ToArray());
        File.CreateSymbolicLink(Path.Combine(files.Root, "linked.so"), member);
        using var platform = new LinuxNativeRuntimeLoadPlatform(files.Root);
        Assert.Throws<IOException>(() => platform.OpenSnapshot(files.Root, "linked.so", TestContext.Current.CancellationToken));
        Assert.Throws<InvalidDataException>(() => platform.OpenSnapshot(files.Root, "../member.so", TestContext.Current.CancellationToken));
        Assert.Throws<InvalidDataException>(() => platform.OpenSnapshot(files.Root + "-foreign", "member.so", TestContext.Current.CancellationToken));
        var oversized = Path.Combine(files.Root, "oversize.so");
        using (var output = new FileStream(oversized, FileMode.CreateNew, FileAccess.Write)) { output.SetLength(256L * 1024 * 1024 + 1); }
        Assert.Throws<InvalidDataException>(() => platform.OpenSnapshot(files.Root, "oversize.so", TestContext.Current.CancellationToken));
        var alias = files.Root + "-alias";
        Directory.CreateSymbolicLink(alias, files.Root);
        files.Alias = alias;
        Directory.CreateDirectory(Path.Combine(files.Root, "child"));
        Assert.Throws<InvalidDataException>(() => new LinuxNativeRuntimeLoadPlatform(Path.Combine(alias, "child")));
    }

    [Fact]
    [SupportedOSPlatform("linux")]
    public void ExactCancellationConcurrentLeasesAndDisposedDirectoryAreObserved()
    {
        if (!OperatingSystem.IsLinux()) { Assert.Skip("Actual Linux kernel component is required."); return; }
        using var files = new Fixture();
        File.WriteAllBytes(Path.Combine(files.Root, "member.so"), "actual bytes"u8.ToArray());
        using var platform = new LinuxNativeRuntimeLoadPlatform(files.Root);
        using var cancellation = new CancellationTokenSource();
        cancellation.Cancel();
        var error = Assert.Throws<OperationCanceledException>(() => platform.OpenSnapshot(files.Root, "member.so", cancellation.Token));
        Assert.Equal(cancellation.Token, error.CancellationToken);
        Parallel.For(0, 16, _ =>
        {
            using var lease = platform.OpenSnapshot(files.Root, "member.so", TestContext.Current.CancellationToken);
            var bytes = new byte[12];
            lease.Bytes.ReadExactly(bytes);
            Assert.Equal("actual bytes"u8.ToArray(), bytes);
        });
        platform.Dispose();
        platform.Dispose();
        Assert.Throws<ObjectDisposedException>(() => platform.OpenSnapshot(files.Root, "member.so", TestContext.Current.CancellationToken));
    }

    private sealed class Fixture : IDisposable
    {
        internal string Root { get; } = Directory.CreateTempSubdirectory("arc-native-linux-").FullName;
        internal string? AdditionalRoot { get; set; }
        internal string? Alias { get; set; }
        public void Dispose()
        {
            if (Alias is not null) { Directory.Delete(Alias); }
            Directory.Delete(Root, recursive: true);
            if (AdditionalRoot is not null) { Directory.Delete(AdditionalRoot, recursive: true); }
        }
    }
}
