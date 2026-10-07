// SPDX-License-Identifier: AGPL-3.0-only
using System.Runtime.Versioning;
using System.Runtime.InteropServices;
using ArcForges.ContentSandbox.Host;
using Xunit;

namespace ArcForges.ContentSandbox.Tests;

/// <summary>Actual Linux descriptor and memfd behavior; these ordinary component checks do not certify helper isolation.</summary>
public sealed class LinuxNativeRuntimeLoadPlatformTests
{
    [Fact]
    [SupportedOSPlatform("linux")]
    public void ActualImmediateLinkageExportReferenceCountsAndOwnedPlatformCleanup()
    {
        if (!OperatingSystem.IsLinux()) { Assert.Skip("Actual Linux kernel component is required."); return; }
        var fixtures = Environment.GetEnvironmentVariable("ARCFORGES_LINUX_LOADER_FIXTURES");
        if (string.IsNullOrEmpty(fixtures)) { Assert.Skip("Actual compiled loader component fixtures are required."); return; }
        using var files = new Fixture();
        File.Copy(Path.Combine(fixtures, "valid.so"), Path.Combine(files.Root, "valid.so"));
        File.Copy(Path.Combine(fixtures, "unresolved.so"), Path.Combine(files.Root, "unresolved.so"));
        using var platform = new LinuxNativeRuntimeLoadPlatform(files.Root);
        using var invalid = platform.OpenSnapshot(files.Root, "unresolved.so", TestContext.Current.CancellationToken);
        Assert.Throws<DllNotFoundException>(() => platform.Load(invalid.LoaderPath));
        using var valid = platform.OpenSnapshot(files.Root, "valid.so", TestContext.Current.CancellationToken);
        var first = platform.Load(valid.LoaderPath);
        var second = platform.Load(valid.LoaderPath);
        Assert.Equal(first, second);
        Assert.True(platform.HasExport(first, "arc_loader_answer"));
        Assert.False(platform.HasExport(first, "arc_loader_absent"));
        Assert.Equal(42, Marshal.GetDelegateForFunctionPointer<Answer>(NativeLibrary.GetExport(first, "arc_loader_answer"))());
        platform.Free(first);
        Assert.True(platform.HasExport(second, "arc_loader_answer"));
        platform.Free(second);
        Assert.Throws<InvalidOperationException>(() => platform.HasExport(first, "arc_loader_answer"));
        _ = platform.Load(valid.LoaderPath);
        platform.Dispose(); // Retains and closes the actual outstanding module reference and every sealed-file owner.
        platform.Dispose();
        Assert.Throws<ObjectDisposedException>(() => platform.Load(valid.LoaderPath));
        Assert.Throws<ObjectDisposedException>(() => valid.Bytes.ReadByte());
    }

    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate int Answer();

    [Fact]
    [SupportedOSPlatform("linux")]
    public void ImmediateLoaderRefusesMalformedSealedBytesAndForeignHandles()
    {
        if (!OperatingSystem.IsLinux()) { Assert.Skip("Actual Linux kernel component is required."); return; }
        using var files = new Fixture();
        File.WriteAllBytes(Path.Combine(files.Root, "invalid.so"), "actual malformed ELF fixture"u8.ToArray());
        using var platform = new LinuxNativeRuntimeLoadPlatform(files.Root);
        using var lease = platform.OpenSnapshot(files.Root, "invalid.so", TestContext.Current.CancellationToken);
        for (var index = 0; index < 16; index++)
        {
            Assert.Throws<DllNotFoundException>(() => platform.Load(lease.LoaderPath));
        }

        Assert.Throws<InvalidDataException>(() => platform.Load("./invalid.so"));
        Assert.Throws<InvalidDataException>(() => platform.Load("/proc/self/fd/0"));
        Assert.Throws<InvalidOperationException>(() => platform.HasExport(1, "foreign"));
        Assert.Throws<InvalidOperationException>(() => platform.Free(1));
        platform.Free(0);
        using (var foreign = new FileStream(Path.Combine(files.Root, "invalid.so"), FileMode.Open, FileAccess.Read, FileShare.Read))
        {
            Assert.Throws<InvalidDataException>(() => platform.Load("/proc/self/fd/" + foreign.SafeFileHandle.DangerousGetHandle()));
        }

        var released = lease.LoaderPath;
        lease.Dispose();
        Assert.Throws<InvalidDataException>(() => platform.Load(released));
    }

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
